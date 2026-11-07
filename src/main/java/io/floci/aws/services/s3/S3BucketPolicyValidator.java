package io.floci.aws.services.s3;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.services.iam.IamPolicyEvaluator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Rejects a bucket policy that breaks the
 * <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html">IAM
 * JSON policy grammar</a> as S3 does: {@code MalformedPolicy} (400), with the message S3 gives for
 * that mistake, irregular wording, punctuation and trailing space included.
 *
 * <p>The messages, and which mistake S3 reports when a policy has several, are what S3
 * {@code PutBucketPolicy} answered to {@code tools/aws-capture/resource-policy}, replayed by
 * {@code S3BucketPolicyAwsCorpusTest}. Only the recorded combinations of mistakes are pinned; the
 * order below is inferred from them, and a few messages, such as the one for an empty
 * {@code NotPrincipal}, {@code NotAction} or {@code NotResource}, follow the pattern of a recorded
 * one without having been recorded themselves. S3 checks the document in this order: its {@code Version}
 * values, unknown elements, the type of {@code Id}, a missing {@code Statement}, content after the
 * document, repeated elements, the shape of {@code Statement}. Then every statement's structure
 * (unknown elements, then whether {@code Effect}, the principal and the action are present) before
 * any statement's values: {@code Effect}, repeated or conflicting elements, {@code Sid},
 * {@code Condition}, the principal, the action, then the resource, whose absence S3 reports only at
 * that point. Every occurrence of a repeated element is checked, not only the last. {@code Effect}
 * is matched case-insensitively, a {@code Sid} may be any string and may repeat, a condition
 * operator may carry no keys and a condition key an empty list.
 *
 * <p>S3's own checks on top of the grammar are not made: that each action is one S3 defines, each
 * resource lies in the bucket, each principal exists, each {@code s3:} condition key is defined and
 * each action applies to a resource of its statement, nor the 20 KB size limit. The recorded cases they
 * decide are listed in {@code s3-put-bucket-policy-aws-gaps.tsv}.
 */
final class S3BucketPolicyValidator {

    private static final String NOT_JSON = "Policies must be valid JSON and the first byte must be '{'";
    private static final String INVALID_SYNTAX = "Invalid policy syntax.";
    private static final JsonFactory JSON = new JsonFactory();
    private static final Set<String> DOCUMENT_ELEMENTS = Set.of("Version", "Id", "Statement");
    private static final Set<String> STATEMENT_ELEMENTS = Set.of("Sid", "Effect", "Principal", "NotPrincipal",
            "Action", "NotAction", "Resource", "NotResource", "Condition");
    private static final Set<String> VERSIONS = Set.of("2012-10-17", "2008-10-17");
    private static final Set<String> PRINCIPAL_TYPES = Set.of("AWS", "Service", "Federated", "CanonicalUser");
    private static final String WILDCARD = "*";
    /** {@code service:action}: a service prefix such as {@code execute-api}, then a name that may use wildcards. */
    private static final Pattern ACTION = Pattern.compile("(?:[A-Za-z0-9_.-]+|\\*):[A-Za-z0-9_*?-]+");
    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");

    private S3BucketPolicyValidator() {
    }

    /** Throws {@code MalformedPolicy} when {@code policy} breaks the grammar. */
    static void validate(String policy) {
        // S3 looks at the raw first byte before it parses: leading whitespace fails here too.
        if (policy == null || policy.isEmpty() || policy.charAt(0) != '{') {
            throw malformed(NOT_JSON);
        }
        Members document;
        boolean trailing;
        try (JsonParser parser = JSON.createParser(policy)) {
            parser.nextToken();
            document = (Members) read(parser);
            trailing = hasMore(parser);
        } catch (IOException e) {
            throw malformed("This policy contains invalid Json");
        }
        checkDocument(document, trailing);
    }

    private static void checkDocument(Members document, boolean trailing) {
        for (Value version : document.all("Version")) {
            if (!(isText(version) && VERSIONS.contains(textOf(version)))) {
                throw malformed("The policy must contain a valid version string");
            }
        }
        rejectUnknownElements(document, DOCUMENT_ELEMENTS);
        for (Value id : document.all("Id")) {
            if (!isText(id)) {
                throw malformed(INVALID_SYNTAX);
            }
        }
        if (!document.has("Statement")) {
            throw missing("Statement");
        }
        if (trailing) {
            throw malformed(INVALID_SYNTAX);
        }
        rejectRepeatedElements(document);
        List<Members> statements = statements(document.first("Statement"));
        for (Members statement : statements) {
            checkStructure(statement);
        }
        for (Members statement : statements) {
            checkValues(statement);
        }
    }

    /** {@code Statement} is one statement object or a nonempty list of them. */
    private static List<Members> statements(Value statement) {
        if (statement instanceof Members single) {
            return List.of(single);
        }
        String notWellFormatted = "Could not parse the policy: Statement is not well formatted.";
        if (!(statement instanceof Items list)) {
            throw malformed(notWellFormatted);
        }
        if (list.items().isEmpty()) {
            throw malformed("Could not parse the policy: Statement is empty!");
        }
        List<Members> statements = new ArrayList<>();
        for (Value entry : list.items()) {
            if (!(entry instanceof Members object)) {
                throw malformed(notWellFormatted);
            }
            statements.add(object);
        }
        return statements;
    }

    /** That a statement names only grammar elements and carries the required ones. */
    private static void checkStructure(Members statement) {
        rejectUnknownElements(statement, STATEMENT_ELEMENTS);
        if (!statement.has("Effect")) {
            throw missing("Effect");
        }
        if (!statement.has("Principal") && !statement.has("NotPrincipal")) {
            throw missing("Principal");
        }
        if (!statement.has("Action") && !statement.has("NotAction")) {
            throw missing("Action");
        }
    }

    private static void checkValues(Members statement) {
        for (Value effect : statement.all("Effect")) {
            checkEffect(effect);
        }
        rejectRepeatedElements(statement);
        for (Value sid : statement.all("Sid")) {
            if (!isText(sid)) {
                throw malformed(INVALID_SYNTAX);
            }
        }
        if (statement.has("Condition")) {
            checkCondition(statement.first("Condition"));
        }
        for (String name : List.of("Principal", "NotPrincipal")) {
            if (statement.has(name)) {
                checkPrincipal(name, statement.first(name));
            }
        }
        for (String name : List.of("Action", "NotAction")) {
            if (statement.has(name)) {
                checkStrings(name, statement.first(name), "Policy has invalid action",
                        action -> WILDCARD.equals(action) || ACTION.matcher(action).matches());
            }
        }
        if (!statement.has("Resource") && !statement.has("NotResource")) {
            throw malformed("Statement is missing required element");
        }
        for (String name : List.of("Resource", "NotResource")) {
            if (statement.has(name)) {
                checkStrings(name, statement.first(name), "Policy has invalid resource",
                        resource -> WILDCARD.equals(resource) || AwsArnUtils.isArn(resource));
            }
        }
    }

    private static void checkEffect(Value effect) {
        if (!isText(effect)) {
            throw malformed(INVALID_SYNTAX);
        }
        String value = textOf(effect);
        if (value.isEmpty()) {
            throw empty("Effect");
        }
        if (!"Allow".equalsIgnoreCase(value) && !"Deny".equalsIgnoreCase(value)) {
            throw malformed("Invalid effect: " + value);
        }
    }

    /** {@code "*"}, or an object mapping principal types to one identifier or a nonempty list of them. */
    private static void checkPrincipal(String name, Value principal) {
        if (principal instanceof Scalar && WILDCARD.equals(textOf(principal))) {
            return;
        }
        if (!(principal instanceof Members types)) {
            throw malformed(INVALID_SYNTAX);
        }
        if (types.members().isEmpty()) {
            throw empty(name);
        }
        for (Member entry : types.members()) {
            String type = entry.name();
            if (!PRINCIPAL_TYPES.contains(type)) {
                throw malformed(INVALID_SYNTAX);
            }
            checkStrings(name, entry.value(), "Invalid principal in policy",
                    identifier -> !identifier.isBlank() && (!"AWS".equals(type) || isAwsPrincipal(identifier)));
        }
    }

    /** An {@code AWS} principal is everyone, an account id, or an ARN. Whether it exists is not checked. */
    private static boolean isAwsPrincipal(String identifier) {
        return WILDCARD.equals(identifier) || ACCOUNT_ID.matcher(identifier).matches()
                || AwsArnUtils.isArn(identifier);
    }

    /**
     * {@code "Condition": {"<operator>": {"<key>": <value or list of values>}}}, where each operator
     * is one IAM defines and appears once, every key is named and appears once in its operator, and
     * every value is a string, number or boolean.
     */
    private static void checkCondition(Value condition) {
        if (!(condition instanceof Members operators)) {
            throw malformed(INVALID_SYNTAX);
        }
        Set<String> seenOperators = new HashSet<>();
        for (Member block : operators.members()) {
            String operator = block.name();
            if (!seenOperators.add(operator)) {
                throw duplicateCondition(operator);
            }
            if (!IamPolicyEvaluator.isKnownConditionOperator(operator)
                    || IamPolicyEvaluator.isNullConditionOperatorWithIfExists(operator)) {
                throw malformed("Invalid Condition type : " + operator);
            }
            if (!(block.value() instanceof Members keys)) {
                throw malformed(INVALID_SYNTAX);
            }
            Set<String> seenKeys = new HashSet<>();
            for (Member key : keys.members()) {
                if (!seenKeys.add(key.name())) {
                    throw duplicateCondition(key.name());
                }
                if (key.name().isBlank()) {
                    throw malformed("Policy has an invalid condition key");
                }
                if (!isConditionValue(key.value())) {
                    throw malformed(INVALID_SYNTAX);
                }
            }
        }
    }

    private static boolean isConditionValue(Value value) {
        if (value instanceof Items list) {
            return list.items().stream().allMatch(S3BucketPolicyValidator::isScalarValue);
        }
        return isScalarValue(value);
    }

    private static boolean isScalarValue(Value value) {
        return value instanceof Scalar scalar && scalar.token() != JsonToken.VALUE_NULL;
    }

    /** One string or a nonempty array of strings, each accepted by {@code valid}; else {@code invalid}. */
    private static void checkStrings(String name, Value value, String invalid, Predicate<String> valid) {
        if (isText(value)) {
            if (!valid.test(textOf(value))) {
                throw malformed(invalid);
            }
            return;
        }
        if (!(value instanceof Items list)) {
            throw malformed(INVALID_SYNTAX);
        }
        if (list.items().isEmpty()) {
            throw empty(name);
        }
        for (Value entry : list.items()) {
            if (!isText(entry)) {
                throw malformed(INVALID_SYNTAX);
            }
            if (!valid.test(textOf(entry))) {
                throw malformed(invalid);
            }
        }
    }

    /** Element names match case-sensitively. */
    private static void rejectUnknownElements(Members object, Set<String> allowed) {
        for (Member member : object.members()) {
            if (!allowed.contains(member.name())) {
                throw malformed("Unknown field " + member.name());
            }
        }
    }

    /**
     * Rejects the first element that repeats, in document order. {@code NotPrincipal},
     * {@code NotAction} and {@code NotResource} take the place of their positive form, so S3 reports
     * pairing one with the other as a repeat of the positive form, whichever comes first.
     */
    private static void rejectRepeatedElements(Members object) {
        Set<String> seen = new HashSet<>();
        for (Member member : object.members()) {
            String slot = switch (member.name()) {
                case "NotPrincipal", "NotAction", "NotResource" -> member.name().substring("Not".length());
                default -> member.name();
            };
            if (!seen.add(slot)) {
                throw malformed("Statement/policy already has instance of " + slot);
            }
        }
    }

    private static AwsException missing(String element) {
        return malformed("Missing required field " + element);
    }

    /** Only an empty principal or action; S3 words an empty resource as one that matches no action. */
    private static AwsException empty(String element) {
        return switch (element) {
            case "Resource", "NotResource" -> malformed("Action does not apply to any resource(s) in statement");
            default -> malformed("Missing required field " + element + " cannot be empty!");
        };
    }

    private static AwsException duplicateCondition(String name) {
        return malformed("Duplicate condition element: " + name);
    }

    private static AwsException malformed(String message) {
        return new AwsException("MalformedPolicy", message, 400);
    }

    /** A JSON value as written: an object keeps every member, repeats included, in document order. */
    private sealed interface Value permits Members, Items, Scalar {
    }

    private record Member(String name, Value value) {
    }

    private record Members(List<Member> members) implements Value {

        List<Value> all(String name) {
            return members.stream().filter(member -> member.name().equals(name)).map(Member::value).toList();
        }

        Value first(String name) {
            return all(name).getFirst();
        }

        boolean has(String name) {
            return members.stream().anyMatch(member -> member.name().equals(name));
        }
    }

    private record Items(List<Value> items) implements Value {
    }

    private record Scalar(JsonToken token, String text) implements Value {
    }

    /** Reads the value at the parser's current token, leaving the parser on its last token. */
    private static Value read(JsonParser parser) throws IOException {
        JsonToken token = parser.currentToken();
        if (token == JsonToken.START_OBJECT) {
            List<Member> members = new ArrayList<>();
            for (JsonToken next = advance(parser); next != JsonToken.END_OBJECT; next = advance(parser)) {
                String name = parser.currentName();
                advance(parser);
                members.add(new Member(name, read(parser)));
            }
            return new Members(members);
        }
        if (token == JsonToken.START_ARRAY) {
            List<Value> items = new ArrayList<>();
            for (JsonToken next = advance(parser); next != JsonToken.END_ARRAY; next = advance(parser)) {
                items.add(read(parser));
            }
            return new Items(items);
        }
        return new Scalar(token, parser.getText());
    }

    private static JsonToken advance(JsonParser parser) throws IOException {
        JsonToken next = parser.nextToken();
        if (next == null) {
            throw new IOException("Unexpected end of policy document");
        }
        return next;
    }

    /** Whether anything but whitespace follows the document; unparseable content counts. */
    private static boolean hasMore(JsonParser parser) {
        try {
            return parser.nextToken() != null;
        } catch (IOException expected) {
            // Content after the document that does not even tokenize is still content after it.
            return true;
        }
    }

    private static boolean isText(Value value) {
        return value instanceof Scalar scalar && scalar.token() == JsonToken.VALUE_STRING;
    }

    private static String textOf(Value value) {
        return isText(value) ? ((Scalar) value).text() : null;
    }
}
