package io.floci.aws.testing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.AwsException;
import org.junit.jupiter.api.function.Executable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A fixture recorded by {@code tools/aws-capture/resource-policy}: what the operation answered to
 * each policy of the corpus, acceptance or the HTTP status, error code and message.
 *
 * <p>A fixture {@code <name>.json} may have a {@code <name>-gaps.tsv} beside it, one
 * {@code id<TAB>reason} line per case Floci knowingly answers differently, typically a check of
 * AWS's own on top of the policy grammar that Floci does not make. A listed case must still differ, so the list cannot
 * outlive the gap it records.
 */
public final class ResourcePolicyCapture {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** One recorded case. {@code status} is 0, {@code errorCode} and {@code message} null, when AWS accepted the policy. */
    public record Case(String id, String policy, int status, String errorCode, String message, String gap) {

        public boolean accepted() {
            return errorCode == null;
        }

        @Override
        public String toString() {
            return id;
        }
    }

    private ResourcePolicyCapture() {
    }

    /** The cases of a classpath fixture, such as {@code /resource-policy/s3-put-bucket-policy-aws.json}. */
    public static List<Case> load(String fixture) {
        JsonNode root = readJson(fixture);
        assertEquals("Verified on Live AWS", root.path("provenance").path("verification").textValue(), fixture);
        Map<String, String> gaps = readGaps(fixture.replaceFirst("\\.json$", "-gaps.tsv"));
        List<Case> cases = new ArrayList<>();
        for (JsonNode recorded : root.path("cases")) {
            String id = recorded.path("id").textValue();
            JsonNode error = recorded.path("error");
            assertTrue(error.isMissingNode() == recorded.path("accepted").asBoolean(), id);
            cases.add(new Case(id, recorded.path("policy").textValue(), error.path("status").asInt(),
                    error.path("code").textValue(), error.path("message").textValue(), gaps.remove(id)));
        }
        assertTrue(gaps.isEmpty(), "gap entries for cases the fixture does not hold: " + gaps.keySet());
        return cases;
    }

    /**
     * Runs {@code put}, which sends the recorded policy through the operation, and checks that it
     * answers as AWS did, or, for a listed gap, that it still does not.
     */
    public static void assertAnswersAsRecorded(Case recorded, Executable put) {
        AwsException actual = null;
        try {
            put.execute();
        } catch (AwsException e) {
            actual = e;
        } catch (Throwable t) {
            throw new AssertionError(recorded.id() + " failed outside the operation's own errors", t);
        }
        if (recorded.gap() != null) {
            boolean same = recorded.accepted() ? actual == null
                    : actual != null && recorded.status() == actual.getHttpStatus()
                    && recorded.errorCode().equals(actual.getErrorCode())
                    && recorded.message().equals(actual.getMessage());
            assertFalse(same, recorded.id() + " now answers as AWS did: remove it from the gaps file");
            return;
        }
        if (recorded.accepted()) {
            assertNull(actual, () -> recorded.id() + " was accepted by AWS");
            return;
        }
        assertNotNull(actual, () -> recorded.id() + " was rejected by AWS: " + recorded.message());
        assertEquals(recorded.errorCode(), actual.getErrorCode(), recorded.id());
        assertEquals(recorded.message(), actual.getMessage(), recorded.id());
        assertEquals(recorded.status(), actual.getHttpStatus(), recorded.id());
    }

    private static JsonNode readJson(String resource) {
        try (InputStream input = open(resource)) {
            assertNotNull(input, resource);
            return MAPPER.readTree(input);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, String> readGaps(String resource) {
        Map<String, String> gaps = new LinkedHashMap<>();
        try (InputStream input = open(resource)) {
            if (input == null) {
                return gaps;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.split("\t", 2);
                assertEquals(2, fields.length, resource + ": " + line);
                assertFalse(fields[1].isBlank(), resource + ": a gap needs a reason: " + line);
                assertNull(gaps.put(fields[0], fields[1]), resource + ": listed twice: " + fields[0]);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return gaps;
    }

    private static InputStream open(String resource) {
        return ResourcePolicyCapture.class.getResourceAsStream(resource);
    }
}
