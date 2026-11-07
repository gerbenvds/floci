package io.floci.aws.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudFormationYamlParserTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode parse(String yaml) throws Exception {
        return new CloudFormationYamlParser(mapper).parse(yaml);
    }

    @Test
    void cidrShorthandExpandsToFnCidr() throws Exception {
        JsonNode cidr = parse("Value: !Cidr [\"10.0.0.0/16\", 4, 8]").get("Value").get("Fn::Cidr");
        assertTrue(cidr.isArray());
        assertEquals("10.0.0.0/16", cidr.get(0).asText());
        assertEquals(4, cidr.get(1).asInt());
        assertEquals(8, cidr.get(2).asInt());
    }

    @Test
    void getAzsShorthandExpandsToFnGetAZs() throws Exception {
        assertEquals("", parse("Value: !GetAZs \"\"").get("Value").get("Fn::GetAZs").asText());
    }

    @Test
    void cidrShorthandMatchesLongFormInNestedSelect() throws Exception {
        JsonNode shorthand = parse("CidrBlock: !Select [1, !Cidr [!GetAtt Vpc.CidrBlock, 4, 8]]");
        JsonNode longForm = parse("""
            CidrBlock:
              Fn::Select:
                - 1
                - Fn::Cidr:
                    - Fn::GetAtt: [Vpc, CidrBlock]
                    - 4
                    - 8
            """);
        assertEquals(longForm, shorthand);
    }

    @Test
    void getStackOutputShorthandExpandsToFnGetStackOutput() throws Exception {
        JsonNode shorthand = parse("""
            SubnetId: !GetStackOutput
              StackName: Producer
              OutputName: SubnetId
              Region: us-west-2
            """);
        JsonNode longForm = parse("""
            SubnetId:
              Fn::GetStackOutput:
                StackName: Producer
                OutputName: SubnetId
                Region: us-west-2
            """);
        assertEquals(longForm, shorthand);
        assertEquals("Producer", shorthand.get("SubnetId").get("Fn::GetStackOutput").get("StackName").asText());
    }

    @Test
    void unquotedDateStaysLiteralString() throws Exception {
        JsonNode doc = parse("""
            PolicyDocument:
              Version: 2012-10-17
              Statement: []
            """);
        JsonNode version = doc.get("PolicyDocument").get("Version");
        assertTrue(version.isTextual());
        assertEquals("2012-10-17", version.asText());
    }

    @Test
    void unquotedDateTimeStaysLiteralString() throws Exception {
        JsonNode doc = parse("""
            Start: 2001-12-14t21:59:43.10-05:00
            Spaced: 2001-12-14 21:59:43.10 -5
            Short: 2002-1-1
            """);
        assertEquals("2001-12-14t21:59:43.10-05:00", doc.get("Start").asText());
        assertEquals("2001-12-14 21:59:43.10 -5", doc.get("Spaced").asText());
        assertEquals("2002-1-1", doc.get("Short").asText());
        assertTrue(doc.get("Start").isTextual());
    }

    @Test
    void timestampInsideIntrinsicStaysLiteralString() throws Exception {
        JsonNode join = parse("Value: !Join [\"-\", [2012-10-17, !Ref Suffix]]").get("Value").get("Fn::Join");
        assertEquals("2012-10-17", join.get(1).get(0).asText());
        assertTrue(join.get(1).get(0).isTextual());
    }

    @Test
    void nonTimestampScalarsKeepTheirTypes() throws Exception {
        JsonNode doc = parse("""
            Count: 3
            Ratio: 1.5
            Enabled: true
            Nothing: null
            """);
        assertTrue(doc.get("Count").isInt());
        assertTrue(doc.get("Ratio").isDouble());
        assertTrue(doc.get("Enabled").isBoolean());
        assertTrue(doc.get("Nothing").isNull());
    }
}
