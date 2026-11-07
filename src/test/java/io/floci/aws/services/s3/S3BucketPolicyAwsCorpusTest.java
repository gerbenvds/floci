package io.floci.aws.services.s3;

import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.testing.ResourcePolicyCapture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.util.List;

/**
 * Replays what S3 answered when the resource-policy corpus was sent to {@code PutBucketPolicy}.
 * Re-record with {@code tools/aws-capture/resource-policy/capture_resource_policies.py --service s3};
 * cases S3 rejects for checks of its own that Floci does not make are listed in
 * {@code s3-put-bucket-policy-aws-gaps.tsv}.
 */
class S3BucketPolicyAwsCorpusTest {

    private static final String FIXTURE = "/resource-policy/s3-put-bucket-policy-aws.json";
    /** The bucket name every recorded policy and message uses. */
    private static final String BUCKET = "floci-policy-capture";

    @TempDir
    Path tempDir;

    private S3Service s3Service;

    @BeforeEach
    void setUp() {
        s3Service = new S3Service(new InMemoryStorage<>(), new InMemoryStorage<>(), tempDir.resolve("s3"), false);
        s3Service.createBucket(BUCKET, "us-east-1");
    }

    static List<ResourcePolicyCapture.Case> recorded() {
        return ResourcePolicyCapture.load(FIXTURE);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("recorded")
    void putBucketPolicyAnswersAsS3Did(ResourcePolicyCapture.Case recorded) {
        ResourcePolicyCapture.assertAnswersAsRecorded(recorded,
                () -> s3Service.putBucketPolicy(BUCKET, recorded.policy()));
    }
}
