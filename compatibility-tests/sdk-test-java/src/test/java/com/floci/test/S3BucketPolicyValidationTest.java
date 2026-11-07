package com.floci.test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.PutBucketPolicyRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** S3 PutBucketPolicy grammar validation, driven through the real AWS SDK. */
@DisplayName("S3 bucket policy validation")
class S3BucketPolicyValidationTest {

    @Test
    @DisplayName("PutBucketPolicy rejects a statement without a principal as MalformedPolicy and stores nothing")
    void rejectsStatementWithoutPrincipal() {
        String bucket = TestFixtures.uniqueName("sdk-policy-validation");
        String policy = """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}
                """.formatted(bucket);

        try (S3Client s3 = TestFixtures.s3Client()) {
            s3.createBucket(CreateBucketRequest.builder().bucket(bucket).build());

            assertThatThrownBy(() -> s3.putBucketPolicy(
                    PutBucketPolicyRequest.builder().bucket(bucket).policy(policy).build()))
                    .isInstanceOfSatisfying(S3Exception.class, exception -> {
                        assertThat(exception.statusCode()).isEqualTo(400);
                        assertThat(exception.awsErrorDetails().errorCode()).isEqualTo("MalformedPolicy");
                        assertThat(exception.awsErrorDetails().errorMessage())
                                .isEqualTo("Missing required field Principal");
                    });

            assertThatThrownBy(() -> s3.getBucketPolicy(GetBucketPolicyRequest.builder().bucket(bucket).build()))
                    .isInstanceOfSatisfying(S3Exception.class, exception ->
                            assertThat(exception.awsErrorDetails().errorCode()).isEqualTo("NoSuchBucketPolicy"));
        } finally {
            try (S3Client cleanup = TestFixtures.s3Client()) {
                cleanup.deleteBucket(DeleteBucketRequest.builder().bucket(bucket).build());
            } catch (Exception ignored) {
                // The compatibility runner may retain state after a failed assertion.
            }
        }
    }
}
