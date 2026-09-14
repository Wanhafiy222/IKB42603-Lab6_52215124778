# IKB42603 Lab 6: Object Storage Security and the Data Security Lifecycle

**Student ID:** 52215124778  
**Course:** Cloud Computing Security Essentials  
**Platform:** Kali Linux, Bash, Docker, AWS CLI v2 and LocalStack Pro  
**Evidence date:** 14 September 2026  
**Repository:** [IKB42603-Lab6_52215124778](https://github.com/Wanhafiy222/IKB42603-Lab6_52215124778)

This report describes the results visible in the repository screenshots. Expected AWS behaviour is distinguished from the actual LocalStack results. Evidence labels follow the filenames in the repository.

## Environment and resources

| Setting | Value |
|---|---|
| Endpoint | http://localhost:4566 |
| Region | us-east-1 |
| Account | 000000000000 |
| Bucket | miit-patient-records-29409 |
| IAM user | DataAnalyst |
| KMS key | 3159f871-1f55-4a59-8f79-d269bbac9776 |

The lab setup uses an activated LocalStack container with IAM enforcement requested through ENFORCE_IAM=1. The repository does not include a container inspection or a successful analyst identity check, so enforcement and the caller identity cannot be verified from the submitted screenshots alone.

## Task 1 - Classify data before storage

Three sample objects were uploaded under public, internal and confidential prefixes. The object listing shows:

| Object key | Size (bytes) |
|---|---:|
| confidential/record.txt | 48 |
| internal/roster.txt | 29 |
| public/notice.txt | 29 |

**Evidence 1A - Object listing**

![Evidence 1A – list-objects-v2 table](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%201A%20%E2%80%93%20list-objects-v2%20table.jpeg)

The confidential object has the tag classification=confidential.

**Evidence 1B - Confidential classification tag**

![Evidence 1B – confidential classification tag](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%201B%20%E2%80%93%20confidential%20classification%20tag.jpeg)

### Data classification table

| Classification | Who may read it | Impact if leaked | Control implemented or demonstrated |
|---|---|---|---|
| Public | General public when deliberately published | Low | Classification and controlled publication; Block Public Access configured during remediation |
| Internal | Authorised staff | Medium | Bucket-policy Allow scoped to internal/* |
| Confidential | Authorised personnel | High | Analyst-specific explicit Deny configured; SSE-KMS on later uploads; versioning and lifecycle rules |

Classification tags label data but do not enforce access by themselves. Prefixes are parts of object keys, not filesystem folders. The policies were demonstrated at different stages and some were subsequently removed.

## Task 2 - Reproduce the public bucket breach

The PublicReadEverything bucket policy allowed s3:GetObject for Principal "*" on every object in the bucket. An anonymous curl request returned HTTP 200 and printed:

~~~text
Patient: Ahmad bin Ali, Diagnosis: confidential
~~~

**Evidence 2 - Anonymous HTTP 200 and leaked confidential record**

![Evidence 2 – HTTP 200 + leaked confidential record](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%202%20%E2%80%93%20HTTP%20200%20%2B%20leaked%20confidential%20record.jpeg)

The exposure came from the unrestricted Principal "*" in the Allow statement. It included anonymous callers, while the resource ending in /* exposed all object prefixes.

## Task 3 - Block public access

The public policy was removed and all four bucket-level Block Public Access settings were enabled:

- BlockPublicAcls
- IgnorePublicAcls
- BlockPublicPolicy
- RestrictPublicBuckets

**Evidence 3A - All four Block Public Access settings enabled**

![Evidence 3A – all four Block Public Access values true](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%203A%20%E2%80%93%20all%20four%20Block%20Public%20Access%20values%20true.jpeg)

The public policy was then reapplied as a test. The anonymous read still returned HTTP 200.

**Evidence 3B - Anonymous read retest**

![Evidence 3B – policy attempt + anonymous read retest](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%203B%20%E2%80%93%20policy%20attempt%20%2B%20anonymous%20read%20retest.jpeg)

LocalStack stored the configuration but did not prevent public access in this test. The lab permits this result with an explanation. On real AWS, BlockPublicPolicy would reject a new public bucket policy. A preventative guardrail blocks an insecure configuration before exposure, while a detective control reports the issue after it exists.

The lab's next remediation step is to replace the public policy with an account-scoped Allow for internal/*. A separate screenshot of that replacement is not included in this repository.

## Task 4 - Identity policy versus resource policy

The analyst IAM policy grants s3:GetObject and s3:ListBucket on Resource "*". The bucket policy has two statements:

| Statement | Effect | Scope |
|---|---|---|
| AllowAnalystInternal | Allow | DataAnalyst reading internal/* |
| DenyAnalystConfidential | Deny | DataAnalyst performing s3:* on confidential/* |

### Evidence 4A - IAM policy and credential setup attempt

The repository's setup screenshot shows the IAM policy commands, an EntityAlreadyExists response, and access-key creation. It also shows a UserId entered in place of an access key and literal credential placeholders configured afterward.

This screenshot is troubleshooting evidence, not proof of a correctly configured analyst profile. It contains generated credentials and is intentionally not embedded in this report.

**Evidence 4B - Internal and confidential reads both succeeded**

![Evidence 4B– InternalandConfidentialReadTests_BothRequestsSucceeded](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%204B%E2%80%93%20InternalandConfidentialReadTests_BothRequestsSucceeded.jpeg)

Both requests returned object metadata. The screenshot does not show AccessDenied for the confidential object.

**Evidence 4C - Bucket policy allowing internal reads and denying confidential access**

![Evidence 4C – Bucket Policy Allowing Internal Reads and Explicitly Denying Confidential Access](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%204C%20%E2%80%93%20Bucket%20Policy%20Allowing%20Internal%20Reads%20and%20Explicitly%20Denying%20Confidential%20Access.jpeg)

The screenshot also shows the subsequent policy removal command.

### Policy evaluation

Requests start with implicit deny. An applicable explicit Deny overrides an Allow; otherwise, an applicable Allow can grant access in this same-account example.

- **Internal request:** both the IAM policy and AllowAnalystInternal allow the read.
- **Confidential request:** DenyAnalystConfidential should override the IAM Allow.

The observed successful confidential read cannot be attributed solely to a LocalStack limitation because the saved credential setup is incorrect and the caller identity was not verified. A corrected profile, an STS identity check showing user/DataAnalyst, and an enforcement check are needed before drawing that conclusion.

## Task 5 - Default SSE-KMS encryption

A dedicated KMS key was configured as the bucket's default encryption key with BucketKeyEnabled set to true. A new object, confidential/record-v2.txt, was uploaded without encryption flags.

The head-object result shows aws:kms, the configured key ARN and True for BucketKeyEnabled.

**Evidence 5 - SSE-KMS and KMS key ID**

![Evidence 5 – awskms + KMS key ID](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%205%20%E2%80%93%20awskms%20%2B%20KMS%20key%20ID.jpeg)

The result demonstrates default SSE-KMS for this new upload. Changing bucket defaults does not retroactively apply the new key to existing objects. The original Task 1 version was still shown as AES256 in Task 7.

## Task 6 - Presigned URLs and the SecureTransport condition

### Presigned URL

An initial URL variable contained the placeholder PASTE_PRESIGNED_URL_HERE. The corrected command captured a freshly generated URL automatically:

~~~bash
URL=$(aws $EP s3 presign \
  "s3://$BUCKET/internal/roster.txt" --expires-in 60)

curl -sS -w ' <-- HTTP %{http_code}\n' "$URL"
sleep 65
curl -sS -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
~~~

Both the initial request and the request after 65 seconds returned HTTP 200.

**Evidence 6A - Presigned URL access before and after expiry**

![Evidence6-presigned-url](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence6-presigned-url.jpeg)

X-Amz-Expires specifies the lifetime in seconds from X-Amz-Date. The signature binds the signed request details to the signer's credentials. Someone holding the URL can use the permitted request while it is valid, subject to effective permissions.

LocalStack did not enforce expiry in this test. Its S3 documentation states that presigned URL signature and expiry validation are disabled by default. [LocalStack S3 documentation](https://docs.localstack.cloud/aws/services/s3/)

### SecureTransport condition

The lab policy denies s3:* on the bucket and its objects when aws:SecureTransport is false. Since the endpoint uses HTTP, the intended result is an access-denied response.

**Evidence 6B - SecureTransport test output and policy removal**

![Evidence6-secure-transport-condition-trap](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence6-secure-transport-condition-trap.jpeg)

The submitted screenshot shows a successful object listing followed by a delete-bucket-policy command. It does not demonstrate the expected bucket-wide denial or establish why the request succeeded.

The intended lesson is that a condition must be evaluated in its actual environment: HTTP makes aws:SecureTransport false, while HTTPS makes it true. A verified denial test is still needed to demonstrate enforcement. [AWS bucket policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)

## Task 7 - Versioning, delete markers and data remanence

Versioning was enabled. Two further revisions of confidential/record.txt were uploaded: a diagnosis revision and a redacted revision.

**Evidence 7A - Version listing**

![Evidence 7A – version listing](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%207A%20%E2%80%93%20version%20listing.jpeg)

The listing shows three data versions. The original object has version ID null because it was uploaded before versioning was enabled. The latest redacted revision is 43 bytes; the two older versions are 48 bytes.

A normal delete created a delete marker.

**Evidence 7B - Current delete marker**

![Evidence 7B – delete marker](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%207B%20%E2%80%93%20delete%20marker.jpeg)

An ordinary read then failed with NoSuchKey. Reading version ID null succeeded and recovered the original unredacted record.

**Evidence 7C - Recovery of the original record after normal deletion**

![Evidence 7C – recovered.txt containing original diagnosis](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%207C%20%E2%80%93%20recovered.txt%20containing%20original%20diagnosis.jpeg)

This demonstrates data remanence: a delete marker hides the current object but leaves earlier versions recoverable. Redacting a newer version does not redact older versions.

The lab also calls for permanent deletion of the null version. The repository does not include the subsequent version listing proving that removal, so this report does not claim it was verified.

## Task 8 - Lifecycle and cryptographic erasure

### Lifecycle rules

| Rule | Configuration | Observed status |
|---|---|---|
| RetireConfidentialRecords | confidential/ current-object expiration after 365 days; noncurrent-version expiration after 30 days | Enabled |
| AbortIncompleteUploads | Abort incomplete multipart uploads after 7 days | Enabled |

**Evidence 8A - Lifecycle configuration and enabled rules**

![Evidence 8A – lifecycle rules](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%208A%20%E2%80%93%20lifecycle%20rules.jpeg)

These outputs prove that the retention rules were configured. They do not prove future expiration has already occurred. In a versioned bucket, current-version expiration generally adds a delete marker; noncurrent-version expiration addresses older data versions.

### Key state and decrypt test

The key initially showed Enabled and a baseline KMS decrypt succeeded. The key was then disabled and scheduled for deletion with a seven-day waiting period.

**Evidence 8B - KMS key pending deletion**

![Evidence 8B – key PendingDeletion + deletion date](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%208B%20%E2%80%93%20key%20PendingDeletion%20%2B%20deletion%20date.jpeg)

The output shows:

~~~text
KeyState: PendingDeletion
DeletionDate: 2026-09-21T06:08:34.701286-04:00
PendingWindowInDays: 7
~~~

LocalStack still returned the SSE-KMS object through S3. A direct KMS decrypt of the previously prepared ciphertext failed with KMSInvalidStateException because the key was pending deletion.

**Evidence 8C - S3 read succeeds but direct KMS decrypt fails**

![Evidence 8C if S3 read succeeds – failed KMS decrypt + key state](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Evidence%208C%20if%20S3%20read%20succeeds%20%E2%80%93%20failed%20KMS%20decrypt%20%2B%20key%20state.jpeg)

The direct KMS test demonstrates enforcement of key unavailability at the KMS layer, as permitted by the lab's fallback procedure.

Cryptographic erasure removes the encryption key so ciphertext depending solely on that key becomes unusable. PendingDeletion proves scheduled deletion and current KMS unavailability, not completed irreversible key destruction. Plaintext downloads and objects encrypted under other keys remain outside this protection. [AWS KMS key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)

## Final verification

~~~bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="

aws $EP s3api get-public-access-block --bucket "$BUCKET" \
  --query 'PublicAccessBlockConfiguration' --output text

aws $EP s3api get-bucket-versioning --bucket "$BUCKET" --output text

aws $EP s3api get-bucket-encryption --bucket "$BUCKET" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text

aws $EP s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --query 'Rules[].[ID,Status]' --output text

aws $EP kms describe-key --key-id "$KEY_ID" \
  --query 'KeyMetadata.KeyState' --output text
~~~

**Evidence - Final verification output**

![Final Verification Output](https://raw.githubusercontent.com/Wanhafiy222/IKB42603-Lab6_52215124778/71e8a1b55a8691533d730415a38b5723818a8625/Final%20Verification%20Output.jpeg)

| Check | Observed result |
|---|---|
| Block Public Access | All four flags True |
| Versioning | Enabled |
| Default encryption | aws:kms with key 3159f871-1f55-4a59-8f79-d269bbac9776 |
| RetireConfidentialRecords | Enabled |
| AbortIncompleteUploads | Enabled |
| KMS key state | PendingDeletion |

These checks confirm configuration and key state. They do not prove anonymous access was ultimately refused, IAM denial was enforced, HTTPS-only access was enforced, or every data copy was erased.

## Short answers

### Q1. Which element caused the public exposure?

The unrestricted Principal "*" in the Allow statement included anonymous users. A broad IAM policy grants permissions to its attached identity, while this resource policy directly granted public reads across all object prefixes.

### Q2. How do identity and resource policies differ?

An identity policy defines what a user or role may do. A resource policy defines access to a resource. Both policies should allow the internal read, while the bucket policy's explicit Deny should block the confidential read. The screenshots show both reads succeeding, with the analyst credential setup still unverified.

### Q3. Why is Block Public Access a guardrail?

It is a preventative control that restricts public policies and ACLs. With many engineers, it reduces the chance that a single configuration mistake exposes data. It acts before exposure instead of relying only on detection and later repair.

### Q4. Does SSE-KMS protect against an authorised analyst?

SSE-KMS protects stored data, but S3 returns plaintext to a caller with effective GetObject access and the required KMS decrypt permission. GetObject alone is not enough for SSE-KMS data. In Task 4, the explicit bucket Deny is the intended access barrier, and the original object existed before the SSE-KMS default was applied. [AWS SSE-KMS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)

### Q5. Why is normal deletion insufficient, and what are two stronger mechanisms?

Task 7 recovered the original record because normal deletion only added a delete marker. One mechanism is to delete every relevant version by ID, address replicas and backups, and verify their absence. Another is completed destruction of the key protecting all relevant encrypted copies. Plaintext exports and copies using other keys must also be addressed; scheduled deletion alone is not completed erasure.

### Q6. Which three commands provide audit evidence?

| Command | Control evidenced |
|---|---|
| aws $EP s3api get-public-access-block --bucket "$BUCKET" | The four configured public-access guardrails |
| aws $EP s3api get-bucket-encryption --bucket "$BUCKET" | Default encryption algorithm and selected KMS key |
| aws $EP s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" | Configured retention, noncurrent-version expiration and incomplete-upload rules |

Configuration outputs should be supported by behavioural tests where enforcement needs to be demonstrated.

## Evidence review checklist

- [x] Task 1: object listing and confidential tag.
- [x] Task 2: anonymous HTTP 200 and leaked record.
- [x] Task 3: four flags enabled and actual anonymous retest.
- [x] Task 4: setup attempt, both successful reads and explicit bucket Deny documented.
- [ ] Task 4: corrected analyst identity and enforcement verified; deny test repeated.
- [x] Task 5: aws:kms and key ID.
- [x] Task 6: corrected presigned URL test before and after expiry.
- [ ] Task 6: successful enforcement of the SecureTransport denial demonstrated.
- [x] Task 7: versions, delete marker and original-version recovery.
- [ ] Task 7: permanent null-version removal verified by a subsequent listing.
- [x] Task 8: lifecycle rules and PendingDeletion state.
- [x] Task 8: failed direct KMS decrypt as fallback evidence.
- [x] Final verification output.

Checkboxes record what the submitted evidence demonstrates, not an assumption that every test passed. No cleanup is included in this report.

## Sources

- [Repository evidence snapshot](https://github.com/Wanhafiy222/IKB42603-Lab6_52215124778/tree/71e8a1b55a8691533d730415a38b5723818a8625) - screenshots reviewed for this report.
- IKB42603 Lab 6: Object Storage Security and the Data Security Lifecycle - supplied lab manual.
- Official AWS and LocalStack references are linked beside the relevant explanations.

