Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBIM37TCAMGQENS5V4EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2B3B27E58
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:19 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e56ffd20d9sf52368345ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254177; cv=pass;
        d=google.com; s=arc-20240605;
        b=QHTjHVkEK4pmCuCZI+/fEQXJ7Y/4IfW2RunaCBN1k86+fu5fFQvsM7NUeqDSvNfdi7
         YD+wx2CiE49W0xftzVbvx9CoXwWMZWjz8A7ZZFViETpo3TJKv3Cgi5KeSBz1/BJWBc/Q
         XfyygSpmZl0+lU+H37oinpEi/GRNh87r8YriVXPuHwNXw9jhAdPvr9ros9rMeIkj7IPp
         zqtCrSCtia92oBPCFMbHImNu8rr3BdW/W7uHOug3/d9PC0bhWEI+c83AL4xf90b9oDFW
         iSFU4RMRM8sLRw//Y26rUuB2KNcI4fCaXwNu4C0Qk/4pEYCJW80ystN8YN40Pqd8A3s9
         Uj2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cyjkGfKTwoCZ4yn6TbkhmZK3M7u8TYp3lLGL730D9bQ=;
        fh=AlLy6yrkvGnNX+bo5NC6SXwwob6z+7EvgJek9PXeqOU=;
        b=aKoWsSsW4VFF7RlauZQ8WgqMI16nw3PFvi0sIIYkoca+eflk587VJlM5TDwQc+385f
         8Nt0eAd0kBn4+sKpEAKagxf5naPROzoFA8nuCEFrg+Az8Umh7MvtsYhbz7Cd9sEu1zRI
         huTQMgUkuzHUWdgypalIvie/W7mCoBW5K46fT+bMB+vQjIDje93RG3JRckspiosxOMny
         6G8r/jOSgN+qCcPuoURxKgpZdMezqoLtVS4XoRvhys5P6uDTMoIkT0ibSWOPS0LE8qB4
         0jUIE7IbwenoeOm2bhCCBO74W9JYe9s1SsZWyJtVT9UTeWGh4PmVFBAKfBVXMO2ivgLK
         Qr3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cUakuARx;
       spf=pass (google.com: domain of 3nw2faagkcyisgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nw2faAgKCYIsgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254177; x=1755858977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cyjkGfKTwoCZ4yn6TbkhmZK3M7u8TYp3lLGL730D9bQ=;
        b=KAxaStJ2on8ACO/BAoREOx2k/0DtwBO2nAyedXZVnyrNRPZIiHzKTNYQuAaWp0GQ42
         dJsriUetJj57H9fIL0PfbyhOuz+QZUlKhYTNbLnQU0a5AhY2cD0unkGXGEF5ca7ut81L
         AykrlqVnNH9mhNi4cpmh+khonWi++lpYDWU9fCa6N7fjb55cUyryi8g/1t7AhxYxTWwF
         SfYKwKF5iqPwekdYpJSbEp/oxiTkjdZ6C2o4ms5sOFAQqW0tStCeuurZ7BeNM8c5q+lU
         sMsungDs+yyqj9x7m3Teg1riVISo64K8PyXeV25smheAl/9U2T3eUzZRenh+ZpTWwjOy
         N8gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254177; x=1755858977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cyjkGfKTwoCZ4yn6TbkhmZK3M7u8TYp3lLGL730D9bQ=;
        b=OwqVRQG7y8lFXQYTituHUcPbf/wRONLmCmc2Z+DkC/uk0xCkVCge+IpLPvhSvHdEx2
         7KZ0wxUUOI3VrISYGPokHSehakRhR0Gw5rMQ8F9W71YFph/jxMXPMZG6Mkv9OslvE6cV
         KYjyvvnGMCC2f50v+Jo4yRuowVKcbamtBR+VDcYJeLuC4YW+v8PCs8GCprd9dR9agnwA
         TT/1qbm+X0qz8GKPA6j56UubfW6ENR9uaUfIYbhBa7EUJ576ooMgIl3f+G5GvtfMusIk
         +fIPnHETTlxNHKvrBJm2a5IoGMCV6Wlu+jl8ArHDzbro3hFsuU42AIjZ33+K3Zg3UzRV
         /ZhA==
X-Forwarded-Encrypted: i=2; AJvYcCWrsqX4iqV68T99GGn0KGYRdjCOG0ufX0KmfTB8sl2H2p497hkuMfqqWteQoNiJ9aS/qiorGQ==@lfdr.de
X-Gm-Message-State: AOJu0YyRb+zkTTomXGSdY+SaHzD3Dx6EDvzsmGIk7E7L8XJHduvDPgu0
	HwZgc0+qxGm+9KcFOYAca0gVb4XUI4VI7t0YfxBHeNI5c//cD9mUkoMy
X-Google-Smtp-Source: AGHT+IGaMkCNLzKg4sJmjYzQOV7THXBIKU7rs2Ktqv7V0bvgpQwEe7pp6mdOI6MR7AAAos5ptwfj5Q==
X-Received: by 2002:a05:6e02:1808:b0:3e5:3a15:93ae with SMTP id e9e14a558f8ab-3e57e8503b3mr29326025ab.6.1755254177530;
        Fri, 15 Aug 2025 03:36:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZesQWM3Zw5xjAIblYw6fjyuDZpynDYRNl3mp0QP52gAyA==
Received: by 2002:a05:6e02:1805:b0:3e0:5c71:88f9 with SMTP id
 e9e14a558f8ab-3e56fb3349dls13831775ab.1.-pod-prod-02-us; Fri, 15 Aug 2025
 03:36:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6/dxJK0JlmPgeJX8J58CCeL6pxHCIzrV4yC1VyXhJ9vs+uf5oJkEyDFmssAP0glurcZbiLYe0sH4=@googlegroups.com
X-Received: by 2002:a05:6e02:1949:b0:3e5:4631:5479 with SMTP id e9e14a558f8ab-3e57e9cfb76mr28101625ab.19.1755254176569;
        Fri, 15 Aug 2025 03:36:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254176; cv=none;
        d=google.com; s=arc-20240605;
        b=iamoJwSVCBbwQnV4ZpB/sb5zZSRmozd48u/27hCO//Zv2CI3zwRsdMyg0LXoHp67YA
         eKLJxXDiEf6MZLcZxqXVkgykzN8uL/5NUJW4XPPDRrYaAQVRDuI1UEDBbIBrHJDtcwDt
         FiGg2g39beeuV0Rl0ZluHnm2lUKQZ3M8No8+N/NK4c4ZzOHy6X9WbtollTcFc0AQ4aTD
         HawFXQFPxvgDFq5v6ujh8veCUAoWQ2DX6Nflx4aM9b8SWL+uUYQenO6QX6P3Kna4spOd
         LeUoXIFMC6R1HI5XmpMZRbwChc4woyJtVA9EP5aNnQQLNDXNr942g+k87IcfRdETcCkS
         AI4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BONUnu1NKFOsWRPuaKEG6QiZAgg+IitETz5ddIXNoOc=;
        fh=lBatl5GuTRcjo00r4HiZUiNvf7yBDVN5KIzCiFFXPbM=;
        b=VktT0KPixEeqy7F6V+HG0bnHGNgC3556iS5cDp/U11eullsuSBYmLEzTnxGwHoBSaR
         m9qLKxCwN0nVPfiS3G2dUKFdZM29oEWg0zkvWDdn0br1TmHHVvP2pzpS/5sxs3kKHKa3
         DfrFupckaAaj064eVnrY0oqgCSby5iv63FYfPxeho+1pc8B4xDplV0ingZQC1m4fuX9Y
         gY3BZ/c+SqDX3NtbdGO+yqprgG2+/+W5BdU9opl3kdWdiyt1WD5KuHToUWmT36W6yagd
         dHrX2QQy+/sSeHhrYdi48IbfkaL1b3BF8PY6E7y4VeOMuOp+kx9MycL1o+vvJZIrsJlR
         /JOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cUakuARx;
       spf=pass (google.com: domain of 3nw2faagkcyisgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nw2faAgKCYIsgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e3c7026si496505ab.0.2025.08.15.03.36.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nw2faagkcyisgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d75a77b69052e-4b109919a51so75858401cf.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkdctaYK1jB0HoWBD4DO2pj+6PAuX9+hf/E8n9QEt2d+VzvM1QQeEvZcLxAqY9T5ToF0uh8jGYx8k=@googlegroups.com
X-Received: from qtbih3.prod.google.com ([2002:a05:622a:6a83:b0:4ae:75d2:c21])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ac8:590a:0:b0:4b0:8057:1de9 with SMTP id d75a77b69052e-4b11e125b21mr15990631cf.3.1755254175914;
 Fri, 15 Aug 2025 03:36:15 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:36:00 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-4-marievic@google.com>
Subject: [PATCH v3 3/7] kunit: Pass parameterized test context to generate_params()
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cUakuARx;       spf=pass
 (google.com: domain of 3nw2faagkcyisgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nw2faAgKCYIsgxok1oimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

To enable more complex parameterized testing scenarios, the
generate_params() function needs additional context beyond just
the previously generated parameter. This patch modifies the
generate_params() function signature to include an extra
`struct kunit *test` argument, giving test users access to the
parameterized test context when generating parameters.

The `struct kunit *test` argument was added as the first parameter
to the function signature as it aligns with the convention of other
KUnit functions that accept `struct kunit *test` first. This also
mirrors the "this" or "self" reference found in object-oriented
programming languages.

This patch also modifies xe_pci_live_device_gen_param() in xe_pci.c
and nthreads_gen_params() in kcsan_test.c to reflect this signature
change.

Reviewed-by: David Gow <davidgow@google.com>
Reviewed-by: Rae Moar <rmoar@google.com>
Acked-by: Marco Elver <elver@google.com>
Acked-by: Rodrigo Vivi <rodrigo.vivi@intel.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-4-marievic@google.com/
- Commit message formatting.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-4-marievic@google.com/
    https://lore.kernel.org/all/20250729193647.3410634-5-marievic@google.com/
    https://lore.kernel.org/all/20250729193647.3410634-6-marievic@google.com/
- generate_params signature changes in xe_pci.c and kcsan_test.c were
  squashed into a single patch to avoid in-between breakages in the series.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 drivers/gpu/drm/xe/tests/xe_pci.c | 2 +-
 include/kunit/test.h              | 9 ++++++---
 kernel/kcsan/kcsan_test.c         | 2 +-
 lib/kunit/test.c                  | 5 +++--
 4 files changed, 11 insertions(+), 7 deletions(-)

diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests/xe_pci.c
index 1d3e2e50c355..62c016e84227 100644
--- a/drivers/gpu/drm/xe/tests/xe_pci.c
+++ b/drivers/gpu/drm/xe/tests/xe_pci.c
@@ -129,7 +129,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
  * Return: pointer to the next &struct xe_device ready to be used as a parameter
  *         or NULL if there are no more Xe devices on the system.
  */
-const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
+const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc)
 {
 	const struct xe_device *xe = prev;
 	struct device *dev = xe ? xe->drm.dev : NULL;
diff --git a/include/kunit/test.h b/include/kunit/test.h
index d2e1b986b161..b527189d2d1c 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -128,7 +128,8 @@ struct kunit_attributes {
 struct kunit_case {
 	void (*run_case)(struct kunit *test);
 	const char *name;
-	const void* (*generate_params)(const void *prev, char *desc);
+	const void* (*generate_params)(struct kunit *test,
+				       const void *prev, char *desc);
 	struct kunit_attributes attr;
 	int (*param_init)(struct kunit *test);
 	void (*param_exit)(struct kunit *test);
@@ -1691,7 +1692,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM(name, array, get_desc)						\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
@@ -1712,7 +1714,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)					\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index c2871180edcc..fc76648525ac 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
  * The thread counts are chosen to cover potentially interesting boundaries and
  * corner cases (2 to 5), and then stress the system with larger counts.
  */
-static const void *nthreads_gen_params(const void *prev, char *desc)
+static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
 {
 	long nthreads = (long)prev;
 
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 917df2e1688d..ac8fa8941a6a 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -700,7 +700,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
-			curr_param = test_case->generate_params(NULL, param_desc);
+			curr_param = test_case->generate_params(&test, NULL, param_desc);
 			test_case->status = KUNIT_SKIPPED;
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "KTAP version 1\n");
@@ -731,7 +731,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 				/* Get next param. */
 				param_desc[0] = '\0';
-				curr_param = test_case->generate_params(curr_param, param_desc);
+				curr_param = test_case->generate_params(&test, curr_param,
+									param_desc);
 			}
 			/*
 			 * TODO: Put into a try catch. Since we don't need suite->exit
-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-4-marievic%40google.com.
