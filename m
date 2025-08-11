Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBE6Y5HCAMGQEEB6ZP3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A409CB21819
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:17:57 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-7430a0acfddsf8538634a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:17:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950676; cv=pass;
        d=google.com; s=arc-20240605;
        b=bbkaloE870D3jOkMNpweuJSyUrWt0/LA/u8SPfkcPSi6rPK29Ycgpe8lL7LAf4bUla
         ifKKNV5QAfGm26mum2FfSm1MNiumNJiS5HgY+2VjqXzHM2pbqRa79kGN6mYm5iga/JLk
         U0guRzPY/5Zr7LrowccyGAw/edSanE+tEFlHA+xXi2kSzRUThGdKPoRJUpDnIzG/A2tZ
         DtS1y4H8+F5KnJHxjNaAkPt+o5Xric79ZCdGqXc5IBICQnb1JSH2z1R5Ti4gG0DHlHQG
         dQU/7+TQDmYK2bCdzcsvYUVRjQF5dCB99I/KRYCHvqKinAf4pbnVBqvXrXwAPaiT6xAu
         i0eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=l+4Lf6p/46IUoli1d/aMoNg37JWLDXDFvxrE6UnUIRk=;
        fh=DWCH+bMuayhSDWbddy6F85HqLN7TLXqCQeOpOnutEX8=;
        b=WDeJA53L94Day7WFj0Uw5b6PbDWttzl2WaXen1yFswB4JWPbETBiTMAZf2OhKVoka3
         X+l1HX+fq/TTAQp2WjSeTr3wwQ47UFYQN8I0Tp3KGS27S9iVkvfAkhe21/SfJhSQoQBV
         12La8YjJkcgR2IV6oR2d21fQziOHwCWUEVISxReo4xDKkvWXR+gIXfMcdjJRA+9JJt7w
         pHrCJ4MUE0Cd9S3ttzY/Tvd0XQ+Kw2EYYgsvwO06PNvygYTCT+zIQAfc0B7Ae3VSGvVq
         zGjYfFKEmzKJSHidX/9+ySdWCxSjoOBWf5rCqNgHJF3TpmFOLDV91yFUm2ox89CebRUL
         E1kA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vBiL8eBZ;
       spf=pass (google.com: domain of 3emyaaagkcz8l9qhduhbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EmyaaAgKCZ8L9QHDUHBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950676; x=1755555476; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l+4Lf6p/46IUoli1d/aMoNg37JWLDXDFvxrE6UnUIRk=;
        b=wZzyUBlvahu8nPJWDQhqKTUQQtRH3IG+XbnMEpvSuX4Kn2Tw1NMJtS1hha6F7Er2uy
         fGzT96gyVj346+m9ULlge3yE66UDTd84ZuF3bstdMKYuzHCewRc29zwwfcjf9prpJpco
         dq8IcGD8svcqi8PG8s+Bl2nD6H3hI5P7jUR8NewMBL/Cyn38XsMU4xOqUpbXDq+wVZUF
         peapJs3+1RzldyQYkMmtwD8inUKWr1xRLGtODB0F3rX6t+89bz8JCZ4G1W+WlQpAJl35
         45Txdr0lqaHRl1dMCVL9xlWiqxcxlJD7ZL2EOuVFAFsSNFLZH1uEk45CsS13IOfhCGjM
         CmIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950676; x=1755555476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l+4Lf6p/46IUoli1d/aMoNg37JWLDXDFvxrE6UnUIRk=;
        b=VYnJIh6+a3mWgYcHLSdCwDeH8fjVg2x67HjTssz6mw7m6VmdP/PwGr6T8FmIf9aojE
         3Xrcht3eKWn46Mj5Loh/RU8QjxWe8NgWW9XshFViZyyxpvuKDtG9ULkIJCiMX4jHdeEv
         Tfv3AyLuoQqRs5GlemQWZW57KixSAkG2z/q5DJszwgl7mbtLwZ6SykkBclopN4egZnbX
         CThB9WbkD4w1nGVOX23iaP+jI/DI/K8JLnbRkIXOwsaWMYQeP0iExvRP7jZyj/QsS46u
         tMLTb/eaVqxXW65YHiTMa+FfP/7SuGw7Jt9t1Bp8ijYhknT+qagNTCH4115e33oYGVKv
         AldQ==
X-Forwarded-Encrypted: i=2; AJvYcCXyjhXb3EiCDENfcFCshlMtRGMEFk2BPumxNrKU69CFxfkZeSj6IJjxXoqUVN26+f9IbOmbYg==@lfdr.de
X-Gm-Message-State: AOJu0Yx/65f0Lds3tjMZOCL088/jVhOYPZtTGqLwjSP/HoZadLdjOOO5
	+kLdWiubRw/sJRqlGdxe7EKcjjAxSNgxXryU9d8gxHxZ/Bpd/N4EIEwC
X-Google-Smtp-Source: AGHT+IE4rIfEJJsOc8bSTvutw46rCE0mMkh/oVrxEqn9omuTgDzIGTLSWI2QaWrH/nC4hLoL+inVQg==
X-Received: by 2002:a05:6830:7106:b0:72b:9d8d:5881 with SMTP id 46e09a7af769-7432c9b6311mr9544588a34.28.1754950676136;
        Mon, 11 Aug 2025 15:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMKnB+CzeVMw1dhFexlAeGoXVN9/ud++KYJysazQlGnw==
Received: by 2002:a05:6870:1495:b0:306:e7d7:f921 with SMTP id
 586e51a60fabf-30bfe748737ls2517663fac.1.-pod-prod-08-us; Mon, 11 Aug 2025
 15:17:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6N20mrwHszJ9eDAxMjgFUyHRvyhBw8/7QDt6MAep3lrk3AMZ4ruzmwOhBNXIX35U1pwj61jGDVpA=@googlegroups.com
X-Received: by 2002:a05:6830:3482:b0:73f:f3a2:212b with SMTP id 46e09a7af769-7432c74263fmr6775696a34.5.1754950675301;
        Mon, 11 Aug 2025 15:17:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950675; cv=none;
        d=google.com; s=arc-20240605;
        b=fX1vYFXc5iXoWTLo8uhdLGSC3Buxb0LPraMz1mmfBgY2zUAuF7jzfLkZD3IBMAuQm6
         +fmYeWbB5dN2P4Bm5idqZzzHOWBHjKsCJLnw2xSvVHaw+T0gcqVJcio08/Mt+IyC+qw1
         KJqwdnH2+7yR+Gcp2b814oMPDtVFxxaGOHM7ioMRU1+jRgHrZhJOAa/ce2PC9iLLkmtz
         QlePCHE55FLegO1ooV1YECHz4d+I5/RqlShVl8saDSssTbFKPnLdXpEf4Ef783vImpaS
         WDsiGN3HxuQ3jdnjZCJZrVEnQAGoeORnfYllSOcSsu/t2FjeL4tiL1kqadj8QFFPHdiD
         PR3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=c1k/A69TckTlEbMn2yQThZDMwfxta59hKgkCx2fsjOU=;
        fh=pTXpYqU5PNzv2kckQnI8c5ZIJl4el+GK0c0+nrmwpDo=;
        b=RZ8N/PvPlbJlfJTGq/K+pyEVcyxqrnXb7qVNLmij8WU0/jX2mYJekxRmm/kdhScqjg
         dj8c3lRTTn1ikDRJdi1WhyHSpEg13y3gVDwzr5ZQDiwYc+P0UrKCcHziapE4LcXD2cQo
         A1xUiHW9Dl7ugZb4RhELZwIekVucUpt2EH9C4AaEoSS4jCntcPwYFFTuU2zb+q4IAEQH
         jswcKPTaH+lSVq4oBrFRrMS4swyXF9E2P7z83pT3N9ixSgLH5YUa0SpnybLGCKHKotYW
         rdLlGwJFLhellKoeul+h9sERlLooluzz/tUFFg0klcrXVmgvufXjrkFNQzYcZ2lr2R0o
         6dYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vBiL8eBZ;
       spf=pass (google.com: domain of 3emyaaagkcz8l9qhduhbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EmyaaAgKCZ8L9QHDUHBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bbb359537si763219fac.3.2025.08.11.15.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:17:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3emyaaagkcz8l9qhduhbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d75a77b69052e-4b065932d0bso145847221cf.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:17:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUHik6DxnpGrlMaOd5VzNtN/2kk07UHD4+nxEdvAk3VcbVmh8/57bFp95xr/dg6hwj59p/D7dUywbs=@googlegroups.com
X-Received: from qtbfd13.prod.google.com ([2002:a05:622a:4d0d:b0:4ab:b3a4:9650])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:18a6:b0:4ab:66c5:b265 with SMTP id d75a77b69052e-4b0ecaeac57mr23998721cf.0.1754950674545;
 Mon, 11 Aug 2025 15:17:54 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:35 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-4-marievic@google.com>
Subject: [PATCH v2 3/7] kunit: Pass parameterized test context to generate_params()
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
 header.i=@google.com header.s=20230601 header.b=vBiL8eBZ;       spf=pass
 (google.com: domain of 3emyaaagkcz8l9qhduhbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EmyaaAgKCZ8L9QHDUHBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--marievic.bounces.google.com;
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

To enable more complex parameterized testing scenarios,
the generate_params() function needs additional context
beyond just the previously generated parameter. This patch
modifies the generate_params() function signature to
include an extra `struct kunit *test` argument, giving
test users access to the parameterized test context when
generating parameters.

The `struct kunit *test` argument was added as the first parameter
to the function signature as it aligns with the convention
of other KUnit functions that accept `struct kunit *test` first.
This also mirrors the "this" or "self" reference found
in object-oriented programming languages.

This patch also modifies xe_pci_live_device_gen_param()
in xe_pci.c and nthreads_gen_params() in kcsan_test.c
to reflect this signature change.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- generate_params signature changes in
  xe_pci.c and kcsan_test.c were squashed
  into a single patch to avoid in-between
  breakages in the series.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

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
index 49a5e6c30c86..01b20702a5a2 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -695,7 +695,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
-			curr_param = test_case->generate_params(NULL, param_desc);
+			curr_param = test_case->generate_params(&test, NULL, param_desc);
 			test_case->status = KUNIT_SKIPPED;
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "KTAP version 1\n");
@@ -726,7 +726,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 				/* Get next param. */
 				param_desc[0] = '\0';
-				curr_param = test_case->generate_params(curr_param, param_desc);
+				curr_param = test_case->generate_params(&test, curr_param,
+									param_desc);
 			}
 			/*
 			 * TODO: Put into a try catch. Since we don't need suite->exit
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-4-marievic%40google.com.
