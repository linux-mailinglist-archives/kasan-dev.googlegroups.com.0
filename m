Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLOH7WPQMGQEVS22OHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E23A6A6E93
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 15:39:42 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id f4-20020a05651c160400b002959ea5bc51sf4120659ljq.9
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 06:39:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677681582; cv=pass;
        d=google.com; s=arc-20160816;
        b=dG+NLWhfGleQBWcwy19BT42AtR8SUnzs4Uy1vVGkO1yscX8NrIOH+kVYCk7owMu1ZA
         wf8xm2g4yLZU9Zca8eSScFR/MlfbtzikTNgKEq60st2T2/Gp5sEfRSjtG/aDQl2RvHDs
         9WhAeNvEGxoWXm6m4Lt05ToUx/WGqrylgJgp44/2OLmYsfd8eD+N5RxJEIvF0Xe666bF
         UJ3g+2TNPoOXP+ChcWHaY4DVv1MHfgWydw+BHaKVMvNVuPWyr1CqkcPvclZDXfz2x6Yr
         hDSf4mviBPdlA+IhG0iDj6bGM7PIZw8lBfT00TbRVjDjVdiYDFcr8B9485NnnMfoKZhC
         icEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZSczMy8eioyF90EzfI73sKxka6XuniclfqO5cmsOrqE=;
        b=AntvNkyPZMwtGpOPmSVjQDhOU6n7o1BE2GE/PboTE/yvsnx89nkbcv4oQtHZvQgph2
         e9Ce3Xu1i21kttrtD/x0EsRCNzACwohcjFcUb1ucLx4xPmKWvGR3lJ7JV4VMj58ABEH3
         CBBpsF+daIL28zummTmAcGjIQ5jevHSrdN6WB+ziPrDyWc465tuztH6dqNHYIo/Hk+1f
         oT/RVnpwrqs21+0n4tzvA37nT9HA9m1mD71U1bb6DvETPlc+STVpfzIpciGyZUMQt27M
         Nqs9o1rggYj9wPgt1iH+HtQjmE5ySwTyuYQ/rn0BLOcfMDwUPOPJnZvdyOzRU2OH0MF5
         calA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TZbcESbs;
       spf=pass (google.com: domain of 3q2p_ywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3q2P_YwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZSczMy8eioyF90EzfI73sKxka6XuniclfqO5cmsOrqE=;
        b=T05XqJyMdFZ+Oh9pLT25APF+Oo1Laq0vpJSxi+OpINTluCtsTKX4ak4nGchHJ5hwc8
         8vpstrAFX/W1DowaOLFnKhmtE18oTp13J7DpIY995cAfbp986m+AqnIi8y6PGigWyBrG
         pCYwBcE9IF665NbETODvTJs/bKFiFqN1uUuZLPMNglLPmo5dLOlbFM4mwiPOU3CEvTbO
         QMbSlsxoAz3kPbLs9218hx3jzGkts2ltys7i+PRsN58FzfavwvlZhCowAqU/87QuUWDD
         GtLdf/2Dwx9yoRfnp2QcxPfFElTOAUegQYVP/LXLHbIUMJchBP6A66MW0DABv+e5LLNx
         QSfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ZSczMy8eioyF90EzfI73sKxka6XuniclfqO5cmsOrqE=;
        b=2G4HZUyESroIBu1QOewv0XD9QTfzLFgK5MNWeC0crPR5PwL1w17sGdQiQDgNlozWuy
         0IvFsKZ4x/FyfNCm/hlvXyH6N67qOY5vsqvTzJz2NlCvTL8RVgcTU5TsdSlwCbnWGrv1
         oEUthIc8Z7ffiM1hyryKrb1UrsoUMO5KIFZw0T5nUnSgqUmPgiCDgo7djyff3g4k8yN/
         bJaeLrDGmsPgC3nPIzRKkYBMqz58z+70zJeLxQ6kaiv3XsZvf02EeElsoU19nbrVbWMt
         U2tfkjfqNFwVP3DlmCwIYmr3r1ATkbIp0RWz4Duw5F3egWmc3xiS4+v5i80WbUclCxPk
         gCbw==
X-Gm-Message-State: AO0yUKV6Uqthnhd9I2LQqXHj/j+Cofw6GnG9zYc86lPmQ2P7rUCdzDOa
	Ifrxpy4gUxL+kShQD0WApkw=
X-Google-Smtp-Source: AK7set9QOm81iBmI6uj7kjGTLpxdj1nsGZYF2Dqwsh2niejwzkR75b7+cji4xTtiRgl3fHcDiGZWOw==
X-Received: by 2002:ac2:46f3:0:b0:4dd:a4c5:2b42 with SMTP id q19-20020ac246f3000000b004dda4c52b42mr1908480lfo.8.1677681581871;
        Wed, 01 Mar 2023 06:39:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e26:b0:4db:3331:2b29 with SMTP id
 i38-20020a0565123e2600b004db33312b29ls287645lfv.0.-pod-prod-gmail; Wed, 01
 Mar 2023 06:39:40 -0800 (PST)
X-Received: by 2002:ac2:495d:0:b0:4b4:9068:2c0b with SMTP id o29-20020ac2495d000000b004b490682c0bmr1841445lfi.2.1677681580548;
        Wed, 01 Mar 2023 06:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677681580; cv=none;
        d=google.com; s=arc-20160816;
        b=diyA3jYWFjTetePE+Gr1OXgjf6AyMauqEoI+6GUT3jP7fDuQG7L8F9azoU/9ra5vj0
         PBiod4niK4/OYvn9Vx92+w4dpm/Rbi1Omk6kDZACG4qLAKxvDdiSAw4hUAK6F+TBYAqG
         1dnqywonMGTjN8zQvnjqUjo+TsIbkPB4M+B87DdAXwbPTjUvDbGwU/59iyrBQWvO3oEJ
         fBf22S6ueqESAalHfPdQ3u+uzs9BXoQMCXbyHdUDEQdfvUqcNHks1mSqxMs1LS17EscC
         ZC/tYUhwclTkHiUho43MmPa8UFDLDX8sY2vzoNzPt653GS48VC8pVuZsZimdKhIZAGMQ
         3GxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GvEmc+TQ/70wBv4c0+3F8h651+3YM9ltVwHdaJENm+0=;
        b=lQRERzPNwTi4uMfLv/FkQ7858I+hI1K3c5kvU9v6gDiafWE8yl0fFc7HYVMRzwmEWk
         YALnRalK9jd07tQMCoCKqA7b1nZ56XW7SCix/gsfATiX7fTUFme/kZ6PWpuzGpS1Eaoc
         KE0xdC3fRAHXkNCnt7FsbgRKyY+FeCvwlxnugXP137ypt09ZjjJ5UG3TM01LHBBrCDmG
         b9CdKJ8oHbyz7DmE3kfyWpRy7Lcd80vWg8j6UKlmfKyHa68A1kQPGVnMmqo8OAe4aFqe
         UHeypFygHiHRWXKXjlwgSdghPYS4Yc/lU/9QI5NcaPhHohcwB5AB+tOlHSduydsbeTCF
         OzRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TZbcESbs;
       spf=pass (google.com: domain of 3q2p_ywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3q2P_YwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id y30-20020a19641e000000b004dbafe55d43si644280lfb.13.2023.03.01.06.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 06:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q2p_ywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id b1-20020aa7dc01000000b004ad062fee5eso19300296edu.17
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 06:39:40 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:3c31:b0cf:1498:e916])
 (user=glider job=sendgmr) by 2002:a50:d6db:0:b0:4aa:a4df:23fc with SMTP id
 l27-20020a50d6db000000b004aaa4df23fcmr4014799edj.1.1677681579977; Wed, 01 Mar
 2023 06:39:39 -0800 (PST)
Date: Wed,  1 Mar 2023 15:39:31 +0100
In-Reply-To: <20230301143933.2374658-1-glider@google.com>
Mime-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Message-ID: <20230301143933.2374658-2-glider@google.com>
Subject: [PATCH 2/4] kmsan: another take at fixing memcpy tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TZbcESbs;       spf=pass
 (google.com: domain of 3q2p_ywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3q2P_YwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

5478afc55a21 ("kmsan: fix memcpy tests") uses OPTIMIZER_HIDE_VAR() to
hide the uninitialized var from the compiler optimizations.

However OPTIMIZER_HIDE_VAR(uninit) enforces an immediate check of
@uninit, so memcpy tests did not actually check the behavior of memcpy(),
because they always contained a KMSAN report.

Replace OPTIMIZER_HIDE_VAR() with a file-local asm macro that just
clobbers the memory, and add a test case for memcpy() that does not
expect an error report.

Also reflow kmsan_test.c with clang-format.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 43 +++++++++++++++++++++++++++++++++++++------
 1 file changed, 37 insertions(+), 6 deletions(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 088e21a48dc4b..cc98a3f4e0899 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -407,6 +407,36 @@ static void test_printk(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Prevent the compiler from optimizing @var away. Without this, Clang may
+ * notice that @var is uninitialized and drop memcpy() calls that use it.
+ *
+ * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
+ * because it is implemented as inline assembly receiving @var as a parameter
+ * and will enforce a KMSAN check.
+ */
+#define DO_NOT_OPTIMIZE(var) asm("" ::: "memory")
+
+/*
+ * Test case: ensure that memcpy() correctly copies initialized values.
+ */
+static void test_init_memcpy(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	volatile int src;
+	volatile int dst = 0;
+
+	// Ensure DO_NOT_OPTIMIZE() does not cause extra checks.
+	DO_NOT_OPTIMIZE(src);
+	src = 1;
+	kunit_info(
+		test,
+		"memcpy()ing aligned initialized src to aligned dst (no reports)\n");
+	memcpy((void *)&dst, (void *)&src, sizeof(src));
+	kmsan_check_memory((void *)&dst, sizeof(dst));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 /*
  * Test case: ensure that memcpy() correctly copies uninitialized values between
  * aligned `src` and `dst`.
@@ -420,7 +450,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst, sizeof(dst));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
@@ -443,7 +473,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)dst, 4);
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
@@ -467,13 +497,14 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
-static noinline void fibonacci(int *array, int size, int start) {
+static noinline void fibonacci(int *array, int size, int start)
+{
 	if (start < 2 || (start == size))
 		return;
 	array[start] = array[start - 1] + array[start - 2];
@@ -482,8 +513,7 @@ static noinline void fibonacci(int *array, int size, int start) {
 
 static void test_long_origin_chain(struct kunit *test)
 {
-	EXPECTATION_UNINIT_VALUE_FN(expect,
-				    "test_long_origin_chain");
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_long_origin_chain");
 	/* (KMSAN_MAX_ORIGIN_DEPTH * 2) recursive calls to fibonacci(). */
 	volatile int accum[KMSAN_MAX_ORIGIN_DEPTH * 2 + 2];
 	int last = ARRAY_SIZE(accum) - 1;
@@ -515,6 +545,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uaf),
 	KUNIT_CASE(test_percpu_propagate),
 	KUNIT_CASE(test_printk),
+	KUNIT_CASE(test_init_memcpy),
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-2-glider%40google.com.
