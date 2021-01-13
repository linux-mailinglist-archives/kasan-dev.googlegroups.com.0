Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLN47T7QKGQEJQNJ3JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 522852F4FCD
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:07 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 92sf727966otx.7
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554926; cv=pass;
        d=google.com; s=arc-20160816;
        b=1IrqmxUntZeC86gGip02fLGS8Sp+EoekqL4wXwGQuxeKPEbCyWYE0//8rVMcJ5ajPg
         FKAtJpATpdLgPGTQYUW7azdAvsHspgUayUtFgYT4fXqIOlgnbbjPPDWbR6F6tumHGcMH
         Igm2SQLmfWZ+50SsNj4lqesa0v8XFr60Lbhenm5HSWIsocY+dwSVJdHwFwLDVNoPUEvT
         +uAkt3aswUWnZKwBh40PcGCqmHAWRIDyp2hd7o8kQpi1cdSCkZUE9k/Bgj1XLjZLOCrm
         vsXAHWnaLpTKy8RxnOyfIKEE8UkD9F92FGGqqldJiCZLkWATGjCb5G1ZIuDGpF6BvxvX
         VXEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aUI2qTd8ycxSR9uINaXRZ/7NjMqIc/3Hqdsv0hRn5YM=;
        b=dEnRD1WM6xwNFjSEunwRVGH1Q8+zgf2Rl0rK825C1OBWjDl2UvbkMOsdoCGdqPIUut
         iGG7levbHxrMG69JreWMuzFXsewufSLLXVDEg6DlLTJ7LJtaVbikppf2QJbs23FvD8i1
         3bGjHfbKB7w7tEfvUIt2uo5uaW7u3germmyZpo+3IvdyvqnOORxlFBUxnRu6Kt+YKTxM
         VIDXqdemJMw12QFOn+3uBFem3o9tLB9sTTKm6dXIaI7M/iZJZ5u4Eiw+H+PqQGNcj5gJ
         yG1VEoHzTCiMDGmY+YvF/W+m6PMtors/hjfEsDQzM+3jnBH9eHAnbeSg2hDGu0fdzROu
         mHpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vLdGASrW;
       spf=pass (google.com: domain of 3lr7_xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LR7_XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aUI2qTd8ycxSR9uINaXRZ/7NjMqIc/3Hqdsv0hRn5YM=;
        b=dul0Vc5TMEbgXfDnJmKWS7nkitH5s4jGQSSBQy+0TOVa64XchLjyZwzTQRN/Lfs6YE
         Sudd8b+UflMjZkSCNcKjq703AE53/cKuCIFa2Yawpu3dIbe/iGlDBesumrR1la0VMKtI
         o8W/nfyc8hZyxAyxxvAajTbqJEFwvQ5qgflKE3xwRbqC9WbskroT8fNHuHBzgp73tGlE
         N2DCxLs9JW+smhVmhA/y8IdCPRZTVbP0bngg6y42clKkdg2PRts2xdP60WrXzf8KE7RE
         nXQ+Ag/q4XbnXl8f+Y5qf2yfZVip3CTOCMNEmVO2b1JvonSuwB2bcDqF14jPhJcZRsuF
         0nWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUI2qTd8ycxSR9uINaXRZ/7NjMqIc/3Hqdsv0hRn5YM=;
        b=HWEdVbhEwpHuzeTEmffT2vJfnTqbE+lUdiCZIt0D5mT1YkQ3BfEyPYrFnLKHTBXex2
         0MtxlH3OL09dp+I8lxlletgVt6fVYPFHB5nBSD3kZlu5dOnLcudlmryLcSGxkDIQ6FQ0
         Cr8iGNDkFCotwhf20tlQ6vnpxH1RsMLyNltrbGWhZU2VZlmgN+oSXI73hhhwtZNxSCsy
         bvo8d38FluFn5L/g+fjw2V2NeFWS+8HqrXlit6mTPjscpN9yxjXcyU7YYuPNCH3ji+f0
         7B7D81JqrH7RBtLy0jdkuYD8h4/t8+5N+yGXGQp3paSx/88/oMbJ0ozTp6ALal8sABKr
         Imlw==
X-Gm-Message-State: AOAM533kU3poI2vUeTAlU3vy608ZhnB2+FwH9//OHjvDxlz8FxeesfLE
	+tkDSLB7vultq4XxfRKg9R8=
X-Google-Smtp-Source: ABdhPJwrmlY1K6tDmKZI2biiPl2V5Lgk9t7f1J/5DLZegb7npa5nXLuBbM6eADFbBoRhjUFAodeDcQ==
X-Received: by 2002:a05:6830:214c:: with SMTP id r12mr1763137otd.208.1610554926023;
        Wed, 13 Jan 2021 08:22:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d15:: with SMTP id o21ls661175otp.2.gmail; Wed, 13 Jan
 2021 08:22:05 -0800 (PST)
X-Received: by 2002:a9d:a61:: with SMTP id 88mr1755671otg.18.1610554925747;
        Wed, 13 Jan 2021 08:22:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554925; cv=none;
        d=google.com; s=arc-20160816;
        b=VuTjbs31dJCtaYlx2Y31doDWk8qqcdwsvF+31amUNg77nj7dtAGBl31gNa+KQg2kRN
         +RpcxWZLUPQbwbxUojaca7oBVhaz8a9FZO29q9QdggUW3Ck0Hu3qptmGpMkzvbG74hX/
         Z8/FfVaSDNUvB6dV+M4joMrlc0IETjxvcPtH8XiTMFJyIgMoMNO8cSdRE5FeocDSPafa
         1ygyNjsMBPJjA9nauHBXom9a7Hl9rViZGZPgNc1ZA/DR0fl5x3woo+VRYSSmQDk2bn+6
         aTaXJzQGpUl15qJA8YDPGh+2UBramLYckMfO7HGCmnHZVmVzwJDhAyzHEB5EPdYTnSOX
         +AFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1ElsZsJrO3cOsYp/vFzZufoQKn9+sd3vP1RO0nASQZ0=;
        b=SPVqhhWYmeFoZao4Qn9Ldf5oTWQ19XBS7DohnTnsT/r1HOdI3pQA3+7YluPTVL+/P9
         8kPkRQ/dUl0yyQNKkDJXv73Lk+ZWf3N+Cuz3mRvUL0bIFZPkYxWJ8xJS3dFQTOEUmWOJ
         +mR0h7mH0pgTAo+LcBwCDUplIDHpzUgb7KlgeIHi6PL/KWuxF8bG6K7dhcb4ScOV/Z55
         1HPgANXof9NP07jlmGGENlrgqxgIPHGHypXSrjrsv9LUP0qbfCyyUEo9TJJhmdT4itFb
         OcDUOGWxb8ORLhLgJPm9eyB0R2/5kYwdSV2UXFH5mnitnUiynzn6fdfsmp+Xm8Y2MDpe
         Ni/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vLdGASrW;
       spf=pass (google.com: domain of 3lr7_xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LR7_XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id v23si231335otn.0.2021.01.13.08.22.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lr7_xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id p185so1716528qkc.9
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fd89:: with SMTP id
 p9mr3153133qvr.8.1610554925220; Wed, 13 Jan 2021 08:22:05 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:35 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <e75010281350ff3a4380006218f81e1233fa4e6b.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 08/14] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vLdGASrW;       spf=pass
 (google.com: domain of 3lr7_xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LR7_XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

It might not be obvious to the compiler that the expression must be
executed between writing and reading to fail_data. In this case, the
compiler might reorder or optimize away some of the accesses, and
the tests will fail.

Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL
and use READ/WRITE_ONCE() for accessing fail_data fields.

Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c  | 17 ++++++++++++-----
 mm/kasan/report.c |  2 +-
 2 files changed, 13 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 5c8aa3a5ce93..283feda9882a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -68,23 +68,30 @@ static void kasan_test_exit(struct kunit *test)
  * normally auto-disabled. When this happens, this test handler reenables
  * tag checking. As tag checking can be only disabled or enabled per CPU, this
  * handler disables migration (preemption).
+ *
+ * Since the compiler doesn't see that the expression can change the fail_data
+ * fields, it can reorder or optimize away the accesses to those fields.
+ * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
+ * expression to prevent that.
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
 		migrate_disable();				\
-	fail_data.report_expected = true;			\
-	fail_data.report_found = false;				\
+	WRITE_ONCE(fail_data.report_expected, true);		\
+	WRITE_ONCE(fail_data.report_found, false);		\
 	kunit_add_named_resource(test,				\
 				NULL,				\
 				NULL,				\
 				&resource,			\
 				"kasan_data", &fail_data);	\
+	barrier();						\
 	expression;						\
+	barrier();						\
 	KUNIT_EXPECT_EQ(test,					\
-			fail_data.report_expected,		\
-			fail_data.report_found);		\
+			READ_ONCE(fail_data.report_expected),	\
+			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
-		if (fail_data.report_found)			\
+		if (READ_ONCE(fail_data.report_found))		\
 			hw_enable_tagging();			\
 		migrate_enable();				\
 	}							\
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e93d7973792e..234f35a84f19 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -331,7 +331,7 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
 	}
 
 	kasan_data = (struct kunit_kasan_expectation *)resource->data;
-	kasan_data->report_found = true;
+	WRITE_ONCE(kasan_data->report_found, true);
 	kunit_put_resource(resource);
 }
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e75010281350ff3a4380006218f81e1233fa4e6b.1610554432.git.andreyknvl%40google.com.
