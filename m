Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEXLU76AKGQE3FEF7VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CC66F290C52
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:33:38 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f7sf1447263lfj.9
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:33:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602876818; cv=pass;
        d=google.com; s=arc-20160816;
        b=of54GEVtphp0MVG6QIKm6540tAxfimZ56fDBwbAKRn7gHJDZfnaUD+GLhcqQdVSfEZ
         3hdpH8aWqIx7/OEziUlCMYFKfBzk3uAUfzJlV+gjp13n3d+d5Zg6JOTKCdN8IBKdU2fj
         IevTgJx3LHfbkSP/ovsTDKA5zSW3nTAzZPgDGki+KdmqviqKm+Gvc1I1q+5ZuqtRS5Ec
         S+gp8BXRvZjF3OO/ph2LqLCr+xX4+nZkQsf1I0CW1obENIYVurGnnDaoCLXu6VIt0DUP
         s0vWfR+J83HPU/1Pm8ZOiptaQKJPCHIg0eJ4U8aSmaYUDLszeHIWxMst6TaEninvp/Ax
         YDNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=JwemwemxDQkPswWvU3dDrz8bGMaWW7aTqktj+0q7iMs=;
        b=IoNVGuo0o3zgpRBRAHkCptvf//AmviY0YP2k3gwlFA6rlDpmGIeFH6Vpr9SluGRya3
         PcEzV9HaLbbJ3dTUBim1zviKHTNRgZdk7l/+sbRQ5R3VhrMtW29XJEJqcffoad0WQc+Z
         LAGgZLnAcxFdcicC1A41MXtXzuN5Y0eMkBM68Th7MtRlN+5mV+0G5dA0lmV/iAr810GU
         SS91aUH+tGPBAD9kE6STZiNslHNYOGiNJYJ5/FplTzCfLodPiDh8p+lyXB3Kn/lKKmvJ
         Ufm/abcjZAZan1ikLwtbgUe5EDJOBcowR4sOj/DEVLJ4brvNcHKpY3bNbCqQ+psuoBLy
         tayw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoWrrTqM;
       spf=pass (google.com: domain of 3kpwjxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3kPWJXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JwemwemxDQkPswWvU3dDrz8bGMaWW7aTqktj+0q7iMs=;
        b=UvauM5LrsJTjmDWNJXps6gWD3s3D6L0GN020MFOYx14w2s2yWatAZI9Dbvpu7mCWXu
         db9jV7yyWIFrTVvXtYE+h8BV9bJTDliUL1OqkZkpK02QHPMP8MordZcifU29efy0gUXN
         P2/nyLYtzonkq9c76RAW9Nm0EWKdwpKBf5hCceeOQbEoRRVZsUP1Vrkeb8bntvdaRXgt
         i+bnxVmw0x5aUzeLHuBKhfanur5C5YC500XUKJFKbwsbCqj38ucvh7v+AF7VtFEvIn4G
         NmM6lQAihUIA4cEjHrZpLSHqe7sNZqKA5e84Gi3GfZdqmjBTpq4Mj2F77IphRUn3H8YA
         uVfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JwemwemxDQkPswWvU3dDrz8bGMaWW7aTqktj+0q7iMs=;
        b=qVMRwrIovlKtxGLp0NOyGbsnTskoPJ7O6u3NUJyiLgTzWPuKbygDIWasy9kOT13v1k
         qaVRQIDAVTn3uBKOAjt50WYbPEvADCpN5ektMkpbSiIA4RsDvQn7L9o3Q48o0tkS4AWV
         t9OCQxeP2ZgJNKm26j1nbSLQmV5lGN96EZJYpVBPDeMBSKc1CZ6kYQD7rIwp3EoWP3t4
         mg5u+roZU34CbfnYynaR44WGnRigkHPDsP5WzK/c6N/N894EQkgzfHTKMsc9QryAMQzP
         x4WHiyQQkRqYUb2fJyWmeMUg+RMo8HeZ2sxxMKJrWo3F+suIk2W6koAOIJsi56bzojwa
         sa3Q==
X-Gm-Message-State: AOAM532B36GnFrZimHD3qCPjEwXRyimNyh3wET0WLCAIspxTJs/pp/Ga
	BUJTACZSPvNgG+MSWoSTP+A=
X-Google-Smtp-Source: ABdhPJwKHLQdUTdT73uwdEoHXA1cSpXQ2EZZKniQpPWGr9iCX5sM2lpJOswYat2PNy8h7Y5PbPSa5Q==
X-Received: by 2002:a19:8ac2:: with SMTP id m185mr2059445lfd.81.1602876818276;
        Fri, 16 Oct 2020 12:33:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls2213195lfd.3.gmail; Fri, 16
 Oct 2020 12:33:37 -0700 (PDT)
X-Received: by 2002:a19:4815:: with SMTP id v21mr2179887lfa.603.1602876817192;
        Fri, 16 Oct 2020 12:33:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602876817; cv=none;
        d=google.com; s=arc-20160816;
        b=dERznTD96DCzdl04IRgMxmaT4Jp4OicW8EhTD4ASXBZNa0LCKQgg4nraV8vjZgpVfW
         o1rCNxCAU8QaC+ggif4Wlbgk9nnepnPrPz9Qip8krSCpEyN++fHp4uxTT3XoM1e9p7OM
         +E0H1e801vHgUNW3lG1glLRE/cvnXKsUbKpbRC5mLZ4ETzZu85udCXQXJtrTGZpDxyft
         d8VHFnqf9BTJ0139KSUwDLzwWIwurTqeQQ/9mMm8K9PKR8ovzuGupaiUGXijeHOyunLO
         vuDn9CVurQqHpxeo9g8djN8x2rQW2R3qTlhDcRJXopHi7here5rpDLVleurcGKX54I/w
         Sv3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=0xkOIUrMlpfAxYo59kbuN09qneusLJjvCEfygqYyq5g=;
        b=EGb1Ib2rSFtpEzbT7RkUN5tqNXKW8/8dw6bC5akTvAqQr1poCntgxCGzDV5Xi6bZQd
         HzuIZ3SMeOqIcYX7J+EJxD4x5eP30cCUbHcBTLehNz1saAtUp07Wi4crs8IclohJ4hTR
         T0ygIMEYcnCvqE/EInI1m8Gqlm406OMdO05aRTnJXUF4SXOwiwXIopPZjp+fuRNXA6SR
         ltBB2ovWcxUSgKfY1ngrFyH6sur1Yc0UQk7KgcFFgaKMPANCAP6f6cMcRU9vp8/33e2n
         M5uJxhIVGGd7GtDNI57Rp99woVhY3Ca2m9IzQ0PU98FRLbRfg+uDL2yUuJjjZh/oT05Z
         ATHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoWrrTqM;
       spf=pass (google.com: domain of 3kpwjxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3kPWJXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x19si116379ljh.2.2020.10.16.12.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:33:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kpwjxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h8so33913wrt.9
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 12:33:37 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f1c1:: with SMTP id
 z1mr5753170wro.331.1602876816443; Fri, 16 Oct 2020 12:33:36 -0700 (PDT)
Date: Fri, 16 Oct 2020 21:33:30 +0200
Message-Id: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH] kasan: adopt KUNIT tests to SW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, David Gow <davidgow@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YoWrrTqM;       spf=pass
 (google.com: domain of 3kpwjxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3kPWJXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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

Now that we have KASAN-KUNIT tests integration, it's easy to see that
some KASAN tests are not adopted to the SW_TAGS mode and are failing.

Adjust the allocation size for kasan_memchr() and kasan_memcmp() by
roung it up to OOB_TAG_OFF so the bad access ends up in a separate
memory granule.

Add new kmalloc_uaf_16() and kasan_bitops_uaf() tests that rely on UAFs,
as it's hard to adopt the existing kmalloc_oob_16() and kasan_bitops_oob()
(rename from kasan_bitops()) without losing the precision.

Disable kasan_global_oob() and kasan_alloca_oob_left/right() as SW_TAGS
mode doesn't instrument globals nor dynamic allocas.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 144 ++++++++++++++++++++++++++++++++---------------
 1 file changed, 99 insertions(+), 45 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 63c26171a791..3bff25a7fdcc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -216,6 +216,12 @@ static void kmalloc_oob_16(struct kunit *test)
 		u64 words[2];
 	} *ptr1, *ptr2;
 
+	/* This test is specifically crafted for the generic mode. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		return;
+	}
+
 	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -227,6 +233,23 @@ static void kmalloc_oob_16(struct kunit *test)
 	kfree(ptr2);
 }
 
+static void kmalloc_uaf_16(struct kunit *test)
+{
+	struct {
+		u64 words[2];
+	} *ptr1, *ptr2;
+
+	ptr1 = kmalloc(sizeof(*ptr1), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+	kfree(ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	kfree(ptr1);
+}
+
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
@@ -429,6 +452,12 @@ static void kasan_global_oob(struct kunit *test)
 	volatile int i = 3;
 	char *p = &global_array[ARRAY_SIZE(global_array) + i];
 
+	/* Only generic mode instruments globals. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
@@ -467,6 +496,12 @@ static void kasan_alloca_oob_left(struct kunit *test)
 	char alloca_array[i];
 	char *p = alloca_array - 1;
 
+	/* Only generic mode instruments dynamic allocas. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
 		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
 		return;
@@ -481,6 +516,12 @@ static void kasan_alloca_oob_right(struct kunit *test)
 	char alloca_array[i];
 	char *p = alloca_array + i;
 
+	/* Only generic mode instruments dynamic allocas. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		return;
+	}
+
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
 		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
 		return;
@@ -551,6 +592,9 @@ static void kasan_memchr(struct kunit *test)
 		return;
 	}
 
+	if (OOB_TAG_OFF)
+		size = round_up(size, OOB_TAG_OFF);
+
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -573,6 +617,9 @@ static void kasan_memcmp(struct kunit *test)
 		return;
 	}
 
+	if (OOB_TAG_OFF)
+		size = round_up(size, OOB_TAG_OFF);
+
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
@@ -619,13 +666,50 @@ static void kasan_strings(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
 }
 
-static void kasan_bitops(struct kunit *test)
+static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
+{
+	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(nr, addr));
+}
+
+static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
 {
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
+				clear_bit_unlock_is_negative_byte(nr, addr));
+#endif
+}
+
+static void kasan_bitops_oob(struct kunit *test)
+{
+	long *bits;
+
+	/* This test is specifically crafted for the generic mode. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		return;
+	}
+
 	/*
 	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
 	 * this way we do not actually corrupt other memory.
 	 */
-	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
+	bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
 	/*
@@ -633,56 +717,24 @@ static void kasan_bitops(struct kunit *test)
 	 * below accesses are still out-of-bounds, since bitops are defined to
 	 * operate on the whole long the bit is in.
 	 */
-	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
+	kasan_bitops_modify(test, BITS_PER_LONG, bits);
 
 	/*
 	 * Below calls try to access bit beyond allocated memory.
 	 */
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, bits);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+	kfree(bits);
+}
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result =
-			test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+static void kasan_bitops_uaf(struct kunit *test)
+{
+	long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);
 
-#if defined(clear_bit_unlock_is_negative_byte)
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result = clear_bit_unlock_is_negative_byte(
-			BITS_PER_LONG + BITS_PER_BYTE, bits));
-#endif
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 	kfree(bits);
+	kasan_bitops_modify(test, BITS_PER_LONG, bits);
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, bits);
 }
 
 static void kmalloc_double_kzfree(struct kunit *test)
@@ -728,6 +780,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_krealloc_more),
 	KUNIT_CASE(kmalloc_oob_krealloc_less),
 	KUNIT_CASE(kmalloc_oob_16),
+	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
 	KUNIT_CASE(kmalloc_oob_memset_2),
 	KUNIT_CASE(kmalloc_oob_memset_4),
@@ -751,7 +804,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_memchr),
 	KUNIT_CASE(kasan_memcmp),
 	KUNIT_CASE(kasan_strings),
-	KUNIT_CASE(kasan_bitops),
+	KUNIT_CASE(kasan_bitops_oob),
+	KUNIT_CASE(kasan_bitops_uaf),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(vmalloc_oob),
 	{}
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl%40google.com.
