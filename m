Return-Path: <kasan-dev+bncBCDO7L6ERQDRBC6FYSZAMGQE6Q3L24Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 231598CECD7
	for <lists+kasan-dev@lfdr.de>; Sat, 25 May 2024 01:28:13 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-529618910casf1065363e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 16:28:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716593292; cv=pass;
        d=google.com; s=arc-20160816;
        b=DnT0GM4EJcd9A62yHX5HOr1CoACeH5tMM5SGxMmCzunM3HFqh2739hROdX64PmUnP2
         wuSPeB/GFj/awGdEVEv9/Uctpj0MeROJenrM1mHbFyNnfOLblb7bnryVwf78lFK2p37G
         DY6CRTMC+5b8WXVCWpb/sUZwXYg3kwx6Du3Frzsfp3afoYuqJXBxJgnsP02BwaxOKe1x
         AJgix99WfpTPuqHe5sy/RRIMIZDzgwT0S91XbEn6QjJyyEKCjqHxEJdFjok1fbshEfqS
         ny+cfsF4MMZWtBmlZiAVEYeCm/IDJxq2RohdoVvkXKjHSzrxeX2AchY5BLPs07nWmyRo
         VAVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature:dkim-signature;
        bh=GWjSLJYeqIzYrGu12VyHQ7hPMdRGWcTNR80j2T/+6Ag=;
        fh=qy5PXiU7fd8FEeWqqIUTeJNCAgGsqI4w8Or3z7yd+PQ=;
        b=ti0havOM+wIMiyyStMxD24RAt4FM7qozwQjPXBsJcfMEyY/zQrbjJ+V4UHnqTlO7Qs
         ARRS9ix1NsMAsLOOl9SEH+QqUnxxXFrwOsR98teEadML0hifwjo9ocrVIWTAszjNDWyK
         qVhy3QqJZ66GQbhcwbUrB4uGzUkPE5iHru/d2weUMBILSGEN1Dw9qoeGb40TxH+2a2wB
         pYJPnhKW/vpg9+EEz7NYx3NM1ZhHUqYh3Mk5oohLl20DbuKZyxUaWUoKgRtptJgLVJxD
         wOzD7VDZBsixIYY3OCebRHZMvEG0XBgwH6S2YqeziTCjA2wrW+JoIq2SBzqFIIpET2E1
         09tQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=npRqA4GV;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716593292; x=1717198092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GWjSLJYeqIzYrGu12VyHQ7hPMdRGWcTNR80j2T/+6Ag=;
        b=AKAGOhlZZ0WdfmaCOqbiadgr/NU+ndBGmbQ5GGJhc4+8GQz01lc+B07qwKX8EbcHvy
         ccpZhpIpVjTH3c3SouU93Ed1+JFy9bTKmszTS9irg65Yq82zLhuZYRVO7FqBKHNOM3wJ
         GP8ExkKibr4vhVk8jTOVqRZGGhK6omiGiJH5NjRe5H6hxPh5/KirrALCaE0xMOpftT5+
         K4Lj/pIqo9kswQ1bdV3izD8kijckz4rZQDrkKmvEoq9IRAw784f0Zo2u1Vx0MVw7hEqx
         PswLA4aarVmGijWpw5E0NV9T6eGSMSlywQ3IPkxi13nsNMaKE09P8aFNXsyYaF/NbH/P
         CzDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716593292; x=1717198092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GWjSLJYeqIzYrGu12VyHQ7hPMdRGWcTNR80j2T/+6Ag=;
        b=e1izXYBjizKA6A/cqNTjTb6DYhbzU8LZQECTMBK9zX8X+YJXvjo54g3m1w4Web9bMC
         RkiNbY4e0atxL8XoKGn3m6+eY3RMbK3SduzfGkTHqg5G8Vt47h08cc4KW8Bw+bsxwDYc
         ctBUgwX45mQwA0Z1rO9ANOPhcFMr0YCp0xteIhEe3B1/o7wji8Mr2wQDn7EBDkaKxQXw
         yZQALdgoKvOnkbHn7MxBVyriNAqKYwSaguArGVl3I+hrDIYbJZ2zG+evdM7UDgLdbUT3
         09k8WJPbeVBB0JG1nunEFRCB649BMtLmMQpRz7G/y2qshGUHJBnlz3vaAFNZPzogp912
         u17Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716593292; x=1717198092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GWjSLJYeqIzYrGu12VyHQ7hPMdRGWcTNR80j2T/+6Ag=;
        b=VPsRRjyBSOs0u2tOuFPh0YLqBNurHO995uQJMdKtoXebCZlHS59as3xdsvzE3cC8di
         HWQVT1FiUdelH+x5vHEWW1FKAKNJCdvtncXl+8E/cQs2GjdPsoWlx8KM0Og3Jsj97aJi
         QZVt4SuUfVbZramhqRHtTRT0yHjXwJLa5CzH1sBH1rRRSMQY5FkeresKxC8EsPScj98P
         /a5OM1WBEd6JSj6wHaF31yuvVXyvEvPtmSTUMvtSGaIDfjvM261G16g5OTuF58D8qkuN
         b6wvDpz50EZIUAYCHu7kCofW1fzrPhqSRBrLe9IGeWxEQ3Z5gFkrwEp42z9TC/3PV++D
         9IxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUM+IVtpSt1/5GQ8fzF8yJgaH0QQwOgPwdlqfhg0ixTsnPkKxqu8U1g3b9fUOkFfw0R9utnCLa2D4l+TQburLsXs3x16eneBw==
X-Gm-Message-State: AOJu0Yz8qz1bVxvU6ofZ1ZF4dhIBcRRKq7cCnNHolVwVYosEQ2sqD63f
	+QKiQFBTEF+/Y0Yq6Z8qX7n9qJgc0bbeHTKjuS+dPEugImYzrrL6
X-Google-Smtp-Source: AGHT+IEH+2YUcJvq1xqAr1tCNhbvjR+vFVUaCEUcAUiNL7ZXbSTL0ODaf9QRmqK7nkIjR64R6EG3Ow==
X-Received: by 2002:ac2:5a1a:0:b0:51f:3ae6:7440 with SMTP id 2adb3069b0e04-529667cfb5amr2054721e87.42.1716593291690;
        Fri, 24 May 2024 16:28:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2242:b0:517:bb:fbb9 with SMTP id
 2adb3069b0e04-529367c541fls682073e87.1.-pod-prod-06-eu; Fri, 24 May 2024
 16:28:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWw4Noc9EsOyKvpcqtbAnr9AuTv7sRvSAEJkr2o21Wi9HCNwIssTxTDDdBPR74EiMZyAf8lC0Tb8xSPq6DiYPKpe4UNigVbfnoFLA==
X-Received: by 2002:a05:6512:e8c:b0:51c:dffc:41f2 with SMTP id 2adb3069b0e04-5296410a552mr2804953e87.1.1716593289742;
        Fri, 24 May 2024 16:28:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716593289; cv=none;
        d=google.com; s=arc-20160816;
        b=dIP5P9zbK/Hqx3l7d6mAQynImkZpsH5bM0dsy7QTyZX7IaXZq0/5hB/8iCm6c9konZ
         exxGy0rK1m7tUQaDxrVkk1NT9essSvOMGrc0AsO6LWOZOU4/piDvMHv/7Fb3Gw/S5CqO
         1lTLBAyxecg6hfB33YE4TJBT45rXAnyEeEzkIjahULvR0vjCF++2crZT4ibf/Qh+61Xd
         6yBbEXE53rMr6/osjDXzhmZzgiC6iJXda1VJlyGUxM/qdDo9GR+il6oN99HttDb3wk8i
         1O0IJCJL5LrlzGaWjOoysurdpMeHww85vngECyB9PmU8PK6zQHvxQJYWpTp8SpSP1I+s
         v+Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=bt12rpmlnyDZwJcOrWI/kuwJtRd0gfXYj/S0LGrI6gk=;
        fh=LA0qDgL1ZDjbqUZKPnQWxa+UJxzObj5YGPBQ2e1jnas=;
        b=RUAISOeg5B3cbiR5Oil/+AxohXNEBM5oAPqt0Qs0Mscim8SQeiPYis5rlgZpYN+wfb
         M79tagLGSxNDrJZoq9zKJFjj/nuTo/85t5fYoDUcd3tZ1D2ad1T7l3z2rHxapN1Gmq3o
         L9LorUPamuTczEu/VjZynd956HZ1kd05dXqjL2UL3/YtJ4i8gpbR0Qu5bcdz/StpmyLc
         pIZ0HDsHSZGFH1ckYXHPEVO0x38VKuFUQjXYFFi1u+EJxdCRsitedszFdityw+VT6JY6
         Tc1wlTsL842k8OnHaDBtE4+2K2nyeVlFaBFOMhhz51b85UA1vqKUYdQSY1GW0d75/FIk
         t0Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=npRqA4GV;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5296ec603cbsi61291e87.5.2024.05.24.16.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 May 2024 16:28:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-57857e0f464so1312500a12.0
        for <kasan-dev@googlegroups.com>; Fri, 24 May 2024 16:28:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUN1FS9hxItEsyhxkVJfwpkK+oJ9Md/lGj+ErXlPivnwsjhON1PS7rykxYvrzhX4Zmp0Q9C26XU+NM4v4f5u4yNxmttrxA1epyTKQ==
X-Received: by 2002:a17:906:c214:b0:a5a:8b8c:6203 with SMTP id a640c23a62f3a-a62646d7f32mr231676666b.45.1716593289010;
        Fri, 24 May 2024 16:28:09 -0700 (PDT)
Received: from rex.hwlab.vusec.net (lab-4.lab.cs.vu.nl. [192.33.36.4])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a626c817714sm191389366b.29.2024.05.24.16.28.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 16:28:08 -0700 (PDT)
From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
To: Brian Johannesmeyer <bjohannesmeyer@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kmsan: introduce test_unpoison_memory()
Date: Sat, 25 May 2024 01:28:04 +0200
Message-Id: <20240524232804.1984355-1-bjohannesmeyer@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: bjohannesmeyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=npRqA4GV;       spf=pass
 (google.com: domain of bjohannesmeyer@gmail.com designates
 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Add a regression test to ensure that kmsan_unpoison_memory() works the same
as an unpoisoning operation added by the instrumentation. (Of course,
please correct me if I'm misunderstanding how these should work).

The test has two subtests: one that checks the instrumentation, and one
that checks kmsan_unpoison_memory(). Each subtest initializes the first
byte of a 4-byte buffer, then checks that the other 3 bytes are
uninitialized. Unfortunately, the test for kmsan_unpoison_memory() fails to
identify the 3 bytes as uninitialized (i.e., the line with the comment
"Fail: No UMR report").

As to my guess why this is happening: From kmsan_unpoison_memory(), the
backing shadow is indeed correctly overwritten in
kmsan_internal_set_shadow_origin() via `__memset(shadow_start, b, size);`.
Instead, the issue seems to stem from overwriting the backing origin, in
the following `origin_start[i] = origin;` loop; if we return before that
loop on this specific call to kmsan_unpoison_memory(), then the test
passes.

Signed-off-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
---
 mm/kmsan/kmsan_test.c | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..c3ab90df0abf 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -614,6 +614,30 @@ static void test_stackdepot_roundtrip(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Test case: ensure that kmsan_unpoison_memory() and the instrumentation work
+ * the same
+ */
+static void test_unpoison_memory(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_unpoison_memory");
+	volatile char a[4], b[4];
+
+	kunit_info(
+		test,
+		"unpoisoning via the instrumentation vs. kmsan_unpoison_memory() (2 UMR reports)\n");
+
+	a[0] = 0;                                     // Initialize a[0]
+	kmsan_check_memory((char *)&a[1], 3);         // Check a[1]--a[3]
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect)); // Pass: UMR report
+
+	report_reset();
+
+	kmsan_unpoison_memory((char *)&b[0], 1);  // Initialize b[0]
+	kmsan_check_memory((char *)&b[1], 3);     // Check b[1]--b[3]
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect)); // Fail: No UMR report
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -637,6 +661,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memset64),
 	KUNIT_CASE(test_long_origin_chain),
 	KUNIT_CASE(test_stackdepot_roundtrip),
+	KUNIT_CASE(test_unpoison_memory),
 	{},
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240524232804.1984355-1-bjohannesmeyer%40gmail.com.
