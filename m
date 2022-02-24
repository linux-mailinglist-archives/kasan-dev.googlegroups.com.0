Return-Path: <kasan-dev+bncBD52JJ7JXILRBXM63OIAMGQEUJAC2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 204764C2089
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 01:20:46 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id s11-20020a92ae0b000000b002c2228d0abfsf400445ilh.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 16:20:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645662045; cv=pass;
        d=google.com; s=arc-20160816;
        b=WoUKl8Cjxdbsbr/CGiHfFG1aBMn2oQqDqNIxjvEOX4dc40IzPtNtaglmqLinOwkBMg
         9r9h3Ry2p7eQazXtQs32rXjGhzvArsmJftJv84ExQiFrIzBuiAGefJQGlLDmskgKhPhF
         zJ+ZJr5YiRSBZU94Dis+/RkojTY2wXixbSlHjjSLrj7QM9hGmr8ZfbU5NO0gn8hhrhzq
         ybPGUVLkfsIvCoJ24l5SE4udUH1bIhQixSZHiGI7l42L+X1n6pRYQfcGqukbjZJnDL6n
         lcmlb2aWTfpfsyIm6V3wfzL2BNoZDQ9V1JMyJaldQT7fM0TD4wOaNvPoXuYp8fcAP7vA
         XPrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=RvmWGAE4Ki24tWgrYMx88tlhw+kI6TfOauuPTiTOJRU=;
        b=i7hoDajMG/Qaz+xeG8lsIghcF7hA3T48STe1w2aUhUEm4S9vXlKqsN4lP/O7H/wE3L
         wqJPlvPaHXYvqGg9ltAcNKSojyin3cmwNu6JqBYetFth7LuBh7TOBEbnheEZyaJbR/tf
         FQUFy96TSAShH1xIbvV9iYNR/a3ld2FKxWUvT3j33aZeRA/5mzz5te2lzyf6RTLwPzDi
         OZa8FfByp4fJ9yVAyBVwvTNI7cntr2yCWKCr8f/eg9BLsAa6z3HW0fcR0yMrXXlNcSWW
         ycxFM7gzFXcshAxmRRfuOD1vQs/TBPr4Pz0gojuSFkgwP9rgM/6owpmKHyUWOSTJdNY6
         GLJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PGhrk29E;
       spf=pass (google.com: domain of 3xm8wygmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3XM8WYgMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RvmWGAE4Ki24tWgrYMx88tlhw+kI6TfOauuPTiTOJRU=;
        b=Nj+Xv1IbGqOdvQYYu46QYtXyZzNehw3DxX1jBISe7JBMY3fYWUkwPTpKi0QI+jTm1o
         bteg/PAhV9c+xB7GsfFXqpPN+U3C0aVZn6YiAasDDYfCBN7FIjJ5s0IAQPW1qlJow3X0
         j6a7HKfsWxdud/mZm7IfIAMmWltY9/Xpxuk0SyCN3PhpnAkDnNI3nHxVexDSluNdNwAX
         cxa7/m1D+28cfxSRRIRDqaOBwN7V4BIJ1Rp4HGP7WKVBS7j7fQMOvXVGGKQ9GO1UaCxS
         MaCPAYjtlktcLRmBDDMfYWrw04d5rAF4oAiqYz7KjrU7f8Z4PjcfqqUiqT7XJUDAktyv
         yKJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RvmWGAE4Ki24tWgrYMx88tlhw+kI6TfOauuPTiTOJRU=;
        b=nylcvxt1wnwgdPsarhOPwqdO72fYTwYVSssSY3ZUzhiaTzH9eypt8UZIw6KPapn0XU
         KehcJoEaw0yQT5VScHuZj0xMXNRCEn6jA3zkgWNvvTlndwhIlz52q6sOb5eHwdEh5Yiv
         6d4lDAXOGTKNeLfkC84zjD+4fVWMgXXFyQVJuspVuZf2Tz+UxzllwZy8dSv18ZNFoFZA
         E5FE4PyMk5NCJDMW0y/Qus+5xE1Uy1Jf34Xi+G2z/7b3/e8za4K8wIQeeGrhG9zI49K7
         gmjywosUm2+4FLjnQ0VmZBHS0hnu7T6GYg03VgqujwEpzA/8i+jTAgD1AxNLBQs2+olk
         9tWA==
X-Gm-Message-State: AOAM532wYGkFpZhdo1AHtWdzFG+UcuM7Rtk03Ep+aX1WCuv6cqrFN9f1
	kV9vUsNegmFDgtk9fgsbrB0=
X-Google-Smtp-Source: ABdhPJxxhrnYUsFYWL8j+uZfwEXhPs/6soSt48ZmgfL/YUVMHxlKHYnnNyVCdR92Et/85fQKa6QifQ==
X-Received: by 2002:a02:70c4:0:b0:314:1fd1:f143 with SMTP id f187-20020a0270c4000000b003141fd1f143mr82839jac.18.1645662045114;
        Wed, 23 Feb 2022 16:20:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2711:b0:314:41a8:e4c7 with SMTP id
 m17-20020a056638271100b0031441a8e4c7ls313348jav.7.gmail; Wed, 23 Feb 2022
 16:20:44 -0800 (PST)
X-Received: by 2002:a02:a398:0:b0:314:ad84:75fd with SMTP id y24-20020a02a398000000b00314ad8475fdmr83413jak.20.1645662044766;
        Wed, 23 Feb 2022 16:20:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645662044; cv=none;
        d=google.com; s=arc-20160816;
        b=N/xtUEcVmLo1RfoE/e33QjJTxcuy96IMcNo5mAnn7QcAejgsNLZEMqOMwOZNCL2CdN
         zn+eBUvjtKaT6b+lJqExJPjcKNmHZ8mgafYbirb3cXRLLZzy6CXQprDylh5UZ9BFH9YJ
         zphWrpghC3QzDwvwj6qOMMlsv18uqvpJVoeWOjSsQDuOtDIM1bqXHpyOJ4cC31O2nNx3
         MfrsP/AUnqJfb2iBbEZbCh9vQobJjHGv4jNUZv8lc6kIA0uEhoSB/Tsr+DdOmYY3fqv/
         S2lmbbHa8MD3Cd3NThtleXXlZr6jlHXVQMfXaemndGsrr/Hds/HMA73Dank7RVjmRNPD
         1Zdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=d5dLzGHZ/03S2GwnSJZ7atIUIHBRbtyGlBVTRxvEnP4=;
        b=lbeZNFBnSLcGVO0KSL1CgBcgcQJWsyL8ZWNjujjrVYNv3w5hvluWWbniWHew/SKyo2
         jLUmHlPL9TpdHjkTdWU7p9lg+kwvLVrT3wEOqeGVw3f9W5nvAgVnFyUqQ7CBWxo/x7Af
         mNBzYkmRv/yzhiQ9unROocKmn4P8z7eGqc+OuPSoZg3x5HazyLKlnSgMNDNmKC8JXrko
         O57oqsSftwONeqL2E+SPDO32mDk+29+B54zvQs0HzqwOJYahwXA8CMz6ndLBpXX9Gyft
         9J/cu6OIYqt+Y8c5ti5ettWTGb6Py2t8cjeknbwo7a+YRIvtckOVqFkRJs9hnvAfElWK
         rQIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PGhrk29E;
       spf=pass (google.com: domain of 3xm8wygmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3XM8WYgMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id i7si68011iov.0.2022.02.23.16.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Feb 2022 16:20:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xm8wygmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id j17-20020a25ec11000000b0061dabf74012so296176ybh.15
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 16:20:44 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:ef38:18a6:8640:7dc1])
 (user=pcc job=sendgmr) by 2002:a25:7:0:b0:623:abbe:e6e9 with SMTP id
 7-20020a250007000000b00623abbee6e9mr200654yba.547.1645662044312; Wed, 23 Feb
 2022 16:20:44 -0800 (PST)
Date: Wed, 23 Feb 2022 16:20:24 -0800
Message-Id: <20220224002024.429707-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.473.g83b2b277ed-goog
Subject: [PATCH v2] kasan: fix more unit tests with CONFIG_UBSAN_LOCAL_BOUNDS enabled
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>
Cc: Peter Collingbourne <pcc@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Daniel Micay <danielmicay@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PGhrk29E;       spf=pass
 (google.com: domain of 3xm8wygmkcw0annrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3XM8WYgMKCW0aNNRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This is a followup to commit f649dc0e0d7b ("kasan: fix unit tests
with CONFIG_UBSAN_LOCAL_BOUNDS enabled") that fixes tests that fail
as a result of __alloc_size annotations being added to the kernel
allocator functions.

Link: https://linux-review.googlesource.com/id/I4334cafc5db600fda5cebb851b2ee9fd09fb46cc
Signed-off-by: Peter Collingbourne <pcc@google.com>
Cc: <stable@vger.kernel.org> # 5.16.x
Fixes: c37495d6254c ("slab: add __alloc_size attributes for better bounds checking")
---
v2:
- use OPTIMIZER_HIDE_VAR instead of volatile

 lib/test_kasan.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..7c3dfb569445 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -185,6 +185,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -295,6 +296,7 @@ static void krealloc_more_oob_helper(struct kunit *test,
 		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
 
 	/* For all modes first aligned offset after size2 must be inaccessible. */
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
 
@@ -319,6 +321,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
 	/* Must be accessible for all modes. */
 	ptr2[size2 - 1] = 'x';
 
+	OPTIMIZER_HIDE_VAR(ptr2);
+
 	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
-- 
2.35.1.473.g83b2b277ed-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220224002024.429707-1-pcc%40google.com.
