Return-Path: <kasan-dev+bncBDTZTRGMXIFBBRUL7P3AKGQECCHCRYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CFA11F22D8
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 01:12:07 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 49sf6054659otg.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 16:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591657926; cv=pass;
        d=google.com; s=arc-20160816;
        b=yCYgDb9zjheDh07qhTdmduorLOxS1XIvCXsiaTfm0lLKUcNdldnXiWB0zhb98JzHCL
         9mpFjSIAeCbQ/0cd/uOwkaRttl8x7mghOq78UhiSKfW/+1bHZoUOC/UoKZNAF4DFFGgR
         wmM4uAkZUWuRwGl+c26FCyuVWQFnBtfX09qpiT8yj4rHbS48ePLuLMq5VJMvaxaapk7k
         yzqOFBkKjjhUv1sD3QUWmUMgSFfndx3S66oNkU4uA7vfmzlCfGjiifVPB2j0IF64UpOo
         cbjEYw9CUXjzh/W8RSOVokKLPVRBjeV+xPE1mWTaTC7mIWWc3uHj+QPG6uXdzNJ/k1gN
         deZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SJ5ODR2quEBH6ZB0UCLqNKYC9dd8FEbDppofoAyR8KE=;
        b=aNmntfaPl5a1sxTpsKghUIi/q3clRRiOFZJtJGYK5uABxOHlTVsdA7FRayXimdDbSe
         BKwUwc5S6YpH1u9bszakrOyO537G7AmaPCrJx2O3JQrxPBdMJ8B7K4kylFa+B7avocJ+
         RDukLjrTrgydGioNf42iR8XRU3uY+NVREJjfp0kHQovFcOhGn23f3SA/4EYqZB9KBS0n
         y+qHIdFhfMUGSMFRb9MK4rr97gybuzn+NYLQ4juG4QV/3pckmvNLYOa8C4zxVgIICmEK
         O/mkMeOiNuyLeqAP5g04+g4PvrsRl1b7l54oe8PTA7Fd3QxlQnOu8Z8+swlAj11cGHmP
         cTSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="0G//rxJ1";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SJ5ODR2quEBH6ZB0UCLqNKYC9dd8FEbDppofoAyR8KE=;
        b=kopvdhAAkFrYDf3m/dRTA5Ncl2R6y/+MmIzY63RXMUr9KRXA8ScnkGJjgMc6BPI9dl
         twMSNVtEwsATASCfBTaoUTW+759YbPClidBaB1zL+9YIeAgKWqv6KYcVleZ5+4T+vLmr
         c9vtECaItOSStLvwX3OxEoYLHpL+TsQV7zR8VonnXBsP72Kr4C8YtciBc2tXa1KOBbvK
         a0JJsqN57wGjY5Yie4nNVQPjJfSxKG1/Y/HyNoKkU3SXZPbaG0a2a77Tc6e8tJj67783
         D1bFFVM4zVCxCLOGrB47K0my0/eG8BXrsF5b/A9E/CDERmc+oYgl5M/+YooJRX84gQX8
         a6NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SJ5ODR2quEBH6ZB0UCLqNKYC9dd8FEbDppofoAyR8KE=;
        b=sCdRA6KwxeNOMjrKe7qTu20bMH+Exy/MIS5QTTpN83Dk7AQd9+3/ebm217aZoNwIyZ
         SgyJvx7qt2zE7J1AB0vXYJeD/OqZbc9NOZv2PCyJx8b0GFRksGVr/R9GJUHrDXJq2C84
         DsPxfTJFYASywpqcsekdv/x1irJahPQWlrNiBD7rHnezwGJ04vUvud6/AQQcmrttYXHW
         jM7dRgOObsmFn/Rbz6/alBhbA3clpyvKIRxH5WveGqiSGcbrtSPMjaHRYQO5iPt3b+nV
         L1GXLN7vno2J2dmkM+TM4bDFNoEmsJTahIad+ifjZN6BdE26My2/fs56AlZZ50eeuQnD
         toDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aYQrmWZMrfmIjCzDOOe7kiRDxMB7h4/moQDQCxpXdKiU5VXeN
	NoRjl2VTyZNB+VDljE76JEE=
X-Google-Smtp-Source: ABdhPJwsLiZsX6Tdn2k0VzA7cdoZAoxJnP9CXuheQfBNw/g5AefE859JHErdlUJ7jwIgizCnaU/LMA==
X-Received: by 2002:a9d:7852:: with SMTP id c18mr19053581otm.82.1591657926182;
        Mon, 08 Jun 2020 16:12:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c38e:: with SMTP id t136ls3467878oif.9.gmail; Mon, 08
 Jun 2020 16:12:05 -0700 (PDT)
X-Received: by 2002:aca:6144:: with SMTP id v65mr1346125oib.33.1591657925841;
        Mon, 08 Jun 2020 16:12:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591657925; cv=none;
        d=google.com; s=arc-20160816;
        b=dLTGsHOEX+3NCyWSSY/FIEKibRC+9z4HVmujwZylzg7L5YQHn2asiaVYJy+I3RTDoX
         nXiyp9a6u4TK5i2HHH+KiB/+S9bZomWSEMLMh3/17zsDmDKvTxBeNvyXgNhH/AQ9MlOQ
         CJAPrF2mBEhR32MHAjp2nQ107x/8DiqZzgRtJyqybDIHI8sBHNNBC7/eIxyCiIG1ZjIV
         yPNyKgvx2bddvFG/rjfH1QzDK0gAm2FeAoFj4hL0FyRIbgvlOJLPM55w0kJrj4RQ8JJ1
         iDi5oaTVMhUGlB7yhaEXBL64g6EjMfGgVFTRQJOi0lCgNgW5ulK1BvSGKeczG05sBVJH
         0OKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8CjcHZtHpqea/5Ia7hh8P8BYjvVcTkOsTHmSU9lGUZc=;
        b=eNUaPI+X9jHPqPgFDWJ9+I8zUkcgC96iF2X2pwJmG2+IcitNGQbZu4FZIw1qBPZm1h
         Eu1xNTDnRkGjGLkBiucJwK2zmyIHZPwnRSCyOhpWYPBDOOBO4QL/xEP2gNRg8uHFIUJT
         sabTV2nfsJyCCyguDsaaqgLBKBFyvReeTmEhYouTT7Bbjs6atLby1yvdcpWs7PI5hXcT
         JU8lZaRbX6KVf2eWdaPy+rx7cNXGmy+8oyu/0BpqZcKAWiQJNQ5WYGkFqYxUq7o0H+6C
         Mzn/6XFuThkLe9zhJej9/DzpxINjLfIZHlm6I/M+EZsmfzBNlI2CUoUyll1NkYXU4aD8
         SWHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="0G//rxJ1";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si828658oig.4.2020.06.08.16.12.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jun 2020 16:12:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E182320C09;
	Mon,  8 Jun 2020 23:12:03 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Daniel Axtens <dja@axtens.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Gow <davidgow@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.7 273/274] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Mon,  8 Jun 2020 19:06:06 -0400
Message-Id: <20200608230607.3361041-273-sashal@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200608230607.3361041-1-sashal@kernel.org>
References: <20200608230607.3361041-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="0G//rxJ1";       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Daniel Axtens <dja@axtens.net>

[ Upstream commit adb72ae1915db28f934e9e02c18bfcea2f3ed3b7 ]

Patch series "Fix some incompatibilites between KASAN and FORTIFY_SOURCE", v4.

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the operands.
However, these functions often directly invoke __builtin_foo() once they
have performed the fortify check.  The compiler can detect that the
results of these functions are not used, and knows that they have no other
side effects, and so can eliminate them as dead code.

Why are only memchr, memcmp and strlen affected?
================================================

Of string and string-like functions, kasan_test tests:

 * strchr  ->  not affected, no fortified version
 * strrchr ->  likewise
 * strcmp  ->  likewise
 * strncmp ->  likewise

 * strnlen ->  not affected, the fortify source implementation calls the
               underlying strnlen implementation which is instrumented, not
               a builtin

 * strlen  ->  affected, the fortify souce implementation calls a __builtin
               version which the compiler can determine is dead.

 * memchr  ->  likewise
 * memcmp  ->  likewise

 * memset ->   not affected, the compiler knows that memset writes to its
	       first argument and therefore is not dead.

Why does this not affect the functions normally?
================================================

In string.h, these functions are not marked as __pure, so the compiler
cannot know that they do not have side effects.  If relevant functions are
marked as __pure in string.h, we see the following warnings and the
functions are elided:

lib/test_kasan.c: In function `kasan_memchr':
lib/test_kasan.c:606:2: warning: statement with no effect [-Wunused-value]
  memchr(ptr, '1', size + 1);
  ^~~~~~~~~~~~~~~~~~~~~~~~~~
lib/test_kasan.c: In function `kasan_memcmp':
lib/test_kasan.c:622:2: warning: statement with no effect [-Wunused-value]
  memcmp(ptr, arr, size+1);
  ^~~~~~~~~~~~~~~~~~~~~~~~
lib/test_kasan.c: In function `kasan_strings':
lib/test_kasan.c:645:2: warning: statement with no effect [-Wunused-value]
  strchr(ptr, '1');
  ^~~~~~~~~~~~~~~~
...

This annotation would make sense to add and could be added at any point,
so the behaviour of test_kasan.c should change.

The fix
=======

Make all the functions that are pure write their results to a global,
which makes them live.  The strlen and memchr tests now pass.

The memcmp test still fails to trigger, which is addressed in the next
patch.

[dja@axtens.net: drop patch 3]
  Link: http://lkml.kernel.org/r/20200424145521.8203-2-dja@axtens.net
Fixes: 0c96350a2d2f ("lib/test_kasan.c: add tests for several string/memory API functions")
Signed-off-by: Daniel Axtens <dja@axtens.net>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Tested-by: David Gow <davidgow@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Daniel Micay <danielmicay@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Link: http://lkml.kernel.org/r/20200423154503.5103-1-dja@axtens.net
Link: http://lkml.kernel.org/r/20200423154503.5103-2-dja@axtens.net
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 29 +++++++++++++++++++----------
 1 file changed, 19 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..dc2c6a51d11a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,14 @@
 
 #include <asm/page.h>
 
+/*
+ * We assign some test results to these globals to make sure the tests
+ * are not eliminated as dead code.
+ */
+
+int kasan_int_result;
+void *kasan_ptr_result;
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -622,7 +630,7 @@ static noinline void __init kasan_memchr(void)
 	if (!ptr)
 		return;
 
-	memchr(ptr, '1', size + 1);
+	kasan_ptr_result = memchr(ptr, '1', size + 1);
 	kfree(ptr);
 }
 
@@ -638,7 +646,7 @@ static noinline void __init kasan_memcmp(void)
 		return;
 
 	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	kasan_int_result = memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
 
@@ -661,22 +669,22 @@ static noinline void __init kasan_strings(void)
 	 * will likely point to zeroed byte.
 	 */
 	ptr += 16;
-	strchr(ptr, '1');
+	kasan_ptr_result = strchr(ptr, '1');
 
 	pr_info("use-after-free in strrchr\n");
-	strrchr(ptr, '1');
+	kasan_ptr_result = strrchr(ptr, '1');
 
 	pr_info("use-after-free in strcmp\n");
-	strcmp(ptr, "2");
+	kasan_int_result = strcmp(ptr, "2");
 
 	pr_info("use-after-free in strncmp\n");
-	strncmp(ptr, "2", 1);
+	kasan_int_result = strncmp(ptr, "2", 1);
 
 	pr_info("use-after-free in strlen\n");
-	strlen(ptr);
+	kasan_int_result = strlen(ptr);
 
 	pr_info("use-after-free in strnlen\n");
-	strnlen(ptr, 1);
+	kasan_int_result = strnlen(ptr, 1);
 }
 
 static noinline void __init kasan_bitops(void)
@@ -743,11 +751,12 @@ static noinline void __init kasan_bitops(void)
 	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
 
 	pr_info("out-of-bounds in test_bit\n");
-	(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	kasan_int_result = test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
 
 #if defined(clear_bit_unlock_is_negative_byte)
 	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
-	clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	kasan_int_result = clear_bit_unlock_is_negative_byte(BITS_PER_LONG +
+		BITS_PER_BYTE, bits);
 #endif
 	kfree(bits);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200608230607.3361041-273-sashal%40kernel.org.
