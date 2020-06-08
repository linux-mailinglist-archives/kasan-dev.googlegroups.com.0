Return-Path: <kasan-dev+bncBDTZTRGMXIFBBPEQ7P3AKGQESZIQKOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id BDB9A1F2488
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 01:22:37 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id w3sf15316460qvl.9
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 16:22:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591658557; cv=pass;
        d=google.com; s=arc-20160816;
        b=y4Yzo4pm/s2nbLiSMOoa8yXRvQO446QB9z5dLnqO4qUcTSGyyhZy8z5YmhZRZMBxhf
         r9z4i/k1a4hkbJtyW4m8ab6dIQWOfhyxlKWgFThv/6aU2bzdiOepcDmn6L/VGSzmhVOx
         RGOBPsNYhs0ZKPUJ74gen+3oXBivcQrMSqQj8kCZCrD2yi2WJ2nBpwvmOGu/YrE78GqM
         NA0wgoTXgocFk4Gw0EVYPAqaaXJIvvmPd0Y7VhXFstn0B6BqR9ManQt+jjG0qsinF+44
         gBQEsyVgngOZEmm8ofUDlQ97PkL6PGBmsR2mrQfrEAKZmM/6Ojcpu2fgWp5gzajN6i1F
         AHtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1VKcp4CpkFXLGgaCog4QAb4LLKfQimNR+7lK0OJQTQY=;
        b=McupaG1+TKUIrLRAs9GwRnw7nxpoPF8nzc9lOCdMdO5Wgx6K0OdkGFmbCL4/XunAjg
         EqF3TmhIqDQku7BmFVcbbxtAKiy79kub31BZK1ljQoyvVkNdyt41yCdIYncFFaeQXmOa
         J5N0UbFwUCB+S2vEDt2S24YEfCnL0Zsw2NQNzeMgSatqKbQIHQmO1n2sIX7CljdNcvwJ
         pKRwbA/gJFecPWEzAjHCfbGAJb2Xi+qBEeNqRcnt+lA1Ck8ryc9KAxvnqvvz+jwVF/5T
         Fh/EC56k1kNiJ6T5vfo2yzHpJBPoU65cUb27tgw/8ThZRUtqnV/XY7sget8Yu4qIu2hu
         rPcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ChFaNaiM;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1VKcp4CpkFXLGgaCog4QAb4LLKfQimNR+7lK0OJQTQY=;
        b=sblUMmYA17WQ05InawoDzICnE50U4k2qy3QYnYeUGy1y+pqAwKGee7i6QYwZ4YIC2s
         mBeBcr3TQnL2R3cYqEVVYlidPcrtRG1HJ8N4BZEomzLDi0OiLj3eWaEnhBQYhNIqNSC8
         z7UIhalQljlyJ1mS4Ru1yh+/Rzu5hFxeNeT4tPxMbjDGN0ksKzYhmWHgkiTpSah0xZog
         eYlJRBxOsyvM3U8vPZANC8eu1klzFwOU7KQNsy7O+2GdaPwR0jwAHYlsQ0tR6T3FX3Tt
         ekRinEqvYUyHPF9lGc1rjluyki1dCvKFY22IDh/fp4MzG+P+5Mew957gd2Ci5Q3I1JAK
         04jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1VKcp4CpkFXLGgaCog4QAb4LLKfQimNR+7lK0OJQTQY=;
        b=d7NjCkXFtuoIzUTKuOwUcn/wtvkfQWYxSoxqQ0ff0f2z0dKyeuR/U+BUuidCXxr38i
         pdkE/OS+tmq1usZgYEv1muN8A7KR71MVXpVBlnF1ECSLIx5XRQiNOc1LBv/ymKLXg7zU
         N30KbXnXKdpPnqpIW3gWFtP2/squ3O4v3GsRElkD1KqA2y0BzYXTl0DzmMByFXuojRLX
         xDKXYc3dA8X7Rhfp5ywBdqOqw2dStyUD6Puv/G/CTEhbcK8sYsW0kStXZvV0INOxwWNC
         H7wXsNYNYnZBsXHwP+3nC37IjgCv4saL3q2d9fHjp2B6xIFdgieLqaWf7bKeVJdX0QAz
         NpHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331psTVLlG4unNYe0Ft2+bAPnTyf0PNtm7Zt3u90pXMWE2Crcfh
	YPX17+hmoCgh4F3ZNE3V++g=
X-Google-Smtp-Source: ABdhPJwnCLi/ayytrGL05YnPIbbUklyb0RMZlB16oNZ+DS01+rEoZVyBMXa3LTryM2+cvHTQYj23aA==
X-Received: by 2002:a05:620a:22c5:: with SMTP id o5mr23603970qki.421.1591658556814;
        Mon, 08 Jun 2020 16:22:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3f02:: with SMTP id p2ls7045227qtf.8.gmail; Mon, 08 Jun
 2020 16:22:36 -0700 (PDT)
X-Received: by 2002:ac8:4b50:: with SMTP id e16mr26848853qts.159.1591658556431;
        Mon, 08 Jun 2020 16:22:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591658556; cv=none;
        d=google.com; s=arc-20160816;
        b=irfwXDUk/W/lnnID18yegoJfkprsieadGa6kAhlqWagj4E+7SCkdsepcR8DGL1hiMg
         cyWWDA85RDcsK+KkAhmsyYK8frVqN7hDs2KFDlr1EjNHtuIXwdILAGsxD82nVnKaT7Ed
         2lDAg425v8k+5R0qToluglORyrtmqR9MifU/mmmwklzhM4iAlpiEk0w1EdUflYC9LwZf
         IujbFUmjy2et3K5gCYFYkoIK9am3LJUEwmBRAOM6cMvn7cr2mK9zcWVMzRoRbYeipKdS
         iC86XlWqGrxkkuXwC/LAsUzK2yV5ieVJKCm5heHyMK6jGU13lXNy1mrH5hxCgg7ETC2p
         QCoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jV10bcSa4Lm5eGzwvrp1y5fJTzKq13MMksTcfzghAUk=;
        b=UC1ujf/89HpLGoFL2WaOq1jUqIEMPxaEaLqDNDg4JZDQ86DTusvf/aj1U3Yrv3ZTC/
         SBPtMQOkVL2W2TwJzKe7764oiSvKV+Z5c9VaSgq+omEuB+6s/95Ih+LRaJ7YYk2N6Ykt
         zO3E2DQqwmCAzCjU9Z4mTQeQecAImftFq6gts6+AudVZounHF46EmzXLCzkUNXJzOqJv
         xWb+tZ6J0cCw1lITNj8WIsHGWloTWRCkbJkx+CzYSWiYJ5TUNKPE8/vLTi8+LVcvNPT3
         mopKdkMXQdxiFwGtZXD3v/qzbfCiiLiaCP9As0mnHpxUYK0o8FSrPYX2tk2xS1EIPo4C
         Jq6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ChFaNaiM;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y21si668967qka.2.2020.06.08.16.22.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jun 2020 16:22:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from sasha-vm.mshome.net (c-73-47-72-35.hsd1.nh.comcast.net [73.47.72.35])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4E8CC208A7;
	Mon,  8 Jun 2020 23:22:34 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.4 174/175] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
Date: Mon,  8 Jun 2020 19:18:47 -0400
Message-Id: <20200608231848.3366970-174-sashal@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200608231848.3366970-1-sashal@kernel.org>
References: <20200608231848.3366970-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ChFaNaiM;       spf=pass
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
index bd3d9ef7d39e..83344c9c38f4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -22,6 +22,14 @@
 
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
@@ -603,7 +611,7 @@ static noinline void __init kasan_memchr(void)
 	if (!ptr)
 		return;
 
-	memchr(ptr, '1', size + 1);
+	kasan_ptr_result = memchr(ptr, '1', size + 1);
 	kfree(ptr);
 }
 
@@ -619,7 +627,7 @@ static noinline void __init kasan_memcmp(void)
 		return;
 
 	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	kasan_int_result = memcmp(ptr, arr, size + 1);
 	kfree(ptr);
 }
 
@@ -642,22 +650,22 @@ static noinline void __init kasan_strings(void)
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
@@ -724,11 +732,12 @@ static noinline void __init kasan_bitops(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200608231848.3366970-174-sashal%40kernel.org.
