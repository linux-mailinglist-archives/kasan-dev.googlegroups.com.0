Return-Path: <kasan-dev+bncBAABBIOWXOHQMGQETR4RM5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FF484987E1
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:08:34 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id m9-20020a194349000000b0043955e8f436sf1237787lfj.11
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:08:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047714; cv=pass;
        d=google.com; s=arc-20160816;
        b=hpUZ0P4ZfYuZPsqFjpwm48CBy7M9jE0v58bCYNAt7l1ssA7gzTRCipFC5+ijpGzGlj
         WIJy17yOjuemHb3oMOVFyngciWh588paOqsCF+1SqVj+kMEuGpgGhe5MxBMswifnwTfL
         vRBxyjbcWrU0S876qKDRUfmpZsi1a6dgF01s6X5CMU6alu8NoTtqWezcZ2JOOFjADGeO
         7F4XIyn8S/8iO7MAS0SzI/SEq7ulxx7MOtnRMZfaNvYiKnuBJNGMenD+Uu08hx3nDk7I
         8ryqGY9AK8BsuBsSPuo0jCtsmrJwRSd+KSaM4Zv0ddphVWGGjWHyqXkw9hXb/AOcYtKU
         EDTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZM9HPCYF7Yr5EUi+UjL5oinUz9PZVr0qscdWPnZHmTg=;
        b=xp6a47DxcluRLuz5TdP2RgSZB1kWsfR+aAUdWLWHoBGuGJWpxAhuc9MsITWHzYOMzo
         TviIYD0RS6AbBiP47q3JNAbDQ57oQSfJ/hnQJ1vvbCOQmKbtAQIE7iq8xkb/8KJXS1MT
         /uEq7CSCIHJZ9GYvs5Yt0FmyFcYbkGBarT3JFbXk4F9m05puL+tAluDTAhSfrvE2K6Jj
         HRKtvYQ2jYgVeMZWlEUSQQ2c2rshHa9YeEz2sjIChZ96qkRo6x3jVgfZiG03dcBoZWlr
         1jKBqPLk842ax27cD8beASBahERw/F/pZ5VJfXx3X6SwrTUWFY4BK16OkRkVEr9RrHh5
         AQ0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kHtoih+8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZM9HPCYF7Yr5EUi+UjL5oinUz9PZVr0qscdWPnZHmTg=;
        b=jEHWJDZzOWn8MwmZwbi/OVcyqehXpsOUuN/KhXDI0Iq5F5yudgkizdhD+0hqnAx02K
         pKRPXO9JZalUSz7//0GrexWOSsFpS41XiRL3ESihUc0xHYp8cBUeq45u12Xh78SnURD9
         WSFN8vNjF0GHKuk05QrecgxghY1/Njru/JQ1vuKAgkrWQK+MIURahTB8AvsUJDiLzSfN
         /uEi73NFGyeYiLd8ic91qmblxfvwyiU2DNFwklCn8jPhhpwR02uNybHxulm2JCHvsD/9
         sbfPkX40mIyNgYpH4KSUuzcnxeXJyYqXjR+/m4XTygzk+edfcEv7u/EwX/mv7TVk0Bba
         S5qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZM9HPCYF7Yr5EUi+UjL5oinUz9PZVr0qscdWPnZHmTg=;
        b=FJZoXGVI3ApJbG5SO+J7h1ijer3lpiS8a00qwRF7BzhgrQzjzmCZRCwcsSYYwkON/J
         t97ytcFuoKxP7BiMiKXn7ZodRsOEzMxmxrV84RjKbi1FcwZ7N9seKEt+xQLVY/hOs7ji
         tpWKSwTFYbQ8omKc30dkfFibaQna6vv26ZJTzDsNCJtjl/g0+dfvzfWFs64nhV/8bdHg
         VMYW4uCKPvHLzNC93rl8mcr8R4YU/gDAiDcRuQol5ovX3zjqzcGcRtxK5BcjLJKjI+Ec
         Us7BRfcHR9uaIkeC2w9JnR49itrNHrPFPQx8qBAFnzkubW/EYyPRSuaRAtit7CernbuV
         Yenw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xo5XGdqoiFKk4ELCpx27HDS6AJW+wXIxwqulFdN5UliwMvtly
	NIPcgOVVNssbty4+RT6eT18=
X-Google-Smtp-Source: ABdhPJxtbxhBxaK8wfDOJkSyQFvbIe7kinbtQiQODnxFK5+jIKmgpyzEx26F+jGEgmdmWzVjVqz4Ug==
X-Received: by 2002:a05:6512:696:: with SMTP id t22mr14258929lfe.538.1643047713948;
        Mon, 24 Jan 2022 10:08:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b90:: with SMTP id g16ls577852lfv.3.gmail; Mon, 24
 Jan 2022 10:08:33 -0800 (PST)
X-Received: by 2002:a05:6512:2350:: with SMTP id p16mr14115741lfu.336.1643047713255;
        Mon, 24 Jan 2022 10:08:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047713; cv=none;
        d=google.com; s=arc-20160816;
        b=Bzf+EwjlUIA9/0dpmM5fjMFCQV8TEKOdLTb/wS931ryQngxRNI4qo+OZxhfjwHstmU
         60r+Bx35eodFluvyVG4waKy6kCPZBZ+FYSSSt8OfWpUx4/vcN9yPL4+XLlRMv/q1aOER
         JqGA1VMqG9RZzKQy7JP5MuFBjgbfSNyt1QP5jLMnA0oW+JpNIfbBrKjbElqHjoeGHdD8
         Yvgg9DJWzbLCMJ5bIWtulzQxoszOxAjtZnPMk/l3EJC0jgdc11BsAFOLkqVHue6v5UuV
         xdvsq3rCxX3RPEqlWaFXpWK/uyTxV3nunoJO6f1eeWN7fEV7c37csvYAQhMRApxrnuik
         D35Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=KO09vFf2qxwUrQTKFmzuwYxPPnve2SSkI6ihWxgX6aV6jp2bN0wBfC7DHCOGCIAZl9
         f5BU1tAg7kEtWDyLPr8oM3BalghEKGn19E+/rf30e8G5zJfrbK+84ZOZpcgC4l+5JIty
         8j1VPYAlsiclRIX+xZjMR0IuAsaPrl2dWlFGYC7Pt7otLxLR+xV5oYNz0yqLwPx3ro+D
         O9tsKgQeN+f2//r+o/fnxPIuUhYEUwpl/1Ty2Iz062URzZgPOOb5wEY59rMDCKdN4Lce
         6krwHf5C/xhnuxNsv3h6JodsA0moFuDpZ18yeAH9yx24sgL07AspFCPJ+CcsuyVL00eh
         +Mwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kHtoih+8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id a6si630352lff.13.2022.01.24.10.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:08:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 38/39] kasan: documentation updates
Date: Mon, 24 Jan 2022 19:05:12 +0100
Message-Id: <a61189128fa3f9fbcfd9884ff653d401864b8e74.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kHtoih+8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Update KASAN documentation:

- Bump Clang version requirement for HW_TAGS as ARM64_MTE depends on
  AS_HAS_LSE_ATOMICS as of commit 2decad92f4731 ("arm64: mte: Ensure
  TIF_MTE_ASYNC_FAULT is set atomically"), which requires Clang 12.
- Add description of the new kasan.vmalloc command line flag.
- Mention that SW_TAGS and HW_TAGS modes now support vmalloc tagging.
- Explicitly say that the "Shadow memory" section is only applicable
  to software KASAN modes.
- Mention that shadow-based KASAN_VMALLOC is supported on arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 17 +++++++++++------
 1 file changed, 11 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 8089c559d339..7614a1fc30fa 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -30,7 +30,7 @@ Software tag-based KASAN mode is only supported in Clang.
 
 The hardware KASAN mode (#3) relies on hardware to perform the checks but
 still requires a compiler version that supports memory tagging instructions.
-This mode is supported in GCC 10+ and Clang 11+.
+This mode is supported in GCC 10+ and Clang 12+.
 
 Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
@@ -206,6 +206,9 @@ additional boot parameters that allow disabling KASAN or controlling features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
+  allocations (default: ``on``).
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
@@ -279,8 +282,8 @@ Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Software tag-based KASAN currently only supports tagging of slab, page_alloc,
+and vmalloc memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -303,8 +306,8 @@ Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
+and VM_ALLOC-based vmalloc memory.
 
 If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
 will not be enabled. In this case, all KASAN boot parameters are ignored.
@@ -319,6 +322,8 @@ checking gets disabled.
 Shadow memory
 -------------
 
+The contents of this section are only applicable to software KASAN modes.
+
 The kernel maps memory in several different parts of the address space.
 The range of kernel virtual addresses is large: there is not enough real
 memory to support a real shadow region for every address that could be
@@ -349,7 +354,7 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and powerpc.
+arm64, riscv, s390, and powerpc.
 
 This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a61189128fa3f9fbcfd9884ff653d401864b8e74.1643047180.git.andreyknvl%40google.com.
