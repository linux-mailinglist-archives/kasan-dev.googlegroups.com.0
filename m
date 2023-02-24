Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGPZ4GPQMGQENRYTKGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C626A1862
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:00:10 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id v10-20020a2e87ca000000b00290658792cesf4111215ljj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 01:00:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677229209; cv=pass;
        d=google.com; s=arc-20160816;
        b=w241ASVckT+I1JuIAz5prRaGHlfycww3j+sK0HTgHL+ZngSQ1x++YrqT/UE/wA1PnA
         o0ooSEObEkDGOs/e41hWCXVwajIkTNgHfG90aLJwqbtgL9yvcHWvyI/A3XSsM6MPyFuK
         hKVAPeZpyQkJlKOT3cbsXjED6sg/rnaG9xGOSlrVEL/n0ErrioSMN5QcsXNf4xGcEulE
         83es9+XjwMPUq1tPmYXOu2rA0Bvi+aJp3ZNSiKnhfSIvbyKqGm4AJvF5cEUS7OwZQ5g6
         70gxomwLv57DI8RlEOc6pX08z3V5rmV4oAsyC9aQewFk1dnSRvCTr+uum2+pMwjriCvE
         2BpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yHmoTeXmFfvb/tY1a68CuW+Y9CwLAbySvoDZAGk56IA=;
        b=o+Cb6M/SvgwgnwVHIjTMlViu8tFzh1nqykCnQZmDS1CB2yuqurO4+LfV52rpmMpaih
         hJXlBnx2vvdMWO7sG4cgtOQfmwGac1BEyA4nmnHvdUbA7J70465eJN7gBqoLngjhARWN
         Tg6b/Vj7V9PV2EASMHASptrmTeWzLpjJrS2x9/dk5kcn1cH/sRSyZdyiNYXR0Df30Vvh
         iVPI8HctzO5DleEwZ9EuMESCfoEyXUTOdm9xQgMcr2dCN8K4Mw5mMuOTcSHzQjv9+F9X
         og2q6tt9HBRy35uHt/a7De96zZght+DmYpezHss/ncw+IjJhFRIKMfdpd5QS0LRjnP8S
         hYIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EAGIOwQG;
       spf=pass (google.com: domain of 3lnz4ywukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lnz4YwUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yHmoTeXmFfvb/tY1a68CuW+Y9CwLAbySvoDZAGk56IA=;
        b=FaERrd/t0nModAnnWLRDpL8GdQSCdkJHoYvtNTx9A6yITXgfLVTYMfWsoSZEg2Czi7
         gV5HbqntrnbDuDZnhBiwq5D5VeHBa74I1OiutwNwmj6RT+ePqfxcQ8Zeoofh/om26PZn
         NMKsHPQuLBFN8sMKAus++TB17hUCgxCkbmsF0jdafriS+l/93eQx2wUwdyJYPU1HwVEX
         Xsrm/EZzD7hrItjIE/KuwPT5wwMAgzF296PRKiEtsuIjfX4Ci+i/Z2tbTIxQ0CIA2IXu
         S6M6F/c3cyGTm5eWY+NcQ8ahIwB7Yw5YyeZlruH3vwPik8BmXtco33hjKRlvPQfDymTU
         q0Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yHmoTeXmFfvb/tY1a68CuW+Y9CwLAbySvoDZAGk56IA=;
        b=02PUdQBEx5fchCXuaP5KJodDkylw+GtxUmPkesgctP7cBBe5WcyB4sHxwvRwvv1izF
         7jazxhjm6op5Eb/LVCXndl2BAOl47JrEHh5eJh5tJa/kZTDYtQ/SFFjLQ3Px/a6kZYuk
         25H0YuVkiCe+pgD+StgSCp1jdFeVMC0iUrxW1EYUAvdyy0G+AFXuHWbkIj7hsEQ0Vzfl
         nbqvlcvKRSsjsFKNbBLYp5NvpZfFWNFK8gU71l89JbO9vQ1V89CWTiGXSKoIfSuzS+zp
         t+7P8BUFGDjfC7WDsfjGTLMVr42CaahQG3ASdg8hmZi+p1aBEqHjdVAwqs2hO7H/FLQe
         dfwQ==
X-Gm-Message-State: AO0yUKWZGMTEvTDVc3Yel82JpGJeUTLPC4tm9aR/xUOsPZtu/fwOK4qA
	FGVjNjA7TcFQIbqNG2InLXs=
X-Google-Smtp-Source: AK7set9KORs5MKjt4KVgSy1Th9BQiRmAI6VmDSTgsZs13esL8HFQ/ybbnIMz4y+BpEYYJG06VC1IHw==
X-Received: by 2002:ac2:5470:0:b0:4db:1a22:ed85 with SMTP id e16-20020ac25470000000b004db1a22ed85mr4751457lfn.2.1677229209224;
        Fri, 24 Feb 2023 01:00:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e26:b0:4db:3331:2b29 with SMTP id
 i38-20020a0565123e2600b004db33312b29ls240385lfv.0.-pod-prod-gmail; Fri, 24
 Feb 2023 01:00:07 -0800 (PST)
X-Received: by 2002:ac2:5a51:0:b0:4cc:6f59:ec79 with SMTP id r17-20020ac25a51000000b004cc6f59ec79mr5111039lfn.47.1677229207539;
        Fri, 24 Feb 2023 01:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677229207; cv=none;
        d=google.com; s=arc-20160816;
        b=opuABggvJp6sNWoN83MBRpQ5EWs/uLBg34SY8RX9dtHvF09SkzckaWvCXtdvEsy1ow
         EFTIBhk9t4UtNO2iY9r+eqJ3KvYzB6Zz23MgWGINUpLOBWN0eYvpOc/W0j6a8uCKg4UU
         dZxDeHvIVtoqhY97wYR89HfQu62Dvqd5qqveOy3ycjoKU0vttM4gwl7K9YmIzw+lHvrW
         86jl92mL08GqYOivQ4AvIEe4E1qq1zy6P4adCOKRtdxxwWm6VkQT/uCj2syhPScFVUaN
         B14SpNFooAUryvA+HDHxLs82QXAAAFRnAZPMe0L4NtD7HNTrA1yZICAQY1UhLutW5zYX
         cnDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AjV3k78q3XXhT1GHWCKfTuGEDWgoZOrO6Fv+xEYetZM=;
        b=mWFqruaRmpIHpHAsYiN4N1XDbsoo2/WjEvO1BpUhEImyD4clXJU4sLvtOm4QvmIXWX
         h3P3siOZie6+k58a3kdqYgx+CO040wQgGFKGC8Xn3oCM+A/wKjdzpZDKKTaqx+h9e1wo
         HQZspiLqJL9l1rCzthklH+Dtt35p3RjbWkEYB6/9IhWT+kNaJBtpPWXJ7cw0ueEzgL6n
         4eDc8aSQbo89ebT8elbLYjOrYJGD6u5PJ0aWs/lKcqcVp+jpXZGe4alxp7OSfCx8z3JS
         W46+M8/PZyzjJ23heLMdA9wsHKct42PuUYeDy2uDYxgINFip+PNuF8Nt+cSs4+rGkRlk
         ZyVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EAGIOwQG;
       spf=pass (google.com: domain of 3lnz4ywukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lnz4YwUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id i1-20020a0565123e0100b004dc4feeb7c2si487743lfv.5.2023.02.24.01.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 01:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lnz4ywukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id c1-20020a0564021f8100b004acbe232c03so18238281edc.9
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 01:00:07 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:53eb:6453:f5f5:3bb9])
 (user=elver job=sendgmr) by 2002:a05:6402:3216:b0:4ad:7bb2:eefb with SMTP id
 g22-20020a056402321600b004ad7bb2eefbmr9255387eda.3.1677229206892; Fri, 24 Feb
 2023 01:00:06 -0800 (PST)
Date: Fri, 24 Feb 2023 09:59:42 +0100
In-Reply-To: <20230224085942.1791837-1-elver@google.com>
Mime-Version: 1.0
References: <20230224085942.1791837-1-elver@google.com>
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230224085942.1791837-4-elver@google.com>
Subject: [PATCH v5 4/4] kasan, x86: Don't rename memintrinsics in
 uninstrumented files
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Jakub Jelinek <jakub@redhat.com>, 
	linux-toolchains@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kbuild@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EAGIOwQG;       spf=pass
 (google.com: domain of 3lnz4ywukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3lnz4YwUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Now that memcpy/memset/memmove are no longer overridden by KASAN, we can
just use the normal symbol names in uninstrumented files.

Drop the preprocessor redefinitions.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
v5:
* New patch.
---
 arch/x86/include/asm/string_64.h | 19 -------------------
 1 file changed, 19 deletions(-)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 888731ccf1f6..c1e14cee0722 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -85,25 +85,6 @@ char *strcpy(char *dest, const char *src);
 char *strcat(char *dest, const char *src);
 int strcmp(const char *cs, const char *ct);
 
-#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
-/*
- * For files that not instrumented (e.g. mm/slub.c) we
- * should use not instrumented version of mem* functions.
- */
-
-#undef memcpy
-#define memcpy(dst, src, len) __memcpy(dst, src, len)
-#undef memmove
-#define memmove(dst, src, len) __memmove(dst, src, len)
-#undef memset
-#define memset(s, c, n) __memset(s, c, n)
-
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
-#endif
-
 #ifdef CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE
 #define __HAVE_ARCH_MEMCPY_FLUSHCACHE 1
 void __memcpy_flushcache(void *dst, const void *src, size_t cnt);
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224085942.1791837-4-elver%40google.com.
