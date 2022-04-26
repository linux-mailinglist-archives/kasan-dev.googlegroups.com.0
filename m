Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUGDUCJQMGQER27F6WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 15EE5510420
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:09 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id k11-20020a05651210cb00b00471d1b1be81sf6509795lfg.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991568; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQJbdBXU4pt0SSlZlR7ULNtUyn+mElCL7KVvSCoL8wV8w5OB8gP3/IVjNb6FWobSaN
         /cgq6Pp1/hsZY0xgDIPhKSqtoxL6Xo1GHhzEViHjWHx6heyHDwFgejYOJXCUmUMy7nR/
         6bPaZal1NyZoqbexgj5NQv5Ny6h6MRHMtgV0XSDYe3WY3krxCRLygSVxRHMsht+Hl23R
         yNLmCpDgl/L8S3GyHRsfuWgChlMQdzU/CyTweWkxrA3UuJEviN18VcouzbRQE2yJNW63
         vO11+UU067gibHlacc7GdasGGF9NEUt48vIwR5bVZr2Lk+U7l0DwVSssbYxo+kfWbaHC
         i4NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=u7+DnIRQkTF2bVoJZBDhzDsFWRTByc3d47ChBHZU5co=;
        b=kIqEfsxwjcoV2pRxv5k+P7ZGovR0BtzkHiuhYb2FnNpxfT1khvFM4ExL7XgMJEIwjf
         JEYadZ/U0WPZyZjS+PDN6wNpksWDHnPS3ijdqUDb0lgyvE+X8zPHVBdhYnCFqLi+pNgb
         i5BpLVq5in73PM4Aam3umPpBgycBdv7LnOFHemC18D/ngsKRiBJtz8crT6SUL9z5plHX
         ZIDGMzThPSJgX2lBrg2HODkZtsXGSR4BPH+pCJINb8vFUcw77cPp8a5d7gxtm72M/rnK
         5Ipf17jBJLkeWlzyVwiWApEIUDrqKQx8PpTHyzlgJ4XL4b2tiG25hfeMVH1/4R6+csnK
         OUXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eLrL3mhF;
       spf=pass (google.com: domain of 3zyfoygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zyFoYgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u7+DnIRQkTF2bVoJZBDhzDsFWRTByc3d47ChBHZU5co=;
        b=mjmjz+nCtd/QkNnwE2t5DuBUmJqFm+sQGoOPDAjQ2WbFQn73M3x467ATKbNKUmrrE7
         UD7p5I/gUQHu4B0RhKcOpZRCFbl6OOas2Qo/pVQrtxXasGyW3FGeMkKEeIhzHGcE7kMG
         op1cky484NHXNAA3oUQf7RRP9sXB5L2ixhz09k9Hgl27YDTZpGsfb+ZKfXg1y1Eu7GOv
         uB9z++yReYqvvx7SZttHP8fLFAOf2Il0O96+Q6mG+lwbOFyQFNdYyF5h4jvIjJQN3BVR
         amRS1Lzc0pu6Zf1oq3xWzfBNrbMNPJMTGHNZHZd7ZbXy148pyKdEQE524KrYsnPOHDDE
         5vWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u7+DnIRQkTF2bVoJZBDhzDsFWRTByc3d47ChBHZU5co=;
        b=0Hz3bytgKxBQRb1J5dsVk2c9sMZdy4eGLZKi2p4sU6k9AxKW2vJg78S5790zhVDHaw
         w5V0mGqO5SvhsyuGjG3Z2NdbwyRl7Ws7nOmXPoNs8UXXPQimD09pKfFMIeNTLbNVifCa
         kKtqmWtWZ/hC8eqRXRsG3g09gGKXek430SQ+mIivr/yVFgTyrJLseJvRtbmE18bxb6Uh
         MDowTN2VWP7t29PDj3mwAYfPwEqwChtnKFpF/FkzYSZxfLqrmmpZfxmx2W4INTK0rF7f
         k9LMeHf8uzcY06mBXoya48Uw9dSo7anSq2A6ruVYNMk0D5W8jujOPdiwSXP4kIycKcE9
         CEBw==
X-Gm-Message-State: AOAM532DwP9a4pPDDtdiO062QpmX4DyoreDp7oLQ8o9y2rnHG0nXvJRq
	Atz8OqU8NTr8xFSA9UWHUXk=
X-Google-Smtp-Source: ABdhPJw0+WhskD4x2mIyG9Se3lGye7W3JlKRsrpyfDEGgn3XU4+YjeueWfyP2FA1GEkHiYtvcYkAXg==
X-Received: by 2002:a2e:82d5:0:b0:247:e3e7:7c26 with SMTP id n21-20020a2e82d5000000b00247e3e77c26mr15359777ljh.395.1650991568652;
        Tue, 26 Apr 2022 09:46:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2815:b0:471:b373:9bb9 with SMTP id
 cf21-20020a056512281500b00471b3739bb9ls2093469lfb.3.gmail; Tue, 26 Apr 2022
 09:46:07 -0700 (PDT)
X-Received: by 2002:a05:6512:3390:b0:472:1a4d:ad14 with SMTP id h16-20020a056512339000b004721a4dad14mr2460178lfg.521.1650991567661;
        Tue, 26 Apr 2022 09:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991567; cv=none;
        d=google.com; s=arc-20160816;
        b=G2MRzkJMulWB/H+/X8yJiZxHwuwonOLHbiTK/AGOC9dMTTf4vii4LLzrQ6V2EhEzuv
         GnGoloSzLqNkSqKpJ/8oAJPwc+CK8jc/qFJbBOIbY9RHZEyGecUpEDx7JmY4PNhrKsF0
         kZG7S+4gNMY9wF689+Afl/BNivHKS6fFo2uyTTUds69ye7dd/PQIIB5cckx6GfiNBJNy
         wFTuyjb1DT77cJD2slIGzRK+erGjbOKJt9ut228rCX5MczPaU2f+TQtbmnsnJLbOGM5I
         mt3zQqu21tU5ymAL4x9o1BGDhnw2sdON/3XTTNZyU91rOZZfIPrqP5ltj1GqJTOtX1DL
         M0qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+FBFHZ/D2CVM8zHnxvAf38XdMkZWjnGIg8UqYOIGTJc=;
        b=WvQTXpfhbPlfDIAXgr+WBl/Fpq5jObfEhJtfrdxnv4nnusYxkzi7pg68fI5SYDKB0w
         1npU5ljwTSrUFb8oZWix9jIqFCjxsmMRT3s94yzEzOAU9bqtnz1CiHMVM+5CNXi87Tvk
         M2N6+TSRnY3N2nFBxCNvgG/OhxyZEDInnGVyXi7AuUlmL28MuBTGEQN/hY3gimKy40QR
         1CLPheLhbqAYwacQtODZe8k4nRXEO8tNv0XFiUWZ56G+rvn62k3ECpOR+LDfn7RNK7i8
         +6KdO4gv8R6+9PRs8fdbx2bYw17DkXt4nF0pSPVlHrAn2U+1CWjeBVfavM5r32c1xFe+
         FmpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eLrL3mhF;
       spf=pass (google.com: domain of 3zyfoygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zyFoYgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id h26-20020a0565123c9a00b0047223e9d7c6si45063lfv.4.2022.04.26.09.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zyfoygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id go12-20020a1709070d8c00b006f009400732so9167423ejc.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:07 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:c793:0:b0:408:4a69:90b4 with SMTP id
 n19-20020aa7c793000000b004084a6990b4mr25741991eds.58.1650991567128; Tue, 26
 Apr 2022 09:46:07 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:10 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-42-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 41/46] x86: kmsan: use __msan_ string functions where possible.
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eLrL3mhF;       spf=pass
 (google.com: domain of 3zyfoygykccwy30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zyFoYgYKCcwy30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
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

Unless stated otherwise (by explicitly calling __memcpy(), __memset() or
__memmove()) we want all string functions to call their __msan_ versions
(e.g. __msan_memcpy() instead of memcpy()), so that shadow and origin
values are updated accordingly.

Bootloader must still use the default string functions to avoid crashes.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/I7ca9bd6b4f5c9b9816404862ae87ca7984395f33
---
 arch/x86/include/asm/string_64.h | 23 +++++++++++++++++++++--
 include/linux/fortify-string.h   |  2 ++
 2 files changed, 23 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 6e450827f677a..3b87d889b6e16 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -11,11 +11,23 @@
    function. */
 
 #define __HAVE_ARCH_MEMCPY 1
+#if defined(__SANITIZE_MEMORY__)
+#undef memcpy
+void *__msan_memcpy(void *dst, const void *src, size_t size);
+#define memcpy __msan_memcpy
+#else
 extern void *memcpy(void *to, const void *from, size_t len);
+#endif
 extern void *__memcpy(void *to, const void *from, size_t len);
 
 #define __HAVE_ARCH_MEMSET
+#if defined(__SANITIZE_MEMORY__)
+extern void *__msan_memset(void *s, int c, size_t n);
+#undef memset
+#define memset __msan_memset
+#else
 void *memset(void *s, int c, size_t n);
+#endif
 void *__memset(void *s, int c, size_t n);
 
 #define __HAVE_ARCH_MEMSET16
@@ -55,7 +67,13 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
 }
 
 #define __HAVE_ARCH_MEMMOVE
+#if defined(__SANITIZE_MEMORY__)
+#undef memmove
+void *__msan_memmove(void *dest, const void *src, size_t len);
+#define memmove __msan_memmove
+#else
 void *memmove(void *dest, const void *src, size_t count);
+#endif
 void *__memmove(void *dest, const void *src, size_t count);
 
 int memcmp(const void *cs, const void *ct, size_t count);
@@ -64,8 +82,7 @@ char *strcpy(char *dest, const char *src);
 char *strcat(char *dest, const char *src);
 int strcmp(const char *cs, const char *ct);
 
-#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
-
+#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
 /*
  * For files that not instrumented (e.g. mm/slub.c) we
  * should use not instrumented version of mem* functions.
@@ -73,7 +90,9 @@ int strcmp(const char *cs, const char *ct);
 
 #undef memcpy
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
+#undef memmove
 #define memmove(dst, src, len) __memmove(dst, src, len)
+#undef memset
 #define memset(s, c, n) __memset(s, c, n)
 
 #ifndef __NO_FORTIFY
diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
index 295637a66c46b..fe48f77599e04 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -269,8 +269,10 @@ __FORTIFY_INLINE void fortify_memset_chk(__kernel_size_t size,
  * __builtin_object_size() must be captured here to avoid evaluating argument
  * side-effects further into the macro layers.
  */
+#ifndef CONFIG_KMSAN
 #define memset(p, c, s) __fortify_memset_chk(p, c, s,			\
 		__builtin_object_size(p, 0), __builtin_object_size(p, 1))
+#endif
 
 /*
  * To make sure the compiler can enforce protection against buffer overflows,
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-42-glider%40google.com.
