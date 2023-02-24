Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD7Z4GPQMGQETQ6QYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B7366A185E
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:00:00 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id eg35-20020a05640228a300b004ad6e399b73sf17740388edb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 01:00:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677229200; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICuw9JI7GGI22HZKYPhAj2+kS1UNpxoOOBmJ0WLwXFR8w4NyIWkLyaxryUjCxZ7o9Y
         XBhS8sYr/ilQJs30yJvBrWfopzFZy3app0AFypECLL3giegV+VRsZpxwV4lfuEPSll6X
         uQo3fFnDGLzIwMr4sA+S8F2SA/jbNNho+YqRwSkiEPwuZm/7I0qkVtn5K2R7d7hLPk6S
         UXz7p77J6NkFTL5aU0P4GHGSjLoEoeJ6lobI9F6kxQ5Vcn4Ht52z09UBPuVufvpVzFLU
         ZRv8ICsVi+Zkcws/NKX1ZrS8eG8fgPHruRU83VEb1DtSkyHKgM4y0kv8U3NzWeMv808i
         ZC3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=dpxdhk2WmZPAt+zeqhelE6eIDtaUev/yQaoda27mgdQ=;
        b=L8JUzJWAKGEaENkcDVh5T6WLIbneUE7fTyu6l8ujCUa47gW6j2JLl+BdEahb6xmeg+
         Lu0r6pcN5hM792dEODXMlmY7aH6tWMcFKGPy6yI+drvTt2gLMKiV2Nw6xF/28T3/LN7q
         jMRWvo4rN6sysqLC3S8c3Doz8gwW0S6bFa1DArXzMNRL8Sxx8hQjtipsuCYPc50f1fw8
         x5Qz4XzYFYG3FJd79CuDPqzZCCZQp4oJNF8vuDp2C0SAQq0MNTsUiAlkn16v55WXzfAQ
         6V8UzmzQGT8kEvVV95+t90UbBjILO2cmpRTQn3SZnPvjqfHiRBurcGUp46gVs3gP1mA6
         hSLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nsiAeT3s;
       spf=pass (google.com: domain of 3jnz4ywukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3jnz4YwUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dpxdhk2WmZPAt+zeqhelE6eIDtaUev/yQaoda27mgdQ=;
        b=b2CRO4qP7Apn08ERouyCSYvjUD7zDOS86eXe1l+DkX19lsjm3gQ3l8fe/DqLVYh/Zk
         ELJdrVRJqONeBcDgNYDNQXwtxuJ5KIivu2N/b4+LRI8JAGv6htZm2ZAsXjyhcW/eZGK6
         cBAS8Fuv0koD9rIf6FzNrHvp7DSdI3Qk713+F+IqbMsTpjVgMAIYj6FVaG5CG0wUFOpY
         J+ttQPLY8FgI3H47wijEnSgdPqExuhbV7oxspSavjth12N/Sneqt/nxcLZcxAcXUX5oz
         Jv2519jEsGA4IxZIntQ7IuezPNVNwRCHqiuB/0/qNMIJbV5d1u4uxisZdFnFGm8DZjUg
         EbLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dpxdhk2WmZPAt+zeqhelE6eIDtaUev/yQaoda27mgdQ=;
        b=W5D8360xgCBXG7bmo1Xg2zQtyZffXP34gLaucX4yqCKcH0ED6P3xAcLVCUGLyJknma
         gGx10UaOqsrwq3Ey5uj0ZK9UGE3Ocw6wD3k5pszW1gNnsi/A0kBcWwFJk9XMlHWh82vC
         Z+NVSIPgUXQfYfwE3tZHYDDnmUGJd9FW4qjV492aBkT4sVSSO4l2jj+ezLXr/D5Ar080
         ddIi6eLmXLJB9XxGUvEBYVYaVU4Z1OrZw3KbTfdumtGB88Ltb4JaOEWg9gjFi2hj+Q/k
         81urUSb8jDvCTqI9zIZG621fwDxbN7bvIXrwTvwKt93VAR5bHun6uJnX04qOPB2pz9u5
         ajlw==
X-Gm-Message-State: AO0yUKVCUuzULwVJEjEpyhIhMykxMb4vqNrjEkriydCa2piyeMk2LR/u
	+bRFP4O7YovsERGd4x76ANk=
X-Google-Smtp-Source: AK7set+7ZVL+/Da8NPDxW9N6KhQQ7jvEvt4zBJhD9Q/VT72+LTZ9cPN/FBa9o1x3Z7gQH2LQRHbqmA==
X-Received: by 2002:a17:906:58c6:b0:8ee:babc:d3f8 with SMTP id e6-20020a17090658c600b008eebabcd3f8mr3297138ejs.3.1677229200016;
        Fri, 24 Feb 2023 01:00:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a007:b0:8b1:2846:28e9 with SMTP id
 p7-20020a170906a00700b008b1284628e9ls1231594ejy.6.-pod-prod-gmail; Fri, 24
 Feb 2023 00:59:58 -0800 (PST)
X-Received: by 2002:a17:906:22d3:b0:877:5938:6f6d with SMTP id q19-20020a17090622d300b0087759386f6dmr23230918eja.56.1677229198440;
        Fri, 24 Feb 2023 00:59:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677229198; cv=none;
        d=google.com; s=arc-20160816;
        b=U1k5xEFBa487YbrRhfN519tk4IhHkTV+ke616eyiAhnS8+3mK7ark5D/r5ADxlSXzU
         lgqlQJLQNknZtwDM91pQzrflTBeucigf+T4z8woo4LxEXBL2McJqTn5pfsF0wrK4vYiv
         8D6MAe/ULDZONDxfUHj3xPDg0THSa2XQQVlqbv68Yywtrax07GaTzhKUIMzv8T1+JlWg
         T9Q3HIrGi+TRamCR8x4KjCEfnszWVK/6UEscmsG5+VJNQSd4LW+kuuSW8l15YkLiY4cj
         78lnmQuAXlyBYT11wXZrNZK8h/BF8dddlLSbovXhWOD4cnBtn6PuFXRCXMY3y0eO5OrZ
         TrsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=utTJOkvRGl0nLL0ic/scm4HYcaWRO/7AK96vkAXGENA=;
        b=ka3w88BRBGIfIfI86MvxS6l7XtS9fEo4nbgcxiOPxOBE0dCI29AXQloBqvFO4C6D9q
         WLlOOEAR37jWq6HR2mSg1WzAT5HUuS4BFLLSi9/kqyCMpK1yz8ZJSWCBESSKiZQKN1Y8
         xBzA7/t4R+vZYcBQbhj82aHOEZMYoC4tCs9p9AJ+UX2yrvwuWvwXzhXnF5Dcsmm1EFxr
         tYQEFH56dgsfoUMueGCRDQOuVoe1QUfQX3etcCbr3w4FczzILGgeRzyshE40YIOrQfks
         7dJgk7vvgceF27Z4i9xKtewuwKh8KeYElyD4wYkWMzTdojGJj1oPLEfBo/dHNzih/6l0
         7S5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nsiAeT3s;
       spf=pass (google.com: domain of 3jnz4ywukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3jnz4YwUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p7-20020a1709060dc700b008b1fc586833si786355eji.1.2023.02.24.00.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 00:59:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jnz4ywukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id eh16-20020a0564020f9000b004acc4f8aa3fso18510046edb.3
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 00:59:58 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:53eb:6453:f5f5:3bb9])
 (user=elver job=sendgmr) by 2002:a50:d682:0:b0:4af:70a5:55af with SMTP id
 r2-20020a50d682000000b004af70a555afmr2075203edi.1.1677229198008; Fri, 24 Feb
 2023 00:59:58 -0800 (PST)
Date: Fri, 24 Feb 2023 09:59:39 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230224085942.1791837-1-elver@google.com>
Subject: [PATCH v5 1/4] kasan: Emit different calls for instrumentable memintrinsics
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
	linux-hardening@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nsiAeT3s;       spf=pass
 (google.com: domain of 3jnz4ywukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3jnz4YwUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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

Clang 15 provides an option to prefix memcpy/memset/memmove calls with
__asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724

GCC will add support in future:
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777

Use it to regain KASAN instrumentation of memcpy/memset/memmove on
architectures that require noinstr to be really free from instrumented
mem*() functions (all GENERIC_ENTRY architectures).

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
---
v4:
* Also enable it for KASAN_SW_TAGS (__hwasan_mem*).

v3:
* No change.

v2:
* Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
  param, it also works there (it needs the =1).

The Fixes tag is just there to show the dependency, and that people
shouldn't apply this patch without 69d4c0d32186.
---
 mm/kasan/kasan.h       |  4 ++++
 mm/kasan/shadow.c      | 11 +++++++++++
 scripts/Makefile.kasan |  8 ++++++++
 3 files changed, 23 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 71c15438afcf..172713b87556 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -637,4 +637,8 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
 
+void *__hwasan_memset(void *addr, int c, size_t len);
+void *__hwasan_memmove(void *dest, const void *src, size_t len);
+void *__hwasan_memcpy(void *dest, const void *src, size_t len);
+
 #endif /* __MM_KASAN_KASAN_H */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 98269936a5e4..f8a47cb299cb 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -107,6 +107,17 @@ void *__asan_memcpy(void *dest, const void *src, size_t len)
 }
 EXPORT_SYMBOL(__asan_memcpy);
 
+#ifdef CONFIG_KASAN_SW_TAGS
+void *__hwasan_memset(void *addr, int c, size_t len) __alias(__asan_memset);
+EXPORT_SYMBOL(__hwasan_memset);
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__hwasan_memmove(void *dest, const void *src, size_t len) __alias(__asan_memmove);
+EXPORT_SYMBOL(__hwasan_memmove);
+#endif
+void *__hwasan_memcpy(void *dest, const void *src, size_t len) __alias(__asan_memcpy);
+EXPORT_SYMBOL(__hwasan_memcpy);
+#endif
+
 void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index b9e94c5e7097..fa9f836f8039 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -38,6 +38,11 @@ endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 
+# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
+# instead. With compilers that don't support this option, compiler-inserted
+# memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
+CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
@@ -54,6 +59,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(call cc-param,hwasan-inline-all-checks=0) \
 		$(instrumentation_flags)
 
+# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
+CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+
 endif # CONFIG_KASAN_SW_TAGS
 
 export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224085942.1791837-1-elver%40google.com.
