Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ76RSMQMGQEGZIXHPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CFB95B9E2D
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:16 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id e1-20020a2e8ec1000000b0026c27b66a2asf2094367ljl.11
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254375; cv=pass;
        d=google.com; s=arc-20160816;
        b=ngmakm5aNHBcnk1k9eTW/x+AhmwWuSmGBImIuIRtkMVV4BLkcWvN8mfBGeVvbOlmC1
         3O5xSo1epKD9c6bxiSaSTwqiOjxM8iVUZI6sgDToRldMk4MitsI9NfoJRG2v/rM2EwI3
         HFeykniYUrimh/p/o9n7xdYxWUy67m48bT09iU1rJc8oQL177TjflhBf4Y/EWhvkbGFc
         3qtOF4+ZR1bMkYkHr+/jshTCPuCpmLZQbWuwa0ONvsqq81KbVQCHyc/6pa4MSbkYq2jw
         kKkIhoJUjK2mMT5M2TNtMEa48lO8wbhRzIhFVNW4ORsMtD8AMBoJzGEPOs1dtkDosebs
         pcLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ij0XXzeNSeHLzh9wnSK202HOQHdKqCS5Zmw+UBa9ezo=;
        b=ceKwSS1jrRcp0QTe9wBGNXQMeixQwuVKALM0EMiSK84nKdrwtMj43Vp00JqVWKrHX9
         gzn9je6/M4veBTFaIAOq9eToJPGPy0qb7xbxc1NACoTPMAzfVos3eLgmxd1V7qni0PA/
         isOCp08GeHsiPJEh7u76lHS4zE77RgYzPxVZwtmajeJ2WXcITLqPeJ2AQhRSd2IEgWUR
         tj4wnDkQUOJ8vu6m0sz73Jod0dco7ukF3RfDKV28Q1PebAF/A9ARdUk+vqfZo/YbJ9g3
         fJ7lOKhsCTV3m9qhEkCe7QJ1QHE1v9TCOlmQlmcjkXQ/HGLWP+eC3Z9wFfkabhz0AVOD
         v57Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eNKbMoJo;
       spf=pass (google.com: domain of 3zt8jywykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3ZT8jYwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Ij0XXzeNSeHLzh9wnSK202HOQHdKqCS5Zmw+UBa9ezo=;
        b=Yz7Pi1gJbTEE4lR65CAs3EaINZYz4IEvtTY3AAUyhQDayCys0dbvqDUuxJF+RafY9s
         XGR1K9mmCMQWQi26GlidG32a55lZV1L4J3U2SYbOsQ+Z3CiUzfynGw+NzCJZhbNVmnb5
         RXNEYbhO/MM8mIuvuY4ycHwQP9hL4mcasovSBxfgCfoqbkfkhMXRZCD4erDu7Zvk8rte
         OHFYFstJKPCUgR0qu7+Vxu0wUp1BKLZiTcbVL1TRqlHrmfvAeWvjXmmNb8yEBY8C8ZNM
         eI5IPcWybBsLXOo2LF9hhmNRhhPweoS2g85uajcv0rOdOMU6Q2xwDebVGLzwC2AQIrYj
         orvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Ij0XXzeNSeHLzh9wnSK202HOQHdKqCS5Zmw+UBa9ezo=;
        b=Rmn56cxGh1rp2lHuJnwgDZIgq0iDOKS36TiFpi9IFZqCVgtfTlZLjKqG67I2dWRJd+
         e3DFXNYd/XHaPWnErmTwBjbgLCQrnl4iCcBwN73kzj9cSiT3ioX5ZFLsp6TRajAiv6li
         BdiOS7xe84zY6EeQSSnTN51ldfFM68jg+UYxw/bfHiwwaaR7zDRzE+h5Oy0Xd6kwUQtq
         LImpcS6FjIWTMZOt6xF/5ZfFQJiL21x+kl39lpiA4NnAgczgBJI6unG++DdtyVJ1h5bB
         3BWJqcF+5wHWq6rqIV3ZI6PSHF6P+HiM+5lDFFvyeMe1F0GoL2WsL/TqXibkfqhtZAOh
         oZcA==
X-Gm-Message-State: ACrzQf391dTqiZ5xSo3z2Moh4U5RRm+cvDYIplTmA+hiAjCRm+JW+Fl5
	MattYcBBI1UVcJPavHi1OjY=
X-Google-Smtp-Source: AMsMyM4+8ct8wAqHBFWI9M58j4LcVHvozCOi+0/7PSUWfjtOooleF8yacivnv6fAjxnshZXjyvZGiA==
X-Received: by 2002:a05:6512:16a8:b0:492:e32b:8e42 with SMTP id bu40-20020a05651216a800b00492e32b8e42mr123636lfb.359.1663254375767;
        Thu, 15 Sep 2022 08:06:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:221a:b0:26b:fc94:e182 with SMTP id
 y26-20020a05651c221a00b0026bfc94e182ls2102415ljq.1.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:14 -0700 (PDT)
X-Received: by 2002:a2e:97d5:0:b0:26c:1d93:1a0 with SMTP id m21-20020a2e97d5000000b0026c1d9301a0mr64327ljj.322.1663254374340;
        Thu, 15 Sep 2022 08:06:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254374; cv=none;
        d=google.com; s=arc-20160816;
        b=Pu8336+gBofoqXrnTtFCrtqhyf0r89xUsbisUAPcnqS6NDPtPL0KHowm8fdrYTtW0D
         FbEi8bkYPyJafEY5MQX7W35Z+cxORSk+NSwujMnvOuwjIt6YG+Ja9y+52yt0mV5y1VIi
         HNFvXV0rX+evSwMQQNgOaJW9FmidwFtZcjxl5l3/QPXJ3kjtpEV9lPZtkEMyL5NTU0jp
         dx+aJdNJ/iVt54Vaui0ME0FtucIX68iYK46oOp+8zkx3/HPMidoOYOOonDchugOTy5eT
         dDu6Id67ju5oZO3LrXzV7WTX9Sp6tlUlXGbKXHQZwVHlv5qCkm6Q89iygi1rxnu79WLc
         OaAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=s0jAEbnxevXU2w5QvhShkO+su70yEEyH0HIO5IJWDY4=;
        b=B0K4H9TzMGWUHidmAq+zWt5T7T0MSO1ilsm1dkQpYMaja9IXF+bGEm2YQ7pver0Lii
         7DMfdGajfzUUksDocpBjuFK4kIlPhkIsE0UMRDv+Qbh9RENl/S3rBnUjkThun+FXceU2
         xi6X/Rd6x8rgc9oqnfXLYwvc23aZWxZeWNDXFippFHZSqMdjfj7kYPkCfK5TgByWo/Sd
         PCaJMXilSHyXy3MfuulDPPwq5rIMstN29f4FKJiPFNPQUf5/0navCwuovJ2+5Q2xmrhd
         3bb/8HfMprfmcjT5pgd4kMy3og0Sh8db/gf9HY81b9ReLvlpepplncSByumKEM7MsJOP
         OOkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eNKbMoJo;
       spf=pass (google.com: domain of 3zt8jywykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3ZT8jYwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id i4-20020a2ea364000000b0026bf7cf2a41si404381ljn.2.2022.09.15.08.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zt8jywykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id bx10-20020a05651c198a00b0026c1cdb5b4cso2914130ljb.2
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:14 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:ac2:4f03:0:b0:496:e4:4d16 with SMTP id
 k3-20020ac24f03000000b0049600e44d16mr117698lfr.250.1663254373987; Thu, 15 Sep
 2022 08:06:13 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:09 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-36-glider@google.com>
Subject: [PATCH v7 35/43] x86: kmsan: use __msan_ string functions where possible.
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eNKbMoJo;       spf=pass
 (google.com: domain of 3zt8jywykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3ZT8jYwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
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
index 3b401fa0f3746..6c8a1a29d0b63 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -285,8 +285,10 @@ __FORTIFY_INLINE void fortify_memset_chk(__kernel_size_t size,
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-36-glider%40google.com.
