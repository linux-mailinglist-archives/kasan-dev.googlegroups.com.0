Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQWEUOMAMGQECLVWBXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7243F5A2A8E
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:55 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id f7-20020a1c6a07000000b003a60ede816csf621964wmc.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526595; cv=pass;
        d=google.com; s=arc-20160816;
        b=ES2DFVcqwTK5AP82+TET5O6srNVx0DYj8k3mtfgmFMX8ODlJXo8YrRj4l9DYo86Utc
         jpgHSM7eQkeVvnxargMzaJkbQuDZ+hkQSxTSCoEveTI6uUQbr/Cpu33KULtBp1VXBIn7
         10ofCOdZTZFA6IjHE6cQYQJKALWWEQM2ddnkzIA77nyC9lg6hmnenQMrVphucEaJuZcw
         sOqC7TBLPXFHcGqLwwguXqTehgYmvWa0JLJ+nb6w2t3NL0oJ7kVKT1QfdOoQR7jRKCFH
         3nT61CKupedOL1ympHWUHb7PZn500KbQmq7DA7kMT0jJfT+Y7E4lqedXLAZMFGzyLzCZ
         02Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Kd9KKQWR9KSOvvq3Cd/EpCPhZazW8hSs/ibeaoOvax0=;
        b=DxfMdNyTNwSq0fTeYHjQ5d1cvOiqZLCdAB1snhhh0kdeBn9mKpL77hqtWGkfF/YYPs
         /cNX+T8nVX3VVjoaSAjSegrrCe8aUebT0RcA8GbiCSa0xvixbha7gL/qy+cZMKgdInad
         /DDIkPnVS/46HpxSO22fspqsXT283Qz4HDmrVtdDS3DqTzxHLmHzLaayIqj6qBgUilk9
         GZKwVE+KrB7S7FH0a4F1n8Gigbe9DxlOZCrIRGu+DopMhb+FUDbl0FV+p8kbOKmlWMJm
         feC0f6Hbq3ydBWkmgCC1mpJfgaosrIi9c0jTW6ULcN2ofKH5vNvcr3MYcC5l+oh2l8Jp
         H9sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BC1C5JPZ;
       spf=pass (google.com: domain of 3qeiiywykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QeIIYwYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Kd9KKQWR9KSOvvq3Cd/EpCPhZazW8hSs/ibeaoOvax0=;
        b=mJUi6S2CnlEbaWGrm0Rw4LHcy01ZzET4Rw/1O0MpUOkBbFLSLkOxT/HMR5zf6z4IY5
         DLGel5pWV25fytq/WA8AlE7Rg2wG5hGZ1kJfWONc2LZ/HthnrZa2k9UhBRrtfbyjyn1b
         ROAmEbLOuF5fGRoM5c7kVTkQTK9f6/S/BSDsbrcoEFAte8aypsjKvyHgp6hOzQkeGQE5
         8OkZdYr0PXHic732sfhNg4u7qc6/D+ih7uVx865UC2VN6jkrNQb6NnqJzQg5LVsrtV4a
         l77BbPeO5PgXzJiRDIFwhTIDxXoDr4itcBONSRF5NTFYU1WPquMGSfn/F5zJgZnvozZ9
         aAlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Kd9KKQWR9KSOvvq3Cd/EpCPhZazW8hSs/ibeaoOvax0=;
        b=YLM7tA/YeRLaoWaAmcbTcx8OUprWi5x3r5dRC6exQ+L6RAKOCVCKhLAdBwzUVx2fOu
         OwCPsVtBBvu/r67ejH5iDqCQqcspFEIcmdHWsto8Q51Ygn/wj38hVwJkc5XWZjH4bQhP
         tFFDk/qTaY6BgTkv9lrTxZUC51cme15QMdrLYVJb2seMslCIUlQYKeEorMGC2ADgzSHC
         sbV2WzP+XTMWyQR28lVtt/TcFvFa+UfBn7NzdmL/93FNxRd8Q0FNZLlTfs+QWUGL7O0R
         BCoEoQXA/B70Z3aB9gWCAqphFLMs2KRJ3YytXjj/7QuwyEFnOG947yGUktxUi6IkBA6x
         aUQQ==
X-Gm-Message-State: ACgBeo18qVdaDWb/XEofqunZRDFzK6Y+vPBwSlfnyKe9+r38IWf9niTv
	1zuFd7oKTW6Igu5sAcaZKTQ=
X-Google-Smtp-Source: AA6agR4ApqJ10NdqBA071XDA2m2aJ/yU2B/09DnDLwqrpqtKkKX7u5Q1v5a2jT8oqLJrsRsYw1g3SA==
X-Received: by 2002:adf:ce01:0:b0:225:2751:7654 with SMTP id p1-20020adfce01000000b0022527517654mr79022wrn.220.1661526594849;
        Fri, 26 Aug 2022 08:09:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:251:b0:221:24a2:5cf with SMTP id
 m17-20020a056000025100b0022124a205cfls169648wrz.0.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:53 -0700 (PDT)
X-Received: by 2002:a5d:4ac1:0:b0:225:8a13:72bf with SMTP id y1-20020a5d4ac1000000b002258a1372bfmr85633wrs.72.1661526593854;
        Fri, 26 Aug 2022 08:09:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526593; cv=none;
        d=google.com; s=arc-20160816;
        b=hl6zuWH75E5w3PQPoYbCklNk+d0H5sTnYMzU5xqTbB0gfWzpFvP1vLCj9Pcoj2Aoig
         wioabPRbTom1Jp3SRyCoZkSXYal7yCTWGWQW+FOZr3ZF3L5QvLOjhJifhbdaEHHtMkff
         GulavMEEgZ4CrOG6g2pNJxihRsXBKpTXTy349z9adDF55qXE+hbr01S8wORldxDVWXSq
         d/dvWtHzE2iRVlpDO3jsW/ehVDFRLltJLsj6VuLKKOZ3TPbV4NXvo/4elnzI3omJP7mC
         e7vrFUy1YNCEI4CgqgTEBfVf9y7fM1CClTVaBQ62HHoEcK+J0MNYxDEmLqpbdRX+KPYp
         8ozA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uVzdHqFGYZKd4Qu5GJB2AnYrpVyvjfHfk7LqoEQIkSc=;
        b=VUHsh93KnQ87IrNcCEKa7P7YMN7GFzCnDjACeYfikIFIE4Y97CtnczgXGckFeiYB6Q
         9roowLCeQyrGysvXQWyUskX9UXIjJHvED+t7G66odwfcISJ43AkttDHCw992ExmElBBK
         /WpssZBMMjtbVaaOZy37BbeDVmf2pCHUFoSqXZoQviPXT/58yNUAKIjorK+0A3MMyOM2
         ypjR+k02julOMRQ3rGi9oQGHFK4Kt67087dpQKucINcHFREUTVWHi0gY5fUjhFdPL/vl
         gA+yqokm0wh20S1PF77vN49/5xNko+hWvgZO51+2yPnJE5UsVIH/4R7ed0c5ubh5yXwl
         jwHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BC1C5JPZ;
       spf=pass (google.com: domain of 3qeiiywykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QeIIYwYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ba13-20020a0560001c0d00b002206b4cd42fsi987wrb.5.2022.08.26.08.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qeiiywykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f18-20020a056402355200b00446c8d2ed50so1221870edd.18
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:53 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:368c:b0:446:48d9:2be with SMTP id
 ej12-20020a056402368c00b0044648d902bemr6858842edb.167.1661526593376; Fri, 26
 Aug 2022 08:09:53 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:59 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-37-glider@google.com>
Subject: [PATCH v5 36/44] x86: kmsan: use __msan_ string functions where possible.
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BC1C5JPZ;       spf=pass
 (google.com: domain of 3qeiiywykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QeIIYwYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-37-glider%40google.com.
