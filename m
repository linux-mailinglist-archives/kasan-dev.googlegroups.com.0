Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6OCUCJQMGQEEXM2ZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D83C5103E2
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:42 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id g9-20020a1c4e09000000b0038f20d94f01sf1478443wmh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991482; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuOdubPcmqrZnIPLwe6QrdcoM3vUgRE51vRzsV1WASCQp9pK2QrHXg/RL0mjd3odKG
         7XTTFFYpd3tmXL1j202d9rMfD2ZPUiQEOaU6zSwu47RhyncKkALu2qEqxToM+Dqtvha7
         NOosHjzqRXJK50s90X0LAp3DIquU4ZFA8yr0mOxYOKH6P+Na3sTkjeyYvSu2arcooe6k
         UNaxHFv/X3rGeGkxlJvDu7eEakykgTA+PoM6gUnLeEpkECUibbHAAUOEQFCKSGyEFte7
         p8Yt9fmCh6DvOfmeILVUDGEqtuPBqnUdSyQUOYvGFHiXlD1md02Ic6hAzIaBdMABiKFL
         HvRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kp/GUVY0KFyq9blnCnqcKUkC5scH+yvzUSZ8J3NlmxQ=;
        b=1KVeb6DK9hxGkv2Jye7HdJGkXZzpF47byltsd9ZqgYmO2EfPtZYap/mcQ5A7JfN8RP
         BKxBAHqxVCto7RCB6yilapvW7wAL+3HiNIChyr4ti/iuzYAG2vznUyY+laZN57s+6khW
         KlYbFrUFuE1YFgo+YD7BA1cKsEaKb9Vs28we4uDsthPpgrlJKq1DJ3HqxiXPB09cASEO
         0mgEI4fFiJ3EA93MliAQJvDWi4LKWyGkuuZJJQR8MoYxuPv4WXKFNiKhotGD0dwpIT4M
         ulCHqRKtgTOkiZCzM/6trd61qq1uksqSjDic/tD69s6PpYAAGn2vo47Uz2rGKPbgamqk
         m3uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FvkMkIGR;
       spf=pass (google.com: domain of 3ecfoygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3eCFoYgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kp/GUVY0KFyq9blnCnqcKUkC5scH+yvzUSZ8J3NlmxQ=;
        b=qvwThra+qmsLFUXnUzOAK+Sf4mwHTixWbNZNDlZ0vpimBi9djzNPvL84SO271KOiPr
         9INWbaotbSf8bE15h/bO6UKWzJ+4Vhm1/5hiXUpqk08ULB3vaBtATMpXJLh8uoTxNeS/
         16I5+nQ7Wr5eCttStrgD0PmOEUy7cJommC7IdQnjR/gZRHu8WvtKuXvjzEDK2Q3O94iT
         87wBSkQ6kvKGC7CAnifTWGsdRCPe4j0xHgT0JRKwYHpJEOqBIizvaGhm+iM0FJ0oi8Kn
         YJW2ISVubTx0+q4xWW8iUwLWvzKgodPEMGlHRpaKzxUGRd6UQfsSRm6xzGvLuKKBiHw9
         1LSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kp/GUVY0KFyq9blnCnqcKUkC5scH+yvzUSZ8J3NlmxQ=;
        b=K1htxBQi/x2pE0wR0IOYFz2FRRetK/gG/hRAbho0Oz1d7r6ASpEnqpcMad6e1nHxLo
         Q+mDx3wZyNLIUuY9UBkO3vJwNl2bx5LVKE4ZqDqaUFzb7AWFkH9vvA21LvZDsiw6pYyf
         YCELEmCa2UHvHETqFtx1xQzv6jx9wQ2uIeOU5eGJtyfGSkjsMF18VL0bOdkvWo/Pwy4c
         L6qVQu6qRXo2nHR1sts7ldhRN37xwAjTwK3pPtQZnfcyp/VAeKahlXpWVjKDpTLRNRko
         kXUgClnw5/ZSvM4GZ02ZkVDTIAIR/JaHo1QAUvO0q88Pw5DTzhaZqVQN0HqkYlBIDew8
         y9kQ==
X-Gm-Message-State: AOAM532zQ273sXBPetG9ohSHK85lxC8aqJOiGzKM2C94XnNjudfJXEd5
	IHy3RJvfcsguLUZSjQeYHPQ=
X-Google-Smtp-Source: ABdhPJxuuaHdJmAILFhq8gzxdX6jC2qK7mYdChMnH+6oxo+J+blNjya/nRNktJlk3Gkv1LnhlSW17g==
X-Received: by 2002:a05:600c:4f0d:b0:393:ec48:ecb1 with SMTP id l13-20020a05600c4f0d00b00393ec48ecb1mr9861327wmq.11.1650991482141;
        Tue, 26 Apr 2022 09:44:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34ce:b0:393:e84e:a015 with SMTP id
 d14-20020a05600c34ce00b00393e84ea015ls3806343wmq.0.canary-gmail; Tue, 26 Apr
 2022 09:44:41 -0700 (PDT)
X-Received: by 2002:a7b:c5cd:0:b0:38c:8b1b:d220 with SMTP id n13-20020a7bc5cd000000b0038c8b1bd220mr21879512wmk.118.1650991481124;
        Tue, 26 Apr 2022 09:44:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991481; cv=none;
        d=google.com; s=arc-20160816;
        b=tnhzSlmez1hc6xjJJL63kGoCmqKmnAELvgDOUwhHmsI5TvYlWifGdv3Rwhz0EURxKy
         TNkLr9JCvfEMY3t7mSQt2C4K9EDUjK7r79SYNSs3F9IDQ90vsxOxJ1il6fnqScasP9rJ
         2lf15GG1eSr78yPPup+lLKZkBFJV6SY8KwfUjwmvlTLs9PEUzUoEYddjEnmTJtzfTRDQ
         sxGJInu0OSa9amDypTaDVD/2gudXYDg7MyM3Xt+m9S06os7n8y4QtQUCXOTy5yunZ01b
         HHyYpCGXAIDjeU3aNnWmsc4vfHHjcoiqOpCeTLOEbBW8ZFr88PJrpmAoOjlR2ZzWDTCF
         VHHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/0H5A8X92xIp0p19j3P2M66qBbmfiGtveehlyZCJw24=;
        b=nvdxV8t5xDxc8BQdlsWTF6E7Sp9u031dcheTgLLSfWTDD10HJzR2Ymn43DyprssksQ
         VzIsuZARNOqh1tjWHbEFA0YYZD/vBxYUzKqTxv2kxui0JNQ+40tX4D0fOkhEZlM+IIm6
         MgqvZ9L0qhtEis9OhUzTIzaGrPbAp8iXrSaIRqNMZu4BfedMD6wOMzXpQOFimAkW/z9X
         gBpPbivpfrINSgALkM9N5YfOg1f4ytkomVntKb7cNrwLoShxB63j7RwJG3PmxN4GKmqg
         C4De8J/v+KG2RSiGw/WtpiEZQQ5wDCR+XnKC3M77C7QvUG8SoBQI/iF9BOD0RwYVoVhI
         B5fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FvkMkIGR;
       spf=pass (google.com: domain of 3ecfoygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3eCFoYgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id r1-20020a05600c35c100b0038c8b999fa4si114591wmq.1.2022.04.26.09.44.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ecfoygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r26-20020a50aada000000b00425afa72622so7754477edc.19
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:d310:0:b0:425:f22f:763f with SMTP id
 p16-20020aa7d310000000b00425f22f763fmr9236955edq.163.1650991480781; Tue, 26
 Apr 2022 09:44:40 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:37 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-9-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 08/46] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=FvkMkIGR;       spf=pass
 (google.com: domain of 3ecfoygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3eCFoYgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
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

__no_sanitize_memory is a function attribute that instructs KMSAN to
skip a function during instrumentation. This is needed to e.g. implement
the noinstr functions.

__no_kmsan_checks is a function attribute that makes KMSAN
ignore the uninitialized values coming from the function's
inputs, and initialize the function's outputs.

Functions marked with this attribute can't be inlined into functions
not marked with it, and vice versa. This behavior is overridden by
__always_inline.

__SANITIZE_MEMORY__ is a macro that's defined iff the file is
instrumented with KMSAN. This is not the same as CONFIG_KMSAN, which is
defined for every file.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I004ff0360c918d3cd8b18767ddd1381c6d3281be
---
 include/linux/compiler-clang.h | 23 +++++++++++++++++++++++
 include/linux/compiler-gcc.h   |  6 ++++++
 2 files changed, 29 insertions(+)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index babb1347148c5..c561064921449 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -51,6 +51,29 @@
 #define __no_sanitize_undefined
 #endif
 
+#if __has_feature(memory_sanitizer)
+#define __SANITIZE_MEMORY__
+/*
+ * Unlike other sanitizers, KMSAN still inserts code into functions marked with
+ * no_sanitize("kernel-memory"). Using disable_sanitizer_instrumentation
+ * provides the behavior consistent with other __no_sanitize_ attributes,
+ * guaranteeing that __no_sanitize_memory functions remain uninstrumented.
+ */
+#define __no_sanitize_memory __disable_sanitizer_instrumentation
+
+/*
+ * The __no_kmsan_checks attribute ensures that a function does not produce
+ * false positive reports by:
+ *  - initializing all local variables and memory stores in this function;
+ *  - skipping all shadow checks;
+ *  - passing initialized arguments to this function's callees.
+ */
+#define __no_kmsan_checks __attribute__((no_sanitize("kernel-memory")))
+#else
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+#endif
+
 /*
  * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
  * with no_sanitize("coverage"). Prior versions of Clang support coverage
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 52299c957c98e..f1a7ce3f6e6fd 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -133,6 +133,12 @@
 #define __SANITIZE_ADDRESS__
 #endif
 
+/*
+ * GCC does not support KMSAN.
+ */
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+
 /*
  * Turn individual warnings and errors on and off locally, depending
  * on version.
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-9-glider%40google.com.
