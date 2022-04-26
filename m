Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSGDUCJQMGQEAMSIKGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B9121510408
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:00 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id h12-20020a05651211cc00b00471af04ec12sf7843267lfr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991560; cv=pass;
        d=google.com; s=arc-20160816;
        b=C7KUmE60jXjkQQ3knSUGM3BMBiCDxbRo3V9+4ELm+5jVLnnnv4mXZ5QCUriUjEomDy
         9dn4y+Xo1605YlGG5wAKtxnH5OZJnUcduuogYN4Jf9Ipst60lp5VWN5oBRjc/P/lBBc7
         DtVhZdXKmyMmLPTvgLfQV1fHECT4FERKJpsiGkx9CdS2kNuJOtKwrQjrns9hV1aPl7YC
         L/CZg3tLYtxpxiHHKJEkp+NRd9JmDPjX8WArANoI4/5Q8DNfNO2GZKjS+aLGwflfxM2N
         eEDp7mwa01fd1zEsmPSyjiS2YJjwSPyNe5hgQ5JP6X6UvAw7n2P5rpDitBeQh82204uO
         ZJTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VP1dbaS64dPRY7D2dStraUXILqf8MZY4ENQ9XSKEdBk=;
        b=a5fQeooA4vxzt+xmPo7o7SAxH0X4cgjiHQctOVWdfZ7lHSkmOnXFMbnTrswFFBbrUq
         HwUR9BEH0bEQI20YOuhYfPt4qyVfv/fz95bD1gAv+gZFtn7ZEUz6NKhqozV8s3S8rTHy
         pPsoGUrZxnWTuUvzy6Dc4PqWEVS9ivWUQC4k2nKlaOy4si/cJjQqOLdAbf9YSO93zH1D
         LR3YqVn2e+bRdcHzWGQuwBlwUYK9y/cdDdiICqhHEaB+J0AqQwIU3E5r8aU5Y+Xrtrph
         Yi/4cwq07i1dUI349pZfHN52HCDTcsr1UlXjrvpNF0W4OSAb13OaER7ukH+YL6jIEk1v
         x4Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=owm+BOht;
       spf=pass (google.com: domain of 3xifoygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3xiFoYgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VP1dbaS64dPRY7D2dStraUXILqf8MZY4ENQ9XSKEdBk=;
        b=FZQ9Hn+DMw+2KRdrsAGxp40KUr+qmIuzEnCXLIHfw/VONTR/4p73Ih1RJS7Ky9Wh4w
         VvRfb0f6sawbepylwmSbSEO2J3r+Fe+VYmnn+1+pbA7z5UhGIn3Xq0d9O6t4h/WHpYcX
         y+ePMSLyX4KRIL3w56D6WFGgZw/ie+aEL6rXxQkFSoBmveXMey9dqOkAy4PnWMpfGq0Q
         Eu7xew2i8kjCrwVLat15tdWCZo2jush32FpTJZV6BGcODcQU44gFSnYgC1M8UZzwTurw
         6RaTVxob4rMZPzW2YMFIti/5atZQ54r6VJSnsd/VQAnizc2VL2KvpFn/49rBTErmVL/W
         W0jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VP1dbaS64dPRY7D2dStraUXILqf8MZY4ENQ9XSKEdBk=;
        b=x7j/r+8ZmxInqDhG0upm6esj8UUtXqsV4kD9bgIt8pm76LGcwKhL+5g9AXnts6x3kw
         +Q3Sm8LtVVfUdQYr8CI19aHZCXR5XeG16IjadAY8h/2s3l6UCIkzHfa8j8z+TC/sWM6w
         18tjoSMkhlm3lQElZgXZ23/QnKGlR0qWysHAOvvfrwXXtufyBkjSu84Gl+W9W6FgoiJm
         qq/X+OZyNS1rwezFh1PWy96QCHQExmJCYoXX1V8wFtUPGbgiYBBw08dsSLM3vZNwMvgS
         +c0g+Hir7tqE7m+bbxeQT1XUqUHa8yHJIa8DaTTBakgqxRfhFzDnL5FniTQwxNzPbcgw
         kZlA==
X-Gm-Message-State: AOAM532P6tk4ney85oHUeZCyfLZ6iyKPkpk7wemQ7XlpXB+c5CQu9D/y
	y13/fVwzUBJ0bnKMcIPkP24=
X-Google-Smtp-Source: ABdhPJzXev1sEcMhIo3k8zGEVZNXTox6YFUPNuFj5bORf5WcZZQJsdFK2F6x5SnRH4QwMQpEv2/ZXA==
X-Received: by 2002:a2e:9e19:0:b0:247:deb7:cd9f with SMTP id e25-20020a2e9e19000000b00247deb7cd9fmr14476216ljk.261.1650991560348;
        Tue, 26 Apr 2022 09:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8c3:0:b0:24e:ee06:5b76 with SMTP id s3-20020a2eb8c3000000b0024eee065b76ls2124746ljp.11.gmail;
 Tue, 26 Apr 2022 09:45:59 -0700 (PDT)
X-Received: by 2002:a2e:bd83:0:b0:24e:fe7b:7235 with SMTP id o3-20020a2ebd83000000b0024efe7b7235mr12535441ljq.409.1650991559202;
        Tue, 26 Apr 2022 09:45:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991559; cv=none;
        d=google.com; s=arc-20160816;
        b=kxZmqNQwou1Vqb0894ltLW5ljRoPFz/nxHGyAY0lFbdui6Exe5acawG9MYlNT6ktrc
         4oEBxFVhjTVXK9iwHaj+0HZ/wuqheWSVJt9WSyO1MK1/eqN0JYE2VJ9jzIdmdU9w4dK5
         KVKnQeB0mmQYB7ls21nVRLVYo79UB+9jTKCD3uiv2tg6wbu4/celiuaTm6UmBtg9LtKS
         +wENfKBVc8a/3IB4ztuPj0uIIB0rxUDO9uO8RgooNHAIFKxci029++d6TT8EXR4AuxGe
         yWRlNehu7ESeCCDzQV6M7nhAUB5uPvA0p3DaE0yFEegyhZjvJlPj/IPxBzXWHX4gQAaV
         Wukg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=W69+Dls+nKFAD4lCWK/D6+Hgr/p3mJKYHKVaWr09RwM=;
        b=JUpUvGTtb+LxFn6XrR81SsFmf8VfandobII5VHx47tQaK2DNOfK3l+dPZ5CsQ007K6
         ubgzzc6JbURduxJ9y/cMeENXz1viJTKgVB8rxRU/eAAEVT+w+oK70eT6d0j8EyW/Trev
         riFT4ywYI0ek48ZBtqSvhAkPANcF8TGgRdpPeVFLyeX+qWGK6lSz0ldgRZT7F4O5loJZ
         RRy3lIN3BJOi8m2O9IcRr/6me82tDSpS+eYEDQDac3ODdQekHviIQ3UgjcefY+R6zlUC
         I95Yj9kL+DSsQouw7dQELPLLpUmchfe8VJbfCo77Gw/fohO8y6HafaRnDWqk0P0TVdSR
         D2aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=owm+BOht;
       spf=pass (google.com: domain of 3xifoygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3xiFoYgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si542776ljg.0.2022.04.26.09.45.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xifoygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id f19-20020a0565123b1300b004720c485b64so2412093lfv.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:59 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6512:25a4:b0:471:fbe9:8893 with SMTP id
 bf36-20020a05651225a400b00471fbe98893mr11183684lfb.147.1650991558811; Tue, 26
 Apr 2022 09:45:58 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:07 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-39-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 38/46] x86: kmsan: disable instrumentation of unsupported code
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
 header.i=@google.com header.s=20210112 header.b=owm+BOht;       spf=pass
 (google.com: domain of 3xifoygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3xiFoYgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

Instrumenting some files with KMSAN will result in kernel being unable
to link, boot or crashing at runtime for various reasons (e.g. infinite
recursion caused by instrumentation hooks calling instrumented code again).

Completely omit KMSAN instrumentation in the following places:
 - arch/x86/boot and arch/x86/realmode/rm, as KMSAN doesn't work for i386;
 - arch/x86/entry/vdso, which isn't linked with KMSAN runtime;
 - three files in arch/x86/kernel - boot problems;
 - arch/x86/mm/cpu_entry_area.c - recursion.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- moved the patch earlier in the series so that KMSAN can compile
 -- split off the non-x86 part into a separate patch

v3:
 -- added a comment to lib/Makefile

Link: https://linux-review.googlesource.com/id/Id5e5c4a9f9d53c24a35ebb633b814c414628d81b
---
 arch/x86/boot/Makefile            | 1 +
 arch/x86/boot/compressed/Makefile | 1 +
 arch/x86/entry/vdso/Makefile      | 3 +++
 arch/x86/kernel/Makefile          | 2 ++
 arch/x86/kernel/cpu/Makefile      | 1 +
 arch/x86/mm/Makefile              | 2 ++
 arch/x86/realmode/rm/Makefile     | 1 +
 lib/Makefile                      | 2 ++
 8 files changed, 13 insertions(+)

diff --git a/arch/x86/boot/Makefile b/arch/x86/boot/Makefile
index b5aecb524a8aa..d5623232b763f 100644
--- a/arch/x86/boot/Makefile
+++ b/arch/x86/boot/Makefile
@@ -12,6 +12,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Kernel does not boot with kcov instrumentation here.
diff --git a/arch/x86/boot/compressed/Makefile b/arch/x86/boot/compressed/Makefile
index 6115274fe10fc..6e2e34d2655ce 100644
--- a/arch/x86/boot/compressed/Makefile
+++ b/arch/x86/boot/compressed/Makefile
@@ -20,6 +20,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 693f8b9031fb8..4f835eaa03ec1 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -11,6 +11,9 @@ include $(srctree)/lib/vdso/Makefile
 
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KMSAN_SANITIZE_vclock_gettime.o := n
+KMSAN_SANITIZE_vgetcpu.o	:= n
+
 UBSAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index c41ef42adbe8a..fcbf6cf875a90 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -33,6 +33,8 @@ KASAN_SANITIZE_sev.o					:= n
 # With some compiler versions the generated code results in boot hangs, caused
 # by several compilation units. To be safe, disable all instrumentation.
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE_head$(BITS).o				:= n
+KMSAN_SANITIZE_nmi.o					:= n
 
 OBJECT_FILES_NON_STANDARD_test_nx.o			:= y
 
diff --git a/arch/x86/kernel/cpu/Makefile b/arch/x86/kernel/cpu/Makefile
index 9661e3e802be5..f10a921ee7565 100644
--- a/arch/x86/kernel/cpu/Makefile
+++ b/arch/x86/kernel/cpu/Makefile
@@ -12,6 +12,7 @@ endif
 # If these files are instrumented, boot hangs during the first second.
 KCOV_INSTRUMENT_common.o := n
 KCOV_INSTRUMENT_perf_event.o := n
+KMSAN_SANITIZE_common.o := n
 
 # As above, instrumenting secondary CPU boot code causes boot hangs.
 KCSAN_SANITIZE_common.o := n
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index fe3d3061fc116..ada726784012f 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -12,6 +12,8 @@ KASAN_SANITIZE_mem_encrypt_identity.o	:= n
 # Disable KCSAN entirely, because otherwise we get warnings that some functions
 # reference __initdata sections.
 KCSAN_SANITIZE := n
+# Avoid recursion by not calling KMSAN hooks for CEA code.
+KMSAN_SANITIZE_cpu_entry_area.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_mem_encrypt.o		= -pg
diff --git a/arch/x86/realmode/rm/Makefile b/arch/x86/realmode/rm/Makefile
index 83f1b6a56449f..f614009d3e4e2 100644
--- a/arch/x86/realmode/rm/Makefile
+++ b/arch/x86/realmode/rm/Makefile
@@ -10,6 +10,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/lib/Makefile b/lib/Makefile
index caeb55f661726..444c961f2f2e1 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -269,6 +269,8 @@ obj-$(CONFIG_IRQ_POLL) += irq_poll.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
+# recursion.
 KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-39-glider%40google.com.
