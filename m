Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOWEUOMAMGQEPH4KWNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 91DB85A2A8B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:47 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id y11-20020a05651c220b00b0025e4bd7731fsf663940ljq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526587; cv=pass;
        d=google.com; s=arc-20160816;
        b=DA1ClcV+0FPCYwa9+pdNByvqjSdm0uk8ulToVDNmeZCPiq55nyKQ+yCq/EGStLLySO
         onIamlonq/v8qr0BBE+D/bytVMRtTiWN5elpwL2IHCFu25EnL3wZJs6gmP2y22GYxSEm
         +pw8tv7aL8Av6KI9nF5m5onfGHXulbv+wZBwC/Q7kMmXQzZ0H5xsNTN3uLbKpXKKA/go
         wgXMwmhefVtD3vyQifi01pB9aVaaaUAZd/UWV7rhbi2bP0fyJKucwJh3oZ1rqtDmjFO9
         FJEepm05u2o3f3iMOZmWZN93WEqYTbUQ9PEY9neCzj5HF5mDnpliV0YmyqYrp1oX9e27
         JKRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZBb2Tu5TGdVBtdcOcISgamIWp8Epl5Ft5NHTjmkSlrc=;
        b=WLTI7GvrU7Lz6kUJPl4cBY8aqq55wTipbriPv7FLqlnVwOn5ReKniXpFYWaUBwiIB5
         sQ9s8HDf/C5rr8VqObq2vMFhrqNN/CrLxDUF2SiM6oMHQ4C2LK/JTU2SxaN6dXZ4UEZV
         GEli0CnBCYNwhH8kHZbZ9eRvujFbWwT1Ql1nWoTvhiKD6vTowAQjOltIhLZUoJLhUWlH
         7OZy0vmJ/0LLMNzQWXSwKCjp+Pfjwd9p7ARKlYmZ6F13LNwEwR3ql56/LaZE9XFiB/ai
         lICeRk+I/wlpBjolHyR2J7tGxX3HRZQYbM4AjNzz9520lAecjv8pcro8dRrYD8rIBjRD
         696w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HmM0VO6g;
       spf=pass (google.com: domain of 3oeiiywykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3OeIIYwYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=ZBb2Tu5TGdVBtdcOcISgamIWp8Epl5Ft5NHTjmkSlrc=;
        b=aAb6wpXKEgFt+PPX50EdUDPIs+Op/kz5lSKKIq4kmr0o97EXGoEqW7FnaP/yfFFCtj
         cYpXWxHpGSVevv34Xk9iVJc0xQiYQUog/MhNnOUs7WofxRgg30aHxM9+VEdtyL61Wnh5
         lfFQkq1RaeKpf0ldIbj3jmNFlEhe2LnlZhmMH4pUKNJhla6q1Y+3JXEdBW6E+DXBEQB4
         MjoCKcBVAA4scshcwQFl2k3C3YalgHflxqEpV8vbqF47kzscxiqH8IxgW085dZVPVIrT
         euIgJTBiZ4sKRSKcPKmdHGVnbR93rENZajORp3P0cD7osiqOOS3Qo+N4kP6Fo1Kwu5DG
         tT/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=ZBb2Tu5TGdVBtdcOcISgamIWp8Epl5Ft5NHTjmkSlrc=;
        b=whU7F5BTy4n1smPeaNdkgpWVpLbVgTd8P42R4JUVKtMCOOTx5//JtESzJg85hMFrLj
         FcXYUImBGyDiXsbrqBGtL1FII7aOl0xPFMLuRnE4+qflfn099BO8RGRUaf3PxUsFqrkX
         RZXPkSIbdso3GtLCFeVnCzDnbmRVV5H19PdoQaPYRAb3HMLWL4Uu3uepURxwSRO05BSm
         gBYNiPx2vw8Vwhe4GxGzPUocAaI6zW2IzUf0AK0mcbDwiMSSCYk6MDChDmbfCVjxn5jm
         glKowT9dvHmPe4l9yJf+QRUMcjo1SAOeU5Zqby9zFt3tVmCWgBC2+TCTtHTLscj4MnkN
         25QQ==
X-Gm-Message-State: ACgBeo3qat8D0ZxYgQCbJHsoZLe6N16taEalr9V2NbXtkBFRIsY2v08B
	GaUBSDq06JziNT+QieH8Eu4=
X-Google-Smtp-Source: AA6agR6Ce5nk4SQ8NEDkjDYkm01n9kFOfyocFtLUX98kLwMPHi2kNegQM+8HOsgfhiH08h2InYOZ9w==
X-Received: by 2002:a05:6512:3b91:b0:492:e174:60d0 with SMTP id g17-20020a0565123b9100b00492e17460d0mr2692059lfv.576.1661526587108;
        Fri, 26 Aug 2022 08:09:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9998:0:b0:261:b45e:6346 with SMTP id w24-20020a2e9998000000b00261b45e6346ls710631lji.6.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:45 -0700 (PDT)
X-Received: by 2002:a2e:80d5:0:b0:261:dfc2:2367 with SMTP id r21-20020a2e80d5000000b00261dfc22367mr2363436ljg.66.1661526585865;
        Fri, 26 Aug 2022 08:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526585; cv=none;
        d=google.com; s=arc-20160816;
        b=ojQU/3ukKDcaLzxfvoSBKHUYtwIWeL5xt1a3haUbVBuE3CYCQWORNIIL2jXj3hq/8R
         79bEmoJBLK98oC11bLTQ6oLJmxrXvjS5VkkXUpDn5Zm2iVdkFl8KvlypDXuUkPtdvV/w
         OXHHY50lYOsPccEOJwy3mnbzCcWxJXWzpGtKTIy8cIReJvTZeKfQN9NteQ7BnOKwVII7
         wLCKuYQEPFWfHg4yRbIi9sdJ5MAjhsQ9iej+20A6cSmUBoPOzugoSKF5ssdrM3vGFlUn
         BLka1JhdYb7yp5YqtgU31yXnm5E6mLDRRczduak2ED6c5vwT9GNXoqAxEMzoBl/w7F/Y
         t0Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TL1IO7xzXsHa87B/8VTzh6zaFcPyOOUQBNZupLxKBzY=;
        b=p6vk3Ic1vaKFtzn+uyRVyPfX3Lq9d+nFKarA8VRmG2xavG6jZnVUEe980RFxxJjRXx
         QQJw9mnWACkPI+rLyR093wTGYiuPorTrXw6Hys9nmaJD7vP5Z7Npwf1YlX66aCsyXwYT
         CutLOh6sR9TlN0ATiLYjaCoiEyv+iKsViLP/cSQ+3LJwxDVORN6ZvrYr5alV22keSRTa
         4rdsbsRnjXb6zGI1ew/USpR1ZGd5xkhOUIg4ND3yDaFdOiDCu/SEJUadLKXrhb/LN3KV
         sXkF4u/0pPkxCpaGSzjfWtm5B+a6pDo3x8AbTTPI0ZTVEXmSVki/Qhqguy+qsKbnGMZ2
         sIfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HmM0VO6g;
       spf=pass (google.com: domain of 3oeiiywykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3OeIIYwYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 2-20020a2eb942000000b0025e576d2a12si86785ljs.0.2022.08.26.08.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oeiiywykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qk37-20020a1709077fa500b00730c2d975a0so717024ejc.13
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:45 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a50:fe91:0:b0:43d:c97d:1b93 with SMTP id
 d17-20020a50fe91000000b0043dc97d1b93mr7390732edt.67.1661526585272; Fri, 26
 Aug 2022 08:09:45 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:56 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-34-glider@google.com>
Subject: [PATCH v5 33/44] x86: kmsan: disable instrumentation of unsupported code
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
 header.i=@google.com header.s=20210112 header.b=HmM0VO6g;       spf=pass
 (google.com: domain of 3oeiiywykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3OeIIYwYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
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

v5:
 -- removed a comment belonging to another patch

Link: https://linux-review.googlesource.com/id/Id5e5c4a9f9d53c24a35ebb633b814c414628d81b
---
 arch/x86/boot/Makefile            | 1 +
 arch/x86/boot/compressed/Makefile | 1 +
 arch/x86/entry/vdso/Makefile      | 3 +++
 arch/x86/kernel/Makefile          | 2 ++
 arch/x86/kernel/cpu/Makefile      | 1 +
 arch/x86/mm/Makefile              | 2 ++
 arch/x86/realmode/rm/Makefile     | 1 +
 7 files changed, 11 insertions(+)

diff --git a/arch/x86/boot/Makefile b/arch/x86/boot/Makefile
index ffec8bb01ba8c..9860ca5979f8a 100644
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
index 35ce1a64068b7..3a261abb6d158 100644
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
index 12f6c4d714cd6..ce4eb7e44e5b8 100644
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
index a20a5ebfacd73..ac564c5d7b1f0 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -33,6 +33,8 @@ KASAN_SANITIZE_sev.o					:= n
 # With some compiler versions the generated code results in boot hangs, caused
 # by several compilation units. To be safe, disable all instrumentation.
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE_head$(BITS).o				:= n
+KMSAN_SANITIZE_nmi.o					:= n
 
 # If instrumentation of this dir is enabled, boot hangs during first second.
 # Probably could be more selective here, but note that files related to irqs,
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
index f8220fd2c169a..39c0700c9955c 100644
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
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-34-glider%40google.com.
