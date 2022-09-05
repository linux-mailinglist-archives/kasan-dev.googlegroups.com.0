Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5WV26MAMGQEZXIKNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EBE85AD26E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:31 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id dt8-20020a0565122a8800b00492f7025810sf1835585lfb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380791; cv=pass;
        d=google.com; s=arc-20160816;
        b=PhBra/Iy8SBPwRWEtTkPaYZxI3VqFnLq1FhRXzz48fl2CVtcmL2ymP4nVPXJbAWtKl
         2oNHUYPJHFgA0zGctzC9cfb/G0hB69ddJUagofMe96YbotoueShCMEUN5iomqVdLa+tr
         oagMLYiW5hCLPmCSduSFxlvxa4K/JsGdsLuT67COHtKoN2eR4OExavg4QzZ7Rjq2vztX
         SHzqq4QsMSWc15Jwf+sp7eSGrMKT6oLuJBO4p6DTBfdip7vhAfWT8p670d+ipHNU1Jia
         kmP1XmigpSdcwiYz80m8QTf0M1ljqUqklQvGFL3SJePDUhOihZRXp+WxVKzr36zFCIri
         SMbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q8kGjTl4EHD8UNPo95LnLbNVPcfj9iHMJ+TlZuR0s2Y=;
        b=ar8u2c0Mhg4jogLQPRR7f0QZ3StWcXmM1yzilE2lORH7eWjCkelWTrsHSjnwV41pkz
         uvymqCVQAh/qoIPZaDRsF2L7LOt/V//lpEDoRGK15LFZwgQI6AK4eWcLcggzot1eW0qQ
         8dKDtKqyj1tSt43TLMswgA+BalJ8O57dWFAzxtXRcDcjDrNIWLtFIGbkNzPfoKeespRH
         3dHifGJuB8HuEI+WWSjcgVqJIk9+TG9tT9WeZ8aKtAh1Vj9EcGiZfx8VI5GWCgubmy5Y
         f3lWW31WenSYCRFL8cdbd+owjzbuGo67rTIS5AnHi3zn1ohgxfdUK3k0cqzkHyeheGte
         CemQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bnvE8RFZ;
       spf=pass (google.com: domain of 39oovywykcuejolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39OoVYwYKCUEjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=q8kGjTl4EHD8UNPo95LnLbNVPcfj9iHMJ+TlZuR0s2Y=;
        b=BWAvV+5u31wZ9veearWtHIb4gGzUBvgNG5opdBIXVN9tV4Jf1XLktRfz6IZt4zJxUp
         NSm5weB6lUQUmkS+0SUXnZaJiHa4fwAhB6PkkIKt6X5sZynBbUMLpXs3CIor1zX0pRIZ
         MNPKOeE0RXZoZc8sNRkaFvXIcTeVJxF07py3FbHMCebCuKxDar8/WDBm8linyBHPFccU
         zER6w/nV9NWay/Yp0R8417FFem2oxIiLIbiDCftqCeUu9e7C2QXBCZKbG91aiFuaeu/c
         1QvIdRgaElutqiWQuWjAUIQoS+uSZw2k0/ZVczh5ayAKZbzeUyIwyBvwJAJsQL7RVvIn
         /7Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=q8kGjTl4EHD8UNPo95LnLbNVPcfj9iHMJ+TlZuR0s2Y=;
        b=P/FirtC567nG6u9bEaPdvH5dJEyJ5tw60gVuKelklPqCmWQNRJerqkUL+DHY2AJJYm
         t5rKxLZZ6gzgnvSzynXD/DqbL+jOCl+rFXSP7fTgp/kslWTxDQSKEDtXatI+GbLzTbqC
         4oauYRvwU+LP2GDoGGBbvslLGFSq4gv2MtDf5ZbIVgZsntofUD1bQ7x0goIvAfVoeHop
         FXwyxf+rfWhf15A5FQRjxvOT22/o++0Y0PvGEL1Vac7B4XR337/gAC39IJCP2afy5n9V
         dnMbbaqT+qN7OwXFETvL614S9uV+1SHW6K8PnX744VKOpLvZnoo31mPD3dt9xhosSqtj
         6KDw==
X-Gm-Message-State: ACgBeo2XG/jdL0wT25EGE5S96gtDq//NzhMk8m+0BPcw05dV//BdgK+/
	FGquI4GoVHsVB1YKRz0jbYA=
X-Google-Smtp-Source: AA6agR7HTWVjdU7Ysoz3h6HOPNXj0/2ttm2dFYqCjI49JayOnYnMNQZ+r/l43l2jTzlZmyH8xh/e+A==
X-Received: by 2002:a19:645e:0:b0:494:fb30:1cfc with SMTP id b30-20020a19645e000000b00494fb301cfcmr3476496lfj.4.1662380790939;
        Mon, 05 Sep 2022 05:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a912:0:b0:25d:4f02:5abf with SMTP id j18-20020a2ea912000000b0025d4f025abfls1562098ljq.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:29 -0700 (PDT)
X-Received: by 2002:a2e:92ce:0:b0:261:e39e:2c1d with SMTP id k14-20020a2e92ce000000b00261e39e2c1dmr14156187ljh.273.1662380788955;
        Mon, 05 Sep 2022 05:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380788; cv=none;
        d=google.com; s=arc-20160816;
        b=aWbNlIhV1XcDDGbEURbZrZdZf5Xio3IDTi2ZaW/O0FyT3My4KKT4qdQyjMp7vuZyCG
         A8UPEdADes7ca+U4LjfVQgcCjklwwB2yOLYAJkkbEtHUoykDsoHYTtcyC0lqx9/hMX18
         OpudEOBK5aJ8AhFz1c+DEBit7LAqLXoCsQxcnzgPvHf1C0GblLu/HmFVGUGL9ATf3WmS
         vH39jHrx3h3sWKQYXozclEPjWJbRhgTl/ZI7dkVcl8D5isdK/wZ0oeDKz1Gow6NI4vDe
         crcdA8SbM7HKnD2iI1UDYHq28XjQvLXShqIeGc6+7xgojnXEJfJYrQSzZa1qN6N4iIer
         +QtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ByRxUK8Sn+pDB+Gp2EKIbiaRYh/I0Prcbbdv1W00JlM=;
        b=va3NMTtXyhC6KBWUo8bn6n8KoBjlgCt3QiTw06xJ+S3LNJ0CYCpmwzEq0EsnbTE3DX
         pFbPYicgw6zoNNuLwSp/R+EbGOZGoAG3dWwVr/7ZNIBW3HllbaumCCFgzQwQZ94xf9mZ
         xp2QmXfxRU0O6rMmvVLvdy+Coq3/m4Zs7AjFmmH82aslO16f8KxN1ckysz/MRCi3lzb2
         SKj6sEEJH5ogCiDuUW/yxF4hW7DLoLa2fM67b9j5QmTAdMAQEuGoXk5NN8uWbVYCJOCG
         3BJNF6Dh7SqVbmGSCeXTHo2xd2RjBAZ8TAllb7iE/MvZcX/GTDnK8czx/RrQzDcE9/S3
         toDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bnvE8RFZ;
       spf=pass (google.com: domain of 39oovywykcuejolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39OoVYwYKCUEjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id x20-20020a056512079400b00492ea683e72si345714lfr.2.2022.09.05.05.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39oovywykcuejolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id dz16-20020a0564021d5000b004489f04cc2cso5726297edb.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:9bf4:b0:741:4902:4e6 with SMTP id
 de52-20020a1709069bf400b00741490204e6mr29476988ejc.222.1662380788354; Mon, 05
 Sep 2022 05:26:28 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:41 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-34-glider@google.com>
Subject: [PATCH v6 33/44] x86: kmsan: disable instrumentation of unsupported code
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
 header.i=@google.com header.s=20210112 header.b=bnvE8RFZ;       spf=pass
 (google.com: domain of 39oovywykcuejolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=39OoVYwYKCUEjolghujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-34-glider%40google.com.
