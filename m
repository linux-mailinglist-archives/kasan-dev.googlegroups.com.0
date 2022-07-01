Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMEH7SKQMGQELCDVXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46D7B563535
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:49 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id w12-20020adf8bcc000000b0021d20a5b24fsf420346wra.22
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685489; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9xzgQyjJMtYwgXYzj5gkDJbrlwHSqSq1EI9jDPyldeUlMaT+b3D4lgwFumhDxmQA1
         xcBrV/h5CViEGTxTDbheyA+WKmTNHmWU4mmip34b3ofrtzDtEbpLcu3rRD48iBpPA+rR
         3psTjXAU8qXsU23N389x78E9964j2xuUwPrh0DSCKduK6u79du1CkQoDqyFemooT9h1P
         u/UGS4bDUiYLKOAUHJ55dKwYCt48yD9nD1CdBRKVT47TwOSlJDmZaaRv1pxyUszGtBnX
         W/ktwSIbiHQbuUWY0TEMIHI3uzvfht7bC8S6KjjejHRLTAK8QWXjshu6bNGIm8/88jMZ
         kMIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MFmw2nRwBsCDLnXCOe6709NU0+LIplhmeD+H5gE8LhM=;
        b=Lg9ajgB3ND9Lfu6rxha/ZQwcZN9vNtPd0KtF0yCMHAh7fCh7LwjFLZ/tRbE6sC/SIe
         UzrDb137Be/Fxtgx0mYZZleLkcePpSbX9b9YLoWo2dyfgOBjC/WN8yHkLOt7W3eHkXJs
         4mTfs9b7Zm6isTkeWtFePnRTc8BZcXD7u9IaWbf1se12d/DqKPGdcvVC5xeyRGcxns2C
         qphEAK2ZFt6jjGW13qHHuD2675tDpakOzb/rGvbWkFGsgmf6cc1zu8f65Y4S7ppidAwG
         Q7VgXC5bsHUErAhTG5tW/CGMzB0DlxZb1pJ826EUQ+3f9x+xsluyEpCQVt5ZGGNgPfyq
         UvIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RVivBlTR;
       spf=pass (google.com: domain of 3rwo_ygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rwO_YgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MFmw2nRwBsCDLnXCOe6709NU0+LIplhmeD+H5gE8LhM=;
        b=GPf58XmhmZgU1mad339w3S05IHYT+4fW6WnGRFWTSZCGGJ3bAygDnOfkQNzJJw2EYo
         W7VaEzCVPndcbjW53440N1SGwE6PSDXREgZvQnh7//fQYJ+hn3+nh81a6b1K4Svqhfy2
         C3mOg2ION2qnDpJyi6+ZTVDiUHRSn+BTolieJh6KPitkrDEgAeg3hzjnF/0gzqXaVowN
         ZbWZvV+xqliJx4t1c24DlkFe/pnLCTnz1A0b/lLtPxSc8BvMR3TqGCHrBex2CNGrRe4R
         ek/m2rGoyrNl10Q4b2BazVXNyTgmR9ABkydwuSlhHXd0UwTL1j42Aj9dF3mjF/Fd1CKh
         kA2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MFmw2nRwBsCDLnXCOe6709NU0+LIplhmeD+H5gE8LhM=;
        b=MI4CWOt+DmCxFZlIevxr22LvVhH3Ge0IRP2i8x61LJyf07l2WeOYpA4NMIAj2TsGgl
         UrKeQMDUSPe8K4lsjG6u7MN/R59UQ+WnAknDKc+XnEoTQeIBxSD3CiyWaRP6cFPxPfDY
         IHdx+vxraIcbV/IOaXEc0k4f48zg+lExr0U1Nw4uK5iRo58rLyVChRtCZ0ITSk2/e9g5
         XkmmjYvqZbYYEoTNzBfv2sJAxU4n+2PfodqKCzzPNhd0P4Dqfkb8S4oqnrH/yqpqaTMY
         Ol3wdFkBd+j3wAAi5k8U8xhcjNl+zOvIRmsyl//N3L6ZA2tprIJvJmS2p31yDHXCeiae
         x/sQ==
X-Gm-Message-State: AJIora9M4FcoLWu9iNCVf6Rrfa2yTXr0YZEzNreI9gxXvZ585JgI03Ot
	75+NwHIa9yopaWpErKXG1KU=
X-Google-Smtp-Source: AGRyM1sdR/2+wOdfroSMEhSD0/SzIC3M4cpJSWreYVXmJXmET6SgG6qWeGL2bcPEuhZI8jEvVUQYYg==
X-Received: by 2002:a1c:4c0b:0:b0:3a1:92da:bddf with SMTP id z11-20020a1c4c0b000000b003a192dabddfmr534040wmf.188.1656685489041;
        Fri, 01 Jul 2022 07:24:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47ce:0:b0:21d:339f:dc1 with SMTP id o14-20020a5d47ce000000b0021d339f0dc1ls9665822wrc.0.gmail;
 Fri, 01 Jul 2022 07:24:48 -0700 (PDT)
X-Received: by 2002:a05:6000:18ad:b0:21b:a24a:1786 with SMTP id b13-20020a05600018ad00b0021ba24a1786mr14970962wri.115.1656685488207;
        Fri, 01 Jul 2022 07:24:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685488; cv=none;
        d=google.com; s=arc-20160816;
        b=tJXdJMMkXb31cbk9xYd/TP2b8iWm5MFZ5EtvM7hnmUJRlN37r9yefSDxuScxYwlzXf
         Ru2dytEjUGEW6n85zHJBpNYrK9MnGu3MWyqA9ncy2kAFj6ou78aUoImX+X0qKvxT4Bu+
         uzqhajdtSjhwL6o3i0I/r5USqGWWnhBsXZyvLRsVU6DSiKsJtlXU5XW+Anyc1mxsKfbj
         qdlopBXS++H2bU8BWDw4C8TLzLe/UvKWOY5kvqqFfPSIjxyWOS5bGqbCRa17fO64cNqL
         jh3NY8tnEtYZitfigY6cEQvLgVJ6+dgv+4HSYIzhq75j+XwxrBzRFYdOZU3H400liO6O
         fuWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=iJzH9xEnS9/oOC6mna7qxAN7hxj/kW7q3+xewUipeVQ=;
        b=WnsLxuSGZ6M8Csb+zjGmDfuAwglcFZWExQ40ifWulwilut1QtLLTR0PxGoOJhd4esN
         nThsFlrksX9bl2fyIC+D/ESYWvXcWshqysrG46HBIBmz5t3xeTuh0NnHofNIYk2mlAqN
         MYVfq7sLEDjIBV81qJEbl6D3eb8N7fNaFNlRZroZDKSkcPI8qTdkguBjVle5BmUYludc
         6kXJzyag8srBvR6wBglZSr2ENmILTE5zaNrTDgm3UAyuIOIZptCEP6dg57T+qsQ/i+tJ
         3G8Xa8fYKjuZp2fskV8SOj3BJO+4hFqfWg7WFUHVy1iSzCHORxCLw7oWpurB8aCtkIGI
         LJpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RVivBlTR;
       spf=pass (google.com: domain of 3rwo_ygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rwO_YgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a04819672csi299821wmb.0.2022.07.01.07.24.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rwo_ygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id e20-20020a170906315400b007262bd0111eso842816eje.9
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:48 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:3e13:b0:726:eebc:3461 with SMTP id
 hp19-20020a1709073e1300b00726eebc3461mr14278594ejc.528.1656685487802; Fri, 01
 Jul 2022 07:24:47 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:58 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-34-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 33/45] x86: kmsan: disable instrumentation of unsupported code
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
 header.i=@google.com header.s=20210112 header.b=RVivBlTR;       spf=pass
 (google.com: domain of 3rwo_ygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3rwO_YgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
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
index 19e1905dcbf6f..8d0d4d89a00ae 100644
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
index c2a8b76ae0bce..645bd919f9845 100644
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
index 4c8b6ae802ac3..4f2617721d3dc 100644
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
diff --git a/lib/Makefile b/lib/Makefile
index 5056769d00bb6..73fea85b76365 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -272,6 +272,8 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
+# recursion.
 KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-34-glider%40google.com.
