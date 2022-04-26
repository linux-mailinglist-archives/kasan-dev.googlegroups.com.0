Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF6DUCJQMGQESJH5C5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C36D5103F4
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:12 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id u19-20020a2e8553000000b0024f222a942asf749726ljj.8
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991511; cv=pass;
        d=google.com; s=arc-20160816;
        b=uV1a63Dbqdzx/5sWA50mruOuP8epBxdukLw+V3+LJaRz/EOGw3kkDZe6NHTKG7iG4F
         ACrWWrz4n01ERmC9IbCKWYJxYM2wwx0oEDupcJRDcjFw9y3TDerO0jad7VeVbpKSMz+F
         NwECHZo6jESl7IBt4OxM79EmBvflxvQv/1ntZscaTsMJlFdn0nkR7RM3ZGGnpvwiH+2X
         aNcClgID/XPQBa7xoNSrn+JxLdGwC/KSkUxb6PTQsYj4LftxD5U9MOaiGCJJLEr+IiE9
         cqmSBlMwjWHgMEwIxzS9tbNeMXKMXROUttaGqGfrd14TEwzDwpDGnG6I3G6fpwnorG4l
         GSag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OYOFwX5meFiCZb9rgEjwjn60w4nODD/Pa/xe4XeZ4ZY=;
        b=JBSxvl6YhXh/kN8XrumKdNNFFSj/IszhgCQLV7yOs32m+oDSNQc6AmJM4MaDxNYsuQ
         sHF0y82sNGhB5avrMGO7qGNFS1vkydFdWmmazeUIwzmGnNThiISTeDkNosOoHKH0ajJk
         z1f/apL0jslCAeeOh0ophZr9Uqc+Gd+bUryLo+xIzUoPxIp5kiSKVRjLWS/Nll9P58M0
         AyFYAcSxG58G4Vx9IfM/YvuLgOp4SCA4tuVxqHFbAqiKl2v2PuxeD2LT34OMpF6pPQ+7
         dUf85m8bYzZwxcILs/qipq0fbf2p0zg0h7aEOekgxd4Znb5ZeZrMd/umcqWF6v7GnAzJ
         6u8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iILPrkLP;
       spf=pass (google.com: domain of 3lsfoygykczi274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lSFoYgYKCZI274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OYOFwX5meFiCZb9rgEjwjn60w4nODD/Pa/xe4XeZ4ZY=;
        b=NDNi1sKN22BiTqru2aXbaO7weGfhSdGWKTACUEcxOGd0RcATwgUDxWpQtf97m+O5mo
         Z5tjAHwZZBtokOHSygrTpDczerL0pIhPHwvQW2oa+ntfKmHqGi+i9+SVNHjBixl3xa0J
         iVFbG52AYCpm8yrrPa99RoyTCuZvkJcQvEKmuo4LzaIVLBN5k+m7ke3Bv5j8PONFSci8
         7PYGu7WMx2GS+XzTkDpdp2n6hv+94/VoZD3jupEurUMLtw6JEMwUHes0sDeHBxmkStpm
         U1nc5AdzvcdEGeNe/8hDPsBgco5iHMiiCK1uiFWsmn+esJRxLr0+/OlCdID0a3sgHjn9
         gs0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OYOFwX5meFiCZb9rgEjwjn60w4nODD/Pa/xe4XeZ4ZY=;
        b=BzhVj1anQZ2NLYQ61renvcD0x1qm9njV3PJp9URnNjvk/PcRJqRj0lEzR5QckLX0T4
         GJonkCnZXKAFr6m/rud959rIv4s+ZLZYky0K94aswbpil53DzHv0hpQoYedwZopsh1ng
         iQNGC4uSgq8GmUXfJR6PHF/00uVcUHbDtzdENdtBodwwjLjboHrxe0tc4CcigObc9OuD
         +4z3eGYysomzdPOBKOaZ3ncsJJmMbi3lGMsW2E9zgQd5Zh26z8sf/YWRRHeZtrdaKS8k
         NXld2YhPe+PWJvY5z4BZTX12Jb9gRwVXnjTu3BEDmEFvj1rsFV2rWRBrdlNeJQz+tXn0
         /BPw==
X-Gm-Message-State: AOAM531noUpJCdmXxrbMW/TbJrYLxXq+u3dpvHSaO2yeS+PVVNStOsJ6
	mDrVgS3tEJeaeWgeiFQtcRQ=
X-Google-Smtp-Source: ABdhPJwgxfpC45gLa5utYj5QFdKyKZ5t4vW85zQoDafYYnFCVvj8a5Ry2f+V5PUeoKSZIR/Cb8U4hQ==
X-Received: by 2002:a2e:8502:0:b0:24f:1036:b405 with SMTP id j2-20020a2e8502000000b0024f1036b405mr7514510lji.220.1650991511646;
        Tue, 26 Apr 2022 09:45:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0c:0:b0:24f:1432:3be with SMTP id b12-20020a2ebc0c000000b0024f143203bels1214058ljf.8.gmail;
 Tue, 26 Apr 2022 09:45:10 -0700 (PDT)
X-Received: by 2002:a2e:894e:0:b0:24f:ad2:b192 with SMTP id b14-20020a2e894e000000b0024f0ad2b192mr9683557ljk.199.1650991510618;
        Tue, 26 Apr 2022 09:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991510; cv=none;
        d=google.com; s=arc-20160816;
        b=ZpcgD249zD+BZ6KWyyo4AnOGlnKls3VtNVdGu/N5p5ZQO7+8fdoEZu1S8pG/IDmabs
         N8sD474bmyxnllUWTgPSoaR1734IDiAbNhCFvh3VGhwry1xnPUy3Gfp45lwNnkdER49V
         CsMTy45yXeu9zUcctmnHWTBbGTBgKmeBYjewHq8SVSz0hPremm4P+nOq0iO2KYVRPkDm
         CsPOk9ZtcZUwsa20ST0rn1hdv8syohjrPD+WP8esfQW3Nqn6Y79ey2TwR0FFLFbTWJ+K
         vt4M/OP03QC5Esf/r24ZzCoOXtV7IcC+V/rGeLD4MZTk6uGmvyro7EEJBGXAdpZOy6U8
         TDMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=chRz9X+UoCgYtEKtJoTXT2tB633Q6kPzDish0ozWoJs=;
        b=Lu45T5YKPD5cg3vWamw1QYtMa2JUIvP+qu+BvI+24OtNser+WvVyfds8yxBUNrpt7Q
         YJCNlWTOmyWMvSFok5Xt0YxornUAEah2qaGkYURkyrhUDAZLCbaZ9wkVNr4jKpW6PDUf
         HTV+xmFTfEbGf1d0T597BNRC/hPe1rZaxupqlTzWK/q7iAUFiPILaPUZfP0bX+FIo4th
         EksLnSO+GAPe21VqgJitpWQn8h84EN7OMtbYzeLXygOX8vzEj5wSfhsCmSBLqaFrBcRC
         omb2I9dpWHOJwredFdEkip1DtdbWstMUwqFKXaxI7CEG7iBIVSgI8UhHe7181gPCRerB
         udRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iILPrkLP;
       spf=pass (google.com: domain of 3lsfoygykczi274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lSFoYgYKCZI274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id h20-20020a2e3a14000000b0024f1cf9b1b0si102949lja.4.2022.04.26.09.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lsfoygykczi274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id go12-20020a1709070d8c00b006f009400732so9165973ejc.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:10 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:5189:b0:423:f342:e0ce with SMTP id
 q9-20020a056402518900b00423f342e0cemr25740119edd.120.1650991509865; Tue, 26
 Apr 2022 09:45:09 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:48 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-20-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 19/46] kmsan: init: call KMSAN initialization routines
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
 header.i=@google.com header.s=20210112 header.b=iILPrkLP;       spf=pass
 (google.com: domain of 3lsfoygykczi274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lSFoYgYKCZI274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
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

kmsan_init_shadow() scans the mappings created at boot time and creates
metadata pages for those mappings.

When the memblock allocator returns pages to pagealloc, we reserve 2/3
of those pages and use them as metadata for the remaining 1/3. Once KMSAN
starts, every page allocated by pagealloc has its associated shadow and
origin pages.

kmsan_initialize() initializes the bookkeeping for init_task and enables
KMSAN.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move mm/kmsan/init.c and kmsan_memblock_free_pages() to this patch
 -- print a warning that KMSAN is a debugging tool (per Greg K-H's
    request)

Link: https://linux-review.googlesource.com/id/I7bc53706141275914326df2345881ffe0cdd16bd
---
 include/linux/kmsan.h |  48 +++++++++
 init/main.c           |   3 +
 mm/kmsan/Makefile     |   3 +-
 mm/kmsan/init.c       | 240 ++++++++++++++++++++++++++++++++++++++++++
 mm/kmsan/kmsan.h      |   3 +
 mm/kmsan/shadow.c     |  36 +++++++
 mm/page_alloc.c       |   3 +
 7 files changed, 335 insertions(+), 1 deletion(-)
 create mode 100644 mm/kmsan/init.c

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index dca42e0e91991..a5767c728a46b 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -52,6 +52,40 @@ void kmsan_task_create(struct task_struct *task);
  */
 void kmsan_task_exit(struct task_struct *task);
 
+/**
+ * kmsan_init_shadow() - Initialize KMSAN shadow at boot time.
+ *
+ * Allocate and initialize KMSAN metadata for early allocations.
+ */
+void __init kmsan_init_shadow(void);
+
+/**
+ * kmsan_init_runtime() - Initialize KMSAN state and enable KMSAN.
+ */
+void __init kmsan_init_runtime(void);
+
+/**
+ * kmsan_memblock_free_pages() - handle freeing of memblock pages.
+ * @page:	struct page to free.
+ * @order:	order of @page.
+ *
+ * Freed pages are either returned to buddy allocator or held back to be used
+ * as metadata pages.
+ */
+bool __init kmsan_memblock_free_pages(struct page *page, unsigned int order);
+
+/**
+ * kmsan_task_create() - Initialize KMSAN state for the task.
+ * @task: task to initialize.
+ */
+void kmsan_task_create(struct task_struct *task);
+
+/**
+ * kmsan_task_exit() - Notify KMSAN that a task has exited.
+ * @task: task about to finish.
+ */
+void kmsan_task_exit(struct task_struct *task);
+
 /**
  * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
  * @page:  struct page pointer returned by alloc_pages().
@@ -173,6 +207,20 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
 #else
 
+static inline void kmsan_init_shadow(void)
+{
+}
+
+static inline void kmsan_init_runtime(void)
+{
+}
+
+static inline bool kmsan_memblock_free_pages(struct page *page,
+					     unsigned int order)
+{
+	return true;
+}
+
 static inline void kmsan_task_create(struct task_struct *task)
 {
 }
diff --git a/init/main.c b/init/main.c
index 98182c3c2c4b3..5c6937921c890 100644
--- a/init/main.c
+++ b/init/main.c
@@ -34,6 +34,7 @@
 #include <linux/percpu.h>
 #include <linux/kmod.h>
 #include <linux/kprobes.h>
+#include <linux/kmsan.h>
 #include <linux/vmalloc.h>
 #include <linux/kernel_stat.h>
 #include <linux/start_kernel.h>
@@ -835,6 +836,7 @@ static void __init mm_init(void)
 	init_mem_debugging_and_hardening();
 	kfence_alloc_pool();
 	report_meminit();
+	kmsan_init_shadow();
 	stack_depot_early_init();
 	mem_init();
 	mem_init_print_info();
@@ -852,6 +854,7 @@ static void __init mm_init(void)
 	init_espfix_bsp();
 	/* Should be run after espfix64 is set up. */
 	pti_init();
+	kmsan_init_runtime();
 }
 
 #ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index 73b705cbf75b9..f57a956cb1c8b 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -1,4 +1,4 @@
-obj-y := core.o instrumentation.o hooks.o report.o shadow.o annotations.o
+obj-y := core.o instrumentation.o init.o hooks.o report.o shadow.o annotations.o
 
 KMSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
@@ -16,6 +16,7 @@ CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
 CFLAGS_annotations.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
+CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KMSAN_RUNTIME)
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
new file mode 100644
index 0000000000000..45757d1390402
--- /dev/null
+++ b/mm/kmsan/init.c
@@ -0,0 +1,240 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KMSAN initialization routines.
+ *
+ * Copyright (C) 2017-2021 Google LLC
+ * Author: Alexander Potapenko <glider@google.com>
+ *
+ */
+
+#include "kmsan.h"
+
+#include <asm/sections.h>
+#include <linux/mm.h>
+#include <linux/memblock.h>
+
+#include "../internal.h"
+
+#define NUM_FUTURE_RANGES 128
+struct start_end_pair {
+	u64 start, end;
+};
+
+static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
+static int future_index __initdata;
+
+/*
+ * Record a range of memory for which the metadata pages will be created once
+ * the page allocator becomes available.
+ */
+static void __init kmsan_record_future_shadow_range(void *start, void *end)
+{
+	u64 nstart = (u64)start, nend = (u64)end, cstart, cend;
+	bool merged = false;
+	int i;
+
+	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
+	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
+	nend = ALIGN(nend, PAGE_SIZE);
+
+	/*
+	 * Scan the existing ranges to see if any of them overlaps with
+	 * [start, end). In that case, merge the two ranges instead of
+	 * creating a new one.
+	 * The number of ranges is less than 20, so there is no need to organize
+	 * them into a more intelligent data structure.
+	 */
+	for (i = 0; i < future_index; i++) {
+		cstart = start_end_pairs[i].start;
+		cend = start_end_pairs[i].end;
+		if ((cstart < nstart && cend < nstart) ||
+		    (cstart > nend && cend > nend))
+			/* ranges are disjoint - do not merge */
+			continue;
+		start_end_pairs[i].start = min(nstart, cstart);
+		start_end_pairs[i].end = max(nend, cend);
+		merged = true;
+		break;
+	}
+	if (merged)
+		return;
+	start_end_pairs[future_index].start = nstart;
+	start_end_pairs[future_index].end = nend;
+	future_index++;
+}
+
+/*
+ * Initialize the shadow for existing mappings during kernel initialization.
+ * These include kernel text/data sections, NODE_DATA and future ranges
+ * registered while creating other data (e.g. percpu).
+ *
+ * Allocations via memblock can be only done before slab is initialized.
+ */
+void __init kmsan_init_shadow(void)
+{
+	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	phys_addr_t p_start, p_end;
+	int nid;
+	u64 i;
+
+	for_each_reserved_mem_range(i, &p_start, &p_end)
+		kmsan_record_future_shadow_range(phys_to_virt(p_start),
+						 phys_to_virt(p_end));
+	/* Allocate shadow for .data */
+	kmsan_record_future_shadow_range(_sdata, _edata);
+
+	for_each_online_node(nid)
+		kmsan_record_future_shadow_range(
+			NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);
+
+	for (i = 0; i < future_index; i++)
+		kmsan_init_alloc_meta_for_range(
+			(void *)start_end_pairs[i].start,
+			(void *)start_end_pairs[i].end);
+}
+EXPORT_SYMBOL(kmsan_init_shadow);
+
+struct page_pair {
+	struct page *shadow, *origin;
+};
+static struct page_pair held_back[MAX_ORDER] __initdata;
+
+/*
+ * Eager metadata allocation. When the memblock allocator is freeing pages to
+ * pagealloc, we use 2/3 of them as metadata for the remaining 1/3.
+ * We store the pointers to the returned blocks of pages in held_back[] grouped
+ * by their order: when kmsan_memblock_free_pages() is called for the first
+ * time with a certain order, it is reserved as a shadow block, for the second
+ * time - as an origin block. On the third time the incoming block receives its
+ * shadow and origin ranges from the previously saved shadow and origin blocks,
+ * after which held_back[order] can be used again.
+ *
+ * At the very end there may be leftover blocks in held_back[]. They are
+ * collected later by kmsan_memblock_discard().
+ */
+bool kmsan_memblock_free_pages(struct page *page, unsigned int order)
+{
+	struct page *shadow, *origin;
+
+	if (!held_back[order].shadow) {
+		held_back[order].shadow = page;
+		return false;
+	}
+	if (!held_back[order].origin) {
+		held_back[order].origin = page;
+		return false;
+	}
+	shadow = held_back[order].shadow;
+	origin = held_back[order].origin;
+	kmsan_setup_meta(page, shadow, origin, order);
+
+	held_back[order].shadow = NULL;
+	held_back[order].origin = NULL;
+	return true;
+}
+
+#define MAX_BLOCKS 8
+struct smallstack {
+	struct page *items[MAX_BLOCKS];
+	int index;
+	int order;
+};
+
+struct smallstack collect = {
+	.index = 0,
+	.order = MAX_ORDER,
+};
+
+static void smallstack_push(struct smallstack *stack, struct page *pages)
+{
+	KMSAN_WARN_ON(stack->index == MAX_BLOCKS);
+	stack->items[stack->index] = pages;
+	stack->index++;
+}
+#undef MAX_BLOCKS
+
+static struct page *smallstack_pop(struct smallstack *stack)
+{
+	struct page *ret;
+
+	KMSAN_WARN_ON(stack->index == 0);
+	stack->index--;
+	ret = stack->items[stack->index];
+	stack->items[stack->index] = NULL;
+	return ret;
+}
+
+static void do_collection(void)
+{
+	struct page *page, *shadow, *origin;
+
+	while (collect.index >= 3) {
+		page = smallstack_pop(&collect);
+		shadow = smallstack_pop(&collect);
+		origin = smallstack_pop(&collect);
+		kmsan_setup_meta(page, shadow, origin, collect.order);
+		__free_pages_core(page, collect.order);
+	}
+}
+
+static void collect_split(void)
+{
+	struct smallstack tmp = {
+		.order = collect.order - 1,
+		.index = 0,
+	};
+	struct page *page;
+
+	if (!collect.order)
+		return;
+	while (collect.index) {
+		page = smallstack_pop(&collect);
+		smallstack_push(&tmp, &page[0]);
+		smallstack_push(&tmp, &page[1 << tmp.order]);
+	}
+	__memcpy(&collect, &tmp, sizeof(struct smallstack));
+}
+
+/*
+ * Memblock is about to go away. Split the page blocks left over in held_back[]
+ * and return 1/3 of that memory to the system.
+ */
+static void kmsan_memblock_discard(void)
+{
+	int i;
+
+	/*
+	 * For each order=N:
+	 *  - push held_back[N].shadow and .origin to |collect|;
+	 *  - while there are >= 3 elements in |collect|, do garbage collection:
+	 *    - pop 3 ranges from |collect|;
+	 *    - use two of them as shadow and origin for the third one;
+	 *    - repeat;
+	 *  - split each remaining element from |collect| into 2 ranges of
+	 *    order=N-1,
+	 *  - repeat.
+	 */
+	collect.order = MAX_ORDER - 1;
+	for (i = MAX_ORDER - 1; i >= 0; i--) {
+		if (held_back[i].shadow)
+			smallstack_push(&collect, held_back[i].shadow);
+		if (held_back[i].origin)
+			smallstack_push(&collect, held_back[i].origin);
+		held_back[i].shadow = NULL;
+		held_back[i].origin = NULL;
+		do_collection();
+		collect_split();
+	}
+}
+
+void __init kmsan_init_runtime(void)
+{
+	/* Assuming current is init_task */
+	kmsan_internal_task_create(current);
+	kmsan_memblock_discard();
+	pr_info("Starting KernelMemorySanitizer\n");
+	pr_info("ATTENTION: KMSAN is a debugging tool! Do not use it on production machines!\n");
+	kmsan_enabled = true;
+}
+EXPORT_SYMBOL(kmsan_init_runtime);
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a1b5900ffd97b..059f21c39ec1b 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,6 +66,7 @@ struct shadow_origin_ptr {
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
 void *kmsan_get_metadata(void *addr, bool is_origin);
+void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
 	REASON_ANY,
@@ -181,5 +182,7 @@ bool kmsan_internal_is_module_addr(void *vaddr);
 bool kmsan_internal_is_vmalloc_addr(void *addr);
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
+void kmsan_setup_meta(struct page *page, struct page *shadow,
+		      struct page *origin, int order);
 
 #endif /* __MM_KMSAN_KMSAN_H */
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 8fe6a5ed05e67..99cb9436eddc6 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -298,3 +298,39 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 	kfree(s_pages);
 	kfree(o_pages);
 }
+
+/* Allocate metadata for pages allocated at boot time. */
+void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
+{
+	struct page *shadow_p, *origin_p;
+	void *shadow, *origin;
+	struct page *page;
+	u64 addr, size;
+
+	start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
+	size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
+	shadow = memblock_alloc(size, PAGE_SIZE);
+	origin = memblock_alloc(size, PAGE_SIZE);
+	for (addr = 0; addr < size; addr += PAGE_SIZE) {
+		page = virt_to_page_or_null((char *)start + addr);
+		shadow_p = virt_to_page_or_null((char *)shadow + addr);
+		set_no_shadow_origin_page(shadow_p);
+		shadow_page_for(page) = shadow_p;
+		origin_p = virt_to_page_or_null((char *)origin + addr);
+		set_no_shadow_origin_page(origin_p);
+		origin_page_for(page) = origin_p;
+	}
+}
+
+void kmsan_setup_meta(struct page *page, struct page *shadow,
+		      struct page *origin, int order)
+{
+	int i;
+
+	for (i = 0; i < (1 << order); i++) {
+		set_no_shadow_origin_page(&shadow[i]);
+		set_no_shadow_origin_page(&origin[i]);
+		shadow_page_for(&page[i]) = &shadow[i];
+		origin_page_for(&page[i]) = &origin[i];
+	}
+}
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 98393e01e4259..35b1fedb2f09c 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1716,6 +1716,9 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 {
 	if (early_page_uninitialised(pfn))
 		return;
+	if (!kmsan_memblock_free_pages(page, order))
+		/* KMSAN will take care of these pages. */
+		return;
 	__free_pages_core(page, order);
 }
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-20-glider%40google.com.
