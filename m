Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBMH7SKQMGQECF73SKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 00F0156351E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:06 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id j7-20020a056512398700b004811ba582d2sf1176645lfu.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685445; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1wOzAOyHSVQBPYyfBUxRrxjwihHOis9O6HKFP2IfQTl91YAsN1GHgbwCi09DdI37B
         xDXUtKnzAc97/9nVuQS2hOHJFKFfvdHmppDrr9aVYHeXw2V0XkR/Yfp+3xEfrdZfQWoE
         poQI+JVVCoBIQtXrKydw3EKdNIVuNtm8AvC5achbGtlQV5M/UfwCQNm8Ar41Cc3G6Z6z
         XRQzlDZuxc4XEt3G3EidV0GNXc0PK1WUHkpRrbpdbN/KIV3TZesTdGUXbxFFXT0qKtAp
         nhFQ0rDANkPmRSySkRHYMFxFnH3GEGZnKZ3koLwdjltdJsyzibj1FOS7LWHoxsh18hkA
         FLFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=u3ZidTqLeFMPaz5lH5vfKUGdm9ZnISzqL/+2VxiB4+M=;
        b=ew6ihYHeTmXbDdhf52Z8WNH3meYg0nTL3nOR8XpdX6vpHmoN2NzTG6xP0ClvrvOp9s
         RDcTfy2dY+2SZuZOGb5Yw2mmPbhLKde5ZSqQOeUD36Ja8rMwYSGeQ4OOeTySLSkdmzx3
         QArS1S05zSvOSJg/xrEXt9gcO8WrQUjDbPGcujfK7TZVanPgEIUNl7R4J1i08ACMU1ce
         swELo2ezSjfAl2YGi+x+jAVJtmxFmh1k4NVimOy+0NTNsnwi4MLFtxATnDWslKEk1yz2
         261dpIBdxL8tGrP+QSlXruhllmrPw7dyRME/4VDjOUze/xz+Xn72yN5mc1yVrIKR95TG
         maEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y2pA3EYx;
       spf=pass (google.com: domain of 3gwo_ygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3gwO_YgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3ZidTqLeFMPaz5lH5vfKUGdm9ZnISzqL/+2VxiB4+M=;
        b=agsfh/kBdNWobJ9wQaEVjJZP7K2Xn25zHdz5INc82wb/+Azauvb7S1Mr7t880JP96l
         VYcXJrO5Hf5jMA8DJD9ZJcrQmo+ipjqj572PztsJJbA8i8jBvSIqcCLU0KcgsZY9d1+7
         4VZZSAn1zNcMsz7lBW4G6oIrTKy8LcN3KjXOLfdbqc0eyqI/oAuFnD8F61wwGcTIMf6o
         1tHNGjLr7vQEyxKYgK4ASxQSP43LDSPDA1TTQB6BKyX3RGY6GFYv0p5lL9bo4jn0GfRS
         dSSYQ970tpgo8B0JZjJN47uqNZMkaAYgYMiikoXU5SOZn8GjEK6sHDbrNuYNro6WD6Mm
         EQAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3ZidTqLeFMPaz5lH5vfKUGdm9ZnISzqL/+2VxiB4+M=;
        b=PKyqKs4pDxEIvZMxGECqnkw/zZRCPcf/k4ax1HW2lRzFus4OMFSxQbyNigkyYAP039
         Gm2YGCzyafLWIpAa1xs3omxR1W/+XdEhiHGJ66Aoh7bNfdgjPQ/acoD2s3mcOUuZVaY7
         L8f8wEhnFGdDZJyGiYpcAoD3FZo4Rgtfw1buwNTctuBGYyCfHW9tVASoDJs60ICd5S2Z
         DfpMwIXtLOl7o9MZkz8ZfToaiWybqlUedvjzjKuW6xuh1ZVK/tiEu2/ZFlaUxprHyCYD
         3eDc39JxHzFLkbe3a8fLM2SGQ1v4aJmRcYZNW8u2emZuU5CuXmD9XasiJuCtkBTLf6gQ
         4bnw==
X-Gm-Message-State: AJIora+YcSYIED2hQyesam1o/GoIWtZFLN6LINvJ4x3ahRcgNMlszeiL
	hdE46RH/+hNX5wcwuBP7PhY=
X-Google-Smtp-Source: AGRyM1sRgbbhLXHJ1x6gFWdSKdBJjXFE8S+KdW9ILTYC7P1ndx/jrv88xNufE87ryKJJxbgWwIM94w==
X-Received: by 2002:a2e:390e:0:b0:25a:9763:d2dd with SMTP id g14-20020a2e390e000000b0025a9763d2ddmr8230040lja.210.1656685445498;
        Fri, 01 Jul 2022 07:24:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e03:0:b0:25b:c694:1134 with SMTP id e3-20020a2e9e03000000b0025bc6941134ls2733924ljk.7.gmail;
 Fri, 01 Jul 2022 07:24:03 -0700 (PDT)
X-Received: by 2002:a2e:720f:0:b0:25a:9f46:6f5e with SMTP id n15-20020a2e720f000000b0025a9f466f5emr8025106ljc.103.1656685443572;
        Fri, 01 Jul 2022 07:24:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685443; cv=none;
        d=google.com; s=arc-20160816;
        b=oChS2iKCFVDMx8kLT4rexWSKYkIvFxfXzl0EvB62dHrH4W71r9mH5aBk5h+SmfOKUe
         ScGSzoGI9KBxWhaG0+Xv6l7ExcDILxNHxSDJ7kegS3radEVdRhWExQ1w5tVMsVWBDPJJ
         NeuYdrWvXA5dLv526ZrAco/a7EYW3aHGyZX/0tHBE0Eo3+uSK7B23QjADelp7QyMIO4u
         vjaFXhtX1RKzt1Mg3xofHRTjK883gyNt+YyV7vLJHmUoOG5Riou3SpPbwvK5LM3HwsSh
         Ny0bK6s7RgCYiDIEHrsFqoVF0cie3gn3MRhyUU1yakGLxTUNJNRhh6yqK3KoAg7PCRav
         O29g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=e6DErphzLhmkwnld+r1h2oFxsMsjnlMc9+N+LMIifaY=;
        b=dL87pzAjxtLlUpEpDMDQw7KRSiCcIgZZKYgga/vBgNIM91QM+Jddr7csa2T6gr6XNT
         MAtAsYtbmkSDoI1PiTqtB4ZiooioErSmNwq+VkFDpXNn2Dpg3bv+ubP3n7HoPKunu4Dm
         JKa3Mf5ckj50YOrZHHZgobMoOc09Yx/q2pDNlhRORp5W1D/nvZVI/lqFqmuh0vR0BlC8
         Z1DMsGX4IY2nxziDLfts4o+hRKmk/LAor/Am/ALFn2e59yqEiJstgwTW8yRZAkdDMXX/
         FSmVqac7wUDBWBFnrau/GMEARhmE4fWKcPqxC0WjWWYHRWCR8OSvlhd96zlMBALXoFT1
         XvkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y2pA3EYx;
       spf=pass (google.com: domain of 3gwo_ygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3gwO_YgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si982160ljg.4.2022.07.01.07.24.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gwo_ygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g7-20020a056402424700b00435ac9c7a8bso1877027edb.14
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:03 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:7207:b0:726:cc89:40ca with SMTP id
 dr7-20020a170907720700b00726cc8940camr14991650ejc.141.1656685443124; Fri, 01
 Jul 2022 07:24:03 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:42 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-18-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 17/45] init: kmsan: call KMSAN initialization routines
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
 header.i=@google.com header.s=20210112 header.b=Y2pA3EYx;       spf=pass
 (google.com: domain of 3gwo_ygykcaiinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3gwO_YgYKCaIINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
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

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- replace occurrences of |var| with @var
 -- swap init: and kmsan: in the subject
 -- do not export __init functions

Link: https://linux-review.googlesource.com/id/I7bc53706141275914326df2345881ffe0cdd16bd
---
 include/linux/kmsan.h |  48 +++++++++
 init/main.c           |   3 +
 mm/kmsan/Makefile     |   3 +-
 mm/kmsan/init.c       | 238 ++++++++++++++++++++++++++++++++++++++++++
 mm/kmsan/kmsan.h      |   3 +
 mm/kmsan/shadow.c     |  36 +++++++
 mm/page_alloc.c       |   3 +
 7 files changed, 333 insertions(+), 1 deletion(-)
 create mode 100644 mm/kmsan/init.c

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index b71e2032222e9..82fd564cc72e7 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -51,6 +51,40 @@ void kmsan_task_create(struct task_struct *task);
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
@@ -172,6 +206,20 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index 0ee39cdcfcac9..7ba48a9ff1d53 100644
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
index 550ad8625e4f9..401acb1a491ce 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -3,7 +3,7 @@
 # Makefile for KernelMemorySanitizer (KMSAN).
 #
 #
-obj-y := core.o instrumentation.o hooks.o report.o shadow.o
+obj-y := core.o instrumentation.o init.o hooks.o report.o shadow.o
 
 KMSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
@@ -18,6 +18,7 @@ CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
+CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KMSAN_RUNTIME)
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
new file mode 100644
index 0000000000000..abbf595a1e359
--- /dev/null
+++ b/mm/kmsan/init.c
@@ -0,0 +1,238 @@
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
+static struct smallstack collect = {
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
+	__memcpy(&collect, &tmp, sizeof(tmp));
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
+	 *  - push held_back[N].shadow and .origin to @collect;
+	 *  - while there are >= 3 elements in @collect, do garbage collection:
+	 *    - pop 3 ranges from @collect;
+	 *    - use two of them as shadow and origin for the third one;
+	 *    - repeat;
+	 *  - split each remaining element from @collect into 2 ranges of
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
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index c7fb8666607e2..2f17912ef863f 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,6 +66,7 @@ struct shadow_origin_ptr {
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
 void *kmsan_get_metadata(void *addr, bool is_origin);
+void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
 	REASON_ANY,
@@ -188,5 +189,7 @@ bool kmsan_internal_is_module_addr(void *vaddr);
 bool kmsan_internal_is_vmalloc_addr(void *addr);
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
+void kmsan_setup_meta(struct page *page, struct page *shadow,
+		      struct page *origin, int order);
 
 #endif /* __MM_KMSAN_KMSAN_H */
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 416cb85487a1a..7b254c30d42cc 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -259,3 +259,39 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
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
index 785459251145e..e8d5a0b2a3264 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1731,6 +1731,9 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 {
 	if (early_page_uninitialised(pfn))
 		return;
+	if (!kmsan_memblock_free_pages(page, order))
+		/* KMSAN will take care of these pages. */
+		return;
 	__free_pages_core(page, order);
 }
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-18-glider%40google.com.
