Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDOEUOMAMGQEVJKUDGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 724FB5A2A6B
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:02 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id g15-20020a2ea4af000000b00261cf22a8efsf657090ljm.8
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526542; cv=pass;
        d=google.com; s=arc-20160816;
        b=VvyyiijSRYB/5rutPbgJdXfkyNGuch2KqBYNfRsAA4v0jYPTLyWCenFAbYEkPY7Zb/
         RYM+0yzt6TW1yPtUqd+LL/YFKpT87SUQscf9vXzZhvqBa7BLXWKZ0mwOPZHBZ7Lwuy0W
         XLcbavmXJB2vm+S40Gungkb6ZF8oY//Ia/jF7bY9zrjiuGcHEe35ejp7v9JqVRwahPqZ
         IAx7jPvCCGlbDNe4YKMS8RvLGlXVBSQL2iAYKuIq1Rgv6QBgYaFCMoeRxcJ0A7p+RLGw
         0zl4rJjijapwWCjmfeMvzrbQ8kLVHmOeTWTA2p2bX+EEAaXfnpQ4QC8j+aa5Y1wzgWiA
         7fkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Dy89Oi5vAPyOyZsw/LpygAiDqcK41w9sSWP9hER8byo=;
        b=g934y1MN6Xw6obAekFKl4XsqEF9TkBXgJnJ3h8LkiGpJy/4YWJp8cjdZbJNER25XZp
         +E5K7GF27EYErk6cjHFHR7MsWEOnwDCJWXa0Myba/NBzRDadyxPXAQmbqJARVfCClI+R
         AoI613Fxl9haUUgghZu2OSW9MrKCGs5PQuriKzu9JDgjnirZHqxtBHrPSrDAOp0IcDmc
         fMQmDu7dEmsVuDPsMEJdHXKiPSIlAOgUBgNiG5raNSo2d6fuj5dIkzlX+JjJ30+UtU9m
         aZDGS2IKUmH9TewEG81DRpmSSsrO+mwFn2suRNuiqlfHuVUv33DHAxwqhY3n3HmYVzjC
         OP5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JVje2ZYr;
       spf=pass (google.com: domain of 3doiiywykcrmz41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3DOIIYwYKCRMz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Dy89Oi5vAPyOyZsw/LpygAiDqcK41w9sSWP9hER8byo=;
        b=bNaWyJkHTFUCPCzpr5TfcVZ04zxC9ecEuBFEj96DzvbyJdj3EcffjOyh3ae2ZhJzNd
         nL2EBCXOcUCtECsDu0kZMq28/xD7rx+yiO/P4QzLk3hy0zbd2OcV4Ajhqa+Kp7zvsD5q
         JmVf4B52+PK6lU+BgU9kQ/VrplnVKCoetp0TCHRsN2tizTLdoO2UQPYvhisLLDvPMMwL
         Y2ASM31dGwkTQjZhO6RTII/3Qfd66iUXsSRVPg3kbEpUwwpCL6hSRWqFFdkoi13z/8nd
         BRssrB5PoSH+yELvhwjMFLxem6eTZ6c2Qvs0INSMQPVLyJkA7MxSMNVh+7G9elwi4beb
         7zHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Dy89Oi5vAPyOyZsw/LpygAiDqcK41w9sSWP9hER8byo=;
        b=msDLFTjr6Yx44eC7yKXCuN0lnwIjpF4O4NG5wTPPJr24YQZc7Hg1rx/IUk7BVPwGp5
         jLnTQiQwO66LQQzK0EaQPKTxkWxiHTUONxdXUk5JfxDWLO3aEIirzbFnhpSbXoj3QY+z
         dVM2sn4fwlju0lNCM7rfNIjm+07/JXEEWGHz3IbUdMOt2YZg6vixFiENhjhDzO+2+F+g
         0FmeyOkcfPyMC3roWWcpbQK1j7a1hQYw46yxlqkcCf2ucFWPzWUTyjkqEWBvabaNu+NW
         aTQlt0RAYd+6+gT0XP1EUOisy6Rug20ZFOaByt2gyF3rg2GsIRMAqZjrymmqFubUqN51
         Ahyw==
X-Gm-Message-State: ACgBeo3kPM7k3V4iQSmYNFee8GnzJwZdrQHnIa76EVqJe0pTy2XMXWKU
	pL1+SOEUcOGef7Pd1rme+J4=
X-Google-Smtp-Source: AA6agR7LTU/FHLmtRQPBx+vczREVjN3MAq4MdJFDbFuzzYlLOokHV+0ICOa+Bqf8/mgNGRJbJgYEYg==
X-Received: by 2002:a05:6512:692:b0:492:ece0:32e5 with SMTP id t18-20020a056512069200b00492ece032e5mr2946336lfe.636.1661526541937;
        Fri, 26 Aug 2022 08:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:34d1:b0:48b:2227:7787 with SMTP id
 w17-20020a05651234d100b0048b22277787ls1111629lfr.3.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:00 -0700 (PDT)
X-Received: by 2002:a05:6512:398c:b0:492:ec41:4149 with SMTP id j12-20020a056512398c00b00492ec414149mr2573840lfu.412.1661526540791;
        Fri, 26 Aug 2022 08:09:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526540; cv=none;
        d=google.com; s=arc-20160816;
        b=NkU4MJYd9IKAquf3ElJrrSC66EZYZRhR3DlKPjWVtZ+yPpoI99Co4hLyWCpnqNlaG7
         DM2s5zRfd8JkcWVye0emDnst1/boFM78CDymD/Pf+ACYRcFX1NX4EQqqocTECZ5UQi5s
         4bnz4B7/jZOhVQMFjYYNAy6uWEwXiFGRnqkICrEscZLtEp8tjyEW3YF5CufhXqVFroWG
         BrWzEXnJdNTHltZysY/PLxueQ8wecmiGFT7KyiQkb9IZUAAYEtP8hsf711sDytAPeBGp
         rAn6BNuoXaG4PDEVbjPXRJtk6+6wPdShDIQuGfa2UWlCOTURDrsXXiHTBegLrqnKuOL5
         OCSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=peKPwrvfH0Rhral1Ak/YbLPiQRpKcgzst7DNXReDuC8=;
        b=QXs/BSY4ZU+iogpibgQhx85/eYi5euZYXH479XvJuG0QqCby/Cr3opX2SuBY00B2oG
         fbvDRZ62lf8bYOLIpp+LlOYSmoZJbgAqv2JLxug88qn1F8uARyhVDWm5HyvgCNADoSFx
         CVyg49QbyZjJ3lNJmE3S31y/lY9PsWGjqhqETK+Wq/JceG7KnTWXfWfssF5kqU0+y+IR
         3MjFUpf2pNRrbkf8mAqsPH8x+TN0PGpMPhv9vLcfeM/kdNXCkz/o7hQNvy5/jzRg61iX
         lOdVoGLvsoB2MRV5Zz7pTRjR3JskQwgo/79GJfgvYl3ekW3FhUXp5/OsKpVkdzsBzYAF
         yd5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JVje2ZYr;
       spf=pass (google.com: domain of 3doiiywykcrmz41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3DOIIYwYKCRMz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b12871da5si59489lfe.4.2022.08.26.08.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3doiiywykcrmz41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37feso664110ljo.6
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6512:39c6:b0:48b:9d1d:fd9c with SMTP id
 k6-20020a05651239c600b0048b9d1dfd9cmr2923286lfu.633.1661526540422; Fri, 26
 Aug 2022 08:09:00 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:40 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-18-glider@google.com>
Subject: [PATCH v5 17/44] init: kmsan: call KMSAN initialization routines
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
 header.i=@google.com header.s=20210112 header.b=JVje2ZYr;       spf=pass
 (google.com: domain of 3doiiywykcrmz41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3DOIIYwYKCRMz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
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

v5:
 -- address Marco Elver's comments
 -- don't export initialization routines
 -- use modern style for-loops
 -- better name for struct page_pair
 -- delete duplicate function prototypes

Link: https://linux-review.googlesource.com/id/I7bc53706141275914326df2345881ffe0cdd16bd
---
 include/linux/kmsan.h |  36 +++++++
 init/main.c           |   3 +
 mm/kmsan/Makefile     |   3 +-
 mm/kmsan/init.c       | 235 ++++++++++++++++++++++++++++++++++++++++++
 mm/kmsan/kmsan.h      |   3 +
 mm/kmsan/shadow.c     |  34 ++++++
 mm/page_alloc.c       |   4 +
 7 files changed, 317 insertions(+), 1 deletion(-)
 create mode 100644 mm/kmsan/init.c

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 5ec056380a43b..f056ba8a7a551 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -55,6 +55,28 @@ void kmsan_task_create(struct task_struct *task);
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
 /**
  * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
  * @page:  struct page pointer returned by alloc_pages().
@@ -176,6 +198,20 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index 91642a4e69be6..f8ca3ad78fbcd 100644
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
@@ -836,6 +837,7 @@ static void __init mm_init(void)
 	init_mem_debugging_and_hardening();
 	kfence_alloc_pool();
 	report_meminit();
+	kmsan_init_shadow();
 	stack_depot_early_init();
 	mem_init();
 	mem_init_print_info();
@@ -853,6 +855,7 @@ static void __init mm_init(void)
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
index 0000000000000..7fb794242fad0
--- /dev/null
+++ b/mm/kmsan/init.c
@@ -0,0 +1,235 @@
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
+	for (int i = 0; i < future_index; i++) {
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
+	u64 loop;
+	int nid;
+
+	for_each_reserved_mem_range(loop, &p_start, &p_end)
+		kmsan_record_future_shadow_range(phys_to_virt(p_start),
+						 phys_to_virt(p_end));
+	/* Allocate shadow for .data */
+	kmsan_record_future_shadow_range(_sdata, _edata);
+
+	for_each_online_node(nid)
+		kmsan_record_future_shadow_range(
+			NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);
+
+	for (int i = 0; i < future_index; i++)
+		kmsan_init_alloc_meta_for_range(
+			(void *)start_end_pairs[i].start,
+			(void *)start_end_pairs[i].end);
+}
+
+struct metadata_page_pair {
+	struct page *shadow, *origin;
+};
+static struct metadata_page_pair held_back[MAX_ORDER] __initdata;
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
+	for (int i = MAX_ORDER - 1; i >= 0; i--) {
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
index 04954b83c5d65..e064b4601af9d 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,6 +66,7 @@ struct shadow_origin_ptr {
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
 void *kmsan_get_metadata(void *addr, bool is_origin);
+void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
 	REASON_ANY,
@@ -186,6 +187,8 @@ void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
 				 int reason);
 
 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
+void kmsan_setup_meta(struct page *page, struct page *shadow,
+		      struct page *origin, int order);
 
 /*
  * kmsan_internal_is_module_addr() and kmsan_internal_is_vmalloc_addr() are
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 8c81a059beea6..6e90a806a7045 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -258,3 +258,37 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
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
+	u64 size;
+
+	start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
+	size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
+	shadow = memblock_alloc(size, PAGE_SIZE);
+	origin = memblock_alloc(size, PAGE_SIZE);
+	for (u64 addr = 0; addr < size; addr += PAGE_SIZE) {
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
+	for (int i = 0; i < (1 << order); i++) {
+		set_no_shadow_origin_page(&shadow[i]);
+		set_no_shadow_origin_page(&origin[i]);
+		shadow_page_for(&page[i]) = &shadow[i];
+		origin_page_for(&page[i]) = &origin[i];
+	}
+}
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index d488dab76a6e8..b28093e3bb42a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1806,6 +1806,10 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 {
 	if (early_page_uninitialised(pfn))
 		return;
+	if (!kmsan_memblock_free_pages(page, order)) {
+		/* KMSAN will take care of these pages. */
+		return;
+	}
 	__free_pages_core(page, order);
 }
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-18-glider%40google.com.
