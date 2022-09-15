Return-Path: <kasan-dev+bncBCCMH5WKTMGRBN76RSMQMGQEJYHEC7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DD175B9E12
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:28 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id b12-20020a2eb90c000000b0026c05689de9sf4078666ljb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254328; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z06qtENrox0e6MYh1NVM8tl3KUyYUI2hGR1GrPnmOItF3imfFAEHQOeozWYW4k2iMG
         L8CFstuYa8xpqUqqQUOxyIN7OvNRSAxyzO3nW3naXa5a2CORrRmWvZDyC7g27lclG2XG
         SsYjsWe0uCHmNjrzyyOr1wrCxTYntQejesfnWFK/ZqjUwAA0jLLaIy3D3N2MJPcHT2Ay
         nz5OUOuMbWmvDoEN3vOnKHwq/vNIG9n2sKyyCLhQugYCBia2BCN2TJQgdC9Zlrm8FT3+
         tRfeIWZgZm9DTerALAqAsSVaJRKm4iZwBba+I7CFHv7dOLnLAydHgLbnXrYm9o4fRfNV
         Ag2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RGSYPdC/M6mYb+vuiaeHKHXV8fTw/0ztmkfDzCtj+lU=;
        b=QPsIBY1eWixlEZvvt2H3ubSIXgUGzwydp1RqJvho3rKVhLDSTDzMQausXzlo/7mhxV
         gE2P4oP6FAUYZyWwDp4nuj13beNZyu/WJ5Fy1GNneT7AW43ucNmbFMEIXP6jefiPCKK2
         aau0CwJFDWZ73CRFExCQi3gpaSLfgyZGsR0crkwgaiPrpRKY1BO7OLmx58DKlkSMHiQZ
         NC/ICZypfadaG/2SMdExgGB+TPcButzOWJOlCDS2iRvtlVo3O4p4Zc8A/GGZNHR/HknJ
         gBSZxzHaO/KtUSgEi4+OG3eXuk1289JXfilnX70Z9MMlUcZqsA05Xy58AvUPmJoVrNMw
         S5GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=imTcK6TF;
       spf=pass (google.com: domain of 3nt8jywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NT8jYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=RGSYPdC/M6mYb+vuiaeHKHXV8fTw/0ztmkfDzCtj+lU=;
        b=r3y40L7236EOrhxhGlMUYrn2I+e925SIQwPhjIPdMKhjpzoE+awFkoB2wd9GoVNOcQ
         ae4fkOmlYplXxh7rjLwd3HNWCX+hCshsIIKxRT+jwh5/4geMImo71zETLvgdkYp6Po4Y
         TRqxUxnOKwINDmIRB1QOASmQElB5B0nBvOiBAOa6UQLrbzPIYZ6VqeX6rIo5NNUwgDHj
         ZgyfJOIPC/ZBQPNvZRxygKdp/Shm3jk/B1DvR5q9n9/lSTbq9gszWOYkXxORUGTAj78A
         rbXKCa6oQb5o70vuvq/TuJSMbZ7VdGiRW5S3Jl91H/b86mILEgVkScRhAwIZdUMjZZLZ
         ULrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=RGSYPdC/M6mYb+vuiaeHKHXV8fTw/0ztmkfDzCtj+lU=;
        b=mEeu5iwPEWjshZAfegmEz/QxgZ+x7HDozDzW9U9vtrz1gPfRFV0Ts1svZ15OIakaMz
         XEZE1Ax69B+oA5FSeuJUmniAn6XEHALL1QsRE8H2E3HV1/bkCVZ2uEWL8xFHRyu6Xdd/
         inrcGTzYAVTqfE28GwrTK/Lr1w+8HbK3gGk5g190kKs7APzJVL34mF1KLzy4dncFFgQK
         utsJzHCoh6xKeZHRl0XGm/t/7P7Lx1Lsre/hp4KZeHRuop7zWzIWou3uKgXQtuiZk+Iw
         bNA6rTqquIhUlX+zr7qvPDqC6TfwcVX5CZBxKLos7UjyS8szssBkB0VUS4L35BqdQRBd
         k/JA==
X-Gm-Message-State: ACrzQf3j/ErnvVnQxeR4B7rHD4yO0Ve/F2UBt4ef4apEo2HioRXuOeMA
	Rut91d3SozoVUZfzKH3cL60=
X-Google-Smtp-Source: AMsMyM7sywMbtemaKEVdieZTTukmfasOsq6tdYdAkq2mUeuZ6u3leVkBTY7L70qFyFyEowbvFPxFpw==
X-Received: by 2002:a19:9202:0:b0:49d:7310:742f with SMTP id u2-20020a199202000000b0049d7310742fmr132785lfd.312.1663254327882;
        Thu, 15 Sep 2022 08:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:221a:b0:26b:fc94:e182 with SMTP id
 y26-20020a05651c221a00b0026bfc94e182ls2102053ljq.1.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:25 -0700 (PDT)
X-Received: by 2002:a2e:bf23:0:b0:26c:83e:b4d3 with SMTP id c35-20020a2ebf23000000b0026c083eb4d3mr63485ljr.282.1663254325681;
        Thu, 15 Sep 2022 08:05:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254325; cv=none;
        d=google.com; s=arc-20160816;
        b=m+DqzpJOCOSmaEGrJXhXvSE8tcZFxK7hgIb9ixb4P8DCT7g6uGtj0UNiokZ6nsv71a
         v4LxV6qszOzKzkgMGJOMlvrD8y8dBO43/g03qaFeWyWZNVZITLahzO6Q56NNFagv7Cl/
         xzzL6/k5Imh43idcIZ/zLZKpi6d4By8f2g6/fGDGpjTfRgC6B522hJpi/Fyigtcbkpo/
         y1521NBcM+zO1Q+WEzgKtWZOH+1daWjy39CnFtv82lh+m4XBAVplq+NYYmLPJDongam0
         w/qmR1e1FFD9tasI9zH1ay0MTuAoDLUYTO8RfHchIWDUoSwZOjqLAo7uG/+yhgbSkogf
         fpMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GDD69Hg38hLSA3Zw/mP+awjKG9w/cRToxTsz+vFO2/s=;
        b=HjeIKIIo1MyGUE8SYadOM6403f0/0ZqH01VmYK5IvvQqw6zZy80KNlJZYTxieChONb
         uaCYLMAcfxOAE+ddwKf7Ji0DpJadxHtAslljF5BCYSQGoDgB6BR7BfRrD/gx9jK/OD9O
         HTb42dryIL5nIZleLZj/+Uqe9hx700m3x6X+6LmpkMqvdTjRzDEO4t1n8pf3rYCUlEj6
         NaINSzhGrulJ0w9PeDC1RXg3IT/8LrSKmCGg4ltls9/uOIdSDglFud01+dPJOUc+Brjv
         30JGlQImaU0FW8In1SD1jSOWEMYDIR9qKcpnzzmnnwPMnxjSr3WOnCdzpofSK0po/ZSl
         lfog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=imTcK6TF;
       spf=pass (google.com: domain of 3nt8jywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NT8jYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 14-20020a2eb94e000000b0026bea510aadsi505975ljs.3.2022.09.15.08.05.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nt8jywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x5-20020a05640226c500b00451ec193793so8529834edd.16
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:25 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:4311:b0:451:c437:a5a9 with SMTP id
 m17-20020a056402431100b00451c437a5a9mr266952edc.272.1663254325073; Thu, 15
 Sep 2022 08:05:25 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:51 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-18-glider@google.com>
Subject: [PATCH v7 17/43] init: kmsan: call KMSAN initialization routines
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
 header.i=@google.com header.s=20210112 header.b=imTcK6TF;       spf=pass
 (google.com: domain of 3nt8jywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NT8jYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
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
index 354aee6f7b1a2..e00de976ee438 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -31,6 +31,28 @@ void kmsan_task_create(struct task_struct *task);
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
@@ -152,6 +174,20 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
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
index 1fe7942f5d4a8..3afed7bf9f683 100644
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
index 77ee068c04ae9..7019c46d33a74 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -67,6 +67,7 @@ struct shadow_origin_ptr {
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
 void *kmsan_get_metadata(void *addr, bool is_origin);
+void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
 	REASON_ANY,
@@ -187,6 +188,8 @@ void kmsan_internal_check_memory(void *addr, size_t size, const void *user_addr,
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-18-glider%40google.com.
