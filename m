Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSOV26MAMGQE2J3LU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D36575AD25E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:45 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g19-20020a056512119300b00492d83ae1d5sf1852797lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380745; cv=pass;
        d=google.com; s=arc-20160816;
        b=x24O0sk2broXGcg8++/V5qnQ2II4dXsinHsDttZO7rLuX7R7Cb/VNpXGl3ka2Np48/
         UUfrgcVMCivYTReej4LF3qs5L8selhruUM29mQQgChC5LxOl6pQita87nnp1ZV7WjnYJ
         wIXrUaSGQiVcMEFYr+HZd139VP3fAcpRhDOL9NUQTUqdWn/L98414xl3F0pH1x+X6uoQ
         DI0M0vhTW7wnJKAvWgwT3oEVoovtAKEEwhYDPSIkBesYtnycLuXd8qs5HdL5oNpO2akH
         TxxrEHwEoJLMpQ58VZQgLYX5RmaTBQjf7J+UqFftW49R1VTNd1rXTMhpa/gxD9us3xNu
         aAeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=F1iUyat4ZCbHpnjrz2PoWxhlglIJDwI5KDeJAI2NY6U=;
        b=TQJpL/JUAittIEykbXsosTjmfYBGWiUCM0YhXi2EgTfVjmXrhaUZWEXoWLocpPWf0V
         lvN9lrQXdn8S+6D+59mzJXccX6FACDtHbHXLEGIQylkJ6As5KLMrjzkWrClwjtLHqiqV
         T8rZPZYhx63UQErQGUvniqphZ2GtD38M764DiFAp3cpCqhnokOG2d5pbbx/cGS5QfBhd
         3pWpgVkwgMwvHE7er7YKYJzf5bq0+aB9Y+mrUM+5uibvmrb/uDsoD7NJipRV6lxLjUbE
         PlKu6OTmnTc13zjQA67Z7MrYZTfvPyUeEjURQ9LOohAwfBGkSiuiQ7Il+JoTxmXKDp96
         7GTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anjjT0lg;
       spf=pass (google.com: domain of 3yoovywykcru163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yOoVYwYKCRU163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=F1iUyat4ZCbHpnjrz2PoWxhlglIJDwI5KDeJAI2NY6U=;
        b=FMucVBfzk/3q298vnoQE1zAb+9JhqoQs0/4na7i5RrfwG9Ngn888Tx/JN3eOMXAJrd
         1EGGq7/FSIfvbSS3N1WhgzyPjmrXbm7uLc6MYCMRBAn/S3eM4JMKsKSNfCf9s8RQLxWN
         smZzohbTci/fnjEFsaZ4P7lrn9VADlHM9zbBFxrnu3XgZG6HyXuesP52Wr3N233cDopT
         V5yH4RtS/nexSmYxsmbWTPBn6Dp+zGZukaTiagdiHvMLI3QDgEXfK1/ghNXpSCRPQ8rU
         mCa3SOItaXGF0kA3wPdsZzHjKzcxlpnRNRoQCiVE1f5T9Uji6ZsQHjCdZcRXBlNEz0Lt
         Jo5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=F1iUyat4ZCbHpnjrz2PoWxhlglIJDwI5KDeJAI2NY6U=;
        b=GGOW2odimSIOouvaej5Hv7XWw7gm5UjxMeG3hmWhXLl9yFdlJ264AXBF0/Ea7BE18M
         YBedpAIbxJv21x6UyzqqIOfCq3rsKIV0DeQs4AbsWqbSTw+uSH7M5rWutUgWcpRo3f15
         pLLbbFpA18dN4F74wWcA7/rvrCPs+LEnfLZPFht6vT0XQS1Yg48GamC47EWP+jI0ZM/P
         dBTGWKBitUBMG17pArIeqMUp11sfWr53zdY677B/cgh29Pzv7Y4g3HgB8+aIixEItBXC
         4d4xMUvlgslAjv2VYkwGaHQQhCA76dnYODUJRaznvhAr81WptX1pRvZsRzSCQFWMk7L6
         8nRg==
X-Gm-Message-State: ACgBeo0G/3jR9imukNzCdkXu4WS0Un56EkgHpd5z+kJ4yFyS1prhXf3S
	caxWghWTgR0/3NcL9NGkR8s=
X-Google-Smtp-Source: AA6agR72Sz3F8/eJ2JKhX5Ve4vpNgYyAi8XYOYF6kf/n2/cRBpAtqyWJhxXF+toXfQogCbluJFfQyw==
X-Received: by 2002:a05:651c:1591:b0:268:f837:2821 with SMTP id h17-20020a05651c159100b00268f8372821mr4090397ljq.323.1662380745564;
        Mon, 05 Sep 2022 05:25:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls4741592lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:44 -0700 (PDT)
X-Received: by 2002:a05:6512:33c8:b0:48a:fe63:e4ea with SMTP id d8-20020a05651233c800b0048afe63e4eamr15493223lfg.415.1662380744511;
        Mon, 05 Sep 2022 05:25:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380744; cv=none;
        d=google.com; s=arc-20160816;
        b=gonMNGabv+YEpdAe+WFvAak4MtJ0vzlfcQXj5C+QsT8KIBlyUcsOhzwzmXu4yP4bIV
         xIM06T6fawoMke4s01eRHIQ5pi1AxyfY3WpDgjvD1RhaDbUAplA0MSxMeKJcvs8tsBtL
         +8nsaJ+BUO7bl6jvaz+2A209OQwJZ2Y5Jw0mLF6qrY5JWxuWe+DeCcvmn19BgyPGKmlK
         gF+3EH/X35xeHLu2xlxwv9b/grcghHTuXsUf2wLNrfgDRtJbhY5qy3VbfdDQ6FuntsjR
         VCo8c0RJlEEiiF46m2SU6i7TNnw9owVETJgnLzXDkUHLlnCGEKPN9NkSJnHAQCxHYpRC
         HCjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BF2kccsg/NJzP2Xwpe+d061LyCU8U/vhohlAjevIJbs=;
        b=kDY7GCGaQVI4DqMndH9mmq6MhP6St815QSz5TfL9pHHGpauwEEK7corEq+6ZUm5R1b
         FezURGS0wiqwTriFmWINd+GCaF5BNdGemelhSJ9Mz2rwPH8eYsMT8CDlS8Xy4Qn2xQTR
         VYc/O4w/ateKJzZaVkRDsGgZPlIMyEBsXeMrohTH7z78Dz8tjlqlMImgwqAy7SJemTIA
         gZGsmIBZjEGRHB/6PMyLw2V6g7JOrO6ZyqC4nLcwnwvOa2aSJSAAgHVb1xS521UeyYMr
         hjBJzCBd/bDgc3kH4NHIpT0ftdkFHr1cr1o2xPM31mMJbOsTyliXiMyI3GBTZ1B+tK0k
         j4pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anjjT0lg;
       spf=pass (google.com: domain of 3yoovywykcru163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yOoVYwYKCRU163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id s11-20020a056512214b00b0049495f5689asi328112lfr.6.2022.09.05.05.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yoovywykcru163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id z20-20020a05640235d400b0043e1e74a495so5774181edc.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:44 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2701:b0:741:51eb:2338 with SMTP id
 w1-20020a170907270100b0074151eb2338mr28969744ejk.501.1662380744169; Mon, 05
 Sep 2022 05:25:44 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:25 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-18-glider@google.com>
Subject: [PATCH v6 17/44] init: kmsan: call KMSAN initialization routines
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
 header.i=@google.com header.s=20210112 header.b=anjjT0lg;       spf=pass
 (google.com: domain of 3yoovywykcru163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yOoVYwYKCRU163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-18-glider%40google.com.
