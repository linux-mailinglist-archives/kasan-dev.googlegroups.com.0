Return-Path: <kasan-dev+bncBDGPTM5BQUDRBYOHST3AKGQEH5O3HLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E36771DB375
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 14:34:42 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id e44sf3527830qta.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:34:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589978082; cv=pass;
        d=google.com; s=arc-20160816;
        b=hs5Ahg4Mii853m2koqjXNhu07vVYxCE4G84np6GCm17utLlxE+iE1parN56PgVByzv
         0vYOMCQpnomBfFA0TJ/gjlGLgEC6CR8Jb5P8nER915mKCIRlbM3BQFljEqRY84KtS4eo
         vRkhTaR7OlteW8wI+IPbtDPy87kAlLCV91dEjJPUuzfdNKV86V5jug351jGNFCQD1mKa
         4PdMDJTepzjVzvn/OxHMugHd6o0tNdXevV2h4zN3j0NtGbRnrVNIlJkUw49/z6gfPhlG
         S+ikPPs52eKLJqQgqLWPKlzbL0aA0GHBSUmUVScdZOOUdySnaLcj3oRctNNbMwqgRXcf
         ZOug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6UFsOOK6jwQ4AlW12zA8RTNukRljOKGmk7/Mc6aANN8=;
        b=eyLgSHS3Bnj0j0wVhfWHxDnP6RGsEPhzAGsD+4G+R+D+E7tiSX6W7bOz3A5IWhjg+m
         yw8UaW6B4bHY5DwsDcgZwkim956gpAIrsL6+PUO1Fe1XnJ6ygXK9467iBrMaJU7TAiO+
         C0hOCe/HEezvMtG+ckCy/iZO50E/rWlgL0OEwru8K1PORFiosS9jz2wvwj329tCGcqiV
         YCepeIkUHdEFXq7mj38Jk8bO98DrmHzNP7vMB3q7wkpPi1DHtORFGSdaMLwNAzuE8Fr5
         uM4l/AboGGOc7+vrOqlDBT7EGLvEGfe2q6RofOmVMQQcUsosjEJST0o0ViXkYHtQlrH1
         xYyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZHJAeToh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6UFsOOK6jwQ4AlW12zA8RTNukRljOKGmk7/Mc6aANN8=;
        b=QhuQNGBqg1Bnvrv91PAJPt/wK2C/f3ZYNY40uXaczz1ouptTTpPVQao842MEboBKmt
         3FZtLkpHsO+Q2gaWWDFE/4tULoXTMQY+aR6fgWDhBYEbhJNY5DDv5+1ehowMaQwP8ylG
         5gTuNIOB/Wy4fWJgRirtWMmFiv5IKSHJgM+IVB2geGAXRpCMPzQQ8PjZWt9nufOO4Idb
         hVOVAVmPtlp1kGKVX6hGy8IyLIqvby/0nung8dzjpdHHbeMj6qgar6v5/qIYfZmizrN1
         3z0sWGoZdR7YMACO6Fvj5DPFD/PSdxakEzgw11CWLwOFGc5QCNqeqSUTvenSGczmtaP0
         sCQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6UFsOOK6jwQ4AlW12zA8RTNukRljOKGmk7/Mc6aANN8=;
        b=rC5nNnwhystp2lOMkX264Q5F6hb1CvHLUi+vlcNXY3S6LXsVttQ+x2p8ihm8Svmke/
         S1JGSco5561YpsrNd7o+bl4+bfR2so5KTMkK1ITwvDfKf3KXj/NzPtWYqyp5RVXvwtVj
         STQEkRNuWTzWSXdUGbx1HOiSlQf8P6JSaKjORcoNCZVewg5tCEx81v+ZABiraRwdnDhv
         YY/OAwffzhIxqxKU9oEfPJR6IZh5/ZgMGU5/7O6Qo2y4hI1alSHyVMQRQFafxVhOX751
         K5JOIJiZTAKv42mMKbWQftKYo9Ira/7G/+90IEIfYzEHYztptIx7BZl5qkwxmnMx22zm
         LIuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308w/ptHkReCegfFm99iaKYgKcZPQcoruoL88lktaaY5+qC5HL0
	LnMrpeUXzRZHv+ngUjY/eEU=
X-Google-Smtp-Source: ABdhPJwOgtI0Od6t1KvIlzn99DNVSrcRD/4DQLRQbK5NrA2qZvgde5ZztPK1gAvYBbVE+jq0nENJsw==
X-Received: by 2002:ac8:555a:: with SMTP id o26mr4954436qtr.190.1589978081937;
        Wed, 20 May 2020 05:34:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2d62:: with SMTP id h89ls1289886qtd.0.gmail; Wed, 20 May
 2020 05:34:41 -0700 (PDT)
X-Received: by 2002:ac8:108b:: with SMTP id a11mr5110991qtj.173.1589978081192;
        Wed, 20 May 2020 05:34:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589978081; cv=none;
        d=google.com; s=arc-20160816;
        b=xSk/Yh9nVosE+vOzrEeSD7OZNHXdwuEc0tq3jF8n9+MZQLp7f1fuhz5BTEukqLtVAD
         q8qTnXszByMmSIEoBz6L/fjp1gTxetTT+Mtoxbvj1oJ7SKRoCCvFxKYo/28LQTYNyh0l
         Ox2TB1hc5mz8HMcpLFbHXhgmkZnY2BpVljHt2/5+Pe6UBW1lelaP9yxda7HFJkw0tiZn
         3VCHNzNgiLSra5+MpWDlGXnMvYsjmBc+YZiMS+tHtJYtgZtUgD7ihtSptGw0NAIrnRmd
         rvi1Zr07minHvvu5MtEsV3NOrx0y1gVUlAPAEMcDXOcratyzI3SVXtO3kcCV6ajQJEfo
         xsHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=MLbI5UBGcTLgx4Lz76VmpfjIP0jdV5jjzRMAfolENLM=;
        b=pOPELc4P085ho1mzwV9Cq4Kws7oaOyn67EvOgu58cMpRCwYJ2N9bjKukFviqroNZjx
         a/cYCdCq26drpbrbGjaCJVvwpk2sQR84Opg21YVcgkJm/kt/oOFasGOWtuMdaeZaA9kA
         xErr+ifO4CcOygG1gj9mxB8FPeb+vxPDvLpca1crXTW5skZHbrHjnkoVM11n8zyK3Upv
         bwOTvi42NzIdjozil0/B1Hwez8KpzAt/yh4sbEeHBboT6/cFOnJcPG4AbSgx/HbNKYWw
         OBJyYrMdQeEW8i9GdtKVEAwGscDRBjAZng18Nj8ZXso9WNnLzqnjUDC6Nj8O5cn1VToa
         5o2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZHJAeToh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c7si208819qtq.3.2020.05.20.05.34.40
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 05:34:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e1c8184ea9fe4d3b8efd7702e403f7f4-20200520
X-UUID: e1c8184ea9fe4d3b8efd7702e403f7f4-20200520
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1792537476; Wed, 20 May 2020 20:34:37 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 20:34:35 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 20:34:34 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, Josh
 Triplett <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v5 1/4] rcu/kasan: record and print call_rcu() call stack
Date: Wed, 20 May 2020 20:34:34 +0800
Message-ID: <20200520123434.3888-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZHJAeToh;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

This feature will record the last two call_rcu() call stacks and
prints up to 2 call_rcu() call stacks in KASAN report.

When call_rcu() is called, we store the call_rcu() call stack into
slub alloc meta-data, so that the KASAN report can print rcu stack.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Josh Triplett <josh@joshtriplett.org>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Joel Fernandes <joel@joelfernandes.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  2 ++
 kernel/rcu/tree.c     |  2 ++
 mm/kasan/common.c     |  4 ++--
 mm/kasan/generic.c    | 21 +++++++++++++++++++++
 mm/kasan/kasan.h      | 10 ++++++++++
 mm/kasan/report.c     | 24 ++++++++++++++++++++++++
 6 files changed, 61 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 31314ca7c635..23b7ee00572d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
+void kasan_record_aux_stack(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
+static inline void kasan_record_aux_stack(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index 06548e2ebb72..36a4ff7f320b 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -57,6 +57,7 @@
 #include <linux/slab.h>
 #include <linux/sched/isolation.h>
 #include <linux/sched/clock.h>
+#include <linux/kasan.h>
 #include "../time/tick-internal.h"
 
 #include "tree.h"
@@ -2668,6 +2669,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
 	head->func = func;
 	head->next = NULL;
 	local_irq_save(flags);
+	kasan_record_aux_stack(head);
 	rdp = this_cpu_ptr(&rcu_data);
 
 	/* Add the callback to our list. */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2906358e42f0..8bc618289bb1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -41,7 +41,7 @@
 #include "kasan.h"
 #include "../slab.h"
 
-static inline depot_stack_handle_t save_stack(gfp_t flags)
+depot_stack_handle_t kasan_save_stack(gfp_t flags)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
@@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
 static inline void set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
-	track->stack = save_stack(flags);
+	track->stack = kasan_save_stack(flags);
 }
 
 void kasan_enable_current(void)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 56ff8885fe2e..8acf48882ba2 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -325,3 +325,24 @@ DEFINE_ASAN_SET_SHADOW(f2);
 DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
+
+void kasan_record_aux_stack(void *addr)
+{
+	struct page *page = kasan_addr_to_page(addr);
+	struct kmem_cache *cache;
+	struct kasan_alloc_meta *alloc_info;
+	void *object;
+
+	if (!(page && PageSlab(page)))
+		return;
+
+	cache = page->slab_cache;
+	object = nearest_obj(cache, page, addr);
+	alloc_info = get_alloc_info(cache, object);
+
+	/*
+	 * record the last two call_rcu() call stacks.
+	 */
+	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
+	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..a7391bc83070 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -104,7 +104,15 @@ struct kasan_track {
 
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
+	 * The free stack is stored into struct kasan_free_meta.
+	 */
+	depot_stack_handle_t aux_stack[2];
+#else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
+#endif
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
@@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 
 struct page *kasan_addr_to_page(const void *addr);
 
+depot_stack_handle_t kasan_save_stack(gfp_t flags);
+
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
 void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 80f23c9da6b0..29a801d5cd74 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -105,6 +105,17 @@ static void end_report(unsigned long *flags)
 	kasan_enable_current();
 }
 
+#ifdef CONFIG_KASAN_GENERIC
+static void print_stack(depot_stack_handle_t stack)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(stack, &entries);
+	stack_trace_print(entries, nr_entries, 0);
+}
+#endif
+
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 	pr_err("%s by task %u:\n", prefix, track->pid);
@@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		free_track = kasan_get_free_track(cache, object, tag);
 		print_track(free_track, "Freed");
 		pr_err("\n");
+
+#ifdef CONFIG_KASAN_GENERIC
+		if (alloc_info->aux_stack[0]) {
+			pr_err("Last call_rcu():\n");
+			print_stack(alloc_info->aux_stack[0]);
+			pr_err("\n");
+		}
+		if (alloc_info->aux_stack[1]) {
+			pr_err("Second to last call_rcu():\n");
+			print_stack(alloc_info->aux_stack[1]);
+			pr_err("\n");
+		}
+#endif
 	}
 
 	describe_object_addr(cache, object, addr);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123434.3888-1-walter-zh.wu%40mediatek.com.
