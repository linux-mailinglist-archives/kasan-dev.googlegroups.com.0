Return-Path: <kasan-dev+bncBDGPTM5BQUDRBDE32L3AKGQE4KKUMDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 269E51E9CEC
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 07:09:36 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id y11sf4844694pfn.3
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 22:09:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590988173; cv=pass;
        d=google.com; s=arc-20160816;
        b=rWVHntK7JiuGUs3mXv0JyKd8U2FOK2fiR5aDdEHuqUJXsQZ4PfsIV2ndjrvx0U4V2v
         SDt3jV1GKHAG75cU3y7tzZ6TfYxUhSTgc6PJ3nwWS4DvV8mHPh7uvpi5lYpfy3hVJoIq
         rZbTFmpV5MjBX9yjfo5wFjnBXlryfeHh0K554m4Rp89tQjWz7Ucwo43D8YZql/zDzLq8
         8OQUN+fIZ5dm+Z8k75esNt25WGihi1vP4DHA77qv+5oxnQqrqmeBVyB7MMb6se0z7Ahk
         VQK+vy214/urwqHP29NDu66RuOvb5ywEfPl9T4p509jmcEXv5d/fqiKQFe6JOwd+Pj+y
         R5OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NK2XCFL6828znfI6CUulyUd27K8tRajgsmzItuoMjmw=;
        b=vD4eUuyE6QqRGoCEHEnx2My/zc/Aa3lr6L/sOmnITK9I+GKmhh+5rvD8tkVSShwHOU
         SQUVoquGKwRmy2XRIDa8tnyp7pWuIH2rsvRAWziUSjp9DU6mJOK64P38sfWojQFOCOIC
         Fyz/sLlv29gm+bDXHe5ZsP9buHcz/gsuCi35Grv/YxDQcnDorZO8LZChKE0sBPBZDY39
         k7cNPQx2fNF7zGMBto8Enoey3ghdr9Jdn/huXp0Gss73fGMeIVoOaEYG+KAIDJqc1JoY
         H+MjHpii9MaILQXpCIP8IE6p9eBCgQcc35ghMGno6qwRKRTDyO+mPovQ6VylQh7BuGaJ
         QlmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gR4QbHRO;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NK2XCFL6828znfI6CUulyUd27K8tRajgsmzItuoMjmw=;
        b=J1xASdu372JYrAFQWCs41PScyOAIsHByQj8i62IukvI+PnKo8z8P+DDjVXs/HJfdFF
         XbN5wG6UfBhsnSOmdUtolfx/QRAwYOJLNlC4QX1w00E9vzcc4/iwUlYLVXJH6Nv2ihXt
         oLVzIAcaXUoXzOwVde0E6vpVjDY8L6W894xX+co/pfrGWiunJemUMYTIjhk2PC1jZC9m
         LB97Fjl5MdcYQpEQQX9ar6mEHlC+cOPO4LNLHmK92AK84/rNV5mxwFmUmJo0FIFtxsmD
         i6XMNDn875OjD0QgLF5vVmYzPJp+Zr6zf4u2ytpD1l3ftEbY3x/UqdzzsJfrqMjMhc3C
         YMgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NK2XCFL6828znfI6CUulyUd27K8tRajgsmzItuoMjmw=;
        b=CAsKewFhOSp3lXJnhvbYLxfxAgLS4SEsSsa6qbxnUeXG1RIvvJChpomki4SWaMOvac
         8b5xgQd7isSwDSZ2Ja8XHBGFmze4/5ycUOSTkLeM/NiGV+AN4fkj83T5nyKA2ljshP4w
         7W2c95aFy18DD1lDE5MgaqEo9YbsJ+vZy6R/E676hOK8uY9bBCEWYEonAx8adKBPIq4a
         m9OohhE+5nMvPDJk6sleuZ/WcwscFTcq2p7NHmLF99AUJzWh3tYwyCDH0RxjT6bPTYOc
         ZVBFskgUnVqnQRqm3jpE1GINXYG70RtLbc4v6tDOaUoori3k88uK0sI4VXiGtiVy/vBG
         SHWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DVJO2NoDnOUY4gF8DW3nmkvbXSCH8Mq5Z/58e1gGp4t879thA
	XS7s2k+pRNPuX9CNJ5lch+I=
X-Google-Smtp-Source: ABdhPJwx6pnrY0JD8npqhqxlh0+ZVkSVcgOZp8sg/nBZgyJ54yseh5j8JL2QiL6Ko1HIWBA42Rvq6w==
X-Received: by 2002:aa7:93b4:: with SMTP id x20mr3399710pff.9.1590988173005;
        Sun, 31 May 2020 22:09:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f3a:: with SMTP id y26ls1301096pfr.3.gmail; Sun, 31 May
 2020 22:09:32 -0700 (PDT)
X-Received: by 2002:a62:1c42:: with SMTP id c63mr17603752pfc.293.1590988172583;
        Sun, 31 May 2020 22:09:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590988172; cv=none;
        d=google.com; s=arc-20160816;
        b=0svSUkjr0wl4QP6N26RyqimkyFV8j7SfZgH46THVPszT9Bepy2IsfvCHOI0+/oYh/2
         4pfa0k+LXMkt8/Jcj8aovJJJczYOlgfL4PeTgsaPW3XzTiEoqlalZWxEoRgHJERG1Z82
         1fDhybhUKXLNYelA8WfRgHNYMzNHi7P/m6E7FJw1HucuLWPVCjioY7WtZ9VuI8gKiGY0
         v2TPXJSl46EqAw3M4CbeBnO/3CPXK40dK5MIj3oW10ZA4VvSjiHdHtVv9zQsf/eleuDx
         lqPPFQO/hFrKjeQ0J96kDB+bxEbWT8ktga0xdVPI7bvHK6J5xKjrT02gT/GSaaibxkTh
         7opw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RNWE5TJREuUvwLyEEAgmJnR4EeREVK9B/oaXuDbjwU8=;
        b=iDevk7JbLj/dTDIPRZiXjG1bcWeY5sbu49HPoqeL1Wq2aZPQHx/9TszWYD6cM7B5Kj
         mjRvo0b1USPs719k5IdZKz2/8O0bhJEwmJ8SzwP8dRCsmgAXUzpga7Kao81zuViPzaEd
         AzmON6rhhd+mi9wNe7Ms4kgTvu3nn+GDNzy5Efk/DD3ronD+csgCJDDX7+2P0dtqTPYA
         iGkvu/XgBz8wjWSv+I26TLhK0VTcz+8RIIxxjgU+Iq74Or3VJ4HIMyOc1bOpmt3gUBVr
         WFY2BxsGPgaEAXaTZI3gUK9thHNlJ55Pl/FOd/8sg+noPlPb1YYYfmZb0bonDWVltVmw
         K3NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gR4QbHRO;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k138si955623pfd.1.2020.05.31.22.09.32
        for <kasan-dev@googlegroups.com>;
        Sun, 31 May 2020 22:09:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 8c8c9cb645e24acca8582a4119067357-20200601
X-UUID: 8c8c9cb645e24acca8582a4119067357-20200601
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1545189884; Mon, 01 Jun 2020 13:09:30 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 1 Jun 2020 13:09:23 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 1 Jun 2020 13:09:22 +0800
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
Subject: [PATCH v7 1/4] rcu: kasan: record and print call_rcu() call stack
Date: Mon, 1 Jun 2020 13:09:27 +0800
Message-ID: <20200601050927.1153-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=gR4QbHRO;       spf=pass
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
Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Josh Triplett <josh@joshtriplett.org>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Joel Fernandes <joel@joelfernandes.org>
---

Changes since v6:
- fix typo

---
 include/linux/kasan.h |  2 ++
 kernel/rcu/tree.c     |  2 ++
 mm/kasan/common.c     |  4 ++--
 mm/kasan/generic.c    | 21 +++++++++++++++++++++
 mm/kasan/kasan.h      | 10 ++++++++++
 mm/kasan/report.c     | 28 +++++++++++++++++++++++-----
 6 files changed, 60 insertions(+), 7 deletions(-)

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
index 80f23c9da6b0..2421a4bd9227 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -105,15 +105,20 @@ static void end_report(unsigned long *flags)
 	kasan_enable_current();
 }
 
+static void print_stack(depot_stack_handle_t stack)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(stack, &entries);
+	stack_trace_print(entries, nr_entries, 0);
+}
+
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 	pr_err("%s by task %u:\n", prefix, track->pid);
 	if (track->stack) {
-		unsigned long *entries;
-		unsigned int nr_entries;
-
-		nr_entries = stack_depot_fetch(track->stack, &entries);
-		stack_trace_print(entries, nr_entries, 0);
+		print_stack(track->stack);
 	} else {
 		pr_err("(stack is not available)\n");
 	}
@@ -192,6 +197,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200601050927.1153-1-walter-zh.wu%40mediatek.com.
