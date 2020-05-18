Return-Path: <kasan-dev+bncBDGPTM5BQUDRBBOVRD3AKGQE6VIZSGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 82C321D70E4
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 08:26:15 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id f26sf8033792pfn.9
        for <lists+kasan-dev@lfdr.de>; Sun, 17 May 2020 23:26:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589783174; cv=pass;
        d=google.com; s=arc-20160816;
        b=IxjnQRyMzOr2ed9RpEtrLRRZfRHEepuC+iAGYv/65dTIbL19Lh8NYp1Hu2DPqiwYMl
         kcFpEoO4KSnNKYlsobkkjHzSjumZIEpy7WiYXjYSnKCZPv7ZPkrXWzaaNR4V/LIqxpzw
         EieGskDl7S9MDm68/nRAjO2pxJx3uuEwvhxgY7dO2INpV4z1bFkplyTrVNL8nzkyy2YS
         VJA9lLchNgDxsRJGbb+908XiKcThzdb1VXzBxRn+ZQSsjs9HuLiAs7qli41uTiMK2xKF
         DHmIORFO0cpmAu/04xUVNtioZY9ios21xCDAjVtDjP4godf/pVF8D3nvbKRcTzdl2w6g
         Z7ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ajtocMfEsyMHczZcHaWhy4KWmr4SOvoOnKQF7+wXnYI=;
        b=PjfnoJfUUQ207+xYkT+fC1TmTCHUGCs4cVHT3RecdvNjuea+85ktuhZaWg5OhdNvmY
         BPjp80gB5SH3iaBtshw9fY2/KazdsdHJhAgCax0lJzAhT03/yEPEwaRu7aYCxqO8ZXUf
         Jo96OSRlg4SBrCT6j2hpu+ceQTyOrGRAf+UxjPelZxck9cMVi4nq1IfZav0SzcxLSIn5
         we+1JvqOX3srpDhvNpp7BH+JN7rGUzrPml6hOLCGImxKieD9iEAxhjipg+jCC77SlwE+
         yu0UwIBjdkpEBVhQzno4yvs4JCXPzXYImWDBJ49BD2WwSuWhnzBeIaDyEo3COJyBpIXA
         YzKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=qmcdhdbF;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajtocMfEsyMHczZcHaWhy4KWmr4SOvoOnKQF7+wXnYI=;
        b=a8EhpvTsQxfHP2BKnDFTeb7B9suc/X5r8C7SrvcH21mrnUHNTsusA6SC3oKMlRUKr/
         KHUxjifQzSruGGTT9yFSD1rYTOlGPjFm/AzV5U5dzgU6gyYXzfcXxXlqss9gojqXAZvj
         G5+lL5qPHipJf3tgj9gvbisVALEylffycR3qyQwE5BwXtzukW1miQ2ENXDQkEWA4Tzsb
         BTTpzvhYJOnqYgyvM2fWUAg1Rr8uEuGkZKR0y8RCtg1KBtwm+nK3yRE7Ai8QOPHbnXoA
         B2KhfMJttVkLuU8MyCTYx2V+HPKYctSWl+01HAgHiaYHrF8N5S27JGNtQJzIBN0Wqdvb
         Gl4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ajtocMfEsyMHczZcHaWhy4KWmr4SOvoOnKQF7+wXnYI=;
        b=rIdepmN5Mb2R5npvNrqJxt12ajpE4lTexNWyX+JsW9IQTmpwp1diSUnCssmpAHIyLQ
         tqh+U1HYbHg8Cl3tTIo+gqH572POkEqYSzEOc5sy09tUs0nOzhRkptR6prLNtIdZSEoH
         QuOFvPn8HGm/9IJVGoX8yIANH4QREtnlMNZa0kjlL7qmTFPfuoIjyIATPFcwT0wMo77e
         nRX1CLwEcfWU3YaQ+oN3G87mz793h0nyFg6BJdl7GYRXuAVihTcLEz1okiZiQr5UiIB/
         Ii7SRNbjINCVsZaQxPGsbgoX7V0D6mioapJTRTpiS0huUpZ82Kb8T6ihU6dfVPiUmvae
         uRpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bohOGoL4u7ffV4XTVEIB9h0QYWdnM8RUbfIJf9wgXu10ACczS
	5wF9kEuD6KShXHtiGwEntYs=
X-Google-Smtp-Source: ABdhPJzcNIfR411eFwq86AyRZYDwGz2SHspoPtBFno6+9rlI5RV5XkXfIU6nc3zsdIqfSkYxUpDcfw==
X-Received: by 2002:a17:90a:d504:: with SMTP id t4mr17731310pju.123.1589783173764;
        Sun, 17 May 2020 23:26:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fc8e:: with SMTP id e136ls448020pfh.7.gmail; Sun, 17 May
 2020 23:26:13 -0700 (PDT)
X-Received: by 2002:a63:e541:: with SMTP id z1mr13426121pgj.284.1589783173306;
        Sun, 17 May 2020 23:26:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589783173; cv=none;
        d=google.com; s=arc-20160816;
        b=MumTWBmDUnvn678CeWWLVNjvl2KiTAGPwsdV7pqWTjFDv9KfvaL0lJ+BjC6xsA78J0
         Z1DEw5nlr9sKEr3Dj6BpRDk+LnAPkL8rJjtwpvY7I2Wkt8FQi4+grs/ZNJzImPKBSsXO
         GwTP/yTnwYatE1TUs35KM3Xbw6CGjPcC3syR9wnx0GVoYDSlwM5lxyu0668GckHIEwsR
         +mTEGMxtuwTutanJzQzeiuaiqgTjyfuj/ldH6odg46bcUY3zgLlWF1vQjl3FqxzpcuDc
         3DIZlrOUSl7NZhf5kdCVarHkBCIS06668qcWjmiZD0bXIvsP5oSieW8uTYhCpIFTLZ0c
         W93w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jMwIoafcIPklID0jC/qE2cM2vi67boNK7eoXAW/LkS4=;
        b=yVVM3fNjG7W1MuF8qrSlSR//eJzuMVDkfX2Kr4HBDW2VlEHFBJChvgB1ip72/SehbY
         qDIBbMZzEW1wxu3UM28ziGayZfU081WiC7Q5ddoQJucNjvatsx+iLu+rvuQcSQ9GyXah
         AQlzBfdcTFStPNLOPB210L/LGIiwke2l9TfPrqrbBBdpnupl1nuSAXpAsZd2EfxBxsV9
         F17p+DsxqUzuNbqwp9Aq4TMjAio26FKlzWA5XgIoT2Wdhgm27ge1ZADbLCqbK7szIJ4F
         3aEMzO2hI2tWHEA6PSOP1JPs/RKAVTcxuzyBp7G+7+QoU0IYZB3KboBMKE1rBqwpSDpH
         NyDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=qmcdhdbF;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e17si817933pjp.3.2020.05.17.23.26.12
        for <kasan-dev@googlegroups.com>;
        Sun, 17 May 2020 23:26:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4a6181a3d20249a39e47885731e104ba-20200518
X-UUID: 4a6181a3d20249a39e47885731e104ba-20200518
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1729141021; Mon, 18 May 2020 14:26:08 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 14:26:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 14:26:05 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, Josh
 Triplett <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 1/4] rcu/kasan: record and print call_rcu() call stack
Date: Mon, 18 May 2020 14:26:03 +0800
Message-ID: <20200518062603.4570-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=qmcdhdbF;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

This feature will record the last two call_rcu() call stack and
prints up to 2 call_rcu() call stacks in KASAN report.

When call_rcu() is called, we store the call_rcu() call stack into
slub alloc meta-data, so that the KASAN report can print rcu stack.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Josh Triplett <josh@joshtriplett.org>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Joel Fernandes <joel@joelfernandes.org>
---
 include/linux/kasan.h |  2 ++
 kernel/rcu/tree.c     |  2 ++
 lib/Kconfig.kasan     |  2 ++
 mm/kasan/common.c     |  4 ++--
 mm/kasan/generic.c    | 20 ++++++++++++++++++++
 mm/kasan/kasan.h      | 10 ++++++++++
 mm/kasan/report.c     | 24 ++++++++++++++++++++++++
 7 files changed, 62 insertions(+), 2 deletions(-)

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
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..4e83cf6e3caa 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -58,6 +58,8 @@ config KASAN_GENERIC
 	  For better error detection enable CONFIG_STACKTRACE.
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
+	  In generic mode KASAN prints the last two call_rcu() call stacks in
+	  reports.
 
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
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
index 56ff8885fe2e..78d8e0a75a8a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -325,3 +325,23 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
+	/* record last two call_rcu() call stacks */
+	if (alloc_info->rcu_stack[0])
+		alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
+	alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..870c5dd07756 100644
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
+	depot_stack_handle_t rcu_stack[2];
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
index 80f23c9da6b0..5ee66cf7e27c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	return &alloc_meta->free_track[i];
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
 static void describe_object(struct kmem_cache *cache, void *object,
 				const void *addr, u8 tag)
 {
@@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		free_track = kasan_get_free_track(cache, object, tag);
 		print_track(free_track, "Freed");
 		pr_err("\n");
+
+#ifdef CONFIG_KASAN_GENERIC
+		if (alloc_info->rcu_stack[0]) {
+			pr_err("Last one call_rcu() call stack:\n");
+			print_stack(alloc_info->rcu_stack[0]);
+			pr_err("\n");
+		}
+		if (alloc_info->rcu_stack[1]) {
+			pr_err("Second to last call_rcu() call stack:\n");
+			print_stack(alloc_info->rcu_stack[1]);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518062603.4570-1-walter-zh.wu%40mediatek.com.
