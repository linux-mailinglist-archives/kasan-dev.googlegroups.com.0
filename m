Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6PR4L2QKGQEZDU4TYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id B18261CCFBD
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:31:22 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id o13sf3781069uap.10
        for <lists+kasan-dev@lfdr.de>; Sun, 10 May 2020 19:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589164281; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0PTjp2RGmuY5Rlw/QNGXe8cKSn7z64GUljyc6xi5KssL6s2aBHDdjHcyYDwI2fpgE
         AvNmSK9j7Nb/CJHiTCUwnOLBphRG1/ZN7Oe2GtbD1hbDcJDMIH5LB7YFs2CnT3yagkUt
         HHTJNVH1dudhl2vwATX8V6lSLoZr6BmIM7l0KTy4ZOnMiqoWnvwELwrmupbUCcfiUtQ9
         Hb9nPMBOhK8Uw/e9aYzZGyPaLm8WyG/fe76WtmbvX0CCHq+liWZ9SJugkQY3EwrhEXK7
         TAMtQ+UBtdaYxaOvWMlbGTKv3i41O5EL/ea4mx1stDnsbdBoImGh5wrR/av9bJqvudn7
         LqmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=N5JVOoNxFyl1R4nHFxo9s5pG+H6deXe3DPOj09wv1x8=;
        b=Hr1UcawxwnNZqCZCJBdrIDpSGXropnJX9MVNrjQAbs227GEYswiKWlQ2Rx/+8pVnZZ
         PatOgH0tWvrK5ZefHCpZwAnJAqLeEm88/sH0xfdqhlIB3O3zMLZo4W4iz2+TkYISaKqx
         Gdtv0db7dzIvDrxr1Bu+sOK0ZJTYUJqIv0VyI9hbBfNJM8Og0/XJqrs12UQJWkSK8BH9
         0QvZXLG0WiOUdHVqsQK1MNqZKDZdsoO+KwvvHMBQIdpt7xWDjjWJMvHRe2Pmq2q5lz9o
         CZdL65VhR19rXU9K88EIz3HUZBx95CgjBHKWyX6ijB2Z5Oatdk0muARsuwoRev7P0QW7
         yKfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="Xk/Gft7g";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5JVOoNxFyl1R4nHFxo9s5pG+H6deXe3DPOj09wv1x8=;
        b=VAys05AoleIovZzVZbwZ9wXdqrKkJkjy8ov1zeMv4r5YSR9zGnbEy/GxcDILPIoGte
         7j02gSHon3nSIf8zQjx6sr7vpZ3mozMHIVupn5nYsaGNXWV0F2EOhex0ITiPycIfdG8m
         rfCf+o21YKIxPu2ILmkmH0wjCywf7Y5A4Np8rH/TCxNuaVkkFK5sofikXd8aXjLnxmwH
         qWprVUsaI5dvj87SyfB4Lh2kwLHFD0yMU1S9CLa7oAAnM34PN8RZSf6ArWU1fa3WA9qe
         OjqvribCRlJ6zxje20pdWFQ53ACghL2ISmjFHRExmF8qs/Z+4J496lwImNKhZ1dKRqEF
         p04Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N5JVOoNxFyl1R4nHFxo9s5pG+H6deXe3DPOj09wv1x8=;
        b=SsnP9JLjsMbi5H/Kdzy/g2byCeqvDk2sCisQOxGj5I5bVrfJHSVsTQhoT8McgdZvq5
         bhX63NrkgKZfvdvkXnM5mTPSYAaKisMXIJWHJD3C/YjVdP1G06RFpOav89HNHnf5SzIV
         xqSxzovN8x+Rbat4l+BMH2Hva8pPC1IBMGFBoqEoU8aVYmp7PaUBGOVUD1swVviqjBbf
         TziS0YZU46a9vIIqzpkHLdjGLMVrWGcTxHkgpLOKF8V1WxXr4ha+tZ0dTEe/QkknwnYd
         7qc2DiDLE/QbMSMcEdhn+5xAGHoFSjmKPQckgEabMy6mM7Bzzb99RbbNay//tsMQvrah
         fFIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ8ei5bhhuPF4GulWfHXhfsRrFlujQlI8bnp5hCewBvckSw4DBs
	J+K9/oujYHuRm5T98/M0CcA=
X-Google-Smtp-Source: APiQypLr5hnfDX/z+wvpN6Mb5e6vkyUYP5CD/E1aLgJk2pVS3h2kxjaDMkBzVATveovWs/swa6S+Hg==
X-Received: by 2002:ac5:c4cd:: with SMTP id a13mr9504546vkl.15.1589164281279;
        Sun, 10 May 2020 19:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2992:: with SMTP id u18ls581278uap.8.gmail; Sun, 10 May
 2020 19:31:20 -0700 (PDT)
X-Received: by 2002:a9f:2065:: with SMTP id 92mr8969055uam.33.1589164280855;
        Sun, 10 May 2020 19:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589164280; cv=none;
        d=google.com; s=arc-20160816;
        b=UrdR5fxC+ZC4bKAg94aG2hXmhNl/pPu+dMHz24SEmVqNKsphYz9VgM0KsAOojQHspG
         ghXb+RLsmrP5BM0lCHNggAtnWB8/FeNNoTPokwAAXPG7LVSmj3KrPNtzNSdFjyxos8n/
         YRhuPd5NqXiQsrAf93pO0os9QkqoFT8NtptyyQaw2hl/i2sLxM/hYgUBH51pQGhXa/00
         qUT0XkfUc474Nos0ioftnys8rMLuAwNDx5ZvJzHBVzVsOLTuv5NR9iZEuJ0RlsdKgsI6
         Prblou9Fihr6/EKB5xZR8lgJOnMDG839Re7MPJIBuf+H9PU/dnpwqKrgZ1ch952N56km
         spTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YtnofhKrp6VKNNkt1aec9PQCdva125/vHWFsb6tBfsY=;
        b=Io5jjg5/6qebqoGexi61skQXUI5lHN45soMr0TSkS2lZb8l382+S4LJKRtNmVgmOxi
         yJzEBSQ44emGkkwNq9PZLoGIdewbuWm1hd4rQPbQzu8r4k3Ysvrg66yrTLYXVWYNWNo3
         DID/8lMPcirs9nRpjKHpozX6RkTK1iQW1na4V3w46MrOmk2pro2GTTBzuwOK70nHaIzu
         fUxzXw9AfU6w6/rURX6AM9bgh+aMKWaxVIAK+tYQLUMuYAsdqHd0c+E2Tnh2GdDE4KFX
         Nn1qLxKf4PkJlAomHh/Q8iirCId6vJjB7hcL0ejmmxkHCNdzMatKpKbf3v4QcMcSis1i
         SX1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="Xk/Gft7g";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id i18si670102vka.5.2020.05.10.19.31.19
        for <kasan-dev@googlegroups.com>;
        Sun, 10 May 2020 19:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4d0635ef7d954ad49f852b83bb9fc77d-20200511
X-UUID: 4d0635ef7d954ad49f852b83bb9fc77d-20200511
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1341370935; Mon, 11 May 2020 10:31:14 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 10:31:12 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 10:31:12 +0800
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
Subject: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
Date: Mon, 11 May 2020 10:31:11 +0800
Message-ID: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="Xk/Gft7g";       spf=pass
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

This feature will record first and last call_rcu() call stack and
print two call_rcu() call stack in KASAN report.

When call_rcu() is called, we store the call_rcu() call stack into
slub alloc meta-data, so that KASAN report can print rcu stack.

It doesn't increase the cost of memory consumption. Because we don't
enlarge struct kasan_alloc_meta size.
- add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
- remove free track from kasan_alloc_meta, size is 8 bytes.

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
 kernel/rcu/tree.c     |  3 +++
 lib/Kconfig.kasan     |  2 ++
 mm/kasan/common.c     |  4 ++--
 mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
 mm/kasan/kasan.h      | 19 +++++++++++++++++++
 mm/kasan/report.c     | 21 +++++++++++++++++----
 7 files changed, 74 insertions(+), 6 deletions(-)

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
index 06548e2ebb72..de872b6cc261 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -57,6 +57,7 @@
 #include <linux/slab.h>
 #include <linux/sched/isolation.h>
 #include <linux/sched/clock.h>
+#include <linux/kasan.h>
 #include "../time/tick-internal.h"
 
 #include "tree.h"
@@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
 		trace_rcu_callback(rcu_state.name, head,
 				   rcu_segcblist_n_cbs(&rdp->cblist));
 
+	kasan_record_aux_stack(head);
+
 	/* Go handle any RCU core processing required. */
 	if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
 	    unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..56a89291f1cc 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -58,6 +58,8 @@ config KASAN_GENERIC
 	  For better error detection enable CONFIG_STACKTRACE.
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
+	  Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
+	  call stack. It doesn't increase the cost of memory consumption.
 
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
index 56ff8885fe2e..b86880c338e2 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
+	if (!alloc_info->rcu_stack[0])
+		/* record first call_rcu() call stack */
+		alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
+	else
+		/* record last call_rcu() call stack */
+		alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
+						u8 idx)
+{
+	return container_of(&alloc_info->rcu_stack[idx],
+						struct kasan_track, stack);
+}
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..1cc1fb7b0de3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -96,15 +96,28 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_GENERIC
+#define SIZEOF_PTR sizeof(void *)
+#define KASAN_NR_RCU_CALL_STACKS 2
+#else /* CONFIG_KASAN_GENERIC */
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
 #endif
+#endif /* CONFIG_KASAN_GENERIC */
 
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
+	 * The free stack is stored into freed object.
+	 */
+	depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
+#else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
+#endif
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
@@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 
 struct page *kasan_addr_to_page(const void *addr);
 
+depot_stack_handle_t kasan_save_stack(gfp_t flags);
+
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
 void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
+struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
+			u8 idx);
 #else
 static inline void quarantine_put(struct kasan_free_meta *info,
 				struct kmem_cache *cache) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
+static inline struct kasan_track *kasan_get_aux_stack(
+			struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
 #endif
 
 #ifdef CONFIG_KASAN_SW_TAGS
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 80f23c9da6b0..f16a1a210815 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
 	kasan_enable_current();
 }
 
-static void print_track(struct kasan_track *track, const char *prefix)
+static void print_track(struct kasan_track *track, const char *prefix,
+						bool is_callrcu)
 {
-	pr_err("%s by task %u:\n", prefix, track->pid);
+	if (is_callrcu)
+		pr_err("%s:\n", prefix);
+	else
+		pr_err("%s by task %u:\n", prefix, track->pid);
 	if (track->stack) {
 		unsigned long *entries;
 		unsigned int nr_entries;
@@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
 	if (cache->flags & SLAB_KASAN) {
 		struct kasan_track *free_track;
 
-		print_track(&alloc_info->alloc_track, "Allocated");
+		print_track(&alloc_info->alloc_track, "Allocated", false);
 		pr_err("\n");
 		free_track = kasan_get_free_track(cache, object, tag);
-		print_track(free_track, "Freed");
+		print_track(free_track, "Freed", false);
 		pr_err("\n");
+
+		if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+			free_track = kasan_get_aux_stack(alloc_info, 0);
+			print_track(free_track, "First call_rcu() call stack", true);
+			pr_err("\n");
+			free_track = kasan_get_aux_stack(alloc_info, 1);
+			print_track(free_track, "Last call_rcu() call stack", true);
+			pr_err("\n");
+		}
 	}
 
 	describe_object_addr(cache, object, addr);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023111.15310-1-walter-zh.wu%40mediatek.com.
