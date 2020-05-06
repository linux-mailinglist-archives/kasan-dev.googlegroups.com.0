Return-Path: <kasan-dev+bncBDGPTM5BQUDRBPMSZH2QKGQE7A4WYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C80741C675B
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 07:21:02 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id p138sf632226iod.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 22:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588742461; cv=pass;
        d=google.com; s=arc-20160816;
        b=yhHRKcJbgVeCzkdtP2Tz1rkB/OPQb1rvDoWaT3WPE2nbYInbtnQet0quiVstn4WLj0
         eqyif7D1GatoevR1s2VF0lXnGhdc5H2Vl7Oa0/LuNsfMT70Dq4iWd8yO6e78h+Zd8xXQ
         SSTDVJfrOGTKkJ81eVGlVos7FEJc62eod0IqS2Xgc9mF9feqIXECyZ90B6J8ikaoElf/
         BP6mrNFRyYCPvvmBTuaskcMfisBaBrFqVpSYzwKAfaKRfWMqsjAhjdLQlGLkZjM7Zccv
         7+TqoyVWqnhnJvb8gRA14LqQLHaYUAppeXUTiubJiiUsPiyynBto7/3F1Z0S8Tz9vSnK
         U7Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2WqFtZ7X4mP0PvywC6MhCwPXlcRZ6sOGYIMTOO6R+kc=;
        b=d341xQ0PD5Z/XfHFJe8XKhF/gtUvHTtgHipiH2vGE2WvPMJoBkg8n7MPYxjEqJ3tWi
         i0vMxVLNVFsvXowkRIcp4VvH+p+NE50nqYNIj1+9gV/0bKd1KWMKJ+kw7LzBDRZ+Dh5T
         55TS3E2jsZsZauYEQVB2PE6d9BMsQW8yDNEVXrV17wLlVg7ejUVJdlgi4yKh1j6b3e6R
         FOEZFMueuOOoySRBF+9Zhc2yMi0jdji5gneLwd5uCsKokMW5fQwKtHCeOKfauFtT4mCp
         306GCk4220Zex2fxyF2pnQxk8lObYMptyjUvy4mEHj2AcE9Vu818zjpYEQlPQx5sBarY
         VoVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Z7OBg9xi;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2WqFtZ7X4mP0PvywC6MhCwPXlcRZ6sOGYIMTOO6R+kc=;
        b=grHwBsJvg6/rQlVt6sgvZxs9m2OrSk9p95OcW1xzjk2L6Byc8a2Cfhm41nNDO7AFsA
         KjEOL7bqZs+XmlTHcGYj1Nrb3Ns30+qniK8wqlDIbWOiHXnE5p2de/msICI5Ez70YpKI
         ubxrl7EPKChrHGI2jC/UUw3ggf2ugMcCUaCYT74kaYUQ/ZzXfxEhVTMe9d2FlYgx68xn
         N54Rt78FpBu0B+yugSyY7CzONKYc5Ell1AlOQi48eVcvPitqriCp92cMszZ8hg7J2uHx
         AhzSbVwnDbR99vjwS3V0km1a+LPcwBD1FaUjCoYn+wGMvyg+F9bKJJpYiAjM6PjgE/gJ
         q+VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2WqFtZ7X4mP0PvywC6MhCwPXlcRZ6sOGYIMTOO6R+kc=;
        b=XeBJ8jNt9IjAV37DVVVaDefNEXTzIpF9pFiuzsZithOuxJnpRr3qDmW/nH7bfZRRZT
         8zf0/IQNRsaDNYs2eO7K3WOMm8sRjLSy0RP57iqDtqGtoBFYwd966XFXpmMDuYasarQD
         opKjJ+2MCFZ7c1AUr1Onblckn1oyhLQobdukQNtgE9SxEoOe9ETVFuGEg9PCd1Iirroh
         zBWSYecGXWz1enubazBwlLqrQ5nqimurP1RdpyEV7zNEwoQVhITlLVxManB180NP/Wx+
         nI8Yzw8bw574ejKoaS+idzvMIjEDzT23mofI0wx204dvgEjIVJrrBfaFAvWiSmKqTGds
         RPdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PublWfk5zac1aGU5ptPJwSWJLgafTc0caAoiWdES8jjZ4eqjsONC
	g7GJWtNrgL0/7y8Ndwbp1fc=
X-Google-Smtp-Source: APiQypKpu9EhbqB3iW2EJNYHHBORddqG49TWstTqnxf8y/QM580hCQ5KerSeb5/i2ko6X6JhRU6kSw==
X-Received: by 2002:a92:4b10:: with SMTP id m16mr7482448ilg.107.1588742461743;
        Tue, 05 May 2020 22:21:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:80a:: with SMTP id u10ls628139ilm.9.gmail; Tue, 05
 May 2020 22:21:01 -0700 (PDT)
X-Received: by 2002:a92:9a5c:: with SMTP id t89mr7452340ili.267.1588742461405;
        Tue, 05 May 2020 22:21:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588742461; cv=none;
        d=google.com; s=arc-20160816;
        b=leFeaT7lG2K10wNCFNcCU1z8Fnz7zDQ4CnUM8dsC5zNyUtyiUy/PjUDkNK6xAT5vaI
         QA5YFAereKlj9GrLV0eFMRxXBijonuAN/h8NB5cRQ++zj7vNYovJi//gzqjp2/rHxWXo
         JJghCpjRt5VVhCVaB1OHrE9vn7Amp7voCQa2I0uDlK/DsaTh4clk/HtH0B6hvj5RbKzC
         jQCDPsU6dBmh84P1jUhL1DQkyOb44wkmdx+BGt45VNb4/pGh3OuM0j4Tw8VzO+sDwWpk
         buOjBrJ3PTFeSRUJzDmP+bLjHI/cQ6C8ZseeTM8pXVEOGbmVb5Q0Vy4onoZc8obWzqxY
         giUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ETHA4HWY0Hog3Z3ytmN4JoSnKcZh6hg7h8BcVESgFcc=;
        b=MsvFo7DpPaKiJQRNyRBBsD3feBYKmD29kIa4QW2kH41MTifuzkN+Hr90NTUpTPs541
         0sk6M4CmNUR97w+tgtvTqgeJHfB3l7dusu1EB5nT5tXvMVsH3Yec1qvK0ktzOwgjd4IS
         3le9oTVXdNydoQeij5zqInWiD2Mmx4gdVrhpnKl9WYVdFxOJqYU0wepXQV2eYpM3zctE
         H1x2OgxQ+PqvuqIQ9002VQK8ysJJCoPwQ5KoqIWll8VIcEeDNjYdZvVldkpy9kZHRqqd
         xVYyu1kumofL21+3oudyARkTE7vfAAN+mJ8hmCF4NtGYlwpsZ8uL3kuFoRYd70wN1Rv2
         HhhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Z7OBg9xi;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id x4si94441iof.0.2020.05.05.22.21.00
        for <kasan-dev@googlegroups.com>;
        Tue, 05 May 2020 22:21:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 191ea745ffdf44fda16005a881de4ce5-20200506
X-UUID: 191ea745ffdf44fda16005a881de4ce5-20200506
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1905688655; Wed, 06 May 2020 13:20:57 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 13:20:54 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 13:20:54 +0800
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
Subject: [PATCH 1/3] rcu/kasan: record and print call_rcu() call stack
Date: Wed, 6 May 2020 13:20:46 +0800
Message-ID: <20200506052046.14451-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 207E808D1826991DB0A16DB3C4D0C374BC1D58B8654CEFD3C6BB5AFBE7FBB2F42000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Z7OBg9xi;       spf=pass
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

When call_rcu() is called, we store the call_rcu() call stack into
slub alloc meta-data, so that KASAN report prints call_rcu() information.

We add new KASAN_RCU_STACK_RECORD configuration option. It will record
first and last call_rcu() call stack and KASAN report will print two
call_rcu() call stack.

This option doesn't increase the cost of memory consumption. Because
we don't enlarge struct kasan_alloc_meta size.
- add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
- remove free track from kasan_alloc_meta, size is 8 bytes.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

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
 include/linux/kasan.h |  7 +++++++
 kernel/rcu/tree.c     |  4 ++++
 lib/Kconfig.kasan     | 11 +++++++++++
 mm/kasan/common.c     | 23 +++++++++++++++++++++++
 mm/kasan/kasan.h      | 12 ++++++++++++
 mm/kasan/report.c     | 33 +++++++++++++++++++++++++++------
 6 files changed, 84 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 31314ca7c635..5eeece6893cd 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,6 +96,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+void kasan_record_callrcu(void *ptr);
+#else
+static inline void kasan_record_callrcu(void *ptr) {}
+#endif
+
 #else /* CONFIG_KASAN */
 
 static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
@@ -165,6 +171,7 @@ static inline void kasan_remove_zero_shadow(void *start,
 
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_record_callrcu(void *ptr) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index 06548e2ebb72..145c79becf7b 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -57,6 +57,7 @@
 #include <linux/slab.h>
 #include <linux/sched/isolation.h>
 #include <linux/sched/clock.h>
+#include <linux/kasan.h>
 #include "../time/tick-internal.h"
 
 #include "tree.h"
@@ -2694,6 +2695,9 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
 		trace_rcu_callback(rcu_state.name, head,
 				   rcu_segcblist_n_cbs(&rdp->cblist));
 
+	if (IS_ENABLED(CONFIG_KASAN_RCU_STACK_RECORD))
+		kasan_record_callrcu(head);
+
 	/* Go handle any RCU core processing required. */
 	if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
 	    unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..022934049cc2 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -158,6 +158,17 @@ config KASAN_VMALLOC
 	  for KASAN to detect more sorts of errors (and to support vmapped
 	  stacks), but at the cost of higher memory usage.
 
+config KASAN_RCU_STACK_RECORD
+	bool "Record and print call_rcu() call stack"
+	depends on KASAN_GENERIC
+	help
+	  By default, the KASAN report doesn't print call_rcu() call stack.
+	  It is very difficult to analyze memory issues(e.g., use-after-free).
+
+	  Enabling this option will print first and last call_rcu() call stack.
+	  It doesn't enlarge slub alloc meta-data size, so it doesn't increase
+	  the cost of memory consumption.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2906358e42f0..32d422bdf127 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -299,6 +299,29 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 	return (void *)object + cache->kasan_info.free_meta_offset;
 }
 
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+void kasan_record_callrcu(void *addr)
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
+	if (!alloc_info->rcu_free_stack[0])
+		/* record first call_rcu() call stack */
+		alloc_info->rcu_free_stack[0] = save_stack(GFP_NOWAIT);
+	else
+		/* record last call_rcu() call stack */
+		alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
+}
+#endif
 
 static void kasan_set_free_info(struct kmem_cache *cache,
 		void *object, u8 tag)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..adc105b9cd07 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -96,15 +96,27 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+#define BYTES_PER_WORD 4
+#define KASAN_NR_RCU_FREE_STACKS 2
+#else /* CONFIG_KASAN_RCU_STACK_RECORD */
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
 #endif
+#endif /* CONFIG_KASAN_RCU_STACK_RECORD */
 
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+	/* call_rcu() call stack is stored into kasan_alloc_meta.
+	 * free stack is stored into freed object.
+	 */
+	depot_stack_handle_t rcu_free_stack[KASAN_NR_RCU_FREE_STACKS];
+#else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
+#endif
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
 	u8 free_track_idx;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 80f23c9da6b0..7aaccc70b65b 100644
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
@@ -159,8 +163,22 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
+{
+	struct kasan_track free_track;
+
+	free_track.stack  = alloc_info->rcu_free_stack[0];
+	print_track(&free_track, "First call_rcu() call stack", true);
+	pr_err("\n");
+	free_track.stack  = alloc_info->rcu_free_stack[1];
+	print_track(&free_track, "Last call_rcu() call stack", true);
+	pr_err("\n");
+}
+#endif
+
 static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-		void *object, u8 tag)
+		void *object, u8 tag, const void *addr)
 {
 	struct kasan_alloc_meta *alloc_meta;
 	int i = 0;
@@ -187,11 +205,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
 	if (cache->flags & SLAB_KASAN) {
 		struct kasan_track *free_track;
 
-		print_track(&alloc_info->alloc_track, "Allocated");
+		print_track(&alloc_info->alloc_track, "Allocated", false);
 		pr_err("\n");
-		free_track = kasan_get_free_track(cache, object, tag);
-		print_track(free_track, "Freed");
+		free_track = kasan_get_free_track(cache, object, tag, addr);
+		print_track(free_track, "Freed", false);
 		pr_err("\n");
+#ifdef CONFIG_KASAN_RCU_STACK_RECORD
+		kasan_print_rcu_free_stack(alloc_info);
+#endif
 	}
 
 	describe_object_addr(cache, object, addr);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052046.14451-1-walter-zh.wu%40mediatek.com.
