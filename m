Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRMGRX3AKGQE7H4CZRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB2071D8D8E
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 04:24:06 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id mt16sf1361382pjb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:24:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589855045; cv=pass;
        d=google.com; s=arc-20160816;
        b=IOPR5mDlO4k1dEoHHqyiDLK4P9mpz+RjE/edMAM8ub6JO4I402PphZTpd4WUtFhn0Q
         XAjIGVGGyJSMNRE6QPVZGDkrH/Kwc9WNTUH+aGNrNuMqa7N3MNzvIX6bhB0k+TGaUQ58
         yHh1M9SOOdgt20HwzuqgiKO3uTFCN7ka5k7XMkwtAi9P+ShyCrh/53JNKLSRkrFcYJp9
         kb/Av1D4nGjBZMEzmM1MfVsc2g8IRNmuKpQgQ5aeM5mGqi0bKzYic8iUGsqb9pKKrA+n
         z+RY+z71XJhcwCqtgPqJDZPmeCqLllDNMnqEpWeU3KIoeqCdeiWCGYzuoUQJkUVJH0t8
         O6qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SLU942GZmCUbf/xEtPPqB6Flftcego6rADC/gLg/2/I=;
        b=u6dPPL6p813rFWSAfVnWmiM+Y+NKWglsP0MR1RjaGwENBdecKX3XG5S6UswEqVxPzi
         k1PxCyTlLtNB1py+04eFxycH1xQf44QOcHdffi4RM9rNe20Hkm/Ry0m+NECLzXh+iKmE
         aMdoSSeXEKbKyRKMBOSvSUFm0trQp/qJcTGSY75+z0eNaZZMeibfDVQDUc7/cZXYVr7X
         lQNHNu8v3HvHwRAnZIqD0GIL+uwxnXPfw99thjL6ojuAw4RmHySm0zg5xcccGbR6aSIy
         rnXUpZ6vF5h2nbdlAvMJl4/iHXqi+PD9ORks6jqHKnjdVacWmjhJQS3TDqAtCS5BeuBm
         1IjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=huLSRbgg;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SLU942GZmCUbf/xEtPPqB6Flftcego6rADC/gLg/2/I=;
        b=q1iTkGZ40dtIEG9OMl3eSiHAg5duA0yKqn1rOPK0LUy2QMhRfsaQYoeUKQrx4dKrQs
         39wo9eRdcxIbQRaLzKuni5As4hMDrfg2b9OdcwpI6iHN7wMfuuUKHw5CivlPqYJUwPiF
         81GqlOo/y0t2P00+gVA9UKy5PDC9xx0b3qgUZefas/a23Flhtkq/cSdwUUSMe7PUmwi9
         LsjLU7wY0JzRCBgnlX77zd7XQFYjtE16xUaECBuqFqAdrp6wxIBVnby+f3N5mwvmYPVg
         zrToaIaDjKqKDV0EsuO+YUNR9WqATEjeKNTN75wGUsJsUv9tB8mR+GbMCQJkCCMW5fe1
         l0xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SLU942GZmCUbf/xEtPPqB6Flftcego6rADC/gLg/2/I=;
        b=kS0mA4wIbU/b0QCWvoBPVEGrqgo/570Xq89OZuYCjsDIOBxPh9ix+vWCfIJ7umJuPt
         owoNpg/rTqn6MuHzwyuHk6OKWqoloG7nGJf6U4rulvoG/H5jhJAP+H3vEjTbTRcKV7I5
         8/gHKEbudiZycvVlZTahYkJHsLcQnONmXnslXoTkTvy9wtluaYuqUomabiRtBMGOiW89
         YGksG4gf0RyV8IR5TMmc78To0dUSDdXbKF1EayJTzPGcbLKIIiPznvhQAPLoaRDr6JVe
         Xx0iFRySXQl4f4oac2hQVUJFdqb/F3H7hKLh6oytqCXKK/DQ+aLg2+kxajPCga2e3XV5
         azIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mUO4K5DT8xGvfwFyRfHs32WwV88ciiXzBwL0lPrvQTslbr1sl
	glOGWnVJBrTZWk7RiU9uA4w=
X-Google-Smtp-Source: ABdhPJyGOO5QgkmWuXLsvcL2HmvoR9m6/uLuWUx1pnVjiL0ZCzg0te6QOS86bluk56FVDtxCuLjoRQ==
X-Received: by 2002:a63:190a:: with SMTP id z10mr17003712pgl.331.1589855045232;
        Mon, 18 May 2020 19:24:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fc8e:: with SMTP id e136ls1308897pfh.7.gmail; Mon, 18
 May 2020 19:24:04 -0700 (PDT)
X-Received: by 2002:aa7:9252:: with SMTP id 18mr19979466pfp.17.1589855044797;
        Mon, 18 May 2020 19:24:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589855044; cv=none;
        d=google.com; s=arc-20160816;
        b=PM48B9ETzJPBI7QbGO6Trpzc0ClDog04/UBihkzgxbB1+71JKdH9wIO/8rkxkck20e
         PQM1W/QjtUIzYxyo9y9qNDFSLmSIOf10f2u3YbevgaLs5Vk1dmiaenT3a7qYQJ0OYg9b
         Dqj60RzNCon20Gl3uBk4f6/Y8p/wPYb6mVLyh16hCxcbNzpU2Fxm5W2rSRhZ/7L4Q0sW
         4zbx7TI/rW257umhoW7lk9HTrUKSssTgPDizwtRhPBzXr7guNw+uPSoaewHizjRwMC7E
         farjrE3utGEEhzCE+f7VJeDyyRb+esw/4NOTGzmtu8PjYJ3OUNDNJwm2t7dp4CIMjmEs
         m6vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lZEdQ8ioW1/xHKs8HqXHOWda86nayj2lVNOArdxGEpk=;
        b=RgbZUgUONRWVKYfEx8iN60KgfhtzUaEogn8rS2VcrHPHL4TALEtbG79kM/XwnwjU7p
         McYDwQ9LaA4UD3q1k5hOIqAChjYbo2ybiNR28KYolFXUAABgdxTjSDCIKqTS2py0b3e5
         R+wBHThU9YN8KG4knh+hKOT17FFGCc8IzeVvcxxzkGG49xgDkQh7gXTGM9h1dBbL9KKB
         Y0AzCczCdeXGGlZKG4nkwi4w7J7WA6rKYRTYrsGspxVdZxSHt8lOsFQPfZ2FdSNIxdz8
         6/N5KzZN7Lyvn7L9qio3J6ZV4k2j0CkOOJOUPCH44D869LA4MGOQF38wNTOCIeYxWB6v
         3TnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=huLSRbgg;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c15si118532pjv.1.2020.05.18.19.24.04
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 19:24:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: cef27ef7a3ae4a26904200c6bd5d0a8e-20200519
X-UUID: cef27ef7a3ae4a26904200c6bd5d0a8e-20200519
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 550651254; Tue, 19 May 2020 10:24:02 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 19 May 2020 10:24:00 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 May 2020 10:23:59 +0800
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
Subject: [PATCH v4 1/4] rcu/kasan: record and print call_rcu() call stack
Date: Tue, 19 May 2020 10:23:59 +0800
Message-ID: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=huLSRbgg;       spf=pass
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
 mm/kasan/generic.c    | 19 +++++++++++++++++++
 mm/kasan/kasan.h      | 10 ++++++++++
 mm/kasan/report.c     | 24 ++++++++++++++++++++++++
 7 files changed, 61 insertions(+), 2 deletions(-)

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
index 56ff8885fe2e..3372bdcaf92a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -325,3 +325,22 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
+	/* record the last two call_rcu() call stacks */
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
index 80f23c9da6b0..6f8f2bf8f53b 100644
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
+		if (alloc_info->aux_stack[0]) {
+			pr_err("Last one call_rcu() call stack:\n");
+			print_stack(alloc_info->aux_stack[0]);
+			pr_err("\n");
+		}
+		if (alloc_info->aux_stack[1]) {
+			pr_err("Second to last call_rcu() call stack:\n");
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022359.24115-1-walter-zh.wu%40mediatek.com.
