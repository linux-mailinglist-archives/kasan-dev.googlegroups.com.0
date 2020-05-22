Return-Path: <kasan-dev+bncBDGPTM5BQUDRBY7ETT3AKGQEYM35S3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31FA71DDCEB
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 04:01:08 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id k20sf3746950vke.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 19:01:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590112867; cv=pass;
        d=google.com; s=arc-20160816;
        b=s28Y5SNwGXpfneZ9kphf+1NxivAq3Ocel7ll5thmJYhJE+gH04O+B6uefCsjWrSYjQ
         WH8V0gH1Eb6+yJPXT1q7SLcPMF3SsiWJM4QUXafGOPFHVh/zllbc1fnZXvhbG+QNPg9d
         FmRAm/W5UpirVRpC5jjPgBKwjRSh24sAnp+NTjDYvfFg4Q8zJ914Xko2Rt6FX9Oyum5/
         sPWhziKoYqLYouSGZNhHn4LROHzuKVYEv6lJNNcweu1qSWKN7karv6Jq5xbtTIc+mI1X
         syMEuFeCUQHAEoJyTocKtYu4r/riTcP7vkspPK72Ke69Hb+xrmsSv3bx3YLcmrsWZCDC
         8zgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3cBNT4x7/Q7zUtPwv9SG0Pa2vHrjrNHqdkP1vPAS7M0=;
        b=EyyDYOHuXSSfCKSHIrskmL1ZJEnLZNao298HxJueVHigPAW4k509n6oD266Xb0hhSI
         zoSQEl20JsbnkwT1PAy1AwErm5rguN3OoDxNnNdv7oudSbE2k9RUkUTJDsS7iK4N+Pdx
         E4P3hegkceVQTwHgjjx+q4Mjx9jwRmQLE0dlIIW6P72HV4lcfV/X/4vHEQk9OmFCrDvP
         3/lOoNO0M4eayeCGWU03eWesUtYmHtRGIF4pLSdc754Q6b+v0M9QJNf4SK1QzxB81tBy
         e9hFpfa+vONQj6z4qrDsCJujvhY9leAkh+2DwxSkxZsUiG84lC2mg4KhVmEJbRCJbozo
         4MwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LoLmQVuP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3cBNT4x7/Q7zUtPwv9SG0Pa2vHrjrNHqdkP1vPAS7M0=;
        b=lBhZPb7PUISlo/gu9HdTFTFPydPIks1Tvc172Iz5tELeiJSUia7jZ7ltbZ72psy3Qn
         G3lGmsUes+hiGTJERZhV57dKppflfDUjFCxx7rYScX3m+nIdEzbQyH4aC1+A6qHhewKq
         Dev/4Nwf4VrQvyYqhSVxEeoE75Lx8SGWF+YD7jfqn7lKezSOZug8slSl3l8KVlorQCi7
         1WoWjToZuFPNOUpSThML12rcFpjMQLn4F5Yfn0xllWXcf4Hr149VavOciWzNrtMd7PA6
         p9OqDds546S62/VIRzPuKvn/QUOq+Vlb1ubA5QB8jCkfy6G2rW3ezQ+FqBNFAxQ99hlx
         ZHLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3cBNT4x7/Q7zUtPwv9SG0Pa2vHrjrNHqdkP1vPAS7M0=;
        b=kKTlJOY8Vy41czLOcL7LLhNr8ZppVCcIH50ZpksNOQDqixvUzxuXhLvOhXB81lvwan
         /8/9k08AAHjMl3CKO1hkawymXen2QOSotrevdHIzBSkf+iA5vCACfhcMV0TZbpXCq9U9
         LEyV93MYK26mc2jcBsMqZ1I4wSOm1MNIqfduU1K6O2t/+pYVj/K5sfOb6eHu7tXXqZDm
         5Kwpd+4dQKVYsl88rP9fjoF4SSXK/fjDh2Xxm+MqHENMmF8eMW1UCmkhiF/r9I7t4GJM
         Hc0QUubbDREj5SmUd8iVYUPyynPU91mbheGEGDJ8zwOVbKiNKWwoP8EaPht3VCATnTJI
         keyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531C91QkPnz2yZi+586rf7ZSfxDR7x5DCdVQwI/wLn8vipU4bv4r
	EI8asEEP52oFd2IMggu7ymM=
X-Google-Smtp-Source: ABdhPJwz705PgZO8H3+dPFBELNd/S4xbBofepoWpNCn9MawO58F5jj8tad3bNo06ccoMoCpLydnUcw==
X-Received: by 2002:a1f:9b92:: with SMTP id d140mr9388462vke.82.1590112867173;
        Thu, 21 May 2020 19:01:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:bd15:: with SMTP id y21ls59077vsq.2.gmail; Thu, 21 May
 2020 19:01:06 -0700 (PDT)
X-Received: by 2002:a67:f893:: with SMTP id h19mr9391211vso.178.1590112866614;
        Thu, 21 May 2020 19:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590112866; cv=none;
        d=google.com; s=arc-20160816;
        b=iOHAvelK3ImA8CpGczRG0P/EHsPj7dnRltUdm3cWmrgxXsrP30h/1b9IlUkBzLj4ox
         z0qid6jWz+EYbOFWANwuvvD+Ep/jCD8gA253pyu/VbIEvxgj+aYfoiabNSJzZXQlK68v
         vFG6xENSU4OXh/NznDZqWMaBVIIOxeCxRzXWjjnLHVU7jEUQL1uQsDXEnqF5qsxAk0Qw
         PrEzg5Fz3d1vBJL1NP7w1PWomAo90/EeuGCq5uzizEtf3VRWa9Y3eDpPxogUycIJN0MO
         LT5RTvHT45h0yyqO7mlT0Pt+iOqCx18JjgjMIHncVviDsSdLOrcAEppSC9DB49GZvLOU
         d0+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kry6DzLo7jc9925L70T8XcjXeiprwsgXtu1B1gyF3lw=;
        b=tGVfasa188zWgZtpsamcqAmBN/iD+UOtGbZSBqtyahvpNphtUiWnqBgvCRgcJ/RFVj
         Az0k4wSCezRXOygYuhf0HSCfhYgL9IaDAaQE8Q7e+dSUX3uJ4Ypyewo32Qfn68dtDOqM
         7B2Jgm7BFbsWvhkeJoaMfx4/B+XQyujCRhmIXwyQ2T4fyVE7VFfHwSYleK5CCghbK/Ew
         gj0acF31128yULSkrvRnfKPH6+cVG2Y/Orm62wTAGdr3GQaWxEDtsUiEqJohRvtQeewX
         wJ8i1P1YagIyPtrftu3b2TPqFK+6jFpiWhufRVMUm0cv2CWOwY6MNs6lka8NxKIcK0bN
         LcbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LoLmQVuP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y77si403187vky.0.2020.05.21.19.01.05
        for <kasan-dev@googlegroups.com>;
        Thu, 21 May 2020 19:01:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9f0f0c40d8e54e41b1d7ff79c117022a-20200522
X-UUID: 9f0f0c40d8e54e41b1d7ff79c117022a-20200522
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 121922522; Fri, 22 May 2020 10:01:02 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 22 May 2020 10:01:00 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 22 May 2020 10:00:59 +0800
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
Subject: [PATCH v6 1/4] rcu/kasan: record and print call_rcu() call stack
Date: Fri, 22 May 2020 10:00:59 +0800
Message-ID: <20200522020059.22332-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 2AC2276E087F6D73DD4AF33E2264B3F334C3BE3B77DDB36EB8CAFEB4B585EE532000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LoLmQVuP;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020059.22332-1-walter-zh.wu%40mediatek.com.
