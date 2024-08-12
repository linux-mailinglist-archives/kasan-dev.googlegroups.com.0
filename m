Return-Path: <kasan-dev+bncBAABBEVY462QMGQEDCTDQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B24D94EA5A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 11:55:32 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6b78bafb7eesf63396016d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 02:55:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723456531; cv=pass;
        d=google.com; s=arc-20160816;
        b=PwDEWjE35kPMYyRsST+aQao7o4AsJEVAJqYdsnaoVDrardVyBf8LKVOQ+2NaNAGb3R
         vOKM8tCyb9y+mC/NpBR/27okq0kkqldaMiozzDO98/mIsQrWmxnbZ7Z1vPc9dP4XjJ3G
         DRqIyM3xXPJ8SriZGcmfowiJkWHptnBh+RJvrjvnuDQxFg7NRxde3YB378kUGnpf3mdK
         uwEYvrPJHS0sxVOqUsXzmX5150R6AduUA0tGMTpvG5L6ImzrApOH/MwASHUu6bDAVd8a
         5DWlNlNS6XNOKy2ofu7OivliwBj/jFf9m4UygDXmAWtIGBxL58GgsdiYrIKqcj2O6DEi
         +WMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=0AV2dxaNtJmiTjiFByBSJjuZ6oAwyeqUus0N+NejP4A=;
        fh=IgFH8ePYTsSh6aQy0A2Znww4Pp+IiXy0348p2N/AAGg=;
        b=AizUl0RNmJHHQe1sdAFwYQ5NGtgOvixfdZrkAHufCZUo3rKcqBcP1WtXK708Bng7f7
         O7IeXydkHe2kVmZ1iQ7puIQXnc91fjkzBwb9SRk8iDfMCpnwAiacE5OQxpyYTTV8Qptm
         zihYKvPzXa5jZlqNRnjoslKguTlZh+UcfA5mXQZWsqxEldJGNEENnzZuN/IMT3r0eUTE
         knjnUD0kN254RmnMbEbHL5w3dHsr6X1UAO/H8gCSzMODf0LOfWo5rEn8P4eht7bMmzDR
         0Y9SfUNAo55sAdM3F0k3CKPrpL/Zm1cuop73oWVgcdml0qGZPEDW6UsvwWXlecIZyzZE
         NPxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=IUNA8MZf;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.100 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723456531; x=1724061331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0AV2dxaNtJmiTjiFByBSJjuZ6oAwyeqUus0N+NejP4A=;
        b=XGgQMmAEGakKkopZc6NUozOx+MykMbsOAyj8XhKXNQgiBju5J+m1QEGbgUTtLDP9aC
         FOQjGJQHxzMPTMOVJlc7uJtklpjKfv+HM2rGpK7aYQS/I5QpVIogMbq+PCdBjsFeH0LG
         5lV5wx1qbRcpZ5XMcvbRc+HAcTx4yhkp4ExOcM3IPxuz32OjXjRxxtVEVTA7iRjgwzyg
         fN1ReLp/OstBv1NffF1s0gWBhqv9XFfiFEbIJIML8FCkrfQdyJVAD5W6Me8UtapaLAS4
         ZOemXsVBjTbxDCRNWucGNweZ3keWNmQvBx+CWy4SAw2uIQRrnHpvrb5OR+BFyljgzFzu
         MWbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723456531; x=1724061331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0AV2dxaNtJmiTjiFByBSJjuZ6oAwyeqUus0N+NejP4A=;
        b=B+9SUY+miXlcXykPnIU+bLowTwGSjaPgEDM4oqmWS0qiQxcvdYo+DKeDBsOLUqhsKW
         xOTBZHMIcSyj+pHSIJ1aFwxBec8pWmQT5Z5f2x/zuuJg4exmuWWvr99M5U8ybrcbPvf/
         Dfw8GD4qQ9uX4okg3x4jwe7lCQjiMd0goK7E1xD7paHJ7jFDy3+C2GkH+hvyZ4shwcPq
         uAtFMIq2MCzKxOE2A33duFoa8ZbOrtOhSzT7UvqIR12y+k5I9b3T3v0MPETZ5aaSyi7y
         mVTtJdPFqcZ5c9XuIINFjcRvK0donPk8IkjP+2MDBR0bYU6sf4BBVIbkL6XpYl2RMrjh
         ni1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlI9dwoMCwwXpMXqWU1zlTU6oE8gGfoEa024iPY/wDIoiNvowNvEmH/yhO2Tgwn67E4GivRwcfpqdfVviD/nnpQJ5pMPZPSQ==
X-Gm-Message-State: AOJu0YwcIwwxQbXv69o2v2GNn+OuliETBb2WR534C7rNlk5yVBPQzlxf
	1a1DtwEaeXTBe6gOishqfVX+jgTVQWqmL+h+SDyCPEZ86PDrzCfd
X-Google-Smtp-Source: AGHT+IEbLEK6QlmQ/vuVvngT6dCq0et6xqCZd1ENae3exZpVabSGlwHeXyiI5V/hnT6b1NFj/P4kYQ==
X-Received: by 2002:a05:6214:3187:b0:6b7:ad32:3815 with SMTP id 6a1803df08f44-6bd78de66e6mr88935286d6.14.1723456530503;
        Mon, 12 Aug 2024 02:55:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c62:b0:6bd:735f:a70e with SMTP id
 6a1803df08f44-6bd735fa84bls75981086d6.0.-pod-prod-06-us; Mon, 12 Aug 2024
 02:55:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4Qfoln7zIK4ItnDkylAgjbC9WYdCtYmlFl/Q/UvxKBeyKIePoPBEwmLeii6kmDyTN4KbV4VBDNwU6mfUwOVdKhi777ZnNizZMOQ==
X-Received: by 2002:a05:6122:3bd1:b0:4ef:6870:ff5 with SMTP id 71dfb90a1353d-4f912e7457dmr10416031e0c.5.1723456529767;
        Mon, 12 Aug 2024 02:55:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723456529; cv=none;
        d=google.com; s=arc-20160816;
        b=giU+3NDDDgcJQooGPPzAPdPJGAxDHodsBIZJDjpfmpD9I0Xhcin0BX/puC1GvdjKxP
         dWt/gKTHDbWoBoTtEzY0Ewsq1FQudefput9AzUFQLDf9t/mI7nSrtYgIhzA6ILkWFjq6
         OVkiXBBrmQqA6fyZ4JOrBERJqx62VF5hq19zKpDmXtbST3Vewtv+yiodYtaQS/kTKqiO
         kmHRskgIke8XEWnubRvmZDFINaWprO5TPTB2PJ7BCUWqbXNiuI5IBfuiBn8LHYcoOqku
         ZWG5kT93GFT1ixPP2NSHuJubOmbIn1/w9T3ilP2sAepvrwch16F6g2EyulHOa4C1gfnd
         iZDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=nZqkS7Z96TWLWnJVjQ8HLYQ0F4DVw3Kyu1YxwZNjc/M=;
        fh=gPi/2oxM2UGfw61dG72WKf9VSdsdEJ9vFaV8WPJqE4Q=;
        b=lCi/cG04TqJqnTzDoaycB8IDrztAnktK3lILEpr3KtJZHpwPmfsOzceXcVt/xP/fuI
         mw0E0YIZX+KOOXJr/F12LSaNBsmNGcT8vBljfZvOb8Fw3gc/PxmalbTnTW8GWznpD2Bf
         41Fo46jdrZI8++k0qW3WrnwoAh3Kt7dVtaxPqOA5WgjCHp7QqdZbbgsYA2VZCiF/kjYu
         9l+0gUcHA7L5NkvyFvbSol/4A2m0CoQ8eoGpuHNR3lyUvnE9LK72cf3yxmU8pGqUsmZ6
         JDlZWNMwkeENGTjSaU/QVGUQ/yKliBFJSTR43N6eWa3B+/xQfoMRPb/aZHS8rdMtWF0E
         Zgcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=IUNA8MZf;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.100 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out30-100.freemail.mail.aliyun.com (out30-100.freemail.mail.aliyun.com. [115.124.30.100])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f91f1193e8si167974e0c.0.2024.08.12.02.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 02:55:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.100 as permitted sender) client-ip=115.124.30.100;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0WChYhe1_1723456517)
          by smtp.aliyun-inc.com;
          Mon, 12 Aug 2024 17:55:23 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v2] kfence: Save freeing stack trace at calling time instead of freeing time
Date: Mon, 12 Aug 2024 17:55:17 +0800
Message-Id: <20240812095517.2357-1-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b=IUNA8MZf;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates
 115.124.30.100 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Content-Type: text/plain; charset="UTF-8"
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

For kmem_cache with SLAB_TYPESAFE_BY_RCU, the freeing trace stack at
calling kmem_cache_free() is more useful. While the following stack is
meaningless and provides no help:
  freed by task 46 on cpu 0 at 656.840729s:
   rcu_do_batch+0x1ab/0x540
   nocb_cb_wait+0x8f/0x260
   rcu_nocb_cb_kthread+0x25/0x80
   kthread+0xd2/0x100
   ret_from_fork+0x34/0x50
   ret_from_fork_asm+0x1a/0x30

Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
---
v2:
Rename and inline tiny helper kfence_obj_allocated().
Improve code style and comments.

v1: https://lore.kernel.org/all/20240812065947.6104-1-dtcccc@linux.alibaba.com/
---
 mm/kfence/core.c   | 39 +++++++++++++++++++++++++++++----------
 mm/kfence/kfence.h |  1 +
 mm/kfence/report.c |  7 ++++---
 3 files changed, 34 insertions(+), 13 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c3ef7eb8d4dc..67fc321db79b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -273,6 +273,13 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
 	return pageaddr;
 }
 
+static inline bool kfence_obj_allocated(const struct kfence_metadata *meta)
+{
+	enum kfence_object_state state = READ_ONCE(meta->state);
+
+	return state == KFENCE_OBJECT_ALLOCATED || state == KFENCE_OBJECT_RCU_FREEING;
+}
+
 /*
  * Update the object's metadata state, including updating the alloc/free stacks
  * depending on the state transition.
@@ -282,10 +289,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 		      unsigned long *stack_entries, size_t num_stack_entries)
 {
 	struct kfence_track *track =
-		next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;
+		next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
 
 	lockdep_assert_held(&meta->lock);
 
+	/* Stack has been saved when calling rcu, skip. */
+	if (READ_ONCE(meta->state) == KFENCE_OBJECT_RCU_FREEING)
+		goto out;
+
 	if (stack_entries) {
 		memcpy(track->stack_entries, stack_entries,
 		       num_stack_entries * sizeof(stack_entries[0]));
@@ -301,6 +312,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	track->cpu = raw_smp_processor_id();
 	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
 
+out:
 	/*
 	 * Pairs with READ_ONCE() in
 	 *	kfence_shutdown_cache(),
@@ -506,7 +518,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 
 	raw_spin_lock_irqsave(&meta->lock, flags);
 
-	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
+	if (!kfence_obj_allocated(meta) || meta->addr != (unsigned long)addr) {
 		/* Invalid or double-free, bail out. */
 		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
 		kfence_report_error((unsigned long)addr, false, NULL, meta,
@@ -784,7 +796,7 @@ static void kfence_check_all_canary(void)
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
-		if (meta->state == KFENCE_OBJECT_ALLOCATED)
+		if (kfence_obj_allocated(meta))
 			check_canary(meta);
 	}
 }
@@ -1010,12 +1022,11 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 		 * the lock will not help, as different critical section
 		 * serialization will have the same outcome.
 		 */
-		if (READ_ONCE(meta->cache) != s ||
-		    READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
+		if (READ_ONCE(meta->cache) != s || !kfence_obj_allocated(meta))
 			continue;
 
 		raw_spin_lock_irqsave(&meta->lock, flags);
-		in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
+		in_use = meta->cache == s && kfence_obj_allocated(meta);
 		raw_spin_unlock_irqrestore(&meta->lock, flags);
 
 		if (in_use) {
@@ -1160,11 +1171,19 @@ void __kfence_free(void *addr)
 	 * the object, as the object page may be recycled for other-typed
 	 * objects once it has been freed. meta->cache may be NULL if the cache
 	 * was destroyed.
+	 * Save the stack trace here so that reports show where the user freed
+	 * the object.
 	 */
-	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
+	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU))) {
+		unsigned long flags;
+
+		raw_spin_lock_irqsave(&meta->lock, flags);
+		metadata_update_state(meta, KFENCE_OBJECT_RCU_FREEING, NULL, 0);
+		raw_spin_unlock_irqrestore(&meta->lock, flags);
 		call_rcu(&meta->rcu_head, rcu_guarded_free);
-	else
+	} else {
 		kfence_guarded_free(addr, meta, false);
+	}
 }
 
 bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
@@ -1188,14 +1207,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		int distance = 0;
 
 		meta = addr_to_metadata(addr - PAGE_SIZE);
-		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+		if (meta && kfence_obj_allocated(meta)) {
 			to_report = meta;
 			/* Data race ok; distance calculation approximate. */
 			distance = addr - data_race(meta->addr + meta->size);
 		}
 
 		meta = addr_to_metadata(addr + PAGE_SIZE);
-		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+		if (meta && kfence_obj_allocated(meta)) {
 			/* Data race ok; distance calculation approximate. */
 			if (!to_report || distance > data_race(meta->addr) - addr)
 				to_report = meta;
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index db87a05047bd..dfba5ea06b01 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -38,6 +38,7 @@
 enum kfence_object_state {
 	KFENCE_OBJECT_UNUSED,		/* Object is unused. */
 	KFENCE_OBJECT_ALLOCATED,	/* Object is currently allocated. */
+	KFENCE_OBJECT_RCU_FREEING,	/* Object was allocated, and then being freed by rcu. */
 	KFENCE_OBJECT_FREED,		/* Object was allocated, and then freed. */
 };
 
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 73a6fe42845a..451991a3a8f2 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -114,7 +114,8 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
 
 	/* Timestamp matches printk timestamp format. */
 	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
-		       show_alloc ? "allocated" : "freed", track->pid,
+		       show_alloc ? "allocated" : meta->state == KFENCE_OBJECT_RCU_FREEING ?
+		       "rcu freeing" : "freed", track->pid,
 		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
 		       (unsigned long)interval_nsec, rem_interval_nsec / 1000);
 
@@ -149,7 +150,7 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
 
 	kfence_print_stack(seq, meta, true);
 
-	if (meta->state == KFENCE_OBJECT_FREED) {
+	if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING) {
 		seq_con_printf(seq, "\n");
 		kfence_print_stack(seq, meta, false);
 	}
@@ -318,7 +319,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 	kpp->kp_slab_cache = meta->cache;
 	kpp->kp_objp = (void *)meta->addr;
 	kfence_to_kp_stack(&meta->alloc_track, kpp->kp_stack);
-	if (meta->state == KFENCE_OBJECT_FREED)
+	if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING)
 		kfence_to_kp_stack(&meta->free_track, kpp->kp_free_stack);
 	/* get_stack_skipnr() ensures the first entry is outside allocator. */
 	kpp->kp_ret = kpp->kp_stack[0];
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812095517.2357-1-dtcccc%40linux.alibaba.com.
