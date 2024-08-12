Return-Path: <kasan-dev+bncBAABB4PF422QMGQEECJKN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id F21AE94E74B
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 09:00:04 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-44febfb1ae4sf63907351cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 00:00:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723446003; cv=pass;
        d=google.com; s=arc-20160816;
        b=xiy2nSgmQdVcVFBPVc33yr+o9dgIs3k0V0LIj3ohFwq2WIDg4Fw+muPTM8DpJejL04
         wp9tXrp8ccKhUubMEumCosdaNxX23+UhFKWE2JGI665QIASYM/fGI2Pn0lWg9aSHk28Q
         SvSSicIetqunHTeIwpYJZANi8jjtFp4TjRIpb7NVBmzNyy+jGL9Lv9qBQcSWSuXUWS3m
         RXxOb8yDSidkQaPFiSZj8K9OfA1iJ2Lxu8Dsy16q0eYt2OKgulyK3NOtSVC/vAf21l4y
         MIi1+qU+KA+RKKALnBHj+ZNAycfxFBvVA9Nybcc55PfSeHJw+j8mHPbXUuRga2SCKhrU
         EFEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KGsekXg0BeYMpQfAavbZZRpMvrONYEr8SqHShSmtOGQ=;
        fh=qOZrJRkBqqvvdp+BMrD+Gg5EICZgvaYxbp4XqrY07Zc=;
        b=TOfiqzURhfy8q62WQUzDEmWks84nVeRGxyvm44kKRlmeUcKY2W4WRoFUIvkC1EuPc5
         4PWOJKEEt0HctXFZr/loO4ICNxvB5QbQTtlhGF5B9cieiw+F0KsIMpwPFweVTIh8oSLx
         kBC0d3sfMGpGpRMDJi3yUokc9QqCe1BzHwc/+QKf3A2oKKxAN5uzCZjhwybniefI6Q+l
         qBl6454JMZExQ/M+e5vmhICbX656ZrReBqKOML4HN/Uel1/PUmFAU8h8fgvP93G4by2P
         FvdatdnRFeBfXEmxOrE9/mmfkyWimcVqI63oSYeEWmTqXcI1E9Efh6D14KY+ZpweKK/4
         pvYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=wRJPCz82;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723446003; x=1724050803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KGsekXg0BeYMpQfAavbZZRpMvrONYEr8SqHShSmtOGQ=;
        b=gad641jpbqn4u+Rae8tAGo6gLjS3dKXosJnHQrLrb5CJZjsemUlL2oAJ6qFOpEEsuY
         EBJcGhc6gun6Y/I38lCflqUhYDUh/BuXb2HcUuWEy4rs2CnFS2yRqO/QJKmN6xvXHJcb
         uowZRwyif5vbpt7vj/kAR4Xbk+kMpYn4HoBnZfUjfk/MryixRgk1Z0/H7SOE7gMf/Gv+
         ad/o08tyfmPSTClvM2YOYRGCRE9YuQl/tAw8kcD7vuGl7OfW/6nkCW+ZPhgOjsUl5iyf
         ySbx5fbr8vNJ0GrLEzT/i4q4jabL+5p0Sfu0ZICWi1EzHCl2Ycxa1IpgpC/ER7kXaFuX
         qQwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723446003; x=1724050803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KGsekXg0BeYMpQfAavbZZRpMvrONYEr8SqHShSmtOGQ=;
        b=OxH/MTRRMdgRDtrflRfnVUiFxalL7pS5Ud9czzJcQosjbOEnDlGnqC5iBHSJtWEBLp
         dMn89M5mY4IHh9nFizuwbseO4ur1idsaofIfSm3JJqVyCJKEh5t03NS88Iwa6Zv9XKmS
         wKqS4Z8fRV9l15AbzEGwF1eTGCmZtnHWtZ7/OiMXEr/3zOTgCngRExoRi4cB1Q/kzr9N
         4K9A9fapCdZ4AEZ5uUPX0UsapoBa0v1bEK0yqSX+h+atfnaTRIDenIU7wc3JV7TarY1m
         0sj8+pzcwuLi+1K1nO2PipPYHvv7qulEAHSDkDZ2b3LieLJ+Doye+NqCmdh1hNsTKxJo
         3PfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdBTnxbLD+frGmaU7fuHKqW6rF/vcofvsUH6aWrav19pDjQtajk43B/iptbRYGDVF4jSWj9w==@lfdr.de
X-Gm-Message-State: AOJu0YwRkc3UveEpNMGSLkB4e8s/s36JCdZa3c9eK+5y/+FOQ8yiVfOx
	bvQr5/cej0bjpcr8WfTA3cER1P9pgFqWVY2h0K1Ydcy8GFcFmwv2
X-Google-Smtp-Source: AGHT+IFGngNN6A2ZGSrXhyXzjqCpBiwL33IhxP6Y2HGFHJIHH9FdzGqXxwQVLNSTZ3HVy6h5+UPehg==
X-Received: by 2002:a05:622a:6115:b0:447:dc7f:f09a with SMTP id d75a77b69052e-453125719fbmr102533121cf.17.1723446002060;
        Mon, 12 Aug 2024 00:00:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:105:b0:447:f206:4e7c with SMTP id
 d75a77b69052e-451d12f64ffls67678911cf.2.-pod-prod-07-us; Mon, 12 Aug 2024
 00:00:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhm5rNpsgpfR1QeP4ws9cvYKSf+PK7IZ6cd4cieILjCSElwLZa5hLKsAzbG3Sp54MvLTNU8fPNtGc=@googlegroups.com
X-Received: by 2002:a05:6122:470b:b0:4ed:145:348f with SMTP id 71dfb90a1353d-4f912ee0aafmr9516246e0c.12.1723446001425;
        Mon, 12 Aug 2024 00:00:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723446001; cv=none;
        d=google.com; s=arc-20160816;
        b=jqokMWQ9fNw0A+baBY+YMHTj0E1HOZ8n+g7tnZuOMGf6V177qMt0B1/YjXVhpYR9Kz
         8dbmEKFqmFlLFqRXfnzj1jgwfOeXuME50KCEA/Z+VVaVyMOX3rUyaDQOIkRN1UmLTtBa
         CFDg0R+/4eAZZsae0XCNWRrpzqeADd7jFMUftrEs7ShSlZEnV1fdTf+nkewQgqiSt0pi
         aD33E0eoN5VnUTVaunl86mlSMlimw5ggWHaBc2+ausWP0FdAzQXdfUYMdVzLAa9hA3v3
         CP21asmdxs2IN7GWuljI5jZeSEgmmc9+ykOgBGpIyBbp3nItoyVjZIkmDPtxcj7kzgTo
         Yz/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2sB5TDcVkqlobWIVqrnBXmc0iuAglrquanWdPCiDDFo=;
        fh=gPi/2oxM2UGfw61dG72WKf9VSdsdEJ9vFaV8WPJqE4Q=;
        b=ZTa7ZrepLfeKyspmVlkT66cctGQM4UPUEnDlLApCUcPIPpa4Bxtb7vhcaT/DSRiet0
         UoBxGUtqErk9lLxiaJoGgAHVwdOYY6ExkRCnyl8Jw59O6nmCxeS1cigT+MQa+eyu+Asc
         IXX0pZ2MpM4SscRsfVXPlnhHa0XizVwx5LWej+vBMHlUqywJlb1Zd4owlq7M2xkliYdl
         AxoCWGihv1f2DfN8kj2OSn2zKpt+HmaPDtLKkIZAoIRBF3Tf0Zo33R9VB+z0L0WKcpkw
         9ZnWymdG1jx5aJozH4lDklMU0/fgLyWPOSUuw1p+8/prmQjRaIxFXTlnEa4u7W5JGFsa
         Qr7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=wRJPCz82;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out30-98.freemail.mail.aliyun.com (out30-98.freemail.mail.aliyun.com. [115.124.30.98])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e1b339si19769985a.7.2024.08.11.23.59.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 00:00:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) client-ip=115.124.30.98;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0WCaX4Nj_1723445987)
          by smtp.aliyun-inc.com;
          Mon, 12 Aug 2024 14:59:55 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: linux-kernel@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH] kfence: Save freeing stack trace at calling time instead of freeing time
Date: Mon, 12 Aug 2024 14:59:47 +0800
Message-Id: <20240812065947.6104-1-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b=wRJPCz82;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates
 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
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
I'm not sure whether we should keep KFENCE_OBJECT_FREED info remained
(maybe the exact free time can be helpful?). But add a new kfence_track
will cost more memory, so I prefer to reuse free_track and drop the info
when when KFENCE_OBJECT_RCU_FREEING -> KFENCE_OBJECT_FREED.
---
 mm/kfence/core.c   | 35 ++++++++++++++++++++++++++---------
 mm/kfence/kfence.h |  1 +
 mm/kfence/report.c |  7 ++++---
 3 files changed, 31 insertions(+), 12 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c5cb54fc696d..89469d4f2d95 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -269,6 +269,13 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
 	return pageaddr;
 }
 
+static bool kfence_obj_inuse(const struct kfence_metadata *meta)
+{
+	enum kfence_object_state state = READ_ONCE(meta->state);
+
+	return state == KFENCE_OBJECT_ALLOCATED || state == KFENCE_OBJECT_RCU_FREEING;
+}
+
 /*
  * Update the object's metadata state, including updating the alloc/free stacks
  * depending on the state transition.
@@ -278,10 +285,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
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
@@ -297,6 +308,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	track->cpu = raw_smp_processor_id();
 	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
 
+out:
 	/*
 	 * Pairs with READ_ONCE() in
 	 *	kfence_shutdown_cache(),
@@ -502,7 +514,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 
 	raw_spin_lock_irqsave(&meta->lock, flags);
 
-	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
+	if (!kfence_obj_inuse(meta) || meta->addr != (unsigned long)addr) {
 		/* Invalid or double-free, bail out. */
 		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
 		kfence_report_error((unsigned long)addr, false, NULL, meta,
@@ -780,7 +792,7 @@ static void kfence_check_all_canary(void)
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
-		if (meta->state == KFENCE_OBJECT_ALLOCATED)
+		if (kfence_obj_inuse(meta))
 			check_canary(meta);
 	}
 }
@@ -1006,12 +1018,11 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 		 * the lock will not help, as different critical section
 		 * serialization will have the same outcome.
 		 */
-		if (READ_ONCE(meta->cache) != s ||
-		    READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
+		if (READ_ONCE(meta->cache) != s || !kfence_obj_inuse(meta))
 			continue;
 
 		raw_spin_lock_irqsave(&meta->lock, flags);
-		in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
+		in_use = meta->cache == s && kfence_obj_inuse(meta);
 		raw_spin_unlock_irqrestore(&meta->lock, flags);
 
 		if (in_use) {
@@ -1145,6 +1156,7 @@ void *kfence_object_start(const void *addr)
 void __kfence_free(void *addr)
 {
 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+	unsigned long flags;
 
 #ifdef CONFIG_MEMCG
 	KFENCE_WARN_ON(meta->obj_exts.objcg);
@@ -1154,9 +1166,14 @@ void __kfence_free(void *addr)
 	 * the object, as the object page may be recycled for other-typed
 	 * objects once it has been freed. meta->cache may be NULL if the cache
 	 * was destroyed.
+	 * Save the stack trace here. It is more useful.
 	 */
-	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
+	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU))) {
+		raw_spin_lock_irqsave(&meta->lock, flags);
+		metadata_update_state(meta, KFENCE_OBJECT_RCU_FREEING, NULL, 0);
+		raw_spin_unlock_irqrestore(&meta->lock, flags);
 		call_rcu(&meta->rcu_head, rcu_guarded_free);
+	}
 	else
 		kfence_guarded_free(addr, meta, false);
 }
@@ -1182,14 +1199,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		int distance = 0;
 
 		meta = addr_to_metadata(addr - PAGE_SIZE);
-		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+		if (meta && kfence_obj_inuse(meta)) {
 			to_report = meta;
 			/* Data race ok; distance calculation approximate. */
 			distance = addr - data_race(meta->addr + meta->size);
 		}
 
 		meta = addr_to_metadata(addr + PAGE_SIZE);
-		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
+		if (meta && kfence_obj_inuse(meta)) {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812065947.6104-1-dtcccc%40linux.alibaba.com.
