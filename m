Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ7DQLYQKGQEWKHO7NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C1CA13F553
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 19:56:04 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 7sf750359wmf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:56:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579200964; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVmt/Mvt0cpBS/p8GH3OfUhnmYcG1ai1+DdGp5J7KfL5XqxmBQ0/LsZpfFMG2Ya4Mp
         Nnw/TsCc6K8bxgFsQ6QI3d6YwB/ErnLO9R1ZIISY4h54gPnjNLe+ksT9nEpTLxa/i9LY
         JXGomEBgcHxPm/RbtQncF5KjACcCza74Dzm5R5IoHIhvR6Yvc8BWBIk2t5FkDb6k0L27
         YyC2QIkwjOfdg3YyUmD1q0/K9nfIc3jmyS5hxfkOCizg5sMHVzV86pCC2NW5rq8V+sUi
         Bnynp3wJU6gsKAXTY9sHgBNhFrRq4utJdi8wX/UDTJtYHOKx4ldLkzBW3it/cSPTbfRz
         GGfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Ktcvjy5zAe6PbFxP9R+IFr1ZBi/ZZY67y4M9jY/VT0E=;
        b=NwGnolD+JWoFzmH/KeBsgQjJTa0VmTvURsqMxEN1D3nGGioDNqo3ydBMWBMI+BWIiz
         jokx1Ii+xfRLpMcigzWfRwGxZI6LlCWK0iGDWBYcD1/DS8VZC84+lGYVWP+HU8N4q6U6
         eyxCdYNh2vQI0ZzFkjaLZZsWv1wbz6L7SGj54JBzsWT74Bjs6ln1WtD9DfLS/UskdvTn
         N+a6i+EClj7S3OpueIyc+D70D80kTf92jIeSMQDqO/8th3hhGp8dpMPWXg8ccjn6t5mD
         vWzaqJX1mTLshHLGfr5mJ+BDJETHmsm73GqnLzObUamKFRTazuGBlJwXR6kAZRJbCr6z
         Cujw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QckFlUWo;
       spf=pass (google.com: domain of 3wregxgukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wrEgXgUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ktcvjy5zAe6PbFxP9R+IFr1ZBi/ZZY67y4M9jY/VT0E=;
        b=Oc0lQpCJMFTH3fS5jZqs+AIa6vr4UA5YKCKJIqqwG/bVEJKb2KQ5oaYan2Hy8oaLEn
         3PUSyPbYDR8CB3VQwhM0Hs7Vq/vHzzodfNMirGQa7wrkfi6eAa9fP5ByEUZX/pl0if6k
         vX53ICQYhlIsUFpuKTwe5mKqFk4gIWrOan673yolgfKQ37tdkuRd/C1eZOFOf33ecQTq
         OVJWpjzFBMbSv3KeBnQ5bHS5hX7jtmA8TjX3rKVP+txgDR40SU+ia5WRws+fjC7/QDYY
         R7vuZ2rT8XI3O5VpSSbtpM9RXZpyUktCh4iGPzbK4hOxLOe+7mjD8Mwrz2tPD58HhtCx
         dJVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ktcvjy5zAe6PbFxP9R+IFr1ZBi/ZZY67y4M9jY/VT0E=;
        b=QZ0W0stsb36HqiuJpUvgXVUs//FJ0h0vlLgS/wPesAqCO6qR9+1elDV2ZuMaKpcP3L
         1UEj3TELEMPXqUysdV5GGvZMhXib7ure3gsduwpG/jFJdbhRMoMaQpVngSkQB8fK3SeJ
         n2NRUj36v2hV9RSzFiZUeH4jr65i9MXUkBIcVyFlDtCKx+k3+F7zIhGE9nLKjbWWqqrh
         2t2QTIbewDhoEQ7mE9ib1k3UNnAYT+dJh+4ym+mH2Aw3xNpB++dzucmdlvIYEs1H7tiS
         m9rVKfMbl/KbfkOTnTqx59XL+TqLFd3Y4yDTdnVqdg6IBJbtFlK16rWW0IrjzcrBpb2L
         mn6A==
X-Gm-Message-State: APjAAAVTDt3h19X7kU9yUnKwYcf8SlWD7jch+TnoNsSTOYcznr9KBgNp
	Ezww+x6xOY8TD5M94FvQXWo=
X-Google-Smtp-Source: APXvYqzKQOEgk3Ct6JZHs4IeAPKuigKVe6xsUPKa/XeTiq8kJH+abZggLaGK8SCA00xzN8niLJ3c+g==
X-Received: by 2002:a7b:cb01:: with SMTP id u1mr482530wmj.156.1579200963928;
        Thu, 16 Jan 2020 10:56:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9808:: with SMTP id a8ls1555200wme.0.gmail; Thu, 16 Jan
 2020 10:56:03 -0800 (PST)
X-Received: by 2002:a1c:f003:: with SMTP id a3mr466643wmb.41.1579200963268;
        Thu, 16 Jan 2020 10:56:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579200963; cv=none;
        d=google.com; s=arc-20160816;
        b=Cj0eiEofoCWssvxy0sBRGhXNkrwUeJ5w6CL8UApuJQ7coRg1X64Te5Tfb+GIyPehT9
         nhvqvKOYMWQWTaKPTs6GpELdfA7ZwjPSL7vlmOtn+X9tlhnCyn2aKDsrLgn27SvCZyxf
         /Lqm/pKLu3R81m2+3NL6VxP+20UMhCdVdIMij2Yy6Bujx0FLgpeL+2VMSuNCzmEEW6+F
         eqtmTg9XvCQByvgUtDjHz0oNyZZPFyrevDOdRa1bKCMrjFBh0uXoU1Fh3e7+R+wcpeBf
         fUBx4fBBVMd7lnlCzW3A6a4dKWqTAueUAkJXamTNCAlRY1fZf2yawrZqLH/+19Kel2vp
         CDWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=cOgDAvUwdmbi4m/kDIybPuInzN3fPgnThGH4mtCL7lc=;
        b=lAO0SAnrDh1saKirXT5sH2jqIN/EPZyCPyYL9rN7x9fdRBDh6N8udRz69dNcez9fQe
         +zvhTJcreH/u68ia69sGRJLWZXm9Fypwk3cNbrYgCXi1Zj9u7ywhzfLL6XYEO+h5JUxY
         40iwpAi+EQhPfRY+11BlZBtIZmt2pFt35C/o+TQM5wiRzSQ4ilHZgEsMP8E05QrISaFq
         yMztIb2TwU33Vz9eIDcwHMnjKb5DDKjjRsAnHBDoYSxAxqlB7JSqK72UowxRZwGqtPuc
         guNPhfaLWyHlhfpToJyiiI28GCRET7DQ/QsxjGVd6ER1WlTbtEeKq0G41Mgdi9hN2HD+
         LdRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QckFlUWo;
       spf=pass (google.com: domain of 3wregxgukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wrEgXgUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m2si497245wmi.3.2020.01.16.10.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 10:56:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wregxgukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f15so9671155wrr.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 10:56:03 -0800 (PST)
X-Received: by 2002:a5d:6b88:: with SMTP id n8mr4947132wrx.288.1579200962616;
 Thu, 16 Jan 2020 10:56:02 -0800 (PST)
Date: Thu, 16 Jan 2020 19:55:29 +0100
Message-Id: <20200116185529.11026-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH] debugobjects: Fix various data races
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	tglx@linutronix.de, longman@redhat.com, gregkh@linuxfoundation.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QckFlUWo;       spf=pass
 (google.com: domain of 3wregxgukcz8dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wrEgXgUKCZ8DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The counters obj_pool_free, and obj_nr_tofree, and the flag obj_freeing
are read locklessly outside the pool_lock critical sections. If read
with plain accesses, this would result in data races.

This is addressed as follows:
* reads outside critical sections become READ_ONCE()s (pairing with
  WRITE_ONCE()s added);
* writes become WRITE_ONCE()s (pairing with READ_ONCE()s added); since
  writes happen inside critical sections, only the write and not the
  read of RMWs needs to be atomic, thus WRITE_ONCE(var, var +/- X) is
  sufficient.

The data races were reported by KCSAN:

  BUG: KCSAN: data-race in __free_object / fill_pool

  write to 0xffffffff8beb04f8 of 4 bytes by interrupt on cpu 1:
   __free_object+0x1ee/0x8e0 lib/debugobjects.c:404
   __debug_check_no_obj_freed+0x199/0x330 lib/debugobjects.c:969
   debug_check_no_obj_freed+0x3c/0x44 lib/debugobjects.c:994
   slab_free_hook mm/slub.c:1422 [inline]

  read to 0xffffffff8beb04f8 of 4 bytes by task 1 on cpu 2:
   fill_pool+0x3d/0x520 lib/debugobjects.c:135
   __debug_object_init+0x3c/0x810 lib/debugobjects.c:536
   debug_object_init lib/debugobjects.c:591 [inline]
   debug_object_activate+0x228/0x320 lib/debugobjects.c:677
   debug_rcu_head_queue kernel/rcu/rcu.h:176 [inline]

  BUG: KCSAN: data-race in __debug_object_init / fill_pool

  read to 0xffffffff8beb04f8 of 4 bytes by task 10 on cpu 6:
   fill_pool+0x3d/0x520 lib/debugobjects.c:135
   __debug_object_init+0x3c/0x810 lib/debugobjects.c:536
   debug_object_init_on_stack+0x39/0x50 lib/debugobjects.c:606
   init_timer_on_stack_key kernel/time/timer.c:742 [inline]

  write to 0xffffffff8beb04f8 of 4 bytes by task 1 on cpu 3:
   alloc_object lib/debugobjects.c:258 [inline]
   __debug_object_init+0x717/0x810 lib/debugobjects.c:544
   debug_object_init lib/debugobjects.c:591 [inline]
   debug_object_activate+0x228/0x320 lib/debugobjects.c:677
   debug_rcu_head_queue kernel/rcu/rcu.h:176 [inline]

  BUG: KCSAN: data-race in free_obj_work / free_object

  read to 0xffffffff9140c190 of 4 bytes by task 10 on cpu 6:
   free_object+0x4b/0xd0 lib/debugobjects.c:426
   debug_object_free+0x190/0x210 lib/debugobjects.c:824
   destroy_timer_on_stack kernel/time/timer.c:749 [inline]

  write to 0xffffffff9140c190 of 4 bytes by task 93 on cpu 1:
   free_obj_work+0x24f/0x480 lib/debugobjects.c:313
   process_one_work+0x454/0x8d0 kernel/workqueue.c:2264
   worker_thread+0x9a/0x780 kernel/workqueue.c:2410

Signed-off-by: Marco Elver <elver@google.com>
Reported-by: Qian Cai <cai@lca.pw>
---
 lib/debugobjects.c | 46 +++++++++++++++++++++++++---------------------
 1 file changed, 25 insertions(+), 21 deletions(-)

diff --git a/lib/debugobjects.c b/lib/debugobjects.c
index 61261195f5b6..48054dbf1b51 100644
--- a/lib/debugobjects.c
+++ b/lib/debugobjects.c
@@ -132,14 +132,18 @@ static void fill_pool(void)
 	struct debug_obj *obj;
 	unsigned long flags;
 
-	if (likely(obj_pool_free >= debug_objects_pool_min_level))
+	if (likely(READ_ONCE(obj_pool_free) >= debug_objects_pool_min_level))
 		return;
 
 	/*
 	 * Reuse objs from the global free list; they will be reinitialized
 	 * when allocating.
+	 *
+	 * Both obj_nr_tofree and obj_pool_free are checked locklessly; the
+	 * READ_ONCE()s pair with the WRITE_ONCE()s in pool_lock critical
+	 * sections.
 	 */
-	while (obj_nr_tofree && (obj_pool_free < obj_pool_min_free)) {
+	while (READ_ONCE(obj_nr_tofree) && (READ_ONCE(obj_pool_free) < obj_pool_min_free)) {
 		raw_spin_lock_irqsave(&pool_lock, flags);
 		/*
 		 * Recheck with the lock held as the worker thread might have
@@ -148,9 +152,9 @@ static void fill_pool(void)
 		while (obj_nr_tofree && (obj_pool_free < obj_pool_min_free)) {
 			obj = hlist_entry(obj_to_free.first, typeof(*obj), node);
 			hlist_del(&obj->node);
-			obj_nr_tofree--;
+			WRITE_ONCE(obj_nr_tofree, obj_nr_tofree - 1);
 			hlist_add_head(&obj->node, &obj_pool);
-			obj_pool_free++;
+			WRITE_ONCE(obj_pool_free, obj_pool_free + 1);
 		}
 		raw_spin_unlock_irqrestore(&pool_lock, flags);
 	}
@@ -158,7 +162,7 @@ static void fill_pool(void)
 	if (unlikely(!obj_cache))
 		return;
 
-	while (obj_pool_free < debug_objects_pool_min_level) {
+	while (READ_ONCE(obj_pool_free) < debug_objects_pool_min_level) {
 		struct debug_obj *new[ODEBUG_BATCH_SIZE];
 		int cnt;
 
@@ -174,7 +178,7 @@ static void fill_pool(void)
 		while (cnt) {
 			hlist_add_head(&new[--cnt]->node, &obj_pool);
 			debug_objects_allocated++;
-			obj_pool_free++;
+			WRITE_ONCE(obj_pool_free, obj_pool_free + 1);
 		}
 		raw_spin_unlock_irqrestore(&pool_lock, flags);
 	}
@@ -236,7 +240,7 @@ alloc_object(void *addr, struct debug_bucket *b, struct debug_obj_descr *descr)
 	obj = __alloc_object(&obj_pool);
 	if (obj) {
 		obj_pool_used++;
-		obj_pool_free--;
+		WRITE_ONCE(obj_pool_free, obj_pool_free - 1);
 
 		/*
 		 * Looking ahead, allocate one batch of debug objects and
@@ -255,7 +259,7 @@ alloc_object(void *addr, struct debug_bucket *b, struct debug_obj_descr *descr)
 					       &percpu_pool->free_objs);
 				percpu_pool->obj_free++;
 				obj_pool_used++;
-				obj_pool_free--;
+				WRITE_ONCE(obj_pool_free, obj_pool_free - 1);
 			}
 		}
 
@@ -309,8 +313,8 @@ static void free_obj_work(struct work_struct *work)
 		obj = hlist_entry(obj_to_free.first, typeof(*obj), node);
 		hlist_del(&obj->node);
 		hlist_add_head(&obj->node, &obj_pool);
-		obj_pool_free++;
-		obj_nr_tofree--;
+		WRITE_ONCE(obj_pool_free, obj_pool_free + 1);
+		WRITE_ONCE(obj_nr_tofree, obj_nr_tofree - 1);
 	}
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
 	return;
@@ -324,7 +328,7 @@ static void free_obj_work(struct work_struct *work)
 	if (obj_nr_tofree) {
 		hlist_move_list(&obj_to_free, &tofree);
 		debug_objects_freed += obj_nr_tofree;
-		obj_nr_tofree = 0;
+		WRITE_ONCE(obj_nr_tofree, 0);
 	}
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
 
@@ -375,10 +379,10 @@ static void __free_object(struct debug_obj *obj)
 	obj_pool_used--;
 
 	if (work) {
-		obj_nr_tofree++;
+		WRITE_ONCE(obj_nr_tofree, obj_nr_tofree + 1);
 		hlist_add_head(&obj->node, &obj_to_free);
 		if (lookahead_count) {
-			obj_nr_tofree += lookahead_count;
+			WRITE_ONCE(obj_nr_tofree, obj_nr_tofree + lookahead_count);
 			obj_pool_used -= lookahead_count;
 			while (lookahead_count) {
 				hlist_add_head(&objs[--lookahead_count]->node,
@@ -396,15 +400,15 @@ static void __free_object(struct debug_obj *obj)
 			for (i = 0; i < ODEBUG_BATCH_SIZE; i++) {
 				obj = __alloc_object(&obj_pool);
 				hlist_add_head(&obj->node, &obj_to_free);
-				obj_pool_free--;
-				obj_nr_tofree++;
+				WRITE_ONCE(obj_pool_free, obj_pool_free - 1);
+				WRITE_ONCE(obj_nr_tofree, obj_nr_tofree + 1);
 			}
 		}
 	} else {
-		obj_pool_free++;
+		WRITE_ONCE(obj_pool_free, obj_pool_free + 1);
 		hlist_add_head(&obj->node, &obj_pool);
 		if (lookahead_count) {
-			obj_pool_free += lookahead_count;
+			WRITE_ONCE(obj_pool_free, obj_pool_free + lookahead_count);
 			obj_pool_used -= lookahead_count;
 			while (lookahead_count) {
 				hlist_add_head(&objs[--lookahead_count]->node,
@@ -423,7 +427,7 @@ static void __free_object(struct debug_obj *obj)
 static void free_object(struct debug_obj *obj)
 {
 	__free_object(obj);
-	if (!obj_freeing && obj_nr_tofree) {
+	if (!READ_ONCE(obj_freeing) && READ_ONCE(obj_nr_tofree)) {
 		WRITE_ONCE(obj_freeing, true);
 		schedule_delayed_work(&debug_obj_work, ODEBUG_FREE_WORK_DELAY);
 	}
@@ -982,7 +986,7 @@ static void __debug_check_no_obj_freed(const void *address, unsigned long size)
 		debug_objects_maxchecked = objs_checked;
 
 	/* Schedule work to actually kmem_cache_free() objects */
-	if (!obj_freeing && obj_nr_tofree) {
+	if (!READ_ONCE(obj_freeing) && READ_ONCE(obj_nr_tofree)) {
 		WRITE_ONCE(obj_freeing, true);
 		schedule_delayed_work(&debug_obj_work, ODEBUG_FREE_WORK_DELAY);
 	}
@@ -1008,12 +1012,12 @@ static int debug_stats_show(struct seq_file *m, void *v)
 	seq_printf(m, "max_checked   :%d\n", debug_objects_maxchecked);
 	seq_printf(m, "warnings      :%d\n", debug_objects_warnings);
 	seq_printf(m, "fixups        :%d\n", debug_objects_fixups);
-	seq_printf(m, "pool_free     :%d\n", obj_pool_free + obj_percpu_free);
+	seq_printf(m, "pool_free     :%d\n", READ_ONCE(obj_pool_free) + obj_percpu_free);
 	seq_printf(m, "pool_pcp_free :%d\n", obj_percpu_free);
 	seq_printf(m, "pool_min_free :%d\n", obj_pool_min_free);
 	seq_printf(m, "pool_used     :%d\n", obj_pool_used - obj_percpu_free);
 	seq_printf(m, "pool_max_used :%d\n", obj_pool_max_used);
-	seq_printf(m, "on_free_list  :%d\n", obj_nr_tofree);
+	seq_printf(m, "on_free_list  :%d\n", READ_ONCE(obj_nr_tofree));
 	seq_printf(m, "objs_allocated:%d\n", debug_objects_allocated);
 	seq_printf(m, "objs_freed    :%d\n", debug_objects_freed);
 	return 0;
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116185529.11026-1-elver%40google.com.
