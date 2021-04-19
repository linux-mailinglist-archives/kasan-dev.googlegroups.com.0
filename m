Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4MI6WBQMGQEVPUI6LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB11363DFF
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 10:50:58 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id f13-20020a2ea0cd0000b02900bdd20adfc9sf6006229ljm.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Apr 2021 01:50:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618822258; cv=pass;
        d=google.com; s=arc-20160816;
        b=vyPFpx3RInjytN4eUgqf7n+EG+O32cDckXE8NuBz+JFTSlIdPot4xIRWUfUfdRvA7R
         s+M85jD3WgHqKFsNjD+yzcS+gE0zwIw0e2j9/9S6KwwFJ2pW+YUVTyDF/6sfYoqbmXZr
         oXkXH0R9GupqWfnZnwzaV2SujEPoVF+Scmg/8iF3BXOkFGvqAJm5+OgNxlnPzV9S/ZjF
         o6VkRjLO4rA3W5xA0rPh3fEjxKtLwH0mC9MWKYgTxOPWdhKoFa7TpBXA3wNx8Ttucc4/
         5jmAm6KN7CYg0MQLB0bwxa4j4Mb99aZRxRws1KpGCfGuR144Tr2vQqtzwOxQr6vTQHtX
         nxeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wpqbrc+B8XgVqkDKKt1y21x5iubkhB4RnHhvdX2lYTo=;
        b=0/KOY+cdxwVzLyrxZgjZRIhK/UWq2W3HBFjVQ+d73TpuTITQJ2MhTUkt1OU526HHWF
         vyBngiQw2uG6Jfhu656T3eNp73CODCGtmhGnWguEtjezS7x58j9kABg/fQ/GDHhmo8mU
         pxdX3C7oUsJfjqgPPOAb9S3BC83+STktSif5/ox6A20fy0BowhGTWStRZN4Q4M7o2Fxx
         guZ30UP38pZksdLjylF3Xd1B5hIyv50QR/9Kr4xK9n1sEe3cqfciopYmJN2EcmHFyHxH
         pfKSiwikHE8ZVtV7glK2dZtnvWVkzobbsynl7sJtXGrt9h8a+/TNeUZlGbqgTayiVAaA
         uLpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j0gtczwP;
       spf=pass (google.com: domain of 3cer9yaukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cER9YAUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wpqbrc+B8XgVqkDKKt1y21x5iubkhB4RnHhvdX2lYTo=;
        b=grZi5cZ+QSt55M8wwssy4XdwQMNDG2cBw7ZlFSiRWjMSJG1Cg/TzZxm+STJfzvpxlI
         qpkqpcoJ6DcZ9DV5Dsu/BgB8wY685JYj6LkLqJeBtGLT0n9pEj5XYJNwmk5eUyJvP+SW
         a9e35YkHe/x/cgeTY5bDQ1WvlX7qbo7af+ffF/5YgtmWOKLuZBy8i5JEHmKqtC47GLDk
         cu+Cj91qG0x2sf7trIu+CSMjc0y2N9A3wkMYIJZj/m2lv5ja1c55x/W64DpAVyaVg0s9
         qSm0dgElmprUAopDvJ8XalRujfSZYR7eWV9KnAGg+6jzhZfk3Rlt1rT3AcW8AgbC01NF
         JXvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wpqbrc+B8XgVqkDKKt1y21x5iubkhB4RnHhvdX2lYTo=;
        b=h6t3b7tlF4UOw9JNe9FER6tQqyhvLs/rVkSeeBqb7AS9eTD3d7LgXbf6FxP2XJ0bPs
         JguB1uBHXipEn3679cTaPw693UC7sARX7/Zg9G6xGqIAtgevfFAiN0AiQKRsMl84XYsT
         wBCbQnaQyNjsysjGnmaqjEkJUgzkITKvGJWD/khgq5QCwl3IMAMOAnzm0pMHmZxxatAf
         U4kkPF4qQoBPLHFdGk/jHerUsp3J7QAJK2ce9d7fYxh1Gx5UXegnztomo+8dtzRwSchv
         ttfacmP52RtcZjtJUuOgHX0CV/FfMl+HQ89aPY0IavRlGKjBElPqSXBBEpzmTR4oIDrY
         ALPQ==
X-Gm-Message-State: AOAM531pAAHXUayVbxpr02QorbF7AhBJjxzwJfbQ0MG5mFp7McLSKo1g
	1+607CJUcqpqCMf1EjZ854w=
X-Google-Smtp-Source: ABdhPJwuZrOI+Xy4UPd721nxloqfNeSYuuKAjYGohJKBAH8aP+Mi+uC8rRrdcQleX0KjfgYc8I6fbQ==
X-Received: by 2002:a05:6512:1052:: with SMTP id c18mr11866811lfb.384.1618822258090;
        Mon, 19 Apr 2021 01:50:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:c22:: with SMTP id z34ls10096109lfu.2.gmail; Mon,
 19 Apr 2021 01:50:57 -0700 (PDT)
X-Received: by 2002:a19:6446:: with SMTP id b6mr11627555lfj.98.1618822256939;
        Mon, 19 Apr 2021 01:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618822256; cv=none;
        d=google.com; s=arc-20160816;
        b=A8Fhcz2qs2U682964k+6aWC3hdPL4Hprk/a9hoDt2+uFrutwU2T6KkeT6vjUN6AomC
         3OytRuUrCWDVB9ZEGFcy7Hvtj8Wh5Ms3dz7MqL0JZfJKLG6YCAlNqobB2zdmolVZGddU
         6JQC3zKFUcNLmLQ7gYgBz+WvvtxyBWE14V5zj06nkoTqtMSVzU5r7VBVh5/8ZeDI66OH
         SYuU1v9MK5bXQKkQIgbcJtxWcI+kf60Qj8fgU2shg+XUeYueTvSoJSsKqlqvCze33UnX
         9z76m3QgGejRu09trovuElSbtierFNDGpJrLzs0VrG1W9iVaFxng/F6JNgpqTwJgqU2l
         R8kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vYl7G57j5M+nH2KzFf9qyrbxlx0FOF9ni4b2Z/4AoS0=;
        b=VRHGGKake5/389uWWZxrbzg+IBYHhrUu+V6N272s7XYq+BVWFYEkw+YPotHGYWULad
         YW1K0msUDlcoZTuiT6lAuNNKIdacLAZia8055g49bVqh/3jhpOIB4vQpSn7jgSCLCJAu
         E1c9L/W7tyRgihzkqKfxoYzU09NDePHG+8j9lghFTT5xwOvfZxgb99em9/7Me+rj22Jq
         BGPqRKyXdopR0h9RHWfjGSOqn8EBaIfZ9d6pdB+zC3ti3WIxAtPZPl4LqUh2NUvgBe8F
         W8IqzfrAascPoh4JiOWJENVmMVJBGVPiUjBO/nkhzy1tOywiYph53bEBjnoWdvE2HQor
         7GRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j0gtczwP;
       spf=pass (google.com: domain of 3cer9yaukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cER9YAUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w19si644825ljm.3.2021.04.19.01.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Apr 2021 01:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cer9yaukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j16-20020adfd2100000b02901022328749eso8668506wrh.4
        for <kasan-dev@googlegroups.com>; Mon, 19 Apr 2021 01:50:56 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:92f8:c03b:1448:ada5])
 (user=elver job=sendgmr) by 2002:a05:600c:48a6:: with SMTP id
 j38mr20532545wmp.99.1618822256477; Mon, 19 Apr 2021 01:50:56 -0700 (PDT)
Date: Mon, 19 Apr 2021 10:50:25 +0200
In-Reply-To: <20210419085027.761150-1-elver@google.com>
Message-Id: <20210419085027.761150-2-elver@google.com>
Mime-Version: 1.0
References: <20210419085027.761150-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH 1/3] kfence: await for allocation using wait_event
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j0gtczwP;       spf=pass
 (google.com: domain of 3cer9yaukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3cER9YAUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

On mostly-idle systems, we have observed that toggle_allocation_gate()
is a cause of frequent wake-ups, preventing an otherwise idle CPU to go
into a lower power state.

A late change in KFENCE's development, due to a potential deadlock [1],
required changing the scheduling-friendly wait_event_timeout() and
wake_up() to an open-coded wait-loop using schedule_timeout().
[1] https://lkml.kernel.org/r/000000000000c0645805b7f982e4@google.com

To avoid unnecessary wake-ups, switch to using wait_event_timeout().

Unfortunately, we still cannot use a version with direct wake_up() in
__kfence_alloc() due to the same potential for deadlock as in [1].
Instead, add a level of indirection via an irq_work that is scheduled if
we determine that the kfence_timer requires a wake_up().

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kfence |  1 +
 mm/kfence/core.c   | 58 +++++++++++++++++++++++++++++++++-------------
 2 files changed, 43 insertions(+), 16 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 78f50ccb3b45..e641add33947 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -7,6 +7,7 @@ menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
 	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
 	select STACKTRACE
+	select IRQ_WORK
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
 	  access, use-after-free, and invalid-free errors. KFENCE is designed
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 768dbd58170d..5f0a56041549 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -10,6 +10,7 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/debugfs.h>
+#include <linux/irq_work.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
 #include <linux/kmemleak.h>
@@ -587,6 +588,20 @@ late_initcall(kfence_debugfs_init);
 
 /* === Allocation Gate Timer ================================================ */
 
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+/* Wait queue to wake up allocation-gate timer task. */
+static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+
+static void wake_up_kfence_timer(struct irq_work *work)
+{
+	wake_up(&allocation_wait);
+}
+static DEFINE_IRQ_WORK(wake_up_kfence_timer_work, wake_up_kfence_timer);
+
+/* Indicate if timer task is waiting, to avoid unnecessary irq_work. */
+static bool kfence_timer_waiting;
+#endif
+
 /*
  * Set up delayed work, which will enable and disable the static key. We need to
  * use a work queue (rather than a simple timer), since enabling and disabling a
@@ -604,25 +619,16 @@ static void toggle_allocation_gate(struct work_struct *work)
 	if (!READ_ONCE(kfence_enabled))
 		return;
 
-	/* Enable static key, and await allocation to happen. */
 	atomic_set(&kfence_allocation_gate, 0);
 #ifdef CONFIG_KFENCE_STATIC_KEYS
+	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
-	/*
-	 * Await an allocation. Timeout after 1 second, in case the kernel stops
-	 * doing allocations, to avoid stalling this worker task for too long.
-	 */
-	{
-		unsigned long end_wait = jiffies + HZ;
-
-		do {
-			set_current_state(TASK_UNINTERRUPTIBLE);
-			if (atomic_read(&kfence_allocation_gate) != 0)
-				break;
-			schedule_timeout(1);
-		} while (time_before(jiffies, end_wait));
-		__set_current_state(TASK_RUNNING);
-	}
+
+	WRITE_ONCE(kfence_timer_waiting, true);
+	smp_mb(); /* See comment in __kfence_alloc(). */
+	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
+	smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
+
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
 #endif
@@ -729,6 +735,26 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 */
 	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_allocation_gate) > 1)
 		return NULL;
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+	/*
+	 * Read of kfence_timer_waiting must be ordered after write to
+	 * kfence_allocation_gate (fully ordered per atomic_inc_return()).
+	 *
+	 * Conversely, the write to kfence_timer_waiting must be ordered before
+	 * the check of kfence_allocation_gate in toggle_allocation_gate().
+	 *
+	 * This ensures that toggle_allocation_gate() always sees the updated
+	 * kfence_allocation_gate, or we see that the timer is waiting and will
+	 * queue the work to wake it up.
+	 */
+	if (READ_ONCE(kfence_timer_waiting)) {
+		/*
+		 * Calling wake_up() here may deadlock when allocations happen
+		 * from within timer code. Use an irq_work to defer it.
+		 */
+		irq_work_queue(&wake_up_kfence_timer_work);
+	}
+#endif
 
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210419085027.761150-2-elver%40google.com.
