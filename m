Return-Path: <kasan-dev+bncBCS37NMQ3YHBBDX5ZX5QKGQETRXXLUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D37E727D5DB
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:35:58 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id d9sf1448705lja.5
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404558; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZsSwP5Gr4MKusev3gF2yV8gIcM2fcC8KgOVUkk174W3hAEOdES9li/Pys35QwiLxB
         wWrdQ2Pd/aJAFefgoD2/DJgMQERZvnwv178E4cdktj33WOxNw2tOgbaulzXT7LG5ilW/
         y017xMsjF4YuRsKtxAZbVCJN/QgrAoy046eYHBJQfPPPG7UeLL2S91aUpieLxmjATGlg
         NSArJ/YiMLTPjaw9mspA0zF0B2RO/tsbxoJn6aiqSbfqQukaZuyMWnM+RdmbsDl/SLRj
         P7PEH2ls41T13fW0W7iW5H6Jgw7mQPNUcuj0fhmC2BP34Go3k/HI+LDqA+CcJzKw+TgR
         4KeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fEzFEQ1LCMs5SIBQfz7JUhIAIXB1qubsgwTWNnwHMQ8=;
        b=GLTCqc2BqOw0c/fUX/Z5kkK2Ay2yj3CZk5v91OMpqT3g39QrTmC1vV6bH+GmiftQAW
         1usCfsUAWl9JXOwxBRkX/rreanshv+KcpLe6Jmh2eoDRrJBg5uJNPBJoeTfoEmcr8ssC
         RTTRw9nt0nNIarBAQ+qrZuHAIyNQFWCip2hte/bhDoCKJMhw7FMUMZGwhQnKt9UaLel2
         lXxJeCcwGn1VQ30Xx6STOuPX/lQPE1+QeeWRvs/iA9fXW5+7gpO2M4RXcfOyshxQ+SJN
         PLCtsGiYvEl7am4Jqxg7opo2EShHDHW/6GEeyLJbs+xjkz4TRS+RzkOObMUSXb1Jpj6x
         jMyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fEzFEQ1LCMs5SIBQfz7JUhIAIXB1qubsgwTWNnwHMQ8=;
        b=UG1dcpkfbN54kQ9kYgWEicHkJJrQpfqUvRY8gYSZM4qxN3ZF/WdxFQ6lIuPlM7yP4K
         Y8SFzxxvJUKz3s/th6KRuMXeAOv5i9GkBVBUMIzIwkdla9UNRFz41eIvfYe/+xHl90iv
         VpuTogDDKe/UaFF83gadGi35hdlBXsSNeHooCbgXAunekKCLn/cjAO7KV0kC3yevkSl3
         cVJaHWg1kHmY/KaLNJWxOj6ncaBQPSwf3TPi5GXeWQf1wGGCLf7zj9oDGRHXhrL4+5qK
         wySRBJ7wFvLM0xcLUL8edSGRTAOitYvyyYqKivcNbQ9zMr7qYBDFm0KTwsReAYQqJ8sp
         h+cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fEzFEQ1LCMs5SIBQfz7JUhIAIXB1qubsgwTWNnwHMQ8=;
        b=T1lp0ogXj7ulvBv7WQdfx2fuoefBvtf0LZGJsBDjKBdTUxp9Cqo8X4gwnZ4AV7OGtq
         bv3IIQXyKev2jRZ0dOUZbp7twBzLq9P7SruZJYuSkET4z4VcAuyWVlvhEIEbXawEGYTo
         ZKIjNQ/IciemAEBOA7jCurMSJolGUVfCh2TFsqWpLKnpq86oIIUvPgmUYx5pGdqYbp59
         WfeGwdKjvqUHl3HIR8ECAc87U52V/tm0rIAS71mYQo8zUUDBGfY5Y8VnWeciS6rmr2Am
         8GiKTib07EGzm5ieeYgM6S9IVFvsJi6fkm5mkgPi3PORdXHTomfw0021eBNduVMi4H1F
         zJjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336B0j71jcl4ruotfh1MyOGhfGM4iODM4kIk6sxg26hiuj/Yke8
	OntsKHWzMDVnZs3YAMGwDWY=
X-Google-Smtp-Source: ABdhPJw0+bT4JYYLQsRcvAsOQBpcLCEcbBfKd6ZvtTThIA9cjAK6ra48r33cnSiBlNtsQlOJjk8YbA==
X-Received: by 2002:a19:2390:: with SMTP id j138mr1773355lfj.469.1601404558391;
        Tue, 29 Sep 2020 11:35:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls308483ljc.6.gmail; Tue, 29 Sep
 2020 11:35:57 -0700 (PDT)
X-Received: by 2002:a2e:7a14:: with SMTP id v20mr1687512ljc.429.1601404557300;
        Tue, 29 Sep 2020 11:35:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404557; cv=none;
        d=google.com; s=arc-20160816;
        b=s7ws61lrX96gzzXKpEAdIAr/UEiHrGqulsHxga26zxJEZov0ZKUw+HEhYoRFBU2ocx
         AbRUX8feoLb0th6x7reheaEBoFV5DT+mHYDwQWD0tXuc0tAo/MMoJoBcQ6CQ+8i52b/j
         r6+zmoWLW431VkeL0klNJ/MM2C3HxPPzMNLF1C+6mWpzoA25w96ZPQoaq0yUKM+vaKrN
         LEeYGQpLDBbpatJ470tV6OZSk+mPzdCCV3x10gs1w77VxlybRRgAPBKES8q0pu05T0ux
         98LEPPWa7o/SFXeJhYNOnxl1teo+wWWMuugKNYrQi/6DWpp7UUltzaUYVfo6T7DA9uWe
         rRmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=H9FfRvaA+Wp3IJ0z7DJTjMPazUzC1jfP34QSVpIB8gM=;
        b=kMTVWfQOhut7FOTvzFBEhTobPx//ACOCg9n1hO3VwuEpMkYfGu2sSpZUBcyq7foWY+
         4sdutwA5djjvmVvJeTpKzX3CNfWDRyVY0FS3vqm/co2i4CTbP/P+aca9+9bTu9H3JIKE
         czxXgb6cNu/fuVoo8xk/YuP7PfiLJkRDuwuoPFCNI1XpbWf6kJ+tlKepJAFU2tZNkl3I
         AtFvsr9V3qH/FHBHH04kiX90WppJ/Pbegsjw7hW2tWmo6dqAO7UwNrJn86kAQCGlIdPR
         2XKCsoJW//DRyLeP3KIDEoQTxtKG5k/8kRLqXKvOLvlsqxpFTPoJhQ81bXAYW7x1PUmw
         OfJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f65.google.com (mail-wm1-f65.google.com. [209.85.128.65])
        by gmr-mx.google.com with ESMTPS id 11si134115lfl.4.2020.09.29.11.35.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:35:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as permitted sender) client-ip=209.85.128.65;
Received: by mail-wm1-f65.google.com with SMTP id d4so5628377wmd.5
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:35:57 -0700 (PDT)
X-Received: by 2002:a05:600c:2909:: with SMTP id i9mr6280384wmd.160.1601404556735;
        Tue, 29 Sep 2020 11:35:56 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:35:56 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 4/6] mm: Implement slab quarantine randomization
Date: Tue, 29 Sep 2020 21:35:11 +0300
Message-Id: <20200929183513.380760-5-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.65 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

The randomization is very important for the slab quarantine security
properties. Without it the number of kmalloc()+kfree() calls that are
needed for overwriting the vulnerable object is almost the same.
That would be good for stable use-after-free exploitation, and we
should not allow that.

This commit contains very compact and hackish changes that introduce
the quarantine randomization. At first all quarantine batches are filled
by objects. Then during the quarantine reducing we randomly choose and
free 1/2 of objects from a randomly chosen batch. Now the randomized
quarantine releases the freed object at an unpredictable moment, which
is harmful for the heap spraying technique employed by use-after-free
exploits.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 mm/kasan/quarantine.c | 79 +++++++++++++++++++++++++++++++++++++------
 1 file changed, 69 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 61666263c53e..4ce100605086 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -29,6 +29,7 @@
 #include <linux/srcu.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/random.h>
 
 #include "../slab.h"
 #include "kasan.h"
@@ -89,8 +90,13 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
 }
 
 #define QUARANTINE_PERCPU_SIZE (1 << 20)
+
+#ifdef CONFIG_KASAN
 #define QUARANTINE_BATCHES \
 	(1024 > 4 * CONFIG_NR_CPUS ? 1024 : 4 * CONFIG_NR_CPUS)
+#else
+#define QUARANTINE_BATCHES 128
+#endif
 
 /*
  * The object quarantine consists of per-cpu queues and a global queue,
@@ -110,10 +116,7 @@ DEFINE_STATIC_SRCU(remove_cache_srcu);
 /* Maximum size of the global queue. */
 static unsigned long quarantine_max_size;
 
-/*
- * Target size of a batch in global_quarantine.
- * Usually equal to QUARANTINE_PERCPU_SIZE unless we have too much RAM.
- */
+/* Target size of a batch in global_quarantine. */
 static unsigned long quarantine_batch_size;
 
 /*
@@ -191,7 +194,12 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 
 	q = this_cpu_ptr(&cpu_quarantine);
 	qlist_put(q, &info->quarantine_link, cache->size);
+#ifdef CONFIG_KASAN
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
+#else
+	if (unlikely(q->bytes > min_t(size_t, QUARANTINE_PERCPU_SIZE,
+					READ_ONCE(quarantine_batch_size)))) {
+#endif
 		qlist_move_all(q, &temp);
 
 		raw_spin_lock(&quarantine_lock);
@@ -204,7 +212,7 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 			new_tail = quarantine_tail + 1;
 			if (new_tail == QUARANTINE_BATCHES)
 				new_tail = 0;
-			if (new_tail != quarantine_head)
+			if (new_tail != quarantine_head || !IS_ENABLED(CONFIG_KASAN))
 				quarantine_tail = new_tail;
 		}
 		raw_spin_unlock(&quarantine_lock);
@@ -213,12 +221,43 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 	local_irq_restore(flags);
 }
 
+static void qlist_move_random(struct qlist_head *from, struct qlist_head *to)
+{
+	struct qlist_node *curr;
+
+	if (unlikely(qlist_empty(from)))
+		return;
+
+	curr = from->head;
+	qlist_init(from);
+	while (curr) {
+		struct qlist_node *next = curr->next;
+		struct kmem_cache *obj_cache = qlink_to_cache(curr);
+		int rnd =  get_random_int();
+
+		/*
+		 * Hackish quarantine randomization, part 2:
+		 * move only 1/2 of objects to the destination list.
+		 * TODO: use random bits sparingly for better performance.
+		 */
+		if (rnd % 2 == 0)
+			qlist_put(to, curr, obj_cache->size);
+		else
+			qlist_put(from, curr, obj_cache->size);
+
+		curr = next;
+	}
+}
+
 void quarantine_reduce(void)
 {
-	size_t total_size, new_quarantine_size, percpu_quarantines;
+	size_t total_size;
 	unsigned long flags;
 	int srcu_idx;
 	struct qlist_head to_free = QLIST_INIT;
+#ifdef CONFIG_KASAN
+	size_t new_quarantine_size, percpu_quarantines;
+#endif
 
 	if (likely(READ_ONCE(quarantine_size) <=
 		   READ_ONCE(quarantine_max_size)))
@@ -236,12 +275,12 @@ void quarantine_reduce(void)
 	srcu_idx = srcu_read_lock(&remove_cache_srcu);
 	raw_spin_lock_irqsave(&quarantine_lock, flags);
 
-	/*
-	 * Update quarantine size in case of hotplug. Allocate a fraction of
-	 * the installed memory to quarantine minus per-cpu queue limits.
-	 */
+	/* Update quarantine size in case of hotplug */
 	total_size = (totalram_pages() << PAGE_SHIFT) /
 		QUARANTINE_FRACTION;
+
+#ifdef CONFIG_KASAN
+	/* Subtract per-cpu queue limits from total quarantine size */
 	percpu_quarantines = QUARANTINE_PERCPU_SIZE * num_online_cpus();
 	new_quarantine_size = (total_size < percpu_quarantines) ?
 		0 : total_size - percpu_quarantines;
@@ -257,6 +296,26 @@ void quarantine_reduce(void)
 		if (quarantine_head == QUARANTINE_BATCHES)
 			quarantine_head = 0;
 	}
+#else /* CONFIG_KASAN */
+	/*
+	 * Don't subtract per-cpu queue limits from total quarantine
+	 * size to consume all quarantine slots.
+	 */
+	WRITE_ONCE(quarantine_max_size, total_size);
+	WRITE_ONCE(quarantine_batch_size, total_size / QUARANTINE_BATCHES);
+
+	/*
+	 * Hackish quarantine randomization, part 1:
+	 * pick a random batch for reducing.
+	 */
+	if (likely(quarantine_size > quarantine_max_size)) {
+		do {
+			quarantine_head = get_random_int() % QUARANTINE_BATCHES;
+		} while (quarantine_head == quarantine_tail);
+		qlist_move_random(&global_quarantine[quarantine_head], &to_free);
+		WRITE_ONCE(quarantine_size, quarantine_size - to_free.bytes);
+	}
+#endif
 
 	raw_spin_unlock_irqrestore(&quarantine_lock, flags);
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-5-alex.popov%40linux.com.
