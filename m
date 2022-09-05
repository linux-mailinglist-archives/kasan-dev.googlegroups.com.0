Return-Path: <kasan-dev+bncBAABB6GL3GMAMGQECVCREYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFD05ADAC1
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:11:21 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id m2-20020adfc582000000b0021e28acded7sf1505653wrg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412280; cv=pass;
        d=google.com; s=arc-20160816;
        b=cfjmG5LX2xMEo9LY8cDEoQRROon2odI6B1HygEigmH6eIOQGuCADCiOfMS4wN1fAQY
         kwQIEDmXTBxz7Aq6n6FxLWXVYgRx2nfGg93booEdjBUh5p9abbAi2AYDjkDhMNjUhzCH
         8tXZI9a/y+BJ9OOkj3JxW6P1z9hLSnh8Uy2AxGK5BNDOHitUKX7SGM5dCjrLM9OJEENu
         p2gDnfM0KP3LCFkNxvs1gNqR/pO8xVUE3YHy0wuaTh/QQEmj9Q7HGf0TcxK+zhg5OfYA
         l44BxbMiRaC9QyVK3V2XTYgj8hPDJI3QQKi5jdHEXZgG3pplFEVW/ZSwkUt8ytDxamV/
         d4sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=peHBqzLeWIzVbYz7mdcHeN8k8AlVA872uWUanfB6UnE=;
        b=x1PWLjY7LDZ4UWtBeRIRYiRoBPpRonn8hmuq1fhHqtlWVA2efLGTGxSlK9ncme51l3
         2IqNNcU18jM4EasUWSHAMdHYdRAPC9LOMRQCcLtWoKtr91/f2QFShFX+tAp2EJhtalhD
         qd589Nucv2Ohg6wLUOy0IXTdI9duGtF4XlnqnaPGb/FcvWnpNJhJM5L7CBQQXX9cG8Qe
         WFylVZGxpFHEa3OvB5y0vIrgqhgZuFuTbVkYK7zY1CcLyLQCyQIER1C2LRtqXPWVjbwu
         Jt9eCK478BdAi+fU1AYzONUznV234pNI2/ITwFf6+aBarld+mRaUB5SdIC1yGymYeQiw
         UJ1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="C+K/V0CO";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=peHBqzLeWIzVbYz7mdcHeN8k8AlVA872uWUanfB6UnE=;
        b=ChnwXnzrDtr6fioHiZOIAQwnrvCc/LxT+vrr8fcLp5ALjrhvYQNp+KaEBZSgQy5VgG
         PjoQ/SJRXL5sphjhuyuoXJKHHIPgRR9oTb4bzg/1wHdeum5XeWZrQwGlUQT5Kp0DTfU0
         At92n13ma2kK44wJiweRZDoEDQctkXFf0pBhRXLrMSnFM/QAROAIaKyhbOTazi4JsPjk
         yYXavcYByx9N/rcx1MM6Aem65onMuNC6cJFbrljg4G4g10ujX6zdrmIEjNMeqmTEHZcr
         vQ9bTOaRlkE4K4mEWgV38q3mrL/kjuSPZaY8XLCP0tbqLPh9mfokcwXildQ1k07k6CEv
         KUsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=peHBqzLeWIzVbYz7mdcHeN8k8AlVA872uWUanfB6UnE=;
        b=biQLpaoRW609bSoX7f6lHhMiKU8Agy98+UbRXqcw5vMeIgvfX51if+erQ3KGKc+UPm
         zd7f/GZBe686Z4LVwXBpwPJnyspPmmNmoc4u90T3ktDs4kYBS4WwpfpdaPE4m/Yov2MG
         QDIkZA6pfsK1jeJhOmtQTjb9dKwCXYbvxObqGOo6FueUJUz0KUhETpEYjaLaUsfv5v74
         DNWsHe90yAayS92xtHBRD23EvmfTEcgehRg+ugC5217WX1Y/yOJlMpoW/zCn0dVZ5F4j
         p1+WHt6ZuNDpMiz1ZwdvRqqsVj2R7i60oj3qj4sUyZ77lZSzKjWtWQvpPYxR5ZRgyV/r
         6vkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1SpPJ5GbzHZfHY+DGcEo9klsgtsOD1CXjAwtAKbeY4YIVNhknd
	RGin/2PU/EcNiu/5tg4GUN8=
X-Google-Smtp-Source: AA6agR5DPoGSTs324WgQUwoz6e7deWAlQlCZ73sRcikEHG9TYsJNeJ22cs2di46juITnGNvz8jNLsQ==
X-Received: by 2002:a05:600c:1084:b0:3a6:150d:b92 with SMTP id e4-20020a05600c108400b003a6150d0b92mr12324775wmd.151.1662412280775;
        Mon, 05 Sep 2022 14:11:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1483:b0:3a6:47b:13c7 with SMTP id
 c3-20020a05600c148300b003a6047b13c7ls5136749wmh.0.-pod-canary-gmail; Mon, 05
 Sep 2022 14:11:20 -0700 (PDT)
X-Received: by 2002:a05:600c:a09:b0:3a6:8900:c651 with SMTP id z9-20020a05600c0a0900b003a68900c651mr11789653wmp.145.1662412280000;
        Mon, 05 Sep 2022 14:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412279; cv=none;
        d=google.com; s=arc-20160816;
        b=PdGqFte33PXID8P1zHdhPh/8vgHDfNScSMu1Ng+scqcygKbv2uTuAdx17QmvdIqUq3
         3qNpsaDOmwasuotTex39OIaOE0zDb3DvuhE3mBQRfO7GHiC/Y1SYB2KqUdjQU2jpN3kk
         nYHoUvEBkNoR2Vez2J2aspg/DZiLPywYrzthDZ4rSCofKXXNm3o20wJTw2GdmQ++mPvx
         zqt27BobBfROnFQKbWk1aIQM+fZTlFCs1uXdB4JIZtFPBdBPxf6NfC+nd2kSDWBetY6Z
         Av1XLmYXvwCnNW271wvL1ShVWdwMOUM2i0mu5lfStiLx4+99Hjakw5ELgPOA+y6MkpmL
         SYxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7vds2A+AJqY3I89YHazVxVdb29FIWLrXb8GMpoggHoE=;
        b=FMBWiU6rq1N3KNme+nyKEKRnb0OJufZ+eMt32oQBNXCkxPe1DecxlPC9/3BYbJRdP8
         yBdvmMItlrcQZ4JtaMbXl34OLB+qpuGZ9zneXnyA9iGupQNdiR689nYDh0kkB0MRzwLW
         EJ5syRFTtRvsea1uaEGXIW1+dGIQCDxh93uEguDX+emDDNVHTZPadrKPHjWE3g/wVcBy
         eXikizZFz/9U+ccQACt/5C+ZBIl3/0YVvnKCKD0Pf3OiZ4uJyS5WiuKwptTkfCEpOd/q
         CKlHhbI88mLgUNxdhFKSVXzXu8ogtk4wzl6+7qw8ci2yFLzMehTKtzqRsvyatYyFYPvz
         Y2vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="C+K/V0CO";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si614772wms.0.2022.09.05.14.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 30/34] kasan: implement stack ring for tag-based modes
Date: Mon,  5 Sep 2022 23:05:45 +0200
Message-Id: <692de14b6b6a1bc817fd55e4ad92fc1f83c1ab59.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="C+K/V0CO";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Implement storing stack depot handles for alloc/free stack traces for
slab objects for the tag-based KASAN modes in a ring buffer.

This ring buffer is referred to as the stack ring.

On each alloc/free of a slab object, the tagged address of the object and
the current stack trace are recorded in the stack ring.

On each bug report, if the accessed address belongs to a slab object, the
stack ring is scanned for matching entries. The newest entries are used to
print the alloc/free stack traces in the report: one entry for alloc and
one for free.

The number of entries in the stack ring is fixed in this patch, but one of
the following patches adds a command-line argument to control it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop redundant check for concurrent overwrites of stack ring entries.

Changes v1->v2:
- Only use the atomic type for pos, use READ/WRITE_ONCE() for the rest.
- Rename KASAN_STACK_RING_ENTRIES to KASAN_STACK_RING_SIZE.
- Rename object local variable in kasan_complete_mode_report_info() to
  ptr to match the name in kasan_stack_ring_entry.
- Detect stack ring entry slots that are being written to.
- Use read-write lock to disallow reading half-written stack ring entries.
- Add a comment about the stack ring being best-effort.
---
 mm/kasan/kasan.h       | 21 +++++++++++++
 mm/kasan/report_tags.c | 71 ++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/tags.c        | 50 +++++++++++++++++++++++++++++
 3 files changed, 142 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7df107dc400a..cfff81139d67 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -2,6 +2,7 @@
 #ifndef __MM_KASAN_KASAN_H
 #define __MM_KASAN_KASAN_H
 
+#include <linux/atomic.h>
 #include <linux/kasan.h>
 #include <linux/kasan-tags.h>
 #include <linux/kfence.h>
@@ -233,6 +234,26 @@ struct kasan_free_meta {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+
+struct kasan_stack_ring_entry {
+	void *ptr;
+	size_t size;
+	u32 pid;
+	depot_stack_handle_t stack;
+	bool is_free;
+};
+
+#define KASAN_STACK_RING_SIZE (32 << 10)
+
+struct kasan_stack_ring {
+	rwlock_t lock;
+	atomic64_t pos;
+	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_SIZE];
+};
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 5cbac2cdb177..1b78136542bb 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -4,8 +4,12 @@
  * Copyright (c) 2020 Google, Inc.
  */
 
+#include <linux/atomic.h>
+
 #include "kasan.h"
 
+extern struct kasan_stack_ring stack_ring;
+
 static const char *get_bug_type(struct kasan_report_info *info)
 {
 	/*
@@ -24,5 +28,72 @@ static const char *get_bug_type(struct kasan_report_info *info)
 
 void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
+	unsigned long flags;
+	u64 pos;
+	struct kasan_stack_ring_entry *entry;
+	void *ptr;
+	u32 pid;
+	depot_stack_handle_t stack;
+	bool is_free;
+	bool alloc_found = false, free_found = false;
+
 	info->bug_type = get_bug_type(info);
+
+	if (!info->cache || !info->object)
+		return;
+	}
+
+	write_lock_irqsave(&stack_ring.lock, flags);
+
+	pos = atomic64_read(&stack_ring.pos);
+
+	/*
+	 * The loop below tries to find stack ring entries relevant to the
+	 * buggy object. This is a best-effort process.
+	 *
+	 * First, another object with the same tag can be allocated in place of
+	 * the buggy object. Also, since the number of entries is limited, the
+	 * entries relevant to the buggy object can be overwritten.
+	 */
+
+	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
+		if (alloc_found && free_found)
+			break;
+
+		entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
+
+		/* Paired with smp_store_release() in save_stack_info(). */
+		ptr = (void *)smp_load_acquire(&entry->ptr);
+
+		if (kasan_reset_tag(ptr) != info->object ||
+		    get_tag(ptr) != get_tag(info->access_addr))
+			continue;
+
+		pid = READ_ONCE(entry->pid);
+		stack = READ_ONCE(entry->stack);
+		is_free = READ_ONCE(entry->is_free);
+
+		if (is_free) {
+			/*
+			 * Second free of the same object.
+			 * Give up on trying to find the alloc entry.
+			 */
+			if (free_found)
+				break;
+
+			info->free_track.pid = pid;
+			info->free_track.stack = stack;
+			free_found = true;
+		} else {
+			/* Second alloc of the same object. Give up. */
+			if (alloc_found)
+				break;
+
+			info->alloc_track.pid = pid;
+			info->alloc_track.stack = stack;
+			alloc_found = true;
+		}
+	}
+
+	write_unlock_irqrestore(&stack_ring.lock, flags);
 }
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 39a0481e5228..07828021c1f5 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -6,6 +6,7 @@
  * Copyright (c) 2020 Google, Inc.
  */
 
+#include <linux/atomic.h>
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
@@ -16,11 +17,60 @@
 #include <linux/types.h>
 
 #include "kasan.h"
+#include "../slab.h"
+
+/* Non-zero, as initial pointer values are 0. */
+#define STACK_RING_BUSY_PTR ((void *)1)
+
+struct kasan_stack_ring stack_ring;
+
+static void save_stack_info(struct kmem_cache *cache, void *object,
+			gfp_t gfp_flags, bool is_free)
+{
+	unsigned long flags;
+	depot_stack_handle_t stack;
+	u64 pos;
+	struct kasan_stack_ring_entry *entry;
+	void *old_ptr;
+
+	stack = kasan_save_stack(gfp_flags, true);
+
+	/*
+	 * Prevent save_stack_info() from modifying stack ring
+	 * when kasan_complete_mode_report_info() is walking it.
+	 */
+	read_lock_irqsave(&stack_ring.lock, flags);
+
+next:
+	pos = atomic64_fetch_add(1, &stack_ring.pos);
+	entry = &stack_ring.entries[pos % KASAN_STACK_RING_SIZE];
+
+	/* Detect stack ring entry slots that are being written to. */
+	old_ptr = READ_ONCE(entry->ptr);
+	if (old_ptr == STACK_RING_BUSY_PTR)
+		goto next; /* Busy slot. */
+	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
+		goto next; /* Busy slot. */
+
+	WRITE_ONCE(entry->size, cache->object_size);
+	WRITE_ONCE(entry->pid, current->pid);
+	WRITE_ONCE(entry->stack, stack);
+	WRITE_ONCE(entry->is_free, is_free);
+
+	/*
+	 * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
+	 */
+	smp_store_release(&entry->ptr, (s64)object);
+
+	read_unlock_irqrestore(&stack_ring.lock, flags);
+}
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
+	save_stack_info(cache, object, flags, false);
 }
 
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
+	save_stack_info(cache, object, GFP_NOWAIT, true);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/692de14b6b6a1bc817fd55e4ad92fc1f83c1ab59.1662411799.git.andreyknvl%40google.com.
