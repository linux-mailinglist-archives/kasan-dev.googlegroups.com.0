Return-Path: <kasan-dev+bncBAABBIFYT2KQMGQE7NCAIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 56CC5549EED
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:20:49 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id p42-20020a05600c1daa00b0039c62488f7esf6401649wms.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:20:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151649; cv=pass;
        d=google.com; s=arc-20160816;
        b=oc1vSG159r9Pvry9pqNymWtNHmmXHrAaXnc2Et4pJawFW8+Pk2l80iVsyjjM8I2Z+c
         /mZEVyebgIoOH6zalTy9S9+YOVwLd44cLgzzL9ao1d5ufI3LhJV4ZGteopcex1BQeZ2A
         cvgoAzw5YWRPLoPHV69zT3zQuOa/dzhzN/c2f3djIqw2IhwmpaUBjj58Z5Op0YGjYS57
         C0cca0gKTTtvTvt10WFHbdLy1Pcl7pqNYIP6cgj6FOU1wfhtDhKiYTnv7ah5qIOx0Idh
         hDJuQ3qB7746xa1j21GTCXyE8mNc1Aw/K9ySkv288yXqrSn318GtusypXNE+JoWBqIwg
         F3lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JxqXFxZlMCRDoIDYidM1NInLDLBdHmySEfWjggcX+G4=;
        b=yrlAax4HrH/akr2EHo4st8ZOFwBVybp8KoSAEQpFwISViSTBKz7FPPXNB5UDRG4IMJ
         nfOgJG4xDy30jy316PCmLr4LVMq2x0ap4AEBMzlNx5PeOE+lomUXdP9xcssgXXAYo7+z
         bkM2P+qk7NrLeSG66d1a0gFA0FEDkTjCbbKqDyGT/2xUuWaHnYZzEA+6r/nMz3x8GjDV
         1x9HbTPG6DiXCipdxo7Fpzkyy5F6C3aM5TD/B5Acw0/syCznYrP7B+MndYTdsGn1pdlQ
         HgbQ3ol/94p2pVyUEfhM6dGqpEY6usiw5qgx62F3EeKHmM2/LoKyy7wzUNa3aSNh6mIO
         NeYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="f5d/7XtU";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JxqXFxZlMCRDoIDYidM1NInLDLBdHmySEfWjggcX+G4=;
        b=oadrJsxYRi/O6Jq8FTg7ZoIzf5Q78cjBm7NIFDkzL1GLRwHpi4QFIE0vxPWZe2yCmT
         YEJBTVNBWk4+T7rPZuaxQLyX0a9dXwZxCvGp6d1j+7IBj621iuZ6YCfCn4+vuLx+/hbq
         9064G3AcMoKDDR9Jv5VXjecbHXMNdszSRsbuC6yIyxEHkfX3X3XfI5PnFmgu5oX+2tnW
         OlhZLG8f1kWusl49rnV1M4kxO4uiYjs9M7cgd6ZRXtIubODhCGzQ40vEQ+c/XUcy3Eec
         tIuxcZtFvrqhvXT3kceg2aTC8e+1BwucEb9+qhvZCC6QE8pm1aUdj1wKWuW3h5FS3cr0
         Z6Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JxqXFxZlMCRDoIDYidM1NInLDLBdHmySEfWjggcX+G4=;
        b=aXnVij2lehWwe1W9dLJM45wzpYfNST2x+o2TRpjufJw70pvonFqa4ajvEtOxIfHu3M
         jA4cfXcB8VHVCuGkQz12ChPsbHq0xD6c4FMsIUC3TwqMOtXkP/CcEFC5Nn9Errph1CV+
         8XEmO/0Pt8EXSL1vLYlwrAEHa7VXmEpa2O3n7ZFPqvhWCqxem8hhsen2q+s+UJLu96HM
         7eCw3L48q2t3axxRE//EovtgzesDm7jRIDQxXxEmSQWmiZVBq5lHDHw7X5fPIT0lGtWd
         uneddlNhsNfgVbIJvULs7hXtlkCJqtSUx79CN4V5S5/Uope+yvsRplild7QOPlvGRLSb
         knxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+tu2sH+FnCh1QWnEqPCiBY1u21oB3C9aSD5asGA5SqGKeFWmHd
	xVr2LoSF4fL3j5jBcujikN0=
X-Google-Smtp-Source: AGRyM1sXy/A6mDwG/FsuwFwGq7pIvVxxXp9rNuOsEqbytOG8I8QacRaPfIUqsSN2ce4NLGP9vvPXmw==
X-Received: by 2002:adf:fb46:0:b0:210:2316:dd02 with SMTP id c6-20020adffb46000000b002102316dd02mr1382890wrs.557.1655151648967;
        Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls7058868wrs.3.gmail;
 Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
X-Received: by 2002:adf:d1c6:0:b0:218:4fc3:a805 with SMTP id b6-20020adfd1c6000000b002184fc3a805mr1442371wrd.228.1655151648377;
        Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151648; cv=none;
        d=google.com; s=arc-20160816;
        b=LASDSvtHMxT4+T0Dqy1MbRhmaZbb6jDUUX+nTcGcg4hWn46DzP4Z4RQNsJ1ZPcRm4N
         yiNv4aaeQSm3tBnezFnV5T0RzHiNn21PqlkzASZme1zaKIAGtORc07PbQpyqNirILCnv
         lB4WeAo/AEzS+5+UGPdk70YDYZGA1alFCZJ5s//QWPxJ/omVjYDTyRRGQ7rCEhXfxe1v
         E8VzyvkB65NondVppLaEFzl3JDN4zGz3QfAo/UosgGLc0+m+vYMxbN6wM8mpua3mtiPK
         9664datbDAGQ3KHKTRuVoIkEx4ed1W4VbaciYILzmRWiAp35h8dsyX7iYhliKTtiHEev
         9lhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OqOHaer4kC3Iywced9lKgHi/whHdzXvvFFVWcKJPrko=;
        b=B70vdUfWhKZYoO6HJEg6zpoQ15ipeUZIRqrmC1qII0qcgtF4rgG+8h1jMn2HnwZ2E/
         KDa9YyTxI8mXJKwoo60CNrE4ACMAF/p4xndKbxWwYfbeyZRCbrXGHVipV1cNi0Ilp9jq
         QxJJ+sA0VXN2ozN8Ov4o4udn77qX3EIQ33b06mayk2LYoUMaXAvJI1pmAyphuT1hDynK
         FMbMaQLLwSH6ZKPDgHrehJm4MRKzlzsfqHVe/qyXoC8tNsyOI51Xhzdakcqa6uNtqA2M
         QOke4FRF6GU8krPcm4k32KZUtpsyLHlWTbvFjO6QSBXlAtexmlfWYD5T9eocpgchgbrO
         O2rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="f5d/7XtU";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s10-20020a05600c384a00b00394803e5756si245474wmr.0.2022.06.13.13.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 31/32] kasan: implement stack ring for tag-based modes
Date: Mon, 13 Jun 2022 22:14:22 +0200
Message-Id: <3cd76121903de13713581687ffa45e668ef1475a.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="f5d/7XtU";       spf=pass
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

The ring buffer is lock-free.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

The number of entries in the stack ring is fixed in this version of the
patch. We could either implement it as a config option or a command-line
argument. I tilt towards the latter option and will implement it in v2
unless there are objections.
---
 mm/kasan/kasan.h       | 20 ++++++++++++++
 mm/kasan/report_tags.c | 61 ++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/tags.c        | 30 +++++++++++++++++++++
 3 files changed, 111 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c51cea31ced0..da9a3c56ef4b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -2,6 +2,7 @@
 #ifndef __MM_KASAN_KASAN_H
 #define __MM_KASAN_KASAN_H
 
+#include <linux/atomic.h>
 #include <linux/kasan.h>
 #include <linux/kasan-tags.h>
 #include <linux/kfence.h>
@@ -227,6 +228,25 @@ struct kasan_free_meta {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+
+struct kasan_stack_ring_entry {
+	atomic64_t ptr;		/* void * */
+	atomic64_t size;	/* size_t */
+	atomic_t pid;		/* u32 */
+	atomic_t stack;		/* depot_stack_handle_t */
+	atomic_t is_free;	/* bool */
+};
+
+#define KASAN_STACK_RING_ENTRIES (32 << 10)
+
+struct kasan_stack_ring {
+	atomic64_t pos;
+	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_ENTRIES];
+};
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 5cbac2cdb177..21911d1883d3 100644
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
@@ -24,5 +28,62 @@ static const char *get_bug_type(struct kasan_report_info *info)
 
 void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
+	u64 pos;
+	struct kasan_stack_ring_entry *entry;
+	void *object;
+	u32 pid;
+	depot_stack_handle_t stack;
+	bool is_free;
+	bool alloc_found = false, free_found = false;
+
 	info->bug_type = get_bug_type(info);
+
+	if (!info->cache || !info->object)
+		return;
+
+	pos = atomic64_read(&stack_ring.pos);
+
+	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_ENTRIES; i--) {
+		if (alloc_found && free_found)
+			break;
+
+		entry = &stack_ring.entries[i % KASAN_STACK_RING_ENTRIES];
+
+		/* Paired with atomic64_set_release() in save_stack_info(). */
+		object = (void *)atomic64_read_acquire(&entry->ptr);
+
+		if (kasan_reset_tag(object) != info->object ||
+		    get_tag(object) != get_tag(info->access_addr))
+			continue;
+
+		pid = atomic_read(&entry->pid);
+		stack = atomic_read(&entry->stack);
+		is_free = atomic_read(&entry->is_free);
+
+		/* Try detecting if the entry was changed while being read. */
+		smp_mb();
+		if (object != (void *)atomic64_read(&entry->ptr))
+			continue;
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
 }
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 39a0481e5228..286011307695 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -6,6 +6,7 @@
  * Copyright (c) 2020 Google, Inc.
  */
 
+#include <linux/atomic.h>
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
@@ -16,11 +17,40 @@
 #include <linux/types.h>
 
 #include "kasan.h"
+#include "../slab.h"
+
+struct kasan_stack_ring stack_ring;
+
+void save_stack_info(struct kmem_cache *cache, void *object,
+			gfp_t flags, bool is_free)
+{
+	u64 pos;
+	struct kasan_stack_ring_entry *entry;
+	depot_stack_handle_t stack;
+
+	stack = kasan_save_stack(flags, true);
+
+	pos = atomic64_fetch_add(1, &stack_ring.pos);
+	entry = &stack_ring.entries[pos % KASAN_STACK_RING_ENTRIES];
+
+	atomic64_set(&entry->size, cache->object_size);
+	atomic_set(&entry->pid, current->pid);
+	atomic_set(&entry->stack, stack);
+	atomic_set(&entry->is_free, is_free);
+
+	/*
+	 * Paired with atomic64_read_acquire() in
+	 * kasan_complete_mode_report_info().
+	 */
+	atomic64_set_release(&entry->ptr, (s64)object);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3cd76121903de13713581687ffa45e668ef1475a.1655150842.git.andreyknvl%40google.com.
