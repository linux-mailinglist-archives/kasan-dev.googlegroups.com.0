Return-Path: <kasan-dev+bncBAABBMHP26LAMGQEN2F7JJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E849A578F11
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:15:44 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id h189-20020a1c21c6000000b003a2fdf9bd2asf6053289wmh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:15:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189744; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjddcbdesdnSlhwz0ZyP5gCXOHrqFdOgQLc4jV56Wbawbs9he1ItiP7VE11QfZrsXZ
         0ga+bAtXt5iFhV5RodPyQM/6Vg1zfg0P6PAsx+xDTTwPbO7RmGbcJi8FpoKONEArbkru
         Ims4Zr1/s+wbwmpneV662xC35uRDF+OjHwhTfQJmC4VXHBq5pacHixXhEehfBJnQkDfy
         UC95nXK8L4zgQiVyLgdWxMl7MIXhM17nj1cmwYpIyfbYmeDik5ufVbIPbQuVw3NiT8DX
         3pK7CHobkpOXLmKXUijcCWE3EJ6S5q49xmWisdnDvbYtVlSpQId1JkG7ApWnXLblOjZv
         DmmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OGGGRgVfhbbCKNtj5zGZvU1S5J3H2PCZGDSqT1+RIvM=;
        b=uTPc2TpyW0a9KeaV7Qk+ZpWV54lIJJg3VCA0KeDtBycYjPDciyZyjKpstRds7rPHOg
         4YgUXSekrj5ind7QDBhEjFamcx3TcePeCZsyft/Nh+VG0fPUiqY3rN06Z/gfAlJ9jBiM
         RPOgFiHZlQYQ+pkqxEJwFcGGd/YSCbkpMJH6rfGYI/xbq/pe4w+FLihxMO5IpjAeKTUY
         +wE6MdsaWZg8VBJPeJ54prZEBQCVu8cMWj65DNiwxoUMapaDPQfRMd8pSGgtqIgbvQ/F
         1Z6oq7mzhSaHapHAko8HFPlTpuVpuU9qGJDF0by/pNlkGPH2XJo6Imgjgf8u9osccUmr
         Bbiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iQMr4m8k;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OGGGRgVfhbbCKNtj5zGZvU1S5J3H2PCZGDSqT1+RIvM=;
        b=YdKV/5Wl6BxOIw5rXmr1QIFN/+ou/8u6cyvwTNY26oDbVMHqjtbdxSwAqH+XtfEBbl
         CHkhmyazcsucsQIpGQXHMB6CXDvNkh1KC7wPSQ6Lh4q6v7Z41Z8/nMO8IeiYdeMfBFBQ
         QEGtaLRSBndQWs9hUvPhl5ncmvMd0MmV6CuIP2hzp1IXgHtVZYLYAH5EsMxk5Siaals0
         Vtd7RfxZN2ecmcZKdLb4M7LYLJrKdJYXnbp+MkDiZOm/rHH3IBLKMggaoADZTnPxiCL+
         h+/viX2I1FhskqBDvGL1k+5yx/Gl+VU5OIlIXjcV/JlME4Netm9sNLg/bOm9qmlkd5Yu
         WRFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OGGGRgVfhbbCKNtj5zGZvU1S5J3H2PCZGDSqT1+RIvM=;
        b=Klos5h/wxKhJ3ubc68qDp1FEnFNhfv0nb2zYgFjVNHYohMYaYflmhN7gB76s76K4ud
         gkP8hwQVJ5pF/37+eRHRz2XQArLfcmARtyk9BCpaf17SjK4cTUoZ9edf7se9++DC92rH
         h3zybZd6S998HG0i7P39ziet46aB9SUAGGt/psWHIqfsQ02L2c0Vd25Fq+y6nBfreDp1
         3EDftZWU3+FbkNrgcvlsAvabFP8zVBkGQFFl41qL5VwI6LAbjgpjX1asI5fb9sVd3bm4
         o6aj4SY70gX00h+KhYXv4664QMKdZBZz7hPxhc8/YCPFQKqHULQeGjAoX8G/naKuJCcr
         F3AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+MOGYOr5vt9IFzBtP4VUQbV8qeCdTmSkhQ4P4qmyfn//686yyd
	P1Fg7vadEkBPFrLYNhe79Hk=
X-Google-Smtp-Source: AGRyM1uDnOmO4as5a2278/YvZlV2+GRUgICgNwr6kWMKCGCHoG0FmHLAjLNRNTKY0aQ1TX09LbSgFg==
X-Received: by 2002:a05:600c:1f08:b0:3a3:1b00:c201 with SMTP id bd8-20020a05600c1f0800b003a31b00c201mr7014574wmb.171.1658189744626;
        Mon, 18 Jul 2022 17:15:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e11:b0:21d:934a:17b with SMTP id
 bj17-20020a0560001e1100b0021d934a017bls14156wrb.3.-pod-prod-gmail; Mon, 18
 Jul 2022 17:15:44 -0700 (PDT)
X-Received: by 2002:a05:6000:180f:b0:21d:68f8:c4ac with SMTP id m15-20020a056000180f00b0021d68f8c4acmr25140786wrh.193.1658189743982;
        Mon, 18 Jul 2022 17:15:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189743; cv=none;
        d=google.com; s=arc-20160816;
        b=ICUFrX+NAbESOLTxKhEZ8KSqbe7KXkJkXA1v4zYdkXGx4MRVbJLWPKs3r+zGGXlX4p
         kzIUhuQTwQ+SAjWoKiJfaNybzYhHRUN+rKuCZaUp2ML/ho3EsE8fGSHt0vrNdQ6+AOMJ
         o+Sf8lqmznwM2Hscf4pvjijA2sP9mDDI3Im7oigadSgtZHBj3DThqH7sYwGzWwIfsFMV
         HIfz99AFOWL24mCrHBHfVKLf3QPuaI3HJVB0idqJExj0YwFuj/VVyRdT+oDeeOf6FQL2
         6hLr8pSomz1YrBb3Dm3r3eAORJ764vAJ4sVyzjuXrsPWnm4pX6AziTH6ZUmdtSTQAVN6
         uf2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WzZKkdAFPRpFrhztX0frHyUgTspT1AIBFjL43I0Kz2k=;
        b=ZZROH9Y6IuaONp7wB4rxMBRRyoyJJre52nvhH4KqMJxwH1yK73XygRR3squWMeFs7+
         KFcJ3cEElb3mkJaT4XrmUmciO8bdZQ1uhYu/sV0LJEzMtg47yYfTco1oBcZQJVQ3Cg/Z
         KcbGvU9zZR02UuYWKfBOpsDKocAyBV6ExVqd59J3YZ8WGnSzdwS06PzjRFzSxc1H6c1p
         uSeAzvOjdA28PnTlFF0poWBECAuRkoS+qvcfpwJtwbbtO24QZkv414irFU6W6SZTAJPn
         qnyQkMxxRQW/758+UxNmkZDgH7sO3CAKvpawjoKb2YSF3vHURMCy4F20Y9utmddg+UAK
         lEPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iQMr4m8k;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id w11-20020a5d608b000000b0021d9f21dd58si410111wrt.6.2022.07.18.17.15.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:15:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
Date: Tue, 19 Jul 2022 02:10:10 +0200
Message-Id: <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iQMr4m8k;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes v1->v2:
- Only use the atomic type for pos, use READ/WRITE_ONCE() for the rest.
- Rename KASAN_STACK_RING_ENTRIES to KASAN_STACK_RING_SIZE.
- Rename object local variable in kasan_complete_mode_report_info() to
  ptr to match the name in kasan_stack_ring_entry.
- Detect stack ring entry slots that are being written to.
- Use read-write lock to disallow reading half-written stack ring entries.
- Add a comment about the stack ring being best-effort.
---
 mm/kasan/kasan.h       | 21 ++++++++++++
 mm/kasan/report_tags.c | 76 ++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/tags.c        | 50 +++++++++++++++++++++++++++
 3 files changed, 147 insertions(+)

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
index 5cbac2cdb177..a996489e6dac 100644
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
@@ -24,5 +28,77 @@ static const char *get_bug_type(struct kasan_report_info *info)
 
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
+		/* Try detecting if the entry was changed while being read. */
+		smp_mb();
+		if (ptr != (void *)READ_ONCE(entry->ptr))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl%40google.com.
