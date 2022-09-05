Return-Path: <kasan-dev+bncBAABB6WL3GMAMGQEL35XQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B72845ADAC3
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:11:22 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf3191827ljr.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412282; cv=pass;
        d=google.com; s=arc-20160816;
        b=k5B4WZv8X0c5z/hdw8XLOlf8euIg0Hgi79rTX6peOLdfJut4YeXznb2AgNLNzQ7SB6
         4DWW/oD+E+rTwwixOEl6nj5oXCB2DyhRope3Oi5F+qU+yxMFl5FPudn7KbSeD+mxolcq
         +DXDzS/+o4p9aSkq7+lQj9/txnhfIy1YwR/T7HkN8A7RNAXDS+bISN1XFzm8YnNfWUKM
         mO5mjjh77rM4BJKz8Bz+YMn2l7/N68UhP/VqpmxbDBouhiJ2+UXKRjcD+K7NKrBgBSd4
         dJ/BjMe5Vvkm7X/wsMUHCOFBWuzlW+EcBc7+C9IrmhvNeH/OfQS3jh2rmZumbMXzuZXx
         Ti1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=feJ0KrvIEtp/YmOMq9ak++Nd9MggyBt8fEdWbanlU8Q=;
        b=JmnWsVXl59zaEBgC4QyEfomcX9oyG356axsGQPmLJkQ5scDEpXLMt7x7Hba4vdrFRu
         Z1Dntjh8Hduj7Dg5KqV+iDF7L4ZN7b5XIo4bPlnSRgsutSsp/EcBBYNEYMyRztcLE9LA
         uTYrnKaQEuzwXmTMi3z5RiBJUxir6+NjkUHR6HnOkL6NJi9jrTMuTtA+/Kk9RoBgyeRL
         yuPn/Vt1JKnHsbil22FiT3mxBDwhsdAjjeMVAhbgyHrJL2+2yYq7VoJst+aIY+Jn5tN3
         SYNp5UFvES7gS1zleoJCN4i9+HYdRW4nnGEd3xaAseEgitia7X7lVOS4gpZtLM53Vmbn
         v0jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sS1eNoy2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=feJ0KrvIEtp/YmOMq9ak++Nd9MggyBt8fEdWbanlU8Q=;
        b=UCVHnWI6YtxMixZtI8h12VJCiI4dDGDFLC9mOOIjVuIToqw94doxWy/zfu8GVj1Bkg
         wXQFbe8gqMLbzLrrW8ld+cH7LWq0DpkpxgdqkvEVMTMI6JwbZYZpPfkbgYWy/XZZ8zGf
         ziab3hnd9harx+VN92Oy2EEsFEkNcGlvrWoPzf6w32OD2lIDGNIzVGUeqzHsV0OlaLMa
         irN6f4d1hN91yF/IRsC4GQJOuV9lWL1CuRL1+S/7c2+qVKiU78FYwcvKIrmQgvBwlrno
         PVODZq/ayfdW415Qa3P5frU0YsmFYLsr32mb1gITJ86qTvmxYcK5LcacWWrlpX0Y5oxF
         vQ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=feJ0KrvIEtp/YmOMq9ak++Nd9MggyBt8fEdWbanlU8Q=;
        b=WczVZnJnI4TU5ekg2q9NJDJ52ON3Q5kmjqAkR3KhAETX/N5hy3NQ3JH6I4a00VirPV
         rUJrjHzwfeUvWjPk8Q374pUmdIfalvL3YImsj+ze71Xbyo4uDsaQMXdyyqUZ1Vzcikus
         A7xuV3dNDZkRhunCTJyIdGuK6XwAoEtBIrQwDts+ouu3DlCXVHh/NrDxOij/wGTDhSTC
         eLC+U9tyFzJIV6g3/2TUuTJIkn1EWbQCy2iIlXwS6gh0YszSp0x6Ff/yFJc0PHsqe8Qv
         cp7sVEQI+N0azf6fQAAKq7YrsjLbQAjjsF0584FVDeHBP0bKmih8GwyKNrM5+8prx5fi
         BcZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3DBKJpvRtbQ13hzMWqtKbEzhjhb84aUuGgfgRT7RvzJYpAmwOb
	O8ILMg+pHQ2LGQJJTNckwFk=
X-Google-Smtp-Source: AA6agR4JwYrIPRiSH2zYku/J4jmGI7mv9r3+S+M9TWsAC6EnOsy/R0L6qifuxFZosKuT0Vb2Uniohw==
X-Received: by 2002:a05:6512:2618:b0:492:a7a1:51c1 with SMTP id bt24-20020a056512261800b00492a7a151c1mr16414790lfb.600.1662412282235;
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e5:b0:497:69:64f6 with SMTP id n5-20020a05651203e500b00497006964f6ls193768lfq.0.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
X-Received: by 2002:a05:6512:2248:b0:48a:f8f9:3745 with SMTP id i8-20020a056512224800b0048af8f93745mr15657121lfu.256.1662412281532;
        Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412281; cv=none;
        d=google.com; s=arc-20160816;
        b=ll61qfKu/9W939gK0wcG5jpSL98ife3DaQJA/9Q2AfhI2Gu2cMe8ZlYRV/VHgixEsh
         fa8OCbqkyO2DQhxNd+wDBu85WuufK4Ji6DjjKgaf5NbnrmyzFQbSn5MFsFF25Ukp+g6H
         hXZuN8+hk4QQr9v/2WuysB//ClwlFhKzRUm37XfRXpTw1Yggph1BZcag8es+gOSqVVxM
         AVMhyJAEGwWzlmvFrLYc9rd1tn02dsIgBEuPTz9vQL+4SJ89klkhsyPSZmoeKV+V888r
         A4s8iyQUhkEhFdik7f0q+Rz151n5B9bulmZdQZuZA2wwiLI7Mpp+Sdu1b+Yf/JdPnyNs
         4b0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3TeUnHNBM/F1mPxhPvnT4XtbBDScf0nohA/7hT4/VQ8=;
        b=vlyACdCc0sGnLc1boFkoQ/xRJVqhnsOg+9JMMKRWHnPJ9vJhhpXr241dvzV+dkc1dc
         Ww7s4ZZ/zIoebEHmJqRMHnip3kMhIbhWbT5LitnodQCqfa15ggwnbShUlOxJuRHS1q5y
         FgAtIaaQ5LuXtF1Yo3b5hioQ/pZ8/CXbFxOWwI4EoBNJmkiJ/j4DDkRR3bMl+40OvjqS
         EkpBc+j7WyOSoTQQ4i5axioEQhWY4AP8pAM5BlUP6iagQNudkBpa9SPxL5o/VrCUiB5r
         pelNafZWl5pxzq3fpP+k59BCDRepvxnxDe/Q0lozXbVpb5NhGteRV5Hm+7mRDXdAqnl8
         cEQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sS1eNoy2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id s3-20020a056512202300b0049469c093b9si392274lfs.5.2022.09.05.14.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v3 32/34] kasan: dynamically allocate stack ring entries
Date: Mon,  5 Sep 2022 23:05:47 +0200
Message-Id: <03b82ab60db53427e9818e0b0c1971baa10c3cbc.1662411800.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sS1eNoy2;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of using a large static array, allocate the stack ring dynamically
via memblock_alloc().

The size of the stack ring is controlled by a new kasan.stack_ring_size
command-line parameter. When kasan.stack_ring_size is not provided, the
default value of 32 << 10 is used.

When the stack trace collection is disabled via kasan.stacktrace=off,
the stack ring is not allocated.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Move KASAN_STACK_RING_SIZE_DEFAULT definition to tags.c
- Improve comment for early_kasan_flag_stack_ring_size().
- WARN_ON and disable stack traces on failed memblock_alloc.
- Add kasan.stack_ring_size to documentation.

Changes v1->v2:
- This is a new patch.
---
 Documentation/dev-tools/kasan.rst |  4 +++-
 mm/kasan/kasan.h                  |  5 ++---
 mm/kasan/report_tags.c            |  4 ++--
 mm/kasan/tags.c                   | 25 ++++++++++++++++++++++++-
 4 files changed, 31 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 7bd38c181018..5c93ab915049 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -112,10 +112,12 @@ parameter can be used to control panic and reporting behaviour:
   if ``kasan_multi_shot`` is enabled.
 
 Software and Hardware Tag-Based KASAN modes (see the section about various
-modes below) support disabling stack trace collection:
+modes below) support altering stack trace collection behavior:
 
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
+- ``kasan.stack_ring_size=<number of entries>`` specifies the number of entries
+  in the stack ring (default: ``32768``).
 
 Hardware Tag-Based KASAN mode is intended for use in production as a security
 mitigation. Therefore, it supports additional boot parameters that allow
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 447baf1a7a2e..abbcc1b0eec5 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -252,12 +252,11 @@ struct kasan_stack_ring_entry {
 	bool is_free;
 };
 
-#define KASAN_STACK_RING_SIZE (32 << 10)
-
 struct kasan_stack_ring {
 	rwlock_t lock;
+	size_t size;
 	atomic64_t pos;
-	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_SIZE];
+	struct kasan_stack_ring_entry *entries;
 };
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 1b78136542bb..57f7355377f1 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -56,11 +56,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	 * entries relevant to the buggy object can be overwritten.
 	 */
 
-	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
+	for (u64 i = pos - 1; i != pos - 1 - stack_ring.size; i--) {
 		if (alloc_found && free_found)
 			break;
 
-		entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
+		entry = &stack_ring.entries[i % stack_ring.size];
 
 		/* Paired with smp_store_release() in save_stack_info(). */
 		ptr = (void *)smp_load_acquire(&entry->ptr);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0eb6cf6717db..9d867cae1b7b 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -10,6 +10,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/memblock.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
 #include <linux/static_key.h>
@@ -19,6 +20,8 @@
 #include "kasan.h"
 #include "../slab.h"
 
+#define KASAN_STACK_RING_SIZE_DEFAULT (32 << 10)
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -52,6 +55,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
+/* kasan.stack_ring_size=<number of entries> */
+static int __init early_kasan_flag_stack_ring_size(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	return kstrtoul(arg, 0, &stack_ring.size);
+}
+early_param("kasan.stack_ring_size", early_kasan_flag_stack_ring_size);
+
 void __init kasan_init_tags(void)
 {
 	switch (kasan_arg_stacktrace) {
@@ -65,6 +78,16 @@ void __init kasan_init_tags(void)
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	}
+
+	if (kasan_stack_collection_enabled()) {
+		if (!stack_ring.size)
+			stack_ring.size = KASAN_STACK_RING_SIZE_DEFAULT;
+		stack_ring.entries = memblock_alloc(
+			sizeof(stack_ring.entries[0]) * stack_ring.size,
+			SMP_CACHE_BYTES);
+		if (WARN_ON(!stack_ring.entries))
+			static_branch_disable(&kasan_flag_stacktrace);
+	}
 }
 
 static void save_stack_info(struct kmem_cache *cache, void *object,
@@ -86,7 +109,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 
 next:
 	pos = atomic64_fetch_add(1, &stack_ring.pos);
-	entry = &stack_ring.entries[pos % KASAN_STACK_RING_SIZE];
+	entry = &stack_ring.entries[pos % stack_ring.size];
 
 	/* Detect stack ring entry slots that are being written to. */
 	old_ptr = READ_ONCE(entry->ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/03b82ab60db53427e9818e0b0c1971baa10c3cbc.1662411800.git.andreyknvl%40google.com.
