Return-Path: <kasan-dev+bncBAABBTW5Q6UAMGQEPVDZT6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B17BA79F046
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:18:07 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3fbdf341934sf180175e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:18:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625487; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8si4Y01DpSngM/AhzPmA/vOSKJnwv3cCGh3kqEttAPgoobUwJByddsjmEzdc3JHh5
         kVi2i1luvu1wwA1cpIum22PrEzDa5VFZkj5uqGRhaEpKTFCJxALQAry2rDs2EXMgOqME
         mUbjJ0YRaxQgHqs8WUKkp8wXi82C233YIY7m1A7JyJ7L5sgWVdaSEQNrBBG/iZ3c51+Z
         LAJLSchvrlWy2ADfLs8UCHFqghi84l/C+dC4824YzDgDR838XjZvk/LWfnGkj6JQaDTZ
         Q2wWQFlACs+r2JidYu/rPPPzhcnZvqEghU1regDCdyNEE8bBjkXsaoLufWk7kKIHvAXe
         Jskw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2MpyHaBywdh2ZcQCk1NSgST+Utw9TuD4g+8ltIugloQ=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Xc7HIQjvZdpDE9ZlnxqKUk1xDIw5dN6rzwUtkd2q4/7uFpoZb1Y/zUOmN3XbRLfxWl
         LzNEHZP3JaCHXLT/HjPFYJ669sIkb5+q/zCDFLSjC3Y9BBLj0C/VJYJyN0+DxDsEnNEg
         CCruzyQfMLGG4bA0DBxU1w2+2huCUwCrc5L8MhD4mHvSlZfwTFfcSwQaiBSVyrrALfhK
         WgmvE6nDjuZhXQ0+jbxVQlMyMcIM58I1ib7s7O98X4W2USVGQYe8jgLUwXZ6ye85g3z4
         ncXZ43Qzn/0+DgcnsGYfGfiKHKeCfgtiW/kBruHLptXX2ZYxiZfk4NvUFKrn/Elq+UuS
         boyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aOUyG6zN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625487; x=1695230287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2MpyHaBywdh2ZcQCk1NSgST+Utw9TuD4g+8ltIugloQ=;
        b=G/21q8hw+NMFUfsvq6L1zoYBHJA7q0CX3OFVY98rOixBsw5GELEZBtyMQSWj4HcmVD
         TG5RYdSmG/gDdrhu0szP3qAnE/IOjtyohp6zfwUyS8Rczr7d8HgPcDbUvTCLcB5ZY8CS
         vAfllGm8qrknh+hf14P4tFs/mHPnF7Lx8nPQ0kp6OC9WChUs6CI4Ias55s3zRDehMUbw
         42PcQoMHK+eT0VyoG3b1uPiSP/861hWJFs68bXD8snbbE+f/9o0U1rOvBk8MmsQJ19hz
         FBXGHBE2wwDAcLt9J63SEDHhlYvmuzZXksxY0vRJD6OE3RpP6YF8vUmKLBOFw580ekhy
         JVgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625487; x=1695230287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2MpyHaBywdh2ZcQCk1NSgST+Utw9TuD4g+8ltIugloQ=;
        b=sNhuah8V8UJ9H1D4ZlnRH/tjdI/Zx8HQKDzqkaYtwMdn84Y9zalt94nqKwbVOczBVT
         C9oa1eKfC+hxR7KXGW+K8Ragogj51bjnz9bTH6BI/+kmJ3sEoFhn7RcxSilSDiFACUld
         YPGilYjAqPxfsPwd+QtYzUDWKJxOeSp+H4OprvGFoG8LkiG+bXt7G5KVGpp/MZ6+4HWx
         41sV6fz4rm4N4Ti4Wp0EhURxc4Z2fOSDyyTy01T5kOP3SIaf7gYmsVfcN0ZKDHYTQbGe
         yOYFkELC/YyTPjPxO0d6d38GvTWt+v5nshcQX6NjR9z8iJBqguOpX+TyPJZ6NEk9s501
         J6wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzTA96U1ToEFEHiWxt6jX8EYhH8n0z+SfC+OCV8l+Hrh5dVs2Pu
	KN0jCge/mXsxPipJeril4yA=
X-Google-Smtp-Source: AGHT+IGL2FjK+fqG78xkw+U33Dd6AIK1GM4sojJPlphFJQ1JxYl8evtisAKHOp0XDOhEMtTEmYt5tA==
X-Received: by 2002:a1c:4b16:0:b0:401:1066:53e4 with SMTP id y22-20020a1c4b16000000b00401106653e4mr2527395wma.38.1694625486820;
        Wed, 13 Sep 2023 10:18:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c0e:b0:3fc:1365:b56d with SMTP id
 j14-20020a05600c1c0e00b003fc1365b56dls1862490wms.2.-pod-prod-09-eu; Wed, 13
 Sep 2023 10:18:05 -0700 (PDT)
X-Received: by 2002:a05:600c:2902:b0:401:d803:6243 with SMTP id i2-20020a05600c290200b00401d8036243mr2510722wmd.32.1694625485658;
        Wed, 13 Sep 2023 10:18:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625485; cv=none;
        d=google.com; s=arc-20160816;
        b=KNZz9T0Lg3m49kDX7nQsTMmVP7h9IDSIdWYhxrg1uSrFkMrtnAAzLc9/DrGlbYeACa
         eEcXL2IneYtyq6lRR/kdE7vczJxRPmMR8qN2Cm8ZQnbPXiffCFLK6M7A3EVKd1BsBm3I
         hOnK/Zh0gVjADjOb3EPDLbb1daAD2JCvl5Q0UYOkw/6vhxzvZBc34cHf+bzRZUAfg1fz
         sZ0wUnSIWZltVCOjKUP3D/SMB7OCQaFROdZWB/K73JKou2kqkN/fYqJSRYQpSteL4FAK
         L1GdNE/k3miJXXo1iX5PutPrvWWbfF5Gh+GClqIed7yN5AIsyofNXkU0a0ICK+8zBhih
         B+rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qjH3MV6DYl1G1UYfCD5hIyhq0uUm2VbQwACKU2fMzJc=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Ln0IptBzXbfk8UXU3RU50zhNEpM7QFwopFUkiT1RRbs+PWfPlPpHqRI6ka/gBbc2BH
         Ftl8IHoXh0EBiOrRMmIJCSLKEWrmLyqMPHW+O985yrwzx3aqA5ThcELs2aQ7ZRDI7MBJ
         wbBffI8mfJuS9IE8wvAkuDQkpVD7ynX2x3kk/Z5hAtm4ONwdOv+U4EK0D8ah6DTAXgbr
         xAPLlBrJXX7Oayw6LprZAN4fdU1aPhHD5u9vBfw6jtz/rlOZj1upB21A0AAtuRw2Np9d
         ExhvO4e3Hc24tNtAjZYmbij8e/bvRsJujBLn7Srfi94FaAGblPzQMniwWCbI98bdXIVb
         WmVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aOUyG6zN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-210.mta1.migadu.com (out-210.mta1.migadu.com. [2001:41d0:203:375::d2])
        by gmr-mx.google.com with ESMTPS id az2-20020a05600c600200b003fed6917d56si241652wmb.0.2023.09.13.10.18.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:18:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) client-ip=2001:41d0:203:375::d2;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 19/19] kasan: use stack_depot_put for tag-based modes
Date: Wed, 13 Sep 2023 19:14:44 +0200
Message-Id: <6e2367e7693aa107f05c649abe06180fff847bb4.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aOUyG6zN;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make tag-based KASAN modes to evict stack traces from the stack depot
once they are evicted from the stack ring.

Internally, pass STACK_DEPOT_FLAG_GET to stack_depot_save_flags (via
kasan_save_stack) to increment the refcount when saving a new entry
to stack ring and call stack_depot_put when removing an entry from
stack ring.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Adapt to the stack depot API change.
- Drop READ_ONCE when reading entry->stack.
---
 mm/kasan/report_tags.c |  1 +
 mm/kasan/tags.c        | 10 ++++++++--
 2 files changed, 9 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 98c238ba3545..55154743f915 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -7,6 +7,7 @@
 #include <linux/atomic.h>
 
 #include "kasan.h"
+#include "../slab.h"
 
 extern struct kasan_stack_ring stack_ring;
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b6c017e670d8..739ae997463d 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -97,12 +97,13 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
 	unsigned long flags;
-	depot_stack_handle_t stack;
+	depot_stack_handle_t stack, old_stack;
 	u64 pos;
 	struct kasan_stack_ring_entry *entry;
 	void *old_ptr;
 
-	stack = kasan_save_stack(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC);
+	stack = kasan_save_stack(gfp_flags,
+			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
 
 	/*
 	 * Prevent save_stack_info() from modifying stack ring
@@ -121,6 +122,8 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
+	old_stack = entry->stack;
+
 	entry->size = cache->object_size;
 	entry->pid = current->pid;
 	entry->stack = stack;
@@ -129,6 +132,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	entry->ptr = object;
 
 	read_unlock_irqrestore(&stack_ring.lock, flags);
+
+	if (old_stack)
+		stack_depot_put(old_stack);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6e2367e7693aa107f05c649abe06180fff847bb4.1694625260.git.andreyknvl%40google.com.
