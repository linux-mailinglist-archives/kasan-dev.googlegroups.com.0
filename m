Return-Path: <kasan-dev+bncBAABBNX2QOHAMGQECMIUKWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B83A847B590
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:01:26 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id n6-20020a2e82c6000000b00221698ffa68sf1867361ljh.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:01:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037686; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+FVH/q6XHbbTtQNLUIAb/EAKrjh7fQztncWsEgT/XzWQCJReKnkmSlzvuvZwp85Zc
         eUjDd7qMlm7LSihmHSa4gMxK+UX1AP3ZJO+D2fsZd1Xn3BvItaWJqOx49JDy7bZ3J9k4
         B1KjbHLBtBvjEVwuuRF4J3mRZE2nZdxvsMHcsQCqBz0AhW8RoNaNVyeSH5umALZN9k+2
         jg4VvTmYLK1/zrUfKCtdXeYsIGKh53tMtVVekpU11wJC3ciYiNa+x70og3xWLsJ2MdkH
         57eR8HmNS2Ab1tJsU03Wb3Nmj+1IpTbUSZ/XGB/mcmwEigsbod65kzfcOReWKm2GjI8N
         9R3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nxg2DmpBtcp76paTMHXo2V/+q9LL3s5IaIVRxwBBwf0=;
        b=VkJwTtaPBdfZVqnmSmsFPjgMtTHD0AX5ktcXv/tID5qqFEM6Q0HWV+uX1lh6l8np8E
         X8PEFiZVI3o7wkJMr4CyXVx4A9RvvAAuLYoQZbaFmbTeAcCX7NFesXKQvCzrPi8FX/2a
         uBhw0ZWdvy+zK81tlsWpT/gtvQ9BvcTIixATpCXYsrpqE2K5yQO2W7ie31y8Hqn/cTVR
         +CLrklU+uKqhLxmHQgpyKlXclMWLCf6pSC3m9ufXmkbguWD7gdmZtvfyPM7c0W55vKut
         u0G0y2Vvei3mTjb8Oq6++0IHquM55nxhp/4tNCY0mIZIr3Wwfmsl6zx8IlA67CnGsh1q
         grXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nM+WCsrb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nxg2DmpBtcp76paTMHXo2V/+q9LL3s5IaIVRxwBBwf0=;
        b=QxoXJwyQw3gX+i+nK8HLhFQXx5shIcYtdqloS7IuFFLpmJxXy2U6fWZWfzbbQOiYyP
         FwU06HF2Q+RrYZtn/Q3KujwUBGPBBkROX3Q0a6G310pGERQuU+HNYzDWSc6kKm7wi1rt
         pW8kuw17zaugm89W7nKNqjAdqfSz6wUquhDijDul1MW6wQ14QnF2swyl6P2wyhXfH5R2
         eY3jfZOWLhBIGb3GSSN9Qm9CGRGdIxwA6hxT8iHI5Vn4S0CjRr2Fi8RZAInA03TjI3XU
         hyy42FtudEoBooHh8rE/ZuZvyJJsVTfdkz+HP791Epn/Nc/zyTVaoSzXZE4bZryQkvld
         CHdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nxg2DmpBtcp76paTMHXo2V/+q9LL3s5IaIVRxwBBwf0=;
        b=1XiW0wHH8lSVEMWRUgNNM030eiBD1JX94cYA600Iu0bQ8+jDP6i1BM/vLoSRAhYWW8
         5UcmNTWwbyXvIAekYE2HrN0Q3KFEgy0fBBCQvNBWSN72v1JmjDFvaVKGtclq7oeuWbkc
         PMB3OtDBn9BeFIbvAvx57HAYgqhSV9fLgr5b+4YRQVWD5xPGZjFGTlE/rDtpWyQ4jBI5
         c8NFw3MpO1La7tSq8a9YvDMUoCRC6ahDQMfpkPubjS8xVrXg0Shh0qTGzmaAmK7zkRhJ
         Hvn1k3DumvcuEaQ5PkvP/a2uN9tgvsl2o8LLuoJNjNIU/Wm6f20KkrUu84kWwK93xnpM
         Vv3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532258Dl9jmlSjCJ5iRbDzn/gtvip4q1RuNseyuGFOg3UoqqHoPO
	i+gVUivYQRivplx/iLiZ+q8=
X-Google-Smtp-Source: ABdhPJyBbCtt8j8vwK4zR+pgu6hzkOzrHaTqrXzxxHJP4JZ83JVYE5eRTY3EnUYBAppJfLcrQh5XQQ==
X-Received: by 2002:a05:6512:2255:: with SMTP id i21mr166186lfu.514.1640037686321;
        Mon, 20 Dec 2021 14:01:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls2688770ljn.3.gmail; Mon, 20 Dec
 2021 14:01:25 -0800 (PST)
X-Received: by 2002:a2e:90d0:: with SMTP id o16mr54484ljg.339.1640037685521;
        Mon, 20 Dec 2021 14:01:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037685; cv=none;
        d=google.com; s=arc-20160816;
        b=YefuQTb/9x8QoRQ2DTB9WHVTxR7PVK/eR7txd7PnpwvGGMcXm+ZbYTeIfYc0lrvx5k
         gSgg22v6TjfJJT1AEGRnBpb1FbibSNNmbUcuSYkPwYbIHKzA68xrd1oYjHL6WSpq7Pvt
         Twu+i9lbaxAC7UCzafJKIjuA5fwH4EoI1WqoOT9+gD5dsKWLkRb3fmR5YSnfl9G+edvy
         lAjBcp1n97NsqABfdiDhohLdxP1kb1ijzN7N/mxO0jXCMBJBOBYuJhcbFX/+Ej2O4Kze
         tKhlPhKdGFZoaMKXhLXEt4nMpMxz7FvGeFvmTxE2k4GDM3cMP58wVWzr7hJgVj+l5Swa
         /3eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Fqv7h1AsG69rF+aj+JZZwHLPN8HF8k/gQwZkoiZyU8I=;
        b=qX2QUIDc2mgj1EaHMQKW3ofl2jDjImBCIn8saJLttk+/xdv1r33f44817GUZb9DZMt
         v/3DVHoDGFN7LD05igkRySYZCfcKu/Nb2QyPp2HhGawjlrZe4Yi2iGRTRL6LY8mYOfE8
         3EAAOYemW9zu+R6MUqvN+As63SU12thE35XIHmjs6oUH5CawLQYVsCCXsQ8fLC0pqlaM
         DpWBwYW7bA7FBsQhUlnhk+6f5OqgM2wKkMl6ThuVx27UHK4KPONVj6IXUxJERf/8i50M
         qXM2l0SKqmhPU7n7HTxfnL1mH51+Aah0Gs5NhuytmJ9M5BOdOvR/3nGzWB1kKrb5Tlil
         AboQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nM+WCsrb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id r15si566719ljp.1.2021.12.20.14.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:01:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 24/39] kasan, vmalloc: add vmalloc tagging for SW_TAGS
Date: Mon, 20 Dec 2021 23:01:03 +0100
Message-Id: <2680386eab3abc80bead51b45fb92fc2dff03a3b.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nM+WCsrb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Add vmalloc tagging support to SW_TAGS KASAN.

- __kasan_unpoison_vmalloc() now assigns a random pointer tag, poisons
  the virtual mapping accordingly, and embeds the tag into the returned
  pointer.

- __get_vm_area_node() (used by vmalloc() and vmap()) and
  pcpu_get_vm_areas() save the tagged pointer into vm_struct->addr
  (note: not into vmap_area->addr). This requires putting
  kasan_unpoison_vmalloc() after setup_vmalloc_vm[_locked]();
  otherwise the latter will overwrite the tagged pointer.
  The tagged pointer then is naturally propagateed to vmalloc()
  and vmap().

- vm_map_ram() returns the tagged pointer directly.

As a result of this change, vm_struct->addr is now tagged.

Enabling KASAN_VMALLOC with SW_TAGS is not yet allowed.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop accidentally added kasan_unpoison_vmalloc() argument for when
  KASAN is off.
- Drop __must_check for kasan_unpoison_vmalloc(), as its result is
  sometimes intentionally ignored.
- Move allowing enabling KASAN_VMALLOC with SW_TAGS into a separate
  patch.
- Update patch description.

Changes v1->v2:
- Allow enabling KASAN_VMALLOC with SW_TAGS in this patch.
---
 include/linux/kasan.h | 16 ++++++++++------
 mm/kasan/shadow.c     |  6 ++++--
 mm/vmalloc.c          | 14 ++++++++------
 3 files changed, 22 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index da320069e7cf..92c5dfa29a35 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,12 +424,13 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
-static __always_inline void kasan_unpoison_vmalloc(const void *start,
-						   unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void *kasan_unpoison_vmalloc(const void *start,
+						    unsigned long size)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size);
+	return (void *)start;
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size);
@@ -454,8 +455,11 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) { }
 
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
+static inline void *kasan_unpoison_vmalloc(const void *start,
+					   unsigned long size)
+{
+	return (void *)start;
+}
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 39d0b32ebf70..5a866f6663fc 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,12 +475,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
-		return;
+		return (void *)start;
 
+	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
+	return (void *)start;
 }
 
 /*
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index eaacdf3abfa7..c0985f74c0c1 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2209,7 +2209,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2442,10 +2442,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3797,9 +3797,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3812,6 +3809,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
+	/* mark allocated areas as accessible */
+	for (area = 0; area < nr_vms; area++)
+		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
+							 vms[area]->size);
+
 	kfree(vas);
 	return vms;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2680386eab3abc80bead51b45fb92fc2dff03a3b.1640036051.git.andreyknvl%40google.com.
