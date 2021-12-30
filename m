Return-Path: <kasan-dev+bncBAABBQEKXCHAMGQEPFU7ZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A7B2481FA3
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:13 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id s23-20020adf9797000000b001a24674f0f7sf6529822wrb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891713; cv=pass;
        d=google.com; s=arc-20160816;
        b=IVlO5PJ+Oqwu6vRPu5t8n5Gp9x/Q918zaeAThFqnr9FLfag270Iv513Y6dsPs0CrFD
         WFP+j4OLq1+UD9qFsQ6m/HUudYEAEP+mjDGN8xv/bmexXvCcO9VoZbE+n1XM8uyhM16c
         f1CCaWxyZVgjnvW2vKEfJu0e0RUcFSoJFdHcCQMRUIePZtyM1JBN+kPmafdvZyQLg6kN
         QjLLvFavsKwIh5p8nMXopOsMiKsMaOzSaWMEFCaumDxXzSUKk6H9EMEwH7p9Pn/95PAN
         ewQ5mTkqFAd6ax02nvQccjgRuoyJNvPSPhbrF8YMoYvQPME+sgbmK39vhd7GhCeYZOVb
         7fvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fo+ER3NjOIdtETrqDQiXjUB7Wc5oTixu1FW5Yvc9f9o=;
        b=fLLpuYP1XhdOX9/3gbbgQETTer9re8AA5HBQKQEEq9s6a5OfxUCN/C6SWcHRDNwj0g
         U8l5RpzbgZF9AFXvhcEf6QpWLnMOf9MbOhOHXnHgWeb+i/OhAFOZjoGGXeNuEax5xDhF
         aSnHGwJEKRYI2teA3p4d+AkocWPrrsNiRG5f4TUFPV53CTUWgmkU7KxPU70HTh1lr2kj
         TkfGnMDooQ6dNXDHxoHFqRT5iIc+B4LQzLnHSwF6lJhUB3+gMbCiiXgijLmJZpu0LSdU
         myIEGO2VRa8LGno54koq/Izc9xRS1SZG4i6Lo5oBEveOmliF8NH3edbjWWacfEC9qCMe
         sOnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jayb3W6v;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fo+ER3NjOIdtETrqDQiXjUB7Wc5oTixu1FW5Yvc9f9o=;
        b=Nk3QXVIZzrRNTdl4Edr11Ehv0TS0Bqgsgo3pK3+RdyTGp5rbyHDyio1Weamg2pNsFZ
         Gi55SqM9fMvkipbtned4W4aJiGq/ihkLvTvpnxoCuRUnjTDKffy/YpAMzdSiNAAuWc9w
         NqXF7VAd5a0oBKvjPxEsc+ypMKlM6p/6jNOzfCreLvNOQz+vQTnMcevLv7IQXxcmQ9v1
         8dF8razIBp0FHJzhXikj8yGF8AiQRnlZJf7xN2ueGO6nBc9NcgWPrdlYT4ATC5nE2qpo
         TZRntyeesDNl3rgkiVkM9nU7d+1J2+WKeviikCFuRO6oVHIkBhkoEzgz+gGXtV2lpeDV
         brHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fo+ER3NjOIdtETrqDQiXjUB7Wc5oTixu1FW5Yvc9f9o=;
        b=N1AyxBHdoWLpLwZFGVaVh71fVvuWrcI6qBRVuoZrFHgorOXDOrUZaSdxt/BLq7HOoR
         TAHAcJrJomNQ/Ebdc+XWakZn0OCyEHBFPFr9nVtpW5UQAFGZIzNmfmf/o/aNc5cI31qJ
         ruPeGVvB1FnTTJdlTEpjI6rXfzzyJNa9ghOvWQObcnDk7JwRWLfQY143Noqk5grv2QOn
         wHkCAC1Z8uUuJ44VcwhaFjBHEOrtHnb/rhf4G+GBkTa68ToSD5UzlwLunPpRSuWG6/xU
         b/P5E2ygm23Nw/J3t3ulr6s/wcpGz/WpuCJNHKPAGVEKTwArBnRd8J36gz/Yqmb+LXVz
         ICcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531oLfXRdz4BsWlW6yBbK6jGygysM1PQisOhMiOTR7iyon+IYUN/
	PeahCAzO+LvWN1QR5RUCc9Y=
X-Google-Smtp-Source: ABdhPJyEKabo0AQ7o8fHyEuyQggqmz24Bsaypnoh0gtO4xyhbkSGcBpa6tIFqGpbr3rqoncoqwl8HQ==
X-Received: by 2002:a05:600c:1c26:: with SMTP id j38mr26908974wms.101.1640891713087;
        Thu, 30 Dec 2021 11:15:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c27:: with SMTP id j39ls323601wms.2.gmail; Thu, 30
 Dec 2021 11:15:12 -0800 (PST)
X-Received: by 2002:a7b:c448:: with SMTP id l8mr26923873wmi.173.1640891712427;
        Thu, 30 Dec 2021 11:15:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891712; cv=none;
        d=google.com; s=arc-20160816;
        b=VO9P2wLKqU6WOL/+wg8/G6DshDKe97Mx/HY1K4PRJnNqL3sxVwN/TFioLT+6aQaE5U
         oMmM0rx3NivZS7ZjfXuv5Y97LerG39dxX3cmWham5oiO4GAK35zDFzw8q7UvYkX8/Fh0
         GZErWm3QCIqrhlNHE0e0w24L+LEnYvytloVR2s7aFhVrCVW12tvIe1LzZ6U4mlLX6ACO
         +A3Hs2PYJbQi6TEkAYtvcmJMmFJCFHWiB6RICysDXbWm4tGCHuiHSDWFrQxtEIN0/NdK
         KNXSX/X2gDkD8e7JtgW1JKAPC4qMZ0lQs1C1X2OZRTsavbs4/C5hjxnJxpkTO/2AUVrf
         DqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mVX4Rj9VCh5LXuAxF4z8x/gZeqsD4J17LlYnLyStvnE=;
        b=fzrdLspqf6v+iunLG/+8Pj/AnrpdNpU7U+kdLAmHXelgQsmGh08He9NWbkst+vGAYe
         WPosaqf+zfjHpevbdQckdN3Md+oqnpfLa51o2cXoFandrNw5l2Udev7Uh6Nvt76Ff0Xn
         OZOkeI2hkWgg/Fmf5dgzMB5B8th87k29yR7R+Q3vq+bs8Zhq6JVdXK56cR7EPGdfmfsW
         Q7IuYidX1by+Kwuwa6Icbbbu2Ez+WjpLWJAZq5fDW/GYfekYtdtc5MoYU513dOmgmQsI
         QnHLL54dzrQi4pHuKK1wxq4twVMXy26bOJr9tUdfCm3O2FSUoP39K4ix9b3ItGLCcWE/
         4OmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jayb3W6v;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id m12si946604wrp.3.2021.12.30.11.15.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:12 -0800 (PST)
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
Subject: [PATCH mm v5 24/39] kasan, vmalloc: add vmalloc tagging for SW_TAGS
Date: Thu, 30 Dec 2021 20:14:49 +0100
Message-Id: <30d0da01e7ade09f28ed98191a274112408ec3c2.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Jayb3W6v;       spf=pass
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
index 52336b034fbb..da419db620ba 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2210,7 +2210,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2443,10 +2443,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3802,9 +3802,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3817,6 +3814,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/30d0da01e7ade09f28ed98191a274112408ec3c2.1640891329.git.andreyknvl%40google.com.
