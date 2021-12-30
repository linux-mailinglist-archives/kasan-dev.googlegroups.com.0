Return-Path: <kasan-dev+bncBAABBYMKXCHAMGQEFAC2RCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20FE4481FAD
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:46 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id c31-20020a2ebf1f000000b0022d87a28911sf8326179ljr.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891745; cv=pass;
        d=google.com; s=arc-20160816;
        b=H8ev0hklyTxkl/dlvhcL2um2+PkTjPR837+FJZ20ljOKQtIervO/8R9Y4z8AKjJIoD
         7u9+mhCD96LKyk9dGu4ktr4Eij3SEG/jIQV0w2iLnobdP8CbtbCVAHUd875V+kcezcYF
         +p6SHhl93VKy12Zg/1IlaA6VuFq2hGSStt7DNbWEhVvKnLGfJmKWs3lszRs8FlTjwY9/
         O7ns0hfL/EObL9mKv+7HSOPdCBLG/eSN8RRdNnYQQik5TDd053iSv4t1sK+Tpj4VLQMj
         X0XJNWy2eP62yzMME3ACX92sM1P5840l7M3piAgv+PsZpzy5s//ecIiXTOdR+qhK9+wt
         SsIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YQmnNC2DjbvrE+t5GI4VBAbAY15Ih+D2t1WdDgKU5mM=;
        b=wp5fX32PiYQX7j+7Q3IpFYn0ouHIUUfDl/aStwhAiGwrB2VXk+ppmUZXee7DTtwRZp
         l96Hnm8KpJE82MZ5qs9RZ2GMaD74tOoRKyhvgu1LLIKtvH0RWizCKxziJkLhtuzRYp2f
         Jp4ckeXz3bu02Sy4rq74lXiuaBdrBOY9gvlwxTgqd/eQNniS7l08pBBnr6p42nzVN9w8
         L7WOZ/mJ5FZqL2xi/bMJ8g3DF20dbC+UEpPoixalTwW+C74J2rygzT7w197q3yA5sx4g
         sv5CiwhTl7mG5l4jKz8Tifbn/Y0H5cpHBhBGBj7eFpJJ9mXh9SGA/hGi7Yth7PWvWoOG
         JETQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J9RmHsI7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQmnNC2DjbvrE+t5GI4VBAbAY15Ih+D2t1WdDgKU5mM=;
        b=f4IbpNA7d0ymRgIsXmz1oxEZPzne6ddMSxCHJTWe1reLK/fYKjqIwEBdotxDk/v8Xk
         jQoPvmCkji3d4sPiG/GzMXyDK6BcN8d1cXLwTWYOESJwdTGUpqomeMl3Gme1YXy61Mx8
         DUR5hdM8Y/iT64cildp+uWBB/1CLX7ROFr+2PJB98vmsNA+qiHHeYh+BFqa2w46VuvQT
         0yPobJS5Cn7zz3ZKM7X+wokTv8i/aiQyMPGjfr8eUJ0WNButn8nuQwW2BPfyHMbGRM/n
         RcP0HPTZ7v/6psxWytwk4wOBdyW/FHgV2Zt422wv1RpvpjBPYCKYY/60+dELaOqEfEGR
         iCQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQmnNC2DjbvrE+t5GI4VBAbAY15Ih+D2t1WdDgKU5mM=;
        b=zlRDyt6Z54Lh8hujtfIHEgskdaU8om4WQI7ethauruGLH7m/pC2gRoo0FIkX7bK4/u
         EiVW7/n1sE8cS5yMleackOvm0uJ1LE5Q0MgIFRWOX7MEGzvzmsotba7OT957ZhZw/AeI
         SQDnbkec14+cn9jGRkeAL+TpwJKzHmhv95kSHMCi5j21pyQL6v7MrSxXwcmPxwvU2/V/
         Q38fw1VQFzjWz79xgH75yQGw2DVQcc2dh5+VhX+WaxBqfh2H5Rsno65JO/g8VSuBJ50E
         oKBpCNOtq/oPmc4D4MtrHS95lpD8zFnsP+VB58nE6D+E/ZZzdvx6Jg0SIE9ar8cSMgAK
         ClHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zOWOybQW2xr7/LLXcKc8nfJhzfFcDOOHXLXm4Pj5LWlXccJvf
	MZ93lyl7nlRr6v3r9zlpC/I=
X-Google-Smtp-Source: ABdhPJyVH4y72IB2hEo5t/y4aRxSg/oXTb4uuG+KzoY0VQoPhEvt3J60uUlwH4pI2ZwTD5B5JWCfow==
X-Received: by 2002:ac2:4c52:: with SMTP id o18mr24513757lfk.690.1640891745721;
        Thu, 30 Dec 2021 11:15:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211c:: with SMTP id a28ls1841473ljq.0.gmail; Thu,
 30 Dec 2021 11:15:45 -0800 (PST)
X-Received: by 2002:a2e:9196:: with SMTP id f22mr26841709ljg.444.1640891745040;
        Thu, 30 Dec 2021 11:15:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891745; cv=none;
        d=google.com; s=arc-20160816;
        b=h28qocLhrICliV9/TWNNAQFHa3rooeuE33xtbUEAy6USmQH09a+VbvKyiRA3T4Orur
         UY9ei4KYh9YquphGlcdlSGcr457CYOOubgT2ZOsmGLGL1ObdIMPpK8WDgjMgLg9sETIU
         mBVFC6+fDUQDH8XuQ2FRDt2TExdLwvgBB7vbX5R/BnRp8PPcSrPS1zwQk6QKdeJ2iObz
         PHoQm9DK6/cjDAFmLP7J+gViknlU04syJN6I1ogB0XepzTJ9jyj3KWraCu4N00hWEV8e
         PTik+u+6PQmWqI3WoAd1iKcp4rT/8AER/5E4W0s2y5+txL3VJD0dYVoHn2nibkTwYLaw
         XUlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FABrWA5761iiZUkXnIazPnhUDwA8MsEm5+WPei3KGi8=;
        b=CLL8zziHLGJH9Zljf5On27E4nvnOxKdKuEjWhtYufJB1I10/fYy9yzUh02Z+EqQcFi
         56gAYB07czeg61HYcdjF0xdCr9JeXlpsno8IVJGv1XMZo+pyQ/+LNxN6+/+5bMMLfYc7
         s4edHrcTyXWhaaeqdyuAMi7mh0F3RZVXXgVaitmoyHZ4aBT5OwTRirYey08uhpPqAPgw
         Xkx01/TcbSLRlBySiR2cIpqet5Lj3BzGZ9X+LGJhzSNt8tj/AmLpq7RDu4PIjSCkzI6T
         UNm8I0F8NPX8H4iK2BDVDqkYpF+rcCNnQcuVO5Oc6OCJw2aOjxKbyRl9BNZwInIYfujH
         +NAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J9RmHsI7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id r5si513617ljd.1.2021.12.30.11.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:45 -0800 (PST)
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
Subject: [PATCH mm v5 26/39] kasan, vmalloc: unpoison VM_ALLOC pages after mapping
Date: Thu, 30 Dec 2021 20:14:51 +0100
Message-Id: <2aec888039eb8e7f9bd8c1f8bb289081f0136e60.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=J9RmHsI7;       spf=pass
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

Make KASAN unpoison vmalloc mappings after they have been mapped in
when it's possible: for vmalloc() (indentified via VM_ALLOC) and
vm_map_ram().

The reasons for this are:

- For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
  mapping them fails.
- For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
  kasan_unpoison_vmalloc().

As a part of these changes, the return value of __vmalloc_node_range()
is changed to area->addr. This is a non-functional change, as
__vmalloc_area_node() returns area->addr anyway.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v3->v4:
- Don't forget to save tagged addr to vm_struct->addr for VM_ALLOC
  so that find_vm_area(addr)->addr == addr for vmalloc().
- Reword comments.
- Update patch description.

Changes v2->v3:
- Update patch description.
---
 mm/vmalloc.c | 30 ++++++++++++++++++++++--------
 1 file changed, 22 insertions(+), 8 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 598bb65263c7..bcf973a54737 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2210,14 +2210,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	mem = kasan_unpoison_vmalloc(mem, size);
-
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
 	}
 
+	/* Mark the pages as accessible, now that they are mapped. */
+	mem = kasan_unpoison_vmalloc(mem, size);
+
 	return mem;
 }
 EXPORT_SYMBOL(vm_map_ram);
@@ -2445,7 +2446,14 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
 	setup_vmalloc_vm(area, va, flags, caller);
 
-	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+	/*
+	 * Mark pages for non-VM_ALLOC mappings as accessible. Do it now as a
+	 * best-effort approach, as they can be mapped outside of vmalloc code.
+	 * For VM_ALLOC mappings, the pages are marked as accessible after
+	 * getting mapped in __vmalloc_node_range().
+	 */
+	if (!(flags & VM_ALLOC))
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
 
 	return area;
 }
@@ -3054,7 +3062,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			const void *caller)
 {
 	struct vm_struct *area;
-	void *addr;
+	void *ret;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3116,10 +3124,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		prot = arch_vmap_pgprot_tagged(prot);
 
 	/* Allocate physical pages and map them into vmalloc space. */
-	addr = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
-	if (!addr)
+	ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
+	if (!ret)
 		goto fail;
 
+	/* Mark the pages as accessible, now that they are mapped. */
+	area->addr = kasan_unpoison_vmalloc(area->addr, real_size);
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3131,7 +3142,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!(vm_flags & VM_DEFER_KMEMLEAK))
 		kmemleak_vmalloc(area, size, gfp_mask);
 
-	return addr;
+	return area->addr;
 
 fail:
 	if (shift > PAGE_SHIFT) {
@@ -3823,7 +3834,10 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
-	/* mark allocated areas as accessible */
+	/*
+	 * Mark allocated areas as accessible. Do it now as a best-effort
+	 * approach, as they can be mapped outside of vmalloc code.
+	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
 							 vms[area]->size);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2aec888039eb8e7f9bd8c1f8bb289081f0136e60.1640891329.git.andreyknvl%40google.com.
