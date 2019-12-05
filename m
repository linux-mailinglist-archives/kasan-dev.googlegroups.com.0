Return-Path: <kasan-dev+bncBC5L5P75YUERBKNKUPXQKGQEP7FDXAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A7A7113EEC
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:00:10 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 7sf670236wmf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:00:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575540010; cv=pass;
        d=google.com; s=arc-20160816;
        b=aj7Zekdbu66XR1ddlQdC1xO3O2ISQOXJwGeBlvhZLgKI7GT8dhKeA7v8WC1AVpCzoo
         B1QsXBn2KLihGH/ElG6bpDdTnCIa7L5aIM0Odj0e1/tiTSieQ5dvVxMfQ6iPZgQiTRyZ
         JDOWFyiyZScyQdDP59bUayighUEBpT9FfuUU+Ntsu1KZA6+zHla9dpNLWxDSMszx3/yF
         jNzgjp0lzf8Q8RZYkJyEhF1f9wXrrghaGllSgXUpbZWFmhGb89Tvoh603uHHEpvi/Q4j
         Z7Ev8jSYL3ZlIutrg5O6vHjSiWUf+1re6ycQghhXMo+KFbOSzNM+38iL5j6QPsgFZ+qx
         keKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gisMmfKoPcn+YwgiIK1kJa46WhXF553HpWPfvqHeDj0=;
        b=zR9Z+UwtaqlU2UhYvSkG7sRooisteDwPiwRMXsJOVaJREoBVwL+K3GQOXYOG4qJPep
         FLUERaxcN5JnrV47ta+POJGlA9/ubnFKI5TTFqI+tvEX3zf/Rx29kUeBtGn7nuROuhEN
         DujN5LYVtk95YYGw7M0tvSgvCUVbC5dFI0BPXlUMTlyLXSVpAn/VaLuHrjpps43iT0h5
         Buk2j7v7PTXLxyDQeFLxWVyx5ThGl1m6Oacy/x0HIGASvx5HScwG//vEOEYayuxdmUZW
         vsVB4UK9F26uWXQpBOGkkvjblzDrz6gYQxBRtXr9NCD1RxVxi8vAenex3Oq4Aq/dMdaB
         kGdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gisMmfKoPcn+YwgiIK1kJa46WhXF553HpWPfvqHeDj0=;
        b=R6hW2hjbTe04MriuvK45HnCwGICBlLuwHAG4Fd+tgV6eO8YDtClDWpVf9p2gFW+/wD
         yJHLKAW7xPhmZ/O8FWwsW48TFcU8/K7YJrBnJbzDcTbD4hdk3rIK4RBYCeZmrXzrNvjG
         RYhDidiwmDQ0NN6hz1NSOuBAVArw/ughQeaZEZ+YgnhcrcDeI+xkyD4KmocYotijlSAU
         yihOqdNMVybCHmaYcEiPpUUtcs1TqwLzewZkuImiIOide8GEHqwVJy3oXH3ySAe4qRiz
         3sgnfiWsZsrsmfILWSwEziYXFSowO4V5k+zCjm4eQ3f4d9XQQ5x80lMKaIIPnTaSUvXU
         EjZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gisMmfKoPcn+YwgiIK1kJa46WhXF553HpWPfvqHeDj0=;
        b=umpQF0+/gmvUSx89W8YyI0eD/PkAUjJmSlRxvfP1oa4/VLQzz2BtXUsq+lhor/n5ec
         OxHiBUvHA1bijeq4w50sXFK5bIOY71ZIMbcJvvDNiTpIBpfKzPvuntDU9145szVmqFen
         1/4Fj7jYKSj1lwc9h4vm30FSk05W2PgiMxIAyXj0nqwUpqlP3dWS0JJ5G3fSyrLJKAIt
         /FoID2aIlbx5ar0mw+w16BbP9oDcCqoEuiuqoB6Qp6LDFcwieGXNCGwieiMBeFVR2L/h
         CN7YuX0HfVOj3G0jrTaFXoBhd+8EJam517RLKFi9X63U0qZXd3ThlQdJOTamjfbWS63t
         zaww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUtO7sftPz9s+07VULp1OksxvFQcfs1whtlicDelQ4UL31pNI1v
	TKSZeoLy7+LWXTsTcqolXrY=
X-Google-Smtp-Source: APXvYqwDsp0vOBk419jqwC8S8Sbs95pGASObO3dqypxcCV2fbmOclK82aKqMg4bIU8/OOdhbHfrvNg==
X-Received: by 2002:a7b:cf16:: with SMTP id l22mr4309483wmg.79.1575540009897;
        Thu, 05 Dec 2019 02:00:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:bc0b:: with SMTP id m11ls1164421wmf.4.gmail; Thu, 05 Dec
 2019 02:00:09 -0800 (PST)
X-Received: by 2002:a1c:f316:: with SMTP id q22mr4293148wmq.103.1575540009181;
        Thu, 05 Dec 2019 02:00:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575540009; cv=none;
        d=google.com; s=arc-20160816;
        b=J6R4bMbP1YCPCzJhlqzUeeChCFadhi7mP7CQFsxoDcMUb9+mP4OYGrIz0Ip3CRiSZd
         evoB/0g45X3Yfye1klRZCeANAyw1FMK7omr6t8cthdmE3Do+a1IHVhZc4dcCL0t8JH7j
         Nv/8Yn2TR/V1sfk83V/NVelOjxgkE1i0SJcqxqb7k/t3ol68afBD8XtLxrUsCFAHae8d
         ksBkxXbzeyYmlFt6Re4nDDzotIFBMy33G9KBLfSn5EAL7AlVtDObM7baYXOyVC+bkFmr
         0r+LPzdtMUSNQExTNoZZCb9nVbG0PiL2k+YFI44ssEbsGzZYzdW4XtY9VBho4kVPpjTr
         K5VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Rivdzo7U09m/P8BZYq8kYzQKdsVAjCf2KqRR25eD9n4=;
        b=G9tGgM7K+Ce58s5EHJcjfWo5IcyqXIyUNytfmB/zZXZO7CZ3fgD6+KNyth4LpP2AY6
         cBgNG4RDn0/MUd/VW53KndB/gwaHU1ahAXCp31HApwIKDMtcPZmkJU2ByHYjxnt8b0kU
         diYLzb3StT3yDWi8zduYYRUwgBzZVyOdS3TRhb12l2J402b+5r2W/IJ7TyVRJQXtJIEm
         oYMOSJ//JwMqUEn5Fi93JRQefAxM/oQ+4yWi/Y6vCHWf5gMhPYWXWrnVOjGbgJm41ltq
         c5lcgF/mgxCyvneQxowEsVHdW/YOAnmnR+onyOeEEhHiewQoxiazbuIspD5G0dilrYCo
         vQoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id p16si447718wre.4.2019.12.05.02.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:00:09 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5] helo=i7.sw.ru)
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1icnvW-0005di-NU; Thu, 05 Dec 2019 13:00:02 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	Qian Cai <cai@lca.pw>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: [PATCH v2] kasan: fix crashes on access to memory mapped by vm_map_ram()
Date: Thu,  5 Dec 2019 12:59:42 +0300
Message-Id: <20191205095942.1761-1-aryabinin@virtuozzo.com>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20191204224037.GA12896@pc636>
References: <20191204224037.GA12896@pc636>
MIME-Version: 1.0
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

With CONFIG_KASAN_VMALLOC=y any use of memory obtained via vm_map_ram()
will crash because there is no shadow backing that memory.

Instead of sprinkling additional kasan_populate_vmalloc() calls all over
the vmalloc code, move it into alloc_vmap_area(). This will fix
vm_map_ram() and simplify the code a bit.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---

 Changes since v1:
  - Fix error path in alloc_vmap_area.
  - Remove wrong Reported-by: syzbot (The issue reported by bot is a different one)

 include/linux/kasan.h | 15 +++++---
 mm/kasan/common.c     | 27 +++++++++-----
 mm/vmalloc.c          | 85 ++++++++++++++++++++-----------------------
 3 files changed, 67 insertions(+), 60 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4f404c565db1..e18fe54969e9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -205,20 +205,23 @@ static inline void *kasan_reset_tag(const void *addr)
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN_VMALLOC
-int kasan_populate_vmalloc(unsigned long requested_size,
-			   struct vm_struct *area);
-void kasan_poison_vmalloc(void *start, unsigned long size);
+int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 #else
-static inline int kasan_populate_vmalloc(unsigned long requested_size,
-					 struct vm_struct *area)
+static inline int kasan_populate_vmalloc(unsigned long start,
+					unsigned long size)
 {
 	return 0;
 }
 
-static inline void kasan_poison_vmalloc(void *start, unsigned long size) {}
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index df3371d5c572..a1e6273be8c3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -777,15 +777,17 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	return 0;
 }
 
-int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
+int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
-	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
+	if (!is_vmalloc_or_module_addr((void *)addr))
+		return 0;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
 	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
-	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr +
-							area->size);
+	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
 	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
 
 	ret = apply_to_page_range(&init_mm, shadow_start,
@@ -796,10 +798,6 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
 
 	flush_cache_vmap(shadow_start, shadow_end);
 
-	kasan_unpoison_shadow(area->addr, requested_size);
-
-	area->flags |= VM_KASAN;
-
 	/*
 	 * We need to be careful about inter-cpu effects here. Consider:
 	 *
@@ -842,12 +840,23 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(void *start, unsigned long size)
+void kasan_poison_vmalloc(const void *start, unsigned long size)
 {
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
 	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
 	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
 }
 
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison_shadow(start, size);
+}
+
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 4d3b3d60d893..6e865cea846c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1061,6 +1061,26 @@ __alloc_vmap_area(unsigned long size, unsigned long align,
 	return nva_start_addr;
 }
 
+/*
+ * Free a region of KVA allocated by alloc_vmap_area
+ */
+static void free_vmap_area(struct vmap_area *va)
+{
+	/*
+	 * Remove from the busy tree/list.
+	 */
+	spin_lock(&vmap_area_lock);
+	unlink_va(va, &vmap_area_root);
+	spin_unlock(&vmap_area_lock);
+
+	/*
+	 * Insert/Merge it back to the free tree/list.
+	 */
+	spin_lock(&free_vmap_area_lock);
+	merge_or_add_vmap_area(va, &free_vmap_area_root, &free_vmap_area_list);
+	spin_unlock(&free_vmap_area_lock);
+}
+
 /*
  * Allocate a region of KVA of the specified size and alignment, within the
  * vstart and vend.
@@ -1073,6 +1093,7 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
 	struct vmap_area *va, *pva;
 	unsigned long addr;
 	int purged = 0;
+	int ret;
 
 	BUG_ON(!size);
 	BUG_ON(offset_in_page(size));
@@ -1139,6 +1160,7 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
 	va->va_end = addr + size;
 	va->vm = NULL;
 
+
 	spin_lock(&vmap_area_lock);
 	insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
 	spin_unlock(&vmap_area_lock);
@@ -1147,6 +1169,12 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
 	BUG_ON(va->va_start < vstart);
 	BUG_ON(va->va_end > vend);
 
+	ret = kasan_populate_vmalloc(addr, size);
+	if (ret) {
+		free_vmap_area(va);
+		return ERR_PTR(ret);
+	}
+
 	return va;
 
 overflow:
@@ -1185,26 +1213,6 @@ int unregister_vmap_purge_notifier(struct notifier_block *nb)
 }
 EXPORT_SYMBOL_GPL(unregister_vmap_purge_notifier);
 
-/*
- * Free a region of KVA allocated by alloc_vmap_area
- */
-static void free_vmap_area(struct vmap_area *va)
-{
-	/*
-	 * Remove from the busy tree/list.
-	 */
-	spin_lock(&vmap_area_lock);
-	unlink_va(va, &vmap_area_root);
-	spin_unlock(&vmap_area_lock);
-
-	/*
-	 * Insert/Merge it back to the free tree/list.
-	 */
-	spin_lock(&free_vmap_area_lock);
-	merge_or_add_vmap_area(va, &free_vmap_area_root, &free_vmap_area_list);
-	spin_unlock(&free_vmap_area_lock);
-}
-
 /*
  * Clear the pagetable entries of a given vmap_area
  */
@@ -1771,6 +1779,8 @@ void vm_unmap_ram(const void *mem, unsigned int count)
 	BUG_ON(addr > VMALLOC_END);
 	BUG_ON(!PAGE_ALIGNED(addr));
 
+	kasan_poison_vmalloc(mem, size);
+
 	if (likely(count <= VMAP_MAX_ALLOC)) {
 		debug_check_no_locks_freed(mem, size);
 		vb_free(mem, size);
@@ -1821,6 +1831,9 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
 		addr = va->va_start;
 		mem = (void *)addr;
 	}
+
+	kasan_unpoison_vmalloc(mem, size);
+
 	if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
@@ -2075,6 +2088,7 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 {
 	struct vmap_area *va;
 	struct vm_struct *area;
+	unsigned long requested_size = size;
 
 	BUG_ON(in_interrupt());
 	size = PAGE_ALIGN(size);
@@ -2098,23 +2112,9 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	setup_vmalloc_vm(area, va, flags, caller);
+	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
 
-	/*
-	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
-	 * area with real memory. If we come here through VM_ALLOC, this is
-	 * done by a higher level function that has access to the true size,
-	 * which might not be a full page.
-	 *
-	 * We assume module space comes via VM_ALLOC path.
-	 */
-	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
-		if (kasan_populate_vmalloc(area->size, area)) {
-			unmap_vmap_area(va);
-			kfree(area);
-			return NULL;
-		}
-	}
+	setup_vmalloc_vm(area, va, flags, caller);
 
 	return area;
 }
@@ -2293,8 +2293,7 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
 	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
 
-	if (area->flags & VM_KASAN)
-		kasan_poison_vmalloc(area->addr, area->size);
+	kasan_poison_vmalloc(area->addr, area->size);
 
 	vm_remove_mappings(area, deallocate_pages);
 
@@ -2539,7 +2538,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!size || (size >> PAGE_SHIFT) > totalram_pages())
 		goto fail;
 
-	area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
+	area = __get_vm_area_node(real_size, align, VM_ALLOC | VM_UNINITIALIZED |
 				vm_flags, start, end, node, gfp_mask, caller);
 	if (!area)
 		goto fail;
@@ -2548,11 +2547,6 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		return NULL;
 
-	if (is_vmalloc_or_module_addr(area->addr)) {
-		if (kasan_populate_vmalloc(real_size, area))
-			return NULL;
-	}
-
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3437,7 +3431,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	/* populate the shadow space outside of the lock */
 	for (area = 0; area < nr_vms; area++) {
 		/* assume success here */
-		kasan_populate_vmalloc(sizes[area], vms[area]);
+		kasan_populate_vmalloc(vas[area]->va_start, sizes[area]);
+		kasan_unpoison_vmalloc((void *)vms[area]->addr, sizes[area]);
 	}
 
 	kfree(vas);
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205095942.1761-1-aryabinin%40virtuozzo.com.
