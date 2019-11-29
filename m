Return-Path: <kasan-dev+bncBDQ27FVWWUFRBF72QTXQKGQEWIEQAQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id CC32410D803
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 16:45:28 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id m72sf11318259vka.20
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 07:45:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575042327; cv=pass;
        d=google.com; s=arc-20160816;
        b=EAtD4Lsi8kLVpHZa3RaMs+3b+SEpovGeinCmho++WqCP+FBajtr+rX02QrW9dbRase
         EpHbdEkL1gjbXN/3iVmZ+sL3DXO1IxfpwFj482GYUUQ0Gdp9E27HDLlqvxz7bNtq4tTM
         NGsVksyt7c42jVGxN2j6cdO75U99dI1zYtiJYsK6GzbqjEcK956ASsfuJYD8A3R7gMZJ
         mSPGYPmkK+8tAXArVxoMqRAOTK6icr/eRyWWveERveDPSSaP+sTp2deeoJJH3oM7yHf5
         GJFSD6hJ8y//s6AUS9/Be3J/fPw5LOi2w4oZ2zih4OIh3ICqPTUF/7ncZe2qJQ/dShlm
         A0XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YaPMCu7K44gMjMIti4TISgVz2U1sOb8QLO99w15to+E=;
        b=fxy7zKhKsjd29A1ZHVpBFCZNFDdvZymIyhm7ApFAT56Qh1Vbd3A9deLhDbf0wY1E4P
         Gn6BA5wEyhu3kU4h2e0obynqL2rl0/+W/jOtQhoQhBoqwBB8+BUOf6AML/q94XqrrN3+
         0PFc0GW9E4YbIANvflCnYBqwV2O9DurXxHx9Xz8AkoQ7YL3nvWXrJn8l2UFFDMJwO3L8
         rFjVi4CwGRxw19lzr/4GGKC43Cxh+opklXvBdPaLfi/DtW4RHW69Ec1ocTBrJVod7i7b
         7uYxqmqSVw1KOHo5auHF69/SpohQO846hifP8FxLvRgzAk+t+302Ust8S8NflRoX7JPW
         0cPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=eRxKLAUk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YaPMCu7K44gMjMIti4TISgVz2U1sOb8QLO99w15to+E=;
        b=J2OkgzeL1sllyTxJx2MaCxUTNxPYu9po5DXk2iYMxMLYnzr1bGTM5HUlbUMqPzvV4M
         vXI8VR0hmj8MMkCHJEykX1nGjnlT/3EyQcrTYSIWZfQxDnHJ9puYbHJAJlzIOmV8DluJ
         rgFlg69I5mByeTZ/tC10/i1vhF1XhwhT4y1NQ8wxQ5rt34gtYVtdcvUTbRPm96zb1Cid
         o4h/ao/Ja0b9H0aZK9YVv5Qg4BC6R0KfaNaImtm3/UfU2RYinfE0ISCOfgYsyvSF5yrb
         Mww+gvUwFQw6UHfTnLTc96HvB+YycqQM9xETOpJoElRFd0WgIfvyUzv6Ngwrhv6Nyr2B
         EUJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YaPMCu7K44gMjMIti4TISgVz2U1sOb8QLO99w15to+E=;
        b=Kq+3M0olpJcGJR73tdBgZ087igFF+qr0FLRMrt8vgVaNzkjumOC/0ZhaWzTnBRFBF2
         CAmAYHpfyZzp3U/EtItdfjjDCSfqzl17TO6eAVPow+MArf7Q84+NYlYdRfBnwFCLj+Nu
         TAE8iigszYipuxQDbJZQehedzeBH5pzPe0vVXLDUZKMj3WBH3DuAuButyTIx2yG4HlKy
         c75HUXSYIzS95xSt4Lr79TO0ZRNyufbO4IUPLSweRJqLSOLTs5kYsm1Y/ygi2cdGJnIG
         aXSbJPanSyGhCxT6Tv0m+NEP/zWffJE0OKu4TgzEMklqS6eUnVE8hULN6tEVIc5X2e+u
         uV6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVokshZJmGm00CIC7EthHU9QHGOCSFn8SYM/51bfZ5/v+E1D9n4
	ZZ7Mmz6yHcTOrHYKz15MJsI=
X-Google-Smtp-Source: APXvYqwuMhdhWKYK1juFNGT2QVHi41073pIX1naXCa8ZaK5WE09kO8oXQSHScHE5ZxefHrfjhZCEFQ==
X-Received: by 2002:a1f:2c1:: with SMTP id 184mr10652976vkc.79.1575042327749;
        Fri, 29 Nov 2019 07:45:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1046:: with SMTP id g6ls236494uab.16.gmail; Fri, 29 Nov
 2019 07:45:27 -0800 (PST)
X-Received: by 2002:ab0:300c:: with SMTP id f12mr9802395ual.135.1575042327336;
        Fri, 29 Nov 2019 07:45:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575042327; cv=none;
        d=google.com; s=arc-20160816;
        b=Cl+lqfqmvkWNFE3y/NuaBGcjgY02IKIGd5jA7tiyaUz9INQJNNBwN6jCPbdcTAa8EW
         ZD2jyYiz97tEoslGGD1QVLTT0cS084Dogm+7cOPrOpkfJc706+AMje4UIqVQ31mhT/p6
         KUeiwVm38Z2OYXztnR0LWRFM6ojBeQ2ugPq/b+OEo4ON+0WZjNz2BpT0kCqhunnl7IZ6
         /rVhX3F1HltuYXM1uUik0M0YiqlnQRlR+Nno/+odwBtzPWLPr14ileR6RPh3uIDp65K4
         RvY/I0BsSIX1yVXmc/F3FtbCPxTB1w3o2gpBVCdS5SRGhW3BIyxycynpK2RqI7HZmSaw
         D/hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vsKvBmcEHkBcKrbZ7FMQtODXsXcFjKXnby3n743Jem8=;
        b=WrImrmHcoWY4TqHGOmabmIaP9o7f526B3g7C2BTSVef63TFyyWZIJlA5duvpM3Ir44
         0h1sxcus0M6zzTUlK/tW0RWs7r57Qt8upCy1TUjLna6QDFi4qVsXqZxDwAjluvvvVlJk
         d99kZcD5KH1AqshHOPV4+961U2uBIfptrgndWVYIOqEg6ADbSD+2uIyDF14O1RQziWh9
         N5LNrQjUCaCuW9elVM6AtZKGqnRj86FNj0G7qaVYKVvs96cxE4Z3wDexVhFkFuD5JUqU
         ckoXm/6EDUFzGwyg/2JuaPrixu1O+z1adhB+C6KV96mYw7rtJTj992DUBAyD4G1BfzJz
         Dv1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=eRxKLAUk;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id f12si825446vso.1.2019.11.29.07.45.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 07:45:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id o8so8680872pls.5
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 07:45:27 -0800 (PST)
X-Received: by 2002:a17:902:968b:: with SMTP id n11mr8143652plp.120.1575042325924;
        Fri, 29 Nov 2019 07:45:25 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-4092-39f5-bb9d-b59a.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:4092:39f5:bb9d:b59a])
        by smtp.gmail.com with ESMTPSA id 186sm25273018pfe.141.2019.11.29.07.45.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Nov 2019 07:45:25 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	linux-kernel@vger.kernel.org,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>,
	Qian Cai <cai@lca.pw>
Subject: [PATCH] kasan: support vmalloc backing of vm_map_ram()
Date: Sat, 30 Nov 2019 02:45:19 +1100
Message-Id: <20191129154519.30964-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=eRxKLAUk;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

This fixes some crashes in xfs, binder and the i915 mock_selftests,
with kasan vmalloc, where no shadow space was being allocated when
vm_map_ram was called.

vm_map_ram has two paths, a path that uses vmap_block and a path
that uses alloc_vmap_area. The alloc_vmap_area path is straight-forward,
we handle it like most other allocations.

For the vmap_block case, we map a shadow for the entire vmap_block
when the block is allocated, and unpoison it piecewise in vm_map_ram().
It already gets cleaned up when the block is released in the lazy vmap
area freeing path.

For both cases, we need to tweak the interface to allow for vmalloc
addresses that don't have an attached vm_struct.

Reported-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>
Thanks-to: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/common.c     | 37 +++++++++++++++++++++++--------------
 mm/vmalloc.c          | 24 ++++++++++++++++++++++++
 3 files changed, 53 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4f404c565db1..0b50b59a8ff5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -207,6 +207,7 @@ static inline void *kasan_reset_tag(const void *addr)
 #ifdef CONFIG_KASAN_VMALLOC
 int kasan_populate_vmalloc(unsigned long requested_size,
 			   struct vm_struct *area);
+int kasan_populate_vmalloc_area(unsigned long size, void *addr);
 void kasan_poison_vmalloc(void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
@@ -218,6 +219,11 @@ static inline int kasan_populate_vmalloc(unsigned long requested_size,
 	return 0;
 }
 
+static inline int kasan_populate_vmalloc_area(unsigned long size, void *addr)
+{
+	return 0;
+}
+
 static inline void kasan_poison_vmalloc(void *start, unsigned long size) {}
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index df3371d5c572..27d8522ffaad 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -779,27 +779,15 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 
 int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
 {
-	unsigned long shadow_start, shadow_end;
 	int ret;
-
-	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
-	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
-	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr +
-							area->size);
-	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
-
-	ret = apply_to_page_range(&init_mm, shadow_start,
-				  shadow_end - shadow_start,
-				  kasan_populate_vmalloc_pte, NULL);
+	ret = kasan_populate_vmalloc_area(area->size, area->addr);
 	if (ret)
 		return ret;
 
-	flush_cache_vmap(shadow_start, shadow_end);
+	area->flags |= VM_KASAN;
 
 	kasan_unpoison_shadow(area->addr, requested_size);
 
-	area->flags |= VM_KASAN;
-
 	/*
 	 * We need to be careful about inter-cpu effects here. Consider:
 	 *
@@ -838,6 +826,27 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
 	return 0;
 }
 
+int kasan_populate_vmalloc_area(unsigned long size, void *addr)
+{
+	unsigned long shadow_start, shadow_end;
+	int ret;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
+	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow(addr + size);
+	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
+
+	ret = apply_to_page_range(&init_mm, shadow_start,
+				  shadow_end - shadow_start,
+				  kasan_populate_vmalloc_pte, NULL);
+	if (ret)
+		return ret;
+
+	flush_cache_vmap(shadow_start, shadow_end);
+
+	return 0;
+}
+
 /*
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index bf030516258c..2896189e351f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1509,6 +1509,13 @@ static void *new_vmap_block(unsigned int order, gfp_t gfp_mask)
 		return ERR_CAST(va);
 	}
 
+	err = kasan_populate_vmalloc_area(VMAP_BLOCK_SIZE, va->va_start);
+	if (unlikely(err)) {
+		kfree(vb);
+		free_vmap_area(va);
+		return ERR_PTR(err);
+	}
+
 	err = radix_tree_preload(gfp_mask);
 	if (unlikely(err)) {
 		kfree(vb);
@@ -1554,6 +1561,7 @@ static void free_vmap_block(struct vmap_block *vb)
 	spin_unlock(&vmap_block_tree_lock);
 	BUG_ON(tmp != vb);
 
+	/* free_vmap_area will take care of freeing the shadow */
 	free_vmap_area_noflush(vb->va);
 	kfree_rcu(vb, rcu_head);
 }
@@ -1780,6 +1788,8 @@ void vm_unmap_ram(const void *mem, unsigned int count)
 	if (likely(count <= VMAP_MAX_ALLOC)) {
 		debug_check_no_locks_freed(mem, size);
 		vb_free(mem, size);
+		kasan_poison_vmalloc(mem, size);
+
 		return;
 	}
 
@@ -1787,6 +1797,7 @@ void vm_unmap_ram(const void *mem, unsigned int count)
 	BUG_ON(!va);
 	debug_check_no_locks_freed((void *)va->va_start,
 				    (va->va_end - va->va_start));
+	/* vmap area purging will clean up the KASAN shadow later */
 	free_unmap_vmap_area(va);
 }
 EXPORT_SYMBOL(vm_unmap_ram);
@@ -1817,6 +1828,11 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
 		if (IS_ERR(mem))
 			return NULL;
 		addr = (unsigned long)mem;
+
+		/*
+		 * We don't need to call kasan_populate_vmalloc_area here, as
+		 * it's done at block allocation time.
+		 */
 	} else {
 		struct vmap_area *va;
 		va = alloc_vmap_area(size, PAGE_SIZE,
@@ -1826,7 +1842,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
 
 		addr = va->va_start;
 		mem = (void *)addr;
+
+		if (kasan_populate_vmalloc_area(size, mem)) {
+			vm_unmap_ram(mem, count);
+			return NULL;
+		}
 	}
+
+	kasan_unpoison_shadow(mem, size);
+
 	if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191129154519.30964-1-dja%40axtens.net.
