Return-Path: <kasan-dev+bncBAABB272QOHAMGQEYCTHOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E40F47B5A1
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:20 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id ay41-20020a05600c1e2900b00345a568e6b2sf553650wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037740; cv=pass;
        d=google.com; s=arc-20160816;
        b=IXHcOz/5kaZMoLYd7H5J7OP60yjeIcJjyAyPXufOpljjB3xF46Tn+9W/+CQJZpP+vi
         B1/Hrhj5J+IQ8mIp7Pn/7llZMhlKcmXuLlXQkAnsgyomMTuJ/1gA2YVE55OleSslzaaO
         64CAP14llUEZhra2slRZU6ww6NUzFG3m6ogwfOSZtmcFhhXiHpT8F2uiQytuZ4gPSfPT
         istVzS48Qr4ZdgD5RcAWfttuYFDLO/EcMj4AY1yFOklZggrEktxygxRU6Aufye58zHcB
         K25zkz4z7s9v3p8M2WPGrNUv0b8tuG2qxsARdG2FTyBh166MQuO+9eZSkU1LEWXmILfS
         RgYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ClCVxy6BYyMMHEBYtakPQ9at8YaRcQKMAhk15eZPO+Y=;
        b=dt8v5fUrnVrl4g94U+zzX/FNbs18pSY2lurRMi9RwWjv/v9CYP9INHeNy+KvPGeDq9
         lZMoB+FNgJHRH+AKipTaPIjbLkV3S70bqRdwJ9UhixL655GrobdkYygm4w6Z3FtL/xo2
         fjsbBdZZDexbKSW48Ra7VDTpR4sG3eDR5emNodEK0DQQyieKUoNbNlBiNj7Hl+Nt0pSb
         2b/k4wzUoOhZMgZTG202tiDCoGuYlYerOBsYoKCIZUENs3qh8ic0c628Hm3xlT+ZTHms
         vyfdECOWvA1z/IlDHkXl0NeMYy6qnB0VjPkMUyFF2C9lZUUlvGd9iplVLm1kDwBO0fTE
         DV3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gs3TUW08;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ClCVxy6BYyMMHEBYtakPQ9at8YaRcQKMAhk15eZPO+Y=;
        b=fbXrLTfbY2c4JH0vOMjS8qR9WzMTw4viWjnh19KzQtdAuMNtcxqb2FikhI7kmSyU32
         I8eqgJtgVTMPx3r7adO66+3nmsSJejqaTNtmmIUktbCJVB2wCnuzcM4cb6HGB+PmSu+0
         4PfSiYe12zg3X+JfqzN0o42zoMSX6iht2ar6yGbCG6pHyeNd/ttoj92SCtTLMQHsfMc2
         fGnLIbpxPxwXcL008qg60JA7eAFVXia0jABSvSr8QbqiYrZvf3Qso8gwp8rjqzLVF2vc
         HPbEyzhlK2gDwh8dvFsKhFeEr/jqbKhxSzZqCq8zQ9MHXkbyLLg8nb7X/AuiIn9YGx2d
         gzoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ClCVxy6BYyMMHEBYtakPQ9at8YaRcQKMAhk15eZPO+Y=;
        b=OgrqOjSXE5hjnRtaDGRTeL0hTuooBr206vx54h+K7GTRyaJyVE0JXK6LEj39HdL4aw
         GoweR6liMQVbm/40id863zMo9ZojfP5Wi9oyhc2t0CQBzokmCfhWcq+HX/pq2s1le4Zi
         A5BMSDUhLVo4P3GNaXV93GHAh57rDq3MySqO0gidmuVaPQgpUhfQZUbt9tOAmW3GpYqK
         TT/jSN+PLw4tbJKQMUt5lrcqbf0yk/L6EAAMdceu4J7dvY7aAdbEd5ZD6h3laDpWrch9
         ec8hczYBWOgp8ADQWDO5wUp7mrAEL+5BB6RC9PrV0oezS6BPx14z8nHTIT6RCaHccGC9
         Amwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EwXs/QA8st3G4/3OhzS+aRt9DWTAaR9bu+XBIeY6biTar86oX
	k9lPVjLDWInUg0R4Z3pzRpM=
X-Google-Smtp-Source: ABdhPJzNrvs+IJhYsbeq082X3oeCjXPQ1b0YgVBh1a6bEvTYb6yrzzA3OqYqPvAF5RxFiO7/0yEMhQ==
X-Received: by 2002:a05:600c:1d28:: with SMTP id l40mr3680wms.192.1640037739830;
        Mon, 20 Dec 2021 14:02:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6389587wrh.3.gmail; Mon, 20 Dec
 2021 14:02:19 -0800 (PST)
X-Received: by 2002:adf:f911:: with SMTP id b17mr86816wrr.611.1640037739261;
        Mon, 20 Dec 2021 14:02:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037739; cv=none;
        d=google.com; s=arc-20160816;
        b=qOVXHvyWBJUwIygsvBa6YcaFk/a4AhkfDNKmTY/zLm/l1c6Zh8jcq0JTCXQyYcWmpm
         BlgQOdPL2m92roh9XOx8OK/mzMZwpKMGq1CJ618naTqTIBDJLb620XgS2f5UiBsbkohZ
         1fObG+xjNLTGEirxy2vBQFUW7VYxAcax2oIIYox5aN+r/csHjIyvczwmViM1hOsgj1MG
         XGhsjc37gy8066RY/cZiVuIdJqVNtVDaXTfPnBTfir5MkbOr+vS79jVpbTvS7mAwHFMT
         qBwQKGlFN8hbAYYjYg/KAl4oLeXvDcoi0WZU+fXIx5drouYSf6vtNmVdwrq2nUbmF/8i
         Exyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yh2u9z3tn4/Tg0QhiqtJYkJa7Ju7wNCufTpXT9TmOy4=;
        b=PjzCv9xxKyVYGdpqPlhcEEjR12bn7CDXcJIHhbSjzEO1iTpvpy88aEgNmVMmWbg+xL
         +MaeoZgHEG1ltEKhDqZr06f2orGlYqbItlU1UJrQ4fFdqPeZajkuHzLXus9yz8mleGUO
         UEIDKZ8fGNP1qsPzouCa/F+Ust6xT/2io/924z3tIFD4oypk4SE6zG7ZKENn+t0CnLBO
         I1O2ysNyto27/rANgOSa+wLtm27aMbN83IggKoeWwfzo20lbG5p8JNh78+7PqC/gAic4
         oTg0MlcMUgFslndh5QQReU3j/Cy2Sb9C/T61rrawWMyM2Ulp3h3mS/gtnHJfjRt3Bj/w
         6uCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gs3TUW08;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id ay11si53965wmb.0.2021.12.20.14.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 26/39] kasan, vmalloc: unpoison VM_ALLOC pages after mapping
Date: Mon, 20 Dec 2021 23:01:58 +0100
Message-Id: <516dc726dc6311d8bb9f1a90258190f628a3b636.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Gs3TUW08;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 388a17c01376..cc23e181b0ec 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2209,14 +2209,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
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
@@ -2444,7 +2445,14 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
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
@@ -3049,7 +3057,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			const void *caller)
 {
 	struct vm_struct *area;
-	void *addr;
+	void *ret;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3111,10 +3119,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3126,7 +3137,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!(vm_flags & VM_DEFER_KMEMLEAK))
 		kmemleak_vmalloc(area, size, gfp_mask);
 
-	return addr;
+	return area->addr;
 
 fail:
 	if (shift > PAGE_SHIFT) {
@@ -3818,7 +3829,10 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/516dc726dc6311d8bb9f1a90258190f628a3b636.1640036051.git.andreyknvl%40google.com.
