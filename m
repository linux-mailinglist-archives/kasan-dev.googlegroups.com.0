Return-Path: <kasan-dev+bncBC5L5P75YUERBEFWUDXQKGQEPSUEU6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FB371136AE
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 21:46:09 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id y15sf281806lji.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 12:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575492368; cv=pass;
        d=google.com; s=arc-20160816;
        b=U/T19fasLTlsrYQa5CbzyAwuKLqgXzddXkRz+JBz135JEFOQfdERoHxva0LyBMowjO
         94gIeePRN9424MHloBfdTF+SWPFmCW1yvrDa6gYzzvsqx3cHtANhMes9uIGgAD7bgi4D
         aRBlvlrCONpYOy8Js0dj/TM5HgIsSDL30+WX4XhL7sCRGTbHHLOtNBFP01SSdxk1SXqo
         3IYvq6ua+NazkyMfSMZyduU5mmcsTpj5HqKfmP5aqlYwkMNz/nfWWCa+q3LhLWQgIjrB
         JSfKmWavWI6IwaESSWoU0BIid8o7ZfkvGcFvkz8LZEnGF9x7OiWL8PTUD5HDS82edInF
         4BQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FSfmdkMc67pSVKWeTu9ueIeIVQ96dqX66CYGGaBEmZ4=;
        b=IdkUAzADOye7WPhCFCS69IRHLXQ8KXoC5HjdmIQ5JYjCR+VBcqKgTI6BK6Ni3GjCDv
         Fn/etZ8cDfSx4OG/9dC947SyWbMzU6+2N4wuNRSI6v3dWVwg9c/5Pm/tMcbYtW9RhrSQ
         QIWMA8VG5rAeiSRgiH4JCCPq2cRBI4MNCHMO+AC6m3y63GG6UP0n63LqSs4cL38meonA
         fwo9EJrwY1jgt1EgnORp8XMYaWuzE8BvTUG2Nc0bcZi1MJHnfh7cyOvWCJJQNezA/rqb
         IuLwrLdHr3r9zOnTzTSuVwCiCeKgnjM/OEQceKFuoQF7Kh5QiiflWk6bOdvvdYGo2K7j
         AIXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FSfmdkMc67pSVKWeTu9ueIeIVQ96dqX66CYGGaBEmZ4=;
        b=skTlCH4i3ucsp3qODH8eot5tlhGH8ACH81fbJKMpRDSa/fiWRIDrnLDOLUPztWlKrp
         9AyIElUEDACrk9OH2wGPMo6J2d7Xv0mUYECxWiOe9MRxY6EnqehM9KKfkCgk+YEmXpT3
         YhnDygODwcXGJOz9k1QtVSdmBDmC5KWVfZXJfil3W4DnDCP6deErDRlV+oujsmPLfiFR
         KF2GL2rlioliQB2jTEGqkNU1+JBH6DgWso7JmhRthd2y74nfJDVSqsNs5Bjn2GFhK5VV
         mjOGmvo6hj1J/RuQrDLylVFE17bg2c62KL+8qVviTmC9YtOWpCjekhGct7awT8nwI6gn
         L0Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FSfmdkMc67pSVKWeTu9ueIeIVQ96dqX66CYGGaBEmZ4=;
        b=nOiRllEqE6MOB7YBzzEGZmxYcO62qJP9R0MYbGk1iaJRHKqtvkdh8mr/+Mj+6MuHb9
         4SK0E++yYldo96KXsaLUuR9eRp84uGHpbmgToJatpXcNTZ1TQRHSo0RMZzOyInk1v+Fa
         hbskjuhfzBPEQyssTzm6pRS0feoMnEQmNb0wIrX306qnCU/Tg2ot44oc7wWLmgoYJwsZ
         56ohgvX5kfjQThQ1SwUKOSBm80pL+CpgjaanSjvGdm0tD2SKYlLAS73yFVYqo+fiOT6n
         BQMvmcMKuiP0vpHmTVB8U/F/l/zAIW0Sahd8JFzxrtf2eX72HCMakS1CR0t8duDxkOGr
         2Mug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU6OapmrOuYGR/lFt71GshMT+1L0nIp43JnLZyHnIYkDhL8BFb5
	6KLL720AfcBIoppdDObvEIk=
X-Google-Smtp-Source: APXvYqzAe7N+cE3LXGo6wJu7M5QvpUATyYrKT6/gexulIMe4ncbNWoW17ftTMU4D5N9ecSEgvsXiAQ==
X-Received: by 2002:ac2:51a6:: with SMTP id f6mr3168659lfk.174.1575492368529;
        Wed, 04 Dec 2019 12:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1b6:: with SMTP id c22ls122647ljn.14.gmail; Wed, 04
 Dec 2019 12:46:08 -0800 (PST)
X-Received: by 2002:a2e:809a:: with SMTP id i26mr3239233ljg.108.1575492368009;
        Wed, 04 Dec 2019 12:46:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575492368; cv=none;
        d=google.com; s=arc-20160816;
        b=PHjoecsy+aDCm5kAorrT0YAcXbrc/bflyiQ+TqbR8X6E+z4W/wpXXFpca8MSWZav9g
         BQMm1ZZB9xjFrwOCkht8m3ZAyk1BYG64SAEAdXIAPID78jzDByeb27E9Vcx6/hjBYWGx
         tNCpFKim7cAAaUHnzzLtImph/MXZTbQ0+Nhwp9mZaoVB9mWUaamy8pVZM8vflxpFcpvx
         zwFSMyKF1fgasgGTfg7eU5DXm8tBsaBOvFt+CmokyyTsufW4fD9MC5+/n2V9JWa97Tmo
         7kfBL5xERXqtfQJh2vpWWmjI/XbwfJ32/p3jazuaw4bDSp2Jo5VYxZECRXe8q7doUdq0
         MOlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yj1n1pPkONt0RgRx/mE0g33aeh73lCM3ma7j6c1ttNY=;
        b=rN3wBk3J0sZeaY6Lm/5RPN+uMaOiS97cC03tk1zDAFIcr40TinMdTMvAz2IdU15ysH
         95HLaHSVJuZq7tpXCkQDU3NeNfCzusOWZCmM5Tv1TyirbbJbxRLJKFwN4o7D7cgesBMa
         /fPy9cusuEw17IFziMwysADgvr3Zy/dYU4W3RguFLpPtdddu3VsBDlfNWZbW/FXG0/2+
         1RLkUie5kJIn3i2ifDlha6722+QBh/icniPY3I3X55973s8YSCpbjVUtt9teOvkH6Vn1
         g1Be601U5E9qzydnyIVkoezquSo63qFQ/AWppWs6WIHMhza45psL/1lx7IPQqeojPP4Q
         KfZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id c17si394460ljb.3.2019.12.04.12.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Dec 2019 12:46:07 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5] helo=i7.sw.ru)
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1icbWy-0001lh-Pk; Wed, 04 Dec 2019 23:45:53 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	Qian Cai <cai@lca.pw>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: [PATCH 2/2] kasan: Don't allocate page tables in kasan_release_vmalloc()
Date: Wed,  4 Dec 2019 23:45:34 +0300
Message-Id: <20191204204534.32202-2-aryabinin@virtuozzo.com>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20191204204534.32202-1-aryabinin@virtuozzo.com>
References: <20191204204534.32202-1-aryabinin@virtuozzo.com>
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

The purpose of kasan_release_vmalloc() is to unmap and deallocate shadow
memory. The usage of apply_to_page_range() isn't suitable in that scenario
because it allocates pages to fill missing page tables entries.
This also cause sleep in atomic bug:

	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:

	Call Trace:
	 __dump_stack lib/dump_stack.c:77 [inline]
	 dump_stack+0x199/0x216 lib/dump_stack.c:118
	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
	 alloc_pages include/linux/gfp.h:532 [inline]
	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
	 apply_to_pte_range mm/memory.c:2031 [inline]
	 apply_to_pmd_range mm/memory.c:2068 [inline]
	 apply_to_pud_range mm/memory.c:2088 [inline]
	 apply_to_p4d_range mm/memory.c:2108 [inline]
	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
	 __vmalloc_node mm/vmalloc.c:2607 [inline]
	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
	 __do_sys_setsockopt net/socket.c:2133 [inline]
	 __se_sys_setsockopt net/socket.c:2130 [inline]
	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
	 entry_SYSCALL_64_after_hwframe+0x49/0xbe

Add kasan_unmap_page_range() which skips empty page table entries instead
of allocating them.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
 mm/kasan/common.c | 82 +++++++++++++++++++++++++++++++++++++++--------
 1 file changed, 68 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a1e6273be8c3..e9ba7d8ad324 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -857,22 +857,77 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	kasan_unpoison_shadow(start, size);
 }
 
-static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-					void *unused)
+static void kasan_unmap_pte_range(pmd_t *pmd, unsigned long addr,
+				unsigned long end)
 {
-	unsigned long page;
+	pte_t *pte;
 
-	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
+	pte = pte_offset_kernel(pmd, addr);
+	do {
+		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
 
-	spin_lock(&init_mm.page_table_lock);
+		if (!pte_none(ptent))
+			__free_page(pte_page(ptent));
+	} while (pte++, addr += PAGE_SIZE, addr != end);
+}
 
-	if (likely(!pte_none(*ptep))) {
-		pte_clear(&init_mm, addr, ptep);
-		free_page(page);
-	}
-	spin_unlock(&init_mm.page_table_lock);
+static void kasan_unmap_pmd_range(pud_t *pud, unsigned long addr,
+				unsigned long end)
+{
+	pmd_t *pmd;
+	unsigned long next;
 
-	return 0;
+	pmd = pmd_offset(pud, addr);
+	do {
+		next = pmd_addr_end(addr, end);
+		if (pmd_none_or_clear_bad(pmd))
+			continue;
+		kasan_unmap_pte_range(pmd, addr, next);
+	} while (pmd++, addr = next, addr != end);
+}
+
+static void kasan_unmap_pud_range(p4d_t *p4d, unsigned long addr,
+				unsigned long end)
+{
+	pud_t *pud;
+	unsigned long next;
+
+	pud = pud_offset(p4d, addr);
+	do {
+		next = pud_addr_end(addr, end);
+		if (pud_none_or_clear_bad(pud))
+			continue;
+		kasan_unmap_pmd_range(pud, addr, next);
+	} while (pud++, addr = next, addr != end);
+}
+
+static void kasan_unmap_p4d_range(pgd_t *pgd, unsigned long addr,
+				unsigned long end)
+{
+	p4d_t *p4d;
+	unsigned long next;
+
+	p4d = p4d_offset(pgd, addr);
+	do {
+		next = p4d_addr_end(addr, end);
+		if (p4d_none_or_clear_bad(p4d))
+			continue;
+		kasan_unmap_pud_range(p4d, addr, next);
+	} while (p4d++, addr = next, addr != end);
+}
+
+static void kasan_unmap_page_range(unsigned long addr, unsigned long end)
+{
+	pgd_t *pgd;
+	unsigned long next;
+
+	pgd = pgd_offset_k(addr);
+	do {
+		next = pgd_addr_end(addr, end);
+		if (pgd_none_or_clear_bad(pgd))
+			continue;
+		kasan_unmap_p4d_range(pgd, addr, next);
+	} while (pgd++, addr = next, addr != end);
 }
 
 /*
@@ -978,9 +1033,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
 
 	if (shadow_end > shadow_start) {
-		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
-				    (unsigned long)(shadow_end - shadow_start),
-				    kasan_depopulate_vmalloc_pte, NULL);
+		kasan_unmap_page_range((unsigned long)shadow_start,
+				    (unsigned long)shadow_end);
 		flush_tlb_kernel_range((unsigned long)shadow_start,
 				       (unsigned long)shadow_end);
 	}
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191204204534.32202-2-aryabinin%40virtuozzo.com.
