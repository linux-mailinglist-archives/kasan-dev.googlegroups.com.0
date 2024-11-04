Return-Path: <kasan-dev+bncBAABBOPFUG4QMGQEBNIK2PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 5473F9BACF3
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 08:07:40 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-7ee07d0f395sf4619814a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Nov 2024 23:07:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730704058; cv=pass;
        d=google.com; s=arc-20240605;
        b=dG7Lhyq2Cu4NbdT0RjNeb0E6s8vgC8RTGiXhUo3O9sk/mtAmnFbp/LquV5HbSFeMg+
         SB5Lv/3FWWS83w3xUgpXrXuFf2wWLIrsmD8vp++ZTumK0+M2rmE7I1ZuOoIiyFeXq+Sv
         IUIv5FFLdf/l03dj77nOF+iupR41UD1VJdLdMuq/rAEw3Z9T932ld7jQ4e1Wxb+4qyFd
         S9RtjCqkWJHRxBTIKhhgspV4RF8m9CRTRvv6g0zPYMIKFZxH+OgCbg02JgQiuw+TJOiI
         cLzRB4+1RtV4LrqwBpxKoUvFSiklbGTjvNqRYwxSJ/l0niOu/1egQMk/x9doHZ7VZ//X
         tuDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3Gzhz1aXD4CRgHFOSclLgWXwV/0Pa4IQJ6NpGWNvzU8=;
        fh=Dv5/iEybgsjuzhUYRvP5CUtm1N5RCC94q7L9L2nPWj0=;
        b=ISIQ8hlcCf0aFuqtqASzFNnjjfKSohXn0nBKPzToGU+KrjWq5RKZH4ejd7UiDj/b4I
         a0B0TC+W3DDOVQZfU8i8haeEcwQyIdJCORWcqS13FuAYWCasV26v6LnNShuIplUC1BGV
         r3YEyPtJmvoDbQQhCfSUI6ogARqQM0rZW2BxJxqrOOHclUk+JSyWuOLJgvyQoZfBsxys
         /lpxs3li8M469fA08FBWgkZfGTcnJUZCRXiTE1gF67gS9y1SS16HkG8fdszjJ8M9xqxj
         Kz6EKumqKs26KfjJsPvInzNSZCFg5LFrLynoO853KGwJiXWphjP/KuhNsMMAe4l46NS6
         PExQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730704058; x=1731308858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3Gzhz1aXD4CRgHFOSclLgWXwV/0Pa4IQJ6NpGWNvzU8=;
        b=UnQdV6o91Fx4EhsO2BimGPrpMi1NkSnlo2ed1p/J4LzmCZgnqR2+V4sIDiWXVneJmN
         nZTiPrRnIHE32pl69Ag2g1o6YN0JbUo6dBaXZSsNV4gDGd7iMaUgBBtTTNYNUviylJ8P
         2XAgL0yyVh2Uj+dkfplB5GcytUUiGw9wfwyDgd/m4uONi5baScCVRZC8bkKhASRzKid1
         rI4hS1goa+uQOXFu23Wt6yU8rJep/kfTTCTksiunGwVFzTrtWkz3ZPmM6sPvtqkGRgKB
         xROywoQstIoYVLuM6g6AdY8vMHH/4xa3/1cs9JT68wvfPFr08lP7Cp54SlX0O2KYssHz
         6O7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730704058; x=1731308858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3Gzhz1aXD4CRgHFOSclLgWXwV/0Pa4IQJ6NpGWNvzU8=;
        b=hI5Nez7l0dC66avO33/qqYKda58XJ1MVcP1D3MB7kkqcUMN695aYypn/zanqer4vgk
         e+DeQ52VaMmvfgeCn+yERWHwveYX8TpUcbRd/31ffX3iSsEAGmzPwr3Ro6shnAAEQ51v
         pjWB5sMV/GT5Sl6OwOjYUNwCU4uY6WuLmI448BdPfRHWPnZkIrtI5mCZYd2/8KvKPUbi
         aDeuvfKRRvyhfoeWJiOw5erpUpw1cMPPYFbrUj0jTVITE3FFAX/gsn8S/OIhzQlh+OD7
         2prX+ze3XnQrRAoRyNN9nA/Qquan0z+0ieKUdYVK6Bp0oU30tNLSvMjnja9YEmOSIJ4H
         XOoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLPbDKL/f5JWgs0G9VCE3KXOA6zY0iQ4dcbfvVSpquluMRalfoUv14bwBGaQnmpI76TWmL+Q==@lfdr.de
X-Gm-Message-State: AOJu0YwN2pCjXERBdS9AcrDXssZCOMPnPD7twpFD3EoI2sQjmzciQL+0
	RMXFQ8gkLWLvG2ZNhQgLHQkUSsQHsvXC7A1jGt+u6StmflMKaNDn
X-Google-Smtp-Source: AGHT+IFtEx5QvlSGVPaBuF/q7PZ6hGe9h8wiRSJ9+i1z7rZrUFSqwhZxwrVLuzqPGQjZ/a5M3KShcw==
X-Received: by 2002:a17:902:ce89:b0:20b:c287:202d with SMTP id d9443c01a7336-21103ca9e64mr220725785ad.55.1730704057991;
        Sun, 03 Nov 2024 23:07:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2906:b0:1f7:38a2:f1eb with SMTP id
 d9443c01a7336-211038668c6ls3630195ad.1.-pod-prod-03-us; Sun, 03 Nov 2024
 23:07:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZNFc8Kd+RonsWbzbr5waXKyUBB27vCixYY0xG4psgsZyXy6/8MpZCBmWSqFMJbY5IE1dBE250Xw4=@googlegroups.com
X-Received: by 2002:a17:902:ce89:b0:20b:c287:202d with SMTP id d9443c01a7336-21103ca9e64mr220725015ad.55.1730704056186;
        Sun, 03 Nov 2024 23:07:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730704056; cv=none;
        d=google.com; s=arc-20240605;
        b=alkpukkQpdT40aByi4U6iLWH7N/pdSA0i13h8NAt/2d9pW+7jnoYiyH05RCCGO5wYK
         CtVKvPK7/0PaZ16+UhDlEZNis8dyAVFLeLAfaX7mGEU+yoSDc9XGQx1sQJteGANOCTtl
         kJXdvVoNAcWh5El8/zdwHX14IAp6iGxQGi30svGHZS4byVRear1DVBkbxUAtp8HBdiQx
         VeF8MznC/LpQDIP9ToIVvNKMlONcUYB5mCDYzl+VLiOdyr9hhZ4+LM6G/IlHu7om/wxb
         kVp2PYkOL2jbZZIMXqYwCpzmT66kfhO3i1qB771rjxZLHyIhqixOyUMIghiwoq2sHQfa
         /pTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=KGtT4PaLokwZPOqhhQ14keJTwFnPjx9OHr8psNQu1K0=;
        fh=tEDwYQREGwjx5jevK6Xic8KPiOWDrhGjeQsL7oWjUEU=;
        b=TMxTIetjTjfplvvDNRshVYe7RZHc6JvkdS4sdFjRV5q7GTcXMtfEXno/wxwm9ZcK5R
         NeszyNDVa74ZbyW9n8JgOkA5afgf+BlYmHcbZ+aejzQc7iWfptCw1XPPzoUGqfiOtvyA
         Uw0AJrTmAgVkd8hhyk0qWsuh/0vyXBR5W82Bh2WH6wzxYbh8mSU6eQHLgp3aX0PJuKAC
         /ZmyoCmJJEFqYMAFHrEBqshwqhhcUH+yEV837VDNz0PR6sVZQ1irBsPrO2HjG3CEzouf
         GnpvZFUD5AgJg3UKLq9lPuYSgOhqTlixiF2faypmmVsCR9yUNUh70lmjUMfKGF7MFKSl
         PDRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-2110572d9easi3260555ad.6.2024.11.03.23.07.34
        for <kasan-dev@googlegroups.com>;
        Sun, 03 Nov 2024 23:07:36 -0800 (PST)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8AxUa+zcihn4LwtAA--.26347S3;
	Mon, 04 Nov 2024 15:07:31 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMAxreCxcihnbNE9AA--.30183S2;
	Mon, 04 Nov 2024 15:07:30 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Huacai Chen <chenhuacai@loongson.cn>
Subject: [PATCH v3] mm: define general function pXd_init()
Date: Mon,  4 Nov 2024 15:07:12 +0800
Message-Id: <20241104070712.52902-1-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: qMiowMAxreCxcihnbNE9AA--.30183S2
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

Function pud_init(), pmd_init() and kernel_pte_init() are duplicated
defined in file kasan.c and sparse-vmemmap.c as weak functions. Move
them to generic header file pgtable.h, architecture can redefine them.

Reviewed-by: Huacai Chen <chenhuacai@loongson.cn>
Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
v2 ... v3:
  1. Define macro pxd_init after function pxd_init() is declared.

v1 ... v2:
  1. Add general function definition about kernel_pte_init().
---
 arch/loongarch/include/asm/pgtable.h |  3 +++
 arch/mips/include/asm/pgtable-64.h   |  2 ++
 include/linux/mm.h                   |  3 ---
 include/linux/pgtable.h              | 21 +++++++++++++++++++++
 mm/kasan/init.c                      | 12 ------------
 mm/sparse-vmemmap.c                  | 12 ------------
 6 files changed, 26 insertions(+), 27 deletions(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 20714b73f14c..da346733a1da 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -268,8 +268,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pm
  */
 extern void pgd_init(void *addr);
 extern void pud_init(void *addr);
+#define pud_init pud_init
 extern void pmd_init(void *addr);
+#define pmd_init pmd_init
 extern void kernel_pte_init(void *addr);
+#define kernel_pte_init kernel_pte_init
 
 /*
  * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
diff --git a/arch/mips/include/asm/pgtable-64.h b/arch/mips/include/asm/pgtable-64.h
index 401c1d9e4409..6e854bb11f37 100644
--- a/arch/mips/include/asm/pgtable-64.h
+++ b/arch/mips/include/asm/pgtable-64.h
@@ -317,7 +317,9 @@ static inline pmd_t *pud_pgtable(pud_t pud)
  */
 extern void pgd_init(void *addr);
 extern void pud_init(void *addr);
+#define pud_init pud_init
 extern void pmd_init(void *addr);
+#define pmd_init pmd_init
 
 /*
  * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 61fff5d34ed5..651bdc1bef48 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3818,9 +3818,6 @@ void *sparse_buffer_alloc(unsigned long size);
 struct page * __populate_section_memmap(unsigned long pfn,
 		unsigned long nr_pages, int nid, struct vmem_altmap *altmap,
 		struct dev_pagemap *pgmap);
-void pud_init(void *addr);
-void pmd_init(void *addr);
-void kernel_pte_init(void *addr);
 pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
 p4d_t *vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node);
 pud_t *vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node);
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index e8b2ac6bd2ae..adee214c21f8 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -90,6 +90,27 @@ static inline unsigned long pud_index(unsigned long address)
 #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
 #endif
 
+#ifndef kernel_pte_init
+static inline void kernel_pte_init(void *addr)
+{
+}
+#define kernel_pte_init kernel_pte_init
+#endif
+
+#ifndef pmd_init
+static inline void pmd_init(void *addr)
+{
+}
+#define pmd_init pmd_init
+#endif
+
+#ifndef pud_init
+static inline void pud_init(void *addr)
+{
+}
+#define pud_init pud_init
+#endif
+
 #ifndef pte_offset_kernel
 static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
 {
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ac607c306292..ced6b29fcf76 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -106,10 +106,6 @@ static void __ref zero_pte_populate(pmd_t *pmd, unsigned long addr,
 	}
 }
 
-void __weak __meminit kernel_pte_init(void *addr)
-{
-}
-
 static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 				unsigned long end)
 {
@@ -145,10 +141,6 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 	return 0;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				unsigned long end)
 {
@@ -187,10 +179,6 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 	return 0;
 }
 
-void __weak __meminit pud_init(void *addr)
-{
-}
-
 static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 				unsigned long end)
 {
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index c0388b2e959d..cec67c5f37d8 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -184,10 +184,6 @@ static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
 	return p;
 }
 
-void __weak __meminit kernel_pte_init(void *addr)
-{
-}
-
 pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 {
 	pmd_t *pmd = pmd_offset(pud, addr);
@@ -201,10 +197,6 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 	return pmd;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 {
 	pud_t *pud = pud_offset(p4d, addr);
@@ -218,10 +210,6 @@ pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 	return pud;
 }
 
-void __weak __meminit pud_init(void *addr)
-{
-}
-
 p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 {
 	p4d_t *p4d = p4d_offset(pgd, addr);

base-commit: a8cc7432728d019a10cb412401ebc15ed7504289
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104070712.52902-1-maobibo%40loongson.cn.
