Return-Path: <kasan-dev+bncBC447XVYUEMRBIHK32AAMGQEIMWHOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 6690630A2F1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 09:00:32 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id q24sf4469374wmc.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 00:00:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612166432; cv=pass;
        d=google.com; s=arc-20160816;
        b=DtLXogsJD/83RF30ibVt/tJFrjRNLOK5FJ4mvMbZ2O7KkrVc/XDef67S00JQp5D4Kc
         yUlhN8IGN4DJ1SQ5BLesAbb5w/sRLrrB1kgGIowF2MFdw5HrC4zQcb9wYg61QN+CRJkY
         SzthaBJ9RZjJcO6E4j5W8KhmnOp4dOHAp5XxovRUlhZjqooPImR9soYESUmsArduPzFh
         CcQDXpzfAUqCPRMhtEl3tUj7qo7cghfysZPNziZPM5mD86qc4JOLrA9tBZSfukW0hehK
         XWdmJZCFYIIYLZ7/gjDMB2olXiO5ZtXtWeYiyQ4oSsAd9N71UZvi/ziwqDItGdubT1xN
         WWlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4THDDr90ZCOVEUkmgpmn8/H3bAKLe32XkPL1TVySRDA=;
        b=uR9gy/5kRoQNu8y5kWHLGmMFs8230f2hHymTduLYc/SI+SzeWU7r0adkO5WxfHvzdx
         Me7B+fmU4tDdDt7Rk3XqTya4M5iXVT0ib/sWAqwbDv1I8igrSoruH89ESEdVE99srCnx
         ecXiPcPAQPYMEfDWOwlaPm0XObKnvCNpP05yzxAsSF1m5F2HlDbVhkIs+IvvlXiX/7UB
         /bDE0mo1jperl7/k8I3yRcYoKvTmaIfNOoz3371fzvj9BfW5r/51g7bovtz7596Izqdu
         X7xLqQbpuK6VR7NSWt4/pDr1QCcnypGSAJ5fTbzGo5XJyFiBh7CIpHGWVbG/JYOJ2aBK
         jH2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4THDDr90ZCOVEUkmgpmn8/H3bAKLe32XkPL1TVySRDA=;
        b=MLv4z4vxBWKJXNH7SgtmXK4OE4tu5NtMjS5LV89Xj4+fs7XQGcgVzKc/rp0fNU/B70
         mxKVdhgQNJERSNX+x9bN4L3YaGpDZv2eX34FX19HUuQaJPq+iuDVcnTqGOaDopew6naN
         OT7rROy+K0MB8f/eBxr5V5YyxUPEpB0ehk9yfoAIjcOWvYJYK2EzQVKUK20Yi8d0E329
         2mcAEQxcVtfaWBGcybK9UYqZxlR+GgP1dSOqWKHN8385ueIDjbU+YPOs5+hqfWxU5GKA
         ItU1Tkspq5db7xjxn9IK5wHUBbTfAjavMJfTlpIqSHNAXYNibT1cCoe7zxzRN9amlf8A
         MN9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4THDDr90ZCOVEUkmgpmn8/H3bAKLe32XkPL1TVySRDA=;
        b=RU64QR9GXY67FOCQHRNPxaWZYCxmPCu2Jyr/cJrJRtVkbI+6BKmo9Go7E8ufCVWf0y
         p3m2XC52otXXWJ8piccq7SrbK+jvDLKKSGv69J8SmmYvKIfGFKlToE9KRCZlTLh/9nFs
         LOcZ8+ljsJT/lQs1Kis+unePu4u4FYyvZ/IERa3pDOyX0hj9gFW1/3kvInK9luQrQ0OM
         zJKe33XcU86yvKjjyx9idgPzPZRpLJf5h2twUlBPemWoHB3mCDj9slMqZ8C/KImKxPXP
         POLOS/clTQt8HIMOWI/cdfoVxCl6tCgWCjzbYjeQU7S4/gkuye8H2KH/kPQqMWQlK3NC
         BmeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318BetoF4KuaG1LDbUqeQ6yaeVCAQ6hgeR7tvcl9lTdAx+PC4Tv
	d831vjGO7x3cDgFPXqN0lr8=
X-Google-Smtp-Source: ABdhPJwrG6Ykgvj2Qk37ou/4YUcoSzHG336D2R1I+HpjyJDcs7Ql6acfJvael3wZG6PF5LxazTj5Ag==
X-Received: by 2002:adf:e7c1:: with SMTP id e1mr16767222wrn.23.1612166432156;
        Mon, 01 Feb 2021 00:00:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f852:: with SMTP id d18ls7501453wrq.2.gmail; Mon, 01 Feb
 2021 00:00:31 -0800 (PST)
X-Received: by 2002:a5d:5902:: with SMTP id v2mr16357311wrd.426.1612166431367;
        Mon, 01 Feb 2021 00:00:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612166431; cv=none;
        d=google.com; s=arc-20160816;
        b=gQ3qS6X4YkRijiVYSSjHcUU4HGp6gzJTVPltoghRtFrEz3X4wi4PQH+Ccp817lPMPH
         rSVMtBoRiBOJ0nTfQMHRMlG2sFQ0bFXNcYfEidm/rXop8nNNG5FJXj460veqjetaQ5ty
         yzECMJxY572uVA3Pj8Ezfv7/VG3FIZ5sNXPz64ZjZeDRnCYQ/ATa/m7pFsL1HfxVfkwC
         Wwy5RgNeRkA0WXbZ4E2f629p+//agJZCjo8zLjGwku3TrL1YxQ3eTGcfuBv8xLt/Mco/
         BMOxZYGeFBjwsU8EPBzy+MfD0nLw7bJ64W0hkvpRUhNpJHdM1xA7LXxgx0qezafaYVPy
         AJuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=dnbVM1504icxg8r0Eh+Rcs2WqoWdZXmQC6Wui7i5VH0=;
        b=ReUB8caNU0O63lZEZPQS4/2KHvJLVCcoHHCrU1A9lXMYeVmpa7yMhtqkrKX6BWSMed
         zNMuGAPzmQFyv4Jc8UorjlGS/HkGO63fCPC73t3hWg6+sqJyhNMCcLe7ljKdcKbcqlyA
         IViKlznYptr/iyJrgvNZINdyKo8Dn9koPo7d2+BA6xQHmAWWONCabf4ZwFKScpA4SVSy
         6/UBTIuLrHIb0/uyUGf4OQnotRAmmC/1TGU05HGeMxiyCDg/+hxsmU0L/w3Pb2iXAqAB
         ihB3P8TpqLPc+OffgFtgza4dxH32iFME/GkUpDU2gOL2Pz7sa7mVnoUYRu3zW+2GoCBg
         fLKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id n7si859082wru.2.2021.02.01.00.00.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 01 Feb 2021 00:00:31 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 82.65.183.113
Received: from debian.internal.upmem.com (82-65-183-113.subs.proxad.net [82.65.183.113])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 481CE2000E;
	Mon,  1 Feb 2021 08:00:26 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH] riscv: Improve kasan population by using hugepages when possible
Date: Mon,  1 Feb 2021 03:00:24 -0500
Message-Id: <20210201080024.844-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Kasan function that populates the shadow regions used to allocate them
page by page and did not take advantage of hugepages, so fix this by
trying to allocate hugepages of 1GB and fallback to 2MB hugepages or 4K
pages in case it fails.

This reduces the page table memory consumption and improves TLB usage,
as shown below:

Before this patch:

---[ Kasan shadow start ]---
0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PTE     . A . . . . R V
0xffffffc400000000-0xffffffc447fc0000    0x00000002b7f4f000   1179392K PTE     D A . . . W R V
0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PTE     . A . . . . R V
---[ Kasan shadow end ]---

After this patch:

---[ Kasan shadow start ]---
0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PTE     . A . . . . R V
0xffffffc400000000-0xffffffc440000000    0x0000000240000000         1G PGD     D A . . . W R V
0xffffffc440000000-0xffffffc447e00000    0x00000002b7e00000       126M PMD     D A . . . W R V
0xffffffc447e00000-0xffffffc447fc0000    0x00000002b818f000      1792K PTE     D A . . . W R V
0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PTE     . A . . . . R V
---[ Kasan shadow end ]---

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/kasan_init.c | 101 +++++++++++++++++++++++++++----------
 1 file changed, 73 insertions(+), 28 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index a8a2ffd9114a..8f11b73018b1 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -47,37 +47,82 @@ asmlinkage void __init kasan_early_init(void)
 	local_flush_tlb_all();
 }
 
-static void __init populate(void *start, void *end)
+static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pte_t *ptep = memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
+
+	do {
+		phys_addr = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
+		set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
+	} while (ptep++, vaddr += PAGE_SIZE, vaddr != end);
+
+	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(ptep)), PAGE_TABLE));
+}
+
+static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pmd_t *pmdp = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
+	unsigned long next;
+
+	do {
+		next = pmd_addr_end(vaddr, end);
+
+		if (IS_ALIGNED(vaddr, PMD_SIZE) && (next - vaddr) >= PMD_SIZE) {
+			phys_addr = memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
+			if (phys_addr) {
+				set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				continue;
+			}
+		}
+
+		kasan_populate_pte(pmdp, vaddr, end);
+	} while (pmdp++, vaddr = next, vaddr != end);
+
+	/*
+	 * Wait for the whole PGD to be populated before setting the PGD in
+	 * the page table, otherwise, if we did set the PGD before populating
+	 * it entirely, memblock could allocate a page at a physical address
+	 * where KASAN is not populated yet and then we'd get a page fault.
+	 */
+	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(pmdp)), PAGE_TABLE));
+}
+
+static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
+{
+	phys_addr_t phys_addr;
+	pgd_t *pgdp = pgd_offset_k(vaddr);
+	unsigned long next;
+
+	do {
+		next = pgd_addr_end(vaddr, end);
+
+		if (IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
+			phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
+			if (phys_addr) {
+				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				continue;
+			}
+		}
+
+		kasan_populate_pmd(pgdp, vaddr, end);
+	} while (pgdp++, vaddr = next, vaddr != end);
+}
+
+/*
+ * This function populates KASAN shadow region focusing on hugepages in
+ * order to minimize the page table cost and TLB usage too.
+ * Note that start must be PGDIR_SIZE-aligned in SV39 which amounts to be
+ * 1G aligned (that represents a 8G alignment constraint on virtual address
+ * ranges because of KASAN_SHADOW_SCALE_SHIFT).
+ */
+static void __init kasan_populate(void *start, void *end)
 {
-	unsigned long i, offset;
 	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
 	unsigned long vend = PAGE_ALIGN((unsigned long)end);
-	unsigned long n_pages = (vend - vaddr) / PAGE_SIZE;
-	unsigned long n_ptes =
-	    ((n_pages + PTRS_PER_PTE) & -PTRS_PER_PTE) / PTRS_PER_PTE;
-	unsigned long n_pmds =
-	    ((n_ptes + PTRS_PER_PMD) & -PTRS_PER_PMD) / PTRS_PER_PMD;
-
-	pte_t *pte =
-	    memblock_alloc(n_ptes * PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
-	pmd_t *pmd =
-	    memblock_alloc(n_pmds * PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
-	pgd_t *pgd = pgd_offset_k(vaddr);
-
-	for (i = 0; i < n_pages; i++) {
-		phys_addr_t phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
-		set_pte(&pte[i], pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
-	}
-
-	for (i = 0, offset = 0; i < n_ptes; i++, offset += PTRS_PER_PTE)
-		set_pmd(&pmd[i],
-			pfn_pmd(PFN_DOWN(__pa(&pte[offset])),
-				__pgprot(_PAGE_TABLE)));
 
-	for (i = 0, offset = 0; i < n_pmds; i++, offset += PTRS_PER_PMD)
-		set_pgd(&pgd[i],
-			pfn_pgd(PFN_DOWN(__pa(&pmd[offset])),
-				__pgprot(_PAGE_TABLE)));
+	kasan_populate_pgd(vaddr, vend);
 
 	local_flush_tlb_all();
 	memset(start, 0, end - start);
@@ -99,7 +144,7 @@ void __init kasan_init(void)
 		if (start >= end)
 			break;
 
-		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
+		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
 	};
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210201080024.844-1-alex%40ghiti.fr.
