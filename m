Return-Path: <kasan-dev+bncBDQ27FVWWUFRBX44UTXQKGQETVNXVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id EE0C2114234
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 15:04:16 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id s19sf1804364pjp.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 06:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575554655; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGlh1tm1ewgOXKBn3oTDVR2xT5m3VeyXxrPPwJ0dKQ7OAJfjbrYBWU4+kYsWx+BHc2
         Fj1em2Xo8ZbROTbly7bZ0fRppTXamIDJxFiwl/f/GwcTaMkfPZGMOU9lIj4lEmfvF0NV
         dgYprObmAWU5XrIpYjAdo9iRNqQ6c21O6RcdzsQX9K4HFbX3dHeAYR28DK08c/xPZv+z
         BJTAEW+VkqCEuUKqIuF7Vjb3/6IsXyTJ7bLPpd1Id9g0xhL3NtDUbn+FS3Cu9jxOTgSX
         n7BmHJiAeJexX4RjlL2JPbNvGNLvmRlaAL+o1LRmXJjRlY1xqVyASKuqgn4q87A1lDis
         CggA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=QBWNtSK4bw7JBQ9SNL1fJ7qi3caCWP4zLjEp85YEOCM=;
        b=pUOXnCKNJRNtyjXkTI9Cj7scmOFXo5pR2VxIosPYrj8Xbko9Ej+nHKXAFJQ2A4LzUm
         4yhu/6AXMgS88suXOHMapUKwzs4oCtfB4BO1/W0tZgOjOVOibQlAbN6AQeOCH0QKvRTd
         oUjTbDDEvopzcz+eWOS42Qgqha1d2Fu+lxIRt8Df8bd+sbLwTOo56V/DZm8CiENYl0Rg
         wOQQ2x7p+BKO5AzSg6CSm2DWA1UzJMbNt4LuhEU7hR+/oAY/jH8tnxxck5ryCJ2OLbo3
         BtZ+BXWpNPmXiFv0BhDrt6wHIMeHf6mYanjflvrQHCXziQxm53WuQD7ZdgFkUMu9+ulx
         s3ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Asq26IOS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QBWNtSK4bw7JBQ9SNL1fJ7qi3caCWP4zLjEp85YEOCM=;
        b=G15wbaGlLJ0CVcLChDSMq0wHX7k7CGPJ1Seld1UXbCrDexEE8wvk5GhZEaMxkB1Rp6
         42HibXn45pEgf3RjZgzeUmXvgqW0WWk5rIUplagMTCUvCvn6aiOBskmlmHPMQ/h1kjzz
         sboutn9SFjySpHiY1H4R4WwoielXFj2+T5PZ8tc9aJoJzzvzbfNJ8kcA11pYH6LqsQq7
         9ZgHU5QWUU0BrxIQtBB/nmRDyb0vLCQL86vbXusLzJ/dcrzfyAG0tZ7gtrHkRTUx3Knl
         O+f6TBUYVnhkPHGLhOIDnvCWDcfCg9aZ+ob3+5oqz9K2TTAue1BBRINSuloJLAVzxJ5w
         +gzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QBWNtSK4bw7JBQ9SNL1fJ7qi3caCWP4zLjEp85YEOCM=;
        b=Y8DHKKzilj0gZdMAp+5+AlWPz57mZjNo5IOt7nxPvpDZGYx0JaUHV4NYLXkx1yhX8p
         rPwW3F+mFw8peg+9QZUmdkQ9cISYs1C9DwfNvalZz7jUNZToJr9TbkqUyuwIhD4yqfnw
         R4aU+POuq6QC/dT/mTJk5DDuCk1R9SafSfo+1qIqaPehZpFpj4A5GW9lMHfdeKawQyO2
         UaWjGH36Nj/2q32PNDBwHkeB6BwMEKecUuy1/oGW5MiBvFhP6nwwuKjgzC2prZi9kJMR
         K3Yhga0v6+29B82gFalhcXOl8fBx1l/vKGuphD2/s3SFMa7JLXgH60Ib8S5cSar7DxnP
         6cnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYHCLt6QoM/XgKMV/5uE49V9QGQtxvix/BDJwJY1vCPkx4T0sa
	L0WrJPca0Gw51sJs0Yb0Opg=
X-Google-Smtp-Source: APXvYqxdAHhmbnFalId6dWYlPmzwH7NMGluTFJAWoZce3TjGlT2xqqQpkc0MHI6hKNmi5C/Ti0xSiQ==
X-Received: by 2002:a63:e90f:: with SMTP id i15mr9599792pgh.9.1575554655390;
        Thu, 05 Dec 2019 06:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7c94:: with SMTP id x142ls876705pfc.3.gmail; Thu, 05 Dec
 2019 06:04:14 -0800 (PST)
X-Received: by 2002:aa7:9315:: with SMTP id 21mr9087215pfj.187.1575554654958;
        Thu, 05 Dec 2019 06:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575554654; cv=none;
        d=google.com; s=arc-20160816;
        b=Mr5jR8gzrwVppOH6T97l2ophOk1uhYfP6egXVjLzgITKRBqguyHhnJbIrMRcHPHTwW
         R33t46Bpe4X6nFpxSYk8Zl5ryaD5nDHyOq4+4hnW8fMZyxZ1F1v3e5+mfGWrI8girWtt
         2tZwPnsW/Q8Hh5hKzihQu7Y3SxoUiWcTHS9TT7ZCrz65fOhToajbW0SMvAVhvKsKEC7N
         azie5CVxewJh8n1i0EX95/1FuoQMyHpqzxjjAN/EMLIfTxFV1FjTW1g83yJmfgkJViLy
         mCBx3TTmOKjW71ZfVpmiqqo/EByQbnnQm8gAIDJcqcs35wsrwCnXqqHoaDsZQ2rlArf+
         n6oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=t4U/eRKLWH+P5sMJLg1gBzVLKge0A2yZRS0R5HxW/2Q=;
        b=ydjBu5U9AQDt5NiB5yEO2nINjUJLhscPGj2AqAdrpSqvFcAP5n5xCnMJ6RgrLNoApf
         7W1q9bOI+38J+JTOuAd7uSAGN225Aziy8cMc9vQlJqb3VA/Hxv6xEs6Wj+dGPrScC/Td
         O1H1rdVM4hLZnC7GALcaNZHxYJUJyzp51uL+migOyPOq1J+cJpPZv9hqVG4qkYe1nCxf
         AhHjgwJohCUw7Q++/+gkyyK6BuzJMqM10sHkBf172aPaxlHuSAr/gAGbyEI/BHOP4AG5
         kEUAhUaGQKJRnqOhkDTrRaCN1+hpM4Sq2SGtvWmQd5iRcM94/SyAFZioeyZyHPWwJyfH
         ckhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Asq26IOS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id h18si596014plr.4.2019.12.05.06.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 06:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id o9so1298531plk.6
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 06:04:14 -0800 (PST)
X-Received: by 2002:a17:902:54f:: with SMTP id 73mr9434121plf.213.1575554653485;
        Thu, 05 Dec 2019 06:04:13 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-61b9-031c-bed1-3502.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:61b9:31c:bed1:3502])
        by smtp.gmail.com with ESMTPSA id q185sm12628423pfq.110.2019.12.05.06.04.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2019 06:04:12 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	linux-kernel@vger.kernel.org,
	dvyukov@google.com
Cc: daniel@iogearbox.net,
	cai@lca.pw,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 1/3] mm: add apply_to_existing_pages helper
Date: Fri,  6 Dec 2019 01:04:05 +1100
Message-Id: <20191205140407.1874-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Asq26IOS;       spf=pass
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

apply_to_page_range takes an address range, and if any parts of it
are not covered by the existing page table hierarchy, it allocates
memory to fill them in.

In some use cases, this is not what we want - we want to be able to
operate exclusively on PTEs that are already in the tables.

Add apply_to_existing_pages for this. Adjust the walker functions
for apply_to_page_range to take 'create', which switches them between
the old and new modes.

This will be used in KASAN vmalloc.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/mm.h |   3 ++
 mm/memory.c        | 131 +++++++++++++++++++++++++++++++++------------
 2 files changed, 99 insertions(+), 35 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index c97ea3b694e6..f4dba827d76e 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2621,6 +2621,9 @@ static inline int vm_fault_to_errno(vm_fault_t vm_fault, int foll_flags)
 typedef int (*pte_fn_t)(pte_t *pte, unsigned long addr, void *data);
 extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
 			       unsigned long size, pte_fn_t fn, void *data);
+extern int apply_to_existing_pages(struct mm_struct *mm, unsigned long address,
+				   unsigned long size, pte_fn_t fn,
+				   void *data);
 
 #ifdef CONFIG_PAGE_POISONING
 extern bool page_poisoning_enabled(void);
diff --git a/mm/memory.c b/mm/memory.c
index 606da187d1de..e508ba7e0a19 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2021,26 +2021,34 @@ EXPORT_SYMBOL(vm_iomap_memory);
 
 static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 				     unsigned long addr, unsigned long end,
-				     pte_fn_t fn, void *data)
+				     pte_fn_t fn, void *data, bool create)
 {
 	pte_t *pte;
-	int err;
+	int err = 0;
 	spinlock_t *uninitialized_var(ptl);
 
-	pte = (mm == &init_mm) ?
-		pte_alloc_kernel(pmd, addr) :
-		pte_alloc_map_lock(mm, pmd, addr, &ptl);
-	if (!pte)
-		return -ENOMEM;
+	if (create) {
+		pte = (mm == &init_mm) ?
+			pte_alloc_kernel(pmd, addr) :
+			pte_alloc_map_lock(mm, pmd, addr, &ptl);
+		if (!pte)
+			return -ENOMEM;
+	} else {
+		pte = (mm == &init_mm) ?
+			pte_offset_kernel(pmd, addr) :
+			pte_offset_map_lock(mm, pmd, addr, &ptl);
+	}
 
 	BUG_ON(pmd_huge(*pmd));
 
 	arch_enter_lazy_mmu_mode();
 
 	do {
-		err = fn(pte++, addr, data);
-		if (err)
-			break;
+		if (create || !pte_none(*pte)) {
+			err = fn(pte++, addr, data);
+			if (err)
+				break;
+		}
 	} while (addr += PAGE_SIZE, addr != end);
 
 	arch_leave_lazy_mmu_mode();
@@ -2052,62 +2060,83 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 
 static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
 				     unsigned long addr, unsigned long end,
-				     pte_fn_t fn, void *data)
+				     pte_fn_t fn, void *data, bool create)
 {
 	pmd_t *pmd;
 	unsigned long next;
-	int err;
+	int err = 0;
 
 	BUG_ON(pud_huge(*pud));
 
-	pmd = pmd_alloc(mm, pud, addr);
-	if (!pmd)
-		return -ENOMEM;
+	if (create) {
+		pmd = pmd_alloc(mm, pud, addr);
+		if (!pmd)
+			return -ENOMEM;
+	} else {
+		pmd = pmd_offset(pud, addr);
+	}
 	do {
 		next = pmd_addr_end(addr, end);
-		err = apply_to_pte_range(mm, pmd, addr, next, fn, data);
-		if (err)
-			break;
+		if (create || !pmd_none_or_clear_bad(pmd)) {
+			err = apply_to_pte_range(mm, pmd, addr, next, fn, data,
+						 create);
+			if (err)
+				break;
+		}
 	} while (pmd++, addr = next, addr != end);
 	return err;
 }
 
 static int apply_to_pud_range(struct mm_struct *mm, p4d_t *p4d,
 				     unsigned long addr, unsigned long end,
-				     pte_fn_t fn, void *data)
+				     pte_fn_t fn, void *data, bool create)
 {
 	pud_t *pud;
 	unsigned long next;
-	int err;
+	int err = 0;
 
-	pud = pud_alloc(mm, p4d, addr);
-	if (!pud)
-		return -ENOMEM;
+	if (create) {
+		pud = pud_alloc(mm, p4d, addr);
+		if (!pud)
+			return -ENOMEM;
+	} else {
+		pud = pud_offset(p4d, addr);
+	}
 	do {
 		next = pud_addr_end(addr, end);
-		err = apply_to_pmd_range(mm, pud, addr, next, fn, data);
-		if (err)
-			break;
+		if (create || !pud_none_or_clear_bad(pud)) {
+			err = apply_to_pmd_range(mm, pud, addr, next, fn, data,
+						 create);
+			if (err)
+				break;
+		}
 	} while (pud++, addr = next, addr != end);
 	return err;
 }
 
 static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
 				     unsigned long addr, unsigned long end,
-				     pte_fn_t fn, void *data)
+				     pte_fn_t fn, void *data, bool create)
 {
 	p4d_t *p4d;
 	unsigned long next;
-	int err;
+	int err = 0;
 
-	p4d = p4d_alloc(mm, pgd, addr);
-	if (!p4d)
-		return -ENOMEM;
+	if (create) {
+		p4d = p4d_alloc(mm, pgd, addr);
+		if (!p4d)
+			return -ENOMEM;
+	} else {
+		p4d = p4d_offset(pgd, addr);
+	}
 	do {
 		next = p4d_addr_end(addr, end);
-		err = apply_to_pud_range(mm, p4d, addr, next, fn, data);
-		if (err)
-			break;
+		if (create || !p4d_none_or_clear_bad(p4d)) {
+			err = apply_to_pud_range(mm, p4d, addr, next, fn, data,
+						 create);
+			if (err)
+				break;
+		}
 	} while (p4d++, addr = next, addr != end);
 	return err;
 }
@@ -2130,7 +2159,7 @@ int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
 	pgd = pgd_offset(mm, addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data);
+		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, true);
 		if (err)
 			break;
 	} while (pgd++, addr = next, addr != end);
@@ -2139,6 +2168,38 @@ int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
 }
 EXPORT_SYMBOL_GPL(apply_to_page_range);
 
+/*
+ * Scan a region of virtual memory, calling a provided function on
+ * each leaf page table where it exists.
+ *
+ * Unlike apply_to_page_range, this does _not_ fill in page tables
+ * where they are absent.
+ */
+int apply_to_existing_pages(struct mm_struct *mm, unsigned long addr,
+			    unsigned long size, pte_fn_t fn, void *data)
+{
+	pgd_t *pgd;
+	unsigned long next;
+	unsigned long end = addr + size;
+	int err = 0;
+
+	if (WARN_ON(addr >= end))
+		return -EINVAL;
+
+	pgd = pgd_offset(mm, addr);
+	do {
+		next = pgd_addr_end(addr, end);
+		if (pgd_none_or_clear_bad(pgd))
+			continue;
+		err = apply_to_p4d_range(mm, pgd, addr, next, fn, data, false);
+		if (err)
+			break;
+	} while (pgd++, addr = next, addr != end);
+
+	return err;
+}
+EXPORT_SYMBOL_GPL(apply_to_existing_pages);
+
 /*
  * handle_pte_fault chooses page fault handler according to an entry which was
  * read non-atomically.  Before making any commitment, on those architectures
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205140407.1874-1-dja%40axtens.net.
