Return-Path: <kasan-dev+bncBAABBI665L3QKGQE3XP2LQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2487A20EBE9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 05:19:01 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id l17sf13776731ilj.17
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 20:19:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593487140; cv=pass;
        d=google.com; s=arc-20160816;
        b=JgTHmRwn1/Rm00JsNgCeFGsxZb4wFyoCgjBe22NBHzxqcpG7cJKgO4/ENZVbVpPYhP
         jZ7zv921rtXynCK94IYgKvoNNKnMRjRLOmtdQ5f9f+BFbn3CGBok1+UjcFkI7UpEnB00
         tEGG5CHj5ti9quTTCyKv/O0FyhICw3QjwOYXXvkEgipg+BQai7yNA22pU0C+688LpPbb
         QzPGyq75TVB4ndbOxxMkOXoQP4ImsqHIyTMJ6tPSzhBqVT8xSpzctLBk8K5UuYSQDOde
         3L8qMCNqkPGbT1iXkiK8Gp6mqXz/JAj9dq6p8/aWqHU+Y9R3F+lbcLYQw3FbFL3gGjv+
         qNAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sJVhquc1Zak+tX38TxJVSTRi7RgUpFco/M+T+PjbM0s=;
        b=URS5z4oPKr7TcSQm+ib7gUNrFKpIm3q4OjbPku2B4z+hYWnT8kxKHSvJUmlLwWPlE7
         GjgwXBLevb+O3IJJCgm10cMGoSCSFOubyVPwnUE6Ex6LkgQ20aJVksQB0+E9iztROcml
         8OGZ2btq1ps1iIl2r/qtf7SLh1mXgHx/osFGMHo+IXUAy209PhFtOoLLH8NfuI6AF4Ly
         qFXgw1bVZzqWaQpF7Hx6GC7UySZhZkDoEI/qRfJuA+J17CaWmB8sy09Dtjmuwxl3kkfC
         /4B3rnfCmTCwClLYVvs2MBREFBLHiDEyPWHdz8Qp+hPI8OW9q6sEy3KKeE2GIjct77hA
         cTlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJVhquc1Zak+tX38TxJVSTRi7RgUpFco/M+T+PjbM0s=;
        b=esLu3vso+VlDzFvFfYyz5qNUd/AI/k1yCVIuGyKRnUUjo7bl1CI9EzAfNS1dgTK7Ft
         QyUD3kARM5doWYWXYa3z6TiEa/eWydLy0NvcpKgcu4fhVT9ueRf1hSAgprsfOmvIEYKn
         rQb2T6APsdQiurCdrBzpBFCZT63if1WikrYbPqVxOY4fFVESOQibNUy/VrJO2uCSCrMr
         Ds2LLRiXsfpEz4YKSCs+pzKZBODfJmNGhzPchW+qq7VNSgdbUBfsrUjbKXPG+BuF01ev
         +Wf+DtL80wkKwhvUe/Bx3aP7jHcixRsPCxEXRzeZsXi1CC4xq81UuykSlpcP3xtB0J6G
         w13g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sJVhquc1Zak+tX38TxJVSTRi7RgUpFco/M+T+PjbM0s=;
        b=RKi4YT0PRpo4AsllNpgpc+gFMeYxkOEw2OwbpvNI8uXuZqKRgWBy5HE3LhzI696BJw
         +1ZKV/ZWRG9Vj25hxbziXgCe7DAaiAN9IyBqyKYVTNuTx7MXXuhBqNDrje6lJtaWHEM9
         kaVuL/Qx/DfxwD3Ac53hqrQdFLyH+pnRBUCbR1d6KrbRUa3W+iDnejRHT5qda0c5unPg
         kW43Zmi9kT63yXIi4b09OXAxxRR9Fa+NNZio2rkmvSLbpdjEX1P9TfQiXBPYJMvKm/7K
         mFogLPo8PU0krE6SB9d4BjwY4FS4Qxpm43druK5pnV+ff480n1Yms2WMuFuCCbH46sgd
         9NlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QE6SauqmkZQbfqkAwNgcPeQy++i3zwCKshMHvMQM/QJCYSNsX
	HW1/LBLk4CWOiDS7URigFIs=
X-Google-Smtp-Source: ABdhPJzYsXVomSeJ5pywBohxLen95/5Go6Gkva6ZzrkjKTwgxj0QoOfGyDMwfxooV3CKcYDkICC+dQ==
X-Received: by 2002:a6b:600c:: with SMTP id r12mr19726531iog.174.1593487140038;
        Mon, 29 Jun 2020 20:19:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a89:: with SMTP id c9ls4623608ill.7.gmail; Mon, 29 Jun
 2020 20:18:59 -0700 (PDT)
X-Received: by 2002:a92:c0c8:: with SMTP id t8mr660893ilf.229.1593487139758;
        Mon, 29 Jun 2020 20:18:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593487139; cv=none;
        d=google.com; s=arc-20160816;
        b=vRnTYKlYVNnsqAA/fVxp93T3z57SyOXXFwi0UVnhNMQLB3vAWpqsYlDWhJ0MULQ4ee
         Qt3xIl+RfrntXV1sgz3W8YhvYhzJSIaWkkoJUWwp4FejDf/Q3h471bn/2hLwU/yxn7sA
         xl0rvWwRH5J0liE/OI/ep/7nDFsqrIaKUbJ9Ekbx7I0MKqw1hjtA+a6fX40WDWaK+B1b
         InhzfxXRK//Y4Sw86J+N8xgZ9WUZQN7hZ0dXuOj5sIxY51h8iT5EBUUXf0xhFpUD1rOf
         mRLM8kmdtWUqtJfqA76hY44r6MeBgNE0/WkEumzb7JjysFREDfuPHVul0gSP1qbxGUQB
         DJ0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=wcR+iWl/QFbdhs8ixanWpTlaup1RNa5WFQfx2oXg0cw=;
        b=d+2SGNPm5wfC1d+x6uSUTVTIrFyw31sHRPFJLi4GYy8HhmFCdifb8FypPQD9HSmB32
         CzkFWgk+EGExBm2Hrj17I7sb1NjGUObxJ8+p6+//j/DavxqWgklsh+Npy77O58ErcBlL
         NCqHfI+OAAqlzJ9Hrfw3Hc+mpO7znz9T9VEyTzb5SHuEP6CynfjidM0EJEE59ok7LaSN
         LfrgDD1st7HWAW5gGgF9+JvLsKHjpa0c8cBhJTGTR8Qwpa63bDmdBHuah+qKQDwqVXVB
         QxIBR7qf5JVQvdZimLFwMUodC8UuGqpe+KJq+7lpUoLb/Zg456lLV/a7zukzCEglztdL
         gCGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-131.freemail.mail.aliyun.com (out30-131.freemail.mail.aliyun.com. [115.124.30.131])
        by gmr-mx.google.com with ESMTPS id f15si101781ilr.0.2020.06.29.20.18.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jun 2020 20:18:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@linux.alibaba.com designates 115.124.30.131 as permitted sender) client-ip=115.124.30.131;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R151e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01f04397;MF=richard.weiyang@linux.alibaba.com;NM=1;PH=DS;RN=12;SR=0;TI=SMTPD_---0U175Gc6_1593487136;
Received: from localhost(mailfrom:richard.weiyang@linux.alibaba.com fp:SMTPD_---0U175Gc6_1593487136)
          by smtp.aliyun-inc.com(127.0.0.1);
          Tue, 30 Jun 2020 11:18:56 +0800
From: Wei Yang <richard.weiyang@linux.alibaba.com>
To: dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	akpm@linux-foundation.org
Cc: x86@kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Wei Yang <richard.weiyang@linux.alibaba.com>
Subject: [PATCH] mm: define pte_add_end for consistency
Date: Tue, 30 Jun 2020 11:18:52 +0800
Message-Id: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
X-Mailer: git-send-email 2.20.1 (Apple Git-117)
MIME-Version: 1.0
X-Original-Sender: richard.weiyang@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard.weiyang@linux.alibaba.com designates
 115.124.30.131 as permitted sender) smtp.mailfrom=richard.weiyang@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

When walking page tables, we define several helpers to get the address of
the next boundary. But we don't have one for pte level.

Let's define it and consolidate the code in several places.

Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
---
 arch/x86/mm/init_64.c   | 6 ++----
 include/linux/pgtable.h | 7 +++++++
 mm/kasan/init.c         | 4 +---
 3 files changed, 10 insertions(+), 7 deletions(-)

diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index dbae185511cd..f902fbd17f27 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
 
 	pte = pte_start + pte_index(addr);
 	for (; addr < end; addr = next, pte++) {
-		next = (addr + PAGE_SIZE) & PAGE_MASK;
-		if (next > end)
-			next = end;
+		next = pte_addr_end(addr, end);
 
 		if (!pte_present(*pte))
 			continue;
@@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
 		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
 
 		if (!boot_cpu_has(X86_FEATURE_PSE)) {
-			next = (addr + PAGE_SIZE) & PAGE_MASK;
+			next = pte_addr_end(addr, end);
 			pmd = pmd_offset(pud, addr);
 			if (pmd_none(*pmd))
 				continue;
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 32b6c52d41b9..0de09c6c89d2 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
 })
 #endif
 
+#ifndef pte_addr_end
+#define pte_addr_end(addr, end)						\
+({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
+	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
+})
+#endif
+
 /*
  * When walking page tables, we usually want to skip any p?d_none entries;
  * and any p?d_bad entries - reporting the error before resetting to none.
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..89f748601f74 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
 	unsigned long next;
 
 	for (; addr < end; addr = next, pte++) {
-		next = (addr + PAGE_SIZE) & PAGE_MASK;
-		if (next > end)
-			next = end;
+		next = pte_addr_end(addr, end);
 
 		if (!pte_present(*pte))
 			continue;
-- 
2.20.1 (Apple Git-117)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200630031852.45383-1-richard.weiyang%40linux.alibaba.com.
