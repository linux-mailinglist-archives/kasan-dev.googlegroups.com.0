Return-Path: <kasan-dev+bncBDGZVRMH6UCRB67AUS3QMGQEZVL47QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 490DA97AC1E
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:32:13 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4581efb73d3sf104437131cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:32:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558332; cv=pass;
        d=google.com; s=arc-20240605;
        b=jJwMrPx4tlE2Zk+e9ZfR20p408IE0GDzy8j7KquS76KY0UZlgI6WX+45QDn4Psm87J
         zseHVQeIXpHCCSHi4AOYpjeRy65n8h+vbaY1VTaJBZIE20jdPl0OYscDdQcncI88BD+k
         f3VBC1Lta+eECnl338+RZyjLb+33sKnyBsw1yvhDV/vDeGU2+5c9QB2ZTywBR6hTeSJp
         KG8MUNe9u+OdpbKoKFYLuWi7xcvqQ5kCEG87PsIcY8MEpwMghVrtHzAxIqYGzW1AaBAq
         UlkUpsLvYirC8LCrhTk/bllMVy5UESH9KVFp2asJmRII2ra6WRhBnnA+S81J3GU6vb91
         mYtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Kqh7JWQrhf0cpo04dYCBEBorxX8a+/wzoDvE5yiwiL8=;
        fh=SXV3tKY7Y/7mjbuUqYg2SqFBlcXvjDULzyNa1R+Pa/k=;
        b=ZeA0SG8JGEbrHkVL0UdpDkWS+dFppavpxlOYFOBuzT3Hx4ck2oAy/6PAboWR8emXXn
         0/mJXW252wq63UttWOMIBCmkEmw1iEmQ9wwCkytu06mOeLM1R3HTiAzHYaQ0w9YLojDl
         p+4ozMcCokKUnQn+m+qHVJJzLm92fs7xLyphJv0exFk4gh32Ac6syWPrC+oLVUpLEcm+
         QXOS6iPksUtHKmuRdZmbhZXqllmRv2VxFm0D9iDqwAvpayTVIk76j554NeItxca9iCUf
         8kwo4KpqN12C/moGbd8UcyheK4iJAPCjyUnl2XWc0DxKX7+UOIWdtLC7qFYaabYlrzmk
         tnYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558332; x=1727163132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Kqh7JWQrhf0cpo04dYCBEBorxX8a+/wzoDvE5yiwiL8=;
        b=Od5b4NXPYNreYuC3JJo7pMo3t3gq5H8V9qXKzi7Vh3NwzLUUyya3uVFtSvWeT0LHr4
         ioRs5fuxogqDoCawXXyqLqdE+fhEdEqV88JSfljaZyxAt9gsLk+PTeVMzo2l4HVhNQYn
         zO4c2it6olNsiOIbZBGNB5sQ1O0kHuXafKevlowMIcs6LZJH2o4UmN4M4MeYdWGy6zLS
         p7VdMgZOm+Q7odOaacb/tVKnZXlOB+CGyHv1aUAslhD/n60I0GPuj7Uf40Xr8Z768+Ts
         pXUnBwpnD+udeLuFMEH/pCPLgjbciBicMTdfkAAtf9e0a3vvfwxwp+wAuFJ6ay9ZKpa6
         qQuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558332; x=1727163132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Kqh7JWQrhf0cpo04dYCBEBorxX8a+/wzoDvE5yiwiL8=;
        b=NVH1VbHPfYk2YyQEgl5SnFFma8f7rOheKkZ1XgUiMPrE0Sep5s3Dw1uJyaNV7emiyq
         DKFdltfNVt/zcrw62/Xwsr7Ob/+f7Ag1H0D/UOcq82ptowhMIrzQM0vN1CPrFiWvUGSj
         Db3xqaYpwVf46+euvDX8SPhf9hNayLIIgJ2UvMFcJRwqZBqxiiIAZcIKXiL+DC2VrrFD
         vpIDwLlIIFu8lEHKmHI+dMDEXv0wYBGKEtiooquPw7zs40z16Brj9FhEj99RAx4LRMjI
         BzZTza7fqrcu/U5ixj0sZrGVRmnnnsCC87uTyxSkUAvLyBMx9Jn7ZquiBFmVwoAa1cfL
         EzuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6vR/DP8zwO61Z4z1xRCK0170EhCXWDgaIz1R4nR+0fjluIbQtLc/4uW7471jAyCRdBBJt3A==@lfdr.de
X-Gm-Message-State: AOJu0YzBci98dBb34/LadHgIZXjlhVSvHvnJApVqBCQZB0vqi03vxaFs
	Nlv7vRkPYxVxHsgSnZhcl9QxS1nJVKEybygIdBd0sScPHcDSw+37
X-Google-Smtp-Source: AGHT+IHDAg5VQXk94mhEB8yu5ieGNF0nNCDa6sz8vV0W5spNWGJpAGq3yirPJ9QjcBFh+knS3yba3Q==
X-Received: by 2002:ac8:58c1:0:b0:458:3b5e:4f90 with SMTP id d75a77b69052e-4599d256abamr245967291cf.36.1726558331710;
        Tue, 17 Sep 2024 00:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:156:b0:458:355c:362b with SMTP id
 d75a77b69052e-4585f807451ls53846811cf.0.-pod-prod-06-us; Tue, 17 Sep 2024
 00:32:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW08P9G6wZV+iRuMB3Sg8IRbQe2KlQJiRZCl15A2o6n+zchY+5FUsv/A+Dd90Z/XawOh9zaaHYQFpA=@googlegroups.com
X-Received: by 2002:a05:622a:64f:b0:45b:17f:1bf9 with SMTP id d75a77b69052e-45b017f1f33mr16832801cf.30.1726558330854;
        Tue, 17 Sep 2024 00:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558330; cv=none;
        d=google.com; s=arc-20240605;
        b=gHPfBRvNS8KXw+TWa8F983UfnsDFfQoXv9d/9SF1RMa3iyKol9UQZ7Ai7Mz6wZeFip
         LSjg2J+4lZukQvA1jidtO4iMIWzPff8uHZwWMN0iAb25lNlSk5TCwDV/Nc8rdjISDqJL
         NkASLVDKyQ+ArwzbBdZjKnKfrN2Keto6jQrWc1gnj4gMgaxAEG7YDsabgpk8ixyYeD5O
         omAdCg0T3Cz9SWXQt6Sq4/QYYOS9JTXPnLU41/QQpanjuNVkhmsmOQdrWQNCyQYze4V3
         AB/nVEcAJxU5fQ1o89Za5EezHMPn72Wbi+pXc95Gv9dHmTYI/vea8DQ8MdQKXAsjLW9V
         Ao6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=udx7kdyKMbFwoQ5diH8BDeXeoobdbhcachx8EuYDVt8=;
        fh=L0I0rQF349wute9+dmvK5DBpQz+l6pxvsbf+WAdbOHs=;
        b=De4RoyBH5Ahum2n5p3tMKZh2ha8huzjOxNVxyQXhZrCCiSQFGA1tMIbA/knxj4P+Gl
         BQ1if/RkH0PLBAcUWeN+4TloEHK+rLAGuBjYBtCDf054lxv5SinLWw3rjx97B2+L/fQI
         4KOlolCtCQHu9HHoteSqvqe1r/DfScGB7fjd7BaLk2Quz2dwob4JGNs11n3R1Y7bO/mR
         IuzeqtkulsyfYvc+ebJXfxDQrgeSG3fRfWzV9FXExz2Ti1z7SpWOGVWJ4DzsKOo8Zycm
         QZ14N2GkFSjH6Rtr0RxO0zxg/QBPiIIdPc1lARedUoetNCTQxw441yXA5lbPiH1Cjarq
         nlUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-459aad273fesi2500371cf.3.2024.09.17.00.32.10
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:32:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DCE391063;
	Tue, 17 Sep 2024 00:32:39 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id C5E223F64C;
	Tue, 17 Sep 2024 00:32:02 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Dimitri Sivanich <dimitri.sivanich@hpe.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>
Subject: [PATCH V2 6/7] mm: Use p4dp_get() for accessing P4D entries
Date: Tue, 17 Sep 2024 13:01:16 +0530
Message-Id: <20240917073117.1531207-7-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240917073117.1531207-1-anshuman.khandual@arm.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Convert P4D accesses via p4dp_get() helper that defaults as READ_ONCE() but
also provides the platform an opportunity to override when required. This
stores read page table entry value in a local variable which can be used in
multiple instances there after. This helps in avoiding multiple memory load
operations as well possible race conditions.

Cc: Dimitri Sivanich <dimitri.sivanich@hpe.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>
Cc: Muchun Song <muchun.song@linux.dev>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>
Cc: Dennis Zhou <dennis@kernel.org>
Cc: Tejun Heo <tj@kernel.org>
cc: Christoph Lameter <cl@linux.com>
Cc: Uladzislau Rezki <urezki@gmail.com>
Cc: Christoph Hellwig <hch@infradead.org>
Cc: linux-kernel@vger.kernel.org
Cc: linux-fsdevel@vger.kernel.org
Cc: linux-perf-users@vger.kernel.org
Cc: linux-mm@kvack.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 drivers/misc/sgi-gru/grufault.c |  2 +-
 fs/userfaultfd.c                |  2 +-
 include/linux/pgtable.h         |  9 ++++++---
 kernel/events/core.c            |  2 +-
 mm/gup.c                        |  6 +++---
 mm/hugetlb.c                    |  2 +-
 mm/kasan/init.c                 | 10 +++++-----
 mm/kasan/shadow.c               |  2 +-
 mm/memory-failure.c             |  2 +-
 mm/memory.c                     | 16 +++++++++-------
 mm/page_vma_mapped.c            |  2 +-
 mm/percpu.c                     |  2 +-
 mm/pgalloc-track.h              |  2 +-
 mm/pgtable-generic.c            |  2 +-
 mm/ptdump.c                     |  2 +-
 mm/rmap.c                       |  2 +-
 mm/sparse-vmemmap.c             |  2 +-
 mm/vmalloc.c                    | 15 ++++++++-------
 mm/vmscan.c                     |  2 +-
 19 files changed, 45 insertions(+), 39 deletions(-)

diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufault.c
index 95d479d5e40f..fcaceac60659 100644
--- a/drivers/misc/sgi-gru/grufault.c
+++ b/drivers/misc/sgi-gru/grufault.c
@@ -216,7 +216,7 @@ static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr,
 		goto err;
 
 	p4dp = p4d_offset(pgdp, vaddr);
-	if (unlikely(p4d_none(*p4dp)))
+	if (unlikely(p4d_none(p4dp_get(p4dp))))
 		goto err;
 
 	pudp = pud_offset(p4dp, vaddr);
diff --git a/fs/userfaultfd.c b/fs/userfaultfd.c
index 00719a0f688c..4044e15cdfd9 100644
--- a/fs/userfaultfd.c
+++ b/fs/userfaultfd.c
@@ -307,7 +307,7 @@ static inline bool userfaultfd_must_wait(struct userfaultfd_ctx *ctx,
 	if (!pgd_present(*pgd))
 		goto out;
 	p4d = p4d_offset(pgd, address);
-	if (!p4d_present(*p4d))
+	if (!p4d_present(p4dp_get(p4d)))
 		goto out;
 	pud = pud_offset(p4d, address);
 	if (!pud_present(pudp_get(pud)))
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index eb993ef0946f..689cd5a32157 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1081,7 +1081,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
 
 #define set_p4d_safe(p4dp, p4d) \
 ({ \
-	WARN_ON_ONCE(p4d_present(*p4dp) && !p4d_same(*p4dp, p4d)); \
+	p4d_t __old = p4dp_get(p4dp); \
+	WARN_ON_ONCE(p4d_present(__old) && !p4d_same(__old, p4d)); \
 	set_p4d(p4dp, p4d); \
 })
 
@@ -1251,9 +1252,11 @@ static inline int pgd_none_or_clear_bad(pgd_t *pgd)
 
 static inline int p4d_none_or_clear_bad(p4d_t *p4d)
 {
-	if (p4d_none(*p4d))
+	p4d_t old_p4d = p4dp_get(p4d);
+
+	if (p4d_none(old_p4d))
 		return 1;
-	if (unlikely(p4d_bad(*p4d))) {
+	if (unlikely(p4d_bad(old_p4d))) {
 		p4d_clear_bad(p4d);
 		return 1;
 	}
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 35e2f2789246..4e56a276ed25 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -7611,7 +7611,7 @@ static u64 perf_get_pgtable_size(struct mm_struct *mm, unsigned long addr)
 		return pgd_leaf_size(pgd);
 
 	p4dp = p4d_offset_lockless(pgdp, pgd, addr);
-	p4d = READ_ONCE(*p4dp);
+	p4d = p4dp_get(p4dp);
 	if (!p4d_present(p4d))
 		return 0;
 
diff --git a/mm/gup.c b/mm/gup.c
index 300fc7eb306c..3a97d0263052 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -1014,7 +1014,7 @@ static struct page *follow_p4d_mask(struct vm_area_struct *vma,
 	p4d_t *p4dp, p4d;
 
 	p4dp = p4d_offset(pgdp, address);
-	p4d = READ_ONCE(*p4dp);
+	p4d = p4dp_get(p4dp);
 	BUILD_BUG_ON(p4d_leaf(p4d));
 
 	if (!p4d_present(p4d) || p4d_bad(p4d))
@@ -1114,7 +1114,7 @@ static int get_gate_page(struct mm_struct *mm, unsigned long address,
 	if (pgd_none(*pgd))
 		return -EFAULT;
 	p4d = p4d_offset(pgd, address);
-	if (p4d_none(*p4d))
+	if (p4d_none(p4dp_get(p4d)))
 		return -EFAULT;
 	pud = pud_offset(p4d, address);
 	if (pud_none(pudp_get(pud)))
@@ -3245,7 +3245,7 @@ static int gup_fast_p4d_range(pgd_t *pgdp, pgd_t pgd, unsigned long addr,
 
 	p4dp = p4d_offset_lockless(pgdp, pgd, addr);
 	do {
-		p4d_t p4d = READ_ONCE(*p4dp);
+		p4d_t p4d = p4dp_get(p4dp);
 
 		next = p4d_addr_end(addr, end);
 		if (!p4d_present(p4d))
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index a3820242b01e..4fdb91c8cc2b 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -7454,7 +7454,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 	if (!pgd_present(*pgd))
 		return NULL;
 	p4d = p4d_offset(pgd, addr);
-	if (!p4d_present(*p4d))
+	if (!p4d_present(p4dp_get(p4d)))
 		return NULL;
 
 	pud = pud_offset(p4d, addr);
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index f4cf519443e1..02af738fee5e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -208,7 +208,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			continue;
 		}
 
-		if (p4d_none(*p4d)) {
+		if (p4d_none(p4dp_get(p4d))) {
 			pud_t *p;
 
 			if (slab_is_available()) {
@@ -330,7 +330,7 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
 			return;
 	}
 
-	pud_free(&init_mm, (pud_t *)page_to_virt(p4d_page(*p4d)));
+	pud_free(&init_mm, (pud_t *)page_to_virt(p4d_page(p4dp_get(p4d))));
 	p4d_clear(p4d);
 }
 
@@ -341,7 +341,7 @@ static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
 
 	for (i = 0; i < PTRS_PER_P4D; i++) {
 		p4d = p4d_start + i;
-		if (!p4d_none(*p4d))
+		if (!p4d_none(p4dp_get(p4d)))
 			return;
 	}
 
@@ -434,10 +434,10 @@ static void kasan_remove_p4d_table(p4d_t *p4d, unsigned long addr,
 
 		next = p4d_addr_end(addr, end);
 
-		if (!p4d_present(*p4d))
+		if (!p4d_present(p4dp_get(p4d)))
 			continue;
 
-		if (kasan_pud_table(*p4d)) {
+		if (kasan_pud_table(p4dp_get(p4d))) {
 			if (IS_ALIGNED(addr, P4D_SIZE) &&
 			    IS_ALIGNED(next, P4D_SIZE)) {
 				p4d_clear(p4d);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index dbd8164c75f1..52150cc5ae5f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -194,7 +194,7 @@ static bool shadow_mapped(unsigned long addr)
 	if (pgd_none(*pgd))
 		return false;
 	p4d = p4d_offset(pgd, addr);
-	if (p4d_none(*p4d))
+	if (p4d_none(p4dp_get(p4d)))
 		return false;
 	pud = pud_offset(p4d, addr);
 	if (pud_none(pudp_get(pud)))
diff --git a/mm/memory-failure.c b/mm/memory-failure.c
index fbb63401fb51..3d900cc039b3 100644
--- a/mm/memory-failure.c
+++ b/mm/memory-failure.c
@@ -414,7 +414,7 @@ static unsigned long dev_pagemap_mapping_shift(struct vm_area_struct *vma,
 	if (!pgd_present(*pgd))
 		return 0;
 	p4d = p4d_offset(pgd, address);
-	if (!p4d_present(*p4d))
+	if (!p4d_present(p4dp_get(p4d)))
 		return 0;
 	pud = pud_offset(p4d, address);
 	if (!pud_present(pudp_get(pud)))
diff --git a/mm/memory.c b/mm/memory.c
index 801750e4337c..5056f39f2c3b 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2906,7 +2906,7 @@ static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
 				     pte_fn_t fn, void *data, bool create,
 				     pgtbl_mod_mask *mask)
 {
-	p4d_t *p4d;
+	p4d_t *p4d, old_p4d;
 	unsigned long next;
 	int err = 0;
 
@@ -2919,11 +2919,12 @@ static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
 	}
 	do {
 		next = p4d_addr_end(addr, end);
-		if (p4d_none(*p4d) && !create)
+		old_p4d = p4dp_get(p4d);
+		if (p4d_none(old_p4d) && !create)
 			continue;
-		if (WARN_ON_ONCE(p4d_leaf(*p4d)))
+		if (WARN_ON_ONCE(p4d_leaf(old_p4d)))
 			return -EINVAL;
-		if (!p4d_none(*p4d) && WARN_ON_ONCE(p4d_bad(*p4d))) {
+		if (!p4d_none(old_p4d) && WARN_ON_ONCE(p4d_bad(old_p4d))) {
 			if (!create)
 				continue;
 			p4d_clear_bad(p4d);
@@ -6075,7 +6076,7 @@ int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
 		return -ENOMEM;
 
 	spin_lock(&mm->page_table_lock);
-	if (!p4d_present(*p4d)) {
+	if (!p4d_present(p4dp_get(p4d))) {
 		mm_inc_nr_puds(mm);
 		smp_wmb(); /* See comment in pmd_install() */
 		p4d_populate(mm, p4d, new);
@@ -6143,7 +6144,7 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
 {
 	struct mm_struct *mm = vma->vm_mm;
 	pgd_t *pgd;
-	p4d_t *p4d;
+	p4d_t *p4d, old_p4d;
 	pud_t *pud;
 	pmd_t *pmd;
 	pte_t *ptep;
@@ -6160,7 +6161,8 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
 		goto out;
 
 	p4d = p4d_offset(pgd, address);
-	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
+	old_p4d = p4dp_get(p4d);
+	if (p4d_none(old_p4d) || unlikely(p4d_bad(old_p4d)))
 		goto out;
 
 	pud = pud_offset(p4d, address);
diff --git a/mm/page_vma_mapped.c b/mm/page_vma_mapped.c
index 511266307771..a33f92db2666 100644
--- a/mm/page_vma_mapped.c
+++ b/mm/page_vma_mapped.c
@@ -217,7 +217,7 @@ bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw)
 			continue;
 		}
 		p4d = p4d_offset(pgd, pvmw->address);
-		if (!p4d_present(*p4d)) {
+		if (!p4d_present(p4dp_get(p4d))) {
 			step_forward(pvmw, P4D_SIZE);
 			continue;
 		}
diff --git a/mm/percpu.c b/mm/percpu.c
index 5f32164b04a2..58660e8eb892 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3192,7 +3192,7 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
 	}
 
 	p4d = p4d_offset(pgd, addr);
-	if (p4d_none(*p4d)) {
+	if (p4d_none(p4dp_get(p4d))) {
 		pud = memblock_alloc(PUD_TABLE_SIZE, PUD_TABLE_SIZE);
 		if (!pud)
 			goto err_alloc;
diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
index 0f6b809431a3..3db8ccbcb141 100644
--- a/mm/pgalloc-track.h
+++ b/mm/pgalloc-track.h
@@ -20,7 +20,7 @@ static inline pud_t *pud_alloc_track(struct mm_struct *mm, p4d_t *p4d,
 				     unsigned long address,
 				     pgtbl_mod_mask *mod_mask)
 {
-	if (unlikely(p4d_none(*p4d))) {
+	if (unlikely(p4d_none(p4dp_get(p4d)))) {
 		if (__pud_alloc(mm, p4d, address))
 			return NULL;
 		*mod_mask |= PGTBL_P4D_MODIFIED;
diff --git a/mm/pgtable-generic.c b/mm/pgtable-generic.c
index e09e3f920f7a..f5ab52beb536 100644
--- a/mm/pgtable-generic.c
+++ b/mm/pgtable-generic.c
@@ -31,7 +31,7 @@ void pgd_clear_bad(pgd_t *pgd)
 #ifndef __PAGETABLE_P4D_FOLDED
 void p4d_clear_bad(p4d_t *p4d)
 {
-	p4d_ERROR(*p4d);
+	p4d_ERROR(p4dp_get(p4d));
 	p4d_clear(p4d);
 }
 #endif
diff --git a/mm/ptdump.c b/mm/ptdump.c
index 32ae8e829329..2c40224b8ad0 100644
--- a/mm/ptdump.c
+++ b/mm/ptdump.c
@@ -53,7 +53,7 @@ static int ptdump_p4d_entry(p4d_t *p4d, unsigned long addr,
 			    unsigned long next, struct mm_walk *walk)
 {
 	struct ptdump_state *st = walk->private;
-	p4d_t val = READ_ONCE(*p4d);
+	p4d_t val = p4dp_get(p4d);
 
 #if CONFIG_PGTABLE_LEVELS > 3 && \
 		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
diff --git a/mm/rmap.c b/mm/rmap.c
index 81f1946653e0..a0ff325467eb 100644
--- a/mm/rmap.c
+++ b/mm/rmap.c
@@ -813,7 +813,7 @@ pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
 		goto out;
 
 	p4d = p4d_offset(pgd, address);
-	if (!p4d_present(*p4d))
+	if (!p4d_present(p4dp_get(p4d)))
 		goto out;
 
 	pud = pud_offset(p4d, address);
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index d8ea64ec665f..2bd1c95f107a 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -220,7 +220,7 @@ void __weak __meminit pud_init(void *addr)
 p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 {
 	p4d_t *p4d = p4d_offset(pgd, addr);
-	if (p4d_none(*p4d)) {
+	if (p4d_none(p4dp_get(p4d))) {
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 05292d998122..f27ecac7bd6e 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -251,7 +251,7 @@ static int vmap_try_huge_p4d(p4d_t *p4d, unsigned long addr, unsigned long end,
 	if (!IS_ALIGNED(phys_addr, P4D_SIZE))
 		return 0;
 
-	if (p4d_present(*p4d) && !p4d_free_pud_page(p4d, addr))
+	if (p4d_present(p4dp_get(p4d)) && !p4d_free_pud_page(p4d, addr))
 		return 0;
 
 	return p4d_set_huge(p4d, phys_addr, prot);
@@ -418,7 +418,7 @@ static void vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
 		next = p4d_addr_end(addr, end);
 
 		p4d_clear_huge(p4d);
-		if (p4d_bad(*p4d))
+		if (p4d_bad(p4dp_get(p4d)))
 			*mask |= PGTBL_P4D_MODIFIED;
 
 		if (p4d_none_or_clear_bad(p4d))
@@ -741,7 +741,7 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 	unsigned long addr = (unsigned long) vmalloc_addr;
 	struct page *page = NULL;
 	pgd_t *pgd = pgd_offset_k(addr);
-	p4d_t *p4d;
+	p4d_t *p4d, old_p4d;
 	pud_t *pud, old_pud;
 	pmd_t *pmd, old_pmd;
 	pte_t *ptep, pte;
@@ -760,11 +760,12 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 		return NULL;
 
 	p4d = p4d_offset(pgd, addr);
-	if (p4d_none(*p4d))
+	old_p4d = p4dp_get(p4d);
+	if (p4d_none(old_p4d))
 		return NULL;
-	if (p4d_leaf(*p4d))
-		return p4d_page(*p4d) + ((addr & ~P4D_MASK) >> PAGE_SHIFT);
-	if (WARN_ON_ONCE(p4d_bad(*p4d)))
+	if (p4d_leaf(old_p4d))
+		return p4d_page(old_p4d) + ((addr & ~P4D_MASK) >> PAGE_SHIFT);
+	if (WARN_ON_ONCE(p4d_bad(old_p4d)))
 		return NULL;
 
 	pud = pud_offset(p4d, addr);
diff --git a/mm/vmscan.c b/mm/vmscan.c
index 04b03e6c3095..b16925b5f072 100644
--- a/mm/vmscan.c
+++ b/mm/vmscan.c
@@ -3579,7 +3579,7 @@ static int walk_pud_range(p4d_t *p4d, unsigned long start, unsigned long end,
 	unsigned long next;
 	struct lru_gen_mm_walk *walk = args->private;
 
-	VM_WARN_ON_ONCE(p4d_leaf(*p4d));
+	VM_WARN_ON_ONCE(p4d_leaf(p4dp_get(p4d)));
 
 	pud = pud_offset(p4d, start & P4D_MASK);
 restart:
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-7-anshuman.khandual%40arm.com.
