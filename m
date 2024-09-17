Return-Path: <kasan-dev+bncBDGZVRMH6UCRBA7BUS3QMGQEIW7RWJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FAF097AC21
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:32:21 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3a09d8ee141sf22143335ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:32:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558340; cv=pass;
        d=google.com; s=arc-20240605;
        b=MXiUpb2S/kBl6T7tAjHeCuhUWc9eTR2WedkEtHlqZPy3aEbKvjiG/w5+DMiNLP3VU/
         kKUZOCG4zudUV1otg1rvYRkxU6ho6qSbtKYmSPmGzTihLrzg/orwhUAsKyBItxDkqLU4
         986esUTnupg4xFHSNSZTfDo/Us6YqMc7rmz9JhsSi2peTmYRjZqgdZditsm6izwn3GO3
         uq/CLG0U0Wz07Nx26yjK5u9zXYBzx9s3YjmTfQ0ylBRaaU+IyXkiDwkB1Rmm7TuqNrYV
         165Ow3/OnPvNghGkhx3btKoG8oFkn6eITWOYBeP3rCd41l3xfLb8YOiMNlUsZer/ISCh
         K2aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xef38LQI7qaU9fx1W7TGH1SLG1jptnCjBWodAfJupS0=;
        fh=pvkbGaw/Fi822CvCy56wPWEpmA7eV22RMmWol3qG1XE=;
        b=X2poBORIBHBK7Cam9zhIec8wAF0ntlYw97WhWbUyKDU+vutPnDzKG4qZ/OkTQekdtJ
         aKXeGMQWbIIZzNq/9UzTbUOHKGiseA4p6gR3L/iv1AYDJBsrgduO6CnRrz1xTiQ0I4uL
         fD85IVI+Z52/31mMQHNTs6EI3XKOhN34Sa4NgjkGTwPI7btNgSSR9V8h8f7ZLJnlGVOd
         1kOlG4mPMiBha7F3/C0UfJVGZx5SwejAwPg7zeK15aYk/plH6g5vigX2wWBKpHvlu7KQ
         NdOAbBvM7KbvtwC+KKRzdTT8pau6g/RvW7pd3DXlkLCi+nl+o8h8NDnftSKgVG4myi/a
         xw4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558340; x=1727163140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xef38LQI7qaU9fx1W7TGH1SLG1jptnCjBWodAfJupS0=;
        b=mXb6dxG+BVRwo9ItUEiz09t5NY5KZoMto1dEj+7eFT7+4i9S1BlIripObTyXgsaXKE
         b4zagYf9mWF1n248YMgDFPL6lGhe6e427lrpir1BebNu3I1tuRYh9Nrfp+m0TkQe4pm4
         UuyYBJy7RvDNmm+XuoZ5sOKON9Um3SsRZvEBwzU/qt0uoY5OimK3Ke7Cqo3ayDZhfwn/
         ZIAenoT7V1507xXaap3oTIJbrJrnri6gSwP8alV2EbgAArzEgWLpAwEPsRrquL+X2840
         lxcHxoOP0I6OU3lxOPUCJgiQkoRoqtakllFrTna/y1mX8dP4dSItrEglPF3R/+LmFe7I
         NhmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558340; x=1727163140;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xef38LQI7qaU9fx1W7TGH1SLG1jptnCjBWodAfJupS0=;
        b=bssh0IHkLGmD/U/ThBJtHCs87b66g681X2v7qlyW8WcowqRUwe3ccXJRbOOmzkASbH
         ZRHQhoWdc/53Uf5uIEQDWXv7QbeN7WClH5C/F2Mdp1n6JWDryBERHm527IP0qn7zXJZW
         qb55iygVnmm4MLJLgzPsjokqPZLzYQSTp+R0FlRvG+APxXTxLfy+cKy+moCYGfJyCyG6
         oZNo6cldBlkxg3dNn5jEOCJeTF/WbU0LKWanCNLtOKSj70H+pLWK3f/uUWQzHHyBgzf8
         vxHzVZ68jq03QmQWO2iF9+z16fj9KG9yQEu564f1G1tIHMWdz882kK9bpnDKNV7OVk7S
         /1eg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVmoWwsqlrmtYEc9tVErI+FLtmHegU4RPeciH/6qVq23wG0UWU/PETo0XPfnik5WqJwxZqdQ==@lfdr.de
X-Gm-Message-State: AOJu0YzXI/dNZ8H9C0KQ955JAgtZa0hWA96cCxNwEN9lOEspqB6rKVhD
	tjY7R92w9H2qmlt6Dd42N33JnTsja19+woMhhqFiqfXhg3r+gAjo
X-Google-Smtp-Source: AGHT+IHvkvqnSvjLrloAZ4Xhlr1hM6ct8yAYdHp7RA2dJOT4NbC+drpMWpy9MoAwdijMj3p30eWhUw==
X-Received: by 2002:a05:6e02:1543:b0:3a0:4a91:224f with SMTP id e9e14a558f8ab-3a08b6f87edmr126985745ab.1.1726558339892;
        Tue, 17 Sep 2024 00:32:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f84:b0:3a0:8fb0:7a10 with SMTP id
 e9e14a558f8ab-3a08fb07b2als13342535ab.1.-pod-prod-06-us; Tue, 17 Sep 2024
 00:32:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuq2RLdS4yV7eXKBB4HE7ScOOs7mlD4W1YBMsoIw5fEKPL8oYSwyOahwRVjW2nxOQNjuYgSIDs9ag=@googlegroups.com
X-Received: by 2002:a05:6602:1645:b0:82b:40f:63c6 with SMTP id ca18e2360f4ac-82d376b4869mr1095408939f.4.1726558339048;
        Tue, 17 Sep 2024 00:32:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558339; cv=none;
        d=google.com; s=arc-20240605;
        b=FHZKFmJk6c5McDfXdsCbfFkz1XzVQ1Cny0C0tGYMzTbP7P/TlIt3uHpl3ZVI6b12xv
         4k/IWygMmuOBYRqC40EbzO4VQKdCIpp76nQ5EzBVSvnA5ic68kT2QTGivUd6mEYggSLz
         7nS4Ir2jxxBElo7+hiHeT1Tq6KlbeBag51c+/+8hSpF5rpc9cOoHwQpdlD3esV1miHqv
         9ggP8BIL8hBcmf+wKo3WdGWKFoI59RrdbxO6OBxX1Qhlv53Jp+hN+oDHpfZ2Dl7JidYg
         GdSoHLKvzlEEGqdTtkaoBO4qkkuJYBq2tNjYJ1H/FEuoBsCWXsESkFWu8BUvQlqP8bAZ
         aLjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=42BX7NZPRjMZYqs+dFskLn0l9B42cpflvCwiEFssJh4=;
        fh=L0I0rQF349wute9+dmvK5DBpQz+l6pxvsbf+WAdbOHs=;
        b=UEIijrUiaknrMu39iKVBpculX9Y5EFB6PgWXbD7RGsV8uQczzsPToJAcger0g1ug8V
         5IJnPXOGGXKa/UinAkifBkl4l226gemU0E++n/lclYIsbPiM+XN+/3EnsApmeJP0zpP4
         OPPZ8yIqAs0xpiFEONPpWJWomiYsmUbnUi/tem1hgq9Rb+Uh3rHr0gAzemsqOiz3gcEO
         bvpEmEP2mj/eF6vl8zyB0/8ilZ5jbIT+cKU80EqlnqpJt8dfIiIfJe4tcjq84aCAeTwt
         h+kopP38H+9GMDrvRCIXkGPw7er1wepexTi/Mt9LIBHqWbUl7XUS6ZHIWVbn/pEd/TNQ
         6E1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-4d37ecaa652si251810173.6.2024.09.17.00.32.18
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:32:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D9BCB1063;
	Tue, 17 Sep 2024 00:32:47 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 19E0A3F64C;
	Tue, 17 Sep 2024 00:32:10 -0700 (PDT)
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
Subject: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Date: Tue, 17 Sep 2024 13:01:17 +0530
Message-Id: <20240917073117.1531207-8-anshuman.khandual@arm.com>
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

Convert PGD accesses via pgdp_get() helper that defaults as READ_ONCE() but
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
Cc: linux-mm@kvack.org
Cc: linux-perf-users@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 drivers/misc/sgi-gru/grufault.c |  2 +-
 fs/userfaultfd.c                |  2 +-
 include/linux/mm.h              |  2 +-
 include/linux/pgtable.h         |  9 ++++++---
 kernel/events/core.c            |  2 +-
 mm/gup.c                        | 11 ++++++-----
 mm/hugetlb.c                    |  2 +-
 mm/kasan/init.c                 |  8 ++++----
 mm/kasan/shadow.c               |  2 +-
 mm/memory-failure.c             |  2 +-
 mm/memory.c                     | 16 +++++++++-------
 mm/page_vma_mapped.c            |  2 +-
 mm/percpu.c                     |  2 +-
 mm/pgalloc-track.h              |  2 +-
 mm/pgtable-generic.c            |  2 +-
 mm/rmap.c                       |  2 +-
 mm/sparse-vmemmap.c             |  2 +-
 mm/vmalloc.c                    | 13 +++++++------
 18 files changed, 45 insertions(+), 38 deletions(-)

diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufault.c
index fcaceac60659..6aeccbd440e7 100644
--- a/drivers/misc/sgi-gru/grufault.c
+++ b/drivers/misc/sgi-gru/grufault.c
@@ -212,7 +212,7 @@ static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr,
 	pte_t pte;
 
 	pgdp = pgd_offset(vma->vm_mm, vaddr);
-	if (unlikely(pgd_none(*pgdp)))
+	if (unlikely(pgd_none(pgdp_get(pgdp))))
 		goto err;
 
 	p4dp = p4d_offset(pgdp, vaddr);
diff --git a/fs/userfaultfd.c b/fs/userfaultfd.c
index 4044e15cdfd9..6d33c7a9eb01 100644
--- a/fs/userfaultfd.c
+++ b/fs/userfaultfd.c
@@ -304,7 +304,7 @@ static inline bool userfaultfd_must_wait(struct userfaultfd_ctx *ctx,
 	assert_fault_locked(vmf);
 
 	pgd = pgd_offset(mm, address);
-	if (!pgd_present(*pgd))
+	if (!pgd_present(pgdp_get(pgd)))
 		goto out;
 	p4d = p4d_offset(pgd, address);
 	if (!p4d_present(p4dp_get(p4d)))
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 1bb1599b5779..1978a4b1fcf5 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2819,7 +2819,7 @@ int __pte_alloc_kernel(pmd_t *pmd);
 static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
 		unsigned long address)
 {
-	return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
+	return (unlikely(pgd_none(pgdp_get(pgd))) && __p4d_alloc(mm, pgd, address)) ?
 		NULL : p4d_offset(pgd, address);
 }
 
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 689cd5a32157..6d12ae7e3982 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1088,7 +1088,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
 
 #define set_pgd_safe(pgdp, pgd) \
 ({ \
-	WARN_ON_ONCE(pgd_present(*pgdp) && !pgd_same(*pgdp, pgd)); \
+	pgd_t __old = pgdp_get(pgdp); \
+	WARN_ON_ONCE(pgd_present(__old) && !pgd_same(__old, pgd)); \
 	set_pgd(pgdp, pgd); \
 })
 
@@ -1241,9 +1242,11 @@ void pmd_clear_bad(pmd_t *);
 
 static inline int pgd_none_or_clear_bad(pgd_t *pgd)
 {
-	if (pgd_none(*pgd))
+	pgd_t old_pgd = pgdp_get(pgd);
+
+	if (pgd_none(old_pgd))
 		return 1;
-	if (unlikely(pgd_bad(*pgd))) {
+	if (unlikely(pgd_bad(old_pgd))) {
 		pgd_clear_bad(pgd);
 		return 1;
 	}
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 4e56a276ed25..1e3142211cce 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -7603,7 +7603,7 @@ static u64 perf_get_pgtable_size(struct mm_struct *mm, unsigned long addr)
 	pte_t *ptep, pte;
 
 	pgdp = pgd_offset(mm, addr);
-	pgd = READ_ONCE(*pgdp);
+	pgd = pgdp_get(pgdp);
 	if (pgd_none(pgd))
 		return 0;
 
diff --git a/mm/gup.c b/mm/gup.c
index 3a97d0263052..3aff3555ba19 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -1051,7 +1051,7 @@ static struct page *follow_page_mask(struct vm_area_struct *vma,
 			      unsigned long address, unsigned int flags,
 			      struct follow_page_context *ctx)
 {
-	pgd_t *pgd;
+	pgd_t *pgd, old_pgd;
 	struct mm_struct *mm = vma->vm_mm;
 	struct page *page;
 
@@ -1060,7 +1060,8 @@ static struct page *follow_page_mask(struct vm_area_struct *vma,
 	ctx->page_mask = 0;
 	pgd = pgd_offset(mm, address);
 
-	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
+	old_pgd = pgdp_get(pgd);
+	if (pgd_none(old_pgd) || unlikely(pgd_bad(old_pgd)))
 		page = no_page_table(vma, flags, address);
 	else
 		page = follow_p4d_mask(vma, address, pgd, flags, ctx);
@@ -1111,7 +1112,7 @@ static int get_gate_page(struct mm_struct *mm, unsigned long address,
 		pgd = pgd_offset_k(address);
 	else
 		pgd = pgd_offset_gate(mm, address);
-	if (pgd_none(*pgd))
+	if (pgd_none(pgdp_get(pgd)))
 		return -EFAULT;
 	p4d = p4d_offset(pgd, address);
 	if (p4d_none(p4dp_get(p4d)))
@@ -3158,7 +3159,7 @@ static int gup_fast_pgd_leaf(pgd_t orig, pgd_t *pgdp, unsigned long addr,
 	if (!folio)
 		return 0;
 
-	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
+	if (unlikely(pgd_val(orig) != pgd_val(pgdp_get(pgdp)))) {
 		gup_put_folio(folio, refs, flags);
 		return 0;
 	}
@@ -3267,7 +3268,7 @@ static void gup_fast_pgd_range(unsigned long addr, unsigned long end,
 
 	pgdp = pgd_offset(current->mm, addr);
 	do {
-		pgd_t pgd = READ_ONCE(*pgdp);
+		pgd_t pgd = pgdp_get(pgdp);
 
 		next = pgd_addr_end(addr, end);
 		if (pgd_none(pgd))
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 4fdb91c8cc2b..294d74b03d83 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -7451,7 +7451,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 	pmd_t *pmd;
 
 	pgd = pgd_offset(mm, addr);
-	if (!pgd_present(*pgd))
+	if (!pgd_present(pgdp_get(pgd)))
 		return NULL;
 	p4d = p4d_offset(pgd, addr);
 	if (!p4d_present(p4dp_get(p4d)))
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 02af738fee5e..c2b307716551 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -271,7 +271,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 			continue;
 		}
 
-		if (pgd_none(*pgd)) {
+		if (pgd_none(pgdp_get(pgd))) {
 			p4d_t *p;
 
 			if (slab_is_available()) {
@@ -345,7 +345,7 @@ static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
 			return;
 	}
 
-	p4d_free(&init_mm, (p4d_t *)page_to_virt(pgd_page(*pgd)));
+	p4d_free(&init_mm, (p4d_t *)page_to_virt(pgd_page(pgdp_get(pgd))));
 	pgd_clear(pgd);
 }
 
@@ -468,10 +468,10 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 		next = pgd_addr_end(addr, end);
 
 		pgd = pgd_offset_k(addr);
-		if (!pgd_present(*pgd))
+		if (!pgd_present(pgdp_get(pgd)))
 			continue;
 
-		if (kasan_p4d_table(*pgd)) {
+		if (kasan_p4d_table(pgdp_get(pgd))) {
 			if (IS_ALIGNED(addr, PGDIR_SIZE) &&
 			    IS_ALIGNED(next, PGDIR_SIZE)) {
 				pgd_clear(pgd);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 52150cc5ae5f..7f3c46237816 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -191,7 +191,7 @@ static bool shadow_mapped(unsigned long addr)
 	pmd_t *pmd;
 	pte_t *pte;
 
-	if (pgd_none(*pgd))
+	if (pgd_none(pgdp_get(pgd)))
 		return false;
 	p4d = p4d_offset(pgd, addr);
 	if (p4d_none(p4dp_get(p4d)))
diff --git a/mm/memory-failure.c b/mm/memory-failure.c
index 3d900cc039b3..c9397eab52bd 100644
--- a/mm/memory-failure.c
+++ b/mm/memory-failure.c
@@ -411,7 +411,7 @@ static unsigned long dev_pagemap_mapping_shift(struct vm_area_struct *vma,
 
 	VM_BUG_ON_VMA(address == -EFAULT, vma);
 	pgd = pgd_offset(vma->vm_mm, address);
-	if (!pgd_present(*pgd))
+	if (!pgd_present(pgdp_get(pgd)))
 		return 0;
 	p4d = p4d_offset(pgd, address);
 	if (!p4d_present(p4dp_get(p4d)))
diff --git a/mm/memory.c b/mm/memory.c
index 5056f39f2c3b..b4845a84ceb5 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2942,7 +2942,7 @@ static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
 				 unsigned long size, pte_fn_t fn,
 				 void *data, bool create)
 {
-	pgd_t *pgd;
+	pgd_t *pgd, old_pgd;
 	unsigned long start = addr, next;
 	unsigned long end = addr + size;
 	pgtbl_mod_mask mask = 0;
@@ -2954,11 +2954,12 @@ static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
 	pgd = pgd_offset(mm, addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		if (pgd_none(*pgd) && !create)
+		old_pgd = pgdp_get(pgd);
+		if (pgd_none(old_pgd) && !create)
 			continue;
-		if (WARN_ON_ONCE(pgd_leaf(*pgd)))
+		if (WARN_ON_ONCE(pgd_leaf(old_pgd)))
 			return -EINVAL;
-		if (!pgd_none(*pgd) && WARN_ON_ONCE(pgd_bad(*pgd))) {
+		if (!pgd_none(old_pgd) && WARN_ON_ONCE(pgd_bad(old_pgd))) {
 			if (!create)
 				continue;
 			pgd_clear_bad(pgd);
@@ -6053,7 +6054,7 @@ int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
 		return -ENOMEM;
 
 	spin_lock(&mm->page_table_lock);
-	if (pgd_present(*pgd)) {	/* Another has populated it */
+	if (pgd_present(pgdp_get(pgd))) {	/* Another has populated it */
 		p4d_free(mm, new);
 	} else {
 		smp_wmb(); /* See comment in pmd_install() */
@@ -6143,7 +6144,7 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
 	       pte_t **ptepp, spinlock_t **ptlp)
 {
 	struct mm_struct *mm = vma->vm_mm;
-	pgd_t *pgd;
+	pgd_t *pgd, old_pgd;
 	p4d_t *p4d, old_p4d;
 	pud_t *pud;
 	pmd_t *pmd;
@@ -6157,7 +6158,8 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
 		goto out;
 
 	pgd = pgd_offset(mm, address);
-	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
+	old_pgd = pgdp_get(pgd);
+	if (pgd_none(old_pgd) || unlikely(pgd_bad(old_pgd)))
 		goto out;
 
 	p4d = p4d_offset(pgd, address);
diff --git a/mm/page_vma_mapped.c b/mm/page_vma_mapped.c
index a33f92db2666..fb8b610f7378 100644
--- a/mm/page_vma_mapped.c
+++ b/mm/page_vma_mapped.c
@@ -212,7 +212,7 @@ bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw)
 restart:
 	do {
 		pgd = pgd_offset(mm, pvmw->address);
-		if (!pgd_present(*pgd)) {
+		if (!pgd_present(pgdp_get(pgd))) {
 			step_forward(pvmw, PGDIR_SIZE);
 			continue;
 		}
diff --git a/mm/percpu.c b/mm/percpu.c
index 58660e8eb892..70e68ab002e9 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3184,7 +3184,7 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
 	pud_t *pud;
 	pmd_t *pmd;
 
-	if (pgd_none(*pgd)) {
+	if (pgd_none(pgdp_get(pgd))) {
 		p4d = memblock_alloc(P4D_TABLE_SIZE, P4D_TABLE_SIZE);
 		if (!p4d)
 			goto err_alloc;
diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
index 3db8ccbcb141..644f632c7cba 100644
--- a/mm/pgalloc-track.h
+++ b/mm/pgalloc-track.h
@@ -7,7 +7,7 @@ static inline p4d_t *p4d_alloc_track(struct mm_struct *mm, pgd_t *pgd,
 				     unsigned long address,
 				     pgtbl_mod_mask *mod_mask)
 {
-	if (unlikely(pgd_none(*pgd))) {
+	if (unlikely(pgd_none(pgdp_get(pgd)))) {
 		if (__p4d_alloc(mm, pgd, address))
 			return NULL;
 		*mod_mask |= PGTBL_PGD_MODIFIED;
diff --git a/mm/pgtable-generic.c b/mm/pgtable-generic.c
index f5ab52beb536..16c1ed5b3d0b 100644
--- a/mm/pgtable-generic.c
+++ b/mm/pgtable-generic.c
@@ -24,7 +24,7 @@
 
 void pgd_clear_bad(pgd_t *pgd)
 {
-	pgd_ERROR(*pgd);
+	pgd_ERROR(pgdp_get(pgd));
 	pgd_clear(pgd);
 }
 
diff --git a/mm/rmap.c b/mm/rmap.c
index a0ff325467eb..5f4c52f34192 100644
--- a/mm/rmap.c
+++ b/mm/rmap.c
@@ -809,7 +809,7 @@ pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
 	pmd_t *pmd = NULL;
 
 	pgd = pgd_offset(mm, address);
-	if (!pgd_present(*pgd))
+	if (!pgd_present(pgdp_get(pgd)))
 		goto out;
 
 	p4d = p4d_offset(pgd, address);
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index 2bd1c95f107a..ffc78329a130 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -233,7 +233,7 @@ p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 pgd_t * __meminit vmemmap_pgd_populate(unsigned long addr, int node)
 {
 	pgd_t *pgd = pgd_offset_k(addr);
-	if (pgd_none(*pgd)) {
+	if (pgd_none(pgdp_get(pgd))) {
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index f27ecac7bd6e..a40323a8c6ab 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -450,7 +450,7 @@ void __vunmap_range_noflush(unsigned long start, unsigned long end)
 	pgd = pgd_offset_k(addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		if (pgd_bad(*pgd))
+		if (pgd_bad(pgdp_get(pgd)))
 			mask |= PGTBL_PGD_MODIFIED;
 		if (pgd_none_or_clear_bad(pgd))
 			continue;
@@ -582,7 +582,7 @@ static int vmap_small_pages_range_noflush(unsigned long addr, unsigned long end,
 	pgd = pgd_offset_k(addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		if (pgd_bad(*pgd))
+		if (pgd_bad(pgdp_get(pgd)))
 			mask |= PGTBL_PGD_MODIFIED;
 		err = vmap_pages_p4d_range(pgd, addr, next, prot, pages, &nr, &mask);
 		if (err)
@@ -740,7 +740,7 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 {
 	unsigned long addr = (unsigned long) vmalloc_addr;
 	struct page *page = NULL;
-	pgd_t *pgd = pgd_offset_k(addr);
+	pgd_t *pgd = pgd_offset_k(addr), old_pgd;
 	p4d_t *p4d, old_p4d;
 	pud_t *pud, old_pud;
 	pmd_t *pmd, old_pmd;
@@ -752,11 +752,12 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 	 */
 	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));
 
-	if (pgd_none(*pgd))
+	old_pgd = pgdp_get(pgd);
+	if (pgd_none(old_pgd))
 		return NULL;
-	if (WARN_ON_ONCE(pgd_leaf(*pgd)))
+	if (WARN_ON_ONCE(pgd_leaf(old_pgd)))
 		return NULL; /* XXX: no allowance for huge pgd */
-	if (WARN_ON_ONCE(pgd_bad(*pgd)))
+	if (WARN_ON_ONCE(pgd_bad(old_pgd)))
 		return NULL;
 
 	p4d = p4d_offset(pgd, addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-8-anshuman.khandual%40arm.com.
