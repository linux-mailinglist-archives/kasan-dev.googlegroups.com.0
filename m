Return-Path: <kasan-dev+bncBDGZVRMH6UCRBKHXR63QMGQEKYAE6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A192D977B77
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:45:30 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5e1c72ea68asf1258444eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:45:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217129; cv=pass;
        d=google.com; s=arc-20240605;
        b=TDICbV+ZOVj+gai0UfbdJscRAnT8ZrjWh/PpulFOfDnx38iRzA/3nw9r+eGFreRMZ3
         sK6A8YiGWJjStlDPIx5XBXJ+YILWbh/c6Jf3smr4ZNHbRRlse/EKLoV8YIs4e0q9mQYJ
         md0LA81u3fQbvsdrJG5Nq/MmzUzP4ygj51Lkuz2hGlDwXMm+ge2TKhZrAYc4Mw8/+wLd
         A2XJpFeRIMZuslDbcwUCoQ9dLBVPrCwIeaOSWeSWOg6cA5kC5/gXjdwe8+7JyGEr47ef
         blkQrCVHyj44xT16gTKcPT3Wl7PlU6g/4FuH1BoC4u1t68BPPGqhNHh/fGRqMbM7wpjC
         jr9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bNoLIOnqQ/U0Ua/eD7VZelYTVZSunHen/clD9EhAOk8=;
        fh=DiL5uhQ6LZPjY4Qi19Xje42YGqxGBE4IqV/StDghnk8=;
        b=YqLMGEmdfXWrKuesIa2QzsXrHlrOXxAX/ZOlPEG+80bczezGI+Upv/Up45oPUc7GzQ
         B/2y1lrmyRT+KCxku7lc4fkZ2Uii8sYjzzdOysFsZ58zU5qwIy9GOg3hGJzHemY0/4PP
         Dy1sNL0P24l/14k67ioiE4foPfFPpcgPkD/FyUKfcJunc+SkC2/dvqM35H40kZNpSGXF
         1YIiXQqSqe/Tp+OffMXrK/jbkS/46B4FB3YM8SamLPeUO0SVmfAtpTTeyWeO/fQPelz9
         A7ds+RR0e6ux3i3O/znyBTtgHPNHfGg3OT1zyhRpESZZCmgGRmZ2IAe48y4Pq9aJuP/x
         NITA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217129; x=1726821929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bNoLIOnqQ/U0Ua/eD7VZelYTVZSunHen/clD9EhAOk8=;
        b=l6kpIw0GNnuWqpfvXEUCSaGpr2z39sWY3V6bOiXKbLzRK2tAuq6hcxNGsvic+T+ssj
         zhImFL57aeuWflWYUynwR5XgyJ1PC8aRtNUOT6U+XfUS65m0dpqUcWFYSGetQ5QZRLOK
         JE+/tKqGcVLQE6Mf8JSC2UGELNeOqPb/Yg7Oxh7QkIz8LzW1E/qE+t21WM4Tca8cP3j1
         uVRk3vAEOM2p7F+1VCet9202rHhB+8AMTPZJsjLtMvB1RiEXxygbsbLUwvZq8R0b4q4S
         E7fvJVbwZicteV+7kp67Wu/TLc36RVAFuwMFYOUbJiiFdmdAsScrnixZ4DM+VAmMSbOV
         KApg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217129; x=1726821929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bNoLIOnqQ/U0Ua/eD7VZelYTVZSunHen/clD9EhAOk8=;
        b=GpkcNbavbdOVE1QywiyShIhZ1Y43His6uktkUGnXlQ0QRQPqrN1TMvItxa1F2qrHCv
         ujEQZcFR9GuSEvr+51GKGZy4Qa5WFTQq9YBHZQ47s/gyb59x6cZ9Z2h3fvBcV+ROWU/k
         GEwi+KIZ7YhqbjeS1uCoXKJFdNtIkGhOqn8rGm8Ni0djlhUaDYd0Dt3Zj4bF1rV8JPVp
         YeIatQmJfwERfj6C68JJ24yVjvbOedfOiUpXSBJHlUNp3zLBPrNYtRmfzc8HZLqa5W8S
         RSQcMsALYrgyFA5tvGauxWweatxlkPliLQS1hl5eI5ErhfGqTvq5wXg3DK8XqSLd+eYK
         V15A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXiRk/kilTazF6YujH6LLlsvkVmBkNS2zT3QEMSdxRFd/kmpIoQl4pqjpqhmMgg3nT2bqp0fw==@lfdr.de
X-Gm-Message-State: AOJu0Yx6gvrowTZ9M1DpkBN25YFYzVOc4qw+dS/tRSVS7JoeNhBq0FCD
	4y5SJLg7KsdkSMUWgRSFdqM1doKlTQjh/7wp8UqxEs5/vMpBEijZ
X-Google-Smtp-Source: AGHT+IETm0u4gnMMqMLnhT6Or03I9K4rjV2E1PPmhneSlIYRLPdAVZbfcUmcfN/G9XfcmiT/3lNJvw==
X-Received: by 2002:a05:6820:1686:b0:5e1:cd24:c19c with SMTP id 006d021491bc7-5e2011d1d0amr3770454eaf.0.1726217129072;
        Fri, 13 Sep 2024 01:45:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d693:0:b0:5e1:be65:2052 with SMTP id 006d021491bc7-5e2005d6266ls1026180eaf.0.-pod-prod-01-us;
 Fri, 13 Sep 2024 01:45:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0QWpJXcZ6jtMtBdbrg8f+C715rZnj6fdB6N6msuy1EGf0Qkx40ETVuzf1QzoFRhYh/G7KVMVChS8=@googlegroups.com
X-Received: by 2002:a05:6808:14d4:b0:3db:23d3:8404 with SMTP id 5614622812f47-3e071af5ba8mr6225735b6e.42.1726217128258;
        Fri, 13 Sep 2024 01:45:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217128; cv=none;
        d=google.com; s=arc-20240605;
        b=MoJXubgJ/mEZ131J5YOeDT77SSrIMOveKWoGyxxFiih9k/u2Cz2KfYUHjySbSCN6IA
         de1u+1p2f4hUI7WtDX4E5cfQ6HWWTZX++LJnNRXz7ydM520aE9ddjspa2ROgH87JL7Vv
         B7406S/yrpwzInxZkkClAY+LjGhM2tKwBxPn6Bz497p1muMNr8980ArkKOtDlfJ/zUFV
         EBl/M3282zZEPmMgP0QA3fTJmFFJh0eCsI27SokMx7lgXNwUC6gd9alfVZOfu3ZuVwl+
         0NWrs2a0GuCm51xhE4Gn7YNfGwrcZJhllFlxHNsqSp/L42gGiDmeSpbAVwqUCg9YDCXs
         lD+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=qRFGeIKFMKaxzXeamf9aY+QSfC+ZpyEI8KUp89zpC1E=;
        fh=L0I0rQF349wute9+dmvK5DBpQz+l6pxvsbf+WAdbOHs=;
        b=k8QPEDcPRoi77SknL7G0EEfnbsn/swFI2hKPsbp/44GL4jgpHcXrKP98AapYma+fXK
         PcLD2TTyA+TP+EspuL2OJ9MrMmwLE2qn8ERhml1OXqYu4+Ct9trVO1dTMcTUwaeQ4P7l
         hu0rExA5RZfjZJNeN/8LfSnw9cCIfSGIBJcm/Xj3//WLPwVMapa9CqNMe+GZd1rxpkEZ
         5/n9mFJ1GyWQUhWmWNbgXEpi7xe77T8yCgFjJyEhPmIj7nSRH5GLPAwvM6LsuzzcRpnZ
         7yKcQSdi/IDWhqNKdDRdVAWkvFkyAN2DdH43yplcPgFGkhkbyVYPq9hyTf5g32Vz+WXj
         smSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71908fbd2b5si395957b3a.1.2024.09.13.01.45.28
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:45:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B1BA913D5;
	Fri, 13 Sep 2024 01:45:56 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id EC3C23F73B;
	Fri, 13 Sep 2024 01:45:20 -0700 (PDT)
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
Subject: [PATCH 7/7] mm: Use pgdp_get() for accessing PGD entries
Date: Fri, 13 Sep 2024 14:14:33 +0530
Message-Id: <20240913084433.1016256-8-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240913084433.1016256-1-anshuman.khandual@arm.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
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
also provides the platform an opportunity to override when required.

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
 include/linux/pgtable.h         |  6 +++---
 kernel/events/core.c            |  2 +-
 mm/gup.c                        |  8 ++++----
 mm/hugetlb.c                    |  2 +-
 mm/kasan/init.c                 |  8 ++++----
 mm/kasan/shadow.c               |  2 +-
 mm/memory-failure.c             |  2 +-
 mm/memory.c                     | 10 +++++-----
 mm/page_vma_mapped.c            |  2 +-
 mm/percpu.c                     |  2 +-
 mm/pgalloc-track.h              |  2 +-
 mm/pgtable-generic.c            |  2 +-
 mm/rmap.c                       |  2 +-
 mm/sparse-vmemmap.c             |  2 +-
 mm/vmalloc.c                    | 10 +++++-----
 18 files changed, 34 insertions(+), 34 deletions(-)

diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufault.c
index cdca93398b44..2a8a154d8531 100644
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
index b3e40f06c8c4..19f6557b4bf5 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1084,7 +1084,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
 
 #define set_pgd_safe(pgdp, pgd) \
 ({ \
-	WARN_ON_ONCE(pgd_present(*pgdp) && !pgd_same(*pgdp, pgd)); \
+	WARN_ON_ONCE(pgd_present(pgdp_get(pgdp)) && !pgd_same(pgdp_get(pgdp), pgd)); \
 	set_pgd(pgdp, pgd); \
 })
 
@@ -1237,9 +1237,9 @@ void pmd_clear_bad(pmd_t *);
 
 static inline int pgd_none_or_clear_bad(pgd_t *pgd)
 {
-	if (pgd_none(*pgd))
+	if (pgd_none(pgdp_get(pgd)))
 		return 1;
-	if (unlikely(pgd_bad(*pgd))) {
+	if (unlikely(pgd_bad(pgdp_get(pgd)))) {
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
index 3a97d0263052..f43daab23979 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -1060,7 +1060,7 @@ static struct page *follow_page_mask(struct vm_area_struct *vma,
 	ctx->page_mask = 0;
 	pgd = pgd_offset(mm, address);
 
-	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
+	if (pgd_none(pgdp_get(pgd)) || unlikely(pgd_bad(pgdp_get(pgd))))
 		page = no_page_table(vma, flags, address);
 	else
 		page = follow_p4d_mask(vma, address, pgd, flags, ctx);
@@ -1111,7 +1111,7 @@ static int get_gate_page(struct mm_struct *mm, unsigned long address,
 		pgd = pgd_offset_k(address);
 	else
 		pgd = pgd_offset_gate(mm, address);
-	if (pgd_none(*pgd))
+	if (pgd_none(pgdp_get(pgd)))
 		return -EFAULT;
 	p4d = p4d_offset(pgd, address);
 	if (p4d_none(p4dp_get(p4d)))
@@ -3158,7 +3158,7 @@ static int gup_fast_pgd_leaf(pgd_t orig, pgd_t *pgdp, unsigned long addr,
 	if (!folio)
 		return 0;
 
-	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
+	if (unlikely(pgd_val(orig) != pgd_val(pgdp_get(pgdp)))) {
 		gup_put_folio(folio, refs, flags);
 		return 0;
 	}
@@ -3267,7 +3267,7 @@ static void gup_fast_pgd_range(unsigned long addr, unsigned long end,
 
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
index 7e6bb051d187..7765d30e669f 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2936,11 +2936,11 @@ static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
 	pgd = pgd_offset(mm, addr);
 	do {
 		next = pgd_addr_end(addr, end);
-		if (pgd_none(*pgd) && !create)
+		if (pgd_none(pgdp_get(pgd)) && !create)
 			continue;
-		if (WARN_ON_ONCE(pgd_leaf(*pgd)))
+		if (WARN_ON_ONCE(pgd_leaf(pgdp_get(pgd))))
 			return -EINVAL;
-		if (!pgd_none(*pgd) && WARN_ON_ONCE(pgd_bad(*pgd))) {
+		if (!pgd_none(pgdp_get(pgd)) && WARN_ON_ONCE(pgd_bad(pgdp_get(pgd)))) {
 			if (!create)
 				continue;
 			pgd_clear_bad(pgd);
@@ -6035,7 +6035,7 @@ int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
 		return -ENOMEM;
 
 	spin_lock(&mm->page_table_lock);
-	if (pgd_present(*pgd)) {	/* Another has populated it */
+	if (pgd_present(pgdp_get(pgd))) {	/* Another has populated it */
 		p4d_free(mm, new);
 	} else {
 		smp_wmb(); /* See comment in pmd_install() */
@@ -6139,7 +6139,7 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
 		goto out;
 
 	pgd = pgd_offset(mm, address);
-	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
+	if (pgd_none(pgdp_get(pgd)) || unlikely(pgd_bad(pgdp_get(pgd))))
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
index 7e0a4974b0fc..b97eea347a36 100644
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
index 829d0cf5e384..7e2e977efaba 100644
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
index c67b067f4686..de7a6dd0ab21 100644
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
@@ -752,11 +752,11 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 	 */
 	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));
 
-	if (pgd_none(*pgd))
+	if (pgd_none(pgdp_get(pgd)))
 		return NULL;
-	if (WARN_ON_ONCE(pgd_leaf(*pgd)))
+	if (WARN_ON_ONCE(pgd_leaf(pgdp_get(pgd))))
 		return NULL; /* XXX: no allowance for huge pgd */
-	if (WARN_ON_ONCE(pgd_bad(*pgd)))
+	if (WARN_ON_ONCE(pgd_bad(pgdp_get(pgd))))
 		return NULL;
 
 	p4d = p4d_offset(pgd, addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240913084433.1016256-8-anshuman.khandual%40arm.com.
