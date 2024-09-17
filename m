Return-Path: <kasan-dev+bncBDGZVRMH6UCRB5PAUS3QMGQEJ3XNSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 054CD97AC1C
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:32:07 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2d8b4a23230sf6151722a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:32:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558325; cv=pass;
        d=google.com; s=arc-20240605;
        b=aKpCs6X2bizdDgOUB/aQnTzur173hufQIOi6+Snqs00GgYQckQJG12x4R+J+4yK1IK
         5jyfQGF9Yv53bU78V3du0mx6U9anJmPrj5iTJTTgCHHEH9wLXZMuzg3W8pZ+GKsLzMgg
         eS5KwKeSkp2O6hJ20KQ9TiRwVkmViXpEU+nHLVhBLoF62EsokijXzgzUTgmA6MvW6QS7
         3Qp6vgiejfZBGwag20uSswhpLmSP6IW3fSOprX8jPo9UiOD03m2NTfuaDjMNcVDUc2NM
         R91g8ph1Twp+6aSI+iLCyb+VrSvJGTxicauYKpNjROI7/TyWlZKM0HvLJLffvbl1bzJF
         yrMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=90Ag43oBe+ZXb3KE9u+46fFwCzgfZR1IlsYHt/iTqL4=;
        fh=TakyhcwWPAhsYikUoRcPbFD5b9bQlkjLMPJTkWlS+Pw=;
        b=YRyhHNQKAP3TduAEJ1BL6g4pudEDLjn9RRxLkqPsKwKJ0rMxq0IIkrePDqFAym0Gnt
         XR0TOfztE2I5EgcjsUYmAHU+lNTVBg/YMfZ5zworlf3AHrwun5VSO8imBMHgkeZ++/1P
         mUh6FWD//BEZY408ghvy6zdKoEH90IKzjs0bMyqAK1G14vQIzUmY6ReuNFl2HJq7aojj
         yF46pXWOt8isew1cqdBSLBa/fdXydqaLQtHT3u+AbdGFOjSONStw1XLk1xqFhjhtrw5g
         2kk5/EQWajs5/UIyzt8d9YrB0m5thZUiNoLK3L50qWG2xfMKPdlnZSG0G+6GgSiGfHDS
         9+wg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558325; x=1727163125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=90Ag43oBe+ZXb3KE9u+46fFwCzgfZR1IlsYHt/iTqL4=;
        b=uzG0GqfUpBcv3Wn2EI5oulYynskA7kjEMUdPPqaXIiEpv0DA/qLATu3bdQkuBTMvAQ
         1LpSwCz0wbRx/hL0hL5RIoqgO8bKZ3+WtMHmIs/MX/HWHtumQK4/rLzY50CpcdnMUPOa
         rvRpca8G41WxnoL6teHfRHUG0Pzy366qPtAGZ+tskom4yvmxA5zEkg43g2gLMrsCPh/k
         WgzJPZURQiWgF5dKzArBAReC9DklktSOlc2ENAHMYFL60wvr6zJid8UIQsyzg1NyGgF7
         0TT8ekrvX0YIoRKCWa6ZJ/mashKSuneR0/qCXiyGjJ+lYG0cgPKF1zk0nuKt85/+WulW
         dHkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558325; x=1727163125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=90Ag43oBe+ZXb3KE9u+46fFwCzgfZR1IlsYHt/iTqL4=;
        b=MO6ySGqlewJmdgl2A2v7pyd8us4SzNG/l/dfMjA4dMumEHRE9ddBJAfXsholR/3kBU
         8Vq+UsQ8PgSKTtj+ovanO0omjrSSZacliKICJWh50Ez8oZWeoHPbgfO2jUnjwQ9To4qp
         H1QmUDZo06UvIyYGqUcoKARymndTYD5MAikYZBDKiGxgq2okbbbx3W1RCccW2OcC94nD
         RB/g0zxF1eU7a14VHQCML+BdJ76KHSumIJh2Dv4NURnnwyN9RlcEXb754vL8A/yW+Bf+
         hzApFU/vdFKkdzW9VYGL2muwyJRB66UKBg8lyev+jMQ7eSkZUgqKg1S4DyKhGkqjwnBf
         NYKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuLK1IgFpCNqpX+30i4vLJOfH7ta2ZUtiv49E6KYAmoXtWbCs9tcG5x8ppBTc84R6lbrakDQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywo/KWj/Iuyiyh4AzcdaGu727k60G/CUH8MhAJF7VIsJA/7nwF6
	EelOvTRDQn2EnKZ0n9WT6M647phLUF/HDXFCtJ/Dt9DL+mczWAX6
X-Google-Smtp-Source: AGHT+IGn4mkq+agarJTNj59s2X5Nl+2YwxYPhGzT+3eHerBpkYou5kSIFOUadv0yq9OJU3OGWuNnEQ==
X-Received: by 2002:a17:90b:2883:b0:2dd:4f93:93d4 with SMTP id 98e67ed59e1d1-2dd4f93944emr1262516a91.17.1726558325500;
        Tue, 17 Sep 2024 00:32:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17cb:b0:2cb:57a2:d478 with SMTP id
 98e67ed59e1d1-2db9f63b0d0ls2225648a91.1.-pod-prod-01-us; Tue, 17 Sep 2024
 00:32:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUf+lxixTFMrl3Jz1KS9YUes68mC34k2T35pbKuB3sK3n/3hqVqb5pKbiDDLj1nSY3ca/5DZXyQ9fw=@googlegroups.com
X-Received: by 2002:a05:6a20:c6c1:b0:1d2:e78d:214a with SMTP id adf61e73a8af0-1d2e78dc400mr727147637.44.1726558323190;
        Tue, 17 Sep 2024 00:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558323; cv=none;
        d=google.com; s=arc-20240605;
        b=Gv7E81xq4txOW83c9anxt35BFzK1Mm5mzr/0/t76JjLu5QAp7PdCBcnJRhUR16wG+s
         0q8LUWwJ9vWpId/sksMGu401mmK1EsCmxrQjIZQxcCwdkGikkfaZ3ikSkgDA2xDs93D2
         qpU1DVVcAUYmRlW8dtpXQUxkOUGU+/ZmU1bVHJvK1OniRqP3UD9rkvfeEsq02L3mN4tc
         6gc2G5JfWckJHNdOzzf3lKnhXTpWgR2xkVQ004NvUur5Hpjlv74jtnwiAYoIBgHWOH90
         1Q5eEYOb5yVCZdRFxjLfiejve0eyyrk0iFPVyqZabVoy+V/DXzHROOR2uaqJTq9pQCct
         t+4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=CEFgZetd4pxu5jlYUNdyrjKeZ6YDsS89h9L42GW3kkM=;
        fh=zPRZeEmJP4LlGVEGfR3f/0Od4eO8rC08qZYXsq0IL6Y=;
        b=E4j4mE5HMgJHbWQGmAxDwEPLOPOWeArNiHyhXTJhjBI29gFwK+K/ve0pAx7kQ1hgtf
         5QJ6bA46UiBtohHEF2vf2LlDEqPg+JWj3Nu75ZV6ZkTtEki07EDBp8CvQulyqCvVkiIi
         STHM19jX4755pcRi7OIlc82kiEkL3FABpC21+rQ/3RC7bdkCNSPpT6jKn73BCxlEaglW
         ibyTxYoOVcyHLyB/MIPotlOVId+kQ9nhNBBQnOX2gZD0cUm09jUihlH5fGglsZoHK5ms
         /WWNJ+h1fUhajeGqR5Elq4h0ovdhM3p3vAlQy/y8RaQotJjRc9nblxD74UXndrnPqzgE
         4xoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2dbcfde60basi253237a91.3.2024.09.17.00.32.02
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 950FD106F;
	Tue, 17 Sep 2024 00:32:31 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9716F3F64C;
	Tue, 17 Sep 2024 00:31:54 -0700 (PDT)
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
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>,
	Naoya Horiguchi <nao.horiguchi@gmail.com>,
	Pasha Tatashin <pasha.tatashin@soleen.com>
Subject: [PATCH V2 5/7] mm: Use pudp_get() for accessing PUD entries
Date: Tue, 17 Sep 2024 13:01:15 +0530
Message-Id: <20240917073117.1531207-6-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240917073117.1531207-1-anshuman.khandual@arm.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Convert PUD accesses via pudp_get() helper that defaults as READ_ONCE() but
also provides the platform an opportunity to override when required. This
stores read page table entry value in a local variable which can be used in
multiple instances there after. This helps in avoiding multiple memory load
operations as well possible race conditions.

Cc: Dimitri Sivanich <dimitri.sivanich@hpe.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Arnaldo Carvalho de Melo <acme@kernel.org>
Cc: "J=C3=A9r=C3=B4me Glisse" <jglisse@redhat.com>
Cc: Muchun Song <muchun.song@linux.dev>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>
Cc: Naoya Horiguchi <nao.horiguchi@gmail.com>
Cc: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
Cc: linux-perf-users@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 drivers/misc/sgi-gru/grufault.c |  2 +-
 fs/userfaultfd.c                |  2 +-
 include/linux/huge_mm.h         |  2 +-
 include/linux/mm.h              |  2 +-
 include/linux/pgtable.h         | 13 ++++++++-----
 kernel/events/core.c            |  2 +-
 mm/gup.c                        | 12 ++++++------
 mm/hmm.c                        |  2 +-
 mm/huge_memory.c                | 24 +++++++++++++++---------
 mm/hugetlb.c                    |  6 +++---
 mm/kasan/init.c                 | 10 +++++-----
 mm/kasan/shadow.c               |  4 ++--
 mm/mapping_dirty_helpers.c      |  2 +-
 mm/memory-failure.c             |  4 ++--
 mm/memory.c                     | 14 +++++++-------
 mm/page_table_check.c           |  2 +-
 mm/page_vma_mapped.c            |  2 +-
 mm/pagewalk.c                   |  6 +++---
 mm/percpu.c                     |  2 +-
 mm/pgalloc-track.h              |  2 +-
 mm/pgtable-generic.c            |  6 +++---
 mm/ptdump.c                     |  4 ++--
 mm/rmap.c                       |  2 +-
 mm/sparse-vmemmap.c             |  2 +-
 mm/vmalloc.c                    | 15 ++++++++-------
 mm/vmscan.c                     |  4 ++--
 26 files changed, 79 insertions(+), 69 deletions(-)

diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufaul=
t.c
index 804f275ece99..95d479d5e40f 100644
--- a/drivers/misc/sgi-gru/grufault.c
+++ b/drivers/misc/sgi-gru/grufault.c
@@ -220,7 +220,7 @@ static int atomic_pte_lookup(struct vm_area_struct *vma=
, unsigned long vaddr,
 		goto err;
=20
 	pudp =3D pud_offset(p4dp, vaddr);
-	if (unlikely(pud_none(*pudp)))
+	if (unlikely(pud_none(pudp_get(pudp))))
 		goto err;
=20
 	pmdp =3D pmd_offset(pudp, vaddr);
diff --git a/fs/userfaultfd.c b/fs/userfaultfd.c
index 27a3e9285fbf..00719a0f688c 100644
--- a/fs/userfaultfd.c
+++ b/fs/userfaultfd.c
@@ -310,7 +310,7 @@ static inline bool userfaultfd_must_wait(struct userfau=
ltfd_ctx *ctx,
 	if (!p4d_present(*p4d))
 		goto out;
 	pud =3D pud_offset(p4d, address);
-	if (!pud_present(*pud))
+	if (!pud_present(pudp_get(pud)))
 		goto out;
 	pmd =3D pmd_offset(pud, address);
 again:
diff --git a/include/linux/huge_mm.h b/include/linux/huge_mm.h
index 38b5de040d02..66a19622d95b 100644
--- a/include/linux/huge_mm.h
+++ b/include/linux/huge_mm.h
@@ -379,7 +379,7 @@ static inline spinlock_t *pmd_trans_huge_lock(pmd_t *pm=
d,
 static inline spinlock_t *pud_trans_huge_lock(pud_t *pud,
 		struct vm_area_struct *vma)
 {
-	if (pud_trans_huge(*pud) || pud_devmap(*pud))
+	if (pud_trans_huge(pudp_get(pud)) || pud_devmap(pudp_get(pud)))
 		return __pud_trans_huge_lock(pud, vma);
 	else
 		return NULL;
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 258e49323306..1bb1599b5779 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2832,7 +2832,7 @@ static inline pud_t *pud_alloc(struct mm_struct *mm, =
p4d_t *p4d,
=20
 static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned =
long address)
 {
-	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
+	return (unlikely(pud_none(pudp_get(pud))) && __pmd_alloc(mm, pud, address=
)) ?
 		NULL: pmd_offset(pud, address);
 }
 #endif /* CONFIG_MMU */
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index ea283ce958a7..eb993ef0946f 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -611,7 +611,7 @@ static inline pud_t pudp_huge_get_and_clear(struct mm_s=
truct *mm,
 					    unsigned long address,
 					    pud_t *pudp)
 {
-	pud_t pud =3D *pudp;
+	pud_t pud =3D pudp_get(pudp);
=20
 	pud_clear(pudp);
 	page_table_check_pud_clear(mm, pud);
@@ -893,7 +893,7 @@ static inline void pmdp_set_wrprotect(struct mm_struct =
*mm,
 static inline void pudp_set_wrprotect(struct mm_struct *mm,
 				      unsigned long address, pud_t *pudp)
 {
-	pud_t old_pud =3D *pudp;
+	pud_t old_pud =3D pudp_get(pudp);
=20
 	set_pud_at(mm, address, pudp, pud_wrprotect(old_pud));
 }
@@ -1074,7 +1074,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
=20
 #define set_pud_safe(pudp, pud) \
 ({ \
-	WARN_ON_ONCE(pud_present(*pudp) && !pud_same(*pudp, pud)); \
+	pud_t __old =3D pudp_get(pudp); \
+	WARN_ON_ONCE(pud_present(__old) && !pud_same(__old, pud)); \
 	set_pud(pudp, pud); \
 })
=20
@@ -1261,9 +1262,11 @@ static inline int p4d_none_or_clear_bad(p4d_t *p4d)
=20
 static inline int pud_none_or_clear_bad(pud_t *pud)
 {
-	if (pud_none(*pud))
+	pud_t old_pud =3D pudp_get(pud);
+
+	if (pud_none(old_pud))
 		return 1;
-	if (unlikely(pud_bad(*pud))) {
+	if (unlikely(pud_bad(old_pud))) {
 		pud_clear_bad(pud);
 		return 1;
 	}
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 8a6c6bbcd658..35e2f2789246 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -7619,7 +7619,7 @@ static u64 perf_get_pgtable_size(struct mm_struct *mm=
, unsigned long addr)
 		return p4d_leaf_size(p4d);
=20
 	pudp =3D pud_offset_lockless(p4dp, p4d, addr);
-	pud =3D READ_ONCE(*pudp);
+	pud =3D pudp_get(pudp);
 	if (!pud_present(pud))
 		return 0;
=20
diff --git a/mm/gup.c b/mm/gup.c
index aeeac0a54944..300fc7eb306c 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -606,7 +606,7 @@ static struct page *follow_huge_pud(struct vm_area_stru=
ct *vma,
 {
 	struct mm_struct *mm =3D vma->vm_mm;
 	struct page *page;
-	pud_t pud =3D *pudp;
+	pud_t pud =3D pudp_get(pudp);
 	unsigned long pfn =3D pud_pfn(pud);
 	int ret;
=20
@@ -989,7 +989,7 @@ static struct page *follow_pud_mask(struct vm_area_stru=
ct *vma,
 	struct mm_struct *mm =3D vma->vm_mm;
=20
 	pudp =3D pud_offset(p4dp, address);
-	pud =3D READ_ONCE(*pudp);
+	pud =3D pudp_get(pudp);
 	if (!pud_present(pud))
 		return no_page_table(vma, flags, address);
 	if (pud_leaf(pud)) {
@@ -1117,7 +1117,7 @@ static int get_gate_page(struct mm_struct *mm, unsign=
ed long address,
 	if (p4d_none(*p4d))
 		return -EFAULT;
 	pud =3D pud_offset(p4d, address);
-	if (pud_none(*pud))
+	if (pud_none(pudp_get(pud)))
 		return -EFAULT;
 	pmd =3D pmd_offset(pud, address);
 	if (!pmd_present(pmdp_get(pmd)))
@@ -3025,7 +3025,7 @@ static int gup_fast_devmap_pud_leaf(pud_t orig, pud_t=
 *pudp, unsigned long addr,
 	if (!gup_fast_devmap_leaf(fault_pfn, addr, end, flags, pages, nr))
 		return 0;
=20
-	if (unlikely(pud_val(orig) !=3D pud_val(*pudp))) {
+	if (unlikely(pud_val(orig) !=3D pud_val(pudp_get(pudp)))) {
 		gup_fast_undo_dev_pagemap(nr, nr_start, flags, pages);
 		return 0;
 	}
@@ -3118,7 +3118,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp,=
 unsigned long addr,
 	if (!folio)
 		return 0;
=20
-	if (unlikely(pud_val(orig) !=3D pud_val(*pudp))) {
+	if (unlikely(pud_val(orig) !=3D pud_val(pudp_get(pudp)))) {
 		gup_put_folio(folio, refs, flags);
 		return 0;
 	}
@@ -3219,7 +3219,7 @@ static int gup_fast_pud_range(p4d_t *p4dp, p4d_t p4d,=
 unsigned long addr,
=20
 	pudp =3D pud_offset_lockless(p4dp, p4d, addr);
 	do {
-		pud_t pud =3D READ_ONCE(*pudp);
+		pud_t pud =3D pudp_get(pudp);
=20
 		next =3D pud_addr_end(addr, end);
 		if (unlikely(!pud_present(pud)))
diff --git a/mm/hmm.c b/mm/hmm.c
index 7e0229ae4a5a..c1b093d670b8 100644
--- a/mm/hmm.c
+++ b/mm/hmm.c
@@ -423,7 +423,7 @@ static int hmm_vma_walk_pud(pud_t *pudp, unsigned long =
start, unsigned long end,
 	/* Normally we don't want to split the huge page */
 	walk->action =3D ACTION_CONTINUE;
=20
-	pud =3D READ_ONCE(*pudp);
+	pud =3D pudp_get(pudp);
 	if (!pud_present(pud)) {
 		spin_unlock(ptl);
 		return hmm_vma_walk_hole(start, end, -1, walk);
diff --git a/mm/huge_memory.c b/mm/huge_memory.c
index bb63de935937..69e1400a51ec 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -1243,17 +1243,18 @@ static void insert_pfn_pud(struct vm_area_struct *v=
ma, unsigned long addr,
 {
 	struct mm_struct *mm =3D vma->vm_mm;
 	pgprot_t prot =3D vma->vm_page_prot;
-	pud_t entry;
+	pud_t entry, old_pud;
 	spinlock_t *ptl;
=20
 	ptl =3D pud_lock(mm, pud);
-	if (!pud_none(*pud)) {
+	old_pud =3D pudp_get(pud);
+	if (!pud_none(old_pud)) {
 		if (write) {
-			if (pud_pfn(*pud) !=3D pfn_t_to_pfn(pfn)) {
-				WARN_ON_ONCE(!is_huge_zero_pud(*pud));
+			if (pud_pfn(old_pud) !=3D pfn_t_to_pfn(pfn)) {
+				WARN_ON_ONCE(!is_huge_zero_pud(old_pud));
 				goto out_unlock;
 			}
-			entry =3D pud_mkyoung(*pud);
+			entry =3D pud_mkyoung(old_pud);
 			entry =3D maybe_pud_mkwrite(pud_mkdirty(entry), vma);
 			if (pudp_set_access_flags(vma, addr, pud, entry, 1))
 				update_mmu_cache_pud(vma, addr, pud);
@@ -1476,7 +1477,7 @@ void touch_pud(struct vm_area_struct *vma, unsigned l=
ong addr,
 {
 	pud_t _pud;
=20
-	_pud =3D pud_mkyoung(*pud);
+	_pud =3D pud_mkyoung(pudp_get(pud));
 	if (write)
 		_pud =3D pud_mkdirty(_pud);
 	if (pudp_set_access_flags(vma, addr & HPAGE_PUD_MASK,
@@ -2284,9 +2285,10 @@ spinlock_t *__pmd_trans_huge_lock(pmd_t *pmd, struct=
 vm_area_struct *vma)
 spinlock_t *__pud_trans_huge_lock(pud_t *pud, struct vm_area_struct *vma)
 {
 	spinlock_t *ptl;
+	pud_t old_pud =3D pudp_get(pud);
=20
 	ptl =3D pud_lock(vma->vm_mm, pud);
-	if (likely(pud_trans_huge(*pud) || pud_devmap(*pud)))
+	if (likely(pud_trans_huge(old_pud) || pud_devmap(old_pud)))
 		return ptl;
 	spin_unlock(ptl);
 	return NULL;
@@ -2317,10 +2319,12 @@ int zap_huge_pud(struct mmu_gather *tlb, struct vm_=
area_struct *vma,
 static void __split_huge_pud_locked(struct vm_area_struct *vma, pud_t *pud=
,
 		unsigned long haddr)
 {
+	pud_t old_pud =3D pudp_get(pud);
+
 	VM_BUG_ON(haddr & ~HPAGE_PUD_MASK);
 	VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
 	VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PUD_SIZE, vma);
-	VM_BUG_ON(!pud_trans_huge(*pud) && !pud_devmap(*pud));
+	VM_BUG_ON(!pud_trans_huge(old_pud) && !pud_devmap(old_pud));
=20
 	count_vm_event(THP_SPLIT_PUD);
=20
@@ -2332,13 +2336,15 @@ void __split_huge_pud(struct vm_area_struct *vma, p=
ud_t *pud,
 {
 	spinlock_t *ptl;
 	struct mmu_notifier_range range;
+	pud_t old_pud;
=20
 	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma->vm_mm,
 				address & HPAGE_PUD_MASK,
 				(address & HPAGE_PUD_MASK) + HPAGE_PUD_SIZE);
 	mmu_notifier_invalidate_range_start(&range);
 	ptl =3D pud_lock(vma->vm_mm, pud);
-	if (unlikely(!pud_trans_huge(*pud) && !pud_devmap(*pud)))
+	old_pud =3D pudp_get(pud);
+	if (unlikely(!pud_trans_huge(old_pud) && !pud_devmap(old_pud)))
 		goto out;
 	__split_huge_pud_locked(vma, pud, range.start);
=20
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index aaf508be0a2b..a3820242b01e 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -7328,7 +7328,7 @@ pte_t *huge_pmd_share(struct mm_struct *mm, struct vm=
_area_struct *vma,
 		goto out;
=20
 	spin_lock(&mm->page_table_lock);
-	if (pud_none(*pud)) {
+	if (pud_none(pudp_get(pud))) {
 		pud_populate(mm, pud,
 				(pmd_t *)((unsigned long)spte & PAGE_MASK));
 		mm_inc_nr_pmds(mm);
@@ -7417,7 +7417,7 @@ pte_t *huge_pte_alloc(struct mm_struct *mm, struct vm=
_area_struct *vma,
 			pte =3D (pte_t *)pud;
 		} else {
 			BUG_ON(sz !=3D PMD_SIZE);
-			if (want_pmd_share(vma, addr) && pud_none(*pud))
+			if (want_pmd_share(vma, addr) && pud_none(pudp_get(pud)))
 				pte =3D huge_pmd_share(mm, vma, addr, pud);
 			else
 				pte =3D (pte_t *)pmd_alloc(mm, pud, addr);
@@ -7461,7 +7461,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 	if (sz =3D=3D PUD_SIZE)
 		/* must be pud huge, non-present or none */
 		return (pte_t *)pud;
-	if (!pud_present(*pud))
+	if (!pud_present(pudp_get(pud)))
 		return NULL;
 	/* must have a valid entry and size to go further */
=20
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 4418bcdcb2aa..f4cf519443e1 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -162,7 +162,7 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned=
 long addr,
 			continue;
 		}
=20
-		if (pud_none(*pud)) {
+		if (pud_none(pudp_get(pud))) {
 			pmd_t *p;
=20
 			if (slab_is_available()) {
@@ -315,7 +315,7 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud=
)
 			return;
 	}
=20
-	pmd_free(&init_mm, (pmd_t *)page_to_virt(pud_page(*pud)));
+	pmd_free(&init_mm, (pmd_t *)page_to_virt(pud_page(pudp_get(pud))));
 	pud_clear(pud);
 }
=20
@@ -326,7 +326,7 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d=
)
=20
 	for (i =3D 0; i < PTRS_PER_PUD; i++) {
 		pud =3D pud_start + i;
-		if (!pud_none(*pud))
+		if (!pud_none(pudp_get(pud)))
 			return;
 	}
=20
@@ -407,10 +407,10 @@ static void kasan_remove_pud_table(pud_t *pud, unsign=
ed long addr,
=20
 		next =3D pud_addr_end(addr, end);
=20
-		if (!pud_present(*pud))
+		if (!pud_present(pudp_get(pud)))
 			continue;
=20
-		if (kasan_pmd_table(*pud)) {
+		if (kasan_pmd_table(pudp_get(pud))) {
 			if (IS_ALIGNED(addr, PUD_SIZE) &&
 			    IS_ALIGNED(next, PUD_SIZE)) {
 				pud_clear(pud);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index aec16a7236f7..dbd8164c75f1 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -197,9 +197,9 @@ static bool shadow_mapped(unsigned long addr)
 	if (p4d_none(*p4d))
 		return false;
 	pud =3D pud_offset(p4d, addr);
-	if (pud_none(*pud))
+	if (pud_none(pudp_get(pud)))
 		return false;
-	if (pud_leaf(*pud))
+	if (pud_leaf(pudp_get(pud)))
 		return true;
 	pmd =3D pmd_offset(pud, addr);
 	if (pmd_none(pmdp_get(pmd)))
diff --git a/mm/mapping_dirty_helpers.c b/mm/mapping_dirty_helpers.c
index 2f8829b3541a..c556cc4e3480 100644
--- a/mm/mapping_dirty_helpers.c
+++ b/mm/mapping_dirty_helpers.c
@@ -149,7 +149,7 @@ static int wp_clean_pud_entry(pud_t *pud, unsigned long=
 addr, unsigned long end,
 			      struct mm_walk *walk)
 {
 #ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
-	pud_t pudval =3D READ_ONCE(*pud);
+	pud_t pudval =3D pudp_get(pud);
=20
 	/* Do not split a huge pud */
 	if (pud_trans_huge(pudval) || pud_devmap(pudval)) {
diff --git a/mm/memory-failure.c b/mm/memory-failure.c
index 305dbef3cc4d..fbb63401fb51 100644
--- a/mm/memory-failure.c
+++ b/mm/memory-failure.c
@@ -417,9 +417,9 @@ static unsigned long dev_pagemap_mapping_shift(struct v=
m_area_struct *vma,
 	if (!p4d_present(*p4d))
 		return 0;
 	pud =3D pud_offset(p4d, address);
-	if (!pud_present(*pud))
+	if (!pud_present(pudp_get(pud)))
 		return 0;
-	if (pud_devmap(*pud))
+	if (pud_devmap(pudp_get(pud)))
 		return PUD_SHIFT;
 	pmd =3D pmd_offset(pud, address);
 	if (!pmd_present(pmdp_get(pmd)))
diff --git a/mm/memory.c b/mm/memory.c
index 5520e1f6a1b9..801750e4337c 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -1753,7 +1753,7 @@ static inline unsigned long zap_pud_range(struct mmu_=
gather *tlb,
 	pud =3D pud_offset(p4d, addr);
 	do {
 		next =3D pud_addr_end(addr, end);
-		if (pud_trans_huge(*pud) || pud_devmap(*pud)) {
+		if (pud_trans_huge(pudp_get(pud)) || pud_devmap(pudp_get(pud))) {
 			if (next - addr !=3D HPAGE_PUD_SIZE) {
 				mmap_assert_locked(tlb->mm);
 				split_huge_pud(vma, pud, addr);
@@ -2836,7 +2836,7 @@ static int apply_to_pmd_range(struct mm_struct *mm, p=
ud_t *pud,
 	unsigned long next;
 	int err =3D 0;
=20
-	BUG_ON(pud_leaf(*pud));
+	BUG_ON(pud_leaf(pudp_get(pud)));
=20
 	if (create) {
 		pmd =3D pmd_alloc_track(mm, pud, addr, mask);
@@ -2883,11 +2883,11 @@ static int apply_to_pud_range(struct mm_struct *mm,=
 p4d_t *p4d,
 	}
 	do {
 		next =3D pud_addr_end(addr, end);
-		if (pud_none(*pud) && !create)
+		if (pud_none(pudp_get(pud)) && !create)
 			continue;
-		if (WARN_ON_ONCE(pud_leaf(*pud)))
+		if (WARN_ON_ONCE(pud_leaf(pudp_get(pud))))
 			return -EINVAL;
-		if (!pud_none(*pud) && WARN_ON_ONCE(pud_bad(*pud))) {
+		if (!pud_none(pudp_get(pud)) && WARN_ON_ONCE(pud_bad(pudp_get(pud)))) {
 			if (!create)
 				continue;
 			pud_clear_bad(pud);
@@ -6099,7 +6099,7 @@ int __pmd_alloc(struct mm_struct *mm, pud_t *pud, uns=
igned long address)
 		return -ENOMEM;
=20
 	ptl =3D pud_lock(mm, pud);
-	if (!pud_present(*pud)) {
+	if (!pud_present(pudp_get(pud))) {
 		mm_inc_nr_pmds(mm);
 		smp_wmb(); /* See comment in pmd_install() */
 		pud_populate(mm, pud, new);
@@ -6164,7 +6164,7 @@ int follow_pte(struct vm_area_struct *vma, unsigned l=
ong address,
 		goto out;
=20
 	pud =3D pud_offset(p4d, address);
-	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
+	if (pud_none(pudp_get(pud)) || unlikely(pud_bad(pudp_get(pud))))
 		goto out;
=20
 	pmd =3D pmd_offset(pud, address);
diff --git a/mm/page_table_check.c b/mm/page_table_check.c
index 48a2cf56c80e..2a22d098b0b1 100644
--- a/mm/page_table_check.c
+++ b/mm/page_table_check.c
@@ -254,7 +254,7 @@ void __page_table_check_pud_set(struct mm_struct *mm, p=
ud_t *pudp, pud_t pud)
 	if (&init_mm =3D=3D mm)
 		return;
=20
-	__page_table_check_pud_clear(mm, *pudp);
+	__page_table_check_pud_clear(mm, pudp_get(pudp));
 	if (pud_user_accessible_page(pud)) {
 		page_table_check_set(pud_pfn(pud), PUD_SIZE >> PAGE_SHIFT,
 				     pud_write(pud));
diff --git a/mm/page_vma_mapped.c b/mm/page_vma_mapped.c
index ae5cc42aa208..511266307771 100644
--- a/mm/page_vma_mapped.c
+++ b/mm/page_vma_mapped.c
@@ -222,7 +222,7 @@ bool page_vma_mapped_walk(struct page_vma_mapped_walk *=
pvmw)
 			continue;
 		}
 		pud =3D pud_offset(p4d, pvmw->address);
-		if (!pud_present(*pud)) {
+		if (!pud_present(pudp_get(pud))) {
 			step_forward(pvmw, PUD_SIZE);
 			continue;
 		}
diff --git a/mm/pagewalk.c b/mm/pagewalk.c
index c3019a160e77..1d32c6da1a0d 100644
--- a/mm/pagewalk.c
+++ b/mm/pagewalk.c
@@ -145,7 +145,7 @@ static int walk_pud_range(p4d_t *p4d, unsigned long add=
r, unsigned long end,
 	do {
  again:
 		next =3D pud_addr_end(addr, end);
-		if (pud_none(*pud)) {
+		if (pud_none(pudp_get(pud))) {
 			if (ops->pte_hole)
 				err =3D ops->pte_hole(addr, next, depth, walk);
 			if (err)
@@ -163,14 +163,14 @@ static int walk_pud_range(p4d_t *p4d, unsigned long a=
ddr, unsigned long end,
 		if (walk->action =3D=3D ACTION_AGAIN)
 			goto again;
=20
-		if ((!walk->vma && (pud_leaf(*pud) || !pud_present(*pud))) ||
+		if ((!walk->vma && (pud_leaf(pudp_get(pud)) || !pud_present(pudp_get(pud=
)))) ||
 		    walk->action =3D=3D ACTION_CONTINUE ||
 		    !(ops->pmd_entry || ops->pte_entry))
 			continue;
=20
 		if (walk->vma)
 			split_huge_pud(walk->vma, pud, addr);
-		if (pud_none(*pud))
+		if (pud_none(pudp_get(pud)))
 			goto again;
=20
 		err =3D walk_pmd_range(pud, addr, next, walk);
diff --git a/mm/percpu.c b/mm/percpu.c
index 7ee77c0fd5e3..5f32164b04a2 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3200,7 +3200,7 @@ void __init __weak pcpu_populate_pte(unsigned long ad=
dr)
 	}
=20
 	pud =3D pud_offset(p4d, addr);
-	if (pud_none(*pud)) {
+	if (pud_none(pudp_get(pud))) {
 		pmd =3D memblock_alloc(PMD_TABLE_SIZE, PMD_TABLE_SIZE);
 		if (!pmd)
 			goto err_alloc;
diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
index e9e879de8649..0f6b809431a3 100644
--- a/mm/pgalloc-track.h
+++ b/mm/pgalloc-track.h
@@ -33,7 +33,7 @@ static inline pmd_t *pmd_alloc_track(struct mm_struct *mm=
, pud_t *pud,
 				     unsigned long address,
 				     pgtbl_mod_mask *mod_mask)
 {
-	if (unlikely(pud_none(*pud))) {
+	if (unlikely(pud_none(pudp_get(pud)))) {
 		if (__pmd_alloc(mm, pud, address))
 			return NULL;
 		*mod_mask |=3D PGTBL_PUD_MODIFIED;
diff --git a/mm/pgtable-generic.c b/mm/pgtable-generic.c
index 920947bb76cd..e09e3f920f7a 100644
--- a/mm/pgtable-generic.c
+++ b/mm/pgtable-generic.c
@@ -39,7 +39,7 @@ void p4d_clear_bad(p4d_t *p4d)
 #ifndef __PAGETABLE_PUD_FOLDED
 void pud_clear_bad(pud_t *pud)
 {
-	pud_ERROR(*pud);
+	pud_ERROR(pudp_get(pud));
 	pud_clear(pud);
 }
 #endif
@@ -150,10 +150,10 @@ pmd_t pmdp_huge_clear_flush(struct vm_area_struct *vm=
a, unsigned long address,
 pud_t pudp_huge_clear_flush(struct vm_area_struct *vma, unsigned long addr=
ess,
 			    pud_t *pudp)
 {
-	pud_t pud;
+	pud_t pud, old_pud =3D pudp_get(pudp);
=20
 	VM_BUG_ON(address & ~HPAGE_PUD_MASK);
-	VM_BUG_ON(!pud_trans_huge(*pudp) && !pud_devmap(*pudp));
+	VM_BUG_ON(!pud_trans_huge(old_pud) && !pud_devmap(old_pud));
 	pud =3D pudp_huge_get_and_clear(vma->vm_mm, address, pudp);
 	flush_pud_tlb_range(vma, address, address + HPAGE_PUD_SIZE);
 	return pud;
diff --git a/mm/ptdump.c b/mm/ptdump.c
index e17588a32012..32ae8e829329 100644
--- a/mm/ptdump.c
+++ b/mm/ptdump.c
@@ -30,7 +30,7 @@ static int ptdump_pgd_entry(pgd_t *pgd, unsigned long add=
r,
 			    unsigned long next, struct mm_walk *walk)
 {
 	struct ptdump_state *st =3D walk->private;
-	pgd_t val =3D READ_ONCE(*pgd);
+	pgd_t val =3D pgdp_get(pgd);
=20
 #if CONFIG_PGTABLE_LEVELS > 4 && \
 		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
@@ -76,7 +76,7 @@ static int ptdump_pud_entry(pud_t *pud, unsigned long add=
r,
 			    unsigned long next, struct mm_walk *walk)
 {
 	struct ptdump_state *st =3D walk->private;
-	pud_t val =3D READ_ONCE(*pud);
+	pud_t val =3D pudp_get(pud);
=20
 #if CONFIG_PGTABLE_LEVELS > 2 && \
 		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
diff --git a/mm/rmap.c b/mm/rmap.c
index 32e4920e419d..81f1946653e0 100644
--- a/mm/rmap.c
+++ b/mm/rmap.c
@@ -817,7 +817,7 @@ pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long =
address)
 		goto out;
=20
 	pud =3D pud_offset(p4d, address);
-	if (!pud_present(*pud))
+	if (!pud_present(pudp_get(pud)))
 		goto out;
=20
 	pmd =3D pmd_offset(pud, address);
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index c89706e107ce..d8ea64ec665f 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -203,7 +203,7 @@ void __weak __meminit pmd_init(void *addr)
 pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int=
 node)
 {
 	pud_t *pud =3D pud_offset(p4d, addr);
-	if (pud_none(*pud)) {
+	if (pud_none(pudp_get(pud))) {
 		void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 1da56cbe5feb..05292d998122 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -200,7 +200,7 @@ static int vmap_try_huge_pud(pud_t *pud, unsigned long =
addr, unsigned long end,
 	if (!IS_ALIGNED(phys_addr, PUD_SIZE))
 		return 0;
=20
-	if (pud_present(*pud) && !pud_free_pmd_page(pud, addr))
+	if (pud_present(pudp_get(pud)) && !pud_free_pmd_page(pud, addr))
 		return 0;
=20
 	return pud_set_huge(pud, phys_addr, prot);
@@ -396,7 +396,7 @@ static void vunmap_pud_range(p4d_t *p4d, unsigned long =
addr, unsigned long end,
 		next =3D pud_addr_end(addr, end);
=20
 		cleared =3D pud_clear_huge(pud);
-		if (cleared || pud_bad(*pud))
+		if (cleared || pud_bad(pudp_get(pud)))
 			*mask |=3D PGTBL_PUD_MODIFIED;
=20
 		if (cleared)
@@ -742,7 +742,7 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
 	struct page *page =3D NULL;
 	pgd_t *pgd =3D pgd_offset_k(addr);
 	p4d_t *p4d;
-	pud_t *pud;
+	pud_t *pud, old_pud;
 	pmd_t *pmd, old_pmd;
 	pte_t *ptep, pte;
=20
@@ -768,11 +768,12 @@ struct page *vmalloc_to_page(const void *vmalloc_addr=
)
 		return NULL;
=20
 	pud =3D pud_offset(p4d, addr);
-	if (pud_none(*pud))
+	old_pud =3D pudp_get(pud);
+	if (pud_none(old_pud))
 		return NULL;
-	if (pud_leaf(*pud))
-		return pud_page(*pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
-	if (WARN_ON_ONCE(pud_bad(*pud)))
+	if (pud_leaf(old_pud))
+		return pud_page(old_pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
+	if (WARN_ON_ONCE(pud_bad(old_pud)))
 		return NULL;
=20
 	pmd =3D pmd_offset(pud, addr);
diff --git a/mm/vmscan.c b/mm/vmscan.c
index bd489c1af228..04b03e6c3095 100644
--- a/mm/vmscan.c
+++ b/mm/vmscan.c
@@ -3421,7 +3421,7 @@ static void walk_pmd_range_locked(pud_t *pud, unsigne=
d long addr, struct vm_area
 	DEFINE_MAX_SEQ(walk->lruvec);
 	int old_gen, new_gen =3D lru_gen_from_seq(max_seq);
=20
-	VM_WARN_ON_ONCE(pud_leaf(*pud));
+	VM_WARN_ON_ONCE(pud_leaf(pudp_get(pud)));
=20
 	/* try to batch at most 1+MIN_LRU_BATCH+1 entries */
 	if (*first =3D=3D -1) {
@@ -3501,7 +3501,7 @@ static void walk_pmd_range(pud_t *pud, unsigned long =
start, unsigned long end,
 	struct lru_gen_mm_walk *walk =3D args->private;
 	struct lru_gen_mm_state *mm_state =3D get_mm_state(walk->lruvec);
=20
-	VM_WARN_ON_ONCE(pud_leaf(*pud));
+	VM_WARN_ON_ONCE(pud_leaf(pudp_get(pud)));
=20
 	/*
 	 * Finish an entire PMD in two passes: the first only reaches to PTE
--=20
2.25.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240917073117.1531207-6-anshuman.khandual%40arm.com.
