Return-Path: <kasan-dev+bncBDGZVRMH6UCRBGXXR63QMGQEZSIDFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 547BF977B72
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:45:16 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6c360967e53sf11197746d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217115; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pp7ojlPY0FKqdKbLfFCeopyF0Qm2dQrNQ4lOXfuZNClx39NTcbBhUPh6N8Z+xB253g
         S2WKZmjNqB01F8GDjSQvYJVIBoHZI2aFuIX2b1i67IFI/klXXpa3+lLaUpLFrOm9CP9t
         HcDDmm+/6NT0QtkAaFbIvRGXs0HAWSYwWFtzL8UOuPXZnDt72bIj9/PhnEC7OeU9tjpb
         OIdg/BbliqFN+K3vwX824hEqkWHGaTBK7nzmkhd3dHPNvDZc0eQs1JsDw4d5ch19FxfF
         ++Rs+1fKugkr6Bf43YK6HHRaKB1TEmh/GKrXYnJEsEmdHtUL7Hnslzm8JigmgCwKoksm
         KXGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=YAZShqP5Q249vTp3UCZXcdq/fDWjgrLnmjTweM0yh8w=;
        fh=ospgR83s49iVTvdeaohimgsQ0Wc344IFZwiF22lpdhY=;
        b=P332pRwlcFpXgnaEOzjMvNWxPri6HooE84ZkIFf1nkPvF3GFnJgV3+CRsvpJnl6Kwa
         zFABR1Qq1DJX8RLS7UeIiF4jJsStQdf8SAXZtPObuTNYGybvFf49ldWJ8G5Fimf0ocwR
         6bFzbZ7IReiGvFBozEZPjtpUjb/Usoyq2jbsXAe9LBRLbGTa0EtYd0K2Js+rs6edZeC+
         lLK+xTnskG5SxxdeR34jU/VQoq86WWa+K2kd0HDfBV0ys7sT/8qzypwsA9PWI9wGZMu1
         YOYvZmf/8eZfTKTs5rDEJ10jbKdtLU69ESEivAmQqwmlYpu+v4IGvRkfhEs+fIZRoLhm
         ByMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217115; x=1726821915; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YAZShqP5Q249vTp3UCZXcdq/fDWjgrLnmjTweM0yh8w=;
        b=Z+sXjD6Bs+FZoHEixyqk5VDc4KqJbqBJJbv1XuEFRN26gheXjzmJTbWRu3/07IsN6Q
         +mtVemYpuEvoMWzewwYvxWyxLbrzQAFoGbgcdGoPUcdsjizAVo+s/fs0exUMiNhOHRCA
         Xj0bOkFCRt1gX9FKI77sWteE6bPsKbQOcYP211wZ3epcwvH+2HpwcqpW7hbqZUKXGeXY
         RJNOrhghR4et98hQ9L3Ri1LKWe0EhsqYgCQ0Ty9edeJ9XSUQgIzJXV3kzwU+fkvy/L5x
         Lbc2/MCM+jvZCyt1Hx4x0dcofznwvGqhsBq/F1KDikHIDDK2W8oHHp4AlFrfUihaIyX+
         MR1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217115; x=1726821915;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YAZShqP5Q249vTp3UCZXcdq/fDWjgrLnmjTweM0yh8w=;
        b=q485Ce5rgmHQIdeJ6lSUOsEWDCK22S8mZmjyQvURJY4mFxBH7CTFIH5RfO3Qv5Szqb
         FU2tg8XyAfAmbGIK34AY6kyqRzuKnltIbi++VQUlfB1xE0CVAVRmOX2yEOPu/koaD09Y
         l1GRqH5zTkq4Sx6TVWYXbineSxZ0dlgnCvAn2DHV8RfMfsSHNjDo4ZCxlmese15aVyYl
         +riFi3R7HxKXTsphiFxFgRKKQEROf1+BRiNRXS5mhQOXfDKwXts+oDa6ukGnDAYJTKjc
         MpKAxRpbGHQTMX9udMavQfx2m1h9hwML4qXFYjMzNjsYkD3jjqbBSvoe/OS0S9sKenIh
         nYww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/qS5J4mIRb6L1ydR8NZXKXaZ1aIVH7pwCk/pHpv1dJCernN5cKNe07CKIuRO9tOLiRx588Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz94OKSCBrsDw+xlcPPkJediwkhOQ7nBhFLUN8fIEzIeQ/trRLC
	XXK9ie7iRseySmxfCmqbSUTXZOkCrm164fCGGjUd/KHMOCHKlAP7
X-Google-Smtp-Source: AGHT+IGhOysfZjVN/q7wN67yR36jiV7xP4hvterkURCZ0HPUbjt9zqZPRKg07Ov2TVp1OjjeVGnwww==
X-Received: by 2002:a05:6214:4605:b0:6c5:3177:eaed with SMTP id 6a1803df08f44-6c57e102dcbmr27576886d6.36.1726217115010;
        Fri, 13 Sep 2024 01:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:407:b0:6c5:19d1:7aa8 with SMTP id
 6a1803df08f44-6c573507319ls28931776d6.2.-pod-prod-06-us; Fri, 13 Sep 2024
 01:45:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX287ZBUCjIg1ifS+IX4ZperIVWEhUcxKZbCwiUFBQqjYS3gzyMIVmZwmWJ3l27BXGzcfhvl5K9rhw=@googlegroups.com
X-Received: by 2002:a05:6102:3709:b0:49c:92d:1041 with SMTP id ada2fe7eead31-49d4f60c8d7mr1586460137.14.1726217113980;
        Fri, 13 Sep 2024 01:45:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217113; cv=none;
        d=google.com; s=arc-20240605;
        b=V0V9AeSq8CEzauesjzrHC+ymHEagSGynNE69FdvmKjhQoNf0c7PYJlQEIjdWXe3qiy
         VZj7mQGf3wV7TNfhgjBhOybTJWFexu4LRnYZ+yyLZSSvu4ISCxW1sOcDGD9kQk4VbmPU
         Ssq9H2+a0F4wM1Jdb/Dt6EMgENVCYl95Bv6LixdPo5dKD6HGjPYSVRMqTnH8gbVMcEci
         Fa1cl5apZD8jgq0NmGKly7GnnIvAF4piPDu/20TWIrwSTlSCpFAhAEfRDu1edjwzAhiu
         2chdYBXRiCyFsGBq6xGfreiQZpHpMIWbCHlgfXlmlFChI3ODnNFf8ZNmpgFS5VwdryO2
         UsUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=DfoPueKoSMiPINFrFEnLdwElCrFNUUFiXm5c72uAasM=;
        fh=zPRZeEmJP4LlGVEGfR3f/0Od4eO8rC08qZYXsq0IL6Y=;
        b=GwXviNpfHSjzXxFgpFkivU3vB9O+YbrS0REvGSlXpqDU4bDWajddzXv3Se2GhnfcOU
         fu5wJ7/6BUEo3zXVITAJDAcOWo+Z/1n+Ca+xkAZDKKhA5n5G00gfyqav062mb10Rtgsz
         tp1LmwTJaRvZxCStzEwR9Hwd6S7SOCVNifewN9JAwjYhpe5BF5cKhN9kR5TvW9i6iWdM
         /OoymfeGZyY/CTDf1O7XvykqqYmvkb9qWJjv2N1mb4j4aXkrl3+Z0c4AuiUnKQBLUFtI
         pYncUbgjO7/CDyzxG9Pa8Namu4i4Rga/PckjBBOGi03TqkgalV1Pyw7tTDO+ibOuRS3W
         XGRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a1e0cc1a2514c-84906e8bb5fsi174094241.2.2024.09.13.01.45.13
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:45:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E3EAA15BF;
	Fri, 13 Sep 2024 01:45:42 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 2AD203F73B;
	Fri, 13 Sep 2024 01:45:06 -0700 (PDT)
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
Subject: [PATCH 5/7] mm: Use pudp_get() for accessing PUD entries
Date: Fri, 13 Sep 2024 14:14:31 +0530
Message-Id: <20240913084433.1016256-6-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240913084433.1016256-1-anshuman.khandual@arm.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
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
also provides the platform an opportunity to override when required.

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
 include/linux/huge_mm.h         |  2 +-
 include/linux/mm.h              |  2 +-
 include/linux/pgtable.h         | 10 +++++-----
 kernel/events/core.c            |  2 +-
 mm/gup.c                        | 12 ++++++------
 mm/hmm.c                        |  2 +-
 mm/huge_memory.c                | 16 ++++++++--------
 mm/hugetlb.c                    |  6 +++---
 mm/kasan/init.c                 | 10 +++++-----
 mm/kasan/shadow.c               |  4 ++--
 mm/mapping_dirty_helpers.c      |  2 +-
 mm/memory-failure.c             |  4 ++--
 mm/memory.c                     | 10 +++++-----
 mm/page_table_check.c           |  2 +-
 mm/page_vma_mapped.c            |  2 +-
 mm/pgalloc-track.h              |  2 +-
 mm/pgtable-generic.c            |  2 +-
 mm/ptdump.c                     |  4 ++--
 19 files changed, 48 insertions(+), 48 deletions(-)

diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufaul=
t.c
index f3d6249b7dfb..0a06ec92f090 100644
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
diff --git a/include/linux/huge_mm.h b/include/linux/huge_mm.h
index 351d6c72af9e..17ee222e4004 100644
--- a/include/linux/huge_mm.h
+++ b/include/linux/huge_mm.h
@@ -378,7 +378,7 @@ static inline spinlock_t *pmd_trans_huge_lock(pmd_t *pm=
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
index 188a183205b3..b25a0a505ce6 100644
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
@@ -1072,7 +1072,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
=20
 #define set_pud_safe(pudp, pud) \
 ({ \
-	WARN_ON_ONCE(pud_present(*pudp) && !pud_same(*pudp, pud)); \
+	WARN_ON_ONCE(pud_present(pudp_get(pudp)) && !pud_same(pudp_get(pudp), pud=
)); \
 	set_pud(pudp, pud); \
 })
=20
@@ -1259,9 +1259,9 @@ static inline int p4d_none_or_clear_bad(p4d_t *p4d)
=20
 static inline int pud_none_or_clear_bad(pud_t *pud)
 {
-	if (pud_none(*pud))
+	if (pud_none(pudp_get(pud)))
 		return 1;
-	if (unlikely(pud_bad(*pud))) {
+	if (unlikely(pud_bad(pudp_get(pud)))) {
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
index 3545142a5dc9..994babaca75f 100644
--- a/mm/huge_memory.c
+++ b/mm/huge_memory.c
@@ -1247,13 +1247,13 @@ static void insert_pfn_pud(struct vm_area_struct *v=
ma, unsigned long addr,
 	spinlock_t *ptl;
=20
 	ptl =3D pud_lock(mm, pud);
-	if (!pud_none(*pud)) {
+	if (!pud_none(pudp_get(pud))) {
 		if (write) {
-			if (pud_pfn(*pud) !=3D pfn_t_to_pfn(pfn)) {
-				WARN_ON_ONCE(!is_huge_zero_pud(*pud));
+			if (pud_pfn(pudp_get(pud)) !=3D pfn_t_to_pfn(pfn)) {
+				WARN_ON_ONCE(!is_huge_zero_pud(pudp_get(pud)));
 				goto out_unlock;
 			}
-			entry =3D pud_mkyoung(*pud);
+			entry =3D pud_mkyoung(pudp_get(pud));
 			entry =3D maybe_pud_mkwrite(pud_mkdirty(entry), vma);
 			if (pudp_set_access_flags(vma, addr, pud, entry, 1))
 				update_mmu_cache_pud(vma, addr, pud);
@@ -1475,7 +1475,7 @@ void touch_pud(struct vm_area_struct *vma, unsigned l=
ong addr,
 {
 	pud_t _pud;
=20
-	_pud =3D pud_mkyoung(*pud);
+	_pud =3D pud_mkyoung(pudp_get(pud));
 	if (write)
 		_pud =3D pud_mkdirty(_pud);
 	if (pudp_set_access_flags(vma, addr & HPAGE_PUD_MASK,
@@ -2284,7 +2284,7 @@ spinlock_t *__pud_trans_huge_lock(pud_t *pud, struct =
vm_area_struct *vma)
 	spinlock_t *ptl;
=20
 	ptl =3D pud_lock(vma->vm_mm, pud);
-	if (likely(pud_trans_huge(*pud) || pud_devmap(*pud)))
+	if (likely(pud_trans_huge(pudp_get(pud)) || pud_devmap(pudp_get(pud))))
 		return ptl;
 	spin_unlock(ptl);
 	return NULL;
@@ -2318,7 +2318,7 @@ static void __split_huge_pud_locked(struct vm_area_st=
ruct *vma, pud_t *pud,
 	VM_BUG_ON(haddr & ~HPAGE_PUD_MASK);
 	VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
 	VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PUD_SIZE, vma);
-	VM_BUG_ON(!pud_trans_huge(*pud) && !pud_devmap(*pud));
+	VM_BUG_ON(!pud_trans_huge(pudp_get(pud)) && !pud_devmap(pudp_get(pud)));
=20
 	count_vm_event(THP_SPLIT_PUD);
=20
@@ -2336,7 +2336,7 @@ void __split_huge_pud(struct vm_area_struct *vma, pud=
_t *pud,
 				(address & HPAGE_PUD_MASK) + HPAGE_PUD_SIZE);
 	mmu_notifier_invalidate_range_start(&range);
 	ptl =3D pud_lock(vma->vm_mm, pud);
-	if (unlikely(!pud_trans_huge(*pud) && !pud_devmap(*pud)))
+	if (unlikely(!pud_trans_huge(pudp_get(pud)) && !pud_devmap(pudp_get(pud))=
))
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
index 43953a6d350f..af6c9346493c 100644
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
@@ -2819,7 +2819,7 @@ static int apply_to_pmd_range(struct mm_struct *mm, p=
ud_t *pud,
 	unsigned long next;
 	int err =3D 0;
=20
-	BUG_ON(pud_leaf(*pud));
+	BUG_ON(pud_leaf(pudp_get(pud)));
=20
 	if (create) {
 		pmd =3D pmd_alloc_track(mm, pud, addr, mask);
@@ -2866,11 +2866,11 @@ static int apply_to_pud_range(struct mm_struct *mm,=
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
index a5045d0fc73e..5bd02c6208e7 100644
--- a/mm/pgtable-generic.c
+++ b/mm/pgtable-generic.c
@@ -153,7 +153,7 @@ pud_t pudp_huge_clear_flush(struct vm_area_struct *vma,=
 unsigned long address,
 	pud_t pud;
=20
 	VM_BUG_ON(address & ~HPAGE_PUD_MASK);
-	VM_BUG_ON(!pud_trans_huge(*pudp) && !pud_devmap(*pudp));
+	VM_BUG_ON(!pud_trans_huge(pudp_get(pudp)) && !pud_devmap(pudp_get(pudp)))=
;
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
--=20
2.25.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240913084433.1016256-6-anshuman.khandual%40arm.com.
