Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKOWZ67QMGQE4RBJMTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 675CBA7E381
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 17:11:39 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3ce8dadfb67sf54829945ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 08:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744038698; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jro0n5GpL3YWFqJQMhfVBwitO3wPViSNr9yCWjRKR1YPK7ks2rz+ayYFNVqdjvWvYx
         XyWXnmihuCEjlguSjCTweswpEQWpQpYdHc2+8WbOCQ3UrUR32VbGfsHtkl+R4cv7PgeU
         Vpxm47uUm9/++ZQ2EC5oYUIiH+KHPD7Wu9B5+pISTKRp+F/m1lEqlhT/PvdJ7JzbFFYX
         dSI5lykO1OB8CsgAvfVtpIsdvHn7dsXOSAtUdi+DYB9pPlnTwSW+Q8NiRphbzmWKRB7+
         Na8ZjYTL03OVKMHLIDNPdidcn+WExl+iwwCSxvd/SRqdrB28lXXDl/bV7XwdRshgKoIf
         ClQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nd1nN7A2U6M7Z3gqakWwezNZ5zdW+hxNelcrEFGlFZk=;
        fh=vfjDkCHEzclcPmZatmDGi9fmNMW5imF2OZax9eucMN0=;
        b=QA3seHLzKJyvHP2NRSXU3wyZNF6aaVeL7WPnT/L3xfQELR0r+hD1B6k8OVURlEIhGm
         8voKGHzMOKu6vZvIdR3jM4RvkqTzI4cZA8KGtxrv2AW4HDn2Z0kEL11wyeweYSguwu3M
         4f7w11WPrPZQUZV4cMHWP0Eg2J33HWAeXj7iMZd93H6D58tKyJ8WySnW3JZ+tO6fqCl0
         CRS85xppnhtD3w29hSkFLmGyKqR/VLB40guZgCU2Emhup3gyyEd/HYcPKIcNpMHXe9iw
         r82WNh4bS4HYArwdlG59G77vRqbfsCijA/h8EdloG+b6BykV/VKR6kDFWd4C1lR04s/A
         rlYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WCNS4jwc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744038698; x=1744643498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nd1nN7A2U6M7Z3gqakWwezNZ5zdW+hxNelcrEFGlFZk=;
        b=Rh/FA93zZ7KbV6cAiMkijzM6zmPNv/qEVZBFG7aXX1ZoefbMLTgifqW26s+yt61/7N
         IOqs+V3iLG5rblpOhTsnIVSqUsdIJrWGMI9EXMA5gg5IVViod6i1NurUOZ456+71O6jm
         a7+3pHvUuCmhWiQEMujxUiyryc0P9btA8nhXKs9W7Plw9KIibMZr8UA0n8YqhYlI+bum
         jeehG8/DkOOqmmhwyTp58+kQtE+wgz9xARwfHPs1b3pmd1rQukn2U1dcwpQGaDkMu186
         aMbYj7xgi2rxw0MO/d1qzE/bjtSvY0arlJJMtVGMsqkC+ssR5t5svn+33QK6mZgV2ysN
         M14Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744038698; x=1744643498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nd1nN7A2U6M7Z3gqakWwezNZ5zdW+hxNelcrEFGlFZk=;
        b=iaZsDj5BuUSzgebW3O0nMSWmHJBHkPBXVSOVvfx+rtt2IFCP+hWciVZvbwipbW1nME
         ZjcbpO6+ZPwvtOcHfEZ3dNnSMOar/KXzioJLZU2RzEyjN2SayBPYTK5JpEkEIzwNXMxr
         5/2y5OKHgngxbhV94O3Ndrczvcxw64m7Xdlz5w/anfNzZyuiqH+Po9BeZ0pHNPXZSEc3
         aYUrxX4n0HSSkCEMzmgVPO/TO0vv8KKEHl7HBi9p/RONmJUn/YktQQIOhUYpQgDIPc1Y
         ebUIXcbLbw3EwOHpCTgee3hLsMBeFdePNNhcuuIOsxGHhnWwgYgEFryqLCEOcnH+a9d2
         qiGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXuGbFFN8XmGnwU+OnsW83ITrG1ij4+/kEng9MwMYmwTxwZ+ZBn7tKeAtEl+7fd8BYln6W0w==@lfdr.de
X-Gm-Message-State: AOJu0YzXFKL9LDRm47dP0aaHJfL4MNvmV/8wF/aSVlO5uzZyaFXH4hL8
	ddo4CsQIDzueO3BUlrydbBabKUPUgn3jSE8GJgd4uz9XvhOVw+wo
X-Google-Smtp-Source: AGHT+IFu4OcxSh+/mHsMtoqdaPC8Q6jzISADGkGOVLat0jJUkE3SEEeGvKWkmV84zwXDNC1sJGdJPw==
X-Received: by 2002:a05:6e02:2218:b0:3d5:dec0:7c03 with SMTP id e9e14a558f8ab-3d6e534ad64mr141828455ab.12.1744038697791;
        Mon, 07 Apr 2025 08:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALHaLtaAnTGzlyDh5tuHXwzIMQYzBARRYWYXi4kIqiCPg==
Received: by 2002:a05:6e02:1488:b0:3d2:abdb:b6ea with SMTP id
 e9e14a558f8ab-3d6dc8aedc8ls31030845ab.0.-pod-prod-07-us; Mon, 07 Apr 2025
 08:11:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUF6N6QKSlv6qqbfiewjmFif/Xy/RKCYKJsjCM3eWFl1QbsNBiHnqIxphsCmAjA9Htd3/Et3Vyf5A8=@googlegroups.com
X-Received: by 2002:a6b:7511:0:b0:861:1cd4:1fef with SMTP id ca18e2360f4ac-8611cd428eamr1153939739f.0.1744038696829;
        Mon, 07 Apr 2025 08:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744038696; cv=none;
        d=google.com; s=arc-20240605;
        b=iqZ+PHii+GY+JN26LOupjDURnAUGORnb0cPO02MIVvKPE4wU1LTgvJMe80tT0RWkdc
         mdrOKL6BKxAreYbuNaAim435alFt1q37tYGLCZXCj9rv8znniUmCaa12u7ON/s4+Ab92
         YA7/pYsOfvi0E44kQ9jS5N1Wss+5SRzQbA6ctEuw8pCSTCgvz47u+gFlhkZ8r8qnOh2J
         3g+lgVszDF1vN1fj17Gp9g8VM5p0psnBkS653M5Iylqj412p5GsFOaNbJbtLtEJaid8J
         WJ42Q9F4bYlJ5GQpfbiTfhTZGwuyw+xlWq48kn0+Z3zWnv2WU/GfWTXuLbmM4aRocrzT
         nZLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ngcqzYVpe7xkxjw37TRZ0RrIQbWfDyVW1WAk2hgrGY8=;
        fh=LVJPJYP2Tqlg8aWQBGa6aniChm4kWZS3hY9A1BPUb/I=;
        b=gEn5sncCgGSy1S2JNtHqCmXK/VGxpEdnG8WNaaKgftDtQyuXVDm8ZLLLx/fyj3QaRk
         nRaeMGE+IVplnVfO4t/46Pa+4KjiKftg2ir/twplUZxnAMh3g7ndIQccGDD4ourGic95
         Z/IA5i3hqAcSDu86koRwYwlLdCPO5ZkXtRBuEXcresDaXPVYmo0ZUSJNGfMz9k3AfMBM
         iSJtlYoi5FII2/HinyZm+aNRSPhJzDXr6jkyz8k7MeaOH3FSwN1YJoO+0BIvmTHPhwGI
         VlKguvi6VhALkIZSd55zV1P6EHqZmHiUrigUTQmZ2hHsypqvg66CyH1HFWkpwY8mo0Uv
         mK0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WCNS4jwc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5c2e1e1si454417173.2.2025.04.07.08.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Apr 2025 08:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5378eCst023081;
	Mon, 7 Apr 2025 15:11:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45v0spm8qy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:36 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 537FBZII019687;
	Mon, 7 Apr 2025 15:11:35 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45v0spm8qw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:35 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 537Ehxeh017825;
	Mon, 7 Apr 2025 15:11:34 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 45uh2ke5uh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:32 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 537FBVTb14156090
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 7 Apr 2025 15:11:31 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0B32320049;
	Mon,  7 Apr 2025 15:11:31 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E98012004D;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 85284E1613; Mon, 07 Apr 2025 17:11:30 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org
Subject: [PATCH v1 3/4] mm: Protect kernel pgtables in apply_to_pte_range()
Date: Mon,  7 Apr 2025 17:11:29 +0200
Message-ID: <11dbe3ac88130dbd2b8554f9369cd93fe138c655.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Gsml-lqe4-oFygMCgc_o4kWGTfpeXFVg
X-Proofpoint-ORIG-GUID: 9HS87Mcesg4PbHflITRoaij8qwSTG9RL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-07_04,2025-04-03_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 clxscore=1011
 bulkscore=0 impostorscore=0 suspectscore=0 lowpriorityscore=0 mlxscore=0
 adultscore=0 phishscore=0 priorityscore=1501 spamscore=0 mlxlogscore=828
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2502280000
 definitions=main-2504070104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WCNS4jwc;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

The lazy MMU mode can only be entered and left under the protection
of the page table locks for all page tables which may be modified.
Yet, when it comes to kernel mappings apply_to_pte_range() does not
take any locks. That does not conform arch_enter|leave_lazy_mmu_mode()
semantics and could potentially lead to re-schedulling a process while
in lazy MMU mode or racing on a kernel page table updates.

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 7 ++-----
 mm/memory.c       | 5 ++++-
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index edfa77959474..6531a7aa8562 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -308,14 +308,14 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
 	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
 
-	spin_lock(&init_mm.page_table_lock);
 	if (likely(pte_none(ptep_get(ptep)))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
 	}
-	spin_unlock(&init_mm.page_table_lock);
+
 	if (page)
 		free_page(page);
+
 	return 0;
 }
 
@@ -401,13 +401,10 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 
 	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
 
-	spin_lock(&init_mm.page_table_lock);
-
 	if (likely(!pte_none(ptep_get(ptep)))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
 	}
-	spin_unlock(&init_mm.page_table_lock);
 
 	return 0;
 }
diff --git a/mm/memory.c b/mm/memory.c
index f0201c8ec1ce..1f3727104e99 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2926,6 +2926,7 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 			pte = pte_offset_kernel(pmd, addr);
 		if (!pte)
 			return err;
+		spin_lock(&init_mm.page_table_lock);
 	} else {
 		if (create)
 			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
@@ -2951,7 +2952,9 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 
 	arch_leave_lazy_mmu_mode();
 
-	if (mm != &init_mm)
+	if (mm == &init_mm)
+		spin_unlock(&init_mm.page_table_lock);
+	else
 		pte_unmap_unlock(mapped_pte, ptl);
 
 	*mask |= PGTBL_PTE_MODIFIED;
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/11dbe3ac88130dbd2b8554f9369cd93fe138c655.1744037648.git.agordeev%40linux.ibm.com.
