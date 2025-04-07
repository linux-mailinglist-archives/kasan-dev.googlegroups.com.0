Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKGWZ67QMGQEP7A3ADI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 45DE2A7E37E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 17:11:38 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e63405c626asf4797702276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 08:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744038697; cv=pass;
        d=google.com; s=arc-20240605;
        b=HTBCTOoho1mFV09DbLvs8tTpfquEyzoNVNHYM5diGAJ3/LNS5AvsnsMXJNjAOuw7l1
         E/kVdCBv5YyCzNWtM3Uh/IKRQnVmximJHN4NBzEyB1+OR9WmayYrepP/hHOi7xUuUOYs
         v3IH2bcv2slfS7NpV872AI0kpM/pRez5QPfiyLZCjwAD25mqQMPHydKSEtu2b9ES6Waq
         8H7LvSO5jAON5T3EVANKCvroxajZvELoLg60J92WuOn6BzobJMDWLpzi4GdCVBX5TXES
         MNQsVG29TLLq2CheojrHV0RfD4u2R+tiZMNzJGmK0IP1cdMpMB1dyhX0Du+rJ+IzyaPf
         ERvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QHiwqJiNEMUhSWSrzzOQ+C+2Z1Edw5/12IV8lqorcdo=;
        fh=TGNc+pKVrsv3GK3RUnx5Dybx1MvKv3HykIXKJ+8+gWY=;
        b=Pp7H/hjMqa2P8UBp7Xkb7XjvNmSEdMqjIvvFVtNiuPjFkQC/JT741KoZNFqYFMZhWR
         +OUT8u/JCxeS+wYsy8pctj5vWcmIHoIKSJP6IeNLhJRlVGgHbhmJ8GaJU6RDQqnvRxI+
         heR0UY3CTrEJIJo92bdG985S4gVM4diNeEEd//A4MWnZvK7ZsKJyqAfnt9QPBa3G4zpp
         r9H8K4NG9bZQmFGYoW74DIz/DZj2RZ08sAtWJ5uANA9hYBqY9hNcL/9I2fqXGnIFfV5h
         BZl5LpgJ87MZ3KydAiPwmvcLq3k/r1UwvANFPzN8P2CSgXoH4e93jP/IU6sS39MP+BXE
         1myg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WOoAcnFv;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744038697; x=1744643497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QHiwqJiNEMUhSWSrzzOQ+C+2Z1Edw5/12IV8lqorcdo=;
        b=bjHSZYvxrPEpozDM0yhwdExBRJ1B45xHZOEkb+04iZlyaEq7uf86smnz4kRI2NZaD4
         jLC9KyTpcxTJf6hrpTBYlSuF2+gdde+dCgB5U7Qohl3eMV4SVEWkxazC3QoeIyBA251f
         tI1/95V9IiUG+U/askp7kAN678VlQXvvyzCV3zj2ZXAHppsV+VQoDTl+g2qLE8SZrE+J
         izOuqDiVJa8+XNsPH+nEc+Slf4zGqKPl5I5MEtK745KSgQjxoS3i2jbyg/rF+dMNPtY0
         YpiA4BxEkQ249JQ+Z1zQs8sXpVM41mmqye+vguMxXVqsR4Ki1ARDkRSgR4wV5joA9QG3
         +T2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744038697; x=1744643497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QHiwqJiNEMUhSWSrzzOQ+C+2Z1Edw5/12IV8lqorcdo=;
        b=M4H2h2knyAUYcaiWowgdqRWzRhVE1z23dS0dQbBn36HerfeRZUW+AGES9qnPu+P3/x
         /HMh6MU0rKteCjiMrbbM+Vuc3DytYIOMAJEZXyqKM4dlNZ37MgGe/WMRbZRuiWCXP/OZ
         d3kxms/CGWxxx4u40Ke8k4/p7yjrRcUh22q8OoTsEya7tAtwoVWBDvLXiP1xvWvImJid
         oGmzyDnPi0JZTBXH+uFCXLy6WxPIT0yE20rMmKfu0jZU9yIg02lVk+5hHTwYdd7nfcET
         0MA2E5rYZVdjDCzeC/T0FfVPClidpnl4bxcjlnYtjabWnTOssx/zz5CF4pL7mA5krz/x
         P9ug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJ605b4zevNcTNZY1BXYJ2ovDESSyi1NT1VkUNhCKfrRB6ZzbWO2tAWt0KzxfKUJqiTBPtmQ==@lfdr.de
X-Gm-Message-State: AOJu0YxMOsLRaZ1UWoL8d/SDEDqcB01zkqDi+ITvBQE0vjh53LFpQH4E
	JdsSFdzMGHv+0zqX7jjiJwrpVHdII0U4e3SC18h8pVtEZfBBjZUo
X-Google-Smtp-Source: AGHT+IHbSzxpZQPmWoFLjJAbtG/5DBuhf3CS/jY1XWPfH4BpRROS/NkFIRvMSND6jx4+raXf/944AA==
X-Received: by 2002:a05:6902:98f:b0:e6b:7d64:fc00 with SMTP id 3f1490d57ef6-e6e1f9a5565mr20148420276.17.1744038696676;
        Mon, 07 Apr 2025 08:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALp1WKhDslgyu0yKhiSuQAelLb+fneUemeCloF9N73vRw==
Received: by 2002:a25:b10e:0:b0:e63:65ef:4018 with SMTP id 3f1490d57ef6-e6e07a9d2c5ls854062276.1.-pod-prod-09-us;
 Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUqmpk3VNYLJel+Pr0tij00wFqlRjPJzw6YbYOKzV9qzGzujHKSivfUX5hLLbFGtJB5QhLLHC1VYnY=@googlegroups.com
X-Received: by 2002:a05:6902:1585:b0:e6d:ec18:9409 with SMTP id 3f1490d57ef6-e6e1f9cfc91mr20121681276.29.1744038695576;
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744038695; cv=none;
        d=google.com; s=arc-20240605;
        b=f2HCGp4SashDqRkq1+R6IsYBJxJsA/Ap2YyqQggJ0jxk/22KFI4ebdTQomwibMGn1o
         t2ekd9LCipL+mKdMiNFdwH0V8CyBTX7sbEENJXZJJtZYAlVSTQ40+aLOdCCKK9pdW+Lt
         bmhjUMQPM6jHtI1CP08RFDEje21K/I7t3VYMcx+ON631NYNUWm3E2TWUjjJnuLaU/CFt
         QNE2B+yQMaKn2bdpgwy5NwH5mNsky210SjYclZW3RBfQJtdkhr0nePQ9cb4Dg9ob/cUK
         AZQzioBnnqOaw1cjjY3fqKggYDqejOisfZOqSHtqYYOsEJXy8EY4NqQndMtpedIHYRkV
         GYAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OcNsdUXLajTS6Up4yb87KBBXCRng/iRPfXkDho493IU=;
        fh=LVJPJYP2Tqlg8aWQBGa6aniChm4kWZS3hY9A1BPUb/I=;
        b=jDduXYYDCtIfUCRQ6OH5UPTlhRNybGhnCKURoJl0GXehH0Ubqex17138I/o8xHujqg
         RA4G49RQbemzX84StW7Dz9gwex5vjHmXbozMqYuFq2s9JixWQTRzaUaO2tQ8OYJilkAn
         3cUydInQ0lxgACLRoblC86nMvPDi2m+X3DDa5zrQmdqZEQpp2LK9mF02N6rfie8OBVbI
         3VyMDVD7bxnwtqnRHo/4Ur/+/LUjowkNpX/+F6GjE5iKpRRPV6V0x22XLKBqEJSB8+Ec
         wlzdPBHef1QxJtMeMy12nGApPwbHrJdvfmTch917N6yEpfYf1hQMq3FUvFMZ1Vkv/l9L
         fDeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WOoAcnFv;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e6e0c93cc20si442880276.2.2025.04.07.08.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5378IrTc029651;
	Mon, 7 Apr 2025 15:11:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45uwswvt35-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:34 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 537F41Wv022508;
	Mon, 7 Apr 2025 15:11:33 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45uwswvt30-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:33 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 537DrCNJ011062;
	Mon, 7 Apr 2025 15:11:33 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45uf7yege2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:33 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 537FBVtw16122324
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 7 Apr 2025 15:11:31 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 10E992004E;
	Mon,  7 Apr 2025 15:11:31 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EDA652004B;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 823D8E15AF; Mon, 07 Apr 2025 17:11:30 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org
Subject: [PATCH v1 2/4] mm: Cleanup apply_to_pte_range() routine
Date: Mon,  7 Apr 2025 17:11:28 +0200
Message-ID: <93102722541b1daf541fce9fb316a1a2614d8c86.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZjXrqfzVuI4O6PuB71DztWSnTeaDAz2F
X-Proofpoint-ORIG-GUID: B8AxCnBSacob3HedwAwYgmrsIk7eP_GG
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-07_04,2025-04-03_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 bulkscore=0 mlxlogscore=912 spamscore=0 adultscore=0 clxscore=1011
 phishscore=0 lowpriorityscore=0 impostorscore=0 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504070104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WOoAcnFv;       spf=pass (google.com:
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

Reverse 'create' vs 'mm == &init_mm' conditions and move
page table mask modification out of the atomic context.

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/memory.c | 28 +++++++++++++++++-----------
 1 file changed, 17 insertions(+), 11 deletions(-)

diff --git a/mm/memory.c b/mm/memory.c
index 2d8c265fc7d6..f0201c8ec1ce 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2915,24 +2915,28 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 				     pte_fn_t fn, void *data, bool create,
 				     pgtbl_mod_mask *mask)
 {
+	int err = create ? -ENOMEM : -EINVAL;
 	pte_t *pte, *mapped_pte;
-	int err = 0;
 	spinlock_t *ptl;
 
-	if (create) {
-		mapped_pte = pte = (mm == &init_mm) ?
-			pte_alloc_kernel_track(pmd, addr, mask) :
-			pte_alloc_map_lock(mm, pmd, addr, &ptl);
+	if (mm == &init_mm) {
+		if (create)
+			pte = pte_alloc_kernel_track(pmd, addr, mask);
+		else
+			pte = pte_offset_kernel(pmd, addr);
 		if (!pte)
-			return -ENOMEM;
+			return err;
 	} else {
-		mapped_pte = pte = (mm == &init_mm) ?
-			pte_offset_kernel(pmd, addr) :
-			pte_offset_map_lock(mm, pmd, addr, &ptl);
+		if (create)
+			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
+		else
+			pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
 		if (!pte)
-			return -EINVAL;
+			return err;
+		mapped_pte = pte;
 	}
 
+	err = 0;
 	arch_enter_lazy_mmu_mode();
 
 	if (fn) {
@@ -2944,12 +2948,14 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 			}
 		} while (addr += PAGE_SIZE, addr != end);
 	}
-	*mask |= PGTBL_PTE_MODIFIED;
 
 	arch_leave_lazy_mmu_mode();
 
 	if (mm != &init_mm)
 		pte_unmap_unlock(mapped_pte, ptl);
+
+	*mask |= PGTBL_PTE_MODIFIED;
+
 	return err;
 }
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/93102722541b1daf541fce9fb316a1a2614d8c86.1744037648.git.agordeev%40linux.ibm.com.
