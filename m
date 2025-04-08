Return-Path: <kasan-dev+bncBCVZXJXP4MDBBSUT2W7QMGQEZV2RU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F9BA81169
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Apr 2025 18:07:41 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-476a44cec4csf100318221cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Apr 2025 09:07:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744128460; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ihzj3sh/KX/5UeFl2aK+85ST7StKGLk/03qw1qi/11BJ6HeQXFJAgdLC0Be3jNl8bN
         CKElRZcwWv5OjjrXviDHAYF8DF4yeoPU+ieTk81/RB0E3QAN+ESzs+wYLVf+H+qxO6PD
         UEE8DfbYaM4kIzawHjtKyuh5K/fKmoS9UmnqxzLFBzOTm38tQZQAATGZATUIexilGB6z
         2N3g2Wx1iDPxCToqQwDpDjbo6Gbwk+rTRIDVnHTIzwHAQPKSX3w0Ry+1b66atPCBz+xu
         OSFbLQcC2b/hIyPRqWJfcBlYRyUgl76hLjRNDfweSvfKIoxrZ6xd+RAjTfnEULbvQ8c9
         X9CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KSRU/fD7FISnVNSz8xFdpNRASWilzC+YPBviyYtBX6k=;
        fh=BctmRCJHB886l3JlWKRVaDHJvsztafMMhRC7H+wnPU4=;
        b=fVHDrNSTG7vCuoQTGDSZPHJv5Bm+9vNw86F3IWCqQ+pjEhAKvxJ9BdlsRUvMDTztV8
         O+GTe/ucB4EuJf6NOVW31u/fEM8wm7BgBQCZU7YZDBQweh8m2MqYIdOHqbaoGviC3Vqv
         VgdL/iMfjhRiWIhPsRO4s8lysdO5ahIasuDUu3BfVZuqsipmPZlWxmv/XF+D9gnuq/a3
         GiQsHvVA8nVWR4oxYrfpay/MB3g1+hGnuLDp44V1ZP//Z1GPNk4Vt3tDkH++xXBahbxm
         ry4nU4H5mMPbPtEXzdNaTHWchbYOUXm5wQUzcD6tl527KeypdvxDOFk22VFNG7enXtAR
         jUBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tObfqwbc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744128460; x=1744733260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KSRU/fD7FISnVNSz8xFdpNRASWilzC+YPBviyYtBX6k=;
        b=iEUq7ubLYMSKKGptGON9AA+kex5XfTlMh52EHCBMlmCx2XF6ngDZonjMBcPe0qiREd
         rsjcHi7GBTfPrKEDiaJE8bw+JgVHko1h/2XTAenGHqJSCLN4ch8ixdqLFGAkCMV4M3GX
         yVMTzl1NgbdHr9ZekHBG5FiIVSE2OyY26kyGiPS6jQ9eWb5RawHw2MSTVZJEcAR6JGMK
         QDAhcHjUKNmu6HwunNDfOmCLPnpxF3mm7vH7shvXBz1+QYNGdbkTvizNMy7YA2ij0ivx
         rXZrcpVx7aoTkaNy+0OU43nxEuNvIUdrAmkvtE76U3Sc96AJ8357HcFx2J53vy6TZqCP
         YKig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744128460; x=1744733260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KSRU/fD7FISnVNSz8xFdpNRASWilzC+YPBviyYtBX6k=;
        b=QGqyZSEJR8nXxW9/ZuyEYAW9N/r3U5x22VrF9q60e6t/YS39uaAriDSbJkaDWO6uDt
         mc9p7w1GJB99hYCpzcb8Ndv0xdco9AK8IGuHWAkDa7XuqDaJxFflFFEspqg9kaxCT6VP
         khwH5PcblzdbX/yrWBd+TqIoGd78+yBa5+D2i4vLLy+ppZi1oeLv7T221ipm/AqH+ncB
         hQU945eh2X5sY5oFMmv5+fyn7oXLmvtTX8DLPAbhMEakfztnzvCMEM09VHRdq4jeVOW6
         fKmrAqAhSDequpwtBrB0viR0pGRFuCMyjrxSEi1A12riy6GqtyNBLyQkF4Ie0974tkGJ
         E6hw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtwGMOPOuVzHz5LEi0yZLMQl/fCpOfv+C8YV/WWOHOCkNpT8LFXNGDXC3y26gP5qrGRc3WHA==@lfdr.de
X-Gm-Message-State: AOJu0YzmyGWFgcYHxEvl+4inCME+6S2P4RcXhYzLloV34V4+xriq/5By
	tQX5kPFY8I1IlHAcMRBu536Qyrj11+mlvnTBA1B799uB3Q7ks1qM
X-Google-Smtp-Source: AGHT+IHG9Cev7Qz9OrKzhdnYRJyt3oNCuNugJoe6bfxE7up9MgG/Y02jt4tsNINpVvtMIl3nn/CucA==
X-Received: by 2002:a05:622a:1916:b0:477:6ee2:18cd with SMTP id d75a77b69052e-47930f6f90cmr225298411cf.5.1744128458699;
        Tue, 08 Apr 2025 09:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKWq5qt+Ce5wVnCCAACmO27KP3pxfjbCDObFlfVDbXrDA==
Received: by 2002:a05:622a:68c3:b0:476:7e35:1ce7 with SMTP id
 d75a77b69052e-4791615a0a9ls4072091cf.0.-pod-prod-03-us; Tue, 08 Apr 2025
 09:07:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCVRQC15empEZvURpxEc1oTQfyEmWPBFzoi7Kfz9rWJDdT3Q8iAjOKELytbRWZJKBKaz490HNCLUU=@googlegroups.com
X-Received: by 2002:ac8:5ad6:0:b0:476:9b40:c2cf with SMTP id d75a77b69052e-479311140ffmr238664681cf.50.1744128457781;
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744128457; cv=none;
        d=google.com; s=arc-20240605;
        b=gGYXa71fKYNbzdAbX33NaZNYaXgsfj3PgDSjWmV5jLJv8GslyQ5b7r6llcD8roKPlu
         RCyzTZ5trX5Jn5lnjSrey9JBtvYExMy+O2mOZyyj1AHRUCpTNo4lBvr/cOCC95aqH8AY
         pXPXUtmk39Z4UWLfZ7aE1biz9nT6wjrSNR1vQcAX1agO2elqQlpPFS0pAkYt1t5m170G
         cjQDfMlOFPJ22dB1phaXklkhSTe6G8cti/vU+UpeR0eNGasoEbTR8y87RANtNHJFyMOV
         otT1l6zaBOfTS/zSnCld3l5Ij7G2w9fibLTUzRdvz4XDZn8JGzoYe9inex2sT+N67HsF
         yQhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xkRr3rYpnf+evzsRvKXtHeEA6KSnGBV46B7GpE1ybMc=;
        fh=Qpv0vZFsOkAl7OpmVhwpUC70zZ+oFSiffx6v4uyFrtA=;
        b=c+lbz7WyjOXYhOfzhHnYsq1hxx2aYpYAzKQXRHkUoOJT2C1nGN9qMDAkz9drEnNahi
         5h3cxeWoJF2px/mp3pZY0HI+QNDpUlD/iyv7HDqq0VI/ZTUhXn3PEi/c7iN1QOV6g+U+
         VEAO2eHwmLOgclmzebojNXtfayGOtF98g2nMSOBzwqklbHRUvNROG9Plfz72I4/J9BlP
         fqo/MVhYHzRqTiny1t04xp9LdCoOfUgjd04F7MwQF68JCTqILLtrnMPk6XyFXdTu4Mxw
         xOm4vtvGiNFY4K02B+TEfi+mchCuiKzCFMLBrWoOx8ooSh9cq3/XdRuxHYyP6pw26RnV
         PYNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tObfqwbc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4791b0537b6si5292231cf.1.2025.04.08.09.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 538DNidV028259;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vv6a3cmj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:36 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 538G3Tpb014440;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vv6a3cme-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:35 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 538CRs5W013915;
	Tue, 8 Apr 2025 16:07:34 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45ufunkd23-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:34 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 538G7WVI31982208
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Apr 2025 16:07:32 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AA33A2004B;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 94D4920040;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 4E5B9E171E; Tue, 08 Apr 2025 18:07:32 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v2 2/3] mm: Cleanup apply_to_pte_range() routine
Date: Tue,  8 Apr 2025 18:07:31 +0200
Message-ID: <0c65bc334f17ff1d7d92d31c69d7065769bbce4e.1744128123.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744128123.git.agordeev@linux.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: T7M0AXWlw4FgItjk33f-GC1E93-9rXMH
X-Proofpoint-GUID: 9N-c1pIo8G5i8QLTXcZGYOAiygpOCwa1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-08_06,2025-04-08_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 phishscore=0
 lowpriorityscore=0 spamscore=0 priorityscore=1501 adultscore=0
 clxscore=1015 suspectscore=0 bulkscore=0 mlxlogscore=909 mlxscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504080110
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=tObfqwbc;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
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
This is a prerequisite for fixing missing kernel page
tables lock.

Cc: stable@vger.kernel.org
Fixes: 38e0edb15bd0 ("mm/apply_to_range: call pte function with lazy updates")
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0c65bc334f17ff1d7d92d31c69d7065769bbce4e.1744128123.git.agordeev%40linux.ibm.com.
