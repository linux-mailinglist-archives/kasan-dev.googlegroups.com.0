Return-Path: <kasan-dev+bncBCVZXJXP4MDBBGHZ6LAAMGQEQE6MXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 36884AAFCA0
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 16:15:55 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-22e544a4c83sf18233205ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 07:15:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746713753; cv=pass;
        d=google.com; s=arc-20240605;
        b=fa3tdXyyINbgvTBhn5fEM4mw1Zd0TmxNGxeuvj5Z8tZjgQpcqhNggk1+tPRS9edAFc
         8ANuW50p1qR3YM3bFxYHnqDVdOzdTURFHCtqHrNNfherqmc5QeSupjmkEgUbjimhYxuW
         skRuJKXuNg7wJzrgyVa8SoktAyt+EpCXrjQM2dD7miwgacsVithT3jlPINx3gEV8AkPZ
         G2qMQtRV81jUA0up9gCXj23yYTIuABnQZgcCxnJwGZ9HNlxMyeO3kM/f/ZFa5baO+/fo
         zRpEaEHG5RIIe/MvhfYVDh9gfqyC9rChUbfJ7syGFisoCUqfzJlb8Xs1FppPxq0gkyAl
         Ssjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bD4zvQDVjbS4849PlofQBpofeWH35PcpRMGfTHPJXxY=;
        fh=CNEi2LuFUrkJVqBPaYuV03JGse/6n+cyg7a7N/scTLE=;
        b=c/xzMDViu04HYjAimCuP63snvB3fC+nPs9YPC5KQwRlu6HpGQBsnVGxrsR93g8xmCP
         9wlNcqo+IxiRy5ln+rESuX5XIG2/dxHFiUYDh9q20isUskb0BzrfT2AXHZ3ENcw0/elP
         tuIN7xB9igO0ADc04KRJcRqlP4DfGTZlxDdNutA+AOAcOCWlGNbIMC590xx1fKMSAUmL
         rlpOGeEgLlcFYlrn5B3i3MwaXMj3KafSB0dfczL7N7S0kA5g7g9QifJKo1pAmUlZ7CjL
         qB6UJwZGov4M6jLQjds31mrNPmoRvERNkmlsob9O5/+GAeQtY38pFe9UImntCDCNm8+9
         b/Vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cagboBnB;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746713753; x=1747318553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bD4zvQDVjbS4849PlofQBpofeWH35PcpRMGfTHPJXxY=;
        b=Gl7dC7lIJzgtOvSVb3JVXuzLD3kBy3YN2AHqkFZR+9Hx0F3aKtO7KOO35EpziLIzYb
         kzzYbhRRdJZmBDZ7eFVTKyP/JHNXm14+jnpOxGp9qpVUjnzD4oNyHbpUcQpa4Ys7MtX+
         BzG69SD4sY//Gzj0sL5/vl5OiCZmbqY2lF1KH6yO5SuZ9wCYQvtFW5nlWzw1obAsRPCP
         2uGMNJOqea5gk37+d10c80eypZiU1QSxNuRbMBRTnjFZnK4l1YKfSjQee0xFeCIPsF36
         oc4UV4AOag+7EuH0r5KkD/kabIHJPwJOhFmUeaywM2hQhNUiD3XoLgB4MVAkKs5Max6u
         qvkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746713753; x=1747318553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bD4zvQDVjbS4849PlofQBpofeWH35PcpRMGfTHPJXxY=;
        b=SlVqoul5G8lN39mY9llLmrdBt9IqcBvwc1RUJtvq09ZdxTyM+uDeQJvZHOZGEkjNob
         UqBt6/geEunkAiXPluCCKIaYrnp1QT3CNqA2En1DQZ/aEBg9IZBMiQ9+TcXm4IAaXhNX
         iIiW7V126TXOdtu0TLGCnA2eQZ55qi5nv8UyvpEtPW7BRjDRGj14tMNJmxBKXZwk0jbg
         AXYYacqJhetqc7TvUtC3HQ35VhFMAahWOhpMAi7k8tcjKxnesgjTwClROH4PvIUHpIyO
         ztN00V//qd6VXTMD1VesTgdrSD8rPr9dAY46o6xG6N09NUhwEEtGExwoymo7jSH79Xoo
         2eeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUa0XZtRkoatW5fIsh0lCA61ND/G40JIjFVrX3ud2RdAU2CXqNtMaEvNU0S0R4x4cU3kdiSeA==@lfdr.de
X-Gm-Message-State: AOJu0YwgdV5WvErcf6nBQ7ehU98RThOFJfbuDlV4MZVkOqvEHTZ/DoJf
	8ekJ67TlQfb/GvZGRzXIeRu4H9tjJ6+emsaaVEaNKV7+DfXiWxLL
X-Google-Smtp-Source: AGHT+IFMs/goXrx9r2T5KxCNfJpWzYqEJqpLKAMlAgOiWrXppb+/2fwsG2pJ4vT5WkCNqOv44U/1KA==
X-Received: by 2002:a17:903:194e:b0:216:4676:dfb5 with SMTP id d9443c01a7336-22e8476ee2dmr52168245ad.21.1746713753211;
        Thu, 08 May 2025 07:15:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHdqaO3UoaXCGDopRmkiu8jBLdImhv14YQf0RrNUJQPZg==
Received: by 2002:a17:902:ea94:b0:223:ffd3:d813 with SMTP id
 d9443c01a7336-22e847c5d2dls5536875ad.1.-pod-prod-00-us; Thu, 08 May 2025
 07:15:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeqmNmkrFDNwrfurFq8nuUSyrXem4nPU1Z61qDm+usZvk7WzaYjQl3LmbcZAgFEgVTv05X08+gXeY=@googlegroups.com
X-Received: by 2002:a17:902:e54e:b0:223:517a:d4ed with SMTP id d9443c01a7336-22e847110e3mr45752465ad.15.1746713751758;
        Thu, 08 May 2025 07:15:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746713751; cv=none;
        d=google.com; s=arc-20240605;
        b=fJxeDxeD7yc6YBewaHrIgNWht/45o6C8YFmovUEWVrJwm+KyrOl39bC3FBCi5QtPWl
         Zf15aOUj2hQxRDXrMpBQ96ak0u7PmV7b6qZfBOETLVcrfjkcXdftxRUp2FgJ+l0TvQLS
         pIcEjHM68g5zDzN+t69NM5oIErYAaPcVSJvGv6dAMrvgJmIqEvYKC5PE36u3fbKxu2Xz
         If9TGjdSBGcXERrXOtmf4wkLGEzhNxgk17s3Ez+fkcbywct7PuOKirrxgVniSPY2GuiL
         Cg/v9q192uCxW0gUjo9rpdTXoAUH3g1LeFZQJ+gte2SoI6bXnWyH2QvtLkHV0SxGXaT4
         RBZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cKWqTwdZqcmbuUiqx2qKNdy+IGuUWkUCb/XtMBsVClk=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=VvfrVDipLZhdYRE86s11G11W9tbcPPl38R7uIn6PV3FA67/t+v8Bzm1xtNHlu9MYa1
         05nExN+yJk0KnBx/6slZ7SZCYfad/ZTxKz9rntP5LCHZR9QLsRHQVHcV6NMu7Omvavnr
         qYootqNBQl6hvx+L2V4dcd8IK61U3rSod5TpIjL7hW5idZy9efgkGLCiOFylm6rrJeHb
         VfUXtR6EkQQo3TZwTip8JThdqq6FLpu2inEvikwGkl32HxvLWwqLw/S7PtsR8srIyXjj
         4B4KKyfnStbClnAVTL7EkixryRQN9ctQWhvVO8le/BU4T09TERGvZlEODDDoIOfVTbgG
         NT0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cagboBnB;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22e1520b7e3si484375ad.6.2025.05.08.07.15.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 May 2025 07:15:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 548Aemc2011721;
	Thu, 8 May 2025 14:15:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46gu2t11ap-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:50 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 548E1HaA002523;
	Thu, 8 May 2025 14:15:49 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46gu2t11am-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:49 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 548DbWpe026038;
	Thu, 8 May 2025 14:15:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46dwv069g8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:48 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 548EFkqA51970316
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 8 May 2025 14:15:46 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A4FD620049;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8B01D20040;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 3EB75E0DE3; Thu, 08 May 2025 16:15:46 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v6 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Thu,  8 May 2025 16:15:46 +0200
Message-ID: <aabaf2968c3ca442f9b696860e026da05081e0f6.1746713482.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1746713482.git.agordeev@linux.ibm.com>
References: <cover.1746713482.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=NLnV+16g c=1 sm=1 tr=0 ts=681cbc96 cx=c_pps a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=JPUNfvWgwyJmovPnq6kA:9
X-Proofpoint-ORIG-GUID: akX5fdkiTiZCx1fMIpNteeBvuqJGff0m
X-Proofpoint-GUID: f9f6f2OzB1FHDvS_jXduA2GZbmjShWYE
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA4MDEyMCBTYWx0ZWRfXz4TzQbDmsitn gudJTYSiFFa5UlGKcF/BrrrINfVdZJpgLbPKMUxjK5lsKIbJhhEowjLxv0W3RpIUetn67eKd6HF vhYdvIhHkpCJlTJZtoTx3L2p4p27ve4hdr/MjD8yu0e+963LamfYBNGkW1q1IYLX4WM7wEGDL1s
 ocjzse0vNdXYFURagkl4XRCIhs9kkgCMvAf9MZIA8X4NMBmsT0mB4D2LKl4ddlfp6z6xqdnQyj2 D85KP/DvUJu5H8Azp10aOKlOj/F+VtgsUe+v38eQcg5/U3s1/Lr682U4OqnW0s73x6veOnO6eCQ exbvqEyFhIkouxFkFbo1FRBGx8+SO0rYQCSYC3KpI6Dj+Lmun4/KuQMZJzyt+RmJ9hlrtxzhz4Q
 PLTvWabsvTPArkIrMWlHWndyuT01xx9YRfK53W7hJhrCXNgWbLxJ3pZc+KTS+vlMSLk3n0ND
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-08_05,2025-05-07_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 suspectscore=0
 mlxlogscore=552 phishscore=0 mlxscore=0 impostorscore=0 clxscore=1015
 lowpriorityscore=0 spamscore=0 malwarescore=0 priorityscore=1501
 adultscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505080120
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cagboBnB;       spf=pass (google.com:
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

apply_to_pte_range() enters the lazy MMU mode and then invokes
kasan_populate_vmalloc_pte() callback on each page table walk
iteration. However, the callback can go into sleep when trying
to allocate a single page, e.g. if an architecutre disables
preemption on lazy MMU mode enter.

On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
occurs:

[    0.663336] BUG: sleeping function called from invalid context at ./include/linux/sched/mm.h:321
[    0.663348] in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2, name: kthreadd
[    0.663358] preempt_count: 1, expected: 0
[    0.663366] RCU nest depth: 0, expected: 0
[    0.663375] no locks held by kthreadd/2.
[    0.663383] Preemption disabled at:
[    0.663386] [<0002f3284cbb4eda>] apply_to_pte_range+0xfa/0x4a0
[    0.663405] CPU: 0 UID: 0 PID: 2 Comm: kthreadd Not tainted 6.15.0-rc5-gcc-kasan-00043-gd76bb1ebb558-dirty #162 PREEMPT
[    0.663408] Hardware name: IBM 3931 A01 701 (KVM/Linux)
[    0.663409] Call Trace:
[    0.663410]  [<0002f3284c385f58>] dump_stack_lvl+0xe8/0x140
[    0.663413]  [<0002f3284c507b9e>] __might_resched+0x66e/0x700
[    0.663415]  [<0002f3284cc4f6c0>] __alloc_frozen_pages_noprof+0x370/0x4b0
[    0.663419]  [<0002f3284ccc73c0>] alloc_pages_mpol+0x1a0/0x4a0
[    0.663421]  [<0002f3284ccc8518>] alloc_frozen_pages_noprof+0x88/0xc0
[    0.663424]  [<0002f3284ccc8572>] alloc_pages_noprof+0x22/0x120
[    0.663427]  [<0002f3284cc341ac>] get_free_pages_noprof+0x2c/0xc0
[    0.663429]  [<0002f3284cceba70>] kasan_populate_vmalloc_pte+0x50/0x120
[    0.663433]  [<0002f3284cbb4ef8>] apply_to_pte_range+0x118/0x4a0
[    0.663435]  [<0002f3284cbc7c14>] apply_to_pmd_range+0x194/0x3e0
[    0.663437]  [<0002f3284cbc99be>] __apply_to_page_range+0x2fe/0x7a0
[    0.663440]  [<0002f3284cbc9e88>] apply_to_page_range+0x28/0x40
[    0.663442]  [<0002f3284ccebf12>] kasan_populate_vmalloc+0x82/0xa0
[    0.663445]  [<0002f3284cc1578c>] alloc_vmap_area+0x34c/0xc10
[    0.663448]  [<0002f3284cc1c2a6>] __get_vm_area_node+0x186/0x2a0
[    0.663451]  [<0002f3284cc1e696>] __vmalloc_node_range_noprof+0x116/0x310
[    0.663454]  [<0002f3284cc1d950>] __vmalloc_node_noprof+0xd0/0x110
[    0.663457]  [<0002f3284c454b88>] alloc_thread_stack_node+0xf8/0x330
[    0.663460]  [<0002f3284c458d56>] dup_task_struct+0x66/0x4d0
[    0.663463]  [<0002f3284c45be90>] copy_process+0x280/0x4b90
[    0.663465]  [<0002f3284c460940>] kernel_clone+0xd0/0x4b0
[    0.663467]  [<0002f3284c46115e>] kernel_thread+0xbe/0xe0
[    0.663469]  [<0002f3284c4e440e>] kthreadd+0x50e/0x7f0
[    0.663472]  [<0002f3284c38c04a>] __ret_from_fork+0x8a/0xf0
[    0.663475]  [<0002f3284ed57ff2>] ret_from_fork+0xa/0x38

Instead of allocating single pages per-PTE, bulk-allocate the
shadow memory prior to applying kasan_populate_vmalloc_pte()
callback on a page range.

Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: stable@vger.kernel.org
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 63 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..660cc2148575 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,30 +292,81 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
 {
 }
 
+struct vmalloc_populate_data {
+	unsigned long start;
+	struct page **pages;
+};
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-				      void *unused)
+				      void *_data)
 {
-	unsigned long page;
+	struct vmalloc_populate_data *data = _data;
+	struct page *page;
 	pte_t pte;
+	int index;
 
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
-	if (!page)
-		return -ENOMEM;
-
-	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
-	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+	index = PFN_DOWN(addr - data->start);
+	page = data->pages[index];
+	__memset(page_to_virt(page), KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(page_to_pfn(page), PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
 	if (likely(pte_none(ptep_get(ptep)))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
-		page = 0;
+		data->pages[index] = NULL;
 	}
 	spin_unlock(&init_mm.page_table_lock);
-	if (page)
-		free_page(page);
+
+	return 0;
+}
+
+static inline void free_pages_bulk(struct page **pages, int nr_pages)
+{
+	int i;
+
+	for (i = 0; i < nr_pages; i++) {
+		if (pages[i]) {
+			__free_pages(pages[i], 0);
+			pages[i] = NULL;
+		}
+	}
+}
+
+static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+{
+	unsigned long nr_populated, nr_pages, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL | __GFP_ZERO);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages);
+		if (nr_populated != nr_pages) {
+			free_pages_bulk(data.pages, nr_populated);
+			free_page((unsigned long)data.pages);
+			return -ENOMEM;
+		}
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
+		free_pages_bulk(data.pages, nr_pages);
+		if (ret)
+			return ret;
+
+		start += nr_pages * PAGE_SIZE;
+		nr_total -= nr_pages;
+	}
+
+	free_page((unsigned long)data.pages);
+
 	return 0;
 }
 
@@ -348,9 +399,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
 	shadow_end = PAGE_ALIGN(shadow_end);
 
-	ret = apply_to_page_range(&init_mm, shadow_start,
-				  shadow_end - shadow_start,
-				  kasan_populate_vmalloc_pte, NULL);
+	ret = __kasan_populate_vmalloc(shadow_start, shadow_end);
 	if (ret)
 		return ret;
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aabaf2968c3ca442f9b696860e026da05081e0f6.1746713482.git.agordeev%40linux.ibm.com.
