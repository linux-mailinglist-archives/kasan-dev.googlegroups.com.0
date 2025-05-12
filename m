Return-Path: <kasan-dev+bncBCVZXJXP4MDBBP4KRDAQMGQEY73KWGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 81BF8AB3A88
	for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 16:27:13 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4768f9fea35sf112515021cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 07:27:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747060032; cv=pass;
        d=google.com; s=arc-20240605;
        b=XCggJ09AThbPws9gx1UIbBOVYVp/TkW24ho1Xx8u9XDb0SoX8bPOvE56jWeblugZdz
         rM5aH+m5LdZb0UzLsXsVorJsvfAFNL5eZuIXz98dXKgAWKJ3ZdSrsO/GFRKoGCImBjJy
         EQAKOvHQpdPtYjLoAnM1GIxah13uIg5mJvURDDPRiTuvyvU/GRnSVhDF8f6ZX1oPai5P
         vIqK21yOvz+i/l68lvmFGFyHlt2RPc9Tm6V8OuY+PVvua/3Ea80UJmNqF6yCoX2IUQuJ
         +wk+sx2MtfmvVGJTrYi71+6s4G1RVYWyYYrGAHL/meN3tN/bXp37YCfu/cb/oke8kJdJ
         VF9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D0W/L9nxHbaF+y/F3giCzTPrs24CbAlJbY2UG2koumg=;
        fh=Lxze2CbdX/NCnOtdeCANbyJmcBVYkCoSZXeeylTsuhc=;
        b=YWf2X3L9wzoODyWpSN3/sSQ8b3m9WL4Htd/jP77P+88p5Ho3f6nt0TzsfFZa6BPyLT
         SmIXyrc4xallH3k4QKDV/jvnSOfDZxGTgHQcYHzqsbWPqSDhVfBOXh1/xX1AIs7QYrC6
         aQOworI2N+ePKVk3i/Pus12NKp/51d2zpa9inVBTItY6vUvze0jQfMCidlgjM35UPqxH
         vDb5aXjFn4vKGF49p1QpCtYrk4rL1oZ6YzDN4N8gSA3tQ+1RGtlAiMWjHG+LtibmmySh
         StwAbaaxoY0fs8KI6nQ+o5WnDpkvceLjQKsl2UBWYm1C00GLiBX4wqi+Nh8H/4xCUeQz
         e4Dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ixebav21;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747060032; x=1747664832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D0W/L9nxHbaF+y/F3giCzTPrs24CbAlJbY2UG2koumg=;
        b=hN6SvXuCilzWRBUyrI+9oAN69tskiTMq1ZZ4OXLSNWNOr15O3T1T5H9Qs/fzesdkQM
         Adc46LOeN5oy9JA/vbZsGAJ3aqSs/DEKiBfkMQyMH+b/96639PLkOZonZB5+Iov+yz+I
         JtBnQ1dSAdiit7GzseBQxMy7wdS5xUkHbmXTfgqCC1YC+MAv2cI1//kxtG9lG4Ie/xmf
         UfKlII6HztMqxflWjl+kYUmPBzex+4U+EdgHAULrvjvIufKvQ3mqXY4FlrnIJZtMbYYi
         q1JnzR+0pwtyCjyLM+lj/FgpR5Qb1nm7ogs9Ptaj7WV7T6GQ+whAHfVNAcxH6EPHvxE3
         3x/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747060032; x=1747664832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D0W/L9nxHbaF+y/F3giCzTPrs24CbAlJbY2UG2koumg=;
        b=Ly2NzPXm/ALNw9I8K3WBaikDQNpPXtexnoJ8O+GLd47Mhk0gpoeiWnoA09QUUaf3MI
         tbOk4eEcTvkuXrxvHT1LRuGnQ/SNHZ80fOSMg+1Y3/iucyHbTfo4s9nVak1r/GdidJXA
         ltCwn2MfjhqHORc9JlJp0HFfWX3PnaeNLOnORMj50XHKvfi3x5Ij5whsE+TExPtvDqdr
         gVAAmoTR59cpSw2rOKkm01Z8rEwATWdev83EtPE6nOhzU1Yl6iJJT0yww4s9COXtC1iT
         g2+CI9EkVYIICS/A6ti3/3CW2hk/YsMypDXkauJjlWBPq1zBrci1DZkdXV5nqMZJko7x
         xSog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPWc+KISOFRLPJg2J6eGz+bhIbr1lk4iXBbfTshqmn52+4VNcOHZzSlo7rZwYuEgBNXaRyvA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1IdY4w10s3OHQBruOs7v14warIkpQxVe9UZzx6KCnA0tiBixg
	wlUyBCsBr5uLxgV6rCO+8pi5zLnyyEpkrVXSmssjIJhIaLzJMZkp
X-Google-Smtp-Source: AGHT+IGjRgfEVR5CJGiLugA/iFUdtIeUTGmzjdeqxmgK5XyaOuTMHNyiV0KdDHF4BUm1E7qW45rvUA==
X-Received: by 2002:a05:622a:30d:b0:476:6b20:2cef with SMTP id d75a77b69052e-494527b841fmr207623481cf.41.1747060031736;
        Mon, 12 May 2025 07:27:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEo/7bnGlPlTuTdXNUrtMKwLMBoLIaqOffi19WaED56fA==
Received: by 2002:a05:6214:11ac:b0:6f5:457:9fd6 with SMTP id
 6a1803df08f44-6f54b288827ls74696126d6.0.-pod-prod-06-us; Mon, 12 May 2025
 07:27:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmwACiRO2eD2QNl2Iw3BgvvM5UKUuuBrNgwzqIXOZEQhMPEHfg7RohZnG+4/zfZrOVZjchDK4+kbg=@googlegroups.com
X-Received: by 2002:a05:6122:1da4:b0:529:be0:8353 with SMTP id 71dfb90a1353d-52c53ae2d85mr11004411e0c.2.1747060030945;
        Mon, 12 May 2025 07:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747060030; cv=none;
        d=google.com; s=arc-20240605;
        b=fiahqatvHbkvQgeP0GMLyo1zBSFDEXTCT8f2quvBbA3mzk3QZLperSMdN89NrAtk5Z
         OcFavqcTdv5kfqeTRjcw91pVVPaMsmWMhmkQ0Q+JfBWkrAO65dD/cnJWUOaz+nc+v2Gm
         sOwYE16Gw3dlLKUg1i6TldWLzQwsPYC3AU4vAAy8FIa7dtHpkF4ZUewc74mynRcpTeFL
         KaIxm7jqQPom/YhPJXlCCah8qr06muVy356adTOm77mBQWfI65Snx8AL6Ih2iOn48LP7
         FVP99bp6/KOpQxPBn98Bb0ydkUhmANyZvMDD8SJfXyNBwOD7JBSuU1syvDT4bVKoPtaK
         gEvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=obqfSkpMOObPNfAmbcCdBrwfFhHfGF47J/vDFVsSbKo=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=flQUvL0hH2jiuhx2cpVvlKrQxax6K2iE2KG+cezlR0mLge+c7IybpTxZ8ObiC3Q0+J
         FlsjLccoYtic2ofKBAO+l9B/NH0XjpdnoO2T3QRrj6cgedop9MbUAPdAbaIfRtp1uhp6
         R0C4KRoqETvj6iZplC8Nc55+WBEBzSNFn03lb+7sHASP2m7YQPkES4auNaLat1UcloAV
         R6vbpIOPOENSr8yI4+zTBbAxuu+joRX+EABqIPCOHoFyl3opGT1PLONwRF0+Jr2fdRDv
         c5fAgpTP/PdxGMKFE+xmRcQTatluLo3g7TL3Re0XhN+lXRMUDtHjAjzCHmwHILqeDEJm
         E1XQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ixebav21;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52c538af75esi355489e0c.5.2025.05.12.07.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 May 2025 07:27:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54CDnGAh001320;
	Mon, 12 May 2025 14:27:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kj7586tu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:09 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54CDr7nP009240;
	Mon, 12 May 2025 14:27:09 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46kj7586tq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:09 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54CDnf0A024427;
	Mon, 12 May 2025 14:27:08 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46jjmkx86u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 12 May 2025 14:27:08 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54CER6kk16122338
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 12 May 2025 14:27:06 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AD02B200B2;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 95D89200B1;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 12 May 2025 14:27:06 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 5609AE082E; Mon, 12 May 2025 16:27:06 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v7 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Mon, 12 May 2025 16:27:06 +0200
Message-ID: <c8eeeb146382bcadabce5b5dcf92e6176ba4fb04.1747059374.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1747059374.git.agordeev@linux.ibm.com>
References: <cover.1747059374.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEyMDE0NyBTYWx0ZWRfXyrKTwmPOo51Q jVXO+9c9AFtiSIehzQILyRPcDoF7/jMwNC+K+uET/QC1k2DQVEPJfKbBLuM/O3AK1sCyLhjrfuk JxsOwu6xyrSbuEzK2EwsLm2ST/z96qkHW3cObGPVJP2IQfuQQwNel1dzpPsNMWr8SESRCG0BPuq
 AjvFAd2XiMWNUXzCqifQqd4IFj6G7BniClODoyK8ZbsLpNLuaqnv8gW13U9dFzNFKayDaSeG110 kopKU3VxcWK0j34GIxOZXoMbYwqTM/CyFtLeMsLLyG2ofJjLlSih2yqB5F1kOuyxk3QyARtJoVf HPJDUDbZh2wIn+18p8DLNXIXnv07ke8DJfEHIf07plB95qTdbnEc0gMhPB9M3ylO6hizzGfZs9C
 T6G2jL9sKof1stQD7t1sgOys57//9vdK2d/gwcJRoPbEKEc70vwwiLeiH5g4103mFnvKjopc
X-Authority-Analysis: v=2.4 cv=J4mq7BnS c=1 sm=1 tr=0 ts=6822053d cx=c_pps a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=JPUNfvWgwyJmovPnq6kA:9
X-Proofpoint-ORIG-GUID: yf51ftufHbYNS3T2DJKZmgaP-CK1UybW
X-Proofpoint-GUID: PFKdY_lkspTBDtCs5rvxBcsotItLtA39
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-12_04,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 adultscore=0
 lowpriorityscore=0 bulkscore=0 mlxlogscore=608 priorityscore=1501
 mlxscore=0 impostorscore=0 malwarescore=0 phishscore=0 clxscore=1015
 spamscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505120147
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ixebav21;       spf=pass (google.com:
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
 mm/kasan/shadow.c | 76 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 62 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..2bf00bf7e545 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,33 +292,83 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
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
 	return 0;
 }
 
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
+	unsigned long nr_pages, nr_populated = 0, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret = 0;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL | __GFP_ZERO);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages);
+		if (nr_populated != nr_pages) {
+			ret = -ENOMEM;
+			break;
+		}
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
+		if (ret)
+			break;
+
+		start += nr_pages * PAGE_SIZE;
+		nr_total -= nr_pages;
+	}
+
+	free_pages_bulk(data.pages, nr_populated);
+	free_page((unsigned long)data.pages);
+
+	return ret;
+}
+
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
@@ -348,9 +398,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c8eeeb146382bcadabce5b5dcf92e6176ba4fb04.1747059374.git.agordeev%40linux.ibm.com.
