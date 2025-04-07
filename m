Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKGWZ67QMGQEP7A3ADI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 558B3A7E380
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 17:11:39 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff581215f7sf3663723a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 08:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744038697; cv=pass;
        d=google.com; s=arc-20240605;
        b=eW97Sw4lbFn5L/+J3bCqCS6F0HyhptZXBO46YyogFs8JoI9HtlX4GqYeKhkme6OVFt
         o5Jvs3JdRFSrxMIRoOOk0Q9GAksKluvhvk/TM6S3gMZN8tQ5xwdm4eayis51t9WSYe2z
         O5eGDCl9YbKS3/e9sUXdROpeU+YJiM6SGXvDB2hXPlMPu9kE/YRFZ8YUxP6JgH8flP91
         RhW7iza5uzHBRmSE0pUMYEHgKwWIy6wK+mCOSadzN0SCeovPOcwpz2AxdXc9ag5qZJ2+
         spJRqnybcASeE2cAfHx9xKv9NUzoa2cKcOohaoCXtze2Zd8qoo5d2cxS8HUCw4d6u3xs
         Nztg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TPtW0V7Am29hUz3q3M9OQ49LNpIv6y4YhxIOyX5WzRU=;
        fh=nv2ZDfje62QN1Fha1LSGUNdBi6RUThM2T/2VP2gz9NE=;
        b=ZqYYEIgciGWycfs+dyN2xvaMbyYn8u4yJQGTASk+W7EN5t2e6H35ydmEPAWZNoAtL5
         IqBrLu8j5ttmm6q61MF2T5cGjJXA3DB+hwhx8FkiUnl5zROYwYCF7dOpni8uDNQQSlz/
         KE3ImkPOGOWx4V9qT+Cv0t8S6fxxL+SMPhMnTqobrB5q2NI4HyM1HJNOo0++cUzXi/gA
         l9d9IiT7X4p0XHZ9uV/g2VWRwhWAYFkSBlEFaVTQA9hAhBp+x2cyD5I3hcqqm8icWR+c
         gCoFp45eFt41ylOTSD6WeUEIIjeWoKDdfDwyX4+44WMRFm0OiSIFlzAVhA/FscNSgMzQ
         FgDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="iGIlK/ui";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744038697; x=1744643497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TPtW0V7Am29hUz3q3M9OQ49LNpIv6y4YhxIOyX5WzRU=;
        b=wq+0dnfhQ8qtjOJsboRj2jrzErlr0zMSr7L52A0Q0EOMprYcCncx4C14/3oFlS2ket
         LkozfjxqLW65iVrGbcuNY8117zRKHNbxbyepJ1D72smBMSh4A8gLepFT9hTnn6Vuomyr
         xcT5qQB4iqN0GeMc3mQuQeeu5wpZBQ/RKcGRHmvj5hDU8ljbS72q1d9ymt1Q3hggsIpl
         qSEyuptPAytkWKVh2QRm7WTupkSowOkU0DrqxLmJcy/6AbXSje6yNt25tF8WcLDpKgM6
         APFUZCzdHgQdkmYT5PFZGh1Dqo5eaawvCmlRfQCYFp85c8yEwjmjLEcqkMKiTyaoq+bq
         CX6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744038697; x=1744643497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TPtW0V7Am29hUz3q3M9OQ49LNpIv6y4YhxIOyX5WzRU=;
        b=odjHSoHoAf5CbXWnspmAbF3jPyYQ5N9yzMUiA4VdjuOlkXE+qUxvUBN7Nw9zPN5Dem
         7QuL6IxMn0XIon1VDj33dH6HxPHJKYwW5BBD01PBoWjtiSorwRoEE+nrcQ9lemf+/Alp
         urDZj6UEy5Hwsh/iokcD02b+y5PauHiDd84Ecn5MKrf9q7EQiHWKbj5GO8hHeHk35w9M
         MbpV/YW/HGfqQN1LOL4kKmKFw4iSX6/1TRCuki+DSl8bhNC7jJyY92fhmlg0S8BwY3Rc
         TTZmsftOPn83ym2Zu1wFyq3lDS6EfdJp6swFowyideyleTFreVEhl7yKC/mRL6du5450
         2uAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8g/VmSvbrEDP5Wo79A3+0VN58fq7FeIy4ocZGkfC1QTtyj2d8+eD7M1RsPPPjzZXzEkasAA==@lfdr.de
X-Gm-Message-State: AOJu0YynUPBB9z5ELStSHnKYaFLDbYtqGFyBsu/sHBKTJpZ9ZgDItD4g
	xxG89PGDgLoEJmrnS09c1tS2w4Jg5O/7N7+82owfUazj691iTX0d
X-Google-Smtp-Source: AGHT+IHxeSbQYP+6VE1fMPOi1JexO4KXcK1JyFw/B8Fio8pCuuAEgVKcOXQcf8LmyxsQH748hplevg==
X-Received: by 2002:a17:90b:1350:b0:2ff:5ed8:83d0 with SMTP id 98e67ed59e1d1-306a615a938mr18117968a91.16.1744038697259;
        Mon, 07 Apr 2025 08:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ94y+Wrz5GXVF+65pUAQq6obOwX4l9LhittX/wnBCYvA==
Received: by 2002:a17:90a:cc5:b0:301:cdb7:53ba with SMTP id
 98e67ed59e1d1-30579d61d0cls489161a91.0.-pod-prod-09-us; Mon, 07 Apr 2025
 08:11:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3kUaysVz8GDWp/GmAvOxZyopVnubpIc8S2F//xBw/SypfEIXzlbpO6hu3lO/OTJxOwLNSNjK4JP0=@googlegroups.com
X-Received: by 2002:a17:90b:2749:b0:2ee:7c65:ae8e with SMTP id 98e67ed59e1d1-306a6125ab2mr17362069a91.11.1744038695820;
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744038695; cv=none;
        d=google.com; s=arc-20240605;
        b=Cuy8lrzfmVn0ogBFivU2XdBr2v7j3Q+GomdOlIrbM8miyZyTJBAgjdTUVP0CwAuUgf
         L3bZ8b2vfW+NRAtL8esFnr1ExiVmx5n2M0KmiLyP5uc/bodThqJ39WTmORP5mv183tr/
         TR/wRbsLAYcOH/CxTgxCdpJln+nWoh/j97VEydQGgl0GwLqVKpvpcPiY1OBKAIkNlp/t
         iLHQNMgaJVFo522RCiTNlVvzbtvCaf4IeQQSQPOfbkPOnwAa6m3h2pEsxOPhS9NntBLy
         P2GSDMCBqMcC4QWOZOsTgK+Nn0PpiYLJ5P3F1VRlWc2VA/o9/qypMjmR3iaPrp2lx7Ny
         X64w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=57tQfDvPr0M3Zui29k18xkGtBTpws7x4blA2kXuxzE8=;
        fh=LVJPJYP2Tqlg8aWQBGa6aniChm4kWZS3hY9A1BPUb/I=;
        b=Ju7uek/fwSCrk8BN8+Y0vRrlXG+2Q0a8Ycl3yQ682N8E8a55JjvIGwO8RnVkBFnVpp
         42ee58N731rSxBiTGNGFHZcxuMZBAqa24J2HRyOuAZVyQJ/EvqPVipORanYkRBEkP7Op
         Tq51IzV4IvULleicLYRpHtNz3lU4nUOo78cGIAuR+9qq8W714qbyLmi3YpJRey9BIkLb
         +NPfv+97bI7cxmwIbbYNQgF2dqwM00jfxHkJrcN2xINcTlPkAyf8JBRs5NpR6VHPDiTr
         4AXoGMFaPz2M+kG49UTcJJpVRCqQiXwlalc1JfdEpkgo4Snc39s1tWtBY72zY/eYVXRG
         vq1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="iGIlK/ui";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3057cb323adsi525333a91.3.2025.04.07.08.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 537A4FUU022813;
	Mon, 7 Apr 2025 15:11:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45v0spm8qr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:34 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 537EmSRd022056;
	Mon, 7 Apr 2025 15:11:33 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45v0spm8qm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:33 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 537BsEeX018863;
	Mon, 7 Apr 2025 15:11:32 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 45uhj26182-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:32 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 537FBVvI21823898
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 7 Apr 2025 15:11:31 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F08A920043;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DB1AD20040;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 7C925E0EFF; Mon, 07 Apr 2025 17:11:30 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org
Subject: [PATCH v1 0/4] mm: Fix apply_to_pte_range() vs lazy MMU mode
Date: Mon,  7 Apr 2025 17:11:26 +0200
Message-ID: <cover.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: K4njNltb3a39PrtZv2_ODEkMFtlx96GJ
X-Proofpoint-ORIG-GUID: HmhRseE7QFEwjmUit74LYcV6TtFzZkug
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-07_04,2025-04-03_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 clxscore=1015
 bulkscore=0 impostorscore=0 suspectscore=0 lowpriorityscore=0 mlxscore=0
 adultscore=0 phishscore=0 priorityscore=1501 spamscore=0 mlxlogscore=625
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2502280000
 definitions=main-2504070104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="iGIlK/ui";       spf=pass
 (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

Hi All,

This series is an attempt to fix the violation of lazy MMU mode context
requirement as described for arch_enter_lazy_mmu_mode():

    This mode can only be entered and left under the protection of
    the page table locks for all page tables which may be modified.

On s390 if I make arch_enter_lazy_mmu_mode() -> preempt_enable() and
arch_leave_lazy_mmu_mode() -> preempt_disable() I am getting this:

    [  553.332108] preempt_count: 1, expected: 0
    [  553.332117] no locks held by multipathd/2116.
    [  553.332128] CPU: 24 PID: 2116 Comm: multipathd Kdump: loaded Tainted:
    [  553.332139] Hardware name: IBM 3931 A01 701 (LPAR)
    [  553.332146] Call Trace:
    [  553.332152]  [<00000000158de23a>] dump_stack_lvl+0xfa/0x150
    [  553.332167]  [<0000000013e10d12>] __might_resched+0x57a/0x5e8
    [  553.332178]  [<00000000144eb6c2>] __alloc_pages+0x2ba/0x7c0
    [  553.332189]  [<00000000144d5cdc>] __get_free_pages+0x2c/0x88
    [  553.332198]  [<00000000145663f6>] kasan_populate_vmalloc_pte+0x4e/0x110
    [  553.332207]  [<000000001447625c>] apply_to_pte_range+0x164/0x3c8
    [  553.332218]  [<000000001448125a>] apply_to_pmd_range+0xda/0x318
    [  553.332226]  [<000000001448181c>] __apply_to_page_range+0x384/0x768
    [  553.332233]  [<0000000014481c28>] apply_to_page_range+0x28/0x38
    [  553.332241]  [<00000000145665da>] kasan_populate_vmalloc+0x82/0x98
    [  553.332249]  [<00000000144c88d0>] alloc_vmap_area+0x590/0x1c90
    [  553.332257]  [<00000000144ca108>] __get_vm_area_node.constprop.0+0x138/0x260
    [  553.332265]  [<00000000144d17fc>] __vmalloc_node_range+0x134/0x360
    [  553.332274]  [<0000000013d5dbf2>] alloc_thread_stack_node+0x112/0x378
    [  553.332284]  [<0000000013d62726>] dup_task_struct+0x66/0x430
    [  553.332293]  [<0000000013d63962>] copy_process+0x432/0x4b80
    [  553.332302]  [<0000000013d68300>] kernel_clone+0xf0/0x7d0
    [  553.332311]  [<0000000013d68bd6>] __do_sys_clone+0xae/0xc8
    [  553.332400]  [<0000000013d68dee>] __s390x_sys_clone+0xd6/0x118
    [  553.332410]  [<0000000013c9d34c>] do_syscall+0x22c/0x328
    [  553.332419]  [<00000000158e7366>] __do_syscall+0xce/0xf0
    [  553.332428]  [<0000000015913260>] system_call+0x70/0x98

This exposes a KASAN issue fixed with patch 1 and apply_to_pte_range()
issue fixed with patches 2-3. Patch 4 is a debug improvement on top,
that could have helped to notice the issue.

Commit b9ef323ea168 ("powerpc/64s: Disable preemption in hash lazy mmu
mode") looks like powerpc-only fix, yet not entirely conforming to the
above provided requirement (page tables itself are still not protected).
If I am not mistaken, xen and sparc are alike.

Thanks!

Alexander Gordeev (4):
  kasan: Avoid sleepable page allocation from atomic context
  mm: Cleanup apply_to_pte_range() routine
  mm: Protect kernel pgtables in apply_to_pte_range()
  mm: Allow detection of wrong arch_enter_lazy_mmu_mode() context

 include/linux/pgtable.h | 15 ++++++++++++---
 mm/kasan/shadow.c       |  9 +++------
 mm/memory.c             | 33 +++++++++++++++++++++------------
 3 files changed, 36 insertions(+), 21 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1744037648.git.agordeev%40linux.ibm.com.
