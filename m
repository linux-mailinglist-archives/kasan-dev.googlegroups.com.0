Return-Path: <kasan-dev+bncBCVZXJXP4MDBBSUT2W7QMGQEZV2RU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 787E8A81168
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Apr 2025 18:07:40 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2c2b6cc2f94sf3890855fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Apr 2025 09:07:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744128459; cv=pass;
        d=google.com; s=arc-20240605;
        b=J7MN9vzCpTU5OTsFP+/0e/rzkyVVG/RDH01qByRiMNABGBXZa2fBwZwvXQ+kGN2XNM
         RpVinoBQHdnLmOVJSWuAyrfxGHff2/PqYFhixv8dTF3wuLVoQNNY1JvKXEvuSEsfAS55
         GRL5xDFpTYI1paAfYeWxi3ZszytR8H/dpprYYqAadRK9pcIF/MINcCn4J1EesQQC93jy
         v1YoFG1xRwwPu23JV1NsB7RnGAUFjFH4K2oOLOekYlpht+vxhX5tuH5Kv3BNzsxmDuqz
         1+SQTIX+P4sMMW/v9jqNqcxr8SQS0+FMFuZ/0/3YjX5Xkf97rRy6gFi7DVVP4wZ9VCXz
         S8+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZZeDj6/OBful7yTirbtruXantRPsmByKVCWDuPNUhgA=;
        fh=MJO4plED42xS6L1TvXRTkFk5XD3S3vPQ1QFocDPLTXM=;
        b=OgRUwkvby6SFbInG07AhfU/T2wX8nfVX9awYypcA7cK/Uk3pbLZ833Un0v38vKrCiU
         DiCtp3zNDmSCPkSC5VOJ8ABhml051tZ2zRSau2S/ZDXwO6ZPgHvT321RjN8M0TVR8io0
         QM9KI23lFX6Dw2MsuBvHziuW6UplhA1IkRg40cfAmbmKf/LExZSoyN+iCWcYJ9JmGcic
         BWXteN5pgcQrxAPSp4nQU7tjvk0EuNCZARZzwRU2ZyLnLn0szmJJNojASu2CQ+CrayJE
         +H6+zey2QSV0o83KE5vigYCpfyWX8jWGbkcnWRvMiIDmdgmakLso6nXQgoSfjPnWtKH2
         1y6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KuN6IiHD;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744128459; x=1744733259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZZeDj6/OBful7yTirbtruXantRPsmByKVCWDuPNUhgA=;
        b=jrdO2MscaU9EkrEMGRohrZ5FH8sAtpnkornpgEQ/sze+aDRAoPLptEPrRtEvFDrU/O
         QUppQ1QmhHIKfm0v0QqzjPzykxcECS0+007kgI8ZX4OYxnujrWjEBkFkxPpJ9o3sijSx
         HTCK6I72SN7SQ1LJeE1IPQVYG/vDHBVSRoSca0gIw3KohRMhMZsJcGEavCDuIYljYEyg
         jr1+4hqnkhNpddsoAKnoi1Gt/bybh1AVXBgaEYhqeZx8Fnl3G6yX/vp0DPGEy4Pk4g4I
         4Zc4/0PgpAVi3hwISXnLwjyIHjYpqO87a3uAwjoMQe+/1nICHHix75kxjQwYpQTGeew1
         f/Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744128459; x=1744733259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZZeDj6/OBful7yTirbtruXantRPsmByKVCWDuPNUhgA=;
        b=rI26gpgNYprjjVydyLlMznPRWrSGOOJBnf2z6qZk0JKjMZ0O/dBWREhp/MSO7m8VV0
         sjFHafOccBa4BADvKcy2/6KUVkOEjQVwnqWGl+sGbuJ4PGW9/VUS8ORjinKN31X0Op1B
         5kRQOghfRH/WuubwK0H4BD2Qvhr1eHV/bF99xh/EWf8+AoGYeh2hjHxxAV+LS24gLlVS
         YDxJXtwKo9+simL0nAw9Jkpu3lQKu4diyVGR2rNRR+EcniENyewIOOM5f80U817P3YMm
         AXBy4E+t9sZGs1T7xaX09rIfFUrskN8Tq5wcEYq6N8zEtYtrYf6QoHmhC81x45EoFkNP
         F4oQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgoOxFJmOlui6dtwDkRvuWS+4jHow43kh/JADfCq0nuDDohjnOF8bkLxFaRYgTZsy8sgK2Sg==@lfdr.de
X-Gm-Message-State: AOJu0Yx1yUW5ajnXwbmlWBxtF1qp5ekrdm7nNXLKnjGgEkM/qXyMowd6
	f3XXy3R0cDGOGuJmROwIunYCkG5USf5k/zeIkCqlwEQsAnCEK8Pf
X-Google-Smtp-Source: AGHT+IFAt7cVvP7fv2CVXImYuvcrYJk+8KLX7RxPF3Vano9PgSslL+CpGN4RjYoIvm1h5gqC6KQ7Ag==
X-Received: by 2002:a05:6871:64d:b0:29e:4340:b1b with SMTP id 586e51a60fabf-2cd32ebcb69mr6892525fac.9.1744128458650;
        Tue, 08 Apr 2025 09:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK8jePSbDyVfX6BZSUeQcLmE0SkysPtyz92GQq78bWPmQ==
Received: by 2002:a05:6870:434a:b0:29e:3d45:93e6 with SMTP id
 586e51a60fabf-2cc7aaff4dcls2221275fac.1.-pod-prod-03-us; Tue, 08 Apr 2025
 09:07:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuVlKFx0ctzwebKT3fy8UmLusRZ30R5ysFHJMaoHVgtnHRDb2UqJieUphD1Mq3TEggJM7PgXDTuhg=@googlegroups.com
X-Received: by 2002:a05:6830:d0c:b0:72a:d54:a780 with SMTP id 46e09a7af769-72e40eb82e2mr8108958a34.17.1744128457651;
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744128457; cv=none;
        d=google.com; s=arc-20240605;
        b=RwjOnnvpYRDuhZDpQzmvXctCIR4EfyGhn6L0AK0MT9rhM1c9cBmRONX4mLSo5D4RkN
         MnJ2d5pFjk9yj60dIJRFXbddT1W25oGPsHG6Is1LyJNXDQuwYtNa3jB4GX6VvoTqpvFR
         JgpaglsJrhhaqmZoXjdZhO3Wk9Ykulz5wcbYz1ZmSwaQQcvkKYyojN1MQuXzPCB8dlxg
         aNyuguxSJ2XDZyTXap9xJ4jobpYZOItQvt8mQqCZT3zFsav5kdp8GxUu6uUtpy1/ksqJ
         4Il2fkIFwwHmK9Y2E18HGlgE10U2HqfIdouxK54GMfCdpvUpyW8bPn0X2j9YAKVnqJfs
         DPxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Hyqi0uOKVD2qmF0HO2gDnCnMoE/ESURqT+ROeR8reIU=;
        fh=Qpv0vZFsOkAl7OpmVhwpUC70zZ+oFSiffx6v4uyFrtA=;
        b=iZt3+3lUNAo//DEKA1m9fO6si92ia4EUYzVT0Ks9ffFghvaz80bwKZ5xBslzrIe75H
         BHZF1L+uBEmFKPUaamMXpEUnjpRYmGeIt0aN3hvAMgrHOVtn3BkSpXuZN7u4I35pZwBr
         7oN/YVpvPK0W4646RcGRHQ35taoh7OQLZ4ClPwb6dsgxHDUrlmGEoekAlmTK85B4XLIk
         gXKyf4svRnWg1yUTncSGiYXBDcQwevdlvvEPwnw3/2RWMkgRXf6UGX0fcPTt3g6+Pr1U
         nq28CmjJWuvkCsAzSYTOhG4ZsK9IjKzZ5d6QVqSlrKi8DotFzqWCY1byzTp9jPnUoeDI
         RZKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KuN6IiHD;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-72e65176d03si100743a34.2.2025.04.08.09.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 538CSaU4018465;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45w3u313v9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:36 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 538G39G0000730;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45w3u313v7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:36 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 538C4qov014404;
	Tue, 8 Apr 2025 16:07:34 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45ufunkd22-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:34 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 538G7Wah49873200
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Apr 2025 16:07:32 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AD6F220043;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 987D020040;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 49B74E0628; Tue, 08 Apr 2025 18:07:32 +0200 (CEST)
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
Subject: [PATCH v2 0/3] mm: Fix apply_to_pte_range() vs lazy MMU mode
Date: Tue,  8 Apr 2025 18:07:29 +0200
Message-ID: <cover.1744128123.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: zTdW0kqTRTiT22s8uhfmBPaUntY3pzCH
X-Proofpoint-ORIG-GUID: rmIK76a9Z49Qa5aFKSDqoZ2VuPaoExus
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-08_06,2025-04-08_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 spamscore=0 adultscore=0 suspectscore=0 mlxlogscore=635 bulkscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 priorityscore=1501 phishscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504080110
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KuN6IiHD;       spf=pass (google.com:
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

Hi All,

Chages since v1:
- left fixes only, improvements will be posted separately;
- Fixes: and -stable tags added to patch descriptions;

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
issue fixed with patch 3, while patch 2 is a prerequisite.

Commit b9ef323ea168 ("powerpc/64s: Disable preemption in hash lazy mmu
mode") looks like powerpc-only fix, yet not entirely conforming to the
above provided requirement (page tables itself are still not protected).
If I am not mistaken, xen and sparc are alike.

Thanks!

Alexander Gordeev (3):
  kasan: Avoid sleepable page allocation from atomic context
  mm: Cleanup apply_to_pte_range() routine
  mm: Protect kernel pgtables in apply_to_pte_range()

 mm/kasan/shadow.c |  9 +++------
 mm/memory.c       | 33 +++++++++++++++++++++------------
 2 files changed, 24 insertions(+), 18 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1744128123.git.agordeev%40linux.ibm.com.
