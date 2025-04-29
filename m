Return-Path: <kasan-dev+bncBCVZXJXP4MDBBEHTYPAAMGQERDLOUJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 95D25AA1143
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 18:08:50 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3055f2e1486sf8599424a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 09:08:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745942929; cv=pass;
        d=google.com; s=arc-20240605;
        b=MrFThwWrlOemlKQqPiG20LUkmzOsc6oUHEMNA0sl2f5Ikg8wywgqO9Q6ezahelmO+L
         vZKUKix+u2v3mR0lEAbYXkBqUJx8XSr93eBvaSsxDR9S3d81xYIDVqdnZFhXHRtLeRJZ
         MHT4lFxXRQTxuSrlrUAgRwwTpHg13A99cJmSaKScxfExvqXVyueA2/kpYCGF79M+jy6A
         MPX6E4jJQsnB8BW59UHhKL0YFYemwAtdM0HcePfj6hB+++auVq9mH/srLycFa2/Ze4i4
         +etN7rS081YCzu9nP8F5+14k3g8mT/hV/VJnzEWYCAGkfHmmeuYonOAll4t+XeWJXRTP
         wozA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AjTf8KwIRAVLNiM8f9uhsL/NPBcyNztu+kBrZ4xyukI=;
        fh=K4BJpcOty57pJiQb7B1dU2a3lt5wirXLiGtDBEXHzuY=;
        b=NwDCd/qoJU9gOVqobQIw61hiFanilA0yHEZ99vhJ7P13xM6m77DTOyIcH/vjNn9gPc
         RoSUAbEmBEg0Q7+GiQaTbfBrhugBUyKEPSW1MMTqcS2FXrMhCaHnEFMF8VeSRHFqQux4
         o4d1URtuonHjyf+hG3W90JXEjKPxwvFKRclcPaqX9UN1VE5hZLe71zh36CU1uGe2vUWZ
         fRmnjVIlE1OkTbOeN0Qgpgnctmbrg2vL9tTwBm8ztQX0txj5yeGsJ13CnE6YuVjwprUN
         uFcu10/q/lQ7rMYvbbBzl57gE7P+xEn7IVXAP5ZZ1rTF2962DW1AuCpW/cwMULpXAcwR
         pZJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f0r37keo;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745942929; x=1746547729; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AjTf8KwIRAVLNiM8f9uhsL/NPBcyNztu+kBrZ4xyukI=;
        b=NTGAo57cClApdoKnk/yOSqWKHIdUe9D84/nmy6Kz65pWwvOmIg8NORJBe4QVwKdaCt
         rrxq76a0F1WcrExeEb+PtKUQb4Z3spZaBFZVugmbOM2mxmT2vrrsCi7i0c1b/1YvA65o
         L1+3NIQGW8tHrflkJY5VI9ks6ICYnBsSYWLwx5sZT9G92L0in916HtC88kzFuR0xOFhM
         +yZVrB+lw9dG1CidVWxQO6usIfd926HMfvfPvPFiyC/r4KTUM8oOA9xPbZznTQ8b48WJ
         oc7IXIDonSB7Wjyiiak+rGYu0jQwHM9+2P6ZEUwEWNz5bEbO/26EdSVBkNj4wLZ4C0eF
         5Jdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745942929; x=1746547729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AjTf8KwIRAVLNiM8f9uhsL/NPBcyNztu+kBrZ4xyukI=;
        b=Wg3F97VaR6zMj34UA7U3uYEyjGpXL8MdcP0k9Y8XjNt8QXfBNRGc0ioThObkog/J7h
         UZniz74GnKoTy92p7A7bDGNL6q7Kqm5VnNmiQl2ZZupYywlJypidtQJuA17oz4PBzuKC
         f//tmoMpfMgwr3mwYDckg8HOgabsYf+g5Ii1qt2OsnkEzuMgPpgXMEaFLzQTXdj7BROQ
         XjNG+X8sJ9Jn3dd2z9vO1hoEusrK1ZhrZ0CTQOzJZHBPSY9m2trf0t4b7Coa/IdLhCXL
         JCtV2xA7K7j3oAHxvn/Zzn5SVccw2tvvPI+cVAHMwIG/LBiFZUpQ4c1AzJE8Glb3a1+d
         OgWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVOE3Up0r/zluQUncq99EI+AltDRihif5NZzFEcohD/BZvanc5PoPatjhU0d9KGWNXgXd3qQ==@lfdr.de
X-Gm-Message-State: AOJu0YyVtzQUQra8H94H6+GukwmBDExOBTm+zQiOoLnk7hAoJJ7PYYcN
	swoiozvSDsn2uJEOVsJGjCpk+82oLC6qdhHuyuSjpA6YQpx485LK
X-Google-Smtp-Source: AGHT+IFyZIbOc7NznwgFkAjTSAfdHghVYCofOur0HIlA79OWSpc4bkFpnHiJAYaAqaebdycpa62ypg==
X-Received: by 2002:a17:90b:586f:b0:2ee:ad18:b309 with SMTP id 98e67ed59e1d1-30a01300251mr18457020a91.3.1745942928539;
        Tue, 29 Apr 2025 09:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEGJxOdEXl21eHYh60F2qgjpHdx41+ZXahNaqvmVu51rQ==
Received: by 2002:a17:90a:de0e:b0:301:9a05:8467 with SMTP id
 98e67ed59e1d1-309ebceb7dbls2798913a91.0.-pod-prod-06-us; Tue, 29 Apr 2025
 09:08:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSqfllzJD8IXmtiQVAaGjcLE8NSqBW38rUhYbI4U7mOH294kFWrd/b1kKPY2Lg3M9USaQ0adokbkk=@googlegroups.com
X-Received: by 2002:a17:903:22c9:b0:21f:6c81:f63 with SMTP id d9443c01a7336-22dc6a0497fmr194156455ad.16.1745942927285;
        Tue, 29 Apr 2025 09:08:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745942927; cv=none;
        d=google.com; s=arc-20240605;
        b=XhUveyPIv7kwNJXUE+XHdlXQyQBsLjOaswLe9J5Vt1lNCMvMNUF9ptFFf+EVaFi6r6
         O1t7M8xowb+iI8xV64qRTUqeVmoVMGjJVLrWb9BJPCK3mFxnpWJ6FTUuEGcETNJJQA+B
         Edq0CYPuvNUffydi9AEkXO0kMljrsbG82sGxtgXvfTfTiX+MUh+w2GcqrcLrp4XFUcJe
         1aKl1y8M7eM6yMG9ZMf+RMPk4K+n5uJP3PZqG1aLIHTwpNvSH+mNXhhSCF2O9iZ/oprF
         dSi+hxrCc3esrEP6Aqq709h06m18f2ozUxkG90UIpce77hwiiedojmbosLAJpkBoLsiy
         U4hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=exXFY8c3sXTfLTJs5WHyoRrJ3cCFL+f9yepX0KeVH5A=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=dOcjMaAxvoMnuSl3HYm0MqrLm7d5LqBPWG+f+IGw46zqS+BOQUK2Wz/y/Ik0ph4g0X
         6Avi3pmQ3Eu3HJWgIECA1ikasNpTaTtONom6G6lTFN9Js7MLsRaDIYae8t0eUeJQdAxY
         IPqyutZ6DPz5jbJZ+w1Ff4cv9A4HJoiGF6qp9ZMgOJNrqNP7lnGm3W2VzOQtmXWNcVyG
         5bXo9OqKZc5Gb/NiCEZj7C21yLM9hU4RB5fh0bCIZ0iAksXqU4QEonSOH7trE1L445kL
         u24P3/7LDcUVxOJChuMsAfxp6G1L7IE0z7MgxGoF3goL9thmnkJ8bcITlRmLHMQSZWyS
         B7BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f0r37keo;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22db5228a17si5524505ad.11.2025.04.29.09.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Apr 2025 09:08:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53TFi49e007384;
	Tue, 29 Apr 2025 16:08:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ahs9c4v6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:45 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 53TFi9Wf012165;
	Tue, 29 Apr 2025 16:08:44 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ahs9c4v4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:44 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 53TF2ptu008490;
	Tue, 29 Apr 2025 16:08:43 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 469ch33p5a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 29 Apr 2025 16:08:43 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 53TG8fmE19005828
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 29 Apr 2025 16:08:41 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B530420043;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9C5A520040;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 29 Apr 2025 16:08:41 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 4F3C9E1D62; Tue, 29 Apr 2025 18:08:41 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue, 29 Apr 2025 18:08:41 +0200
Message-ID: <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1745940843.git.agordeev@linux.ibm.com>
References: <cover.1745940843.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=LuKSymdc c=1 sm=1 tr=0 ts=6810f98d cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=XR8D0OoHHMoA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=5xA_3oZvIydUEubUgb0A:9
X-Proofpoint-ORIG-GUID: eKosXnLkU16YdrMOn0HBc3RHeNNSB_B9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNDI5MDEyMCBTYWx0ZWRfX2IGG+lmTdPaB wCQTgHqF/pn5FxI4xPz0sOcj4WE0vLUd8BxQaL7T9RfoxReeiW8WaH+0LZ9y9AjrfEVNbAURcby ZJ18Hfp6JC0emTYaITP3j1DZrqHllnldPcdC8KZ2sA3PPZcOSqJUyGPbfqLnivwfyfq9uQrV7LM
 uj3CWFzl+9RNyzde+dpU1+EbY2Kg3FqZWgcoCEjFAOjQrH14065mFxjm2dILaAyex/TQfgyrIYe m2BnFl6vmtlFNHDmTnIpVjFTpdPwNyk3cWAMfVQwIoDbFnMxcsIZOVVxz+cLT1eSM8A6+gaKjtb odjriVZ1221loHCTvYfTEZD1CvqjvJxbDK2dgR3LC6HOCFSAiJMbX1pqmnfmUzCJYTm9Ir3EnBb
 HQ6fejZfxDNwcwYhktrk32uOGuKS/c9/LIWTX6isE0fEzeC1DQZBuxhxazRCQGZNDdgQB3LX
X-Proofpoint-GUID: 0-B2yVFWNPdkcAEAxw-pzdBB9vj7F0Ff
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-04-29_06,2025-04-24_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxlogscore=459 clxscore=1011 spamscore=0 lowpriorityscore=0
 priorityscore=1501 bulkscore=0 mlxscore=0 impostorscore=0 suspectscore=0
 malwarescore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2504290120
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=f0r37keo;       spf=pass (google.com:
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

apply_to_pte_range() enters the lazy MMU mode and then invokes
kasan_populate_vmalloc_pte() callback on each page table walk
iteration. However, the callback can go into sleep when trying
to allocate a single page, e.g. if an architecutre disables
preemption on lazy MMU mode enter.

On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
occurs:

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

Instead of allocating single pages per-PTE, bulk-allocate the
shadow memory prior to applying kasan_populate_vmalloc_pte()
callback on a page range.

Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: stable@vger.kernel.org
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 65 +++++++++++++++++++++++++++++++++++------------
 1 file changed, 49 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..ea9a06715a81 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -292,30 +292,65 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,
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
+	unsigned long pfn;
 	pte_t pte;
 
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
-	if (!page)
-		return -ENOMEM;
-
-	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
-	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+	page = data->pages[PFN_DOWN(addr - data->start)];
+	pfn = page_to_pfn(page);
+	__memset(pfn_to_virt(pfn), KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(pfn, PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
-	if (likely(pte_none(ptep_get(ptep)))) {
+	if (likely(pte_none(ptep_get(ptep))))
 		set_pte_at(&init_mm, addr, ptep, pte);
-		page = 0;
-	}
 	spin_unlock(&init_mm.page_table_lock);
-	if (page)
-		free_page(page);
+
+	return 0;
+}
+
+static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+{
+	unsigned long nr_pages, nr_total = PFN_UP(end - start);
+	struct vmalloc_populate_data data;
+	int ret;
+
+	data.pages = (struct page **)__get_free_page(GFP_KERNEL);
+	if (!data.pages)
+		return -ENOMEM;
+
+	while (nr_total) {
+		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
+		__memset(data.pages, 0, nr_pages * sizeof(data.pages[0]));
+		if (nr_pages != alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages)) {
+			free_page((unsigned long)data.pages);
+			return -ENOMEM;
+		}
+
+		data.start = start;
+		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
+					  kasan_populate_vmalloc_pte, &data);
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
 
@@ -348,9 +383,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev%40linux.ibm.com.
