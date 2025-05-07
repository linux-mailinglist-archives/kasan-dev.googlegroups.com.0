Return-Path: <kasan-dev+bncBCVZXJXP4MDBBC5N5XAAMGQEF3NAX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DD439AADFA3
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:48:23 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-72b8ee50fbesf6124311a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:48:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746622102; cv=pass;
        d=google.com; s=arc-20240605;
        b=hViwZkMO/Ay+NdCXiOHXXGBIbAREelDL4WBjWgm+kL2F7enYxm4Z2q/7WrfqdNnQWU
         EDGbkqbpQhsL6l1dEwW1RAOWycvtG1t9JWs6Ph00yOQZwq28aNDdcTvxS9n7cSI/zspw
         AVcK+wkNUNheseJpHVQXzrZkRHBupSGwcYY9QtvhbO/sWnJBVrphuIt5Y9t+Qr6yIJpB
         v8fAEaZIZ+pcpg/vXgZ7Vt+G01Bt0iL2pQA+aqPD45IjLvZ/BFLqDZZediXaEXXkZoJj
         a2cuaLuj+KpcNOe7fWv++sfXn2/2Zf0UqhYm/tMMIuhhAR/YoSJ8tp/IXacuym7qElNL
         3fuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zcSXm/+aIib1GPFTMNYDJiTte6TYJWu9HfhwbKdRQVg=;
        fh=EA0w1UUSlZCuIqcAcTa/Q0CjkXIiup120m1JNaKsKmU=;
        b=cC5KdU3eyHKWJuj1+hOFzWUJ+2AqdKMSRCqfeamKpkPxMzCchJ9U5+bZCmJ9ZkxK/X
         Rp5RsZ8yA4/CeVDD7lk014TjLmzxVWMNdlLGgT4JpM787S8480FhSjVxk7KLJaoqcDt9
         ujlwX9dkqTflLdI1SBfCwQyQpDHEExTEVSG8O+tF9OhDYjMwCgCQKPN+4DuheufLLPr1
         Jqrg6CNhpNEdvvWEDXecdpNYyi68EkjDalCJgh4AwDN0ta9S/k34CDbEipTqtQ1oK6VG
         U12p3toLrQwC2jvcNuyQ+AqehQCxsuaWTPAOUZCKzeNnxSOAcPXQZspkjPs7Ze3GspfJ
         aqkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="HecTc2/N";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746622102; x=1747226902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zcSXm/+aIib1GPFTMNYDJiTte6TYJWu9HfhwbKdRQVg=;
        b=GEINTyDOMzXqb2hXNMqtFQfLsesi2+se7BuLRAK/Xy5Qk+eLioqVIanyUE1z7tIEww
         ecA4J5mPmXCT1ePOcL9XGtQ+mPhPdQBv6wFs3NssSAjdTsL8X2yJc76vRY6ncoM6oSWa
         A0X7Y6P/gGyeQnV01XB3fQxSDzDEwXVqq3aX8zD/ykIvPjb3Mb8IYqpKW3jGVZ1B/HJV
         4IEwUr15tHI9wzDNrTo17rUaPPQ1XViZ7mjS1B1PK9YDG6UJCTlk3VH6hVsOusNSBJR9
         wpVPidoU9Bt2gab8IrLke1/CFBlhr59ysmxSG++85I/rl8vRrZsXQi+oLkPNW3D+Ahmv
         IAig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746622102; x=1747226902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zcSXm/+aIib1GPFTMNYDJiTte6TYJWu9HfhwbKdRQVg=;
        b=E/ZL5MMBotDGr+/PHBhE2K2UbEkxUfkgkiUrD+/OsC70z13FPymcCttxEYNz1iT0zR
         ww8epZpqZaw0+1SU1TqJf9896VbgslVuAkC+Yha15AFsaWBgMpH7XlHRhDbdgwiHgWtu
         gDqSj2nTpgszXRczzh/pasyVEXWIbqn9HmV+wapCRIwFZwbEAI4sFJiszA1ZHNSt0Ta1
         v5Zw/WzTDyufabtLhKKRZHOIJYEQxKYGeX4PzRYjpt4JKV7TPDWv7ywMDVA86En5hO8t
         MI9DecClWfWWO+edfXFvm7NoPwUgdOSRmJ7rQjzyAtH08E4EB7z6CzdY6NyiPy+JDT3r
         KwIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBJbr+KdEH/yToKof+/NDhjmcSOK/7+wLpunlS9AKhjTUc32axuB+GLI3IxRe+DIP9693+SA==@lfdr.de
X-Gm-Message-State: AOJu0Yws6pt/U47eGV4IhqphPM9p1CYxe3Y2Pl4REgBMJ+U13fRIxHXU
	euxWBA44p4M6lEQabP9GtcuhUzmV2CsMVRrk83Ov/QaZaV3PGpOZ
X-Google-Smtp-Source: AGHT+IGz8N0FihDu8iWnY5+Uo4KRRdU2cJQ1MlXH+GMFR29SrsOIjYGPYZ680pNQWwKFjZBSi2fYFQ==
X-Received: by 2002:a05:6214:2526:b0:6df:97a3:5e5a with SMTP id 6a1803df08f44-6f542aa8374mr50889916d6.28.1746622091729;
        Wed, 07 May 2025 05:48:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGmIwFxm7WNrs4K910iCTk1Kh5444sTHT1x8WeXvPyRhQ==
Received: by 2002:ad4:4990:0:b0:6e4:4a16:b92c with SMTP id 6a1803df08f44-6f508531d84ls6402346d6.2.-pod-prod-01-us;
 Wed, 07 May 2025 05:48:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuUsdELbliP1P8/L/p2fx4PMI/q9FNhdIxzxLYz1TH+RxLya0tjT2Rxvv50RHvLrRVogOFhv/AjRs=@googlegroups.com
X-Received: by 2002:a05:6102:4a87:b0:4c1:9d9b:54b8 with SMTP id ada2fe7eead31-4dc73798060mr2702725137.2.1746622090335;
        Wed, 07 May 2025 05:48:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746622090; cv=none;
        d=google.com; s=arc-20240605;
        b=fFLKNZSsX4HLDycmedqcQ4H5pJ+QC6RPHw8ag3v4Wlbm7is73zLQfsbOKBhoCawCkj
         o0qqiXzaX9u91Wb/MVwUWZljYjzpxHPpdNgQ8QFooMFZN0kyikkyfeGtJ69Hfvm2s6dJ
         hfdd+2dbnBJQcgnsvae8Esziyq4G5bYtAuTQJNXk1kKo5EcucUJmg4cDzejIU3sdy6FU
         VxB7ylbGp81p2lms0JfE3irfMg4yj2duuTFz61TVNEI8h96HcPybO5AU6RoYASLsWUu5
         fjPVYPfyKgO2pQHoQ2YPsWdQEes8fTBRhc3GIoHNTBfpiHPek8GBvzIHQMafHFW/ZOfe
         TjgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ATE+TVfvA/Vz6alaYaJMjHxO6SwwaW8miGELtbRP2SI=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=DDcRidG5Qhjyd32PMmEAZTBSB018PcB+UKDWNykw04Ilqpojh9mY6IsqsHHezD8xj6
         asMOyPJAZKWyXux16VHj8ORczQfFwvNBxFuRmyxnhZo5EsJuTWWSzSot4VfvzbOwBQ2d
         Rygd1VfQ3Ouui2/VOtvqQBT9XZnX3ug3zlbiAeWG+vBXFuR1LP7incq8j8Ge0/MdE82A
         pgdq5Qp8nqwmtlOMeU+NCsOfyh1jEBcw2Ay4udwXIq72CmiHofzWat36/W4ZFOQ4/b5G
         fhbz5uJJJDQg+fTDKzuCYK6/8R3SQqcOKMN61RlIxNS1OZoK74rxfTpy58AsK4yFS50I
         r2fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="HecTc2/N";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8780af44699si465933241.0.2025.05.07.05.48.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 May 2025 05:48:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 547AY9og007250;
	Wed, 7 May 2025 12:48:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fth8bgpb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:07 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 547Cm6OZ016838;
	Wed, 7 May 2025 12:48:07 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fth8bgp7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:06 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5478tVsp002826;
	Wed, 7 May 2025 12:48:05 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46dxfp0pf3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:05 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 547Cm3Ir53215582
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 7 May 2025 12:48:03 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A5DF62004F;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8D2972004B;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 38933E0126; Wed, 07 May 2025 14:48:03 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v5 1/1] kasan: Avoid sleepable page allocation from atomic context
Date: Wed,  7 May 2025 14:48:03 +0200
Message-ID: <0388739e3a8aacdf9b9f7b11d5522b7934aea196.1746604607.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1746604607.git.agordeev@linux.ibm.com>
References: <cover.1746604607.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: pVWMKYbZEyw2181c1bTTvK43aZskAEH7
X-Proofpoint-ORIG-GUID: hX6cycSgroZu4hLcRJQRahMCIvMXjD4y
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA3MDExOSBTYWx0ZWRfXwzS0DU99voB0 DUdkEcnzrLPuEpcFmM3cBCcJSTCF04Q5q0YQKRp7NxA2DN2sqZyOSDNnGyLMBgAVFRxguf7FsZA vH9ck7xIs1vpPGuE/5xGIdT4hkK9UnaQ2JalU4cOHvjvrf5XjO96WsZHdjRZf9uuV9Zlu1fBqLW
 reu+hFA6nbzQk/dnlO1X3wjeg8TqDT9me+niYt3ngPXMRAWnLFNWRPwc7KojxIDjUlcljpvFglt rgggo+W7UWT9vJolJrB0ZnQeGVvqKeBe1QxvFuUfZxTBknlFdmTV20HZ6NSQNRDfi9Z91lmFIWL dYH4rdEz5ZONgu0EWVbByfi2VH//Ppox6m8JdyvqnyVQFVbVe/SNQFPWjKhUShla5LANrkrFUQ9
 Fa3tZNRGw//ePxBPs4oUVpR0d/G6PogNe9uFYsQMnOh6bR80/noPqv1p8McDYcWEEzQZoJ0F
X-Authority-Analysis: v=2.4 cv=KOlaDEFo c=1 sm=1 tr=0 ts=681b5687 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=dt9VzEwgFbYA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=5xA_3oZvIydUEubUgb0A:9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-07_04,2025-05-06_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 impostorscore=0
 bulkscore=0 priorityscore=1501 malwarescore=0 suspectscore=0
 mlxlogscore=384 clxscore=1015 spamscore=0 lowpriorityscore=0 phishscore=0
 adultscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505070119
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="HecTc2/N";       spf=pass
 (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0388739e3a8aacdf9b9f7b11d5522b7934aea196.1746604607.git.agordeev%40linux.ibm.com.
