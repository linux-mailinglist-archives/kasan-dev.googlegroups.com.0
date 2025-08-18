Return-Path: <kasan-dev+bncBCVZXJXP4MDBBOFORXCQMGQEHCB4H5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BAB5B2AE56
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 18:39:23 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-709e7485b3esf105304646d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755535161; cv=pass;
        d=google.com; s=arc-20240605;
        b=gAt7s/q0UmDoq6jxuuzT5O9JY7/hQVrwu9iiVy1oM1U2kOJIB7/iOxVjs06H69IRxs
         +9cAsrwVL5GoJt+4/tT/mNwRAROUZtya6gRzAadqpAo1TsJIfjkQimeIjYEvJc7ONpHS
         QcoJMPk6AUeZ+3jqjcKZSJBGNc55DW57FeQpJ7jm+J1+aI74yAryWuGbe8PH7CX3ZYyu
         u9d66hSjWn1t3Ck3wi9ozWQ3Pxljcx3glqeEmjKMKLCKM/L+YUaqvqzard8wGuPxVOtH
         lE5CSLnAJ9wRsFK7wRMYUz2rZwDi+ghsnqORbFzQ/Gmc49rklDyyq5dFCR7CDgQude82
         MogA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=drTsg7ULnY+RR/TT3O+D4TZz27qWXUEDMJFqCX1IhGI=;
        fh=G4HzvWGS4TUFpGa1CKkz2+PCxsI49nD9oyQIJXJW3gA=;
        b=dnKjnss44lvNCK2xwXwtXxDr3rWJrElX6+FyPx2yw9JU8pKnIduXU9PlY9QJepJDve
         j3SZJ2oRuqXZ31+ge3FQZSnRc4TouYhYpsFP15AKzD162le3OaaCyvdZjhajtFG7PoiG
         Cuub/r0o48m1BFkqDl6VVF/YGG+5nHcVP6EOg+FGV8yfcTpjK5TtD5T+iFGLcWbD+AAc
         LJZHCZwVrhtt7VejbLTryajTHzp9JbhT8p9Nsm05eJcCRnV3yxyfDejhqG89YTuJaaMk
         VMnD+EtuoZYmN+6tw9C6DngfbbFvle4hhXabvgbeP8oUtP0O+ktgiSoX+G8p5l+4ZdSx
         cOuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=elRkxDAc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755535161; x=1756139961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=drTsg7ULnY+RR/TT3O+D4TZz27qWXUEDMJFqCX1IhGI=;
        b=lZV3I2sG0Jvk0/aaa+0dd/YH6QgAd2ySGkV7FI35KpcWLnxoz5wCiEx4Kww+zFrv8d
         pia5myDgnn8VGTRLY8wn7nA/3qlcO3IE+fm7fIO8LHfodoKD518RwmEV7vqQhcjjdpcj
         14HWCBFe6UkxIG+VdPESWsCx+MNRzFqQsv8e2f4fYz2K0A9g8YHQI4soPS/nGVKi3re7
         r7eb8aDPfWqCHoOxfWeEP6BqNk3RwzB7xbo5fxTKEng4ZGudVqAys5VFlDcTHZlni1KB
         j/41ARdVeaXXkn6rBzD2gir53mhwef5rrDXWsSgeO4Tc1pONPkBIiP5R1aiNaC/r4UjC
         WR8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755535161; x=1756139961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=drTsg7ULnY+RR/TT3O+D4TZz27qWXUEDMJFqCX1IhGI=;
        b=v2bJN3fPSLOGdDZlym5pVQqRJofQrJtIFxCayHFPaJ1cUzRGAgOVK6JJCSD2Adfp0l
         k8BivPqLceO7ggPqdTHLQhiRIKAxrsLRpejBn2G28UL6D3zUiSUoIbim7oiwjBmOWMBe
         yMyyJzdY59NZxS14VfXofDZbN4Hf843cxNjMjHMoEwVfWFArzyjecG5dg36DcTsx6VS4
         6pUSKvhN1nt1CYbyzyKMQ3J3okj51XdVwo/gn25tuoZvicA92yTKZrCGYl55OuGCnoaF
         O46WnypKcQZoS1zhOamjsN1ReUfVo3I3DPnA0kgrR7llAnJXqwGjFfq2FSqa1WhXAN9F
         zmvg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWi9xnVGNezkelg8g2iZTdIzBBA6JnWfoHnz7vE8+iwlodItRZhiNqKABP1JcH+Ipjr+0REJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yys56lWKAwBiHIJu/g5UmDBxrI93GkNEIAtLac3MPG+DIACJDSR
	A99gFbn9o/g1SmrP4hh97iDNbSsDhxcA68lQGfH+WxDcuHkQknOTELbq
X-Google-Smtp-Source: AGHT+IGBRoHoKKiogrpFHlbfTSFJMdaxmLG1oj+72ioFGihpq4x7rfufogwxBUZyNUkcemciR9hKpA==
X-Received: by 2002:a05:6214:410e:b0:70b:43c1:745f with SMTP id 6a1803df08f44-70bcae94603mr3522876d6.5.1755535160515;
        Mon, 18 Aug 2025 09:39:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfF+vbGgnHZaqvYN9v3UCh+skc/apdM6XW9zog7/xzKiA==
Received: by 2002:ad4:5d68:0:b0:6fa:bd03:fbf2 with SMTP id 6a1803df08f44-70aabf21e63ls42011126d6.0.-pod-prod-00-us;
 Mon, 18 Aug 2025 09:39:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRYsMf3uzzopoWw7SfWDK7OfG/xJVRbb9PV/V/arLD6glkhRcSKxiyZ6zVznFfWGasd3wc7X9fIlU=@googlegroups.com
X-Received: by 2002:a05:6214:1d2a:b0:70b:adf9:bce2 with SMTP id 6a1803df08f44-70bcb06af55mr3008096d6.20.1755535159480;
        Mon, 18 Aug 2025 09:39:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755535159; cv=none;
        d=google.com; s=arc-20240605;
        b=Kqrs+Ung4lOibqQvbCwYBeCj4vaC7Xy0ha5vzEy07Rf5JJ0HBJETTV+ITpb+0AQEN6
         YarULmZuvFNlSNdM0gI8ucOcOQuNC0+13vjB/eFQR/GzbW8aEb3qIk+7RSWcSLSo0DMV
         Rx+iH+y4KGITXf5rjPAzAVaqJDzGhZxJUq1blyw6AXGkWE7bIOkADMOtPxYD0uJN4KKJ
         YqMMhHkDxSkw6byUyyn0ZTXKEYjd9py4pY71IfDisYeRffCmZVA3JtmtyJXNkSQFrSLw
         bKNuTZyMp3wAigyVM3VGQbpk6PnGr2ZtyBk1i8WFQytVqyul7s7EnK39hPtAi3JXtv+f
         aTJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=R2J8minbyc0pri7w8vlrXNn+dDlIo5btiJgX6/Qc+BI=;
        fh=LdYAWUXcdYrCqzsb33cHKMTwCaURP2yfAndH6C0pUuE=;
        b=QQxqxz+oI66kfK5KA1ovsVwN1RxfJukk/qHr65wbtwHzFPOzSEpivvaMufh1Hqpcpr
         27EuZ4At6lH+LUp177Clo5pCOUldD2M0JD7Rj2qdUmooeB7MXdcfsJJQj8lWQSSaenvj
         TkhsEK+YOepxXDh9gCHOdun0+Z4YFcK+JIjtCZt13Sitjnt/RWNAc6bwMUnA+/UxJRHD
         9+FfTEmr2CfATsUbVM0JnfLYmt261tPEy4Ua/bZEgCT+mddhVwqllwTLbrcwbcfh5pdl
         bbH6KdmTaqPb7GyXhHlBpi3aQOXbYkLXfkjBsa+6mfRPfWiqM1ANavRFsZ6nvRrz1esg
         xGPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=elRkxDAc;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba925dca6si3026476d6.8.2025.08.18.09.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Aug 2025 09:39:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57IBAPPw024356;
	Mon, 18 Aug 2025 16:39:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jge3t6xu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 57IGdGvN013935;
	Mon, 18 Aug 2025 16:39:16 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jge3t6xs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 57IEnhPd014728;
	Mon, 18 Aug 2025 16:39:15 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 48k5tmpje6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:15 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 57IGdDfu31851052
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 18 Aug 2025 16:39:13 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9893A20043;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7DC2920040;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 40A66E05D2; Mon, 18 Aug 2025 18:39:13 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Daniel Axtens <dja@axtens.net>,
        Mark Rutland <mark.rutland@arm.com>,
        Ryan Roberts <ryan.roberts@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 0/2] mm/kasan: fix vmalloc shadow memory population issues
Date: Mon, 18 Aug 2025 18:39:11 +0200
Message-ID: <cover.1755528662.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.48.1
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=FcM3xI+6 c=1 sm=1 tr=0 ts=68a35734 cx=c_pps
 a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17
 a=2OwXVqhp2XgA:10 a=VwQbUJbxAAAA:8 a=7CQSdrXTAAAA:8 a=njq2mmYMnVxNw-6NPcsA:9
 a=a-qgeE7W1pNrGK8U0ZQC:22
X-Proofpoint-GUID: rdIg7Bn1EV5ou23bmQ4mIkst8l_YFpvM
X-Proofpoint-ORIG-GUID: 5LRYwOzw2RvagFJR-QQA6Mi1gd4gE_am
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODE2MDAxMSBTYWx0ZWRfX5onC88oUqhQC
 H6CqLLxjSkAUfiIeGXxUzZmW5PLQk++823B6wyrqoe4HgPmhWNK2EOjUVWLk/TTapXScABqO+Jh
 rXRgSexP136YlBSgmB+kKvvRXejCprjmuR1XiP7JEv6M6ZL+2xzUn5bu7LbMaWzkX2abRJGlece
 HtTSuJ3j/VayB9lBqYPVaHFDuELwDJwwmJtJIrxwWPR29J8laq0lAGfjyLnxBVhUx6WITxS4r4T
 tHcMI1YSERl3rJfkKs6O/E9fg3RDykGV+KEe4Ff7w+kk56ZH1hCCoLoKdBWk0D9EcXe5kZ0CcVz
 4+3oZE+2dZ67MGMAYfPx+qWai042aU5mHpKE92tRYVEC53rUeRf5/1R0wGlXNvwIDvJ6Qej7QIl
 YclZM7WR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-18_05,2025-08-14_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 bulkscore=0 malwarescore=0 priorityscore=1501 suspectscore=0 adultscore=0
 phishscore=0 clxscore=1011 impostorscore=0 spamscore=0 classifier=typeunknown
 authscore=0 authtc= authcc= route=outbound adjust=0 reason=mlx scancount=1
 engine=8.19.0-2507300000 definitions=main-2508160011
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=elRkxDAc;       spf=pass (google.com:
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

Hi All,

While working on the lazy MMU mode enablement for s390 I hit pretty
curious issues in the kasan code.

The first is related to a custom kasan-based sanitizer aimed at catching
invalid accesses to PTEs and is inspired by [1] conversation. The kasan
complains on valid PTE accesses, while the shadow memory is reported as
unpoisoned:

[  102.783993] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  102.784008] BUG: KASAN: out-of-bounds in set_pte_range+0x36c/0x390
[  102.784016] Read of size 8 at addr 0000780084cf9608 by task vmalloc_test=
/0/5542
[  102.784019]=20
[  102.784040] CPU: 1 UID: 0 PID: 5542 Comm: vmalloc_test/0 Kdump: loaded T=
ainted: G           OE       6.16.0-gcc-ipte-kasan-11657-gb2d930c4950e #340=
 PREEMPT=20
[  102.784047] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
[  102.784049] Hardware name: IBM 8561 T01 703 (LPAR)
[  102.784052] Call Trace:
[  102.784054]  [<00007fffe0147ac0>] dump_stack_lvl+0xe8/0x140=20
[  102.784059]  [<00007fffe0112484>] print_address_description.constprop.0+=
0x34/0x2d0=20
[  102.784066]  [<00007fffe011282c>] print_report+0x10c/0x1f8=20
[  102.784071]  [<00007fffe090785a>] kasan_report+0xfa/0x220=20
[  102.784078]  [<00007fffe01d3dec>] set_pte_range+0x36c/0x390=20
[  102.784083]  [<00007fffe01d41c2>] leave_ipte_batch+0x3b2/0xb10=20
[  102.784088]  [<00007fffe07d3650>] apply_to_pte_range+0x2f0/0x4e0=20
[  102.784094]  [<00007fffe07e62e4>] apply_to_pmd_range+0x194/0x3e0=20
[  102.784099]  [<00007fffe07e820e>] __apply_to_page_range+0x2fe/0x7a0=20
[  102.784104]  [<00007fffe07e86d8>] apply_to_page_range+0x28/0x40=20
[  102.784109]  [<00007fffe090a3ec>] __kasan_populate_vmalloc+0xec/0x310=20
[  102.784114]  [<00007fffe090aa36>] kasan_populate_vmalloc+0x96/0x130=20
[  102.784118]  [<00007fffe0833a04>] alloc_vmap_area+0x3d4/0xf30=20
[  102.784123]  [<00007fffe083a8ba>] __get_vm_area_node+0x1aa/0x4c0=20
[  102.784127]  [<00007fffe083c4f6>] __vmalloc_node_range_noprof+0x126/0x4e=
0=20
[  102.784131]  [<00007fffe083c980>] __vmalloc_node_noprof+0xd0/0x110=20
[  102.784135]  [<00007fffe083ca32>] vmalloc_noprof+0x32/0x40=20
[  102.784139]  [<00007fff608aa336>] fix_size_alloc_test+0x66/0x150 [test_v=
malloc]=20
[  102.784147]  [<00007fff608aa710>] test_func+0x2f0/0x430 [test_vmalloc]=
=20
[  102.784153]  [<00007fffe02841f8>] kthread+0x3f8/0x7a0=20
[  102.784159]  [<00007fffe014d8b4>] __ret_from_fork+0xd4/0x7d0=20
[  102.784164]  [<00007fffe299c00a>] ret_from_fork+0xa/0x30=20
[  102.784173] no locks held by vmalloc_test/0/5542.
[  102.784176]=20
[  102.784178] The buggy address belongs to the physical page:
[  102.784186] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0=
x0 pfn:0x84cf9
[  102.784198] flags: 0x3ffff00000000000(node=3D0|zone=3D1|lastcpupid=3D0x1=
ffff)
[  102.784212] page_type: f2(table)
[  102.784225] raw: 3ffff00000000000 0000000000000000 0000000000000122 0000=
000000000000
[  102.784234] raw: 0000000000000000 0000000000000000 f200000000000001 0000=
000000000000
[  102.784248] page dumped because: kasan: bad access detected
[  102.784250]=20
[  102.784252] Memory state around the buggy address:
[  102.784260]  0000780084cf9500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[  102.784274]  0000780084cf9580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[  102.784277] >0000780084cf9600: fd 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[  102.784290]                          ^
[  102.784293]  0000780084cf9680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[  102.784303]  0000780084cf9700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[  102.784306] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

The second issue hits when the custom sanitizer above is not implemented,
but the kasan itself is still active:

[ 1554.438028] Unable to handle kernel pointer dereference in virtual kerne=
l address space
[ 1554.438065] Failing address: 001c0ff0066f0000 TEID: 001c0ff0066f0403
[ 1554.438076] Fault in home space mode while using kernel ASCE.
[ 1554.438103] AS:00000000059d400b R2:0000000ffec5c00b R3:00000000c6c9c007 =
S:0000000314470001 P:00000000d0ab413d=20
[ 1554.438158] Oops: 0011 ilc:2 [#1]SMP=20
[ 1554.438175] Modules linked in: test_vmalloc(E+) nft_fib_inet(E) nft_fib_=
ipv4(E) nft_fib_ipv6(E) nft_fib(E) nft_reject_inet(E) nf_reject_ipv4(E) nf_=
reject_ipv6(E) nft_reject(E) nft_ct(E) nft_chain_nat(E) nf_nat(E) nf_conntr=
ack(E) nf_defrag_ipv6(E) nf_defrag_ipv4(E) nf_tables(E) sunrpc(E) pkey_pckm=
o(E) uvdevice(E) s390_trng(E) rng_core(E) eadm_sch(E) vfio_ccw(E) mdev(E) v=
fio_iommu_type1(E) vfio(E) sch_fq_codel(E) drm(E) loop(E) i2c_core(E) drm_p=
anel_orientation_quirks(E) nfnetlink(E) ctcm(E) fsm(E) zfcp(E) scsi_transpo=
rt_fc(E) diag288_wdt(E) watchdog(E) ghash_s390(E) prng(E) aes_s390(E) des_s=
390(E) libdes(E) sha3_512_s390(E) sha3_256_s390(E) sha512_s390(E) sha1_s390=
(E) sha_common(E) pkey(E) autofs4(E)
[ 1554.438319] Unloaded tainted modules: pkey_uv(E):1 hmac_s390(E):2
[ 1554.438354] CPU: 1 UID: 0 PID: 1715 Comm: vmalloc_test/0 Kdump: loaded T=
ainted: G            E       6.16.0-gcc-ipte-kasan-11657-gb2d930c4950e #350=
 PREEMPT=20
[ 1554.438368] Tainted: [E]=3DUNSIGNED_MODULE
[ 1554.438374] Hardware name: IBM 8561 T01 703 (LPAR)
[ 1554.438381] Krnl PSW : 0704e00180000000 00007fffe1d3d6ae (memset+0x5e/0x=
98)
[ 1554.438396]            R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:2 PM:=
0 RI:0 EA:3
[ 1554.438409] Krnl GPRS: 0000000000000001 001c0ff0066f0000 001c0ff0066f000=
0 00000000000000f8
[ 1554.438418]            00000000000009fe 0000000000000009 000000000000000=
0 0000000000000002
[ 1554.438426]            0000000000005000 000078031ae655c8 00000feffdcf9f5=
9 0000780258672a20
[ 1554.438433]            0000780243153500 00007f8033780000 00007fffe083a51=
0 00007f7fee7cfa00
[ 1554.438452] Krnl Code: 00007fffe1d3d6a0: eb540008000c	srlg	%r5,%r4,8
           00007fffe1d3d6a6: b9020055		ltgr	%r5,%r5
          #00007fffe1d3d6aa: a784000b		brc	8,00007fffe1d3d6c0
          >00007fffe1d3d6ae: 42301000		stc	%r3,0(%r1)
           00007fffe1d3d6b2: d2fe10011000	mvc	1(255,%r1),0(%r1)
           00007fffe1d3d6b8: 41101100		la	%r1,256(%r1)
           00007fffe1d3d6bc: a757fff9		brctg	%r5,00007fffe1d3d6ae
           00007fffe1d3d6c0: 42301000		stc	%r3,0(%r1)
[ 1554.438539] Call Trace:
[ 1554.438545]  [<00007fffe1d3d6ae>] memset+0x5e/0x98=20
[ 1554.438552] ([<00007fffe083a510>] remove_vm_area+0x220/0x400)
[ 1554.438562]  [<00007fffe083a9d6>] vfree.part.0+0x26/0x810=20
[ 1554.438569]  [<00007fff6073bd50>] fix_align_alloc_test+0x50/0x90 [test_v=
malloc]=20
[ 1554.438583]  [<00007fff6073c73a>] test_func+0x46a/0x6c0 [test_vmalloc]=
=20
[ 1554.438593]  [<00007fffe0283ac8>] kthread+0x3f8/0x7a0=20
[ 1554.438603]  [<00007fffe014d8b4>] __ret_from_fork+0xd4/0x7d0=20
[ 1554.438613]  [<00007fffe299ac0a>] ret_from_fork+0xa/0x30=20
[ 1554.438622] INFO: lockdep is turned off.
[ 1554.438627] Last Breaking-Event-Address:
[ 1554.438632]  [<00007fffe1d3d65c>] memset+0xc/0x98
[ 1554.438644] Kernel panic - not syncing: Fatal exception: panic_on_oops

This series fixes the above issues and is a pre-requisite for the s390
lazy MMU mode implementation.

test_vmalloc was used to stress-test the fixes.

1. https://lore.kernel.org/linux-mm/5b0609c9-95ee-4e48-bb6d-98f57c5d2c31@ar=
m.com/

Thanks!

Alexander Gordeev (2):
  mm/kasan: fix vmalloc shadow memory (de-)population races
  mm/kasan: avoid lazy MMU mode hazards

 mm/kasan/shadow.c | 22 ++++++++++++++--------
 1 file changed, 14 insertions(+), 8 deletions(-)

--=20
2.48.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
over.1755528662.git.agordeev%40linux.ibm.com.
