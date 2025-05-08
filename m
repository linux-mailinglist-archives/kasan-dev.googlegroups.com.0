Return-Path: <kasan-dev+bncBCVZXJXP4MDBBF7Z6LAAMGQE66GBEEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B2A2AAFC9F
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 16:15:54 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3da707dea42sf23210225ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 07:15:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746713752; cv=pass;
        d=google.com; s=arc-20240605;
        b=MchGrLGyNjE7O66wodWQNYCvQlUIJigNVInjVNe9QA6wW9eF2n6luWRB6o9Rdw8RpZ
         9ZgOUP4V0VD8IvT/5JAvCGcZNhFyNfrcY5fYH3+LcRGeIINjJoMMHiGHMmD0hyhQNdW0
         MRx2QRQLh5M5BAPeEl/jlRaHu9Gd9uGxN7lVZ2vCKEiX7eUbJuL/zeSSaRZ9EzC6VUEK
         ERk2tX4+JmK65C9y4S947qQVkvBxPDjKqOJ1LUr+VyQMPi1hBLhw2Q77cj5EJhjQd9xd
         Ir1Tuz7RJXTYPtamrnaHrUf2pSFsad/Rq7zWbuH8S222RJo5cosOMtGyO2REuTH8rWmW
         2c0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UpMlI6h2kzUr5T9FGmEoBtXq7+g+STF15XXtroYCzUM=;
        fh=jRD96ptDmiPMsqI53iytyRkmUQly1qlUBtyekFVsBVc=;
        b=h9VIVxCjpzKiasBCmF2tZbG+lnJS8DQw1azKO36cpIogs+K0yAena61/wTYcojSg1P
         aaJ33orvW1e2qN+aWqlpuMNIP5eSs6YOTghY1JhOv0yMkK7SfPKVuhamKZ4rwFQAN4il
         Q96K/94qESXv4drafWi4O/k3S7C6N0YWb9ThZ4YfurtWpQjVxVdbklGfDHuRcP0/iKRp
         /9Qi/uM+RYdbmJ5np5NhAHMnyOjdxDGhj2vG5h0lYfCAoHx7F6ePDv0VBJFOGu0aErJR
         zca4Bhi2sUV90QOsM7ocSPt4exGT/UHVhEw1xs/meOh+g6LZF6q0vUA0+J9p/5BLtk9t
         wIkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KCTxDK7Y;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746713752; x=1747318552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UpMlI6h2kzUr5T9FGmEoBtXq7+g+STF15XXtroYCzUM=;
        b=hVJddvjHZCBiwER1nq0uImz1qOM8qqgeYuvOM0mcjEfyKnnbTL/42I4gEE7WHUavcd
         LHgnDmNWJf+iWXIDb+mDy665iBy2M9ct0u8K2Ba7ALQdM448lz3F2rFfRxbXBbbdOVpj
         wgoD+SnANjlBAyeZBuy51u7ZWU6c2i34JGiE8PJcnwy6vU3/e0ZsP6Vdq8kpmdSyQQan
         ZFE7t6DNDWKuIN+in+8RESOuLhNbyyy5uiBVCyXS5Zglveo59Fx1/5cBcc1zEAaEVdCG
         yjtviCZwfNFX2L6YyX+1J+x+2acGvBnYmOfkEt1ov/BspbDkMLxuOsbTzg3dTeL4bccL
         bavA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746713752; x=1747318552;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UpMlI6h2kzUr5T9FGmEoBtXq7+g+STF15XXtroYCzUM=;
        b=qrLl5YUG7IbsP603HKDMJQ+loVIVa4YMNtJ/E5uR9H0BkC1rOlAfuJ9VshIXZb8uwy
         IIe46Q60vKFwjYIpAosQ9NAQSdiptHNf2FUYfmxJ6LZJhomqqpCGD7u0catDsvnEMUlT
         RMr58X6ycW7KLXkpHF1oKTi5pME4Qotdx3RXSBM3OBU0jHmXZaZeLmAa4Q9Bse/kc4vZ
         T6sSdZH7ErYG6vQESuOMATxUehY6OGWtxE/gHS69TKHwxtqG81NUTgAz8Iri64jTtMRN
         gRtX4jXbnr/laODvTXHIIpIpxheD48N+Gi8CErlaPp/iCBH0s2E8Jje7xRKqA2HX85y6
         CkUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLGT/+0SWRDcRJiCd++Hr+KLdfb2EhdsSUTw6qgobz1NB1cKz9uf70eW66MCyys004vcND0g==@lfdr.de
X-Gm-Message-State: AOJu0YypNX+IhtI4tJnAdx9s0UimblkBLfUJguFDvxeiCaUz3rYaxEN0
	sp9YRM/AONzhChR9hkzBECuT0kRMzCYWySDbFb9AR6HN4986Np1E
X-Google-Smtp-Source: AGHT+IEnKjuLAFhot3iECQBvUDKr5B9TwRlSIbiKcKnN+2F6KjAgppqVooOhH3Wc5IyrLCFdttrQSQ==
X-Received: by 2002:a05:6e02:1d97:b0:3d8:1e96:1f0 with SMTP id e9e14a558f8ab-3da785ae8f9mr53117375ab.20.1746713752201;
        Thu, 08 May 2025 07:15:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHbkqtoDmyzR1yGvQIOdnrIlXRZPeag5lqnOr01W91T8g==
Received: by 2002:a92:c711:0:b0:3da:7341:8c06 with SMTP id e9e14a558f8ab-3da784b6993ls9389195ab.0.-pod-prod-08-us;
 Thu, 08 May 2025 07:15:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0G6V7181ATblMdTH7k4oUMwHES72A1WrI/lajLloQ8zh9kT4Sb0xiXPcD37fnDKYgVEA6Ri0yAjk=@googlegroups.com
X-Received: by 2002:a05:6602:6d02:b0:867:4f85:5262 with SMTP id ca18e2360f4ac-86754fcc72cmr427787039f.1.1746713751282;
        Thu, 08 May 2025 07:15:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746713751; cv=none;
        d=google.com; s=arc-20240605;
        b=g3/6ylWV9xQ1NthzokmFXvQHH388Di0xl+ievI4ot8u7ATqjXWbdgBGyq8d/I5QjWF
         gptVwFH/3B5FSyIH4VjfQPHk33+XPR6o0QKIYdDaC34DEgFyVKd24nf6zFcasFhz4N9D
         cAJZ3psFYXuxgNpb9GxvVwzDkd6nOC2hnlkD1Lo/IGiVhC1dA4OlSba1Ab2iOfX8hMHB
         sT9QfN/jykqM7Fuj6Jlgz/jy0Pr692+YG+vhtcyo741lTwrQ1mnXhZyha02ydHgBuvKp
         3naFeZGgLoVH6+sRlOgVYyr2NyyDuoamzfRQbzsNtZoQ16kvxtJ3d5GLuVPuzbFOkTpk
         zbnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=f+m+xTEPHEMKdR3eEwuuaViB2V+AZubNzaEp9oZeZwc=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=kzGeHs5RTh431Kck9t6m5Fz28P/CXqzlMK0RIdJrnDqf7Q4+flQDUB+9eFsKhI5/y4
         BFwcEibpGAeV40Btm0MNumx5w4zAayIQfSJuwPd88RW/y1sfiDFreOsepQaC89cTaW71
         T69c0xZ+9uJ/vFdpHpVwbKNs1qKL4S3A6LIvcjMM9vHODQ0mAegWCt0CpRCcUKFUNMC4
         W+luSKEEfGYhRwpJLOad0E6W+yTUksvH+l2GGVBMQ7ZrRyQtEGJqsOZRDkJmJIkTNsQ0
         wW6BGaBP0v2t8IlZOm8He++JaflEXZAq4BAWjX5PAygaDbgz2/gDCXMPDTGU+GQ0E6ug
         Q+bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KCTxDK7Y;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-864aa2b85cfsi64893139f.1.2025.05.08.07.15.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 May 2025 07:15:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 548C0mJj008209;
	Thu, 8 May 2025 14:15:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ghg2bfkk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:49 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 548E9AAY009667;
	Thu, 8 May 2025 14:15:49 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ghg2bfkf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:49 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 548Dux4V002826;
	Thu, 8 May 2025 14:15:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46dxfp64hj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 08 May 2025 14:15:48 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 548EFk6D51380482
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 8 May 2025 14:15:46 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A4EBB2004B;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 91C8320043;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu,  8 May 2025 14:15:46 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 3C41DE05EF; Thu, 08 May 2025 16:15:46 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v6 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Thu,  8 May 2025 16:15:45 +0200
Message-ID: <cover.1746713482.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: AKtVaM5uVmYE74Iy9WuCxbmTNkixOYKg
X-Authority-Analysis: v=2.4 cv=VJLdn8PX c=1 sm=1 tr=0 ts=681cbc95 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=dt9VzEwgFbYA:10 a=c7xF9FPc4WhyVLjLziMA:9 a=zZCYzV9kfG8A:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA4MDEyMCBTYWx0ZWRfX9evs2pW/vmvI uaQ9MXcNNnG2WrBEb/SSaxVUazPyJ/p7AwWxdoy3r7C0qY5G1W9mNyZvHZ/2+16PzTw37K//HUL zutS8z1JcDbiKXsTOs7Az7YeVzta+i1EnxTq8wWyxHn9OsGG/I+NLv6KckZXDhsXX2H7YbgkIuT
 5918/oA6NCLqzyHc4/2KK+mfT/NizNO68J8Bvza61/U5gHBS1/+WYlTryMGeU5xYzA82hvwW0vV Tsm/hhGOcwaAoVyC2LxfQwzirkBo+/kHOGri10XMD0l3kYZFnGHoAro37wu/tDKSMXdYx+uWhO3 XpA+s48NO/qIBXjA3u/s2MPyxBrZkWktG4fAeE/2ipJcinuSilGhpbF1u439yuV1+sbY9wb6Fdu
 kEKyN2DpLAn7xPMQdiZKFY2jsRZzWaaW7+FdP0pEDMdqsEC2Rj8lxP57EnsdQIIhuba4Nbh2
X-Proofpoint-ORIG-GUID: PNKKMLgrIrAIgjC9ptEXSfm69CYYsH-h
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-08_05,2025-05-07_02,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 mlxlogscore=608 malwarescore=0 lowpriorityscore=0 spamscore=0 adultscore=0
 priorityscore=1501 clxscore=1015 bulkscore=0 impostorscore=0 mlxscore=0
 classifier=spam authscore=0 authtc=n/a authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505080120
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KCTxDK7Y;       spf=pass (google.com:
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

Chages since v5:
- full error message included into commit description

Chages since v4:
- unused pages leak is avoided

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 63 insertions(+), 14 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1746713482.git.agordeev%40linux.ibm.com.
