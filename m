Return-Path: <kasan-dev+bncBCM3H26GVIOBBX4R2OZQMGQEN5XKTKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B679911767
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:13 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2c7ef1fcf68sf1087394a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929632; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCRZ38YONkbhixRViGuOz7EcqZiqup/iasIMnIkYXhHttCh5Iop5DOrDWlHgtCiL4H
         LiiLyFCvsm6eXbZeXKCyny2j/89ZjbqBjW+UiHe3fyKKo7OygUVdGpQG12K+gqbOFwYL
         /0L/xw7XbgTdCoL1tBLMRej3UieoXtTje31obaaXiRN8x8nPiGbr0cBumTbsdrVt2ANi
         hsKak2DR65RqxnNONJ4ncTyQJliEmi1ZYGBoiLug6Js8hc1mW2MIe2iYOJV2zOMUfXVp
         zMGWtytoGJV6Zk9s1nUKxgd9bEdmvW/tnWGt1ACIoKWM8MGp0DP/wSGglsXRD57k8DMF
         p5jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LidAtNJVqed0E67QQK15/qo2VQrgtz21E06gYjN6Zgw=;
        fh=n97ZyJTo/XKmodJwt7Qm7rjUmNFb9XGz1wXq5DSkEqA=;
        b=1IEPBiQzm6uJrRnT6bNgNPRmft+zpGUV9aGZ4Tr9E0QfU7EXQVaeE+0DLLWnJBwtyt
         4A9bMPc2XGW0wETpl6SVMTaG1tjL9oYMPUhxTG4dQV6WF9EETnp7Xcv+AS6sCYRfN4NL
         z/SULI6tmW2UWWmqg4MOGJl9ygBTKJI4QsT1X3h017LUGlU5knPJSgd3mrkjtzLEVfzB
         ONGd8hJyAm5TZLOjAMug07u8+X3JMBpu8Ec+0n9F7OG/fPsiB5aG1bPXxkKH1vsCI121
         XiPjKY3krgbQuMT7TpyDVv2f0dZQVQ2mVi6T5tcfO8tHVbAR64w6/CTw1Tk6osTmd1WM
         cPUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=CpVjcAR0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929632; x=1719534432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LidAtNJVqed0E67QQK15/qo2VQrgtz21E06gYjN6Zgw=;
        b=ZhPcdQzvCaw5RyV28FSB+zygwbkmI0qVlRytyJNkT8+A6j9rN9o3fYy5P0qKusW0gZ
         jmxGNc9/mA3r5zghFUccEK4fh+osFkQb3Z2FcJJDvXBKIdFxeveGjPIxhUSze0GawVHA
         ppcaA9Bg6RpNsOlk+PiChrWRHcat8PGZxvgd2uzUdCnvcf82hbtZN1sal60UlPWBX5PH
         G+oFf/psd0vg7vdkfleCDkcdvzw4X4h0+x/hW1y0hC+flJynng/6XOo+sa7DIrwX25Xd
         LRdiyHG7i78BjO/mVVYl02jAIh+i5zuR1kpZp//MmpKODNxV9rGA/PZ4dsQ3sMBW7TL9
         I+9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929632; x=1719534432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LidAtNJVqed0E67QQK15/qo2VQrgtz21E06gYjN6Zgw=;
        b=exT+mYFcMOp1Xv1DlhHoqg384DVNsZBGMwORiCFiQpaMSXvelsYuQZDYda19mWhe2Q
         cdx9w8nJe03LIHEmzC8kui/0gKmMhmA3eGncnvpiV1MmGaOkyDAz0re8d/GyXIpZe+KR
         kNBRhx+og044E6GOOztM1q7+zaVgwYTGLAYcgWFSvxiDQm399SLJy6DQYRgUK7Ax0IPH
         lRcchX14NZWn41JUNcsrIGJPO41qCptxfFxAkJEK9pEGlMdD+D99327VAyP1NvBHMChN
         /ILkADNu6TXqfLMG8SKT7tYXUkFnDlgVNjUmic1zDdectaoIjKb/ezJftwacgrhh1/YT
         iV/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmgahChHmLuuhJSNlAaAEmcQXyInYf9CYOL9X02ibM7jc64pkWE8KyORMbb1Cji1+t2cXoIdt32o7178oWaUoM+SDeya6eRw==
X-Gm-Message-State: AOJu0YxZ8KI8za9tkZE2fX2aIDVHF76cxNT5hkyeTDtDOnzsGUFyZ1La
	XS1SRecCZ2m1Y8xtFZyB0RJ4X6lWqXXd5zhCvKWGddwan2/NmXJE
X-Google-Smtp-Source: AGHT+IG/n6vnNMN0RvLVQ68A40IJoWB5n0m+N0/MCe5abG/dKzagAIixYJl/jL70/mKwuzVnFx++tA==
X-Received: by 2002:a17:90b:1241:b0:2c7:b1ad:6df0 with SMTP id 98e67ed59e1d1-2c7b5da57d0mr6553926a91.32.1718929631680;
        Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1952:b0:2c2:e667:d721 with SMTP id
 98e67ed59e1d1-2c7dfec0c54ls839574a91.1.-pod-prod-01-us; Thu, 20 Jun 2024
 17:27:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTJUttNu9cPUmYxzj/4WQuGiLMO0EdKIpuJVWGpNn/9K1C1urGcric4zi5T5bmdkeGDfO9Koj/whBz1nCNk+2Jbmyvl9aiZmCTTg==
X-Received: by 2002:a17:90a:7848:b0:2c8:633:4a37 with SMTP id 98e67ed59e1d1-2c806334bbdmr2165296a91.13.1718929630582;
        Thu, 20 Jun 2024 17:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929630; cv=none;
        d=google.com; s=arc-20160816;
        b=A+3icd3zu+3YIdNG68ZOzQXQDmGJeQF//+dwX7/tQffCJsmBoI2+/TrMcezs0pdNV+
         m5lvxck+QNPG9k0f5etJC1jl9KqXyF/I3sVoYSu20MfqV02ZuxhMupxE4UUjjxvp4hUT
         6Dz2imxknTCLdhuQ46o+GR3UPfwdQvyBuQhaJCtAuEA/FPZgeChzJK6P5wC2eEGLuayE
         47abprgpXRST9lXZlDQkGnHuw0c6/R3m3m5V6rsS7oX1b/AzbqEBQKy+EHvSGTBFQaLC
         oLxV3y4I+2qiDvD+/30foBgud9F+x8MQJuSZF6JZn8hQQFMP+Ng0qmxZMfJWEwTwR/1v
         Kkbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hop8BCpVSniaFM1MpaXvqCFGVqZnzKhq9StiRXmewRE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=OFXspxXtPLbIsNjnErqksYT77+ZW6Snb9XV5fbh+u5wOBqlbG+2YQjwV+/GNHYl0AB
         i8RiOgKT7nd5R38e8z2o7y0I66n3WpFfnHxJBkCikw/Fu5T/uJQZy+6vKcbSG4pXWTRI
         FuYT46JGUBHKj5jwg/vKKdvHiBTCXLVWSaSe2B5gdyuKO0ymG2mT1fnpRkHazsig2cAd
         P827Lz5/l9gOqQ02BGy/yO8W2KlDq2TTtxgEaEtT1qSZtdfT+oJEXQngZQWi+6OqrbaC
         ZWO3o6BKZkVJzcJLqfpfxFAWHaais7/cJ+xxddd0n7c43INt+OwJLF5ZzQdSh8YDXltq
         0Thg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=CpVjcAR0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e4e0ddecsi144206a91.1.2024.06.20.17.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QZfW022585;
	Fri, 21 Jun 2024 00:27:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7t0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:06 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R5ij023521;
	Fri, 21 Jun 2024 00:27:05 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7sw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:05 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLcZY4030993;
	Fri, 21 Jun 2024 00:27:05 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn3u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:04 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QxY857213382
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:01 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2AC832004B;
	Fri, 21 Jun 2024 00:26:59 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0AA3520043;
	Fri, 21 Jun 2024 00:26:58 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:57 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH v6 32/39] s390/ptdump: Add KMSAN page markers
Date: Fri, 21 Jun 2024 02:25:06 +0200
Message-ID: <20240621002616.40684-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: D7iiuOSKyPIFLwMOccTbCBPFEbLUtDDO
X-Proofpoint-GUID: opa2CPcd6-_OVWf6pOKSPr_YpfqQEXBE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 phishscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999
 lowpriorityscore=0 clxscore=1015 suspectscore=0 mlxscore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=CpVjcAR0;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

Add KMSAN vmalloc metadata areas to kernel_page_tables.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/mm/dump_pagetables.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/arch/s390/mm/dump_pagetables.c b/arch/s390/mm/dump_pagetables.c
index ffd07ed7b4af..f51e5d0862a3 100644
--- a/arch/s390/mm/dump_pagetables.c
+++ b/arch/s390/mm/dump_pagetables.c
@@ -36,6 +36,16 @@ enum address_markers_idx {
 	VMEMMAP_END_NR,
 	VMALLOC_NR,
 	VMALLOC_END_NR,
+#ifdef CONFIG_KMSAN
+	KMSAN_VMALLOC_SHADOW_START_NR,
+	KMSAN_VMALLOC_SHADOW_END_NR,
+	KMSAN_VMALLOC_ORIGIN_START_NR,
+	KMSAN_VMALLOC_ORIGIN_END_NR,
+	KMSAN_MODULES_SHADOW_START_NR,
+	KMSAN_MODULES_SHADOW_END_NR,
+	KMSAN_MODULES_ORIGIN_START_NR,
+	KMSAN_MODULES_ORIGIN_END_NR,
+#endif
 	MODULES_NR,
 	MODULES_END_NR,
 	ABS_LOWCORE_NR,
@@ -74,6 +84,16 @@ static struct addr_marker address_markers[] = {
 #ifdef CONFIG_KASAN
 	[KASAN_SHADOW_START_NR]	= {KASAN_SHADOW_START, "Kasan Shadow Start"},
 	[KASAN_SHADOW_END_NR]	= {KASAN_SHADOW_END, "Kasan Shadow End"},
+#endif
+#ifdef CONFIG_KMSAN
+	[KMSAN_VMALLOC_SHADOW_START_NR]	= {0, "Kmsan vmalloc Shadow Start"},
+	[KMSAN_VMALLOC_SHADOW_END_NR]	= {0, "Kmsan vmalloc Shadow End"},
+	[KMSAN_VMALLOC_ORIGIN_START_NR]	= {0, "Kmsan vmalloc Origins Start"},
+	[KMSAN_VMALLOC_ORIGIN_END_NR]	= {0, "Kmsan vmalloc Origins End"},
+	[KMSAN_MODULES_SHADOW_START_NR]	= {0, "Kmsan Modules Shadow Start"},
+	[KMSAN_MODULES_SHADOW_END_NR]	= {0, "Kmsan Modules Shadow End"},
+	[KMSAN_MODULES_ORIGIN_START_NR]	= {0, "Kmsan Modules Origins Start"},
+	[KMSAN_MODULES_ORIGIN_END_NR]	= {0, "Kmsan Modules Origins End"},
 #endif
 	{ -1, NULL }
 };
@@ -306,6 +326,16 @@ static int pt_dump_init(void)
 #ifdef CONFIG_KFENCE
 	address_markers[KFENCE_START_NR].start_address = kfence_start;
 	address_markers[KFENCE_END_NR].start_address = kfence_start + KFENCE_POOL_SIZE;
+#endif
+#ifdef CONFIG_KMSAN
+	address_markers[KMSAN_VMALLOC_SHADOW_START_NR].start_address = KMSAN_VMALLOC_SHADOW_START;
+	address_markers[KMSAN_VMALLOC_SHADOW_END_NR].start_address = KMSAN_VMALLOC_SHADOW_END;
+	address_markers[KMSAN_VMALLOC_ORIGIN_START_NR].start_address = KMSAN_VMALLOC_ORIGIN_START;
+	address_markers[KMSAN_VMALLOC_ORIGIN_END_NR].start_address = KMSAN_VMALLOC_ORIGIN_END;
+	address_markers[KMSAN_MODULES_SHADOW_START_NR].start_address = KMSAN_MODULES_SHADOW_START;
+	address_markers[KMSAN_MODULES_SHADOW_END_NR].start_address = KMSAN_MODULES_SHADOW_END;
+	address_markers[KMSAN_MODULES_ORIGIN_START_NR].start_address = KMSAN_MODULES_ORIGIN_START;
+	address_markers[KMSAN_MODULES_ORIGIN_END_NR].start_address = KMSAN_MODULES_ORIGIN_END;
 #endif
 	sort_address_markers();
 #ifdef CONFIG_PTDUMP_DEBUGFS
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-33-iii%40linux.ibm.com.
