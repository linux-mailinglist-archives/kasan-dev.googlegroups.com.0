Return-Path: <kasan-dev+bncBCM3H26GVIOBBRVFVSZQMGQEH5RTZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CC149076D7
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:52 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1f844f8a565sf12162455ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293190; cv=pass;
        d=google.com; s=arc-20160816;
        b=hfSxWg3s70QazKjlzy7XbHgERsqZnfR1nHF+9HpFQAw/77dGIgjUt3YNWH6OFDxxg+
         fGQDReobfuZdKGwDHidOO5L6uXhdR6VsnO3cxwUc2z0qTrklkqAkZIw1Owg8RO9retWk
         0a3lam9FuLda7yw0dC2596OqbJSXh2OKp5USBs2YXlwHk54tBUYeG9+d81HwDLjYYF9G
         6wJhliIevEmHqHgAduPF/7O6xemsrAxi20K8Ammp+9m3gig1RFUFsT4h+af88PBU2SIv
         o5n/aZnU8F8tJIs5pUA6EVi3vlzEzF1oW/t8+UWaHd6gnOoUQFbeT4s5Ran5LmiPCO0y
         w+uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gXQl1WGtZDY6gWA4iua7SiNZzVPMJ6zy6yEVNG2lqQU=;
        fh=K0HTbeB9h0rHgl+WB/yLAoLNnqZ9eZSUFwYmwET2mOg=;
        b=Gn0VT3f/1iyf5R+NEPmXRp7+9BcYEsGhymSbn1fBjuB343RPrijRC/u2dYgqKzuRR0
         fQJUZJgnub0b7WluNijqi9hdc4v7FyvTYaDWzTWEovsyPj63ZUwUXefRTt1w4UBAVbxN
         a+wFToEkAnw9c9vOOjnIyZOBRApNN5UQRWsMnu8ZnQsfMXcdZJe7juMoy37BqPuW0QrU
         r9QW3v7eHsD7LD/JOpdXFV7jJD4EAvCRcpSxGWbmYfmTeyMEu6ulG2eNRVNgEb9pn7e6
         ftasp09D5r2RAfq5svI+YPvViV1KkSt6GAX3jJJCOsaZroa8qjJaghCtwJ3qkBhSYr47
         /qEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KekhLxm6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293190; x=1718897990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gXQl1WGtZDY6gWA4iua7SiNZzVPMJ6zy6yEVNG2lqQU=;
        b=DRX6MMBEISZQwdPk2pZUhz8CGk0MTTrp8T88dckoPjy8eRs1BWfz2mWujFpJEQJWnT
         XfBDxKI+HXm4s3jG48XO3AS1MwBh5o8mSTjU+w6OeQ8szmMVrQoKhfjCQlG/qaB2oBqQ
         Ubj/OAy+TxnbQgLLWsP4XaKme/swJOs8vloLNsZepM6KbEFOIU2MEdEgEAkp9+4+86Xi
         g+YJC7sHv/7UuyZ5+7sOVv+zKAq6ah3VQbImu7oam/Ej+2gMIckm70D4C9krgxr4hGoq
         gZHZ+JGXvlCt9fR5JFOFOagK6d0FeAmjlucgoZoWvufJItYsZM3I+cfojChLg0v4SfMP
         jooA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293190; x=1718897990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gXQl1WGtZDY6gWA4iua7SiNZzVPMJ6zy6yEVNG2lqQU=;
        b=aOgfuqEBca+K/oxJTuudjuO1JRUCOl4Tw65G4mjkvgh6qLEf+BoFUqex6Dx8dD5qIn
         Y6FejtIaDbK12oZwZmyqfCbhw7VNIrUR4hV4p5DE0XoKV/VkZ+ub6KyLrD5SXXASXVMM
         4Vrlv7W9WxG24wH+YO9cqKNsd4IXCWdUVtLFdSScIHlgdMVEvPiILYMHplTHj+ZWNFEu
         1ZP9fv6KeFQxTCbfksQoLG+zaGZg9ZLVtpzaE4GxqeY39E06TnXSzUpYBSKCnjKxTXtF
         aubZxlp750GeuOhUBoLh9REKw/eOuMu2VFdHI+lK2BwLkpjP3IvTzWLbcDRyTn2gGtGp
         ztew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXo4n8yMo32HsmjBlzOk5MROhD8oSUxY82WlCZOethGBcjBRvDrAT22tNl0HwTGvcnXKG4gdBmr5vM3/d4SBUVzEDY5GGVxAw==
X-Gm-Message-State: AOJu0YxG+yduAsF2x50mKPlMIs7ax6vXUFwEHo2mADE++XwOMSBQ0o5C
	YQRZrVM+N4ToExGgnpNGrMdFXtK7vhTo6NKYpUU75KgFqT4dfPlI
X-Google-Smtp-Source: AGHT+IHvabnDggGcP0GmwxPuHxZZQBKSAYsYLgSnLWWCo2r7l2HJWJQOHdh7qGPA0bpZDpyhjAPFOA==
X-Received: by 2002:a17:902:ea0a:b0:1f7:11c8:bdd3 with SMTP id d9443c01a7336-1f8627df7ccmr191415ad.29.1718293190470;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dacb:b0:1f7:34be:f997 with SMTP id
 d9443c01a7336-1f84d75fb78ls8966375ad.1.-pod-prod-01-us; Thu, 13 Jun 2024
 08:39:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVp2OCKOP4UEyttR3vSB5h2AHxQ65qAEG+G5k7qiY2lOS1NFGO8NHudSE/KX2O5XSz0adD7JveOYZIyKD7rjhoBAaxPOL0cU17nrw==
X-Received: by 2002:a17:902:d506:b0:1f7:1891:8c60 with SMTP id d9443c01a7336-1f8627ebb8dmr289335ad.35.1718293187798;
        Thu, 13 Jun 2024 08:39:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293187; cv=none;
        d=google.com; s=arc-20160816;
        b=FYEo0syPLya71yFxUbnn0o1MRX2bOmx6SvGNJI8ho1FXhwfR/h/+dA/WqS2x8qG84/
         ayY6Ilr/bn032CST6gXSoXPZHblBbHdsp9+UilH2bt6b2PrCnmUM6HANgc7y0EWV6d2p
         TUi0XNL8LsbU0rpNKIU6bwUe20Wy7Bai6tbPNiymcrwxoTPP06Y6ojHQA1stCbdCv3pA
         8p6QA/M3K1msvMJ4ejCYCUAabLF7BO2A94vYeOjsceSV4ZBp0ykV7dTJ0FftxMaRH9eS
         UAGR2bUfKW16XHfvgtG6HktA72S6G/1CeT2tY5pLGSvp/nG4WcKxltTFLHSZsu60lTBM
         7faQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A5/DP3QFUFkYA2+5kJImY20b3CDMSHPGwimqBdu525I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=J1rypMrpOLqA0nmUft4HMP+PoehtXvPAXYYpxaZ0vXa2rH3OiDDTl/HzUA1Py5JDEB
         ZQHcKCSZpgMXyK7dZCIocjepSeCe8KUsZi/UZd2apJnSbKtdW65/tn+aYukrYSEXs87D
         9sc5ToV62A5EO1O5FDx8/N/Oe0HQ/sLwk+sgVq8Wsy12IDM3nl/D8bq+kzAbnQObhw/k
         EZTCaMQTi3e8kXyjFslTDqBeXkzjfMaE+dWBCMVc+a7zG4ls8Pxi/701CrrICZyfT/Bk
         cdEvh4zcJUT0QK/4rdxD33l37vO+dWZ/QgQC7YXo+i8/4ZGb+uSpdOhNzvpRu2QfgDFY
         YPaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KekhLxm6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855ed583bsi574015ad.11.2024.06.13.08.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFRYAU002831;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11ymn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdfuc026422;
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11ymg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF9UJu004368;
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mq916b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:40 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdYVb43385236
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:36 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8819320063;
	Thu, 13 Jun 2024 15:39:34 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 12A2D20067;
	Thu, 13 Jun 2024 15:39:34 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:34 +0000 (GMT)
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
Subject: [PATCH v4 03/35] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Thu, 13 Jun 2024 17:34:05 +0200
Message-ID: <20240613153924.961511-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ohH4Wf6GBU_oLonoZfUiQF3dUEI7gZ3l
X-Proofpoint-ORIG-GUID: WaDxr-0abG3R8ki6jMioCFv3al33-FAR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 malwarescore=0 spamscore=0 suspectscore=0 clxscore=1015 lowpriorityscore=0
 phishscore=0 priorityscore=1501 mlxlogscore=999 mlxscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KekhLxm6;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index b4cb45255a54..9791fce5d0a7 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -946,6 +946,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-4-iii%40linux.ibm.com.
