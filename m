Return-Path: <kasan-dev+bncBCM3H26GVIOBBD6S6SVAMGQELBVWOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 846587F38A1
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:56 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-7a95b842954sf610938239f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604175; cv=pass;
        d=google.com; s=arc-20160816;
        b=q5jk4FfGDm3hl3QU57eX02MJjWNa+AqcLc0LIAWE0Pzgg2jyrd3nIJYyI5+DrDNMiB
         RvXWCb1+bMSO4wI1mslj3XB033esfsuxUzz7HI/Jwny/q63t6qBiiq5xGZaNhVCqwHLK
         4QSyMAmVjPcC6IHT8TSM3dfHnN+9GfzAR4w7S8j907u//E7QZe8osVg6LCZb1vWGcIJp
         67j2hL2B7octpE/4I0lcd6IgnN7m9cRBhiRLExcji1QpfDQ1copyeT4Iu9tNhgI13DfC
         4HyBBn3bFjG7FlqyqT7+M9JIZdm+ZHiY+2tC8WpKOgWjLFZu2/Vmh2QlrBDmnPZmpzIF
         oHDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Yn9mRLg/zjVUun9yAxsmnWwA71OTBbt4KTSl7d97epM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=TTCox5fUjqIZmDkeeAE9HcHEe3N3PvJb67eSkWiSvRl3brNVo6uXGPLerR4PLMk6Ih
         vQHE1SC1JcPs0fTWld53CMQhTP2f8qZ2JET39YJlyq6tV0rTot4nSQ+CsdVpjdDcqQma
         22ptGr3WU6PV+Crz95JhMWomHycp0Sn7d0Gff9s9zxiuNyqGoQdDe74giWp34AL/4myt
         runCx69pwlt7tM/cQsmGIhxhesbIjumr+xvJCyLj7Ms5vvBQMXhlEvk8jWIjrFCZSd4s
         ZCjCu1Hy9znUXlzeOOHkdhS65ojWVAl4ao1IahpNaZUXkMCE6Luxu5whRZDv0hGr6TzI
         i7oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fzSIGqMv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604175; x=1701208975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Yn9mRLg/zjVUun9yAxsmnWwA71OTBbt4KTSl7d97epM=;
        b=dwCLXzjDPyNeUOseXx2/Nze2ItW4ofsSVw0+k+CNYLykDeY9vdXkiWGn6jR9YXDZkd
         msbR7iInm3kTIUnLkMShC8iMceaH39/XWPXrZTsRqTrKC3djfUIK0Gn6OY7ROLUSpUi1
         6gxLsWm2x0l/nCdx5/nJiEDQ3yiDjay6CChP+H+pfF+ZOL7XjU+C3u2XIi43OUVw850F
         KHPe7Ve6KbpUCfOlCOzEsXsVIWOY9rETkVy/JCO/0g3V0rxwOfCV7PQGLmeWiqOViwIP
         eoAXVvcIXHk3M6Y3SRLoX9b+uuDFf/zikiwutDsoTA3sf6DGHv+xdTxdg2RlLWwYd5E6
         FN6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604175; x=1701208975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Yn9mRLg/zjVUun9yAxsmnWwA71OTBbt4KTSl7d97epM=;
        b=H26AIJP4cpxHZiRfawyczPn5daiUA1tJjlV26CSu89xppEsz20v+uYF/wI0+k69eul
         CRs+nOzp3S36Q1e/0BxYmdnQooHf9N4JYQBqyZx3VE0YPZK++4sAU8/KMtbXP1m3eexN
         kZDNL4WwaN2JZT8dvfmHx7kNgABcTKCaYOqG1BZAafQ8zvsyQyN0XUd1QVZckQPtAxBJ
         RoismcI7J3vrSbxK0zEbyOyrrc89Gr2NqWORCobPW0hpGFN3iSvURLNWl9a0y0Nus9Ew
         9gk7yNDqGLkR2L1UJL82BNV6qRv4kd0rrTSQe9C/yz9LLVk0fNnM30HMxin9I5IzV4/s
         xhDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzITBZPrXKKLIkkYW8arEgqSa3AF1duZd8yQ2/A3Lkw/I/PqI1T
	E+ZmcFqBCYck25a6Ga6tMJ0=
X-Google-Smtp-Source: AGHT+IELJbxLuGzbNqSs8vUVlnV9EvO6WjsHMpjVbio+/1CX+/ONWUDIoixp2H4GtuHCpfEEb2vC+w==
X-Received: by 2002:a05:6e02:5c2:b0:35b:2908:a17b with SMTP id l2-20020a056e0205c200b0035b2908a17bmr242823ils.31.1700604175360;
        Tue, 21 Nov 2023 14:02:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2611:b0:35a:a617:5f3f with SMTP id
 by17-20020a056e02261100b0035aa6175f3fls3788996ilb.0.-pod-prod-09-us; Tue, 21
 Nov 2023 14:02:54 -0800 (PST)
X-Received: by 2002:a6b:5c01:0:b0:7b0:1dbf:291a with SMTP id z1-20020a6b5c01000000b007b01dbf291amr211359ioh.16.1700604174722;
        Tue, 21 Nov 2023 14:02:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604174; cv=none;
        d=google.com; s=arc-20160816;
        b=GWS1fBkfgguktYoVpVLdBjzRoEkjhLlM1MLQvBro8wKBeSzaVzwPj0cvr7zSsHgxZA
         YYN4xK69qU/vSPYpyyUNrmA9izgQJey+zLYKvfwG+CKgCsSpLhz127040zKHIxj8jRKv
         Q0xl42W3gJYEjRHJQhXtDwype9/A5C7WUFYhd4sYnTx1TJVpE7Zl1YHTvz2uPZD8apJB
         xP4FL/6LBP06VA/4oD9EkJVYiP0Wa7N/aSKgkXG/6Z92C/voNVJOnIrG3cIxzboQIOCT
         85Wr2SGEI9yq+uK4bJmd803VChOwAWPjFrMWzMhn6oL08E2akCDd0pLWGxB7arjBAXri
         oe3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hyzSs9QF4Fbrzmaz17PByc3Grb3VWKov5aR8cjL1QZg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tWTf3t4G7l0Xhg4Yvc68tIqt+O8vou/fUa7MluW26m0KfKTj+pDKLNqrW2ySRC1zXy
         BO/NjA56fAi745zqUc1H/k/gR9lx1FOBLmH7uhSdC1K3Msx0ohqZnjfO3j+7HHGdf0jD
         yU0P5lnjHJSdgBvhXCZ1jpW2S0hNqWmnaWi8T3mKEcZx0+UxULIwoArpmlP4TfBrzMa8
         7HSfNuHXGnzdYv2u4A22O2e3WQfBw9NhsuXfaVvopt1e7b8jrXoJ266jRxabXH4jXLgF
         KCE1XiALYipn+SgGx3R59fuPaNMZnx52g2QP9n4qtGxCo6K3DvafRrk4aEk8+K4mptrT
         AFgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fzSIGqMv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ba44-20020a0566383aac00b00439ca012a0bsi873108jab.6.2023.11.21.14.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:54 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLv6sO004888;
	Tue, 21 Nov 2023 22:02:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85fd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:50 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM27Qv024217;
	Tue, 21 Nov 2023 22:02:49 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85eb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:49 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnYvC010672;
	Tue, 21 Nov 2023 22:02:48 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujsg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:47 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2i3K37749398
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:44 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C49CA2005A;
	Tue, 21 Nov 2023 22:02:44 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5CA7C20065;
	Tue, 21 Nov 2023 22:02:43 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:43 +0000 (GMT)
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
Subject: [PATCH v2 22/33] s390: Use a larger stack for KMSAN
Date: Tue, 21 Nov 2023 23:01:16 +0100
Message-ID: <20231121220155.1217090-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: KYXpu23BM31nVkVFCprLxl_MgonXVagY
X-Proofpoint-ORIG-GUID: aXlTyuZpUN7e8h_8crzmxsB4goXciuqQ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=886 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fzSIGqMv;       spf=pass (google.com:
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

Adjust the stack size for the KMSAN-enabled kernel like it was done
for the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double
the stack size"). Both tools have similar requirements.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Makefile                  | 2 +-
 arch/s390/include/asm/thread_info.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/s390/Makefile b/arch/s390/Makefile
index 73873e451686..a7f5386d25ad 100644
--- a/arch/s390/Makefile
+++ b/arch/s390/Makefile
@@ -34,7 +34,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_DEBUG_INFO_DWARF4), $(call cc-option
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
diff --git a/arch/s390/include/asm/thread_info.h b/arch/s390/include/asm/thread_info.h
index a674c7d25da5..d02a709717b8 100644
--- a/arch/s390/include/asm/thread_info.h
+++ b/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-23-iii%40linux.ibm.com.
