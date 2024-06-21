Return-Path: <kasan-dev+bncBCM3H26GVIOBBWMR2OZQMGQEA5JR73A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D911591175E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:06 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6b51725a7ebsf9914586d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929626; cv=pass;
        d=google.com; s=arc-20160816;
        b=rw5SNieu6EmJMmlzeyb9N9m+UbgUE6DbikjI1SUMmyMESr2gFo+lNLTHRsQvzxkdjw
         M6a7P6+Km0GYJEKzg9xEePm/FaWTspzj3OGLu8B9CdDoQnWu/oE/kpF53+mnaYGy/1FS
         dOIS01MJC43UM0WzF6miqxMaHmOFsRTqQzeUNjTYUtbtzD4nkKhWhajnVFureAbhKEqy
         WpEPzRV7tIlFBEfoOJNGlgTk30DFYy4qPfMGSbL4N0rBlW7APvpuwb1pqMoDqq4PUQ6+
         xRzNGQWncSqTMpbi+15tdIsc4Hnk0erIdQuUCdDBV53VEnosTWr6gsW0416VFZNrDnJm
         N/WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=17JCVini5nmxTl1F5Q6KVVke5x+u9+w/sXFwFLX/MgU=;
        fh=mg2z6vLCzKkwwFpRsuapt22Nt5UIqWsB4aW6LyARNKU=;
        b=AaHS/x7q7uspTylTOC0KpvVORBG8q9Wg95VyygcG20ovYjIiKWCi+rOt1D7YAwPP7w
         /PnkLm4suzVeYCQ2tFN53eJydKVxYGNkXLmnxltN7RurRWFtef8QXftVD8jiKV0VJpEE
         +zDWmcsHjIuK9zJpSUnPYe9t98ftrGslZv+yCJiYCWqC2lmJ4yRxbI6nnRk8E30BIYzm
         874UmHTsNPiWJ3TRLrFTD3caFnmNN5zC543LoYE3dOuyOVSFFhui8h1Mtm6ObFiTurSS
         Np9kasjKJg4b+Lk1LkinhQ+P24DYmd4RxXI/9aLAYsP1IBKzpxxEw1Eg0xikvxD6nHHW
         gbog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MuA06LqS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929626; x=1719534426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=17JCVini5nmxTl1F5Q6KVVke5x+u9+w/sXFwFLX/MgU=;
        b=NF15AXV0DNTK2Lr+PpSLfNqtBISLeCMRDRMVNW+pGaB5rXb0KMIiBz2K9SvDCnvWXJ
         ZdtMMjxNWVDCcXutZT0RE9KPrpWQnsGNcKSEcJ2xhdjaZeFxgtsf4bKtGrhwY5pmYkVe
         sxNRMlfpCUVlgYJfKHyuqPhZcNBCRobkatZL4kVAoT7IQ/QKQ7cK4hN//81KJb6f5see
         ryG9ilSxY79QygLclmQADqATgejLgPsva48NYX4IJBn2kClIQ1z9T24EiTf8pVdyAQfG
         LHjN0HjJJ2XG+w+rcpN/87t+23csBSb87w3NQjlUJrhf8laidad1L9pExAULg8v5U1ld
         D24g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929626; x=1719534426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=17JCVini5nmxTl1F5Q6KVVke5x+u9+w/sXFwFLX/MgU=;
        b=cLQRoDVcz2OBnMgERrXe/rZB7SMfx+p90TGHS7TtGenVW6lfaIhhl4ZuR0ldH+5le/
         huwFr2ZGoO34x4EJb7yhjMmjXV56cpqaa6FC3627xlYTDw8GI2tYIQyWB7vrvJVQFlA0
         k5Qp3hZDHDdCzzeiVQ/Np27SgK2rlIinyDXYpHcSisJmEAGA2vGh/1V7hJsulJiKZXFN
         xVmRvQvBIos3hLqrk8wM45Wwt5cBWtIFMqrncnfojN1gpax8hXTuM1YtPLB7opkWlRfN
         pem1qKRW3taPuS/J/Cihz6TtHwW8uG60GKVCajNnrXcCRNehCdM42gJCKG+5i3aVNuoL
         Kwrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5+3y+U6nEK89kn/y7/pmN7AP1TNVA66bwEKQ/15hLcDwM9rUgOGpQkZnfLaoQYtHgmGorRAUNNQE5RtqXNF6IFpldxYq4gA==
X-Gm-Message-State: AOJu0YweCEUWZxyoY4G9wpl8u3IVRawp3OEElINzBWQY3hKFtL2WAWTP
	xmfIQs07+5USP0WHYqkYcve+t0qlUHncWwOquzYrucefg32x9jel
X-Google-Smtp-Source: AGHT+IFwV0f1+ia7VLCl/in2SxjRBspiv/76NlaVDOX2gwZVimUw0HaNsm+q8zO2yVGbyy6FX5gjVQ==
X-Received: by 2002:a0c:c302:0:b0:6b0:48fb:138e with SMTP id 6a1803df08f44-6b501e24895mr65120366d6.14.1718929625775;
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5508:b0:6b0:7204:3b2 with SMTP id
 6a1803df08f44-6b510329253ls20060026d6.2.-pod-prod-09-us; Thu, 20 Jun 2024
 17:27:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW57DJaJFZp8cGXsuhFK8lD9DUpqe6uWl+BXFJXlwmaSeODyU1tbIvL0G2AlLspCj7qCJU6OpD3tOLQFFenYx0aS5nKomPkzvafXg==
X-Received: by 2002:a05:6122:a1a:b0:4eb:5d5b:a894 with SMTP id 71dfb90a1353d-4ef276ad2f7mr7833710e0c.6.1718929624851;
        Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929624; cv=none;
        d=google.com; s=arc-20160816;
        b=i7sYhOCtFQwHW+PCG9A+34O54+sPLmPTTCHdNKmvgDLEXwUJ9ogBNoSS0VOp+KryIt
         UQO4OqM8uYjna/jTVo03f5PzS1nGFdVgem1BhQ26Yz8vpJxJNDlz4qSiY+QUKGXw0QWv
         vXGGseW6UTf50kj6bA7Wc74V61e4zQF975UYoXiAyizerur5AOmNcrDpIsmcqd8ELIXT
         2YMNT33NN+drTvlKM2HpBpN9Hl6Bujj25Iw54j8dKTnfkgeYKtlZX+/D7HholIW/dCMP
         EY9JacRwo2qieH6KLKLleTUiSYcMHGq7k8AIOZK6q332EzLtt6MxqVgEINwy9Wm3zYr3
         c28w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A5/DP3QFUFkYA2+5kJImY20b3CDMSHPGwimqBdu525I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=mC7hvk8MKibEgvlA8GM3/EgT6ickwU6a+so+isGBa6bolXju8Id4ctwuSYeX5UV5tv
         dLI66arG8KoRFCz9uGAAcASwhaGMHBKxMX2m0RDXDPpBdBGHVBAgO3qv5T9HafZptj9V
         9QcbNwG0rPSvj9AV1gfZeguclA4+e1h+Zw2C6dwbOTt0WTAWApp3O3psjGzHm/EDnPTQ
         IYZ7yfTmLbs8mvUgI0m1nlssxRv+lrvILBC4PcE+iQlVHNjZqKfHQMJMowSEjPRE5+27
         kcgxCWa74aVRSKa+ty8io90NmNfkjLUMut/7cszlCAgJy56vD8+7BPJSumEFZmG5LoHu
         pi6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MuA06LqS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef4672b312si30059e0c.3.2024.06.20.17.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNQc7l017321;
	Fri, 21 Jun 2024 00:26:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr89y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:31 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QU8u009337;
	Fri, 21 Jun 2024 00:26:30 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr89r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:30 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0KnaS019946;
	Fri, 21 Jun 2024 00:26:29 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujnw1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:29 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QNa656361470
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:25 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A32F02004F;
	Fri, 21 Jun 2024 00:26:23 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 81F572004D;
	Fri, 21 Jun 2024 00:26:22 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:22 +0000 (GMT)
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
Subject: [PATCH v6 03/39] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Fri, 21 Jun 2024 02:24:37 +0200
Message-ID: <20240621002616.40684-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: UM8xOfNifosib3PyMS4PrVZSIaVvXwYa
X-Proofpoint-ORIG-GUID: toQ6s0bg_q3_98lVFmOUcEXGd-YIb3ZT
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxlogscore=999 spamscore=0 adultscore=0 phishscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MuA06LqS;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-4-iii%40linux.ibm.com.
