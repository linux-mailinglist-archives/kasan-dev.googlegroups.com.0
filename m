Return-Path: <kasan-dev+bncBCM3H26GVIOBBLX2ZOZQMGQELCYSHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D46290F29F
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:52 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2c51c2f1d78sf3599570a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811950; cv=pass;
        d=google.com; s=arc-20160816;
        b=eE18ibniJWoM9sRKDIuy22b5xfc8X+LUadsU4oK3YmZfuZccLliGElT41RzTSQ9wb7
         lykWwJr6Lo98g+/TJGe5Y72XV0yoOgamBmMZpfJMWt1q4LFgwyBg+481KD9ooJkg7U4Z
         0a4uxAhiN3XmxGP4IT3Q8U6+zdCfjpvacrTg+QfCTlH9MqCzG5lUOlV9XeFPl2ovWzDo
         uyA3aEagXhdobXxlAgdmQ5o03y/0DauIDFtm1Ht0sCE6LGviElpQLNqgQ/Vka7hRnAcW
         bQBl73spK27OvJ92UhgQ+qdo0I/d7ieouKpM+Rz6esS7gDe6KEy7Zp2P4R2GTGPyko5Q
         R7Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/STfuXmYTrgJG4N7Hv/q17mxu8HW4LSU0tTivfiBxJ4=;
        fh=lP3FkO4jlwenLCxgCEKEz7JB7SA3nkei4hZv+8vMg7w=;
        b=dRg73bQ7UDnUnVJfzIUwK7TBPw/Y12tlDxGPC9RKffDzqBuga1esz/FtQUUrNM/XYR
         lCIFnZKaiAFBA4ott1tZW/3qS29MK7QUNd5xfXW/mj7h6x5vReXTKMQhvgV5C9pWmtL0
         ZW88kp4LSaIsd7MvUsu+T+vaOFaxlBF7c7WNNcvvgC69v/5Viio9mtMp55rPC0YXNawk
         vpUpoeFarRMV2eB125Qt8uTO3/fjowWje9vl8Vs2SgJAfiqryq9vAe5RteMREPj2BzcX
         8Gyzc6dLg3mJ5AC1OCbeup8rSaixLZJ2SqOGxLJYO2XwSFTuc/tBCOF3mBTgeXj74pAG
         GeZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rxzKVds7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811950; x=1719416750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/STfuXmYTrgJG4N7Hv/q17mxu8HW4LSU0tTivfiBxJ4=;
        b=vYBy4r9sHZRYp95fK8fX1IJ2lTG1Q69wFjtzekzIRuUxjQM++s/DGPuN8xLtbNvtrK
         uqdD/IXYy7rcg0Rjjsb9pnw0Llc+jkncmrmGTyJ6f/G92KSYFd8yLRvQY2IDfhcCEA+p
         2aEQf4tUV8PjqphaiA1Zg0ieSUxPpfBpRQsr/nSPprQ3oZDHe0p+36Cx5X2CMIeLhWBB
         3sum4+hOHrg4EegQnVbDvXTlt19LiQnZz6olB/BDdBNp82GBTZfywwUqbvhGCizZB96n
         RipG/7o0oFhGn2XnQMPRteUxiVqDOkC58ZYZzv9y6FbOVMPyoEzvNCkMx4/toKGbXUxY
         UlTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811950; x=1719416750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/STfuXmYTrgJG4N7Hv/q17mxu8HW4LSU0tTivfiBxJ4=;
        b=uojPhYQuMxCtL9Q14DBy0cTJAYajywUya0eEOu/v7w3RTQuK0Lw3GfogoBEEChE6GD
         LygiPA5ySNyhOY5ZAZY4BZCK997zQdQoQm5aU2pJjtzybdbiEleG3/92xhIKjkGxKXrY
         1C810OQP62CDIkEe/t5s45EX3DthwhAcZ4AylJPXPetvpYQ3cr+is1mSpWlAf4g2ZLX2
         vFXAiWg/7xIrvbfeeOtO9rwa3YJRQ+IzNre6HM86FQg/fNxhQ9gpiMgB1NGB3l0JYJDi
         O5yGEzTq5u3d3svtlwNFcQjqOR7WwhX/54/CK7HeBTakECoszcTI7yCyxoc8PZbME/HI
         1Y2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIenFMqw7Ohc+AwPfMk1mjql8jx1Tn02QZ8OvzPjBBHgfBf/ij+hjesDIjMG1CUQcYWdCJjrIyew1mgLQNgcScar3JRqDfAQ==
X-Gm-Message-State: AOJu0Yw8lakf1aHC0NYZQyKdJ7LFdAYT4LmbwlBWkVp/yXP/h23suquB
	N/AFPTBLLcUoyFTX3+brftuKTVKBMVtnJmVy6xbFAAWTIFsSAkNR
X-Google-Smtp-Source: AGHT+IFgruthIRQWFVPAaTHGp5vmuGm5w2pjWbt0y1gVjBEWgende7I7oEg/htCfXAc+Etn/aaWaHw==
X-Received: by 2002:a17:90a:5d81:b0:2c6:f21d:8d8d with SMTP id 98e67ed59e1d1-2c7b5dc76f5mr2638166a91.41.1718811950478;
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf08:b0:2c7:c2a0:857e with SMTP id
 98e67ed59e1d1-2c7c2a08670ls483175a91.0.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbfKB6XKMNAdauZnJ1v1ostS0Kp1JSXqIkOG2Arn5hrUn518onp+IUuCE64ysC5Yz/F3PVldv59nMaPQlA77e+3bW1smgpwtalQg==
X-Received: by 2002:a17:90b:2313:b0:2c4:a9b2:d4e9 with SMTP id 98e67ed59e1d1-2c7b5da54ccmr2981924a91.36.1718811949420;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811949; cv=none;
        d=google.com; s=arc-20160816;
        b=plgZDuStISv0hX3Qvl3E9/3p/NTpGjUILsQcwmChiCg98hj10Cie/yLT9qlKogiS3C
         LGAhQMBvqpM9nWXFcwmSug9kBANVi+FPmq51/82fWDyOx8uKdVkPGRJyem+8ayA6Ns/V
         s0kxpvbKxZSc7ma8/EJ5B7k4PH/BoFGYUachmCaX4I/9j/UBjC1xD45VhFPy3XQzWppR
         TxNGkWBE6ACMR1ay+sVQnd/SO2/FcevrOErJj1fosetreo92WWd5YDj0fNpFE55ld5km
         Mi+rhEl6yssdpLzRRUr6JbW0UK06eCjsEXr5s7SBxq0sswjsNW39J8QuLJg/sGziiJsP
         ylTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Scz6uta8wJUcmkDwOaiOL8UogdsQpVaK9UJlhoWG7HU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=bmswlOYCI4PoMXZsg/T8werTxb8OCObK9d2G4CKW1wCPEkg1u2l/wPCIFU2rsnuc2U
         nmt4C+M6KPM2QkhnPOkdF+vUHHLTqm21a840L+YxeElCyrRt5iGU403pcDqWwNLBDF0e
         6MnjQFn5OJUWmmjzI32CTBAPQlGG+htnHMqZ0lpUg9I7DoaPus2F5UrCn597gE+ylv6L
         HWysmrPqQbdnSaVXtSQXlnVQ0KAZqbhHSQKF0o/Mf2aPA6nVUifePPI1k0tXOMdNy6Kq
         cYj9zuO68YYVaPt+PUECXPg/9ca0raNRYT5u/0SKpvFBBcShsOeYP/lPMSui+A9vfVH9
         5t9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rxzKVds7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7d6672e92si28034a91.3.2024.06.19.08.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEtwGJ013034;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux3fgupe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFhBe4032622;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux3fgupa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFhSXM023897;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdypk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjZku47907278
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:37 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 41BAA20063;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E4D912005A;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
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
Subject: [PATCH v5 04/37] kmsan: Increase the maximum store size to 4096
Date: Wed, 19 Jun 2024 17:43:39 +0200
Message-ID: <20240619154530.163232-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: yqBnn__VPUChFXLmx57TWXMbRlB3RKnh
X-Proofpoint-GUID: wAGMmQY3YfNo3xdFT986fs_57LHV7tLj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 clxscore=1015 phishscore=0 mlxlogscore=742 spamscore=0
 mlxscore=0 malwarescore=0 suspectscore=0 adultscore=0 impostorscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rxzKVds7;       spf=pass (google.com:
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

The inline assembly block in s390's chsc() stores that much.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cc3907a9c33a..470b0b4afcc4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-5-iii%40linux.ibm.com.
