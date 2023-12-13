Return-Path: <kasan-dev+bncBCM3H26GVIOBB3MB5GVQMGQENUZXETQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B22681234D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:40:31 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3b9e53e2e60sf9590252b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:40:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510830; cv=pass;
        d=google.com; s=arc-20160816;
        b=z7ZWLaTkzSGwPP9IMFZ97uBvcfx8vQf7ESuj3JrkHxzxQmn1J9Oh56c8tEfK1XuQIp
         uf3UlwfDjNjswq6FtPKXpI8solG/u/qUBr1QdusA8PclhBktF9+6AoKFAinipihrJXlw
         35w5ZDGkt5RntrboX9+CsUGcX2wfjQX6+nMRdNXBphmoiknglKRgALanH5DBrv5UfLXI
         bi0+UYBA5XjEP1Ay+BU0ApbpskW4Rb6oDkKMbxSNhK+875Q+j218LNWIMGNyR+pPwlDO
         BFa19/T0eEAqJbwPCiekuuVKbY9ijI41tiL38v84KUxvkCO1nugCwoUCBYZ/CojcQoZI
         iWvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IMxjUr+SYp+Hx0mx5oAZjYcVd2IzcjfbPOOBX46VLZ4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ODNzseqoaQ6X+SAfpCHPW0iyh6jhRzO4VnnAXphW5x1TGejIooofhIkQKc31f7HMhS
         rwcIM/2x9LG7Gd8MhXL/TDwIgM7D4iNxTmDbtCh3UIsBfS9VZnMoVrerJfwoo4nhthBe
         GODbXGxFLBZHGHVWC5mMqQ6BKeI/NkYm205f7dKlH9mKlZUWIPt+nmIs1z87HMCjVquL
         bSL6FR+ab0+jv5Xi6Q9X2OYVu/uEh14/hSEeeQxtniTK+T18u60a9rhfpS+SQ+/zdecj
         bttZaO3cR74I5w8Ct/hVjaXe0rIE4ZFWRlFNeIKFQw4XtOQOVA73MDO9tBEExinktTva
         ge6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WP8t72Oh;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510830; x=1703115630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IMxjUr+SYp+Hx0mx5oAZjYcVd2IzcjfbPOOBX46VLZ4=;
        b=QXiGx3XbTrhvWdKFLEnuvEivu1AJsXYC1gLHtR51esYwM0ZUKuhb3qwlESbtogmH7d
         xr87GRzxm52NxMXpx5NQTRNWITX5PmU7WG5ygoueDbqc2BJwQhKLToJ4IxwYohC6P0tA
         5ZHw9FWkKz+85yKoFu2RI3QnIeDV9m/PlZIlXxuKir+k2KgMIwhDzk//Ntu/W0pB9Lv2
         qc0/A5tkZPw/tnFgQ9nFY7u/1YzgJV1S6xM1dxg0h+l33akrje8+KnacrMC2pB7B7FbP
         KajZ+9lwMIQ6bU+d7R0TQT1XAYPfDQPJEbZZbCr6K9X72qImXbWmoGvSRXA7NSSbEwIx
         dmtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510830; x=1703115630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IMxjUr+SYp+Hx0mx5oAZjYcVd2IzcjfbPOOBX46VLZ4=;
        b=Hexd58v6Ivw1u92rIVjX/D1HVavzT923Fyfg2mb+1YGwYniPSQgSMmyM23PJSqROp0
         CQ1CBQpj6xmGNxUTnA+/lYY1nmx9AUK/PjPTgVYDUOs9eS+5rDvLNg3WmBDfQwh6oY3t
         E0a7vEH7+TACcr8YTJo4mdPdhhgM0mBAWvSuYUTekikuqLGD3wcJ9UMbJzYU2fAbQNcR
         SaDpiSOsPHJEAzGUyvp7345gGcJtyvGtaOSm3XK/eB9SOo20ztPLjElmCkdS8t3xArpu
         9BfanyFDXvV6YUsD4rj+tjdWM9cY8gQnygrgLNBZ9tOasfFmoSdHeLhpMAPI1aqOicbE
         zIIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx4xHPl1hw3DEbaeUPE4H8vN/S1suadLPvBcxlzdYTCn9mpwuoG
	sKKtPneTEBMX9JfsjrpoUqI=
X-Google-Smtp-Source: AGHT+IG6QQBu3LKSv6gR3G9gMAIEw5dRoixIk6PcpDFqLgplK4C+wjdati6xlVITfHVuQ7ruA1o7jg==
X-Received: by 2002:a05:6808:3c99:b0:3b8:4164:5fe0 with SMTP id gs25-20020a0568083c9900b003b841645fe0mr12314658oib.37.1702510829887;
        Wed, 13 Dec 2023 15:40:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4b43:b0:6ce:f521:4ecc with SMTP id
 kr3-20020a056a004b4300b006cef5214eccls1945452pfb.2.-pod-prod-02-us; Wed, 13
 Dec 2023 15:40:29 -0800 (PST)
X-Received: by 2002:a05:6a20:1610:b0:18b:4fa:a877 with SMTP id l16-20020a056a20161000b0018b04faa877mr4730150pzj.14.1702510828883;
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510828; cv=none;
        d=google.com; s=arc-20160816;
        b=qMjtaXk/sSNznQKWG15H0lSepjPEwwYSH2YFbaud1+LL0VtDydkM/c+oHHUj83sQfL
         iyysD3eLCypWl+Jol0w0NscXXV7gNX23ntfY82v6kWuSCMj0v9OfPftc3ai3D5k/JfJz
         6inuxzdVOdzbl1deHQEKb9USYxCS6OweMaP14RM1KPtno7bilsozZQ7YkXWRfOdrGu2h
         MpyF7D/Go5+zrZdfZE1RfYQYDtvx637Tfuh4YDDxCtjM4IPa8HUVs9s+fhAu33sDG0YN
         fM7pb4RnbmoQG5q2LzVU0cD6/b3MuSNvuhUzLXmKXNQV7K++c0GRQQQSJO4xfafTGWsT
         y6Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uWvuPPN5yMGUzijlzwdfjnYn6oWAG+E9+mRhNLF0PzU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=C0nmVUyGt7CC8Dp7+G9d+rpp/2PYpmVv17jy7x1C20faGbB2uirX9Evo12T/IrCBkq
         SSuzuscY5g1Ng1Y2DXF7hPkYh/nfHXpUZUeILhLnZzvynsEqInKd81YCjRzTsoSk2Uyb
         pLoCLmk3izjfUCaveS3hsua7j91E6ghdZbn6zsEcd0CakR7Vi4PKm9OTH0DU8lDB+EwF
         LyHp+rOHmIudFOULlqPDvT+18zJcxsMJdGKUa6uhQilCZvv1o8n1MP77gQdCh8bB7bIu
         2sRUc6NS+Dfz1tTMCoVD/9rm791qRXDvdfdnrf1D1xTHEj4QOz+NCf5lJ5kI92iC+84h
         UZ6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WP8t72Oh;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y9-20020a17090264c900b001d345bd5d20si319198pli.6.2023.12.13.15.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLr4a2019480;
	Wed, 13 Dec 2023 23:40:23 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5vp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:23 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNTnBs001737;
	Wed, 13 Dec 2023 23:40:22 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5d8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:22 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNMPKY013892;
	Wed, 13 Dec 2023 23:36:44 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4gm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:43 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNafIt17695278
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:41 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 14B9C2004E;
	Wed, 13 Dec 2023 23:36:41 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9F2BE20043;
	Wed, 13 Dec 2023 23:36:39 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:39 +0000 (GMT)
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
Subject: [PATCH v3 20/34] s390: Use a larger stack for KMSAN
Date: Thu, 14 Dec 2023 00:24:40 +0100
Message-ID: <20231213233605.661251-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: _KTup_EWxPhkC5n29RfmF3CCmvf4rKJK
X-Proofpoint-ORIG-GUID: riNn7eVXpvOl0DpCewBLQEHSMh_RwdVH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 spamscore=0 malwarescore=0 mlxlogscore=874 priorityscore=1501
 impostorscore=0 adultscore=0 clxscore=1015 lowpriorityscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WP8t72Oh;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-21-iii%40linux.ibm.com.
