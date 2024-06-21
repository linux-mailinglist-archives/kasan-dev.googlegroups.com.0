Return-Path: <kasan-dev+bncBCM3H26GVIOBBSER2OZQMGQEDBGFULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F7A391174A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:49 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4405e3b3b78sf232271cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929608; cv=pass;
        d=google.com; s=arc-20160816;
        b=AWDXSsJ5rIVvuY/8iueZmC2iZ3XoRFW6qOde1UvGndGNmVsfFVakyecm4SFW3xjZ/F
         hMaP7BBfd3Bd+kmJNSTN3KqkkaShxovjoIxNJOhBpUT+nASaIC6QxSBs4eTaqRSAi8oZ
         hG+kkliMhilNIm7X52Do3KWF9fVi8bedt0rOLXY5wW/hwv8FLkChIU8tj/cbnNUT9a5s
         nKLs+J1cDRbRg2S/NXPF0Rr6xK2TjUqUrB0eWokrJcfUblXfgmfPaPveocOIkKscyXPn
         xumQ4JHTQ4BOAcRK68aDOa5ABfaRMXM/GJzoc4+gYJhDk+g4GNKzB6RrnSM5XrqPeovF
         eOxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fALnm7pvT/aHSwSqkOosm1+v77uwIzT/l/CeVCrvFuc=;
        fh=f5Q/3RS/xNx2SYWbrIR/hHC4s9wQ01Xw+Z9es40uJN4=;
        b=QY6jiGNSWTyzs63wIO0+OYVTGIzWnrsEiHmuRg8zzY5IZnOlGU0HmvGxmXBhl4sBhw
         7c/vqSbmp+UP6cbkbct0BMos1sw2FV5jc0cCCIxZ6zMfTCJdNUDF740Ch8RNNvBxXLIX
         AG1LyRCMiSBDMjS3raByueLc5PydlBXea48SlzGjLcWFr3fU5470zCr6ln+pZ0ydz8XG
         8vsKooZKtylqFN17qHcvt5u427N+kt2euDqhybpX4W7nUKTAiows8XRHv9ath1YRQgfS
         w2RXN/HVfCbthicc6Gjs1trWgszJjOBCZjSP/RCa0r2QJyie+jkemRarICfS6wP7tIq0
         GCGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=omgAPtXZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929608; x=1719534408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fALnm7pvT/aHSwSqkOosm1+v77uwIzT/l/CeVCrvFuc=;
        b=hw0RUa+I95wGVpoNRd+yQyqbNHeV+GrfzjvBnKBkEox9R7VlcyTiTs3mXYjkJcqqgr
         xtdreOS257wS65QDhlT+8XmPDvHxnuDeoQmgfaBB59ULZYHRGOGdPRI70s6ylvjMQSc+
         eiVwYN0lJdIn5Zd22nOQnY+M3qdS6OXlCpINzBztlRhrEeRQQ6kY2M38DRxfvdoc1hzm
         wuIgw0o4/q543/oh+RQsGyK3wZ+ccjfsGr1oA5lXuNKJFJn1XTTanq5j1BhbZZSSNTLz
         uClfWdIIOMhNSlbf42E/w9I/cNNGguC2FLgn3qetkiC6mq6lEXddYivpiW7Jsl8OEhT0
         BHYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929608; x=1719534408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fALnm7pvT/aHSwSqkOosm1+v77uwIzT/l/CeVCrvFuc=;
        b=iuXutpiFAzdEsMPpY1joVuY8rEPX+0lbdQPZ6BsLWdReoeTiC6EbnqjTMG2CRk8j+u
         0yhQ72ojR+U5qEdBUlKiLj/uexVtMxbgmikcrPaIn5t8v6Thg5gQBxg9RA4ufhNSlxR4
         cs0xwMr1A6V+AyYmMQW/x4Q8sT0sIkHA6ILQ/LYoM2vg63A6+TX9adVfZE1llM7/4evO
         01yAd39bPhOLu9G0ze92rYdesHt1dQuoTSAX25MzA6K0nCbBi8g/+giYkK2Ikwnbuk7k
         V56C8Dgiq9xpbgMrRNI8dKg4T6IokHCKHYPMWym4iqBaae3zfnK4/jlcecsVq7wfxpx/
         a4hA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2AkeuUbiX4EDSo+xrx9XMtwSzX91QdJkcN460vlluJWrZUbjv6KTtBcJSlHz5nlMtcy+0TlvzreTsggu4lcosKZVv/UoZ/g==
X-Gm-Message-State: AOJu0Yy8AiO9JxwncsXkl7yl0OG8l+s1js4NpRCSyZZigo9rxvH8VNaH
	2JmDyz2HJ5puUb9uOOX01lYvDy9Szu1WCLOBLez9Eq94GXU5YIWI
X-Google-Smtp-Source: AGHT+IF+H9rGGa7WPfR6RhwXyu1ISA8jS+Sl6ZcT8V/DvGVqpRnl8p2DMgdmh3+UUDIKs34AwboLFA==
X-Received: by 2002:a05:622a:1a1c:b0:441:55ac:c490 with SMTP id d75a77b69052e-444c1b49059mr1565041cf.20.1718929608461;
        Thu, 20 Jun 2024 17:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1146:b0:dfe:6e9a:9820 with SMTP id
 3f1490d57ef6-e02d117a0b4ls1479239276.2.-pod-prod-00-us; Thu, 20 Jun 2024
 17:26:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXb+lQZ7M7j2vVD/aM1Bjy9wvypzd7fkaAxl2dsdwY69a3G/f36fbcIxCBafKWcs8pHEFq4B5c79YGlpmIP4QkQ0nWX5PiipDTwPg==
X-Received: by 2002:a25:664c:0:b0:e02:8703:28e with SMTP id 3f1490d57ef6-e0287030438mr6011229276.12.1718929607513;
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929607; cv=none;
        d=google.com; s=arc-20160816;
        b=aiz6KJ3/SYZOBEWbjPSFQEbi3hTwTaDt/N5/s/erUiLsMDk/JcEqm/hWES5wWbOURj
         nOrhJI/TDevEncsXS0opaCDKbVVaLMM3yc9d1SAB+hLSTcvh2Q6ajnc9dtxdX9cHDFb8
         zUQEmMp/fsoZa++knCcOtRd/+I1a8ffauoQcx54F25YDgknh3nCvIBAytREn5jAhdwGo
         dnypIAxICA+pbQP2ru3GlQhrfJWLT14LgwgseCK1DqPF8kJcpCjG3mDD/OB/f8NGW6+V
         zWYJCVEJ4dei3/yaxnAt0E5Cqf2Eui0zVE9Chq29efhF/DDNCNcdUX9t2GQiCYo/CANt
         BIhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fhyNLk4BgDYNJAsfSc8ftWCxz9OlL/4RiKPE6HJFalY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=asnfK59p8aQKIV3KJMYmcCpZKveabCjl4wtQ/G5O3tmVfkyfiOtL06T597pOrAWxw5
         SgNm/08x+cYQL9VrlaUUMfA1U3Dzc57sf0JZVNa2B8aQA0cpuYfZ2zR7pCp+8FF6q5lR
         1QP5v/Z7MkrlmIVHENoMjhioZUZyAio5PwXm8B4AkRpo3lrM8wnrimrT/pOlW5mbhPvm
         p9tlvEcbX8J2Nqx39q7ZMLrTOP7OqHVFzx5rQk2tTjONlB4pyNeWbQYwnBZdyGrOln2X
         ADfiBlqM8TzNVcYpCyd0p4n0xVSmUiyLEdh5kTnHIu3F1WKvSZ92AMFkgwN4IXwgGry7
         Et8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=omgAPtXZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e02e65d30adsi5667276.3.2024.06.20.17.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNwuqu026203;
	Fri, 21 Jun 2024 00:26:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1hr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:44 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QhWV003105;
	Fri, 21 Jun 2024 00:26:43 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1hg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:43 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0HLif030949;
	Fri, 21 Jun 2024 00:26:42 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn1u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:42 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QbQM56361224
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:39 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1F4D02004F;
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F2D0F2004B;
	Fri, 21 Jun 2024 00:26:35 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:35 +0000 (GMT)
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
Subject: [PATCH v6 14/39] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Fri, 21 Jun 2024 02:24:48 +0200
Message-ID: <20240621002616.40684-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 5W7KJG6jJlxWPE_in6LwMdbQ8ARjeHya
X-Proofpoint-ORIG-GUID: JqP1_YZ35bt2dIEOHFacKgEIXr16xCpW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999 bulkscore=0
 lowpriorityscore=0 priorityscore=1501 spamscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=omgAPtXZ;       spf=pass (google.com:
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

Improve the readability by replacing the custom aligning logic with
ALIGN_DOWN(). Unlike other places where a similar sequence is used,
there is no size parameter that needs to be adjusted, so the standard
macro fits.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 2d57408c78ae..9c58f081d84f 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -123,14 +123,12 @@ struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *address, u64 size,
  */
 void *kmsan_get_metadata(void *address, bool is_origin)
 {
-	u64 addr = (u64)address, pad, off;
+	u64 addr = (u64)address, off;
 	struct page *page;
 	void *ret;
 
-	if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
-		pad = addr % KMSAN_ORIGIN_SIZE;
-		addr -= pad;
-	}
+	if (is_origin)
+		addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);
 	address = (void *)addr;
 	if (kmsan_internal_is_vmalloc_addr(address) ||
 	    kmsan_internal_is_module_addr(address))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-15-iii%40linux.ibm.com.
