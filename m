Return-Path: <kasan-dev+bncBCM3H26GVIOBBTER2OZQMGQE2R7H32A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 45BDC91174F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:54 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-375e4d55457sf15040275ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929613; cv=pass;
        d=google.com; s=arc-20160816;
        b=k8PqRXq31/w3tVkzJsCr8d2/R1zDWKyVaUg1Fp7Dn0gMpYIY1d3Kl1MqNmwr2Cmh1M
         304UE3k9wCfMrS2I9s/st2CqiBDrve9LA/v4QGnHp7wk4syqKopasQxJp62nTUW/9AEi
         8NfQslJBWKlsiTT+X8/vPNt1HBpTTRwfzk9ldcjEzOGNZE4sgCLcAEA4bB3v3laq5WiA
         ifubcUipC5yX0lFeRMaLJNuSQNLjL9w5fPvYwMkSX5zbnd+IMqbD5dxIGY9yyQw0uSmV
         aqlXi2wN8h14xQ0i34P9HK42s1pGrELEwb9sBjf/WRAYCUY5YooY07bs1ctzFhswyPQq
         5hxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TmS0mIoDEdwIxs4WFSjuVCJx/6aXnLmkwqC7M2uU+hA=;
        fh=tOB4E6JWMnmhtgGkUOFalAO8FiFeq5U3g1D5J7MzJBE=;
        b=QG6QolSoaDQb5gNxfeLkRjGtpVuwKqVik6dKt1sRt1rYQL/aQC50zv0pDkR9bWwKe9
         NhWgbNEjmGWB1D6Dk/uIe3nwqjBhUbugA6fhUfh7odkXSEopNvu//4DzpC2bVkFXjOjp
         jXYiwTTQUoECpwWO5ZN0JDIY+0wB1585CDhR1DL7QKnPVnFsTG3EHUHtp7LsY2I8zhQE
         qVe/A75CSDCoMdM0haXLIyiME71Mfo6fP/FFP5vmjZMa6Ce8ClfQSxqt6MWB9UWa2IRD
         WCMNfviEiQjO4GlfNOcMktf++hi28UdGhafkQ7P+h++s248f1TSf5HmrHot++usIbUQ6
         1A8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=foNfqk7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929613; x=1719534413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TmS0mIoDEdwIxs4WFSjuVCJx/6aXnLmkwqC7M2uU+hA=;
        b=JT+kZQZPYbYD6ozywIOefiTVHTkHEtz7v6+Y3s4RfoRJCe9B4Zi5ZZ82+8AUFr4hso
         GCtALNuLkz9+xVhLsC4/GwnUn3lrsDafkNCXMdd8Mgtp4dg60XrAJgXcpeuYTQGrJSam
         jsEvQ/5obTn/Uxrz5L8qB8iyHAuTq2PKgMxTsECkUB2Vqua0a5yxACWbjmQRgx+1f+ez
         LLqSmeTIsGSZYONXpMYJ8QpWG0RvvrwkyIwtJc6++tz9lKdIVEd9cOhpvzcBMmVy3SH3
         mQUFgHQIpnMDmjNEnA+SOD4MndTgkNw91KekQAxnCkoRntJvLUganLzmf0HevUjUAuPh
         AcFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929613; x=1719534413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TmS0mIoDEdwIxs4WFSjuVCJx/6aXnLmkwqC7M2uU+hA=;
        b=rZYhusQYXQ3R/7JPXvTz+4pnUuUe8fVLWxZ6q3/T9BO+9qEo95DL8v2FSZaJvJLLuh
         aOIkEW9ooJ3wZwU6pyhL9ThXFJHdD7AC14UiXX+iD/m88Snie33tcdMPfisMng73JrDe
         PLFa0HzJMmPBSdTfasA7o/yMr9LGWpF+bpsYP/MoZyh8nsHliDjgTTEKb9p4n0H3rJW2
         JhpsGYuexDI7D04olccaTR/UX7vVST67O2YC/mVSfy3V1mCHiHm4ziNqalzGfodW7Bgy
         Na/j+5zTRlbKTdCEZ9lcx896lCG6J66XUuc/75fXWaSvDgi4ZBVGhW55/nPgVVSP/BoO
         MMfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfETpkR74m1TlXQWdKJSXKfPi7M08PrH4pfOxDx3vM9F183FjH9/pgOdKgLAgwUTa5hZaPnoWJgiYaCaoRFEMwaoAT6REYNw==
X-Gm-Message-State: AOJu0Yyg3C3HOIc9/RhaoLbFNYBPsZ9bZcHifI30hI2eGjXY7YoC8MC6
	oU89Xy+olHCHEdyjAac7mVWMdqy605JFWC80rgqzkXoTAIQuSPP6
X-Google-Smtp-Source: AGHT+IHkKmA27sQ/H8y1OI5XSlraq0Qu4UCuI/DpBhossis00uSQeWZxuaArK6ctxBsq7U2RTmvCNA==
X-Received: by 2002:a05:6e02:1b0a:b0:374:9a34:9ee with SMTP id e9e14a558f8ab-3761d72d2cdmr66881485ab.31.1718929613107;
        Thu, 20 Jun 2024 17:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2199:b0:375:c587:1b42 with SMTP id
 e9e14a558f8ab-3762692410bls12320585ab.0.-pod-prod-04-us; Thu, 20 Jun 2024
 17:26:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuwCc4iy4bAe8phC0p2Ap5GF1ZQhPSROxK1RQIOYZGp5WD2qht0PdcAxGJtWgQduOhR1XIwdufGMrq4ENHFfjiO8+9dObYKe7DAw==
X-Received: by 2002:a05:6602:154a:b0:7eb:c2d5:a420 with SMTP id ca18e2360f4ac-7f13edcf9c9mr832603539f.5.1718929612424;
        Thu, 20 Jun 2024 17:26:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929612; cv=none;
        d=google.com; s=arc-20160816;
        b=1EiSRW1W3fS515dqO2r4RuR4/G1naMKQP2Crivi03zFPtYLfFnwohRMLNweQe1bL27
         b8Zg+EN5RBJVavQ9pCghCr84ViVCox2wSElnjbLD3Rw0HnrqWFUivEmOSU0kzo8WAF1M
         A32n0x52NtRc5iebVq0l3gpXW6inx0swWAAm3vWzzxWEQA6X2kts9m+uGlx8hFXI1Xe3
         eGhzJyFKeMXPMr8xgb+hrD16d3PwQSCQJga8wZkqAtaIxu3jLz0/rFs7GZGzz6YBmwYF
         8SVD3Byi315ZZKXDsP0oZVDvuVfHrnRciuZiA1z8FMjn6J4FTKCMmq+IMqf6DSjRP5A2
         Qm9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MbSV/0QgndyxPpucafkqjoUk93XB7CWZmEyrMAmxEI4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ouiYqUXf7r5y3AuUMGB0aaLHR5CCCOG4nAdF1uKcyftO/LCaC5Bh3yZ6dzgul06yfe
         oJf+tvTKKyqxY8NsNBsxo6FgEVIvcli36mUw3AzkG+vvNxd37B7iU9iQYQZ1yb40P76f
         If1W9M8JAvjOhzn1nrTQ3exobgctytLG95ztQOk+kkyc/0hbORnBZ9kMrpltPYWsESPP
         +bYsCjom220LfE01c0SnPD+7Wtdx/sWyLTaj0l1adDJndVM7qfnSFoGDPKIGvctENqJ5
         rPbK89/aZ/Nrez1/Bzh962egDBRbVYd4gp++v6Znou1Oc6+P13tWz++q6LpjWEtixUKS
         m1JA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=foNfqk7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d12706d3si11791173.6.2024.06.20.17.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0LFt5001852;
	Fri, 21 Jun 2024 00:26:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8aq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:48 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QlKR009504;
	Fri, 21 Jun 2024 00:26:47 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8am-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:47 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLdx1d007675;
	Fri, 21 Jun 2024 00:26:46 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspampe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:46 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QeJQ29819576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:42 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C16962004B;
	Fri, 21 Jun 2024 00:26:40 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9ECF620043;
	Fri, 21 Jun 2024 00:26:39 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:39 +0000 (GMT)
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
Subject: [PATCH v6 17/39] mm: slub: Let KMSAN access metadata
Date: Fri, 21 Jun 2024 02:24:51 +0200
Message-ID: <20240621002616.40684-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 1A4HKTza_ocuX6M60P_a4YFE-_n9G1yK
X-Proofpoint-ORIG-GUID: UxAe7IFBDVT7uND_PYXcw2RbRkIaNOQ-
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
 header.i=@ibm.com header.s=pp1 header.b=foNfqk7y;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 1134091abac5..b050e528112c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-18-iii%40linux.ibm.com.
