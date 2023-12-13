Return-Path: <kasan-dev+bncBCM3H26GVIOBB7775CVQMGQEWQBFYNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 48B758122EE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:33 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-28ac420d2a4sf2610127a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510592; cv=pass;
        d=google.com; s=arc-20160816;
        b=pEsxy5hDCMiMym8ic2TgR6HkxMNqZ9VNXQ41HSzAElolQLoy/4LLoVsRZo79CD+lAy
         zMUMFLrXanAhd7BD+VTGc3ucN6wgSiqj4CjIAW3wol2A4Ij5U7PF1mXtZTg+hHBSm+zg
         6W7dSIkXizRBbsbiIuAdo6UXeeXF+mE2XQpWXh2CBNSa3Alx3ogTS8mTAZuMl99ZHCoV
         6HbG5fDwhf4j2m77hjYZoF0E3rcBPhikKVfI8vIs5Cr7ka+zKRcrJATREDQ6k4b35OjF
         f3wQMDR+q8w48ZJ/pKNqsvonDJce0qgi1xfWTFg6ps9P62wLmW0A9GannH4/lNKhzy9U
         CkbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HX7jUQjvRhRXc+3Xn+8Vjh/G3+HYLyfqnIeuaK9vLDk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Sti/Ys6vxbiSHAbl03PH8rC8nTyy0I7HqKVYX/pAFXyN8IdmCSEPvhuYmkcpeqB3J7
         oMoC3JsMRGRw+bGrdTrnzIgD0cydZLFvnKiBumUfoNCkV1yFME3Ekj4dwFtVbX/B7TKO
         GQ2X0cbBTfa/ryIb/vKRz7zyLq2waDnri6vI0ZQDgS75eHw2TNO3N3ATDsyDvBfhXJtw
         6kJaHRiyehJtTJxfpznhwoa2lso0aZXJxyH7f6MYISX6vPxYU4PHugRCarS4O/8+SYld
         CEo0huzT3d/udvS9SYw1BiEcJvzJB/9m9+KYk8181QY/glYgvgZsrQUnZZucrGK1e7XL
         Y6Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fJkCRxEn;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510592; x=1703115392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HX7jUQjvRhRXc+3Xn+8Vjh/G3+HYLyfqnIeuaK9vLDk=;
        b=thvQcDPhw37viNsbGa8MX1ZrPmtr/hiJni2mfouiU/siKpZT/zeE4O88UXWons/2d1
         N3iHtwNeuaMHXZaCFvUWrgvpY1+MmNUuigj2njo7Ahfb6i/hjug224vi+EcrnZKWO+iF
         FM7g6UWmUvEUa3Q6rfOVPo/shQP/rFAibXn1DOO/7MpRtXTpIyxS62GMzPBQYMkkcx0A
         XLG0Oy4vvbxTDeCTXGto9bfuo8eD0MlPTggER1mKHzbKsdZwEds8efVr+OMBZNLEyvss
         Nd6SJaLN+mJRnBArcrZhkdcBI70L3deLeVjZFlet5ovoK64qOYDeX5N0dK2bnJOFdmjF
         bzPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510592; x=1703115392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HX7jUQjvRhRXc+3Xn+8Vjh/G3+HYLyfqnIeuaK9vLDk=;
        b=iuq6MqQyKYt06wH6LT4CoVIFw9JDRfCVWuvc4JXgtHni8NMmZpiTgeCLSst4qvAftI
         KUVjxzgrzgDz8KH/IYakXINPdetYUkrpDlheimOUcraUsDqHA3+RBUdIOO98KY0pazaE
         iU4APsFoh4T8DGoQjMOe3P8Q5Km/43yReEBDE3pjsx/s5F41z8qh9aVH1lcOgBa+Y404
         ArKeOOsO3HNIxnimDGr255tpOFhm4ucwuF0WEP7m6ZARip1L8rh1hVBaoFtcY0GnTphe
         sB1wHCuuTrJ6OCFVivqrHC2a5aqMpIexQV7oc2hTiMwt6uXokplzUWN94vIPIA1vJbPG
         XGJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzOaHQLm8lrFwGvVmRE41F3Ybz5m6n2n7PbuCTXUB7iDaMmdYat
	BmC63FlW8U8Y5RHt6I1bFNE=
X-Google-Smtp-Source: AGHT+IHJAvbvsDJ9hgp/wMOBCDuQgH16bP5MLnT9/wltF1pWeCDQg+j0IsA7xlv5w8SBKBT79rieuw==
X-Received: by 2002:a17:90b:4c0d:b0:286:b6b6:2a4e with SMTP id na13-20020a17090b4c0d00b00286b6b62a4emr6613277pjb.62.1702510591740;
        Wed, 13 Dec 2023 15:36:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf96:b0:28a:d78a:71c3 with SMTP id
 i22-20020a17090acf9600b0028ad78a71c3ls1725129pju.1.-pod-prod-08-us; Wed, 13
 Dec 2023 15:36:31 -0800 (PST)
X-Received: by 2002:a17:90a:4943:b0:286:6cc1:781a with SMTP id c61-20020a17090a494300b002866cc1781amr6659924pjh.93.1702510590704;
        Wed, 13 Dec 2023 15:36:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510590; cv=none;
        d=google.com; s=arc-20160816;
        b=u1j7b/IlR+6IombzfPgTrC91Ssy8bXgkIA086LKqdCodGljCkV+EZDat9U5wiwfY+k
         3DvdwAUPm1cpiAeQ96n3DsJk/xnmz+L7iKKVpAyQrkwUAvQCLvx8C/x3y3WsqGmxRrw8
         L+QBvfH6kyqcZANtGBU92o1vMYMLzK0mohy/FcbPXFuLYI1nBTIAGU4G2R9/k+Q9gRUs
         jrX64Urz/EfNS6KIgniOoSUEnSEdQFOXu76nrP3LQYkucPNN0B/EBscfig895W0L8OS8
         wENen08Qulm+deBwTRt5dl830tGXq88VntHDnph5pBE7ud+6s/lHYHuQ71oLlGMRy6s8
         ZI5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aJy+33XKEF6nDugdst7XcqtyB+KXoQlaeqKIDwP5hKQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=N+ZqM3zp6PCzINmcvgFp+PGUkElOi9DRNe2cqPBmQMMhIkj/hRvdXia67SqELK/AMZ
         t2Q4nUyMYU2vSDqmDWk7sHVlzv5OQU0M/xITQM5GUlanmiaRzpiTAr7NDlCXL5vEdg70
         Q+yq2KcOR9zU78ZW8lHJrJs+WRbvq9dgEwyHt5hJVU5FPz+jfs3H1X9AcaeVQZsIcUlx
         tOav4SJOdV/dwT9iBTTNW5r4CvyvMtfQ90JynbrUT9uiQWicIqdkNFSKC3ippBEALr51
         DnBraurQUiNIXe1zV7el82tt3o2K4l4kA6ZY39Uxl+SuOm4OCMsda8Of4yXiRB7Gc01p
         g+uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fJkCRxEn;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ml7-20020a17090b360700b0028b06d87049si31789pjb.2.2023.12.13.15.36.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:30 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKaLpJ003679;
	Wed, 13 Dec 2023 23:36:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek48ym-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:26 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNaHiY022962;
	Wed, 13 Dec 2023 23:36:25 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek48y1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:25 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNFEm5013937;
	Wed, 13 Dec 2023 23:36:23 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4f8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:23 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaKdT17695252
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:20 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C56F820043;
	Wed, 13 Dec 2023 23:36:20 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 611AD20040;
	Wed, 13 Dec 2023 23:36:19 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:19 +0000 (GMT)
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
Subject: [PATCH v3 07/34] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Thu, 14 Dec 2023 00:24:27 +0100
Message-ID: <20231213233605.661251-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: i4JpRSSp29x3tjdWkj2o92p0bxjHziCE
X-Proofpoint-ORIG-GUID: PRnzVNAw21kFZDf3ZPbjJSrCYd2IExSw
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 phishscore=0
 mlxscore=0 adultscore=0 bulkscore=0 mlxlogscore=997 suspectscore=0
 clxscore=1015 spamscore=0 impostorscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fJkCRxEn;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b9d05aff313e..2d57408c78ae 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-8-iii%40linux.ibm.com.
