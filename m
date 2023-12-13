Return-Path: <kasan-dev+bncBCM3H26GVIOBBCUA5GVQMGQEVWN4U5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E32F78122F2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:43 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35f68dc93d5sf20060465ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510602; cv=pass;
        d=google.com; s=arc-20160816;
        b=JS9cdgofv33jnHfyKxJ+nNHYzkDlMVsRSW+I6rUAjxu5ircSF/OfwrMDa9DWiJyq6F
         oW/uJGy7WAppjRNxe8jj+0eDH81oSCEscAVw+N/8bsYOW+7XaI181Cv7JSO2B/vdNinu
         pXYpbck2tcukdwL10UgsBIqy3yw69VkIghBEM3d5pAQKHOoG6+qMmpeqrx/0b0bM4lMn
         5fbA1QG4DJ6mP2xP61oFL37r6P4BUUKewSpDgXm69bGnpqyaSXLjA+gCmpVycDnMsR9i
         kveCn5PwCOSOxL60RufseTqQIPfa1EfCR6WFYs71lPtNU9+dEQ4jfi1hZzKoQ0bLJ9al
         I2vA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dtrLyJBsAAnmL5TwpGHxBxPJhc1w4LkXf7RXD3VKuJQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ZEDh/BYGn10jbF60aGmwetWxUP7b5sRx6d2r0UPccBn5W4MZcnQRSfBj8xFOnhzrfn
         viYs9dFKrt1y/2HRRoVHDRb+fss0BRWGndhSc0DGwSsSHS4pBYyfQGzO3zidLAiOEN4S
         3y0t6go0gOgpTdBvP3XR5qDfFfRnqd+aQFdGLnSwZvEjONbZkz5YA7MabMOF16HYbo1i
         XMjCiuVJM0MEBqkRaj2gVvdvdJPe+w8ELRTETamYEQTYzh1ZbJ4Lvh9INnH0czzfRpat
         5ZIINfVHr1ICBtYsZiSiuf5HL5dH+UFqvPyoJuo/zuc0AMlO+J06+Mcij3fqAd2Xodb7
         IQyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DjrNa9T5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510602; x=1703115402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dtrLyJBsAAnmL5TwpGHxBxPJhc1w4LkXf7RXD3VKuJQ=;
        b=jJb5pqGfvUVqhRhKy9qsHd7QpOMg/ImH2u5FhTXS3fUJYetChljiJT0FKsOJjYLOJD
         fk8Z3+PBFIco6VX6y15ZUKHq9qZR908MJTQ30Jy/SMd8kZxpnGv4k5vWJC5Tc24HZWs3
         NOMfg2SVVHwMbZN4Xb5F4Q1LIVR5Xl9jPh8fa4pnkxaS6o1GXgndK/VDIYu/MDQx5Nbn
         ZTvFB5deL7M1UkHjavA7aiQQeqJslsQ/QgdE1EhHuZxEMPWt9ZTLcHJUEQis6FKE1mwS
         xSSQWfHP1ctQeCAZYPyXlNxKycyoZDSe1bdaBX3URXEuObda3ECoyvtt+fJnByxWsn2y
         8DFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510602; x=1703115402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dtrLyJBsAAnmL5TwpGHxBxPJhc1w4LkXf7RXD3VKuJQ=;
        b=hU7AHn+1iHF6sA9QmIlisANdR1yicTFCtAyWvoDelV52mjCPnxdfeqYKGR0p5UTrcu
         L2qE9W/CbB/jJZHuyhiwY8daXMajnzIpYrl7cR/SOJCE5jjHvvS3jtp7i7lNDPnkVtRu
         0jAnJHy//nqHSJHl1JLIFVJLUICPzZu6W3jVEm8jM4wI/Jup4WNEvtKetIZWmcHgtZGq
         I67qS0Gisz49BLmSwEuCGp4JCKQuOCaeCn40zk1d8J8/TENLR304MZ5Ds4ARjc4ayrTC
         2BNZYM2/ePyzpFKzjxcJYI9vSEEJI0x0Crw6eGAiHfUHXsAZBuEy2RdpxyPWXjqcbr95
         hZPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyzr0Vsrae9fEEMnEiPIw0qEBf7SZoXwpz+PSy+Z9NBFGZYkerj
	n7GwRZn/QA75aFBLK0l55hA=
X-Google-Smtp-Source: AGHT+IFdnAJvpfqp4zXiUXmGSuWFCHwjroXdO6bSEitBhZ7aexFsw1XA0lFzC4kI2U4xCCSulsNWZA==
X-Received: by 2002:a05:6e02:20e2:b0:35d:5ac0:5062 with SMTP id q2-20020a056e0220e200b0035d5ac05062mr14222527ilv.48.1702510602537;
        Wed, 13 Dec 2023 15:36:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2483:b0:35c:d384:abf1 with SMTP id
 bt3-20020a056e02248300b0035cd384abf1ls1376090ilb.2.-pod-prod-05-us; Wed, 13
 Dec 2023 15:36:42 -0800 (PST)
X-Received: by 2002:a05:6e02:1521:b0:35d:7711:da09 with SMTP id i1-20020a056e02152100b0035d7711da09mr12396915ilu.63.1702510601906;
        Wed, 13 Dec 2023 15:36:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510601; cv=none;
        d=google.com; s=arc-20160816;
        b=x1SPisCH7Cq78sLYhqAIUBAOO+AG/btYhOsaElnc0cWba5VeXtUatqCr4bl+VTJmLM
         RZYTZ3G9az7APfSCgX6R1etsT2A4pQ8GpL7bA9ykJYDBJq3GHu5t1rZzBQM6UQ98q7FY
         VAXFcIRtqBeCk4q3BzSdsdue6NHTQBQZYeLswvP2SR92Ut1I2WHBtFGCepEV/7bOq/ov
         LidtKVluHuyp+2KFla28A8L0+0iHhWyoXJWf+OjPpTE+a+XjSIgq9AiMZsPHlDijYR1U
         R1dglBqtWGLbuycfz2d8W4+Y9RU/FAalUEmOoAPM2U/hIKrEO0lJuv3/gAbkUnngo94K
         38Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xivDROMC2MSJ5oqx3z383eaVzZ8qGYoAxlkMDaT1E7o=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=RoOMgNgwefBbRXzCGwj+aO8JKxGkFWTdmU98bSJakieC9gB63/UJiAk0nU5zvuY/jA
         8iM3uphxT1BG099ZapGtIjt4R7G5LuBREnu7yYOpnsgj8AOTj0tXK/LTOD5jWrs5oKY4
         XtYg4h926NrFhwhTQPbqyaEIDBtEfU06pAPSN1F+iynEwhBtgO7YvJHCiR71jEaEuRQl
         ms+AAxClzUGZtP8RBiJpgZfPYAbWG4bDt+smBjqkAYpmfcdgUKQARIfMPAyas48+yD/3
         zDPtESg+213+shtwXO6S5j2wF4gsd2aWZDSkBcVReMLOuGO2Ntahpu1/Q9kwhl341wcc
         n81A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DjrNa9T5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id p13-20020a92d48d000000b0035c8d7c3820si1214566ilg.2.2023.12.13.15.36.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:41 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKaLdq003691;
	Wed, 13 Dec 2023 23:36:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek4929-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:37 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNQiae029277;
	Wed, 13 Dec 2023 23:36:36 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek491u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:36 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL4sCD028206;
	Wed, 13 Dec 2023 23:36:35 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyvrpf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:34 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaVgv31130210
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:31 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C203A20043;
	Wed, 13 Dec 2023 23:36:31 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5C3B320040;
	Wed, 13 Dec 2023 23:36:30 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:30 +0000 (GMT)
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
Subject: [PATCH v3 14/34] mm: slub: Let KMSAN access metadata
Date: Thu, 14 Dec 2023 00:24:34 +0100
Message-ID: <20231213233605.661251-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: pVuzK0gQdTIFnChN-MT9dtMNaW8q7lGC
X-Proofpoint-ORIG-GUID: NkNYkei8hiVoPWsPSF-7lXxeLJhRULql
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 phishscore=0
 mlxscore=0 adultscore=0 bulkscore=0 mlxlogscore=966 suspectscore=0
 clxscore=1015 spamscore=0 impostorscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=DjrNa9T5;       spf=pass (google.com:
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
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index b111bc315e3f..2d29d368894c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -700,10 +700,12 @@ static int disable_higher_order_debug;
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-15-iii%40linux.ibm.com.
