Return-Path: <kasan-dev+bncBCM3H26GVIOBB4UB5GVQMGQELF7BM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C313581234F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:40:35 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-db402e6f61dsf8141212276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:40:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510834; cv=pass;
        d=google.com; s=arc-20160816;
        b=XymCIENpoBXVWygwVbtG2C5LY4n6Dktnm0InUVqztOn5+kcJ9KeR2+RV6pwnWRuL/f
         h64DceilwzBRlAxDecnYNzocS1A+CsHipulv0pRmZa00m8Fdn6gm5QEy4imjQnL89ArU
         LKQUEGsMEZk8Cvk8kl/TXQ3CH2K6/NVsvuHHgv8K9yKV3GbNe0KToN+r7uUtTRPZ3SUu
         pnY/72S1P/oRwyyt/DUXtEgoG1YCXtWBOrrDRxj7aG8j2COkUMdOSqFW3aXdGNk2cXCe
         Q5vgGmAcTm8uHU8poexYVxaX/1EUpvW3iSg6itY6chc/RNt1IKvlFdQF6c/7UOZ7x77E
         nsMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zGLGnRTsn+6y0M07UC/4npmdWTMKCbzBgJ0XjTf+E9g=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Eaj3WT52yTRK35cZsMWCYuC7N4AuMdzikGVqv95pTrmZudO9/0OnpI034Ddu7cOnLu
         5Oy/3rh7lYkDDJr6HcWLXh9e/wrrpTlwXrDapEW/ImGSpd6yrRQqghJAEp6orn6EWtgY
         I9v6xOwRQsxUXof0q1r784auty9luMn0y/FdCRkhOptTqp4TXiIvfUgTdURQ/EmjK6F2
         N9x2nWOGE90LUJkSsTBzJKincV3cBUj3OJABACHFDNl+vUDIm+niZgpsmY4VowxEXLsW
         uczs56nSxH/Zwa/6IDJYVrBGY1OS+772v7fN2EfuRxetQ811elOZhnC7jZLQnJRvpEhr
         8fgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rug7CVLV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510834; x=1703115634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zGLGnRTsn+6y0M07UC/4npmdWTMKCbzBgJ0XjTf+E9g=;
        b=b0r7zo67bgB63lQk9zlNpCSHPbk2UYwYOccVI/z+nvT7bjosMw5+td7/0i80H3cxGw
         lgA+kfep3vPSkjyidAxFjGdmKqd1fkrN7qDk02Am0EiqDmohwjU0tYKiLPAYCPYZjvy7
         NvjcEiNjdSj5g+mAO+BXOIoqRyR4lZLn4XOnapkvar35b1Gr46U6hazfG9Iw6p5ASS0o
         YMH4+3SO0TCkI0uvoIX3PFUs9jWmSxyBY/7b1HFw8oqBWYK0J++XVEY/9XEhr5GhnRfH
         98cT/XXTPqgwXZ83c+4eYz0CPxgAOXr9xwrSXorIBxZrUYp6xYCV1go01KNRU3Wy5MJR
         GaWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510834; x=1703115634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zGLGnRTsn+6y0M07UC/4npmdWTMKCbzBgJ0XjTf+E9g=;
        b=aPcEtoGxD3Xa2nA+oHyU+tADVgvVu3ZUxfwc5/6tLGnssvS45Z8zxGhjPhfF4hPaLS
         QVOPaDB5mIMs68irwc76cvGqbhqaZupfHafEo9Z9l4oc7vjiptotyWyiKPiJz23L9OS3
         9gNu4b/LZBeHvDyZmHen8LvAnD86aFh8kh9q47EuWBPCvyV164gYLQCzgNEk706Yjwwi
         +XZYpO0cu1Bw+g3kUtofJ1wzfKT8Z9DQw9vuURb9bnyUDgBpoziLN1BYkb0vQGCnJCB5
         6uFoYik4fh4UcsbVAcEN/OUa4hwP7k/m6/GcfIkZB+OcVIZFzhf7ZsuWBgGFU8owrgri
         JiZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxT380PQyOMSrb7Vhykv41dY6F0utEB6ZhIF4fqYYO1xCcxQKZZ
	GMMwDGay7gH5glkL6IjHMTU=
X-Google-Smtp-Source: AGHT+IFQJb667cufnRCEIxF3RAd+mcVwzf3hS0IwWtIgUw1NhhlfJ2HeGKi6aX9YYkUZ3FDDtfG+mg==
X-Received: by 2002:a05:6902:1b83:b0:db5:47c3:e5b9 with SMTP id ei3-20020a0569021b8300b00db547c3e5b9mr7423776ybb.9.1702510834432;
        Wed, 13 Dec 2023 15:40:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d081:0:b0:dbc:da54:fc5 with SMTP id h123-20020a25d081000000b00dbcda540fc5ls1085452ybg.1.-pod-prod-08-us;
 Wed, 13 Dec 2023 15:40:33 -0800 (PST)
X-Received: by 2002:a0d:df11:0:b0:5e2:9aad:b527 with SMTP id i17-20020a0ddf11000000b005e29aadb527mr1892707ywe.53.1702510832855;
        Wed, 13 Dec 2023 15:40:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510832; cv=none;
        d=google.com; s=arc-20160816;
        b=Dy/KR2+oGZSNk9rxTTNh3ri1sZT+ss4++IvxEVA3aFmZO6Q3wQVPZ1BcPcTdwnM+Ih
         DX5eFmirSd9bH32ugXPKx+h856LtB/lvbEN0V8LfMc2EmN5Ckcgl3FCePGWlFGg2zNro
         ZNZV4LyYK3e51y2VlfiofZLL/kTSD+DumTFlG21I97g2jopXRFGx7XFBwVGk0oeJPR2p
         fwGlNCHERPVNwDN0R60f/zGlEWfGIqqTwD5WvBJ3h7VlO/09lqjPcBrn8guib3ETUlqw
         J5a/8OFKd0T58zF8iM8yvxIDevfATflPYcDYgEsKbT/zXQePGhJj9FD3Tcp+ZZ5yBBJx
         TysA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f61PT7g/vuAibsjDOy6DAIgpeWx3be7RgbReYtda3cA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=iGZhdC91Z8JXXY+YxoCzAfcPsFs7MkhnbpaL5W2tFFQwHlo3VUyLtDBrJ4SGlmKL+d
         AXlCAyhMnaNPHknoqOs32V+psatJB/6QIb7jU9QqHrFe2Tmu7mzuOCWnnK5eTbhmTjMK
         xno0kmd0sO83d+yqQ/3WNIUqWP3S3Wx9WPJlhYVu8hTpC9LOjKSLMrcaGg0I8mVhjail
         59N/Bzf0noC9Hkl3Gke2xCJ/+Mw68ynRtJ5nKVMSHJ3dpYE1QZm/zdI7K6O9CCmWUSvG
         S6bx38D8bLfRLQOyoJsBe0P/k3I6iaCI2T8dpQDuS4atIPI/6Wke5Vk8iRTU8cDiy/km
         /jLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rug7CVLV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id j27-20020a0561023e1b00b00466025e2258si3198402vsv.2.2023.12.13.15.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:40:32 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMe3sQ026112;
	Wed, 13 Dec 2023 23:40:30 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5xe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:30 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNLwT7018904;
	Wed, 13 Dec 2023 23:40:29 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5bb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:28 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMvT5Y004899;
	Wed, 13 Dec 2023 23:36:33 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skm9wb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:32 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaUlL11600636
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:30 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4060820043;
	Wed, 13 Dec 2023 23:36:30 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CF4E820040;
	Wed, 13 Dec 2023 23:36:28 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:28 +0000 (GMT)
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
Subject: [PATCH v3 13/34] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Thu, 14 Dec 2023 00:24:33 +0100
Message-ID: <20231213233605.661251-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZnvMsRQHFj5YzlpSvFIojYHFjtCw1G-g
X-Proofpoint-ORIG-GUID: 9YWJfdp_hxIenSUs6PPpY0jtFMAnoXZX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 spamscore=0 malwarescore=0 mlxlogscore=999 priorityscore=1501
 impostorscore=0 adultscore=0 clxscore=1015 lowpriorityscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rug7CVLV;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-14-iii%40linux.ibm.com.
