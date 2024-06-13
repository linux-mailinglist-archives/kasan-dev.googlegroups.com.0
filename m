Return-Path: <kasan-dev+bncBCM3H26GVIOBBSVFVSZQMGQEGZAI75A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 691559076E3
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:55 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-44057384a9fsf536021cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293194; cv=pass;
        d=google.com; s=arc-20160816;
        b=oWYNbOaxXIoeP8ePngygfP5Q/Unu/TSJX6LJuuTcm9+y8hwUg8zLogamBDOAHL88yj
         kNibo4u4D0Z+PYfctKtEXKV4orSnmD0yn5/fb59XTb8lHjHZNCLYG2Snwj5LUu4dGt5G
         sdLnSu3r8/WImcTp18vMzu0Gpajs99/Nmjifd7cT6No3GxeaknMr6XucmyFw1ZWwn7IC
         mMOmAnSzERFVdevQAjpfhLvTckrpj4NNgdH104wcN8w3ylfptuUJgriO5FJCuxXWGIPA
         smcNRSPbb4B+8kbVWH5Bv2vnMzFwZwkX16kUsbzo4M+8bWoT0Dx7P3W4Pm65pdM74uBU
         AN7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EsdG8NQHqPWEBw02/2fAlVbWO8xQorW3gdEn3U1elnY=;
        fh=UzFlcRrAXsbxvROHv3sjoycskg1/BWxC1HGKJ4iafyo=;
        b=bz3kb9vZyaSUlAl3FjSNZ8y8JLNFaDo/vSpF1JOY1YIaqxKKnwpJ8UVJbOhIIVlraV
         pxziX/ROHGCxPYLDw+6aCTHXk6H9SUH91u0l0+2JYmTnwFhCY5wJY2IJv1kdEBW9fApY
         9+W1nvvXQygnnQQ4OwhbN1lsEKycpoRFq9AG3KzZU6cGrhtbVslTmY1fgdMBLCGP1j0C
         NMRB+cXhUmhYkAQ6daNwUuHAzgQxGGHc9hz/5ZjGQA0h1cgAcuJWlNsmHONfNFFZP6a0
         MJnOsrsvFX9YJsOIcZuF34bGIm2StVWmJPlOI3aPF7afJ2rprGNSDOszRWU15y3idPYC
         I/gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cWyIHDq1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293194; x=1718897994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EsdG8NQHqPWEBw02/2fAlVbWO8xQorW3gdEn3U1elnY=;
        b=fPBpW9phJk7EST+EDPVWcUgOy8pVdEb+REtzj3IVf30fIhpQoHC4tKw2xQOKdSrY/e
         tS3wF2Bb/AjyUZZVaqV+lKCPTQX001yM3KGWRisscuPuXVMT4yX7qJU3bBcnFNeo8YcC
         0XuIielp6Rzg/tx5U1psYkLcI8kEveEN36g6DEqSA7Mf3pCjTYYcDS08PEZGH7T9Qqju
         0vgOBFgA5PDf5igXty7Kxm1MlTyBZZGR5r1b53LSmz+5GsdlcDGSRMJvKksufpBpnBUy
         6DqaoMMmTvYdzB6q4VJFUTHc7cm2zqOq/zdBbUkvwciEfI6AdXkkp5SdE72sz7836rtk
         lsqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293194; x=1718897994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EsdG8NQHqPWEBw02/2fAlVbWO8xQorW3gdEn3U1elnY=;
        b=vDa8gXXuMYxe4x7WC9dsD0a23JavnNe6FkcWdvMamNIczZK7RY1YokmwaxQweKt44L
         xEnJv5d+1LcCD64YLpWU+WdHKQ3GKKxoqoE8mdsTRBfj8d4W1Y5kQKvwELtJO2e0VycK
         5rosObCHS7qzAJoyZIdfqiOYH79sH1JjiCBKBZwvSH282f9Up60+C4pJ+lF6PqKGnK5L
         O9Y3nzKbs+l7/r2RwIYLYOUU+iVYC1bOLUNupCvVuXJeIkCzD3XmOYgx7fGcj7BrpD3j
         5sTlA9SHEBZGIRp4PxaDe2cKf48fiFj/mDin2Fggs0cpFGihSJIRHzZG5feePH9k83gy
         r4mw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWebrSBbXqrx2rxjKLC1W8ODS0abURpeOwG6M8jB/s0bJFmtOms6Bt8bcvv3xtVA2nhFuYRkVaWIesrPZEvlymDo0S3aG4FRQ==
X-Gm-Message-State: AOJu0YzYj0hZVPyFKgPPNKRCShpXWdIxaUV+Iq1jym1LPVh+74+giSeZ
	vSG2iEqBK7RU/EUXUpEvdAUMC4/io31Ieukd6bGlD90A92xft4Gt
X-Google-Smtp-Source: AGHT+IGCCMsu2Npy6fVJwYF0zUmFx4Wg9bpWKEYNBcItN+aNhIygbWaevQfit6/gnErphBuH8zIhWA==
X-Received: by 2002:a05:622a:5a95:b0:43f:ff4f:c130 with SMTP id d75a77b69052e-4419dcff32dmr4492701cf.2.1718293194276;
        Thu, 13 Jun 2024 08:39:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4ca:b0:440:348c:4bc with SMTP id
 d75a77b69052e-44178dc911als14307191cf.0.-pod-prod-06-us; Thu, 13 Jun 2024
 08:39:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYQ94JhAZnJIG5M/37KO0B5FMmayZKIlVKQBAIvAefyn/IMguIm04bOkSh2VLTaHuoF2vEzaHys5DfMwKxfo2iopwXjugERyDwEA==
X-Received: by 2002:ac8:5d47:0:b0:440:c960:c14d with SMTP id d75a77b69052e-4415abf5f4fmr47905161cf.27.1718293193489;
        Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293193; cv=none;
        d=google.com; s=arc-20160816;
        b=vWOjmquSMzinsIU4S/mHT/XZpFgEojHrlgbiyi6FB62sObC7Pfmp5vg08O8k/AIgbe
         hAH0MIFUr6oy4LSFx+XuGMNxWMra+Dlc2Ozz6Q5LR3R7xN3C2LGOL+ru0AkxSPTfHHOe
         L6egt69B5rad/n5mvpcNJUeWY80hI8mPc/IGrdzygCloQN7BXRCeO5wHo2QDgwQwXQaL
         jcsgHBsm2u83m+ye+8nBjVbwod7dg+5eHhOoI1PVq17unk+QPw1HHyE0ToXQv+V79Yd6
         5yx+T5YWuip2Gif2+azX2vE2kwZd5e04MbT/WGk4kZJV1AmcfkOkT2wELG+9acZh7QJ4
         yn/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fhyNLk4BgDYNJAsfSc8ftWCxz9OlL/4RiKPE6HJFalY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=SSInYqVMLBrcRU74Tfo1ohahNqICfs7TgRQQPgjUGxJQxtX5P9fBg+mK+0shVFw+m1
         8J2nucSLnotTQ/Q/410mhpp70bSwWGynRmO9irKYDL5GZRE2T32JDr7id8ZssoQXiGWg
         aU8YQEJoQS8Sj1/4/IOXd5nkDyQYQrU+7KwkMc8/1sKVsbUb89rQn7KrIvUk2WeEnyxk
         qftoz4cxcvFZdlFedMAT3opql8QmbcynWODfmV8aN4uK0YENmOQKdL+k5wQTwuLn14Qq
         0QtuQ5a37YqtoitfJdM3prozonnYqI3d2i/FjDLFuRHhPBwyUxsclFA/KE67sYt1h9i/
         9bYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cWyIHDq1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-441eecb7d9fsi919311cf.0.2024.06.13.08.39.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFRdFr006553;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext122-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFbRBs026015;
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext11v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF1n5T003878;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mq9174-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdegR28836448
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0DD092006A;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8F70720065;
	Thu, 13 Jun 2024 15:39:39 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:39 +0000 (GMT)
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
Subject: [PATCH v4 13/35] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Thu, 13 Jun 2024 17:34:15 +0200
Message-ID: <20240613153924.961511-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VR4XIXc8lKCWS8yjNDEOiQ51qu6t9VNR
X-Proofpoint-ORIG-GUID: k0noGJyAWC71kZXWZHDEVVjEwOhT6Aub
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 adultscore=0 suspectscore=0 lowpriorityscore=0
 clxscore=1015 phishscore=0 spamscore=0 mlxscore=0 bulkscore=0
 malwarescore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cWyIHDq1;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-14-iii%40linux.ibm.com.
