Return-Path: <kasan-dev+bncBCM3H26GVIOBBYOW2SVAMGQEQQRHYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 942817ED221
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:43 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-28004d4462dsf12552a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080482; cv=pass;
        d=google.com; s=arc-20160816;
        b=fBXr/f0xetBafau7RuXDu+ITQR8KPuZvO2tv4FiesQLIKcWD2YofHLqmPBOfdNLGyE
         vqo3YKIIVMisGLFImv2Jr07GAZTs4gg2zZdP3PcDLM33gHaD4XKUwg9r+b7rTIwiM/4L
         hjLIm6StIANX3tH1cjO9Db+2s7skJiRH/rsEMqnN/xPXMEteHskVy8/3pM2Kk7FGw0H6
         g/zs1rRNRbDjZ+lhG/EYCvdY7B127M9ssHasspqSLFvFEDZ/CWZvAtsV/qD2yE8ZT1XP
         PtkpwnQ7quYeiPXVDrr+W2smUpJLU8UNo+2wuudoZ/ED1SS1ybZ2vhu7TMwzyRXJJ2/9
         3ZLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wb4Yda0D4LrTuyLmg4khmTIKn68K4Y9NlkHHe3HAfYc=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=tO3Gwf1yMKIxppOayxSTKzbP3tpDcW4ZfGjbQLLTpRZlpbaKEP/0cPaXDD5NfnL1dH
         6KMUn6sHV4h4UwECqJjmXSksMptMdjh+RVlgUzFcpaHWXRa+q91askw8Lnu/8fpAtUa2
         FIflbBGbtBBs7WJwayPU/pl0VqddPBzd5vEQlys+kx08vvexXyA+XWlEnPJMSKh3JKiK
         aaoAzJPuAwY9opV6m0qJpzjUlv9qhi68BKwGADpLInLKYZHbsW2q3oSYcH41FF+bK7rN
         197juJ5LS8K1jzkmgVDRxhTe7Niugh3fZjbb8o+245Z7aaW6gF1gJTvFP4+84la1KRIa
         /dDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jt5dURUl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080482; x=1700685282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wb4Yda0D4LrTuyLmg4khmTIKn68K4Y9NlkHHe3HAfYc=;
        b=I3Vk0L+zoUjGpPFQ0PZhAwzmkCY9cxWx/XNHTET+dmO98d+RkFhYPwgty6KqXe1b5O
         nejc5PxI9x1cLfCaT90Q09+IqoNrA1Ka19qOM5o/N/Cw6F1kwIBW4G3q/Az3uPk8HmEZ
         ot8nbKZaf3TVo5yTbMUuYKdvHfJtuLxKKNigPKz5qlHED+9FIIFdzoZdkH00lMZkqDrF
         sywQQI3O61A1YKBoRIeKXXGh1N/rADZHhRqQ6ueL6Kw0RzYQ4XjTVJ8OPXcKO0XO+Fe3
         ZnjI7JfCZZmtPsv6vXIDrbYLE6p6otbrvE/DKZ51rRcR1YuI5hqwzVQQZ5CaOOBj0Ofy
         CSBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080482; x=1700685282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wb4Yda0D4LrTuyLmg4khmTIKn68K4Y9NlkHHe3HAfYc=;
        b=pC8j7Bpm2+1OVtq7OTX2+RuUwEikHxfzW90j0/mFVoRdP7usb49YKpaLF40uGQS0Ar
         2vZ4fmcDmSug759KtNQh9VAZdVfSj5RfSHLJZQl4hwBAimULOJESHBTC2kfxRE6HIKgU
         r7TOX4KXn4NvlE6mrHmJ314R5a7w1fvwYmXHjXUL0ytYx6Yb3t6h9j/oTOd9Cl/P6O8X
         xEczgtwMCvHYMcBCp/Tk8xPOPVmkC1PS8l53JSGvQ4VG7bGG6PmqDb5guE8Bgng5MeoY
         bZbkOlK3HpGcLaVmnyvL4TgsYllujt/Xja8cjwc1P+lfC62XluG02zrlpHnzPTMDgk+s
         g1rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyv1QMbfKybk+WjjxnSHww0Fx9hNFniD9vEb9WEK2IJIeTCl63T
	jxL3YgSpzF0V3qUfMDwtEao=
X-Google-Smtp-Source: AGHT+IGe8wlc3XahCOEGwQIoXCuoIxJIyVxfvxXa5P/mlCxngCyT7YZzT5vaJBAnpbgtt3j3wRH9oQ==
X-Received: by 2002:a17:90b:4a90:b0:280:c98f:2090 with SMTP id lp16-20020a17090b4a9000b00280c98f2090mr15617087pjb.32.1700080482056;
        Wed, 15 Nov 2023 12:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c4d:b0:263:b62:446c with SMTP id
 pm13-20020a17090b3c4d00b002630b62446cls134193pjb.0.-pod-prod-06-us; Wed, 15
 Nov 2023 12:34:41 -0800 (PST)
X-Received: by 2002:a05:6a21:33a7:b0:187:afb0:c2f7 with SMTP id yy39-20020a056a2133a700b00187afb0c2f7mr154795pzb.45.1700080481028;
        Wed, 15 Nov 2023 12:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080481; cv=none;
        d=google.com; s=arc-20160816;
        b=rMSln5Rq3eyUMTQzTvBLKijb6SOCFMkQI4qWVKvFZj+CckpUuqQuqeA0gZmFqB7Bcl
         zb2cXq89Kfj3UXk7iOOlWtBlRSKWB1dk4FCVk/zsOkrJxg4fFXt/GliZqpbhTujc9vG9
         kKP3ANvRmwtu31Rh5DlwFuwmblJ4kJba4yfmrhComJraqQNMaer0KjsFpkfN3Oassz7z
         xNmXr1B2Z+uac/8w9EaEemOnb7RZvDnkFqr7bfgDgB2swXnzoNcRGOda6HBQMqL+1Dix
         YdmIE7+rpMY7c0TTZ8P4Cx7LDTKqrbTtRXeO5STRe4Ehzo68QxgJ76nuvZLTdngDpc8V
         8BbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=O6Uyqo5OPYXf2k9vHa7gqaU9xWAA3SvhZTKyHesodmk=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=DA+Ai6SDjbGtQXO9vRB6R5Qeg3DREnOrA+ytutQJpxh1BOYQNBL/ccmbsbMlRz+y6n
         ehnntNJSNEQwD6eOKjEeKTSnEcqN1oFqwOYXYfgAjjByhxHMrC97kirGHmQkOpShIzQE
         xRhsJbCKtzL0U9LVR3/6iHIEiGMcAZ3ITiFblFXxIO2zdwthX9So1CuYsWWBwEQrzXPn
         5BQo9p+3oL90ukhkCY2UahV7KrUby/diLneMo4Juac2kJc0CkqUJYyhZmYKTb5q7OADw
         uwC1a7u0ks88Jb6Lt++0eJ1cp0tSnYyhrk3YIQlPUfuUKOFhBSJjU5+T5pnVSviIGlcJ
         EogQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jt5dURUl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id l22-20020a656816000000b00578accc7cedsi219013pgt.4.2023.11.15.12.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:41 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFbVM001512;
	Wed, 15 Nov 2023 20:34:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38ctd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:37 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKFm0q002004;
	Wed, 15 Nov 2023 20:34:36 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38csu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:36 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKItrV010007;
	Wed, 15 Nov 2023 20:34:35 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uakxt2du4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:35 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYWoV9241144
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:32 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 91F1A20043;
	Wed, 15 Nov 2023 20:34:32 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 422CB20040;
	Wed, 15 Nov 2023 20:34:31 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:31 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 14/32] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Wed, 15 Nov 2023 21:30:46 +0100
Message-ID: <20231115203401.2495875-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZYMSZKqeOhwUhd7n4RP9OakG2PdNo3PF
X-Proofpoint-ORIG-GUID: hRzHL7ZhRRkdAISReVgZqtBSn0Ah32ec
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 adultscore=0 spamscore=0
 priorityscore=1501 lowpriorityscore=0 phishscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jt5dURUl;       spf=pass (google.com:
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-15-iii%40linux.ibm.com.
