Return-Path: <kasan-dev+bncBCM3H26GVIOBBJEA5GVQMGQE4ELIEXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 9941181231B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:10 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-28af1128a09sf77302a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510629; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrGRfEcFhPxNJ7Uidu/BH8XbwLbx+Mxo8z5otpeb1Lxo2nguPjjC8f2TKI14uw/raK
         XNSxbibQdTFTjKJIeIfg0QU8obMDGfLiSw5qN2nTw62H8tkdMzFnIrQJycsBwUZwaQt5
         doiks5EQmpX5L+6s800wnbxnEZ5OUyD8pw2+qKuv6sNUFtR34bZ3dr5XcAi+wp++cN2Q
         XM+E1ZHzuRwtZ5Oa/DLjjNNB4lia28KIM+YjixbGd7PcxynxhXnWQ0UEcgFoi5bbjcgD
         eC15Y04Hf9EA/zfP0nlldes4tJDxC5gCVhDm8j+nI9wbHQhsPAC/sfl8lvtbmhrL1SMh
         PU+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YwPZt2ER8FGRkauzMNkIZQ7SI0/uF/ATQv5fWVnzLis=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=y8LuJuf8mtZcFVoW6zro60J5bzqFp+4iyt1GLnxonl8f25KqvZWInPROSzXc53maYL
         92Sq0ds2uK3KQWEdiq5TpUDdQp9JZkwn+Guwo5x1DjFB3r2NUJNc5Ld/MW6YqAzxEtXQ
         NM3GTndY0A06974W8OQ4QSIk4qJtK3OVTY5vCWBu2DwnLrRLtvJAD+gMgmja17LExFEx
         5d9YAwakxyVUIGOEoLeo5vYKlv8uo8GQhlz+0YJyXETcmVeNyOKWEsaerSxctzgWME+P
         Fexrv+PdBRZK5Lp8tFsI7KgKJWxKA9HRDMEQHD+1gcvRnLvYyA2Vc5FVSgxnghujTeRq
         fgww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eFWo7b1K;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510629; x=1703115429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YwPZt2ER8FGRkauzMNkIZQ7SI0/uF/ATQv5fWVnzLis=;
        b=AXpCGlqRH0iBRkuv7vMM9znQHIRC1eqZwhS8Q3eIu2oBrWUDr4GS5iD8H1mg/Jg8sh
         Y2TaL2wtBSM0Z6/uOWa9UGGp6uTalhPDpLarWiBeEqZtiDdvQmvryzO3QaIfJfrjA5bb
         ZuRhQ6fWV5JeSvhMdr5ttKuyhKUHTvkinSp1jYr9q5ZBRnq8myMtG/VKi/DM9pb2C0fD
         rU2WAw7hyYYlGUg1fK4rRrRnHKnpc+JU4pHg/a0jC81PDGweHJElROUOPZgxK30IHl6r
         gmlO7HGK0qHr94Ol6CBegAHQuhrrW7yUwx3BduwUVf0/WfT2EQagZCr5GhWnRflYMWRY
         9+3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510629; x=1703115429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YwPZt2ER8FGRkauzMNkIZQ7SI0/uF/ATQv5fWVnzLis=;
        b=W/4QuOfbXboO8vbNnLf6bTGnrH/ryDye623vIeY/mjd8HDNqcjcnpMerrMxxGSK2Il
         muX6/Rf93hdnLRjehCQ9a7qEXhBxYD4dhmjK1uQAvd9sVC5bOTLmd7Mvm3Um/Mb5N9pu
         GFL9G9w/kmAL8LzRGIRNk4zoRH/n6RD+TwkxIkyOQ7SVNdbZuIvcyUOMPFHPEmTnlZqS
         sH0+qnhotJrtbL3mkyhMTKoYAL6AHRxInX0ZLRry6PPfb8q+IP2d6N025JtncT+1Y15W
         BaAU66xNjTB4PU+0IE5bIt5jHDopDpWe7N3PHEbGmdfR5FujxGGps3x4n5k7TihtKAAo
         5Klg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw7Ue+/ReuwBYeV+YhrpIGfseJpkX5O3QWEAPB2gp2z6YlPU/f3
	xZUeujmYziMK5294ZwhhCvY=
X-Google-Smtp-Source: AGHT+IFW240TNUnqv6vc/cDmWtp+t75qVQ4GOo0wFGRbGTPvVdAa0dNtsniKEuWQpoWpZQMqU98SGQ==
X-Received: by 2002:a17:90a:6fe2:b0:28a:e884:e151 with SMTP id e89-20020a17090a6fe200b0028ae884e151mr2079777pjk.23.1702510629027;
        Wed, 13 Dec 2023 15:37:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba81:b0:28b:36d:1e65 with SMTP id
 t1-20020a17090aba8100b0028b036d1e65ls55250pjr.1.-pod-prod-00-us-canary; Wed,
 13 Dec 2023 15:37:08 -0800 (PST)
X-Received: by 2002:a17:90a:9318:b0:28b:70b:1939 with SMTP id p24-20020a17090a931800b0028b070b1939mr321956pjo.6.1702510627907;
        Wed, 13 Dec 2023 15:37:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510627; cv=none;
        d=google.com; s=arc-20160816;
        b=HIcCPt36h6qqO7PgF8rybwEol6rQcNya9aBVQLuURaUKU0KYcYNCsDkXvuPRVxuHQ0
         86eCZSHFKMs6jmqt/1Pw/OFTaZgazvcE2zE6AWOirWR2cDbDXVs60RYwfAd/nUeX5uOi
         JYeRXEERPZKsnedppfDSjD0jMt84syYjEgvLUtFCtYEURrvL1gIFkzB3Gw2Rr+/PxvYK
         hJHl8pJ5lPYlgujg2/acSTItS3kfw/eVUT3OCeHpVc/lobmlNalxxiAKaDGFwlEKXJm2
         8VailM47RpVl3pAuXuHt04LBCHAHi34mqbQvMsUMMUEw3RkPQWwme4OcKKbUJjOMRJqD
         azGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s1bHT1l6xxSUQY/AfEWlqSevErmthDammvxOjEN6IQ8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Uo6ZcqHpXg1m0wSxKJvf9HoGS779LyKfqFfzkI4QRDcap53wIAgVFg4yBqNSv9yADL
         ajooMzteu7VY+wKeY15QKgMr3AZowXwdJi65iPMD5eXqPa7XgQX5bALp1fq8MfC8SRtU
         W4mWcbszN8hvZdyBuOcZeMtkn9pbpQd0KOcPa81UEu2auCRFFaPEMOYfNlNrBcr2jpdH
         ztabAXtlgUWVyPf2KGCkqcMlGaTxvQ71LToTWmsgWDV5qRQnpuU/90A0O8jUuwX5onB8
         1ZhcX1qgaJy4KnwYazFnlkADqXaW18ITkFKLS7XYqH3nXIdFvEAluumQknHxtOzVdpUP
         1lCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eFWo7b1K;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id w18-20020a17090a8a1200b0028ad73d17f7si188902pjn.1.2023.12.13.15.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:07 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMF2rG005788;
	Wed, 13 Dec 2023 23:37:04 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybw52s8h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:03 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDLQCdm020018;
	Wed, 13 Dec 2023 23:37:02 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybw52s81-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:02 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDGTUb8014824;
	Wed, 13 Dec 2023 23:37:01 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1y1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:01 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNawNT27263502
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:58 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E56E420040;
	Wed, 13 Dec 2023 23:36:57 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7283920043;
	Wed, 13 Dec 2023 23:36:56 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:56 +0000 (GMT)
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
Subject: [PATCH v3 31/34] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Thu, 14 Dec 2023 00:24:51 +0100
Message-ID: <20231213233605.661251-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: GuXSY6mkyFJdvPjUGGnInPnY89ZZCBBh
X-Proofpoint-ORIG-GUID: lCgzKW-fN2NdnghC9Ytb979L4h5Hs2ko
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 bulkscore=0
 phishscore=0 spamscore=0 suspectscore=0 clxscore=1015 lowpriorityscore=0
 impostorscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=eFWo7b1K;       spf=pass (google.com:
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

put_user() uses inline assembly with precise constraints, so Clang is
in principle capable of instrumenting it automatically. Unfortunately,
one of the constraints contains a dereferenced user pointer, and Clang
does not currently distinguish user and kernel pointers. Therefore
KMSAN attempts to access shadow for user pointers, which is not a right
thing to do.

An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
work, since it's __always_inline. And __always_inline cannot be removed
due to the __put_user_bad() trick.

A different obvious fix of using the "a" instead of the "+Q" constraint
degrades the code quality, which is very important here, since it's a
hot path.

Instead, repurpose the __put_user_asm() macro to define
__put_user_{char,short,int,long}_noinstr() functions and mark them with
__no_sanitize_memory. For the non-KMSAN builds make them
__always_inline in order to keep the generated code quality. Also
define __put_user_{char,short,int,long}() functions, which call the
aforementioned ones and which *are* instrumented, because they call
KMSAN hooks, which may be implemented as macros.

The same applies to get_user() as well.

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 111 +++++++++++++++++++++++---------
 1 file changed, 79 insertions(+), 32 deletions(-)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 81ae8a98e7ec..c3c26dd1fc04 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -78,13 +78,24 @@ union oac {
 
 int __noreturn __put_user_bad(void);
 
-#define __put_user_asm(to, from, size)					\
-({									\
+#ifdef CONFIG_KMSAN
+#define GET_PUT_USER_NOINSTR_ATTRIBUTES \
+	noinline __maybe_unused __no_sanitize_memory
+#else
+#define GET_PUT_USER_NOINSTR_ATTRIBUTES __always_inline
+#endif
+
+#define DEFINE_PUT_USER(type)						\
+static GET_PUT_USER_NOINSTR_ATTRIBUTES int				\
+__put_user_##type##_noinstr(unsigned type __user *to,			\
+			    unsigned type *from,			\
+			    unsigned long size)				\
+{									\
 	union oac __oac_spec = {					\
 		.oac1.as = PSW_BITS_AS_SECONDARY,			\
 		.oac1.a = 1,						\
 	};								\
-	int __rc;							\
+	int rc;								\
 									\
 	asm volatile(							\
 		"	lr	0,%[spec]\n"				\
@@ -93,12 +104,28 @@ int __noreturn __put_user_bad(void);
 		"2:\n"							\
 		EX_TABLE_UA_STORE(0b, 2b, %[rc])			\
 		EX_TABLE_UA_STORE(1b, 2b, %[rc])			\
-		: [rc] "=&d" (__rc), [_to] "+Q" (*(to))			\
+		: [rc] "=&d" (rc), [_to] "+Q" (*(to))			\
 		: [_size] "d" (size), [_from] "Q" (*(from)),		\
 		  [spec] "d" (__oac_spec.val)				\
 		: "cc", "0");						\
-	__rc;								\
-})
+	return rc;							\
+}									\
+									\
+static __always_inline int						\
+__put_user_##type(unsigned type __user *to, unsigned type *from,	\
+		  unsigned long size)					\
+{									\
+	int rc;								\
+									\
+	rc = __put_user_##type##_noinstr(to, from, size);		\
+	instrument_put_user(*from, to, size);				\
+	return rc;							\
+}
+
+DEFINE_PUT_USER(char);
+DEFINE_PUT_USER(short);
+DEFINE_PUT_USER(int);
+DEFINE_PUT_USER(long);
 
 static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned long size)
 {
@@ -106,24 +133,24 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
 	switch (size) {
 	case 1:
-		rc = __put_user_asm((unsigned char __user *)ptr,
-				    (unsigned char *)x,
-				    size);
+		rc = __put_user_char((unsigned char __user *)ptr,
+				     (unsigned char *)x,
+				     size);
 		break;
 	case 2:
-		rc = __put_user_asm((unsigned short __user *)ptr,
-				    (unsigned short *)x,
-				    size);
+		rc = __put_user_short((unsigned short __user *)ptr,
+				      (unsigned short *)x,
+				      size);
 		break;
 	case 4:
-		rc = __put_user_asm((unsigned int __user *)ptr,
+		rc = __put_user_int((unsigned int __user *)ptr,
 				    (unsigned int *)x,
 				    size);
 		break;
 	case 8:
-		rc = __put_user_asm((unsigned long __user *)ptr,
-				    (unsigned long *)x,
-				    size);
+		rc = __put_user_long((unsigned long __user *)ptr,
+				     (unsigned long *)x,
+				     size);
 		break;
 	default:
 		__put_user_bad();
@@ -134,13 +161,17 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
 int __noreturn __get_user_bad(void);
 
-#define __get_user_asm(to, from, size)					\
-({									\
+#define DEFINE_GET_USER(type)						\
+static GET_PUT_USER_NOINSTR_ATTRIBUTES int				\
+__get_user_##type##_noinstr(unsigned type *to,				\
+			    unsigned type __user *from,			\
+			    unsigned long size)				\
+{									\
 	union oac __oac_spec = {					\
 		.oac2.as = PSW_BITS_AS_SECONDARY,			\
 		.oac2.a = 1,						\
 	};								\
-	int __rc;							\
+	int rc;								\
 									\
 	asm volatile(							\
 		"	lr	0,%[spec]\n"				\
@@ -149,13 +180,29 @@ int __noreturn __get_user_bad(void);
 		"2:\n"							\
 		EX_TABLE_UA_LOAD_MEM(0b, 2b, %[rc], %[_to], %[_ksize])	\
 		EX_TABLE_UA_LOAD_MEM(1b, 2b, %[rc], %[_to], %[_ksize])	\
-		: [rc] "=&d" (__rc), "=Q" (*(to))			\
+		: [rc] "=&d" (rc), "=Q" (*(to))				\
 		: [_size] "d" (size), [_from] "Q" (*(from)),		\
 		  [spec] "d" (__oac_spec.val), [_to] "a" (to),		\
 		  [_ksize] "K" (size)					\
 		: "cc", "0");						\
-	__rc;								\
-})
+	return rc;							\
+}									\
+									\
+static __always_inline int						\
+__get_user_##type(unsigned type *to, unsigned type __user *from,	\
+		  unsigned long size)					\
+{									\
+	int rc;								\
+									\
+	rc = __get_user_##type##_noinstr(to, from, size);		\
+	instrument_get_user(*to);					\
+	return rc;							\
+}
+
+DEFINE_GET_USER(char);
+DEFINE_GET_USER(short);
+DEFINE_GET_USER(int);
+DEFINE_GET_USER(long);
 
 static __always_inline int __get_user_fn(void *x, const void __user *ptr, unsigned long size)
 {
@@ -163,24 +210,24 @@ static __always_inline int __get_user_fn(void *x, const void __user *ptr, unsign
 
 	switch (size) {
 	case 1:
-		rc = __get_user_asm((unsigned char *)x,
-				    (unsigned char __user *)ptr,
-				    size);
+		rc = __get_user_char((unsigned char *)x,
+				     (unsigned char __user *)ptr,
+				     size);
 		break;
 	case 2:
-		rc = __get_user_asm((unsigned short *)x,
-				    (unsigned short __user *)ptr,
-				    size);
+		rc = __get_user_short((unsigned short *)x,
+				      (unsigned short __user *)ptr,
+				      size);
 		break;
 	case 4:
-		rc = __get_user_asm((unsigned int *)x,
+		rc = __get_user_int((unsigned int *)x,
 				    (unsigned int __user *)ptr,
 				    size);
 		break;
 	case 8:
-		rc = __get_user_asm((unsigned long *)x,
-				    (unsigned long __user *)ptr,
-				    size);
+		rc = __get_user_long((unsigned long *)x,
+				     (unsigned long __user *)ptr,
+				     size);
 		break;
 	default:
 		__get_user_bad();
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-32-iii%40linux.ibm.com.
