Return-Path: <kasan-dev+bncBCM3H26GVIOBBH6S6SVAMGQE6NRBKFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 09C5D7F38AD
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:13 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-357429e8ac0sf58283665ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604192; cv=pass;
        d=google.com; s=arc-20160816;
        b=CmpaSQNR6pmXdPBDhDfbFn9l0CHKHuaDxD2exn9ggrSO7CnBkAEGHyCBsBIxXuEf8V
         TqfVzO7au7PK5lNKLoNiOlKbv1zrbrCd+gfHOP84Z0z9ykJt68xx20Mhmc4IACuFrxIp
         TN4xEgOOvWJ7yUtJ8zJTWycd66G45efSIx9c59DlS/Oq5Syiy+X2D3ognEcDNTIjlRve
         vbcNZqLiJb2MsggdMk7QlEn21aiVFVmJlKU0X56okCDabktjm86V/Za8amOnI1Wmr5ng
         yjhJic3peLY57NPor9MZH64+ZGZI08W15hZHvquIfM/+4SBnPc/5mn389x308TdXtJo/
         /J8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Po9CjP1H8GrMoXIJB+A1d+E1G1TNn0tC0cIBOICKmeM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=VRtgiUlGXm4xTM0u66z1mKwfWHBsOJkdmTxkQkwzsjWXHfx9Pnljtb2+JYrLmTXPgP
         4+gGRsyvUo0hA8WbXF82aWoxpMSkZfTwTpv5Bsku7y3/75t5tw4RadbpLDhPRwbi2B5K
         yuE0ndyGUMqO7KjHkz3N4bcFVKSbv8Yqr/wJHdwF+2EIRyQhM4Wfa7EyUr2jIPBIULuC
         Fr8y1RPwblwvnMo6/g8uTsge+etBLtY7GsQlQ519cZjRGm7Pf8pzXqwd8Kv42L7HjHUl
         BHE9Y9ky22wAPLE5cwABBEX5mvCtPBRqBy/ZJlosyUZQ4NBDfuQkjRc5g3kdWeclZrpw
         34Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kvD3L93D;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604192; x=1701208992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Po9CjP1H8GrMoXIJB+A1d+E1G1TNn0tC0cIBOICKmeM=;
        b=xiDm0aN3Sp1yG3NnSyJPkc9z5NIPYu04fuq71IzrcPfPxW41ZmJByqw4huwsE8bSQf
         N08WyvWSTy2ATw476p4TWEbuq8V+dEWd/6KBGSfmmhxuHZCYruqYgupnB96hH1KEtagC
         0r0v7hDVzQT8qIwuBqwi20icaZmGRNxMNqkqHs6joQdnz6JltyY3ALIiFnPZ8lu1q9h4
         jGM5IDRLGUG3PiF6KgC+L8ODrurXMOHKpOaNzzgInL6RZrShC6Gq5fETLsYb5mCbTOTG
         K9eOJjaRjrtoycFS6XOiaHKyb0Eul/W0E/x6wb1bJnWjctaPZVyyLcSa0GU6dBfAdxIK
         P9HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604192; x=1701208992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Po9CjP1H8GrMoXIJB+A1d+E1G1TNn0tC0cIBOICKmeM=;
        b=i5/dVBLEvOqR7vzrNNHLYh0m9Uf8Q9NGPQfhV+fSq22zMpORWP1LR5D+nQ9tf6q9TL
         NSDRXE8qqKA5YixuE6AEfrOmb3GABMxGA/aMNOvgM6BY0iWpDDfIZ47vZQglwyDGO90A
         mT5OPm4IZTDV1e2E8Ze59NzLNft4YzBwwpet6Mf1l0YJrSc4r/LBjWjI2qjoEE8jWuBI
         l6ebEZEejYWF0d5UAfszYmR/f4AMBu76WA0zG2Y+HsP+qgKxhNxd25HH0KgHq/Rp9Bn5
         DFslSLGRMIKHjDpp07wvaH3J0ZV9747STnsGVFiKFmC+g17ilY4QTa/Ac2WZ6aVYZa6q
         oQyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwKWc67atz+sjwntjsPY46Zz662PpgNJ7+bUxzNFkpeGTLGTCtq
	nh5ZjwtXi1krk2JNbB+b1Qs=
X-Google-Smtp-Source: AGHT+IGB7x64/fDABkF6WydG01swlrf8rhIP//cxzRKSA9Be0IESlcO1kJRVlBce1tSiMyoC/p9imA==
X-Received: by 2002:a05:6e02:546:b0:359:523d:f1f7 with SMTP id i6-20020a056e02054600b00359523df1f7mr279113ils.9.1700604191830;
        Tue, 21 Nov 2023 14:03:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c88:b0:35a:fa96:e358 with SMTP id
 w8-20020a056e021c8800b0035afa96e358ls1812799ill.0.-pod-prod-06-us; Tue, 21
 Nov 2023 14:03:11 -0800 (PST)
X-Received: by 2002:a05:6e02:1d07:b0:359:4b3b:530d with SMTP id i7-20020a056e021d0700b003594b3b530dmr368313ila.7.1700604191210;
        Tue, 21 Nov 2023 14:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604191; cv=none;
        d=google.com; s=arc-20160816;
        b=fEfwFWypSCRATANC+kf/WPc509aY8mFLyWBhKawYFGRO5Vr7eS5+0TEyDhLCO2zMpo
         SnVwKPQWsaUJ162S2++nbQW8ayCNnnWGAOEIrwMHZkh7hd/fGuRwRJRhgmyFY/MiTgIk
         2w6hV5Zmfnb8ux0oezaYuCSIpYsZPPkiL5S+x5q0e8y7zZy7DqBmNcptSiLvDg0RFuMt
         jMLbIAgFuLoQBrJyjtFYOahdv538CAp+k9J4hgPK4kpfKLDslIKEVeBkoX3MpOFc0WrD
         mn43XXC/qQzGVILCwzBY1hCqVbIc7FQyNGTLIUu2UTHzfROc+ajf1BNGH7yEKmtI2vtg
         vIjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pCHaNUsH9l0hG+UVZcWLc4ZJz+vOcJVUmc7g0ZpB+XI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oWBRCa84rHEQAp4iVFfaw7W5i3DeeOQmRFm8qtQqDoL9jO6s/F+ATg2Zzjpdmo00C2
         vZzYqdynLrjlWwn3oHbxE8mrJ7BnGYwfuiQIPxaFbhxTdbDS6RiTkNs4nmDEOpGRgb77
         mmoXgIiEWgOk4K2KDJyOwK+fMN+8sAcGjuCxd9RV5FIeNe4VGesq9d0xeShQ0JdloNji
         z50Ty7RAqwpDMyLHPmXqo/4d4YMFDLDEMOZ5hX8e8gC5/bXMJOiX0hJpv1tTp5eStm04
         emkionOp439Dubw5ylW6bxc3mwbVBhVf8g2iVR57NEnPHtghL5EP8HWOb7aSssnJNemp
         /Cgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kvD3L93D;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ba44-20020a0566383aac00b00439ca012a0bsi873160jab.6.2023.11.21.14.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:11 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlV76020427;
	Tue, 21 Nov 2023 22:03:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68c89-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:06 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLmuPP024544;
	Tue, 21 Nov 2023 22:03:05 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68c7a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:05 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnIiM007606;
	Tue, 21 Nov 2023 22:03:04 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf8knuq85-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:04 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM31Gt19792508
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:03:01 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 131C120065;
	Tue, 21 Nov 2023 22:03:01 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8F32A2005A;
	Tue, 21 Nov 2023 22:02:59 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:59 +0000 (GMT)
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
Subject: [PATCH v2 30/33] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Tue, 21 Nov 2023 23:01:24 +0100
Message-ID: <20231121220155.1217090-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: zmsg0rsqRwIHfkoUeMMCHE1uQMZbOsJ6
X-Proofpoint-GUID: xQEF54zQDF8Y0lAb497R7bcH1qccldfU
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 priorityscore=1501 spamscore=0 impostorscore=0 mlxlogscore=999 bulkscore=0
 mlxscore=0 malwarescore=0 adultscore=0 phishscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kvD3L93D;       spf=pass (google.com:
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
 arch/s390/include/asm/uaccess.h | 110 ++++++++++++++++++++++----------
 1 file changed, 78 insertions(+), 32 deletions(-)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 81ae8a98e7ec..b0715b88b55a 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -78,13 +78,23 @@ union oac {
 
 int __noreturn __put_user_bad(void);
 
-#define __put_user_asm(to, from, size)					\
-({									\
+#ifdef CONFIG_KMSAN
+#define GET_PUT_USER_NOINSTR_ATTRIBUTES inline __no_sanitize_memory
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
@@ -93,12 +103,28 @@ int __noreturn __put_user_bad(void);
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
@@ -106,24 +132,24 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
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
@@ -134,13 +160,17 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
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
@@ -149,13 +179,29 @@ int __noreturn __get_user_bad(void);
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
@@ -163,24 +209,24 @@ static __always_inline int __get_user_fn(void *x, const void __user *ptr, unsign
 
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-31-iii%40linux.ibm.com.
