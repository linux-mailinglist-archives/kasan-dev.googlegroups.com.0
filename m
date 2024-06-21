Return-Path: <kasan-dev+bncBCM3H26GVIOBBB6M2WZQMGQE7UEGHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B4DB9123E7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:45 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1f9bb14b0bbsf1528445ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969863; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mq65UsGGV4NgSRwJbExVzYPzDKPf6O1d6dbQf2UK7lb2kE6hXlTTuO/WMqVi8R6Wcc
         BIBfWEQGNOVeFTx4CTyoNRz7krzylkayoYG02yWj87dfAMkDoPZ/6zZdgo3MmbP71KVv
         gxhOexAwoBAwRgtq56K/ZLY18Ng33cCv2lTQmSKBxGR9+FKL7otJHMQ5qXHArNIHY+LD
         aI6NVItOikZoMcUvgvKS+TjPmhwjpwjb2g2WZka2jc/p18ul5NGkMxIq4zdWRNYeq3zu
         f4+YURMywRUL4ZooudHlt9Y04NbpreZpXcwaDqn21lf2zLaUISN81dILR+eS4+oFcNAp
         +sGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=K3UmSJlaEihDglll3XoIKclMB+R6/0oQQYKrhldWf3E=;
        fh=sspFYM2KmgtfjTj+yIciM+ggu1gWssaTzHIp0c/TXNw=;
        b=IMh4OV1sC1dbbpy4DLHNTmDROgX6ptVgqOtUewEeMiC78eG2U1i8IGNzIIlEeAKHey
         7rQ6VqfgBkNO2+msX+Od/4E3uycs8OXuVHJArL0+R8WdvM9vUJmFoMRQBe309mQeKZtX
         I47W00ElrWrik3Nc4qgV11pD5rWUb16r+mWqYFZL2BDOPeRMPpXFQXbRCxc+Orhu6dYT
         9E80Fqdlsk/g5nZ6pRNUh3+IyWV1pPowV6F3oiIag5CROlA2tqT1TTOZkm2e7Kilmicv
         c94N6GsNBU7uWbBxKcon9X7mnswT8SDIYH5kzULTBEhiio4OaXW2NGbHoEdRHK3M23Sw
         qZxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aOqigZl6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969863; x=1719574663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K3UmSJlaEihDglll3XoIKclMB+R6/0oQQYKrhldWf3E=;
        b=jTerA3l/eZ09Xy9EPrg98UlmR2odsKLpNJYe5jc0siQJHrEB6BGz1FiuJS2iM55vAH
         SZppW+I5kpKyOLMQWjPVs/p9AtYDddNFVghQ4jzOgvWGeG8znzM0OQTDam7JHCCNBL/k
         ZrDbz/I7roTPd6PuyKxh5HAhgyaFsfvDSQUX17EqJC4bbQK81v4lgCwedzmEi1tvbS+k
         Kfq1Z71VqqRW+4VDtfbi3byKU0quBbTIotNSK/9e18+YxyfwF5VRwIemCmwHkZxNQAIj
         ptYmZiVbKXVHFdY+Y5DxTLxuUpGSIeBt1en99rlG+WZjkO6DhvB5kZYJNOHuPOEAi+xv
         ZSGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969863; x=1719574663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K3UmSJlaEihDglll3XoIKclMB+R6/0oQQYKrhldWf3E=;
        b=hTwrVhTKLas8I12yoMVwSpIjdzCoK/+CeFrjF9NFbpLRTLRdDPBlCCE7s3jZ+9PQS8
         C24SMXXAX+yhJ3plckjv2MX8AtkgJsP3OqwSnJe7F8usXmSU2eIWYhT0LPaAFkAQjAfH
         y9Pfxa/9I9Q9dgNm0vWlnLLTm5quyC0vo6oIqF7NDU4CazZaJAvlNboOrHkgEnnWVgqD
         RmK2ugIvGMgYjsbfrOKz5Z9ghipWK0ItRn3tHYg2mxH3fIwVqcuzkZ601yjDE08WMW40
         MRRSDmsckkx+6ip13XwxCw/pei+18yD5dIHOMMhjs2WUiXb3V/3PZWwGe66CtFWabWY6
         Fehw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXH+FfmwRhkky8Ve+RptzOvbX2I/IHO+meWx/xY9EZ+bmzNWO42WK6FTfCcpQB1lMnwTC/it9O3z5rU0+dEq64jbz1KXe5/mQ==
X-Gm-Message-State: AOJu0Yy3hobRDhQZDuiTIlLcJ4peo0tyqTNFi2mpzUsjszxKBDauIuC9
	39UVUfUAbM6y6jSUUE0am5w8nyLmhGeUsz+UbPCh7OGgU+ecklVK
X-Google-Smtp-Source: AGHT+IFkqyPBxfWW1OqIrY0KZBtP1+XHGI38vZ/ssAvmo/Afln0tynpXVY3hEmLtihOk+U43pkby8A==
X-Received: by 2002:a17:902:7488:b0:1f6:b033:a4e with SMTP id d9443c01a7336-1f9e7f8880dmr2817775ad.4.1718969863523;
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:20b:b0:2c8:65b:a42f with SMTP id 98e67ed59e1d1-2c8065ba96cls681287a91.1.-pod-prod-09-us;
 Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY9HxzZTy594ntB9lUwnciKK/NV2wMler7YMz3KRjMKPmQKFTOtsblEgWn84VPZQByWjIYh7pXvgLMwm5YSrHOSIL4cOVO3ZnaQA==
X-Received: by 2002:a17:90a:e50b:b0:2c7:2103:67bb with SMTP id 98e67ed59e1d1-2c7b5b68c03mr7602862a91.16.1718969862192;
        Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969862; cv=none;
        d=google.com; s=arc-20160816;
        b=q9m9nuPs61cQSwFB/dZVAoxKIfFtVBoHbiWSItT3luz8QvcvoFpM0pc+IFIbjSCPxi
         gAYLUySxJ5Jq/v7hdKbzlLDWhcCg8EiXn4oHgO9UDphaUAhXOW21VBSbQM2yqL8PJY/L
         Jd6RllxBXuULugyiGWava30TAktU6Yus2AgU3qNDHNDmSEjHolxUdx2NRtBBpMmiitMg
         +Srp2x2q58ZVyOp0tFlpQ8sOb8c3y7kyiSDOzBOq9KdHvsiST2ZYYlHYyh1fz4gnjiOR
         hsNMDzmtHBZPmySMRAE+Ryh/yQsmBAepG9u4fo8P0PWMmGVFTCMNKOvyPGnbiAb7lUVj
         EO/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8e8PMGe0cxjRcokQIWDPjb5O7pNlgWjHP8CNiuKdZuQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=QuQUtwpRY/kCdOwz8pOi6VP+93XvfNYz7GB0qWx+jnOJjCptZZE+RNE5zJ00bRzr3r
         fjZPEkS3Awfon6FVmQKUpzbKrXB3sOVskasGZt6y38WTK53JN3QJvINPMqkjgwrXT72q
         W7kK+ht00l9RGkDoXJ/MAtxmSVFGWVFp5SrEk4J8Jk6tT/R58FAEGHdZcmea0evrSyjt
         tgJj+jc0tORGnyrB25cHjM++j0+PtNzuVTPQJ/vovM2qGvegIyCAMzuyQKWNb0V70XEI
         3hRBY+RcwXc/zMLDYODO3HHOAb4TeHIumYUFpUgFolgXW/kGV3XqXfbYiJ2p1toem4RD
         lelQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aOqigZl6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e945195fsi180535a91.2.2024.06.21.04.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQxgB001227;
	Fri, 21 Jun 2024 11:37:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:37 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbawF017006;
	Fri, 21 Jun 2024 11:37:36 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:36 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9DkKt025805;
	Fri, 21 Jun 2024 11:37:35 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6w0k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:35 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbUvk20251122
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EDD8B2005A;
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5A7572004D;
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
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
Subject: [PATCH v7 34/38] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Fri, 21 Jun 2024 13:35:18 +0200
Message-ID: <20240621113706.315500-35-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: jz7JX3bos72ODugP84WEsI6sfjAsgluO
X-Proofpoint-ORIG-GUID: xYDFEuXR5f0KaQMRo7BBYw5TYc8gW_j-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 bulkscore=0 spamscore=0 phishscore=0 mlxlogscore=999 priorityscore=1501
 suspectscore=0 adultscore=0 malwarescore=0 mlxscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=aOqigZl6;       spf=pass (google.com:
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
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 111 +++++++++++++++++++++++---------
 1 file changed, 79 insertions(+), 32 deletions(-)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 81ae8a98e7ec..70f0edc00c2a 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -78,13 +78,24 @@ union oac {
 
 int __noreturn __put_user_bad(void);
 
-#define __put_user_asm(to, from, size)					\
-({									\
+#ifdef CONFIG_KMSAN
+#define get_put_user_noinstr_attributes \
+	noinline __maybe_unused __no_sanitize_memory
+#else
+#define get_put_user_noinstr_attributes __always_inline
+#endif
+
+#define DEFINE_PUT_USER(type)						\
+static get_put_user_noinstr_attributes int				\
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
+static get_put_user_noinstr_attributes int				\
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-35-iii%40linux.ibm.com.
