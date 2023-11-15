Return-Path: <kasan-dev+bncBCM3H26GVIOBB7GW2SVAMGQEDLTO4XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id ADD9F7ED23C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:09 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-35aae13790bsf764305ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080508; cv=pass;
        d=google.com; s=arc-20160816;
        b=xTnAF6+8JnUSf90FWz+CQSd9RgvGAtxlNGIbW9xmAZsPpysHL3TQPnyMzHpeATakHp
         JvNONLZLY7t3I5wMrwk8eJyUNSW1jFZAjDLRXtBfPCOpM1FEUamsk2DinExL1kV6Ow7g
         oyS9QD4IMDzm1FOtjk0HjkJEVUeevovCiAtMFXA/BC+VjgXn9irYg4k7+4AFeZ/ZGSlk
         eq5dDTlKJHWr6g411vmUrtz5BXAofVd6+gIkm5qhNCm7+OiqEonDM6TO27xUNEat8rFf
         5m9/xDEpsjCypj7nR3GLqyWTQHLqRwABRMJTZukZr+ZNvyqa9oY298TsjcZIiPVfRORK
         qITQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kbrifFjoz3hXoIlGbngz4JMRbzsUDakZG/WLFNK9rFk=;
        fh=rr9aOGaxyzCIKap4dF0OG9XKBkjSWIKv3pUt54EDRpE=;
        b=a2/5KwECWSVpwGSYvbF6Ya7wolN1wN7z8vKDjVOU8FY7sO1LPgrNQVdv+UAkFCSdWP
         vSiBVvOjJL0hN+MhADnLfPhtrStzEnZGf1u28dxGX3xyN1OPHNZURVxRLu+ijZiS7ZOu
         2oQ/cpgVTTqmnGEzibZFHOYKMWxQeXbrmMh//FChOpyoAwU1GDLlRHs0T3xBGfjbRTaF
         k2rtk5RYi2isAPhe4Gz/YEPRqBIm2CgP7bC+AAo9cnutDKZ66z92BzARMQ/6QniUvGbe
         4t/q1p9e8sCixTIr3FTtxZBqLOur57TBwSaagc0INPo/7bvuK6Ro5PDbRs+ck12xGxZ/
         MCtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fSebvw9z;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080508; x=1700685308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kbrifFjoz3hXoIlGbngz4JMRbzsUDakZG/WLFNK9rFk=;
        b=NLsRITU/PnnOnp7/6aTMQ4Uabe71yKtiJsQLYxMO9Sz0AdB39WeSsqGfyLPCw+pqp2
         rz4bmCCAOgKr8ZrHQ1rs41Sg3AgxpqDKU5y2g1dDuMSzNKjxHt1Wk68U1k+tQlTFqMQv
         +4Kqr0/EZ6RlVombRhJQLXu3+94nAnmOX+s+pYgnR1sI+iUHN5BmDna+udwq9IcDd9HV
         zvteIjCuvh//YGuS/bmUMva0L/05X/ed0+SH0pOSxX5ex0nwh/UsgOXh/y+8Pa8iSpwp
         7AhEq8YRGSKn3JmP0QT/7y/YJbtN1QQCGzE4fSltVCReVlOEXEuUmH/ygDSwhS85s/g/
         XCAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080508; x=1700685308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kbrifFjoz3hXoIlGbngz4JMRbzsUDakZG/WLFNK9rFk=;
        b=aR7vAwJEbtNevV38Y/HX/4q5nSZ6EY/bsDmeF44e6hbPvQIJu0QT5FAKC2FSF4j5ck
         hXZgSV/DrNBRHi0xGycpk/sVjPm09xh4Y2ei+8UtfPg6XR6+tnAHw+kDsp/Xh3lhBNys
         Ebl4gVApcRvWoL4G0cDaCiYTHHlayZ8GgeLqKc8XNjw2XsqydvCKtq8zcHvdwCHnghxd
         iwqXIW75CtseTLHVV4uEwoeA2R0OBTDwKjtkkxNWHohihJ3QbkwwQDbJsIjn79EuPHuC
         rtN0wP/Cnx3vvFn7AjCQYnpOMoPJVnb8sBYYo3U2bQSX6IYgMnrl5tJyjFCvfhDYnxYk
         nUTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwLUlLMszYDATBa1v4mhhDR7qN1tmkHAhmyzbWRZLseE/ag2scw
	EPWx5VY5UBHZtJABEYP0pxVFFA==
X-Google-Smtp-Source: AGHT+IE0/LhACE6iXjI8lOQtYLBXiO3yM3cmDbz1glnm114C6aYsxn6cQeGlR/pD+L8I3YLvDeYo2A==
X-Received: by 2002:a92:cdaf:0:b0:359:4048:38d3 with SMTP id g15-20020a92cdaf000000b00359404838d3mr17837677ild.9.1700080508541;
        Wed, 15 Nov 2023 12:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d3d0:0:b0:357:af8c:6704 with SMTP id c16-20020a92d3d0000000b00357af8c6704ls62623ilh.2.-pod-prod-02-us;
 Wed, 15 Nov 2023 12:35:08 -0800 (PST)
X-Received: by 2002:a05:6602:15c7:b0:79f:ce11:c1b0 with SMTP id f7-20020a05660215c700b0079fce11c1b0mr19794605iow.6.1700080507984;
        Wed, 15 Nov 2023 12:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080507; cv=none;
        d=google.com; s=arc-20160816;
        b=DhKEQ+mi98i8FgnYpTJBnanYG1EFo0sECikco43XSi+GCl/i/hwuErCOo8+xYknb86
         lC2XaFiDVNLDEOTJbEjy+w6Jg/VADg9UPY1Zj5O03V5L8AXcmVOMy7wEz2W+D0yyYoxp
         kI6T08/ymjWGw1FPb8Bd+qDCU4rnUXj28gu9qYSZr3sS0817gU0TyaGbn0IlZPkYmNfs
         pqVXY7LKZLSDI2xuA8TraUSC31WWyu5066vhPOIN7HDC0Y67Ew4RXYJ9kyn1grXTZl9d
         ooBmxH+6iWM7NHJF6Vt/wsYg6W8kUL5xxZ1jTHRpx89+VqLwHiYdQWrTB48GvMbxNr9j
         bHAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pCHaNUsH9l0hG+UVZcWLc4ZJz+vOcJVUmc7g0ZpB+XI=;
        fh=rr9aOGaxyzCIKap4dF0OG9XKBkjSWIKv3pUt54EDRpE=;
        b=00ev29hGeX2Omeh6QVQ+HQ0rMzxcyeBnq0cW6GOxUsPBRkkuxWRlOo/4Hj2d7PB/gA
         8qe6C1ja7h9wodNIodzycvYWtGyrfqsD5JAESFsKcbHGGX802ZMUgD2HbzZVOhcIxCWO
         69NHwat2RLZHowctjsk/AC1bYOmLCp3trv7VKHT3Usf5xIYRLZ4IaPdcJZFnRI4aORau
         oqDPSQe9HImUNhvH6A2u7BW09KuF6b1zZrJo/MVaubC9WlS9/wT4x+Ddt6n5sPzXIQK0
         26d1So/v/GdHG839hPOKic1XsQ8OKSdPvwIi5Z5z5blWjvgaLNUKPZjVRutMz+/+LFIp
         pnRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fSebvw9z;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id r8-20020a056638130800b00463fcd15b78si1261243jad.0.2023.11.15.12.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKWwg6031423;
	Wed, 15 Nov 2023 20:35:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g1um-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:03 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKXeXX001667;
	Wed, 15 Nov 2023 20:35:02 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g1u0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:02 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIuWb010012;
	Wed, 15 Nov 2023 20:35:01 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uakxt2dyf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:01 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYwfU15860306
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:58 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8B99520043;
	Wed, 15 Nov 2023 20:34:58 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 290B420040;
	Wed, 15 Nov 2023 20:34:57 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:57 +0000 (GMT)
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
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Heiko Carstens <hca@linux.ibm.com>
Subject: [PATCH 29/32] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Wed, 15 Nov 2023 21:31:01 +0100
Message-ID: <20231115203401.2495875-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: aXkXwYW8xMvzSI-lsQeWlg0pVYb5rqYU
X-Proofpoint-GUID: T_08zhpSfGPVRxxdCdrw7y3TGl8MixS1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 spamscore=0 adultscore=0 priorityscore=1501 suspectscore=0 clxscore=1015
 mlxlogscore=999 bulkscore=0 mlxscore=0 lowpriorityscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fSebvw9z;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-30-iii%40linux.ibm.com.
