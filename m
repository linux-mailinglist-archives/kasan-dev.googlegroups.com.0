Return-Path: <kasan-dev+bncBCM3H26GVIOBBNX2ZOZQMGQEXUHV4AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA3490F2B8
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:59 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-376210a881dsf8419375ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811958; cv=pass;
        d=google.com; s=arc-20160816;
        b=CoGWUWWDtlccJwCQ6FfPokZ9fx831YOBTJkMgCDQkVWCXyBDGvXWuatRSszXNx2wLD
         X81H6KFyc4ykQG/5PdHdu+N3IVks4e/oGd0LoSO7Q9vdOoe5rBxhS5fNiIH26+ujIuK3
         /j0VUBRBs5kxtNTEtwL4zSB9H5UXqRNUbfSXGnwThefXf1/C6Xj1iKDErEv6J612t2bJ
         7ot+LMBhdsJv5sVfrslEaGFwzKpbVZdBtqLM4i4bSwctIDhfQwPfRCVPyaVdN+rfdLKa
         P6mLH4WSkIqQPOMhceGRR6u6YLsjfIZzYdcbziv0oTri1moJH+o30KwVDs6B2sLXSKBK
         B8Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TQp87rbMRQ21zZ0fXzHmOMqUpQrsyvC/hjZvvxGGqSo=;
        fh=nWmnS9pLW2DcTXZ/FdbYDvEQ9P0df1ZywK58vJQtoV0=;
        b=eIT7FuCDc/KEla33JRSvIFt1Q27LYCq7dvo2sNhxSpq71CIQyEpqvdM0Hssi5K1R8x
         AQrRP+e6OjTBa/DIRZnw63GyaYpg3jyrYnnwV8sElv5kRhbl9p+9nAkyBZ/H+BmaUtoF
         QW4pMV9BzAmUiWmEuW+dngbJBTEwedu2x84rkCL3kOh2V6aTLgB4CYaO+XONKuL/0HMG
         9M91K++cVd/QPtlTjY9sI/g5TgGcbcTZlbXvuV2nyJIobPZH65oYQKAw50Aw7H0KvyFG
         BmBZtpAK3iSEfWD3AxwclN6GxhZKf2Gq7KLHIG9wuAgcdNpYYYAx6Zm21rAe9ut9fSqh
         8otw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LCohBSxo;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811958; x=1719416758; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TQp87rbMRQ21zZ0fXzHmOMqUpQrsyvC/hjZvvxGGqSo=;
        b=iEAKIN3s58yJfX9wZpep4/okp5uS/wxN7TeB2YbOmFg8o7zhiptfi2N1rJ4iYOz8Kr
         43oLrzOGxXthIttvOagNTw2oP6A1f0alt9Kgi/9XAcD6wxqEgKvIp7VBUjxfg4CPp7Gd
         gX9sY0e9Khzu6Ro/iBCi2o/auia2HESEuwfhLWF7hai1hxMopc4QbkO6RObgWFG7gzG2
         fgefBTIOLz8PAI+nZV71wyLCbjgJkqisjWw6gyy2Abty+lu2CvrEsHN+UTZkbLypPQFw
         fJZpmzA+FWGAOq0+GJ7kAH3wRNcbjQKVx2ItX79VMyafllDIuBZBJBW9QVNj8vkS2v/h
         //nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811958; x=1719416758;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TQp87rbMRQ21zZ0fXzHmOMqUpQrsyvC/hjZvvxGGqSo=;
        b=fIvDC55kKZk+3gwN1A1euNAz8+9R7oTh/eVk3pBeYw48ySRGca+641UyKF13zR2hW+
         W1o/2qp0Ix5YIWsAR9efsoeGgTjF3THIWv2jGWQgFtD29N00+0Ut3IzKW3/YKT+Lv6Fl
         39oHFh5jEmWUDvqeJw23lU/YjsH+tmkKwIKkvDVkFw2QGEy5lgREjE85HJPasxvl8/Dq
         1xzjwsL6tcj5h2YvaKhRZDFaF2xAY6Pd1EP09cizmcwKdoXxkQYTiMHNkH7opnfHyEHr
         L0ryMMWbKVK4uG5pMZGQigFpilTO9ebwpH1hcPSQFIzmpbqqF41VOuVlEM5QVw1Gp0FW
         H9HQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+T8wTqUEPnEzp99QzlgG3U8zAlEayFpbGXXF0Hl+l6YyAsT9VUjX0gPJ6H7Gd4CUE7GIoJ9Xz6+Sb7vFn+ouTkbiM99P3pg==
X-Gm-Message-State: AOJu0Yz+CyQjGseFSBJ6fqoweFKQsnUqP/o3L4rog+YBNeJU1NECaBDF
	jzVixZSmkSRnuD2/AQOygM9szclOtkmH4q/WptqM6CdSSp8YKF2s
X-Google-Smtp-Source: AGHT+IEaaVfMIuSTUhfANr0jItZatkEQIFNIkI561WF4tdbRHdr+K3vfnex4Tlz7ISAq2TCYHJPd4Q==
X-Received: by 2002:a05:6e02:138e:b0:374:92d0:caa7 with SMTP id e9e14a558f8ab-3761d7076e1mr34361965ab.25.1718811958728;
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:374:a2f2:54be with SMTP id
 e9e14a558f8ab-375d5682815ls56732935ab.1.-pod-prod-03-us; Wed, 19 Jun 2024
 08:45:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7uHuk8OnalNLyalraiTzpJlYfxadn1a/it+auB1BDLoQuEp3r2v0bE0Jfexvrb/3gevcdK7SwEVb41aWJosvdQYjhUQtUZACTFQ==
X-Received: by 2002:a05:6602:3421:b0:7f1:3ad1:234e with SMTP id ca18e2360f4ac-7f13eea32f1mr350677939f.18.1718811957782;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811957; cv=none;
        d=google.com; s=arc-20160816;
        b=vOmKHEWCO1GAL7sorOYxs60UwVhxqxbFkjNbnyxM7Kc26i+NB8W26Zrgm6lxY7BkUY
         PEWq0OvHM9MV/9VWkHa4L4owBvKwCkzN9125URsjAwe3r66A+h+kppp64BDUAxqR9C0r
         YNVwfTHOwvdo4YBxSrvY5n8XZfEZYhGHCD49UOYEQitnzrwAu2qHvzSsB3a12rrTe8kM
         FCqrrWxLkWGoAJC/4+IFF3ZlhP3epwt5W0xMHFNQJuYXIJjbeJgzWhO1znPhZ4cFsDdz
         d96LT+B0NXcksxqvvrvYr+LkHHapBckXKrOEAeWm1tsGf2Eppt9FIHE5qlpl6d2fDlck
         br/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=agNOfeGwaIxM1BpsZrTsKKrINqSU+ZKT6FzhLObZk18=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=c2H8It2pepyi9nb/owW5Fy8DCUiNMIKndvC+5RySnGkHk+LO892noXQFK7ZhlpFgmS
         2uYQc8qmydHhn1IGNK2t4DY9N3habHHucSbs4lwaVfGMXrZRDl7iGcyVEsPsQyyowP+/
         hGcOEllC67SG+HGhbHl1T1Nf3f6ovp304FMoDALvLTfYMwPu0C4iOKS2fYmkXD5MK8zs
         sAhk49fZJE7IsbqiEfKYRouHmZt2yeNAsEXHkbqztFGUoeMe8hlquuIb0j0GR9kNw6mu
         SQhnfILB8Q3KUcLCXSgOh2ckyp+KkJPH6dUxe9a0HqL9eV9ACgoaMF2oCyj0iShfLzN5
         QqlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LCohBSxo;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdba20e5csi73745739f.1.2024.06.19.08.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEwrZ1024141;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5c5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjqUe006314;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5c0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEKDs3011355;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtp2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjj4B47382964
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5D8CB2006E;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 04F352006A;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
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
Subject: [PATCH v5 33/37] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Wed, 19 Jun 2024 17:44:08 +0200
Message-ID: <20240619154530.163232-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: o1S14x9snFEyIzy71_JihxIM4LerZ1J_
X-Proofpoint-ORIG-GUID: N4O8l3X5dHvqWA4Z8xqzRXfIZtZKvw2I
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LCohBSxo;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-34-iii%40linux.ibm.com.
