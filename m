Return-Path: <kasan-dev+bncBCM3H26GVIOBBU5FVSZQMGQEEZ5J7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0358E9076F4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:05 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c1e953176csf1016620a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293203; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThylqqerXb4wxTF4AOyN78sUPmyE0rYWtG/aPAVkJU0rh4Jg81WSS8MKN3qi/Bi7+P
         oLT31+T7lzLLirnPojmSrdnRGpQKcVcE1oXTVrMU1Me6qnj37VMhTjPDbZhSe9DIAEae
         BdlnIfuQ/SJfwLy2JSplpWa8otCIgMFVgxP8w9C4jSHgfBASEzbB/k0seoZA60f3FfSC
         1ti0oBS3XVELWRHLfHn1OTIzErdolRB/ZG2rycELR5qkj2AktvGCtbzgx7P0tHKsod1S
         pGZxamYLzegq55c/VrX10idnxfvDwuSRRAYv3HEGJl/eaxfoDZTvmKviP40W3V5ZEbkP
         zImw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sI3Eu4fOkFy6PfHMdqlyfwSLi+VYaBzPUg5baHtv4Jc=;
        fh=LJ7utGoW7xEQsZ5KZxwIN+REgOaoLwkHOLa86XjcFW4=;
        b=hvdH70koOvnAG9xdo1fM/wgLd49rLyNCpVnK/dxw0PGqH+yPBx1vsHfdABBPdtkifl
         oO79bKIJ9gHE2QmlPzH1D2i5wUwQeUkWBiAsSOVJjaCw1SaS8U2cYnnd4mP5k1SfljJ0
         N3E2lzj7NNFtwGXjQnX1+LRd+o3CgYuLYwzy9EMMt7otiDyAGBTKABtOsYXsKGGRXfxJ
         qY8mJ4ulQxBhqRO15/sg8pODQI8W+RYga4hqXboxh39gCtKdUpOE85ZiTrRcM8y9LvrQ
         355+nR7NeTn2vIgp6n0tGhvnq4HPRcaUpEcTvwXPPcawoc0v5gwOJ9h4MsxiJJz1Lcxa
         OakA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fSifDVun;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293203; x=1718898003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sI3Eu4fOkFy6PfHMdqlyfwSLi+VYaBzPUg5baHtv4Jc=;
        b=gcvD2PP/vXHoSJTF7WONyM8bxGwbOaVo3tJGdnZhyShQMMVwJoA3tNn5b7kdcJvpXx
         pjLjqhmvGqjDrJmVrs50DV3TsicGBt9CoR5XJau0LwI41DK/z811nU9GrZvO4AU3rk+9
         tGim/cKuqmVBrXqomwceADDYBTpQTab+fdja8qFR7/c/SsiKLfx+kc2X8QfL8RMXBKUh
         Kspz0neS5Faxxb7gIIonwTG+XeYkbdc1UG67FFZobJndiwF7fWu4zFegZ2CAsWX1ahF1
         7Sj77oRc6g27BWbETeynwM4/VFmYWT1MksTuYnesVAnw0nKzN+cn3Md4j7QPPlKkEVgW
         TWKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293203; x=1718898003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sI3Eu4fOkFy6PfHMdqlyfwSLi+VYaBzPUg5baHtv4Jc=;
        b=ouXVNkgxd4M/hFD5yFnxekzdzGIXGI95F1YXsjTKp/V9ojyyIUDaqfwpOtjPD+A2/g
         y4cfmebtDOebhBqDmY2ujNs8OoqHt/PipFDnPifkAGOn7J+JlMwWGocbMFLczIIPJ4b1
         AbnJhWuRk62SbgRCYUUHjTFqHRcv5gSYyIosSfw45pkfDrVJH7BnZkIndYQeKGbB2Vm8
         TxywcA7r5+BYVZTeeq45S1mLujjnRvrGFV9UrY8scGBWsPd7SoGRaEJeeMGNyWlVa7S1
         2Enq0+EEjeWSvvS7Tmj/DuZMpf73oXh0Cm7RESMHLsMUyeohAKaTxqawHkw3gbx1pC8W
         ++9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzXc98JehCEbAIVh87K6V2eUcntIlcDObT5dYQ8GjLAFLjEHT4pNzZj12y76UDehrxb6fzxHtSFm0tonmqOEdaVosheGMXFw==
X-Gm-Message-State: AOJu0Yz7Sog1ROeg1N/93OtdeSEgbX/j+7FZ5PQQi9EAJbiXHcoZYCpN
	om2frK7eOsrXQwTV52d+sGkeI/04/SLrvswX2/wPUmKuDLY3KOEn
X-Google-Smtp-Source: AGHT+IFhatfJXoarQZ3fN0y4BfgdW9lczFu2BslRvNsVF634I/azlEkxz2fZCjX0R/4+tjFoKNlpww==
X-Received: by 2002:a17:90a:c7d0:b0:2c3:3cee:7d7b with SMTP id 98e67ed59e1d1-2c4da9ceaa8mr188112a91.0.1718293203532;
        Thu, 13 Jun 2024 08:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7182:b0:2c2:e667:d721 with SMTP id
 98e67ed59e1d1-2c4bde85546ls680397a91.1.-pod-prod-01-us; Thu, 13 Jun 2024
 08:40:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVX7ddWL2/F2AWoA70jYRI3LmXl8Xm8r07V6XiqZpzH19HHObFLI64CZLJy6rwrdysYQSuW6O2mUVhpU10jlIss37IH7K7TPRMEnA==
X-Received: by 2002:a17:90a:1150:b0:2c2:cefc:abea with SMTP id 98e67ed59e1d1-2c4dbb43d8fmr105462a91.32.1718293202263;
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293202; cv=none;
        d=google.com; s=arc-20160816;
        b=SaoV6uUuQcC+rZvcb3MxBuFpATCI5RVaN+2MksNyxbXFgMhLTXFigZuMaP6SMIGS5u
         f2QxDjUgInd2euxGKGh71oJJkgZd7q37V8iFjb+9PKZryGCyP/n7IBH9zAz2nXx/3Duo
         HApr8mMw58agjMn5Wt6HbnqftjBoqjutVq17JWNlD6WiS0OVnZQIPKMsWZ12afptfn5T
         l7xj8usElCpF9UG1+JYfi5ETeOMhYDjOzg1ucgiLkdo3hUqDk76pwZxfw4O7mTab1ZZl
         sRxbLPFnxffXfSb4ZsKmycb/FOBAgh6vOmwC1m6k30b52ARvM4avAQTrGORJTJgGp8zQ
         sSng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CYFEFjp+FNib01S0Zs5TmXfuADWi3PITsqpL8+vbRiE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=QHry0PhmPnhDZcuy/mKocEVO+pK5BWrbY6PUk9Bj+r5WJzeUy6AuVIx/mqYYcmWn3j
         KHG8RTavqS3UXa3s5bp6SHCT6r0TV05MAjxobsDj/TLiJH2ewDn4w6HcpLgG/NFtyF1B
         5SA1XjHsMlT8uSoDNl7pQZnP+6xZ9k1WJ2ogYGURIqYeZrRArX/zn2TmFs/8tiNZGXBx
         acntqi2Jzz9G189dRJjln0DXELseqZW1woFH8gGiwzG/Lp5VVyqe5s27dbQuDC63z1W1
         cmoB1ttvCmEEKv8SQ8GgrT8nowintA98WIsY6X8Nfn+mqM4Y+sufZF41+8FdIjpvm4LT
         uLoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fSifDVun;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4c9228c35si73586a91.0.2024.06.13.08.40.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEpF5N029454;
	Thu, 13 Jun 2024 15:39:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdvkI026881;
	Thu, 13 Jun 2024 15:39:57 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEfGBm028808;
	Thu, 13 Jun 2024 15:39:56 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9gb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdoB748431612
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 86C592004F;
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0A95820063;
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
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
Subject: [PATCH v4 32/35] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Thu, 13 Jun 2024 17:34:34 +0200
Message-ID: <20240613153924.961511-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: -_M5ulyygg4ASeGuTz-Bwb4CIhDqNlvv
X-Proofpoint-GUID: 0o6Aa2cEi8g05kK7vU8AUdruIPbuy9kH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fSifDVun;       spf=pass (google.com:
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-33-iii%40linux.ibm.com.
