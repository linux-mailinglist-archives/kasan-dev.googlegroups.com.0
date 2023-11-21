Return-Path: <kasan-dev+bncBCM3H26GVIOBBG6S6SVAMGQELVCIZPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6524D7F38AB
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:08 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7788fa5f1b0sf777030485a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604187; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLfqmZFCv1zoqeF+W4688qgC3qXcnb3HXXo6SMjF054Tz5Yf+k/J3xGcj+hLhlGBvD
         atnjcsT5iPOO6IalHEj7lGWo5gbWIJjbYVJV45b/ESxQUlKlWhHfFphteixorpDH0x6F
         tmsTYtFEsES/8dBp+rMR5VSld+g4WNOsXFdifB2DdcZQJq2m1zXD3aAqJ3uGXo3bfr9X
         7yFnnziqX3hAZyvIXJObtRnx6KZxEqQ+Nr6d0fozsQ5hnYN/6IgcdT31CjVYX0+zW6uN
         Iu+hLnTQGeeib1n3FNK8mqM8ukXxUhwAR/w2JO37+3Btxkiv5VwnukTgJ0XnVV1yWdJ4
         ayEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gM8698Nzyg0EbKxBFVnIheLjz1FIrMhM9tBs+dNRqTY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=AcPOcs2uyft5mgVo70gQv0GUXlUgedEeiT7JYf6fezq5R8lc6wLGTujQfJwfZjnDAQ
         vSRY2Op7PyJ+MNK9AeXfX2PccoRmzAWN0yzDNQsEBLk7YxW2FM34hAmzsKEHudIeO46G
         AUTCh2iioQ/MNB+q91xI+miRzQfKbZPvXoEkHW29PcQxbUfspqJ0sI5HePR+edfguAg9
         v1/WApjAYQGbHyqH+DWIpgc2aMFapUGeI6VG2c26VaSUHVSvPfHmw/4w0ZFSsmnOd/kJ
         +yENxnEZHbvM8d9m3VWGezs2txVK6rsJwsgcfLJreW17/e4V6Xc2z21uPB/FS8B6bR7Z
         sZvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L+8cqqrF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604187; x=1701208987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gM8698Nzyg0EbKxBFVnIheLjz1FIrMhM9tBs+dNRqTY=;
        b=DoVonLi4wSAIuYxNO9UuIQPxR8IvPH8CqCmR1DnQ3DrgiEJPqFDlRP51vHdgvRfL/0
         +CI324yZbiznL+rWvcioLYuuO0wcS6yT1T0ddhCsoByy17YZD7TkoueOekGhMm0DVNMn
         4UCw5bwmfYuqrH5M6IOayFT/tB9t3yql/81fk/YIBAS+/WuBLIB8x5cz1KnOBbA1TTqJ
         qcwTb3kml159dQB2xmvKnwTGWMlKCb+q/EM4lO1IjR0P5IhTGMvDjRRL1PGJIIqw/R+y
         HR9IhmOGudSBxR4lZYxkJnunlRzozTqkBjbHOhrscwnel7O+FKz5Cwije7Kt+mLKYCO/
         yP4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604187; x=1701208987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gM8698Nzyg0EbKxBFVnIheLjz1FIrMhM9tBs+dNRqTY=;
        b=JiOm5T0rmAbLltnsAWenvzQz0n0fYJiKWvf2pxcQJipdDzMkRwymGUY/Tb4dA14i2n
         UMTNTAGDZ8tps/ThHiyBkcR1FID43llJEILb1/NfdKg1n11+EDv6t1RtKyO4tyBgiQ0N
         xwLC1dmiSl7/TkmGS3LULIVKP8qwlJ5OTv/TQ4Qcj4ESxQXKdSG9Uawa2ruMmf+GI566
         seY9vwTZv+zoSnS50pFjyiZOdWukg4dZhF8b39bhmE5CD3e1U3x942gy+emdqt0veVgV
         P8tVQ5N/G7kqisLZmOSFlX70wABAQu/Kqvyp03TxtvZ3O7DKYmHv/5fQpXGzjYRwxuXz
         HJzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyqeghgROZqwMLVO4lC3qEuAiRWHgEKOqt/OwR4n9L3hpxEcEKc
	87pE9cQp2395lYbSKBhCfYc=
X-Google-Smtp-Source: AGHT+IHs50xIIZoYum9vve70FLmKhlpoS8nwp+o0sqkZpb4w5oI4u42OHwyDnF76jU5CP4GXp6wkxw==
X-Received: by 2002:a05:6214:e8d:b0:66d:2ae0:44cc with SMTP id hf13-20020a0562140e8d00b0066d2ae044ccmr515644qvb.21.1700604187188;
        Tue, 21 Nov 2023 14:03:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1e1:b0:66d:6af7:454e with SMTP id
 c1-20020a05621401e100b0066d6af7454els3379177qvu.1.-pod-prod-06-us; Tue, 21
 Nov 2023 14:03:06 -0800 (PST)
X-Received: by 2002:a05:6214:5006:b0:679:d33e:3527 with SMTP id jo6-20020a056214500600b00679d33e3527mr565331qvb.51.1700604186409;
        Tue, 21 Nov 2023 14:03:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604186; cv=none;
        d=google.com; s=arc-20160816;
        b=lQqurRQBlFtnUNY2YhD0PgbMZekce5Z/KP0xeSl50H1Q+rzNshwWOVXhAavYn8yeUm
         wFv6i707NLzCc5/ScQIOKAjih2n8e7R042CzrYjFyYHngnhsrD2ONbb8CgbHZTfgCVmm
         wbQ0LsoFvTqehhRk+NeQ6SF/vm6hVXvcELpdrVWdhY5DtZ2zmrP19ynpxi8PhxU6cVna
         /I3oElPCPOrnOcKiQHUW0H214hOmk9Eg+oqBBTglFsxJC6sce1zRHGABTA2o1On3mg/1
         hAn9HZG8011sGgx4Zx1VFga5+NM/Wfwbg0jsSA1KUD8hQGC57rtZBa8f9ozgYinvSkZb
         B68A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UDKtZIjnMspB2frCJtdqVzxUk5TBX7T6UOIrPkAOLVA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=QJL3ehzGmhgjNDWc6dt5DLOwsqn9mcL4oULum3smwNH4HB0hgJdEjwR30OOFEhNZJ5
         58FFAgldAepsr4cLNldy8TE9nBajfslQRJ7+46pFZwY7NoREt6HprA8MIRnsII0fQQIp
         zrFVCy/CzPXgLmFybcFJDdq8YgAFOY1LGLC9SgTjECHkIFx2fhOE2fEpfgbLKWkm6b0Z
         W6z9PELSChGEDaiYpynY35kERyzfpOizIRnZRsH7+BnySw8tZBw4FG0iynSG9EOzSjAA
         OT6LkXi7A3hZkmwuzPLq04Rgw3zMmg7SF9KdDB758xpAnyxQ8wZW5l8LrSTTkj0qhPZ7
         BH+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L+8cqqrF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id br16-20020a05620a461000b0077d55ecee50si201190qkb.7.2023.11.21.14.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:06 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlnrH021914;
	Tue, 21 Nov 2023 22:03:02 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68c5r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:01 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLm62H022921;
	Tue, 21 Nov 2023 22:03:01 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68c4t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:01 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnblt007094;
	Tue, 21 Nov 2023 22:03:00 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236m1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:00 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2vY062914868
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:57 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0573920067;
	Tue, 21 Nov 2023 22:02:57 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 90AFD20063;
	Tue, 21 Nov 2023 22:02:55 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:55 +0000 (GMT)
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
Subject: [PATCH v2 28/33] s390/string: Add KMSAN support
Date: Tue, 21 Nov 2023 23:01:22 +0100
Message-ID: <20231121220155.1217090-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 7M62AdOtlqzhieNaI_BHgPGcFZ8gsSni
X-Proofpoint-GUID: coPIcXW9nwH1Nbuhp_dwGo5aF4-eO1Lm
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
 header.i=@ibm.com header.s=pp1 header.b=L+8cqqrF;       spf=pass (google.com:
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

Add KMSAN support for the s390 implementations of the string functions.
Do this similar to how it's already done for KASAN, except that the
optimized memset{16,32,64}() functions need to be disabled: it's
important for KMSAN to know that they initialized something.

The way boot code is built with regard to string functions is
problematic, since most files think it's configured with sanitizers,
but boot/string.c doesn't. This creates various problems with the
memset64() definitions, depending on whether the code is built with
sanitizers or fortify. This should probably be streamlined, but in the
meantime resolve the issues by introducing the IN_BOOT_STRING_C macro,
similar to the existing IN_ARCH_STRING_C macro.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/string.c        | 16 ++++++++++++++++
 arch/s390/include/asm/string.h | 20 +++++++++++++++-----
 2 files changed, 31 insertions(+), 5 deletions(-)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index faccb33b462c..f6b9b1df48a8 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -1,11 +1,18 @@
 // SPDX-License-Identifier: GPL-2.0
+#define IN_BOOT_STRING_C 1
 #include <linux/ctype.h>
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KMSAN
 #include "../lib/string.c"
 
+/*
+ * Duplicate some functions from the common lib/string.c
+ * instead of fully including it.
+ */
+
 int strncmp(const char *cs, const char *ct, size_t count)
 {
 	unsigned char c1, c2;
@@ -22,6 +29,15 @@ int strncmp(const char *cs, const char *ct, size_t count)
 	return 0;
 }
 
+void *memset64(uint64_t *s, uint64_t v, size_t count)
+{
+	uint64_t *xs = s;
+
+	while (count--)
+		*xs++ = v;
+	return s;
+}
+
 char *skip_spaces(const char *str)
 {
 	while (isspace(*str))
diff --git a/arch/s390/include/asm/string.h b/arch/s390/include/asm/string.h
index 351685de53d2..2ab868cbae6c 100644
--- a/arch/s390/include/asm/string.h
+++ b/arch/s390/include/asm/string.h
@@ -15,15 +15,12 @@
 #define __HAVE_ARCH_MEMCPY	/* gcc builtin & arch function */
 #define __HAVE_ARCH_MEMMOVE	/* gcc builtin & arch function */
 #define __HAVE_ARCH_MEMSET	/* gcc builtin & arch function */
-#define __HAVE_ARCH_MEMSET16	/* arch function */
-#define __HAVE_ARCH_MEMSET32	/* arch function */
-#define __HAVE_ARCH_MEMSET64	/* arch function */
 
 void *memcpy(void *dest, const void *src, size_t n);
 void *memset(void *s, int c, size_t n);
 void *memmove(void *dest, const void *src, size_t n);
 
-#ifndef CONFIG_KASAN
+#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_MEMCHR	/* inline & arch function */
 #define __HAVE_ARCH_MEMCMP	/* arch function */
 #define __HAVE_ARCH_MEMSCAN	/* inline & arch function */
@@ -36,6 +33,9 @@ void *memmove(void *dest, const void *src, size_t n);
 #define __HAVE_ARCH_STRNCPY	/* arch function */
 #define __HAVE_ARCH_STRNLEN	/* inline & arch function */
 #define __HAVE_ARCH_STRSTR	/* arch function */
+#define __HAVE_ARCH_MEMSET16	/* arch function */
+#define __HAVE_ARCH_MEMSET32	/* arch function */
+#define __HAVE_ARCH_MEMSET64	/* arch function */
 
 /* Prototypes for non-inlined arch strings functions. */
 int memcmp(const void *s1, const void *s2, size_t n);
@@ -44,7 +44,7 @@ size_t strlcat(char *dest, const char *src, size_t n);
 char *strncat(char *dest, const char *src, size_t n);
 char *strncpy(char *dest, const char *src, size_t n);
 char *strstr(const char *s1, const char *s2);
-#endif /* !CONFIG_KASAN */
+#endif /* !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN) */
 
 #undef __HAVE_ARCH_STRCHR
 #undef __HAVE_ARCH_STRNCHR
@@ -74,20 +74,30 @@ void *__memset16(uint16_t *s, uint16_t v, size_t count);
 void *__memset32(uint32_t *s, uint32_t v, size_t count);
 void *__memset64(uint64_t *s, uint64_t v, size_t count);
 
+#ifdef __HAVE_ARCH_MEMSET16
 static inline void *memset16(uint16_t *s, uint16_t v, size_t count)
 {
 	return __memset16(s, v, count * sizeof(v));
 }
+#endif
 
+#ifdef __HAVE_ARCH_MEMSET32
 static inline void *memset32(uint32_t *s, uint32_t v, size_t count)
 {
 	return __memset32(s, v, count * sizeof(v));
 }
+#endif
 
+#ifdef __HAVE_ARCH_MEMSET64
+#ifdef IN_BOOT_STRING_C
+void *memset64(uint64_t *s, uint64_t v, size_t count);
+#else
 static inline void *memset64(uint64_t *s, uint64_t v, size_t count)
 {
 	return __memset64(s, v, count * sizeof(v));
 }
+#endif
+#endif
 
 #if !defined(IN_ARCH_STRING_C) && (!defined(CONFIG_FORTIFY_SOURCE) || defined(__NO_FORTIFY))
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-29-iii%40linux.ibm.com.
