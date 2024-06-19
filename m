Return-Path: <kasan-dev+bncBCM3H26GVIOBBNP2ZOZQMGQEGJZY2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BA6E90F2B7
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:59 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2c7a68c3a85sf1668205a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811958; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNnpO1w/WD7n60OPeumyK+/VcMPU8Zq3GNoZBe45I2UyLOgk6KEthJl0FshqNkC9Wy
         wRavkB3u3nT00bl+FlWxlIIWx2ucrAVg+ZpIzk6OLmZa1gFRrngfos84uqbenwRHgoUH
         qhY/cCpyXEE/pGUQd9dTrJ8lxg/y12yUK1Ox1R5Kvu2KP5SlHiiGlPUobgmFA2/V6lbO
         C4V+UgSBfp2jNAd/cNmDBWcd2IipVZ3v9xuUWOItTTwLVWI85Rgyd/6AJ5KW1lCOgJN4
         bSO7GWD46tqwnwdOo9glkxhECq9LPnYuwt7LjVgMSE8Vkj4OnNZ4NczAEdh5kr5Sz/Ri
         Abgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xRNHWtLcMjapvtVInUtC9gL1F9DI4VtdxTdQGq6QWLQ=;
        fh=utS/wbAXOHMbSqxnImbjLM6QnpL+KzUe/UuUyk0KD9Q=;
        b=QFjPnX07j30SD6wBJrGWgIuYGWEzXUWirPi9iXALeAEWYIdaG3IxDgpGgIRN23+E84
         65EOQ3u7WqPfpRYM5OkVqLRgRmPA4kTZd5+MAguNd67hiYOie2PsVJud0wVlRsgMmTHa
         5SZOT4pSJ2hE16m5c+WoJZl98hyg96Di20VRKWCCfi9FWM734xUNgeQwKrpMMoK0eEJ2
         A7ncjVpEfo7KeTLCVrTor+ReJV9ZKjAKyDlF1T1GjVmJOcEadyicMA+9KxJdqN3ITVoJ
         BC2HC4bh/lIYR7CYyzMHCN5WRIX1esZT8uwL+tqgWuQYax1vq8Xnij/LZtfj9XKyqU4e
         Z/Vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BtKVmwsW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811958; x=1719416758; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xRNHWtLcMjapvtVInUtC9gL1F9DI4VtdxTdQGq6QWLQ=;
        b=RBxzOpds+H6I8nyRDfaCUC3Zr595wIrOEOA8hv0LNGza47HSvTiJqdWIyV1Vwr3EQA
         KepQGW9YIi7RUAys1RigMpcGDnHGXxA7op+En6OfeZYAKLZlYU5V43Sbr6EsYOSjhli2
         TwEjbOiJZZdCZxprQMhZUDgfmaqqRuSLy93Z4nqu+aJTIv2KZeuBrZWH1qKBtQoDxjar
         R6e4trcXSkEUH7cQ/GJImjdd7z+xy2zIMkOVAv+BiblPeKn6T9wK7I3t2+U3ArI6j/9b
         J4ZzeXJnpMrocUqN/NJSvHC3QVc0DTdQI4I10s+t84vqI8fDIBFKmOJaIe/Yo5/JdCkn
         ghVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811958; x=1719416758;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xRNHWtLcMjapvtVInUtC9gL1F9DI4VtdxTdQGq6QWLQ=;
        b=e/DHPmrXoWnuIcEfmYpxbGtBONuiNVixzgkZSqG+PzMHhc82wGWerz2WBETb9yXotR
         ls31dogCOYotAR/5oZ8nkQTmT27Pnk5xh/cCcNStPNcM8UlyOLzYrBxCPZ85vamjNo61
         veFbiapIA6gD4jdxGrvgsAY7njZpKMqbQ+pXdYJYkVDVulfqKe4WjUWY7ovyB+Pi4VsO
         L/iXlSTB9s7ux168ksK/gaNkKsn1i7ZyNMda2dYzIZqKe4N0kh+Mh6Oo7N/jyofW0lsx
         v5QmvHokXVZE5eGXASTYWisxAmQhvcEB3ajrj3m7jiJuP+OKKx8rvE+ctK0badbz0kuj
         zwrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWt6RUCF7gIvtdXNtTqHjOl2ZUYWtvweBs0WMOLDlZuXyTjUwCNvO4ENULxOHCGkeZoszlRrAA8JPPaf/VVUCE4FbyuXGZ3Pg==
X-Gm-Message-State: AOJu0YyH7wCheiCb8Z3H6+vEUnAl/PmZBI0EkIwqxeX3+IbT6J3jao4I
	g9dmO5NBHI6BFuhO/y2oBKWjlwaQ8w1WwwNXVSY/s0rM047C8sTF
X-Google-Smtp-Source: AGHT+IGzMPtQn6upMq5sFJn8Lhu///woT56gp6hf1BZ0MD7scVaOmqxFcfhsBsPM5TIL99zhJePNJQ==
X-Received: by 2002:a17:90a:bc85:b0:2c2:97c2:1424 with SMTP id 98e67ed59e1d1-2c7b5c8be42mr2838912a91.25.1718811957909;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3508:b0:2c5:128e:240 with SMTP id
 98e67ed59e1d1-2c5128e04c0ls2533623a91.2.-pod-prod-06-us; Wed, 19 Jun 2024
 08:45:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcuWQld7f/OjtQO+pGK4Yei16+Ci90b7lmHMy2b3eyaj88rYZNj9guUwb3EQz9iyTpt5u28z+aog/gQ0k43KOfiSRbdm04YyqaUg==
X-Received: by 2002:a17:90a:b881:b0:2c2:d260:e4b8 with SMTP id 98e67ed59e1d1-2c7b5d83386mr2840865a91.40.1718811955693;
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811955; cv=none;
        d=google.com; s=arc-20160816;
        b=XKi7RypK9hHXpCK7n/BDUcj7GhBybhwobgME3bahCmLKeT/D3bnLtR6ZDVkkrqH8Kp
         D6+2lWWOQpqBA02qPgeDCOuYjakx9bzN3QfZt0Q2wMckh/4kytEZHmhqReGiYYzGbcmY
         TLlfaZyOaMuEshg+CzrxjH0MYF41R6eQXmd57V70Bm/3I7sbNv3gdlUOoCIf0D6/wLAy
         2OlYIqAXyjiOdC25JtO6kquJQliRVB8EM+MXz2S70WaPWmo3xS0P1+f/t/tIV6cMqRsA
         O6MTEYzYpG/Eap4xeZSs14ncTXkgX93p9vT3zbbyCo2znM3YzFSPBXPXmRxd3iSF2ndl
         0HTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=twgTpfHCjImRnKDbwT1fFnn3UXy6li/j6Qe1IMbE5zU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=duyjzZx82+YpdpEHh7s6D8H8j9TIneLUwbVaisQmNLmrCa7Q33NfLQTo4zgbKEhJDu
         gM+0cRd4VnzQDT7G9h7NsVY8Xrm7xVvTjXWRpcJM7aJLuRlQf6bpW2Cn6Oadx4coW8mj
         JEo9sXYaL+X1llHxr7TfC6GVwaBU9cF79xm7fuQa9OSww7kFmiXQJc0/mBsEDEIKy9YK
         5QgDE0ZyTaHWpeHLybfvY2cvUpAKAr9nUlf1XKyONGRUn89lrf1uBpnkJIfKZF7KvFtA
         gYPuEXMgJXA1FL/TqeRzzxnZ4Cm8g9+yVnV1LkyHZE7u1l87Pn9Kdun9C8GyJNRXTL8v
         7DKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BtKVmwsW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738c1998asi276171a91.1.2024.06.19.08.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETPqE000732;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8cf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjpu4027917;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8cc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEF4L2011037;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtnw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjiZx32834174
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9E7C42006C;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4FB1720067;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
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
Subject: [PATCH v5 31/37] s390/string: Add KMSAN support
Date: Wed, 19 Jun 2024 17:44:06 +0200
Message-ID: <20240619154530.163232-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 1vJnWjP8onhRd1nDUiLNOB821DSsFz-x
X-Proofpoint-ORIG-GUID: r5jD2ijdGJxfVZVu2IqQYF5MTuXKfUuS
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BtKVmwsW;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-32-iii%40linux.ibm.com.
