Return-Path: <kasan-dev+bncBCM3H26GVIOBBUFFVSZQMGQE3Z6XTHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 51FE39076EE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:02 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3748f11c647sf319285ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293201; cv=pass;
        d=google.com; s=arc-20160816;
        b=oKkcrnWzXFj2Kk/gAyicA4noVUuKtwUX4H4Czx7aSLjY8Tro+F7ebDvZ77rmCuj1vz
         DZun8zmFgri3ywXsuRJmqaSvpNImBTFR5GOwKCc4qJWHt6Jz3Zt+pSvx/pwDHVCA3FA2
         PDcRGJaM2+64c8k1RvU0CjsV+Tixk961e0XRpLNHzoIrfzYPNMv+WQXKzJrNOpBCMBE4
         4t3OJhPpuiuTYVEElOSCAoNbxrjInawCM0bth/2W8otWxnmWnBc9Yi9WANXgVZ7qym1O
         4riPF6MOEB33amB8yPT6ydz4QSgfaTBGieKCv9gaCMCFjkaqhT/Pz3Mca5gEughyzxMC
         jTPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/08MBJ2H/QREu9nlhX+ZIC3L9tUKCj1FiV/AQq4JVPE=;
        fh=HP6jrsjTrqRXEIrD99ezLbbJcrIGu1q6RAcZXvrSWuE=;
        b=gzD4MyybCFb9L5DfLzppWL1q+roRuoae7o/LLsEl/l+bJqWVObFFOa6EyL4YXqIFzZ
         L6qWo3/cd6Ca0dRR2DjdXNeZpllV6bNKkrQUdBBtjP9gcpCDLWO/b+rcumDTzoLxyu/A
         siAMjDg2ZxuOOnf1/GWV9YMMkSCwq6xxrbZoEcj3+z5HHVvlm813AEng6aUkjC4rgVIC
         oFosz33jgcwUOVdrVPGj2FzANcRDdN3jM8Lvi4pZW+tUxDfHrq2aL0QiNBeX/1NaN8C1
         O1L7edRxdsEEWnw5bmlaGyjHyU6t1/DyTgbRIy9nu5u5FB1X4ZVVSd9ABA2mWzT+C7Sa
         la9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="O8U/ryfl";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293201; x=1718898001; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/08MBJ2H/QREu9nlhX+ZIC3L9tUKCj1FiV/AQq4JVPE=;
        b=pV6fOZmtVjnWVMZkIYBvvKKf682IcJh9HHFCRQZkBqf0v3HaczFZM4Jnf13oAubmxD
         cFkSaqyeX0NiZdnTxH8YsmDvdZoqkG1VaT9ZleJRwF9CBq087udxGHeFncGJdQoDbajS
         gRpAwPsYemRurG1qvI6eX9d3DfFp7N5ZYGLbj7MQH4kFQcQTTLdRdQqAmPnbvdRWJVmt
         Wj6p5rSVOlDoxnUhM2R21eHJyGayOvlQyo0lER5u4jW3klgN03jR73U0ZjU8QOn/3ATF
         O/dWG3MQDs/zgDp1ZlXlRXm+23qYYyXEhWSMhvLeKrW4256Yr661eFrJqPb927ieFiyy
         sFMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293201; x=1718898001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/08MBJ2H/QREu9nlhX+ZIC3L9tUKCj1FiV/AQq4JVPE=;
        b=Xc1ok7E7tcJRjI7xx6zAjmyekinyJsVZbfzAuMEdSHnlmuFTkxGfxYnFV/GDwTiIJE
         HpOSVIxFOpxc/BDCHUsQN6seb13xavwGUO6188RfWf4bCAaZHKWq8J7HtPgKuyZetTyT
         BwUf5Y66VXcW0odRrZRXjtr/Y9G6UoXXNGQsR9tyU/h7pSmWsrLDzIZJ5l9aKkCvdNuc
         3b9TY+A/V8HaX2/SLShavSe2bh/u/p75qDy/l8HPbruSHvBtTJjmE9LYWo/LZTRLun9X
         azx3z7NyzGHlntKX1JHck4UhrcWWzs+Raiora6RAvS1BR84UE4fLxtEUXxgJKIbCHQ28
         qHOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPKhxS28mN79ltJ9D2bVtfaA68lD/vnQzuQYpA0fhVT0C5/PEdco3c/pmm+vxBt2Jd3tR04BdeU4tIL3Yk3xEIaU3dnFhcGw==
X-Gm-Message-State: AOJu0Yy6r3Va+d6FcB2f3gO8nm1asPPmw5zv1yujW1mcH6scKps6k1Wt
	rOTqiveUJGeAU/98trZwITnMeez+eXaSmOKP7KiU16XpsZxcpxIU
X-Google-Smtp-Source: AGHT+IFkaAkLh6To9q/8DuTSdolP7NBXRNCQO9xNcdnF7cIrOnV+0uq3ildLlwIl2LdpRaaQ0TbwnQ==
X-Received: by 2002:a05:6e02:6:b0:374:862e:2504 with SMTP id e9e14a558f8ab-375d73fb354mr3171125ab.25.1718293201047;
        Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b4a6:b0:24f:d1bb:9951 with SMTP id
 586e51a60fabf-2552b67e445ls404493fac.0.-pod-prod-05-us; Thu, 13 Jun 2024
 08:40:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRfBqzYZ8s/PGpbnRh9K9/0R0malBJHAkrGJED4LHj7xEy8tH07FnDq69S1wiO81Hj1c4MfUZvMFDb0Ptit/Xraxwh3YxU7kxCRA==
X-Received: by 2002:a05:6358:5317:b0:19f:1aca:84c0 with SMTP id e5c5f4694b2df-19fa9df9003mr16744755d.11.1718293200117;
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293200; cv=none;
        d=google.com; s=arc-20160816;
        b=He1K2Xn8aSy7XKO6S4npuT2yxDXM4JXRX5sc+fSK+5vfcfbQmVMGIM8thELvGY0Xyx
         4OmeLgkW2QdfZ5FWL+uzhncz7BuAk5f9jP1yDWKUV2Xk7voxyS8g/C8I6DUJ49DlGbzP
         zsHAwP9FH1hTzi4UOwogxvJfy56St19zhH/amle3u9CcHveuLm3/4ykg8pp/ipqvcfns
         a/5y678iOXmmcsavLrpSQQn6iTvnXnCqOrFNEfevnjgXFsYcYNBwHAy4w5QWFa0m8ARl
         Lj0ng80tL/GZGen4cSbr7ZlJ9AfvxZ2VHxZ6CzDHUxzwcFsRP4NVf+RYPddaD6uIiKhU
         6dVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=twgTpfHCjImRnKDbwT1fFnn3UXy6li/j6Qe1IMbE5zU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=v1HaMulak4g7ey91akk5SwXNBwcqmzFG5KY/wP2Ys9Op1hv0Rz5pBIzb7mK/AO2G0C
         KJoE0RoVqlM3Ky424w1X1rKA8KRauSprQRa5seYnYQ7+STX8U3ldfK1ctzKCU29ZP+iE
         HHPavmDt0ATIWs4Vpgb+XX18CVmJr1Up0hu7AYpobtUBtXyC/B/VaJwu3Z1VMjlXxWFY
         Dtiudxj8YychrvQm1zvanJuYTcehNQJxk3J7lim6ZPviK5yD/UWAvuJkyNzZWWsiCjhZ
         rVCE9zUxZs5KDt8xquOynLGCW0m1pm02Wqcc2lCu+8SNUq0hJnTzaZ18J1nHXVfKTNdd
         KexQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="O8U/ryfl";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fed4d08039si84998a12.0.2024.06.13.08.39.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFPTbc021282;
	Thu, 13 Jun 2024 15:39:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgdf0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdtcx014929;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgdew-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:55 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEZQIF028710;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9g6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:54 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdn7944433780
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 65FBC20065;
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E78F42004D;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
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
Subject: [PATCH v4 30/35] s390/string: Add KMSAN support
Date: Thu, 13 Jun 2024 17:34:32 +0200
Message-ID: <20240613153924.961511-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: xAt3sBIWGlvAE8P-bHZ7h7aJJYjlYuY5
X-Proofpoint-GUID: 3bn059eewfkw9Fedtd0GxZ69YNCOvbgM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 clxscore=1015 bulkscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 mlxlogscore=999
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="O8U/ryfl";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-31-iii%40linux.ibm.com.
