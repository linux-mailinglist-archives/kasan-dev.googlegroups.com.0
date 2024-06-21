Return-Path: <kasan-dev+bncBCM3H26GVIOBBYMR2OZQMGQEBERADYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 03CC4911769
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:15 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2598e0fbeecsf1869554fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929634; cv=pass;
        d=google.com; s=arc-20160816;
        b=equ8Tp2vdF+4RhpKFFbnqGypp3waoJdBkIcpD3YvNXLgdIjOHzZCOFXcNscYDHeoT2
         btdflXAi6rF/KkbNue3p9NgtKD/8764XuY4hFZWno32+W/2eHiEOVzBKJVkLkwdjj/+P
         K3uX4iBfWMHcwweBtJZWiFqB8ZqOMw/uG11T8GgXMCSYxu72COz2beexhZkwP8etBPbC
         9Lu5mBsvyI/mc2l+4pcJaeCb6RhQDyQVUV+gw44r/wg5uOUFGG2JQFXvr2Q78ZWzyf+m
         PharhQHTqt8pYFwceFPlqdiVP1JRkg99Nkd9RxGcUiV7PxY5ljzeRqIG0OKAWLPoj5Hf
         jeCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8AR09fMwFA2e6xCwXBbbYNiViytv2CALsw5dHMj4gFg=;
        fh=+suf5W/hTzXlucG+vEkhY6775A+tQurKmgFfNIhbNMM=;
        b=sxijNjOLb7nmJGHF0AamvLaIJR8twwsz59bACW7Qy+VijwglZS2Vwj3bi+8+UkgLC3
         3dqdezj+fPspKaXjmXI1VMUcYrihSK3IzbUt/EzPc3suCRm6HiHkLkXf8Yjs4aAWljNv
         MBMIIpf7wD9bAS80v2uerkBwksevtJWlLXZ7Lwa3Jlmgwm+nHD8udtzoBBTy/tKfwFN4
         Wdy01xpIDNeDSjQJA8OfNugpS/LcghRm9NUvrUGFeprtTZgeRsxeUUGnZfnqU5pZLK3Z
         V99/k1/PMFtSLFHEzb8TxCmoUk7GZhp/FqOkWU1cKT/g8rmkuP28W1SF76etmcHbNfi9
         cydQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jiBtDJef;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929634; x=1719534434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8AR09fMwFA2e6xCwXBbbYNiViytv2CALsw5dHMj4gFg=;
        b=d08V+MpR5+h0ol9p+yLEuu8q5T0Bqt0jdy5+6AJjfUP1S6S+I75jX1bI7Z/cmPptVb
         joIeNBF9TN5ZTVH2U5x7A8wEjw3DFUB/ar/EFB5z36Ar4WiS0UdhxmAqXbac+Bmqzxm1
         WxLJev3rDN2QNri7VYJ/EGkCphHCsQ3DYSDlfGJMxYGt9ZZ+hIotnrzMa2EtkjEh6oPi
         sqJQNZzvjBNg93369f0uHVwTm6Tqlfz7g4QdPEqgavD12Ve+ifLwWwgONOT6DUtuA3bG
         WDXLyVnthZfvCunaaNJgH331UleUdPbhbNz+Dh15MfBLFXAmyhuO94vC1djRb5mzTd+D
         aFdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929634; x=1719534434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8AR09fMwFA2e6xCwXBbbYNiViytv2CALsw5dHMj4gFg=;
        b=WTwdmE5arI7bFbfyTYLi/WiNrXzBPN38Baq57JXUcXPUAAqOYVuFfDjbC+ORmMbaq8
         GzRnEkRikFTN8PVis0riT/lcqDy2u8UlWKanllwFs0P/HC46fNN/7n4y9hgpIER3iAP2
         mLZyvEgjta6AuFxV7EN6PkFtd2fB8aHBZqA6nl808NOtUD56WJI4dQlRrDjNcmdW5GbJ
         4un/CB53x78NWpyt0ikNce3kkm8F5gPkiOYXpyOeCJDGhDZWBM9BiviTVkMdJhL0Xtxi
         6bcard3gDXwszkzyB8zlwywSTRtV46nsogV5VdBVZK5bONAk0H5RWg74E4qWWRh0Kjw4
         7kpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfkluUxxWV3XdTawCwNQrg3XZU+laQctYCk1597/U33qsGe7JbcgcFpJuXlC6SdFw2Bo+Q10iPcCv/pus3pp/sKJxNbmqE6w==
X-Gm-Message-State: AOJu0Yx57oH4Ky8zayrev+yy85Gz+adzxaV+dO2xu/1u0V0DXpv7CntY
	7eqyOV+VDgebXfSSv1f78o14V/l/iA8Ubf2OrdLf+fMGkNu0/pLr
X-Google-Smtp-Source: AGHT+IHOOGoI5zL49Vs4sqk9Z1/nFA5oxqh/Dwqx9zsNCprFICP5bXulNQBSLL1qx6vUrDbf21F48Q==
X-Received: by 2002:a05:6870:e390:b0:25c:c35f:e25b with SMTP id 586e51a60fabf-25cc3603346mr2681713fac.37.1718929633785;
        Thu, 20 Jun 2024 17:27:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:27a6:b0:705:95e9:5906 with SMTP id
 d2e1a72fcca58-70640f95b47ls791420b3a.2.-pod-prod-02-us; Thu, 20 Jun 2024
 17:27:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGQc5emCP/YTEb+Bfeu7z0xZohT4YV00OXw9EO6EbtQ4Zw1+74CTDWevz/vntZiHAK3RiQ7SBnIwJ3vQ1Sc+NNvYL6bTbRNLtKRg==
X-Received: by 2002:a05:6a20:c512:b0:1b2:a889:f7da with SMTP id adf61e73a8af0-1bcbb6e1323mr6241382637.55.1718929631178;
        Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929631; cv=none;
        d=google.com; s=arc-20160816;
        b=Qz2vBNELFmBuCnnC2NCxkz2IoHv/HeWEBw3eGEMBeeifwjueO3yku+zP+S4Fz9YZ2i
         FAxk+eIsJdkUX0vsb6MgkvWhMxSOOPUD5dVd2//Y8F3o52HQmWdpCFHiEBG7clnyJY2k
         rsz+H/LQ/CIMzKBmH48G7MhoHc5gI/V86jU5mgLtaAGArtolG23b9RbZGX68v6rDhK5V
         cIUTKp6IQ4idK+faaOFX66wEtJoJoMw3+/5QRZAgR4LrXDEWjGVzicKMbb/Vj2ndeXsv
         UZw7nquS9IOe8xZxfi3FwYqT/YS5FCcS2Mk2qBJPGB2a4KPh2//qMsnQam+QpzsWNzJR
         ycfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=twgTpfHCjImRnKDbwT1fFnn3UXy6li/j6Qe1IMbE5zU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ur61xBshllLh9K2LvMBRSznORRa+/YxGjCSMs+x+gWn+oS46MzGmTc+UELxccAXXgH
         kjFz8dLmIO4TWhfmTElPS0q18lVpTi+bhi2B+hBRMcW1BjYPse1VjhHCg8LvLHfregZS
         Tl9bFITNwMTXVK/bSl3usg2sGzDRq8ireTDRMUq4Qe1ZGaSk2wajec8UUO5kQVxEb1Wp
         GJE8mBXye4OS+sbxAbvOqZW5NZnUqYtY7Wy1ehyjHxyfpAKPSMZGmRbYRGK/H5/TztLg
         kkwS2Ptiu9anA3or3JdKuqXcMYqRdbZnj50DTz5wzyyYAJCZM+lFKgKBP7Tkk+VJsuxJ
         EU0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jiBtDJef;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c709e9f07fsi940513a91.0.2024.06.20.17.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0R8Nr030442;
	Fri, 21 Jun 2024 00:27:08 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8m05k6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:07 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R7Kj030413;
	Fri, 21 Jun 2024 00:27:07 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8m05k1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:07 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0Mhnu030888;
	Fri, 21 Jun 2024 00:27:06 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn43-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:06 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R0hd56689060
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:02 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6000820040;
	Fri, 21 Jun 2024 00:27:00 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 40E5D20043;
	Fri, 21 Jun 2024 00:26:59 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:59 +0000 (GMT)
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
Subject: [PATCH v6 33/39] s390/string: Add KMSAN support
Date: Fri, 21 Jun 2024 02:25:07 +0200
Message-ID: <20240621002616.40684-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: DCrf_kw9F0ThMge5E2Hiq5L8_HHpB9Db
X-Proofpoint-ORIG-GUID: 94o7KX1XsNd8aCWgl6SdTmdusc7KBk8Q
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0
 priorityscore=1501 suspectscore=0 clxscore=1015 impostorscore=0 mlxscore=0
 bulkscore=0 lowpriorityscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jiBtDJef;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-34-iii%40linux.ibm.com.
