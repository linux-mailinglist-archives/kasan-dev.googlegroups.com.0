Return-Path: <kasan-dev+bncBCM3H26GVIOBBH4A5GVQMGQEJZX3HEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C6358812311
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:04 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-6d9f5369586sf8677650a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510623; cv=pass;
        d=google.com; s=arc-20160816;
        b=DhEBtqiNtjXZVfuNaKO1bnSMBP5CROjhNix/d9DP/hPFO3eq0zAZYNaWo6WFGb7z31
         jY0fYoHrzJJu9Vs9uWRfUCMOz5bRq8W/hoM8IUUrTuYmi/AJJZyGbbk8DXYGtrYrVbeB
         gfCCnIkF3suGGU8+/gN9kNon/vNCtRpoeH50by88/l6HBKb2mZT47t8J4roYqx28Nm8r
         Sx+NvgNlRLPSTrpoHCxz+BcVKUT6w3Uy5Qrzh1y9uIqnJhFihYNMhdYVIUz0C3F0UuyF
         CJwpDpep53+wyuypQHzE/aBuvXm31nWlOgrxXMrsDL5PbkIYtZU7ZPI6iB/y90yp4UVa
         79rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2IiLFZYkm9fFRI0rnNOeH8ZVjeTm9zgyEO0U1mXNZg8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=bLbCX2HwQP1wXA0VPgoacVcQuj0ewvRuh2VLkCcxdXfi5ahxjcJ7lZfMgjlFbHfEJB
         1v1QIMO1irdGVA2WoIj2DK7JRD3YADL1ExNldv9b3/m8TBeFMD3uuEaRmc57gi+wADJT
         QfLe8VkoXz1c2OEuiaXgAC3islrp9lfXM+QEmyArkRalbz68daue9OSdL11405DmS8QW
         F4AnLwr+QHnWgV0UIHAVuqtCIDCTDkTqugy9QLeR7kTGFM46S3cRWG1q00mRKphHh0nA
         oX5+dSSvnB7qMm6axQg3i5L+C48G1iH8ze2bkM7Tnyyww7IpG5/j0cewAFhwPQYwc+WC
         F/0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=r3caq7Ta;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510623; x=1703115423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2IiLFZYkm9fFRI0rnNOeH8ZVjeTm9zgyEO0U1mXNZg8=;
        b=StjXSxc6ozHcjbFQjKr45TVtGc4RXqfdGJgHShb5Op0LLoNdF+f5Qzw028Bdo5zVOp
         KwdbC1zJoHukQKj7mv5DsYQ6TY/mRV5Xm8u4A/VaSUbW4l98CloSukKFBKU8i3HbgwAZ
         qT7Tt8D1NvRFRom3lE6RZ11GPrLhn8ZBgF9KnDy6Uv2xjQ6W2wrwvLeNCTRrt9XobfeN
         j8ZGMyDFLnJnqorA/2A8xjey/aowGX4jDg94bhlcuWHVfFVwltNqugBhEZE165YhSYhO
         JVH41BVUSHTmtBHnz2MuWcyfIKNPe3XGpKg+gVme0OYduwp7sUFiFoJX+TRhvhFEJHbn
         u0RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510623; x=1703115423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2IiLFZYkm9fFRI0rnNOeH8ZVjeTm9zgyEO0U1mXNZg8=;
        b=r64Xy38aDVUb2U2ejnvMwPqqg8ILjwCo2pUcKYyBst05Bz0Lf0TnuzGlgJoq7tGAu3
         2Jg4mKlAUY/YIL5kZUWqjJTQpHqzOJnpoHMfzkCtHaDeT5+G4bvZpoOYbkgTh7KB6r3i
         DsDwDTxmSLF0QuCmZj8hmhjZLx1aYFr54kvkZjRVtno1uc2nCV6ldlrVbq07iM45uGh0
         G6pij+wuQd6/L8Wf7HR0sk25tQeyn3Zfn8eH/cd66t9bTt8bOwJq08Up6ffReNNuvenf
         G5VhGad5Sf93Q06Rc3SfyF+Z/v6cI4gjLoPcL/gU0NBsyR0vli2Q4UXYoy72/XwQJRKV
         9jXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyS8Yz22Itay06LMRHQ/nzWVABzJdAiALN2SN3fFPrjdHgvjWIy
	pfFesdQfMqZlDPaSw04/IK0=
X-Google-Smtp-Source: AGHT+IEa8b+KTJJ9WuEFf9k/kZEWwOtAeUMa/t2zdzF7l9AKk3yJZwnjyibHDBY2Bm95jMPJpITNQQ==
X-Received: by 2002:a05:6870:c186:b0:1fa:1355:da45 with SMTP id h6-20020a056870c18600b001fa1355da45mr10647045oad.11.1702510623069;
        Wed, 13 Dec 2023 15:37:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c05:b0:1fb:1d02:120f with SMTP id
 le5-20020a0568700c0500b001fb1d02120fls1421955oab.1.-pod-prod-05-us; Wed, 13
 Dec 2023 15:37:02 -0800 (PST)
X-Received: by 2002:a05:6808:14c4:b0:3b8:b402:74de with SMTP id f4-20020a05680814c400b003b8b40274demr11098550oiw.32.1702510622346;
        Wed, 13 Dec 2023 15:37:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510622; cv=none;
        d=google.com; s=arc-20160816;
        b=zGvn3BHro1Nf22lYUVQcO1EU8ohlYolyb+eyJ/fyuI0AiActwfVkpRDSQO07a8sczp
         zQKQjTScl7KlkwTnGg/kAQ/CnJc1C6VeJa1CBvYklFtqGUAI/HHfGCPh2jbWR/rkDtaH
         R4VZ5b5k4XfsmPb724YTMUzlhjt4D40Br7isOOVIVPiOPnmtbPJwmEQzlj8BIC3Hn1Vm
         kR8UnLnNHWTjCMnBeQB/rs5iJtSHxv+op1+W326dp7l8WnTUUU7V/BdgPxY/jcPKSe2y
         mDaXFkczu17MYAdW/n5cAMHF3P5Y3Oze0opP8VlvS8GhHsXM1RN0+j5JzBc2XA4x+FQH
         ikug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uehXTWhTAti2RbWOf4Uy4ADfWEwLA/3Qguip2P6sfCk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ZLeLRdkbxwYLhEUE80DRWEgAYvsTjl1+yBo/tgPBSB+ppmjNc/bR/hnEk7Nsyg7nGm
         PIXTsLQeKdRuWzwUB/C0gamq37ZliiVMGF7FsGG6llCSB/X/A10ODGRXCFhTbXWghHXb
         Ibfel38sAq7ICYAEI+WcKekAbdmtXTUakkpmqjDr4rZciCh9QHFuT7GTIqCOizQKI2ct
         V5hLYLHjeT9H7dhGzbJXX+pwZnKY+fkQWbtxNGjBUT7Yow3XIdsR+Lavs4piFcTdP4LO
         rTecGE4XmRXRE/ou5x4FNgKVSOWsyP83mwwpRDOzWhYS/kL8mmt5GNDXeIESChdsPqSC
         l+zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=r3caq7Ta;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bv9-20020a05622a0a0900b004239ed495d6si2321662qtb.2.2023.12.13.15.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:02 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMNSlB009777;
	Wed, 13 Dec 2023 23:36:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1d43-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:59 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNPLv0015845;
	Wed, 13 Dec 2023 23:36:58 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1d3u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:58 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNOPrV014136;
	Wed, 13 Dec 2023 23:36:57 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4kb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:57 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNasWZ19399296
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:55 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C829120040;
	Wed, 13 Dec 2023 23:36:54 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 616EE20043;
	Wed, 13 Dec 2023 23:36:53 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:53 +0000 (GMT)
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
Subject: [PATCH v3 29/34] s390/string: Add KMSAN support
Date: Thu, 14 Dec 2023 00:24:49 +0100
Message-ID: <20231213233605.661251-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: avSp4lR9n432laRfm456yBo3_eY87VR9
X-Proofpoint-ORIG-GUID: yTkAPanVBluqwaQP7gkJ1tZqPgPXBCFg
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 clxscore=1015 bulkscore=0 mlxscore=0 spamscore=0
 suspectscore=0 impostorscore=0 mlxlogscore=999 phishscore=0
 lowpriorityscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=r3caq7Ta;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-30-iii%40linux.ibm.com.
