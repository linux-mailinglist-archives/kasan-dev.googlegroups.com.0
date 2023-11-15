Return-Path: <kasan-dev+bncBCM3H26GVIOBB56W2SVAMGQEU6RERKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24AB57ED237
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:05 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7a9b1af00ffsf475239f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080504; cv=pass;
        d=google.com; s=arc-20160816;
        b=UuBMkCUSg9FQIXmTVbneCQr/Dvfw1JrRCjQqm5pmZhQK5RuPqzZkToTzvhyW/rT+Y1
         GtZ+6lfWVkkA4uMTcFjZduOdjPb0sAMUwb9BIqBbwYVd+VEy2gMGqkSH8aZs/awzGBlZ
         peh5l6bv8vbV4XVSlSPTiNvfiZdujVu/YhEKZwLcB5sFwuT7hDCGdbhKEUzOQflNZVLT
         osvh6MBJS0F65S36LFqGWeS4CNGOrEEsmnbK/+2hlNyp7vJp2JOHQQm/9+eplomuqrxw
         7pL5qI0XrddRh/m23V1QcpyLD3SOsr++Cpx+iqo3G0AqigmA4CpYhMuiiL0qF1G0UCbT
         rn0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=80MJOH5TVdU95alVBLs1Yd5QAZeisB4ejnae587cWGE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=RApQdRaBRoLBgO4E1xTPiH5sY/y5b9bmJIU9ZNgUNUjUs/HEFpcRaa1ap6uKicZWIQ
         jX5rJDn7q8GwneKdYBFJqFpIosDWmQV5aOqRTJrB7N1dh93FSxz6n5nZpWIBrVyOrmFK
         Xhu0OikjObgsWPUTKQtZXXBreQgLKcNhfFsvNUWfhkFBu4o5BYZZV3A1YI+kFRGLCGHv
         C9fnMzBYTp65o+RZxT1Ld76dDEX2Q5bardsuBKq2WdBu/zDybflxNYyhvZdULX9iVNx2
         YfLb5UUzvJJb0OFksNdCn6kdQCLlRg5HtYPr84qylD9S9u2Y7eXGeX+Zt+nPQ1ohTiQy
         /DYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Um1Q9Qho;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080504; x=1700685304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=80MJOH5TVdU95alVBLs1Yd5QAZeisB4ejnae587cWGE=;
        b=uKadzgbiOdD6ECUHOQlEYj4DbdWSLB5D2O5ck3l4IfPo/o/qMcA8urf4bKXDf4fX+v
         WfJDvOLrZEmxkvsWxlRrDl2+0jOJXQguiHPgUApdxxaAZYrZE8j//j2Fh7RKU8Y+uW9u
         H7oYekMVVinV110N99o4fbWZ3VS/MaXgyyBCCWTb956xjH4ETBO+kgOUuIKL0nF6uKdW
         T6HLQh/Hl0ItMGwy5+Mh/5qbb6DjAO2z/uykHStBuO20ZwKG25scPHKg33hyZyzaMDrb
         bpeCNhOG+07d4lM6PaANitPbHLCD/ef8x0cSaysqLJ4XJZajqdJLK2wbDMcjze+zmPrs
         KPng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080504; x=1700685304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=80MJOH5TVdU95alVBLs1Yd5QAZeisB4ejnae587cWGE=;
        b=sdQLG4zW3TuUcUUws6Ahh/hdGtda5tMwZlCt0RchricGC2BWpnlM+Pka7sxosiGDmI
         j4/ZHtdacmWBs8tAgCGeJwTTlahz6i3PKp6DylxferO/8r6jOOtOw5RClVB57wnaMxgY
         0I4SDBemExTAKgGSe4GOMzKF6Yf2bCblR3X9f/QAaT8pWJuVsdrMN5GqFBwCQVET1nlQ
         JteNqzmVefQJXhYtwGZMz98ko8tfjC+/plk8kCWiRnmPxGyksuPJ4vOeziiG0Buh6WTg
         GOIqfoXKBUPA40QUSjSBKVgRBMvPuLTq5CeCN9U8PlfW6UtTyVsxLRjctXMqBl2RkNTw
         cfqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YySZrLi9FbF/S2p523KaZI1lE/db6vbnQyKj1Ee3x1cucREq/rJ
	lIpxoF0g+je5lQMF10Qdi7A=
X-Google-Smtp-Source: AGHT+IG5H1VBKxAjDEPtys6+OWNW/6WNtkihAi7g0e+a/kZ7xVJW0k5RYXvu/SA0H6OJgBpijkJEqA==
X-Received: by 2002:a05:6e02:1a4f:b0:359:6b27:98d0 with SMTP id u15-20020a056e021a4f00b003596b2798d0mr8363296ilv.1.1700080504039;
        Wed, 15 Nov 2023 12:35:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b744:0:b0:357:fba9:f281 with SMTP id c4-20020a92b744000000b00357fba9f281ls60973ilm.1.-pod-prod-00-us;
 Wed, 15 Nov 2023 12:35:03 -0800 (PST)
X-Received: by 2002:a05:6e02:1c27:b0:359:30fe:d60e with SMTP id m7-20020a056e021c2700b0035930fed60emr6200225ilh.1.1700080503135;
        Wed, 15 Nov 2023 12:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080503; cv=none;
        d=google.com; s=arc-20160816;
        b=ncKGF4p4/qCvEXdIb+BToy12JJoBSfJNS+noKO9wfgtwqxszuQd+geSIYmUvfmgA/e
         q6DCQU7qdJEJPdWxhVRcoAPOns/ztyMtdFume8GmxIjuOs2sTSQKfFeNKslt5yjmtJMz
         JDsSYDFQ5gbI615YkUEr3GeEwR7mkERtShuP6f8SmA1N+llP/9PygVWw/DdKK629GDyn
         z7Ixqas4DquPmDCdG8ECD2hPff47lPkLgvp+PPnakiAowprVxlTUEZSDWi6WlLS22UPa
         w9kH1efGX1819zdLGP2rUico2U6JyeDgH1V1dHw6j0scNhtHpepYIlDbwcdGQdEvBN+7
         VrIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nq9e5Kh1g7nUcH6hHoYLD2BDAEyO/grN3klBejPwfzM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=H8sNZBvwL6LpxWIOJxKWeOcl6+dm9tUEEm8d2tPao79jhcXv+kwRSOpyKlanfnQh2U
         r5QA91VMfik1GSTwN6tI7GnMlSqGQJYJ5TL2eaSo3cD4X2SoJHiqe01HFGsWrO6DcF99
         PXMdrbxxC4rRRgcOgPucV9274o4DIzRImp37FjL/pvFMgavFfoytdWht4zls7nq/RhR0
         nvF6DKfrqHkywlBFJsyA803F88LAzYyQPGh/I32G4eznKQG43f2kpzOIi/BYSM3kR48V
         err0zskVwm3tdF0kldVZn1AgiQADqmLzNc/gjUUnsD6PWBEhOb+U96tB8VwWiIDcjIhw
         jorA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Um1Q9Qho;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id dh10-20020a056e021f0a00b0035ab2a0b897si1225761ilb.3.2023.11.15.12.35.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:03 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKKGTF020216;
	Wed, 15 Nov 2023 20:35:00 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8cje-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:00 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKMA2V026068;
	Wed, 15 Nov 2023 20:34:59 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8cj2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:59 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIusa015453;
	Wed, 15 Nov 2023 20:34:58 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnj0qm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:58 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYtlr42074872
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:55 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EC46F2004B;
	Wed, 15 Nov 2023 20:34:54 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9A57520040;
	Wed, 15 Nov 2023 20:34:53 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:53 +0000 (GMT)
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
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH 27/32] s390/string: Add KMSAN support
Date: Wed, 15 Nov 2023 21:30:59 +0100
Message-ID: <20231115203401.2495875-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: ui8k3Y8VmDpWZcOWLfPqxXUDgEJ41dXf
X-Proofpoint-GUID: UXrJJp2IUCZ86lgkxA4hnMPl1rgWzyiC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 phishscore=0 mlxscore=0 lowpriorityscore=0 adultscore=0
 clxscore=1015 suspectscore=0 mlxlogscore=999 spamscore=0
 priorityscore=1501 bulkscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Um1Q9Qho;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/string.c        | 15 +++++++++++
 arch/s390/include/asm/string.h | 49 ++++++++++++++++++++--------------
 2 files changed, 44 insertions(+), 20 deletions(-)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index faccb33b462c..6d886c84075b 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -4,8 +4,14 @@
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
@@ -22,6 +28,15 @@ int strncmp(const char *cs, const char *ct, size_t count)
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
index 351685de53d2..94925024cb26 100644
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
@@ -74,21 +74,6 @@ void *__memset16(uint16_t *s, uint16_t v, size_t count);
 void *__memset32(uint32_t *s, uint32_t v, size_t count);
 void *__memset64(uint64_t *s, uint64_t v, size_t count);
 
-static inline void *memset16(uint16_t *s, uint16_t v, size_t count)
-{
-	return __memset16(s, v, count * sizeof(v));
-}
-
-static inline void *memset32(uint32_t *s, uint32_t v, size_t count)
-{
-	return __memset32(s, v, count * sizeof(v));
-}
-
-static inline void *memset64(uint64_t *s, uint64_t v, size_t count)
-{
-	return __memset64(s, v, count * sizeof(v));
-}
-
 #if !defined(IN_ARCH_STRING_C) && (!defined(CONFIG_FORTIFY_SOURCE) || defined(__NO_FORTIFY))
 
 #ifdef __HAVE_ARCH_MEMCHR
@@ -194,6 +179,27 @@ static inline size_t strnlen(const char * s, size_t n)
 	return end - s;
 }
 #endif
+
+#ifdef __HAVE_ARCH_MEMSET16
+static inline void *memset16(uint16_t *s, uint16_t v, size_t count)
+{
+	return __memset16(s, v, count * sizeof(v));
+}
+#endif
+
+#ifdef __HAVE_ARCH_MEMSET32
+static inline void *memset32(uint32_t *s, uint32_t v, size_t count)
+{
+	return __memset32(s, v, count * sizeof(v));
+}
+#endif
+
+#ifdef __HAVE_ARCH_MEMSET64
+static inline void *memset64(uint64_t *s, uint64_t v, size_t count)
+{
+	return __memset64(s, v, count * sizeof(v));
+}
+#endif
 #else /* IN_ARCH_STRING_C */
 void *memchr(const void * s, int c, size_t n);
 void *memscan(void *s, int c, size_t n);
@@ -201,6 +207,9 @@ char *strcat(char *dst, const char *src);
 char *strcpy(char *dst, const char *src);
 size_t strlen(const char *s);
 size_t strnlen(const char * s, size_t n);
+void *memset16(uint16_t *s, uint16_t v, size_t count);
+void *memset32(uint32_t *s, uint32_t v, size_t count);
+void *memset64(uint64_t *s, uint64_t v, size_t count);
 #endif /* !IN_ARCH_STRING_C */
 
 #endif /* __S390_STRING_H_ */
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-28-iii%40linux.ibm.com.
