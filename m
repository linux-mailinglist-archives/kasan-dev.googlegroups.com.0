Return-Path: <kasan-dev+bncBCM3H26GVIOBBA6M2WZQMGQEHTAWE3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ACB99123E2
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:41 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-44057e67d44sf255031cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969860; cv=pass;
        d=google.com; s=arc-20160816;
        b=QGmPw/YepDKCHwI6CTBe+PoF6hh3dbs+T3Bn13lHlD+qxHpgKkNA1h5rPUtnfsEPhs
         WT9GlRkQiQQxqpfz7cmsrA2IlSPypU7Flx8c/oxkFzLmFBaUvLAFQd3ow7ekA+Rx2bKS
         dlmHXYMeKKof7FrJlM1p01FvWmM1/FrcEbZuGD+1rz4Sjpz+8N1kjXjMJ4FTP0/Ibh7f
         y5gJ0GlLs9psLxNj72GuwMyiLtZaQn3inmXxAE0gPYNqBj4oPbgs3hQJeBv9DSFeSgC4
         B/f495Ud+a4QxtPvMSbP11/AVf78Wesz8R1BYgyUhADymlaCcl1EeI399wHObTRg3JtY
         YbgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PP+D40m9jNFLcCciylpE1o7KPqzRmwtD6fYaC0OEtk4=;
        fh=ROf8FsmJiWPzH1urwTiY//UPFhoH1n3EtTl6nE3y8Vk=;
        b=O1N88S1IiNd2X66amjNqt/StrEUSyTRT3hfO23Y87oJ++uT2aej2vNegrzfwgZaOI5
         W/EOKJZe13bth5l+yYyMi8p5RTI5KK1tpIaBxqoOCaykL9oZqpHnDT/+Co/xwwIaw/wr
         bCFkYt9gkPh6MbnQawltdCQFBFUa7n155QRLzy2hfaT3JrPMZGSZbnJRo/CJ4dBsHxXY
         lb37kszG65QjdBOOuHShsoXCQosJcSabBO5qAMgrqQh2weys2JCmAI/uV35uVBaasobn
         6GczNpM3ysJeUIiVlA91RwRgD6OSWeemDlC9woBuRz+QbBxMGIV4TLdHc3CRdBWQnzRp
         Hffg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aYXtoMYb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969860; x=1719574660; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PP+D40m9jNFLcCciylpE1o7KPqzRmwtD6fYaC0OEtk4=;
        b=bFT+02EQJaER64/lxZun1M0nRi/HzLJU49wTyvDim1JGkPg/t0n5ICPEvtMy5ZtoLZ
         QrZqOJSTHSKkevCIcEdw48Yf91Bp+avZb+CcK8HZIwpuhfcrDg2E0XIrdbHnm+VsAnux
         8B5LNYAeaQUS+b+6Cf5DYz8KFaIsWCxQAloF92NnIFkMR0skqZ9f1voCWhNwmpXq9P76
         qtZdZgRCRtar/motit6U9ZnRdA2ApsvRj23yOexeKae1vnuZRiRT0yR3yQQq1Sp5Xoru
         1YvanPZoOiI0h+8gPzOkbQcPA3L0DXaQ6oUUpcnDo+G43NiwDOSEWHol7821r1rYia0P
         BxTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969860; x=1719574660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PP+D40m9jNFLcCciylpE1o7KPqzRmwtD6fYaC0OEtk4=;
        b=qgzvdBisDjDWxF78kOTbe7LGMPQLjMLBvHqAYcy0rOlUV/RBbUP3MDStmBT//rR4TK
         Lrqm5PFPLllJkjIebJ6CBiDZUXYoENbhwePj+voedQe2Q4vM8pI5nK9kPWEqqFudY3yJ
         vMB25gOj/Z6v+tJlqsgTpoaobbzGiAxvCgtm8NloJsIopnjjg3IJi2rkivnLJGKGsU4i
         7tMUqOSCEYlMD5NFPBWgohEebDCYvmNM99cnWS2TNMa7HBNup0V3zLtDZRZwcTAqEsdG
         YFlSEvTW54RFJmfX4PeLPYDVchk+cyQyLVthw/cIJx+rHCSxB2RzM8fdIPOr05OpS59W
         Z6Jg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0PzH7/GO1LuFLPBbBmTpEsUdcKBhxeQkM62k044P8HoIwRWabqDWWklSCGz4alwpWFYUx6xQfN7yiOkwtgU1bPtO4ZeNliQ==
X-Gm-Message-State: AOJu0Ywd3q4mb3ZToae6ZKttXbeTjLVmI+CF+vGv1Tip1dBm6UJ4e4Ed
	uXPfoE4Z5tVCabHwCLCBp0qUlPVoTs6OQmvLBPTDx166tQINAVLe
X-Google-Smtp-Source: AGHT+IF3ldplUo0e83B/Wo3qTWB8LvAjd6GuC45eIkHXlCqA9ugLjSEnpXUgSZqObyzKGC1vlPT0+A==
X-Received: by 2002:ac8:7fce:0:b0:444:b755:2a9b with SMTP id d75a77b69052e-444c1ab56a7mr2746391cf.14.1718969860083;
        Fri, 21 Jun 2024 04:37:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1892:b0:e02:c978:fc46 with SMTP id
 3f1490d57ef6-e02d116c890ls2804874276.2.-pod-prod-03-us; Fri, 21 Jun 2024
 04:37:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvvakfedCQ0VvH6Dm66WMqSjABdeOBVajWdF/MBwBT4LjvxXkRTRgCreCsTRNN5KOT12Xx5mOpUHmbxXPXXJT35nNobUypg180pw==
X-Received: by 2002:a25:8403:0:b0:e02:b7ee:5354 with SMTP id 3f1490d57ef6-e02be138271mr8665029276.20.1718969859158;
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969859; cv=none;
        d=google.com; s=arc-20160816;
        b=hvpy0T/YFDhEyAaoO0o3Rcvw4coWkB7WwI9vuRrCA0K9hAiQWAXINZB+dKuzyr4WAE
         83pwT5dSNVchkm2DzEXukavX2QeooSsHLjx18rE1CSDY6bc5SzXjkyk0m/tukIJSNtW9
         W3e5m37e1phrlJ5nRm+UAI/mVmwMdUIZcJKoSZQwq+MzBp7DZFkgH5ufrB8d7zAsm2T+
         ErM9ps2haQtJCRN1A2LAVEjxFLtTCfNoc4FV+c5sTCGNuhoTHVmRlbb7gmaK13J9Js+c
         4zRtKI9OoOovTYAfU0Ei/aIZ13jvvCwXk86aFLirKc6P8VhuYiC8804BXGL/XHFuN75d
         SC2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=twgTpfHCjImRnKDbwT1fFnn3UXy6li/j6Qe1IMbE5zU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=w1Q9B3JQ9ZL4mVDNtFXU5QpFxAcWMkrlwwfM2qHpXL7COQuc+jgkZRL6IdYcHZ5T3s
         79jDM0Zat9icmdWDduTn4S06Gzb/jzSxUzfw8YWIxGON1fa1uIQs+BC2i9p1LWLhtOwJ
         fnwSWUeRNObkpAaITdOkdLPQAoAXmW7bzgufQLhEmvNr4fmEz1OXAyK0M6sEcjRm2M7L
         CVKrIc82miiIny71s4Ai/SN5hiaHFLoJJ0mzPeL0K5541koiKg4v3XyMj3kLcNuaGwgC
         Crzc6ntovpsIpMBikw+xVbRq4zOkqeUL8IXO5PpYXWQwMkYeVg20gn/Jy0ceL3xHjZV2
         TZrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aYXtoMYb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444c6b931a4si419641cf.5.2024.06.21.04.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LAoUL6014184;
	Fri, 21 Jun 2024 11:37:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5046c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:36 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbZ56017560;
	Fri, 21 Jun 2024 11:37:35 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t50469-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:35 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Lx4G030885;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvbw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbSjg49676548
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B14842004E;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 27B452004D;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
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
Subject: [PATCH v7 32/38] s390/string: Add KMSAN support
Date: Fri, 21 Jun 2024 13:35:16 +0200
Message-ID: <20240621113706.315500-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 3PFulpmb0GyW_EvRMDVFj7MrXJtxbV1X
X-Proofpoint-GUID: XQwQMTK_IdbRjv4p0bY5Pn4_ph8BXBKO
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 phishscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 mlxlogscore=999 suspectscore=0 mlxscore=0 adultscore=0
 bulkscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=aYXtoMYb;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-33-iii%40linux.ibm.com.
