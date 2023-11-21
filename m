Return-Path: <kasan-dev+bncBCM3H26GVIOBBLOU6SVAMGQEJMVZKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 483D57F38EB
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:07:42 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-d9a541b720asf7741481276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:07:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604461; cv=pass;
        d=google.com; s=arc-20160816;
        b=fHr5aYR2Xxh3JhKgoOx6mJrCqhXpVEsVULlBh/V5y9zFAxoMw8svxvvh4FO9DlIDns
         YL0SHPtsI6OC8Gfs9FCOZycIamkE0KN60xsCg6fwqpjRo+8f7U0+SPytyjq7KxSIzX2h
         InfBD2Pbb8bpvK2Lh82gZmgsvPvFPu8UYCCl1Jq09CnV2Qq6Aw1imD0I9WdYgmo1GFII
         VlHEWCShoW4pFVhKynDYZuTiWfPB8X3a6eqceX40TCGBCPrnakg/F7NoZBwSz8GoWH/a
         ruGVPnqh7hh8rw3ow8OJk4H2uocmBCvYc4DSSNSNwojndpjT8FRhQ4hD45d+Xhe2Th2S
         Wj+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0Axlot5ZsRI4YCvREIbb4tnTefgeyqBIR54mZTobKdE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Ak9farRTzqTzBV3uYNxmqi2WiFadtYWOfR3nyQnMw9HoflaCQlcUfFDF4E+xiW0iEy
         KXRbcSVMEhregapQKS/yfuT/THIb8DL8TYXqQwvy9LVj0TfB+8QECUdNxDgQKil1Xr2y
         Hd0FqHZKxFVHTz3Uar9vFYzFJjncR9/cYqtXBAAsqGijSyzrBXRhjkieX1tFyAxDm6W7
         qkjr6gHkMLuETzabik2yX+gPvoHx7nA2ytH3+mXGEqBqJCCr7ds7/Ii9YTmH9c2mUCtC
         XTrj9hlv2lXm9NSHimlPdYuxZC8KhdHNO9G6ORTW/PcSgTUyR4oxlInRfqR/7boHqfTd
         9g2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EajBtHgX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604461; x=1701209261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0Axlot5ZsRI4YCvREIbb4tnTefgeyqBIR54mZTobKdE=;
        b=bwoGcF+bhLvtuqHmE0e7ceR3sRzevqaztQzEh+BPOsLnddi8W8qJWlpNJ0f+mMI1bI
         eK0IDmJOGbPe/3Tp8gjbRUDkU3KO4I+I5cpOsdikAOFNZbS/FIwgtj1AWxbtmgyLgnfs
         Me+ptPi+mIErNjul3GNzoKMQCbO3tjoSZrHtfqQHyJFoVpZOp6/0yKr2aCHBRt4/NrJn
         cv3Kz+4hnzkwXqn02rnKOcEzyhTLjyC1pJ2SQOTwXr0/TabU8Od4kVzvnayK3Dw4vIOJ
         Oaqq1KgLA0LM6RrbtqRyZaMfiYQhmAume9NZ2uue/ABV+oreGzXxm0P6oT6eoX1/cn3q
         C00g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604461; x=1701209261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0Axlot5ZsRI4YCvREIbb4tnTefgeyqBIR54mZTobKdE=;
        b=YdlGkTgDbPQEaJ2WR0qBBYqf3AGHUt8u5GQSMiEKKyk1DjkRX2q+ke83aAOy6qwff3
         qwewO7jYDB7f9YLnl5VycYpfsw0k9SPLc96/o0hfcun4GmN5EA6yzGeyR+6shjpzCnJC
         kOLdtMIGEknbKepR17bfDUrialLuJ9kyG90oh2pk5qJcN3H4PWH0SSKuX76JxIl9xMTT
         NiHDGLpsxLAvjNU/S3raLachWG1u48WYm0c9eHSpv4WkKmkP6eAv+mjFYdG3BTpBKgeK
         TYhvwlFOR8vLHf4thnUfzMOmvXCvOJNGTJyuye0kM8HRiyN/EYLBGA5P3aE56e3CqZMa
         g0Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx/4zBhmlzQsb40Kn6WVdpH64VWRAiT1SrchoOgXwXsyl6X/J9p
	I5Yye28BRuQYI+HGlw2KuFg=
X-Google-Smtp-Source: AGHT+IHBuUZM/oPjcEZfJjOwRK/u69Nf6kG/DkOX0+TyNVPQc61S9x2Qv8/gwnmMt4CutfPjw/zFWg==
X-Received: by 2002:a25:ae0b:0:b0:daf:81e5:d2f9 with SMTP id a11-20020a25ae0b000000b00daf81e5d2f9mr336006ybj.5.1700604461149;
        Tue, 21 Nov 2023 14:07:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7614:0:b0:da0:33b3:b1b5 with SMTP id r20-20020a257614000000b00da033b3b1b5ls540777ybc.0.-pod-prod-08-us;
 Tue, 21 Nov 2023 14:07:40 -0800 (PST)
X-Received: by 2002:a25:2317:0:b0:da0:cbae:34ba with SMTP id j23-20020a252317000000b00da0cbae34bamr352572ybj.33.1700604460325;
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604460; cv=none;
        d=google.com; s=arc-20160816;
        b=vkGouKZYikyZn9Yuo1xyjSQPc+7NaqBtlzv1euPLr8JaQd8CNY0aW9jX3LnmeJBzkm
         YWCbS/MvbRQ2E9Cc5pGo/L/0q32DXluKplX95YaMVztGmXMWpfK+EfwvvbJN1kB+OikC
         sz4/pNsKnCSde8dlDmoCrclGTwXyjnyQCwbgm7n/qjjePcPUOHcyCGPWZiNvd869p+wu
         2pzexzKu1fyat7/q2yw8nI7mgz7R5Uth316Bmdwxe61HSMomuj6XFxuzY2hfVIRt0ldP
         40Fjp+S6+3rCPU0uVezb5IlpEEjNJ3HPMUhAXP45VU6M38yR/vIU+XH39AwdsKucEVTC
         L7Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yCM6nKo/pJqwZmAlXIYbIKppz1uiSIrRp1Z3Kg1KovA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rQiOJt7tImGswmq6YqNTFwvbdsWW6d2J55r00JjqdCaF4N2hfZEvzfd8JHG+QnMdxt
         XtuEK17u4Gnd4jtbJw/FECchQ1XdMJ1dXn/lS/PQg6D0YnuZqdIf47xwbSTCIW5Vho2S
         bDgzxRUmJ4jv7yBgNeshnHV60WIG6uwpxRtvSL4xTBaSTwONKwOg4+j3/mSBjeRaF0Xy
         8FuVZQH3kxMzMpoVSKJ9zbCvGDm3dV3MxSd13FyompCIJmcZ3zwPpjYtvsIoGnam7VBt
         o813IUpo6ts84N0MUnUTpB9uKPoO2186HCxjiQHaBVGQpX0dRLSojxk0elUvHqzsQMg1
         bRYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EajBtHgX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x139-20020a25e091000000b00d9caa2a9dcasi389017ybg.3.2023.11.21.14.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLgklN032320;
	Tue, 21 Nov 2023 22:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8myj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:35 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLjHmm007105;
	Tue, 21 Nov 2023 22:07:35 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8mwp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:35 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLngjk007115;
	Tue, 21 Nov 2023 22:02:45 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236hp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:45 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2hRn12845594
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:43 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E60042005A;
	Tue, 21 Nov 2023 22:02:42 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7939B20063;
	Tue, 21 Nov 2023 22:02:41 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:41 +0000 (GMT)
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
Subject: [PATCH v2 21/33] s390: Turn off KMSAN for boot, vdso and purgatory
Date: Tue, 21 Nov 2023 23:01:15 +0100
Message-ID: <20231121220155.1217090-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: xWRTiXwSYw1FLRrlcw5nESB78XrORh0o
X-Proofpoint-ORIG-GUID: C2-foF7xP9dmTBdBoh93zV1R1Je1g8y7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=751 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EajBtHgX;       spf=pass (google.com:
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

All other sanitizers are disabled for these components as well.
While at it, add a comment to boot and purgatory.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile          | 2 ++
 arch/s390/kernel/vdso32/Makefile | 3 ++-
 arch/s390/kernel/vdso64/Makefile | 3 ++-
 arch/s390/purgatory/Makefile     | 2 ++
 4 files changed, 8 insertions(+), 2 deletions(-)

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index c7c81e5f9218..fb10fcd21221 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
diff --git a/arch/s390/kernel/vdso32/Makefile b/arch/s390/kernel/vdso32/Makefile
index caec7db6f966..7cbec6b0b11f 100644
--- a/arch/s390/kernel/vdso32/Makefile
+++ b/arch/s390/kernel/vdso32/Makefile
@@ -32,11 +32,12 @@ obj-y += vdso32_wrapper.o
 targets += vdso32.lds
 CPPFLAGS_vdso32.lds += -P -C -U$(ARCH)
 
-# Disable gcov profiling, ubsan and kasan for VDSO code
+# Disable gcov profiling, ubsan, kasan and kmsan for VDSO code
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 # Force dependency (incbin is bad)
 $(obj)/vdso32_wrapper.o : $(obj)/vdso32.so
diff --git a/arch/s390/kernel/vdso64/Makefile b/arch/s390/kernel/vdso64/Makefile
index e3c9085f8fa7..6f3252712f64 100644
--- a/arch/s390/kernel/vdso64/Makefile
+++ b/arch/s390/kernel/vdso64/Makefile
@@ -36,11 +36,12 @@ obj-y += vdso64_wrapper.o
 targets += vdso64.lds
 CPPFLAGS_vdso64.lds += -P -C -U$(ARCH)
 
-# Disable gcov profiling, ubsan and kasan for VDSO code
+# Disable gcov profiling, ubsan, kasan and kmsan for VDSO code
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 # Force dependency (incbin is bad)
 $(obj)/vdso64_wrapper.o : $(obj)/vdso64.so
diff --git a/arch/s390/purgatory/Makefile b/arch/s390/purgatory/Makefile
index 4e930f566878..4e421914e50f 100644
--- a/arch/s390/purgatory/Makefile
+++ b/arch/s390/purgatory/Makefile
@@ -15,11 +15,13 @@ CFLAGS_sha256.o := -D__DISABLE_EXPORTS -D__NO_FORTIFY
 $(obj)/mem.o: $(srctree)/arch/s390/lib/mem.S FORCE
 	$(call if_changed_rule,as_o_S)
 
+# Tooling runtimes are unavailable and cannot be linked for purgatory code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_CFLAGS := -fno-strict-aliasing -Wall -Wstrict-prototypes
 KBUILD_CFLAGS += -Wno-pointer-sign -Wno-sign-compare
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-22-iii%40linux.ibm.com.
