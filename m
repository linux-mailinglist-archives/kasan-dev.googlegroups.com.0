Return-Path: <kasan-dev+bncBCM3H26GVIOBBEUA5GVQMGQEMCVBFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 63B538122FD
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:51 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-59127d45e36sf3176265eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510610; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRZe3Gh3/9cinz0xSFLhWDO/VFJcrOTrcU4krElcYWusxPJRzixVwonNeCQ6sh3XR4
         FdxzWnublGPzY+ft4BnMz5WT7GyyggiSqgpEQk13VFYPiwU+VsRFU5jG4ZJ4k1Ocv02l
         AAgW1sK0htjQJRG871sR9UjAhUXEXHqceYh9bDdeErPbtzIHYMPk0SNzybp7MOQWbpdG
         FDPAIpoTJ+uZt9xmSHJp+jQJdlvntCFq8B+Lfgxo5YphHFsQZQtMNRYmNVLnJSsyaHRx
         wXdnZHRwEZWUmWd5hpzPjaZBpcTj7AMUDqAjs0rmr9i+PWq3bGCvq2q3vcB0nLqGYPyI
         zl2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ftyR3K5npsTuh08Rv9c/R+kt6wXn4WqHg1Bm3xadop8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=CdOiTRDryuS5XBzTdw4PTK7OJ5uwCp7NPMIaQk+P3ZCZdF9LabvzKUJONfCJngiWwI
         mVAJJtvV7WJqBKhGhndxcVwf47Sgiv2noBCWG6iD++kEC5n4tNT3cy+eYJDrTLoikupI
         TqQyVpgXco91FJ4wGW51DLG8cKi44sx2ciWz8tBZtohhxVrpSWzAo2ols0RRaRll0iGn
         PMeyhHutWkDpmSkfRpSenhkUG0q7njwPS2zcbmSBZecSxx3saeBLerj9BFCyDMIQW108
         SXm400YLKyxBRyEptU11zU4KI7uwVN0pFU3CHtrcrbdnBBC+SkKX0DIq9M1ugX/bDXnd
         GvFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Py1mP98b;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510610; x=1703115410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ftyR3K5npsTuh08Rv9c/R+kt6wXn4WqHg1Bm3xadop8=;
        b=LQMFiEfO9ogYpHpZjJJ/XStSIKdt3ewOMwRkz19PqJJpxbtAyNtFAxlHMEb90ZgIQd
         olYVZNiwIa8JVnW52CIVrJoQOm8dIZAtkOBGiwKcmdp704JS1kH03yCFI3WQGt8ElWHB
         NzbUyruj3yKaJlewnJLivnDPyr7mL9IA1mEp05a9/1fIjY3qqn9Z1zZZ1dh5tHAr9YSs
         f+gcrsiJmtK3QucGI7/ittlct8oWw5GD9XV440cwmRD8ZeBwVPHteCrNvE+wNpDQg+el
         /hHg4EgBxbyTVgt7Vp5xQyPi1kZD0RDnL2K7zblWE0ZIj9MwhPlkcleTk71xBgTQdS4p
         N3/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510610; x=1703115410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ftyR3K5npsTuh08Rv9c/R+kt6wXn4WqHg1Bm3xadop8=;
        b=t5SYuzxXU2mmpklFuKsSrkpTbHQXrGt2njddiCt96M4emptfvbiAANefBsIqhhMpqk
         IhTnJm3lcKXcFL7peJ8sM1k+SIGCgBBPoWLBJj40G6K+5dL6t1hQMK/P+FMiOW0UgI6o
         o60KrnzNIi9iwXfRm2K5vfrJiEUpu55td20BCA6r3F/92gzPrpKA1Mkt7bq5OC4Vfao2
         aJ/7rL6Il/Pc0oqtd6rI7gaVRwsZl3iTxAhSQ+qrycKWcPg7wo69C+dkN6Cflu65C8qy
         FlexK447KrB8Dsw8qq4aprxoNSR7cC8vc4bSl0LdAYWKL3zc7GU9siO8Ni6borW9n3uB
         JEOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxucBJQJw1TUrvb88HCluCQv4yx0BtK149znSxdWdMjKhQIzvmN
	yBqsrsMIwd+sYKQWGoGEPrQ=
X-Google-Smtp-Source: AGHT+IEWr4V4F1c3dB0by3UM23FUqq9ci9GN01c0y1cX+lDNvrBgAUPhE/kR1sNaQJgTt1oIMZCEbA==
X-Received: by 2002:a05:6820:1ac8:b0:58d:6ea3:8fc with SMTP id bu8-20020a0568201ac800b0058d6ea308fcmr8689521oob.2.1702510610132;
        Wed, 13 Dec 2023 15:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1caa:b0:58a:74b0:573c with SMTP id
 ct42-20020a0568201caa00b0058a74b0573cls1147557oob.1.-pod-prod-05-us; Wed, 13
 Dec 2023 15:36:49 -0800 (PST)
X-Received: by 2002:a9d:6849:0:b0:6d9:d902:44f1 with SMTP id c9-20020a9d6849000000b006d9d90244f1mr9794185oto.37.1702510609318;
        Wed, 13 Dec 2023 15:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510609; cv=none;
        d=google.com; s=arc-20160816;
        b=DQEjMsAkaU6/t5aZqsDgJByGpplTKYHN74GY8flC7gqIX57NmD/h6ODVUQsNC+01Fy
         xUXUub32uDQkgXwjdtni+c2fQ50BGjj60PY9IZFho5+1Ov2I5cmwBef9kRJPoGELk+9r
         DVorejX6WukpNOJWjiF+8aPhKa1QluiJCWX6O3jXxiOmQ5ryY5mlCJA5rWk7sFQegp5h
         xJEjQd8jquOx8fBfPqheCt0o+T+jCkewZMOgq4kUtna/LcSUfzLLbwxTwQ0r+SqD0YlU
         IurSsCqJPCk9hkKUN3I9DlOKJF1Fn5rBSPl6/btcYSMiRaZqDnnZ3IUcopCS2rP2f+Rp
         FYtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rlCQsZ3FaFOShLden0tv6ATBRD4EWRplBBAXRzxDZSY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ggZuv9vfPmtkhsokdcH108KGCXwKkAXTCw8KLk72A3hie9zE9Ifd/+DnzCxdP9mn9w
         d2b8LDmBC2mu9wQ/zKiFlaClbBl035Xa39xmASMkx08xAm7FxhVWDU4iWNzCe/hBFdmH
         GIlZr7oW+3YsmM+LDkjl6frNzbhr3VnRXggZCCdVb5zdumWSwTVVzhLk0JAAGXKUA5yG
         veoQQS488mvJc+2R3BO0Avco2coZIvFnEVEPLqCzdJDCsIyrs1mlZvrDZPQKszGJs0b6
         ymYS9y7xBvwAuVilmKa3qFaam6dye/ewQLbH72B1RW0TCRskmfr64QbSIII57phURnaf
         bocg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Py1mP98b;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x24-20020aa793b8000000b006ce77f21362si810124pff.5.2023.12.13.15.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKbIKV023765;
	Wed, 13 Dec 2023 23:36:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0wj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:44 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDN1IcT028789;
	Wed, 13 Dec 2023 23:36:43 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0w9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:43 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKnidh008455;
	Wed, 13 Dec 2023 23:36:42 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtmvm9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:42 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNadSt45220118
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:39 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8151520040;
	Wed, 13 Dec 2023 23:36:39 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 111A120043;
	Wed, 13 Dec 2023 23:36:38 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:37 +0000 (GMT)
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
Subject: [PATCH v3 19/34] s390: Turn off KMSAN for boot, vdso and purgatory
Date: Thu, 14 Dec 2023 00:24:39 +0100
Message-ID: <20231213233605.661251-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: PLExDOrLrxMWM3bk6s7GZrTHSzR8vYyL
X-Proofpoint-ORIG-GUID: Fk9-MI15mlYrzZBW50f87CcP6jmktpZ6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 impostorscore=0 clxscore=1015 adultscore=0 phishscore=0
 mlxscore=0 bulkscore=0 suspectscore=0 spamscore=0 mlxlogscore=736
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Py1mP98b;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-20-iii%40linux.ibm.com.
