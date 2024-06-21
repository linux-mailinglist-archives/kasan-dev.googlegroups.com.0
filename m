Return-Path: <kasan-dev+bncBCM3H26GVIOBBBOM2WZQMGQEWGL3B4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id BCF199123E4
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:42 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c7a6ce23c2sf1994818a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969861; cv=pass;
        d=google.com; s=arc-20160816;
        b=n9SIaWrjk9y9hrWPJoW1PXnAhbiKpT9VSPq1w+Yie0undCK7skONXsqEtwjbKpEN/R
         ihGsseNEd9MDCoY8Wybwupi+HRVxDERkIK35tTKNb2j8CbBU0CU5tlc/3SUpVC8ZCMfW
         mLbWeRIpXhHzVxWwUf7dvaUBP6C3eSICtgUdNmFrxnl8/3ZUFEXI0cMOlHWbYMxiiOqx
         xW3mWAUw7AslD073V6PPI+Ftg1MQrlsZbh1x82KG3HmQLMF5PnLONeeSzTDBWUZ2L35s
         PTqvWPkeomZqMlCL/wsk63rowhEpZ2y7ZPwoipx3J+L1F0qRU40flukml/a/aZf3+vUu
         osyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8Q6x9F85xTjY3umU4skm6r31QfiAe1pB4sW7kwa8DKY=;
        fh=roxqg8pPYqb+e9qTI5zb8CuXv4hFHbxLZbyKOOldn14=;
        b=UmhtI7MqMx9yGOFlnAtqM1AiwpKniVRbyLA1CvLJaJZgBfLViHwaKAf5hmGr7dL/DS
         lSycPPfc8tVjHcZLMQsyzjQDrUuQFS2qRz4aPvTmh+XiCHOUOxS0VAPZgtAPuPcQ7JqQ
         bXzWmPqmK2pOfUCXzdV2HYPFJj4NGTbiu8dMNGGFsBiEUR2MdmgBemqqJRydwapqkTIy
         MRO1w9Mo3DUV94flizePU+/MuhlaL9nzeZ1DuSUI3b9IrLdJCfx/XSs62FltBjlB6Se9
         V7qDstooKKzj37fFcsui040Hbj1+EpuJp067RlBW0izAvbLoSpi/eE6oPda+YIKTT2Xe
         yoHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UCF4KT0a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969861; x=1719574661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8Q6x9F85xTjY3umU4skm6r31QfiAe1pB4sW7kwa8DKY=;
        b=WYJMVM6/I1ad0j9bSxPAVlb/Z5Rr78sRFX5QOcXr9P6i5glWwFLfBBvkOCK5rjp6Qc
         qnrUMT9TFAIgtUMQxAXGwguHH2/hGiQ89Q6Q3+R9IewSb2PMG3vmXs9gWTP7epFj2TZZ
         mQKCF3MN8HVhOZhkGJeWjfyBwXuIiKHUAM2NSwQyFc1zIYgjGgcM5NIg2dTB1LPfGeYy
         pJtlaTgo8Y9olz2BpdS4345CTh2/jyGVpDWf7x/yQpAcsZ4NYBEIgO5O+8x6hEm/tnm5
         RD9c4R5ItQu9wtzpWIJNaudQb8I9gJ8Qvz+DKzd7hReRWqolZetEQB0D1Q60JDrUxwea
         QMAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969861; x=1719574661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8Q6x9F85xTjY3umU4skm6r31QfiAe1pB4sW7kwa8DKY=;
        b=ShoNttEWh1fUYLMIiE/BJfW86BzUsN0abYFEc0HUNJ0cPf0oMFrzXtBEjxVXW3W3OP
         1l0aPCFFNoYl9jFECTqe+ayp718cRffz5UExYfFX7glp+IlOW/So98zuF2lgGEtwPY6B
         Y+nMc0CaKIAR5rDmrkBk7F0QbTakCdmljwDKm7/Hslq8IliO+iuCUIH47iHKuxefZrb3
         JUbfpiI1lMzb2aRktpYno2HVEjnGPl1Dt0gzDSG1ocXhKIGyEXSdhkfOwvePw4NjgjLl
         +U/OPGbfHqH5dS/yAYutuzn4OBWHtvcAQU6IMjyLOl9/qZ/YIASirVNB5b5jnhY6tLsW
         JMdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkI8xF9plz669Sz3zshzkYmhGZhec8uUSnvEcftKYgyRrDELRxrx9VwYjLqlIgMfA+BW68E8mQnlleJ36KROHD4Br4fOCA3Q==
X-Gm-Message-State: AOJu0YySjytMG/XrZYUGInY1W+Xge5ejnOt7rDMd1H1n3VmrhkxVJXXb
	wFrKaV/MpHWxn85PyrmwR5kAgR7XuMBQHFi0GRckoj6JHroSUMj7
X-Google-Smtp-Source: AGHT+IHplXsmvcpNlkGsvHBkNZVhoC4SwhGDo44d3gboCbhpWwMB9xb2cQyAfjf3AgLGDJ8xTQ5k+g==
X-Received: by 2002:a17:90a:eb88:b0:2c8:a8e:c1cd with SMTP id 98e67ed59e1d1-2c80a8ec214mr3237440a91.11.1718969861293;
        Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9ae:b0:2c4:c051:4b77 with SMTP id
 98e67ed59e1d1-2c7dfee90d5ls1081454a91.2.-pod-prod-09-us; Fri, 21 Jun 2024
 04:37:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgIG6qnLDJGsy9CXYAWLsFnSmVg4mccBQaxh+MDinXgYUYImE67yhRLzkJKnU4Cr+cY0CuNRty9DuKUgneX88b3tLtA1q8jz8+9g==
X-Received: by 2002:a17:90a:c70e:b0:2c3:1234:8bbb with SMTP id 98e67ed59e1d1-2c7b5d7bfaamr8181100a91.38.1718969859876;
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969859; cv=none;
        d=google.com; s=arc-20160816;
        b=vxyLpni+xc+AyCfrkMOH9k/108i2geYTpSQ/qgqAgSGkV+FNAO02DjgXuEUJ22iKmU
         RY1zEpPBnApk6WLecNSFFSbg5bImQ6L7ojmlfewgtXFHSDi/+Lz+sCkjw58pS7F9kpqm
         U2dQZd3I6ig534XTcoBx/MCxfTYvdeEa5Hkr2CFECH7LBp42QiPLSNgVkyU3s+JoaIQZ
         XUDtu2C+GtyFWEOdO+Ad1mvxB7yXpepgmSV4cSFFzp2meWDpiS65UwIE4xuOl0Iumkj4
         EBLztGBzTWzW+juxpOnfbwVyCm6fG96FaJTYBkgH3xv6TgTRKuXEm/y+cudDDSfAzNOk
         yx4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+zoFJVlk37wQaOMfwbNCgteXo249s6T95ikp3xQJB1k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=QlmbuxukfhTyVCK42qZYvnr17ZyO4FSEJS5cv4w3ccttA/DrBxLnvgzsTACv2E+Wp3
         jdKP/KBFzpggMOpOtx4L83lLkKRMU6e2EsAfpDHeW1/iOnDeUPYlpl8MUKE5fS/cugpP
         W8/OwhOX+hVzIG5qSNgvNVHF+Ap37EM0+V2xj8LPMktxuubPUen3kgGGBzy4zYrxGkG0
         kRPyGBSStgid/d9pR5v6WJRifyswbWUTFleaLMVvuscKgB9AhCtQTnXvdvzqXjGAgnuE
         cfkyvyZWFif8vmVxZgo+V3S/tRSUJOrZO7L7N5fX8qqh0hZfyGZUdY+3NJbJ6iaR1YUt
         P8mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UCF4KT0a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738c1d4bbsi514796a91.1.2024.06.21.04.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBT6s9029206;
	Fri, 21 Jun 2024 11:37:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080n2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbJEk008790;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080mv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Ef4J032346;
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv68-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbRa055378336
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 77EDA2005A;
	Fri, 21 Jun 2024 11:37:27 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E1B712004B;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
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
Subject: [PATCH v7 30/38] s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
Date: Fri, 21 Jun 2024 13:35:14 +0200
Message-ID: <20240621113706.315500-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Cjz3AGYCfNKeIGjA23EoGVN2dv6kxTTF
X-Proofpoint-ORIG-GUID: 4cxJA7IRQkUmZHTUVyn6E6n_yLN24h_e
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 suspectscore=0 priorityscore=1501 spamscore=0 malwarescore=0 clxscore=1015
 impostorscore=0 phishscore=0 mlxlogscore=999 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UCF4KT0a;       spf=pass (google.com:
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

Lockdep generates the following false positives with KMSAN on s390x:

[    6.063666] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
[         ...]
[    6.577050] Call Trace:
[    6.619637]  [<000000000690d2de>] check_flags+0x1fe/0x210
[    6.665411] ([<000000000690d2da>] check_flags+0x1fa/0x210)
[    6.707478]  [<00000000006cec1a>] lock_acquire+0x2ca/0xce0
[    6.749959]  [<00000000069820ea>] _raw_spin_lock_irqsave+0xea/0x190
[    6.794912]  [<00000000041fc988>] __stack_depot_save+0x218/0x5b0
[    6.838420]  [<000000000197affe>] __msan_poison_alloca+0xfe/0x1a0
[    6.882985]  [<0000000007c5827c>] start_kernel+0x70c/0xd50
[    6.927454]  [<0000000000100036>] startup_continue+0x36/0x40

Between trace_hardirqs_on() and `stosm __mask, 3` lockdep thinks that
interrupts are on, but on the CPU they are still off. KMSAN
instrumentation takes spinlocks, giving lockdep a chance to see and
complain about this discrepancy.

KMSAN instrumentation is inserted in order to poison the __mask
variable. Disable instrumentation in the respective functions. They are
very small and it's easy to see that no important metadata updates are
lost because of this.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/irqflags.h | 17 ++++++++++++++---
 drivers/s390/char/sclp.c         |  2 +-
 2 files changed, 15 insertions(+), 4 deletions(-)

diff --git a/arch/s390/include/asm/irqflags.h b/arch/s390/include/asm/irqflags.h
index 02427b205c11..bcab456dfb80 100644
--- a/arch/s390/include/asm/irqflags.h
+++ b/arch/s390/include/asm/irqflags.h
@@ -37,12 +37,18 @@ static __always_inline void __arch_local_irq_ssm(unsigned long flags)
 	asm volatile("ssm   %0" : : "Q" (flags) : "memory");
 }
 
-static __always_inline unsigned long arch_local_save_flags(void)
+#ifdef CONFIG_KMSAN
+#define arch_local_irq_attributes noinline notrace __no_sanitize_memory __maybe_unused
+#else
+#define arch_local_irq_attributes __always_inline
+#endif
+
+static arch_local_irq_attributes unsigned long arch_local_save_flags(void)
 {
 	return __arch_local_irq_stnsm(0xff);
 }
 
-static __always_inline unsigned long arch_local_irq_save(void)
+static arch_local_irq_attributes unsigned long arch_local_irq_save(void)
 {
 	return __arch_local_irq_stnsm(0xfc);
 }
@@ -52,7 +58,12 @@ static __always_inline void arch_local_irq_disable(void)
 	arch_local_irq_save();
 }
 
-static __always_inline void arch_local_irq_enable(void)
+static arch_local_irq_attributes void arch_local_irq_enable_external(void)
+{
+	__arch_local_irq_stosm(0x01);
+}
+
+static arch_local_irq_attributes void arch_local_irq_enable(void)
 {
 	__arch_local_irq_stosm(0x03);
 }
diff --git a/drivers/s390/char/sclp.c b/drivers/s390/char/sclp.c
index d53ee34d398f..fb1d9949adca 100644
--- a/drivers/s390/char/sclp.c
+++ b/drivers/s390/char/sclp.c
@@ -736,7 +736,7 @@ sclp_sync_wait(void)
 	cr0_sync.val = cr0.val & ~CR0_IRQ_SUBCLASS_MASK;
 	cr0_sync.val |= 1UL << (63 - 54);
 	local_ctl_load(0, &cr0_sync);
-	__arch_local_irq_stosm(0x01);
+	arch_local_irq_enable_external();
 	/* Loop until driver state indicates finished request */
 	while (sclp_running_state != sclp_running_state_idle) {
 		/* Check for expired request timer */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-31-iii%40linux.ibm.com.
