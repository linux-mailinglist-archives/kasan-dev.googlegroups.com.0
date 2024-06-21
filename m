Return-Path: <kasan-dev+bncBCM3H26GVIOBBXMR2OZQMGQEEVCQZQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74AD7911763
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:11 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2c79f32200asf1609249a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929630; cv=pass;
        d=google.com; s=arc-20160816;
        b=bvHf02PDRARcb4ff2bDuFeVe1Pyq91HfcyLZ+MA2Sy1qUwEZUVGV0nVS23tEjuQ0WI
         N+NM4yMhCYpZLP3olrkti0EHBhqxooPM1HMaFcWT4BIj5Dy6DxdZvO+RhaK67JZzUanR
         +YOXsUKnCoejBRUt56yQu/Kw/H/Ga4+1+mlgTTwYbR+MOqNgMIkw022B9upiVfpeYXaD
         +Z7IJUSNSN+A0EPJp2RxzkuEDlAixywgq/KQe8ypYGo4TsSRppvrp+Uu9nQY5Py+zQJ7
         XRgwZcPJj4KF85sc41jVafft/TE9n7qYTL8mctjIboP7yByLDmSG5q9FIu6fU/1XkZGf
         TXWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V/IGS5E6iCNpbZeoOG4So8OJqXXArbL67WuxljenAOY=;
        fh=Pd+1EiIp5L37sBIVCCiTAFwi0P0fEcuT47vQqgxoCWw=;
        b=C6KUArb0VI3eG8vCDh62IG4F9CKB/bYebObihH6rq5YoPz05Jli+ln9QynWs1IKzF1
         INlLuzNqHEy30+C/NWesxJgv/c4y5+eKSeLWbivD8R0T+1PV/qJi8mgssNrDi+OJux5H
         EWYxyDJpv0Mlv+p4bX8sacsh+x7eJ8QTfatsvJJPppGWVz803zvmfssn5Z+iuhwYPI+c
         1P6HA6/Gb5EJ/jdkdO8YECQfdOVvIVFm+BCO5SQBI2yQyfbfLIWCm5pryP2J3lEBt4ub
         DPBAHgUYaXk4aZEZ2S5zt/gkuQm0Iy+kYaNCNrUWsG7dInjMBwsjD//k/+5cZLZAQKp5
         o9Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IQLYQcBZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929630; x=1719534430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V/IGS5E6iCNpbZeoOG4So8OJqXXArbL67WuxljenAOY=;
        b=bg9mzvE1Cntiz/QWC+YzhZxg1wnxmHibPAUUJAJ74MpSgcV+CKOF7+pODcAKwOTOym
         wy/HLzja1ZstfQpOCcRzbZiEZ2vOkJpwK8Wrtau3R296OLzbrvi9fmxSth5SeCqzH6DO
         S4j5A/TZJ7STu8VrveIpc76NRN7arbrft/LfxasfV6YqqdMPwQnobLR6X0Jkv3jWKAvW
         WdEQ14H1ub8PnVX+vgn+ErSE5vG8kmrNw9tmtKB3wWbkpu3YDRYhWIC38ZktNTSJbsrw
         HWQEZy3BkQc0Wo8aDxtMv5YvqMRv/l9w9jYDTjeq0Dh6vUc27aZ30TMKwHT34s4S6IUs
         C/1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929630; x=1719534430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=V/IGS5E6iCNpbZeoOG4So8OJqXXArbL67WuxljenAOY=;
        b=hezmQDd6L5c1krcnQodeO9UC4NrIawUp6jgMcaSRaz+S11alLl7vXe9iOhYFsAfW/2
         fgHIgSYVCfgVH0SNQf5SIv/iwnsNaY+bpXJgh81Higk1JN77lc6UAZL1dD7odx5L8Lqe
         zR8s1TQVptBdWuDYhQXERk9d+3it4pnYt/CNazRN2+UvmJTc54VRhkJqNNDDhQE38Pxu
         bssWRaaRAG49AyMvV2I7+3CPKHUtUhvbjLdxa+aykEuf3DpmjT0RB8UkuzEml36/I4Wk
         oAGJPICxzeij4/kAiY8hTQZ24EZwe1wdOPX1n5GE0fKpj3ezpgSmbhIkjK/8vnxYQ99f
         riWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1lbRW/hOatnskt2bmoe8zOmBNFJWneQpFEgJ8ji9tHuyEBCX3tkDGfJQHSK5GZU3QHy0eGKQCbHQKtU+ikeZmj4G+8afKiQ==
X-Gm-Message-State: AOJu0Yze8oOtsN/l45hg0B04MbKmaNj7asoDCdnpoqTqpNyVGDQmnSJ4
	3NFhCUjv5k6qY5GZPA1Sak4uH1GdTjvYdyghbXUZuIR2VVKZor+F
X-Google-Smtp-Source: AGHT+IHqSmdWtRcgxtakleaULq6DKN3NAc1kWKGL2cVuMCQ0ShQI4QP9gz0M9nox7aOrD3//2hStAg==
X-Received: by 2002:a17:90a:db8a:b0:2c2:f2d6:60d4 with SMTP id 98e67ed59e1d1-2c7b57f3fc3mr6922609a91.8.1718929629977;
        Thu, 20 Jun 2024 17:27:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:224d:b0:2c5:128e:240 with SMTP id
 98e67ed59e1d1-2c7dfefbd1dls985844a91.2.-pod-prod-06-us; Thu, 20 Jun 2024
 17:27:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU06lo4acWxloNeJiipxEg3E9DkDgWLKJ34ykMxQmaoecO5stASR4Nn6S0G+dCpWoixr56zqN6Uj4w8GAdjEx6yhiK/KbLmbczrHw==
X-Received: by 2002:a05:6a00:22d3:b0:702:65de:19e5 with SMTP id d2e1a72fcca58-70629cf7ea3mr8519677b3a.33.1718929628901;
        Thu, 20 Jun 2024 17:27:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929628; cv=none;
        d=google.com; s=arc-20160816;
        b=Eu9vknYt7JRuDHLjcHS1SohXR/LpvMTvnvpYAPgRn5UVfxZXAMhjSfshzbakXdiX6T
         vpmIwY+EAF9sa29kU7OJQ+Fduuy5aEUEaj3+1/F8w/Hrd7a8UXZVX8Rxt5OqTE1wHZmx
         7ht7l75RO2OFdjhh6ieRSLMIgq51A/lba6pQWdbJpQeZYI1aq4+pALtc7xih0ACjj6wB
         2DQoWBU8vOnD+ktweW/a6HnnGXcOG8oggD16SxYVHgEE39uC2ucnMY7eFOShAIRRYMHI
         W9ynqNbOkpx23KlBtjsmADHKsIr0bi8iYhbvjFqthAP+kDiqetzuI7+4l+6g3KTRmkPg
         sXRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+zoFJVlk37wQaOMfwbNCgteXo249s6T95ikp3xQJB1k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=N+/bl9BnZwCEfX9NJFIG/BVSbKPRMYy4i310gUHwpT17gxS5nuJ/1iZdbIUwyrhfvW
         zwvpUBgRuGqI8GAkR4SUaVOW1D4IToCnr5gzgcdKTuUA70LBL0q3N1tHFvgB0bfx+WXb
         QwWL4/N0gHQcjsm8o8DLNNrcADhGvQ65EE9iC7A99e4hqqVN40Rka+58oKnX6upLV579
         hqwVs3MUEgZPs72jOH03NYqPjZ5X/EDq2OpmtZmxAGKNJJm4iULRLobSz4dj2ISml3mJ
         ZzQZX4Koc867f44hpUovG7sRMkydmd4IQ99yPSmyyK1jwIlUZgjOjQD27ncNTP9+uHPr
         YHrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IQLYQcBZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70651194b50si42565b3a.2.2024.06.20.17.27.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0Qnua007904;
	Fri, 21 Jun 2024 00:27:05 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:04 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R3AH008332;
	Fri, 21 Jun 2024 00:27:04 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:03 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0PCOr019980;
	Fri, 21 Jun 2024 00:27:02 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujp01-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:02 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QuN328836416
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:58 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B1C8D2004D;
	Fri, 21 Jun 2024 00:26:56 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 91A1120043;
	Fri, 21 Jun 2024 00:26:55 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:55 +0000 (GMT)
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
Subject: [PATCH v6 30/39] s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
Date: Fri, 21 Jun 2024 02:25:04 +0200
Message-ID: <20240621002616.40684-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: mJfVanZcD3aql1zd3WEmKagMvpX0kn1c
X-Proofpoint-ORIG-GUID: NFgq7-uLXQwiRiHtpJGf6Y1zeU6AIr_p
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=999 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IQLYQcBZ;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-31-iii%40linux.ibm.com.
