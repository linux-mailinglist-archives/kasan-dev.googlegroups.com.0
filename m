Return-Path: <kasan-dev+bncBAABBH5S5KVQMGQERI5UKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D6348812734
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:48 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7b711ddbf1asf660619839f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533407; cv=pass;
        d=google.com; s=arc-20160816;
        b=voaxmAIMyomgKcNTUawXBoaY1Wvyoqpti4hlTzz5aYAXmlXtq2WUDB32iSQ1CQQTc6
         8NGGrrb9ROfgqDAu6NETL18nHeR+8L/igPp01dRDX5xjOtMfSK6xkeOZK8lxa1wxS+GZ
         LKDCC0yHLe+YGbU7ZDAP+gRf04di+LM2bWC1tZ6DYEMqjj9grnMTQ7EtYHhsQSI5ol95
         BQ+fFxULnD/hQVWgvYEeZZUsh9gdJCAD6riDAKoV3VQ6/2z8SdKg0G+SHO8gbmdlhfC3
         Pb9uxS8CLdScR7l3HMkF6NhEqaXxQf0BgTTu+XsZWVBlkOqn7ymcoGhK2XCa5W5NCxNg
         tfEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z3R746YrlO7HvYpT9AJWdxYSiq05rRxQFn0be68Oi9w=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=DGSknJvneDzL5mgtSILxynIFJaLXn39R2amTcnN6CE79oBZ4vDkFCq9Vg3yOAnJSkl
         A92yji7dv1qHBsZbvaZ09d28IRQplS1Tb6Vv4ismdyvkW4faFCvqYM1Mu6dJcTN25KXs
         IFv8RzeiypwZBvkdSvVYvzD8SdYhxTVbOekXe59+oXXSKJV1OPjPHh4hGbAoObRyy+Kw
         k/dcb68ts35h2mJ9JXrRDq1+YnGWiWrfWrkN44hNqSyiqWvvmUBkqicne9LFNvvXyUuN
         pf8Kb6S+W8aIHjowlMQO87PLtQCAQdt6vb62ATnzLSlAeMbnqH76jxWQ2I2ihwGamNXN
         AQ3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jPBCCJIq;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533407; x=1703138207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z3R746YrlO7HvYpT9AJWdxYSiq05rRxQFn0be68Oi9w=;
        b=DfBOfb+A9uKYwUP5qHWeeoPXjRQLiamMX105dGSs4vUBKtNGmiOVjr7PdY2UzWRARM
         geh6TJZDxKhdw7Ou6L+MLTb+Eq/GMosGUUdQgSiqYt7L+s9Ffyu+ckrSafxRwimgofhj
         d84LVq71ydHVQwSYZyErVulEIPFAKBwnbXTIPqTP2eXFHIj1BzuIyPjhC1EtswCWvL2U
         Tqlkx/FwaFgXXwgdpi3mXxvX/k5FhYyciaZ2+TrQuCR+U4sVJ3DBTAaGLJZ0fwRJX09N
         JZynaWIWFtNUVMoBGOTrlXcoUgEoeo0Y1HxoyOa5/tnmuGOQeJFPBFalNa38dsahEquN
         Te1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533407; x=1703138207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z3R746YrlO7HvYpT9AJWdxYSiq05rRxQFn0be68Oi9w=;
        b=O1vUGFd9HOCXN2v3bexPb7epO/02jfWN7gsQHHgy/cXD7qGx7F8x5uJDpAII+b5BmT
         ECiyU6K1wjQeaDX/OlqTfh611lQfRRzKpHUkHk5cNy9fdsnKRv51vljhYjp1lXJPRCY9
         OuQzMeF61j9mOFW6zgnLbGRSVrTv7/py7ucIXRs7NnLyRudTkl46cEiaYucObaYZzrZv
         9fOdH2hbWg1fAfXHpHgW0eQ4XAOzxqJsE4GlcPQi/5OH0UU9fILO5oyO6Aop0i39GQoD
         I3wF6MJPFpiADwwu4tITLbNINrpR2/EAdUrPTte9HJf3CJTEfbopLchU+rsirapPgaA9
         2amw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzkzWSuZlYsevOTHewHp6fXFat8Wl6pyn4rdTAdxlAv6Kncllob
	jjJnsSkZMEmxYSt2B4o2GCY=
X-Google-Smtp-Source: AGHT+IFg8nKGP2gSN2OzLpUTjWln46Fkb+4EsPF8Z7uiWTGWc+uGN7+JTm9bIWZtdnrYzLIGS5rp8g==
X-Received: by 2002:a92:c24d:0:b0:35d:637e:c3d2 with SMTP id k13-20020a92c24d000000b0035d637ec3d2mr11938564ilo.20.1702533407561;
        Wed, 13 Dec 2023 21:56:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:4286:b0:1cf:8bde:e276 with SMTP id
 ju6-20020a170903428600b001cf8bdee276ls111789plb.1.-pod-prod-07-us; Wed, 13
 Dec 2023 21:56:46 -0800 (PST)
X-Received: by 2002:a17:902:a9c4:b0:1cf:8bb6:f9c1 with SMTP id b4-20020a170902a9c400b001cf8bb6f9c1mr4856705plr.59.1702533406517;
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533406; cv=none;
        d=google.com; s=arc-20160816;
        b=g90R/ec/eExfSLmp26wI1jPMB/3trRGEQvVS//poHPfJFTvRAHqHA6SPdTOj0JhhOv
         FvNxoYr5/flSutQsdZ9YzZnDOYbWTIPrBJi+liXODdDY9hIaAhj3Z0p1zm6h+NnAWeml
         o/+rwoIbaxVjHWiOKcVhrBFaT7Q0cj9A5pVksvYsmO6aDDdMHZKenzsqPerxineUes2z
         q7nxlbDCE/jvka/byOOpV3ndhno6vRFGtg3eaXTk5Ts9NJ4RD5hv+j8akZIY8kRftjsx
         oqL05/6JwG6bcPmPwgXkxQCJU3VVofg2FYkBaqz7FlMcYPGGVs1lSvS2iBMPUlgN1mcs
         oZAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Or+ER3iSwLY+2GcnBysJHFAbWg54QnxrivHZZRWSUlo=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=PP9Oclrsx3o0wmDSLS924MUaLAZvaLW5ZBmKrge43q3IVrE7tBglFv3VZ+I32OKQV+
         b1V4EdXYRjVHMuSKwCxHj8hZYe/kC0ysEDWhODEunEoVgaUPcJRXsPo/sAUdcrZ2cvU+
         QXDTZRDSQQmPTlcNjwYMxYbed/8R4Pikp+xxfJ+1h9ZbTX8rhlRYIzDLEh5zR5BAUzFs
         8qU0k6i+fqiPzv6sflm0c6UAx0PY0E50D7VF/zGQ+bBQnENnl30pWxLsEcy6EmXqbxvR
         1h8JP2tDkBGdF0AVOGBEGsmk14bC3nXLt/VMMhJs41Ry5Z5iS4CcvfDqdsRslcc/YIq3
         m7rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jPBCCJIq;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id o10-20020a17090323ca00b001d33221c807si329963plh.5.2023.12.13.21.56.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5bkhT003442;
	Thu, 14 Dec 2023 05:56:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyuqp0av5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:40 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5rRSq022695;
	Thu, 14 Dec 2023 05:56:39 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyuqp0asc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:39 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3jVip008467;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtpnfx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uO5O46727664
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:25 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D30272004D;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E42AE20040;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 98F37606F0;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 10/13] powerpc: Define KMSAN metadata address ranges for vmalloc and ioremap
Date: Thu, 14 Dec 2023 05:55:36 +0000
Message-Id: <20231214055539.9420-11-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: BSRtrog9VNVw4H1y8EPLE2_PMzM43F4_
X-Proofpoint-GUID: z-dPmrvTGG-i94A2fIfwubmwfRHh6Qb7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 adultscore=0
 mlxlogscore=999 impostorscore=0 phishscore=0 priorityscore=1501 mlxscore=0
 lowpriorityscore=0 spamscore=0 suspectscore=0 bulkscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jPBCCJIq;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
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

Splits the vmalloc region into four. The first quarter is the new
vmalloc region, the second is used to store shadow metadata and the
third is used to store origin metadata. The fourth quarter is unused.

Do the same for the ioremap region.

Module data is stored in the vmalloc region so alias the modules
metadata addresses to the respective vmalloc metadata addresses. Define
MODULES_VADDR and MODULES_END to the start and end of the vmalloc
region.

Since MODULES_VADDR was previously only defined on ppc32 targets checks
for if this macro is defined need to be updated to include
defined(CONFIG_PPC32).

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/include/asm/book3s/64/pgtable.h | 42 ++++++++++++++++++++
 arch/powerpc/kernel/module.c                 |  2 +-
 2 files changed, 43 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/include/asm/book3s/64/pgtable.h
index cb77eddca54b..b3a02b8d96e3 100644
--- a/arch/powerpc/include/asm/book3s/64/pgtable.h
+++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
@@ -249,7 +249,38 @@ enum pgtable_index {
 extern unsigned long __vmalloc_start;
 extern unsigned long __vmalloc_end;
 #define VMALLOC_START	__vmalloc_start
+
+#ifndef CONFIG_KMSAN
 #define VMALLOC_END	__vmalloc_end
+#else
+/*
+ * In KMSAN builds vmalloc area is four times smaller, and the remaining 3/4
+ * are used to keep the metadata for virtual pages. The memory formerly
+ * belonging to vmalloc area is now laid out as follows:
+ *
+ * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
+ * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
+ *              KMSAN_VMALLOC_SHADOW_START+VMALLOC_LEN - vmalloc area shadow
+ * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
+ *              KMSAN_VMALLOC_ORIGIN_START+VMALLOC_LEN - vmalloc area origins
+ * 4th quarter: unused
+ */
+#define VMALLOC_LEN ((__vmalloc_end - __vmalloc_start) >> 2)
+#define VMALLOC_END (VMALLOC_START + VMALLOC_LEN)
+
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_ORIGIN_START (VMALLOC_END + VMALLOC_LEN)
+
+/*
+ * Module metadata is stored in the corresponding vmalloc metadata regions
+ */
+#define KMSAN_MODULES_SHADOW_START	KMSAN_VMALLOC_SHADOW_START
+#define KMSAN_MODULES_ORIGIN_START	KMSAN_VMALLOC_ORIGIN_START
+#endif /* CONFIG_KMSAN */
+
+#define MODULES_VADDR VMALLOC_START
+#define MODULES_END VMALLOC_END
+#define MODULES_LEN		(MODULES_END - MODULES_VADDR)
 
 static inline unsigned int ioremap_max_order(void)
 {
@@ -264,7 +295,18 @@ extern unsigned long __kernel_io_start;
 extern unsigned long __kernel_io_end;
 #define KERN_VIRT_START __kernel_virt_start
 #define KERN_IO_START  __kernel_io_start
+#ifndef CONFIG_KMSAN
 #define KERN_IO_END __kernel_io_end
+#else
+/*
+ * In KMSAN builds IO space is 4 times smaller, the remaining space is used to
+ * store metadata. See comment for vmalloc regions above.
+ */
+#define KERN_IO_LEN             ((__kernel_io_end - __kernel_io_start) >> 2)
+#define KERN_IO_END             (KERN_IO_START + KERN_IO_LEN)
+#define KERN_IO_SHADOW_START    KERN_IO_END
+#define KERN_IO_ORIGIN_START    (KERN_IO_SHADOW_START + KERN_IO_LEN)
+#endif /* !CONFIG_KMSAN */
 
 extern struct page *vmemmap;
 extern unsigned long pci_io_base;
diff --git a/arch/powerpc/kernel/module.c b/arch/powerpc/kernel/module.c
index f6d6ae0a1692..5043b959ad4d 100644
--- a/arch/powerpc/kernel/module.c
+++ b/arch/powerpc/kernel/module.c
@@ -107,7 +107,7 @@ __module_alloc(unsigned long size, unsigned long start, unsigned long end, bool
 
 void *module_alloc(unsigned long size)
 {
-#ifdef MODULES_VADDR
+#if defined(MODULES_VADDR) && defined(CONFIG_PPC32)
 	unsigned long limit = (unsigned long)_etext - SZ_32M;
 	void *ptr = NULL;
 
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-11-nicholas%40linux.ibm.com.
