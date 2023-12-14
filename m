Return-Path: <kasan-dev+bncBAABBF5S5KVQMGQEELFQPNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC0FD812732
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:40 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4258a2540cesf101807361cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533400; cv=pass;
        d=google.com; s=arc-20160816;
        b=ne3mrIooowPUetFSxvUAqgJCfbse8ItrzPw4DhqSj9OZXGM9QyOVB5H29NdMnveWtN
         KYY+cDkgycvTZZibRCKatOzBuh9O35ZJVpfDfRMiCg90kkBkNrvKZhyrwr4gSkOH9r9S
         fn3WmaIBRMrhYIRjpzFkQlHrUYKb4F/XhX+6egb9tXw9erjcS1pf+L6Ae0tEA62PpfO5
         l6VlDtBA6qFibuibQMi2NaRfPSKj6ERw/C615DnZae2PNcnI3jbiLc3TO9dFMGvbjBLE
         ARudCLM1dRgDfD+dl2GV7Cn474NTE99r+x+YbtiZCZNpE1GuOGMZEfg3VZ+DXLpKiaS7
         nddQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1dBlTd2p0fikWAYTASa+gMwfBOfLDlHva1KZ9ajwmQM=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=vRuuUK2Hy03BXhrRa09ZtEJLhrFkUmX+B7GBRN0JcLHr+cPCh0zdaYqNeU8RjKZl86
         A2+HkefuFu8aQsdgje88NmW8F7m6hOFuNbEi9NaCI9CAq5/vPbWlrL5nDgMJkIswo2HV
         pCs6igaPwEgzuDdPgoNds0De82XG8P8dOWNd6RLgS9D1WnR6hYSP2Kgig6HezwZaNgbN
         ZWRm3mDCU/usz9EmFuF+SrAg24SsuX6FceU6STcrf3SVPQhZPIrLn8AhVOSXitlk7dWN
         5sRwq0JFIxvqd++jhBU/1AlXP+2vGjVnIgMIXbGgha+x3X2LFvpez4s+qNkKechTEVbq
         hYaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=r2biZhd7;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533400; x=1703138200; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1dBlTd2p0fikWAYTASa+gMwfBOfLDlHva1KZ9ajwmQM=;
        b=rtJTiyI4aw3zqjBKOroocu7jgFRx91ZxKsa5Fj/8vNkrqXPS3SmvvMI19wjwFClfCD
         WjByuOvb1L7CS8p3FhDHJwG2KmZVK+zEef1YqZBxZsjEEs2WkdUTyvdfr/wUkhvWmvb9
         5nvewhkREMw/Lhp5qebijmA4fwbPgzb8Ykhv1A3p3Lr7ZMJ/p2J3iqMcbCal0ISrsnpZ
         FeU6pJeKKEIeR4sT8BlGdI8z6ytKRvIgHQRTRvaecatz7TDhSBmGcZYO9u1fIMMOd4QD
         vRtV+cgl8DV5OqSAmNl15D1OgG3dRRSsq23gBQSsgsItQe2evn4LflC2Hm892pwMW2h5
         6XfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533400; x=1703138200;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1dBlTd2p0fikWAYTASa+gMwfBOfLDlHva1KZ9ajwmQM=;
        b=k6SWnw5E/X1W6p4qdBVmx6ROlGsE/9hpUPVHts+FJWSSduS6w6mXhsVQzXGL9WTBNr
         X5gZ5wG1wn2GClJd8iGBi3iz3726/0HAMQxfIgvyAx0omEU/h//D1NHGUXsxPYseKSfO
         Uvjpqp0cBx2R8nMJyypwS+HROhIG7Cqhr3zsKLk5konGnNDsWQh7CviR9ZDaFoLJDvd9
         5XRuvKFNqWNikPd9YlkIVB8JN7Hl+ADtm99ytmb8IED95Jl9YvEJ7uIXy81+g6pGQPkh
         2MwBb9z6iDQzGmyeWmVDjClQAFue+8y39n/H6huUARUKohi1UUo49qEC2mY/9Mzau3oN
         Oycg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyHYBvU2EZlNZ0XCZbHk4AaY1NPaA2SxrMUTuAKEc3bLHcfUVXN
	AfyRqsBV0kh45m0CxS2KbdM=
X-Google-Smtp-Source: AGHT+IEqoqFfY7P02F73ALxxYGt9akxkIKtdw5t5yhbSB7LHibGSWWlWttu/mhrSHrTfjiyoO3QwuA==
X-Received: by 2002:a05:622a:54c:b0:41c:e129:87dc with SMTP id m12-20020a05622a054c00b0041ce12987dcmr13705053qtx.36.1702533399795;
        Wed, 13 Dec 2023 21:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1aa4:b0:421:c71a:9295 with SMTP id
 s36-20020a05622a1aa400b00421c71a9295ls3613294qtc.0.-pod-prod-01-us; Wed, 13
 Dec 2023 21:56:39 -0800 (PST)
X-Received: by 2002:a05:620a:458b:b0:77f:25f5:36ed with SMTP id bp11-20020a05620a458b00b0077f25f536edmr11350716qkb.144.1702533399126;
        Wed, 13 Dec 2023 21:56:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533398; cv=none;
        d=google.com; s=arc-20160816;
        b=iYsFwSHE8lfDZpaUvBsexBrXGWixRESRf3hJQb/LQytHJuWdYa025xgbpIrNwQXjSd
         4Nbj/FwKFNCbWehZKdQMCQIsIRKTQslDp75ops8lZaBlooeESAOokRAOck9DLfeNR+wr
         yZMkDvFVeIzB4Oyym9Yj+3B3t2B4dYnZto7l32CfOuIaemL2328p7wNCH1TCqWwYJ2EN
         2XHBGs0qeoDwyRM3FoHGimnYBNYlT22IL//FkKkrEHKNjfnvv4En7yQ+4KIMDOs26Zs0
         KEEWbneCqXdFfqsT0/uCmRpHduY4fg/4pHqAmcGDLMYetPmCReT7CnQeW1f++5XtTJ3g
         htEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ovh2+Yrkn7RejFOEC//qHuFziQE6QAg7xqk0h8rVmGI=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=nveyOtn5tcEiMSntC/DoYZQ+4+S82ylzt5DLLgTMeF71CYvz8/dNsNn7iHnMc6KUmt
         DP1LrJBWCl+rrgueAiTi0+mP2+S4+RV1iDO2L2HTtBn49eBdqdIvdxIBXWqBrEG9qYRI
         mj3Cj3/tjFKO259RPONuqfrRByAPd9IqlOLIcnLbU5+f8z7FUX858J8SH5MIau/Roobt
         kcrYPmPACc0FSJjRUxh0kyN42cssEx6bsFZxBo7qa57Rhb2QRzfYT0jxOrOSZJWje+Eh
         2kAfpiyb2Qxt1No6yKoYyojWRi8JHXBxZJ5vtZofTxC8+woHRUxFn60s1rvDFMNS8Qiz
         hxXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=r2biZhd7;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l41-20020a056122202900b004b2f93695f7si1378036vkd.4.2023.12.13.21.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:38 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3j4SP012290;
	Thu, 14 Dec 2023 05:56:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypr2xbm0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:31 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5Q8Xa019113;
	Thu, 14 Dec 2023 05:56:31 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypr2xbjx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:31 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3ZZKd012593;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp6eg1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOHO22151740
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A9AF920043;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CAA982004B;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id A6B3F6070D;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 12/13] powerpc/string: Add KMSAN support
Date: Thu, 14 Dec 2023 05:55:38 +0000
Message-Id: <20231214055539.9420-13-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 3BssezVAxDdviUPaDOyqZR4dSdHksbIi
X-Proofpoint-GUID: 8uj1JSwoXAIg2-3RyoUW_4goY-hONVyB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 spamscore=0
 mlxlogscore=999 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 mlxscore=0 phishscore=0 clxscore=1015 bulkscore=0 adultscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=r2biZhd7;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
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

KMSAN expects functions __mem{set,cpy,move} so add aliases pointing to
the respective functions.

Disable use of architecture specific memset{16,32,64} to ensure that
metadata is correctly updated and strn{cpy,cmp} and mem{chr,cmp} which
are implemented in assembly and therefore cannot be instrumented to
propagate/check metadata.

Alias calls to mem{set,cpy,move} to __msan_mem{set,cpy,move} in
instrumented code to correctly propagate metadata.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/include/asm/kmsan.h               |  7 +++++++
 arch/powerpc/include/asm/string.h              | 18 ++++++++++++++++--
 arch/powerpc/lib/Makefile                      |  2 ++
 arch/powerpc/lib/mem_64.S                      |  5 ++++-
 arch/powerpc/lib/memcpy_64.S                   |  2 ++
 .../selftests/powerpc/copyloops/asm/kmsan.h    |  0
 .../selftests/powerpc/copyloops/linux/export.h |  1 +
 7 files changed, 32 insertions(+), 3 deletions(-)
 create mode 100644 tools/testing/selftests/powerpc/copyloops/asm/kmsan.h

diff --git a/arch/powerpc/include/asm/kmsan.h b/arch/powerpc/include/asm/kmsan.h
index bc84f6ff2ee9..fc59dc24e170 100644
--- a/arch/powerpc/include/asm/kmsan.h
+++ b/arch/powerpc/include/asm/kmsan.h
@@ -7,6 +7,13 @@
 #ifndef _ASM_POWERPC_KMSAN_H
 #define _ASM_POWERPC_KMSAN_H
 
+#ifdef CONFIG_KMSAN
+#define EXPORT_SYMBOL_KMSAN(fn) SYM_FUNC_ALIAS(__##fn, fn) \
+				EXPORT_SYMBOL(__##fn)
+#else
+#define EXPORT_SYMBOL_KMSAN(fn)
+#endif
+
 #ifndef __ASSEMBLY__
 #ifndef MODULE
 
diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/asm/string.h
index 60ba22770f51..412626ce619b 100644
--- a/arch/powerpc/include/asm/string.h
+++ b/arch/powerpc/include/asm/string.h
@@ -4,7 +4,7 @@
 
 #ifdef __KERNEL__
 
-#ifndef CONFIG_KASAN
+#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_STRNCPY
 #define __HAVE_ARCH_STRNCMP
 #define __HAVE_ARCH_MEMCHR
@@ -56,8 +56,22 @@ void *__memmove(void *to, const void *from, __kernel_size_t n);
 #endif /* CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
 #endif /* CONFIG_KASAN */
 
+#ifdef CONFIG_KMSAN
+
+void *__memset(void *s, int c, __kernel_size_t count);
+void *__memcpy(void *to, const void *from, __kernel_size_t n);
+void *__memmove(void *to, const void *from, __kernel_size_t n);
+
+#ifdef __SANITIZE_MEMORY__
+#include <linux/kmsan_string.h>
+#define memset __msan_memset
+#define memcpy __msan_memcpy
+#define memmove __msan_memmove
+#endif
+#endif /* CONFIG_KMSAN */
+
 #ifdef CONFIG_PPC64
-#ifndef CONFIG_KASAN
+#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_MEMSET32
 #define __HAVE_ARCH_MEMSET64
 
diff --git a/arch/powerpc/lib/Makefile b/arch/powerpc/lib/Makefile
index 51ad0397c17a..fc3ea3eebbd6 100644
--- a/arch/powerpc/lib/Makefile
+++ b/arch/powerpc/lib/Makefile
@@ -32,9 +32,11 @@ obj-y += code-patching.o feature-fixups.o pmem.o
 obj-$(CONFIG_CODE_PATCHING_SELFTEST) += test-code-patching.o
 
 ifndef CONFIG_KASAN
+ifndef CONFIG_KMSAN
 obj-y	+=	string.o memcmp_$(BITS).o
 obj-$(CONFIG_PPC32)	+= strlen_32.o
 endif
+endif
 
 obj-$(CONFIG_PPC32)	+= div64.o copy_32.o crtsavres.o
 
diff --git a/arch/powerpc/lib/mem_64.S b/arch/powerpc/lib/mem_64.S
index 6fd06cd20faa..a55f2fac49b3 100644
--- a/arch/powerpc/lib/mem_64.S
+++ b/arch/powerpc/lib/mem_64.S
@@ -9,8 +9,9 @@
 #include <asm/errno.h>
 #include <asm/ppc_asm.h>
 #include <asm/kasan.h>
+#include <asm/kmsan.h>
 
-#ifndef CONFIG_KASAN
+#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
 _GLOBAL(__memset16)
 	rlwimi	r4,r4,16,0,15
 	/* fall through */
@@ -96,6 +97,7 @@ _GLOBAL_KASAN(memset)
 	blr
 EXPORT_SYMBOL(memset)
 EXPORT_SYMBOL_KASAN(memset)
+EXPORT_SYMBOL_KMSAN(memset)
 
 _GLOBAL_TOC_KASAN(memmove)
 	cmplw	0,r3,r4
@@ -140,3 +142,4 @@ _GLOBAL(backwards_memcpy)
 	b	1b
 EXPORT_SYMBOL(memmove)
 EXPORT_SYMBOL_KASAN(memmove)
+EXPORT_SYMBOL_KMSAN(memmove)
diff --git a/arch/powerpc/lib/memcpy_64.S b/arch/powerpc/lib/memcpy_64.S
index b5a67e20143f..1657861618cc 100644
--- a/arch/powerpc/lib/memcpy_64.S
+++ b/arch/powerpc/lib/memcpy_64.S
@@ -8,6 +8,7 @@
 #include <asm/asm-compat.h>
 #include <asm/feature-fixups.h>
 #include <asm/kasan.h>
+#include <asm/kmsan.h>
 
 #ifndef SELFTEST_CASE
 /* For big-endian, 0 == most CPUs, 1 == POWER6, 2 == Cell */
@@ -228,3 +229,4 @@ END_FTR_SECTION_IFCLR(CPU_FTR_UNALIGNED_LD_STD)
 #endif
 EXPORT_SYMBOL(memcpy)
 EXPORT_SYMBOL_KASAN(memcpy)
+EXPORT_SYMBOL_KMSAN(memcpy)
diff --git a/tools/testing/selftests/powerpc/copyloops/asm/kmsan.h b/tools/testing/selftests/powerpc/copyloops/asm/kmsan.h
new file mode 100644
index 000000000000..e69de29bb2d1
diff --git a/tools/testing/selftests/powerpc/copyloops/linux/export.h b/tools/testing/selftests/powerpc/copyloops/linux/export.h
index e6b80d5fbd14..6379624bbf9b 100644
--- a/tools/testing/selftests/powerpc/copyloops/linux/export.h
+++ b/tools/testing/selftests/powerpc/copyloops/linux/export.h
@@ -2,3 +2,4 @@
 #define EXPORT_SYMBOL(x)
 #define EXPORT_SYMBOL_GPL(x)
 #define EXPORT_SYMBOL_KASAN(x)
+#define EXPORT_SYMBOL_KMSAN(x)
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-13-nicholas%40linux.ibm.com.
