Return-Path: <kasan-dev+bncBCYL7PHBVABBB2GTQ2EAMGQEWWP5OSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE1283D95C3
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:03:05 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id f9-20020a1709028609b0290128bcba6be7sf2685492plo.18
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:03:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627498984; cv=pass;
        d=google.com; s=arc-20160816;
        b=ERXQED0tQnIPDNOdagj3zBltTuFFowionbtXCIe1V8D46TubX3izxdMCMWK6sB3CGg
         oQsc/5ufHTxXLFg1ndKLg9POHItpuXI+zE3179/wsPHk09VWr5Ug5GpuOUe9jQa2SZ12
         hFLyHKeBbphgHHkojvq03ytMtAHRA8GzTTcl6YucseJU8cEL3Tmyh4RdLZ0R+QRalEPB
         z1ik8ubSkSKyhRNPKB8167JqJ9FjIXqQd7nRiRGcNHiieTaIe4i2rSPG7P5OE4J9aqPX
         eJrU9Vez21If9XSoVjPk6uPFwv2SDJJ8eFBerLHgLiIcz2lMzqV4K1Z1XvZvJIbUZLuC
         MOOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=x9fMAHFbgUigcubLprMglPBis/HKFvga/EXHKtLS1xY=;
        b=EsIxxkwUCHn+w96AFg+NzWN+Hk5jjowm4Hsj8M/fQUQJ5T/lnEXk0Mr3o8VR9rvvar
         SVekt989YX6NiqbEH++ICe2I9cPS01Z/JYrfAY7waA+QV4vuIjl2M03NQ3s57VYm9H66
         WB/qE55nF/uOOG6SqXkNbM+Q8pMUhNfP5BgX9438aJ0y8fjV0yXqAtknUHpumj4R7fX1
         /1iR1BdHwS8agQGEHT6lSpxSDyLUoiWp1KmEVehoV0E5xZj0uotuRq4wKgGuArLJ0BcH
         yLlQuMf1fNWcKCZUpoH67o4L2mIWZQgSg4v46jQUeQ9cPitLfBrh2JyJVVMYS0exYAJz
         0flg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Dagu6+gi;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9fMAHFbgUigcubLprMglPBis/HKFvga/EXHKtLS1xY=;
        b=RRNJigE/JLwjBsH9XGB9t+fk+JgDpiZ1RDxQ5VaTk72aLrgiqAoJMoNnt2y/2ghVeR
         EoBraI/OAPLMtfdIbVF0qonAsStU4dtJqhPeH1KoYpGlwk/j8t+LBu6uA4CrMfPIGPtf
         cfkhmB/6lOVOva3eic8lPvBdHHxadnCZx7cDicOLfCEd+swXR3wR7NkUhaIb1h9e14zm
         EoLwgUzDIDk495A6bHfeqtI9wQuLy1oT7jrzpRBIzPQYjtn1bRX+uJ2jKQVuX5BB1ooO
         aBRfjWTjEzmwq97TmWhAHaD6lxV0ZD6Hx8A8qeTteO95cw5oqhIe5mQl1VswBbTMYmNq
         D8Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x9fMAHFbgUigcubLprMglPBis/HKFvga/EXHKtLS1xY=;
        b=Ya+OaGont77PLEee2smFAcMwU1F6Zq5Foz4AfKQbqJM+qyXggbUezauSEI+LQtQMfK
         kqUU3DDcD444atb+Ud8rys+gxqx2i5vIOC5p+HYmsZAeBpAv4k9FRad/fAKVahfflkV9
         7fx4VNLRp4suM/i6gsJ8eoacyHys8elF/PRWiaq1LZ3gphl891hSzF2vPZLJKMNVEzw4
         s9DNi/2GHhSGL0XE4ER/1p5OXWVgkz5728qyQCm2aT0bbYFljtLfizNokCJ7nMhScTwv
         31Eu/YgvoD+zRSOCCi6MUF6tL6yZn/AOQwQ1G45XfkhZqN/gVQY0TG3EgYpEk5pSCVW9
         01qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YeajDeS1O5qNY+Vy8CfX32hX5keymhlPOmJ1DitR2huROSp0M
	zxxmV7DWaoV1EpPbXSznPaU=
X-Google-Smtp-Source: ABdhPJy2VJZ8ycTvZptPUkFV8vZDCxxrATEmcG/p+gYw0pJr6ZjY3zsQdbk3IjMU8lqIQTxuaGhZqw==
X-Received: by 2002:a17:90a:44:: with SMTP id 4mr1162269pjb.130.1627498984613;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a1a:: with SMTP id p26ls1325887pfh.9.gmail; Wed, 28
 Jul 2021 12:03:03 -0700 (PDT)
X-Received: by 2002:a63:171a:: with SMTP id x26mr326864pgl.51.1627498983734;
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627498983; cv=none;
        d=google.com; s=arc-20160816;
        b=BT/LLeYNE19z/C0TmBh7KkxeNUKGVtrRyPT4SVqOVkjzzsZSOfooxw3ApPdm6GIJlo
         i0zQgWOOJGekVXKNW15CEQJl+uuGIyi3Geq8a6kzoSIg7wQn6QA+jC6wl4mxnWM54pLx
         Aum1TiQzU2RKaE+H1N8Bkd9kiRyOC2LIj4HEU+B5L6WycsRx/C9FjMPBfgQWAQaVN3Np
         DHUsyGlQ++w1T+0w7XruK74vhMWXQxTOIyqehtFqdzuLSzO2NEuYuGPrJlnRD7kJBFf6
         AiKdhzBaAzV2Fdx9d+Y3TieHD6owX/l+PIn5k1AQnN0iysp2LJiXcinlxCdzCmqvSUTQ
         KPBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4QysXU3cgPE14ICbtSebIdAEvd2Whhmjixbyt0l4VQQ=;
        b=mLFbf/z0K7agc9D28ApTQgpfGJkfOPyovBvJvgG7Zef3NVOK+MwA9ODYO1HhZfoxE7
         oTUAh1iMSjSmPhaU+17z4nm9+trx6EXvr697VY6xBdIjH47Zosp+3bZpMrB+VYFByc1b
         SZIAUtsn02pfBwD64DcPRAIVWGY9RkwC880yZRZ3Sv8M45iO3QnqNDQyAui+at4O/o3w
         k1oAB4AcS/mo4CmB072lFmup3LcZCT5pJCgQPsxED1PkZnvJ/rlt3FwnHsijffqrZUkm
         Q5m9yPPpEqp5+bW2Q8J3PnwuxpPxi6DBzyxcnOG/XqS0PG3znmN7BGugrexerc+AgpLZ
         eZ8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Dagu6+gi;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y6si24738pgb.3.2021.07.28.12.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098420.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SIeVYX142956;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3a3bf7jety-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from m0098420.ppops.net (m0098420.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SIf6pS145086;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from ppma06fra.de.ibm.com (48.49.7a9f.ip4.static.sl-reverse.com [159.122.73.72])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3a3bf7jetb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.filterd (ppma06fra.de.ibm.com [127.0.0.1])
	by ppma06fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJ30nS014713;
	Wed, 28 Jul 2021 19:03:00 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma06fra.de.ibm.com with ESMTP id 3a235kgtux-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:03:00 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJ0GX924904094
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:00:17 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E63D3AE04D;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 850FAAE045;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 3/4] s390: add support for KFENCE
Date: Wed, 28 Jul 2021 21:02:53 +0200
Message-Id: <20210728190254.3921642-4-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210728190254.3921642-1-hca@linux.ibm.com>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: wG5MQjOYWukoOHGzEbQlaeySmTJNQ0TO
X-Proofpoint-ORIG-GUID: sP12_R-6Ygk47a7VgXJO8eOnkHK6yxHN
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 clxscore=1015
 adultscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=999 phishscore=0
 impostorscore=0 malwarescore=0 spamscore=0 lowpriorityscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107280106
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Dagu6+gi;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

From: Sven Schnelle <svens@linux.ibm.com>

Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
[hca@linux.ibm.com: simplify/rework code]
Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
---
 arch/s390/Kconfig              |  1 +
 arch/s390/include/asm/kfence.h | 42 ++++++++++++++++++++++++++++++++++
 arch/s390/mm/fault.c           |  9 ++++++--
 arch/s390/mm/init.c            |  3 ++-
 arch/s390/mm/pageattr.c        |  3 ++-
 5 files changed, 54 insertions(+), 4 deletions(-)
 create mode 100644 arch/s390/include/asm/kfence.h

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index a0e2130f0100..f20467af2ab2 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -138,6 +138,7 @@ config S390
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
+	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_SOFT_DIRTY
diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfence.h
new file mode 100644
index 000000000000..d55ba878378b
--- /dev/null
+++ b/arch/s390/include/asm/kfence.h
@@ -0,0 +1,42 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_S390_KFENCE_H
+#define _ASM_S390_KFENCE_H
+
+#include <linux/mm.h>
+#include <linux/kfence.h>
+#include <asm/set_memory.h>
+#include <asm/page.h>
+
+void __kernel_map_pages(struct page *page, int numpages, int enable);
+
+static __always_inline bool arch_kfence_init_pool(void)
+{
+	return true;
+}
+
+#define arch_kfence_test_address(addr) ((addr) & PAGE_MASK)
+
+/*
+ * Do not split kfence pool to 4k mapping with arch_kfence_init_pool(),
+ * but earlier where page table allocations still happen with memblock.
+ * Reason is that arch_kfence_init_pool() gets called when the system
+ * is still in a limbo state - disabling and enabling bottom halves is
+ * not yet allowed, but that is what our page_table_alloc() would do.
+ */
+static __always_inline void kfence_split_mapping(void)
+{
+#ifdef CONFIG_KFENCE
+	unsigned long pool_pages = KFENCE_POOL_SIZE >> PAGE_SHIFT;
+
+	set_memory_4k((unsigned long)__kfence_pool, pool_pages);
+#endif
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	__kernel_map_pages(virt_to_page(addr), 1, !protect);
+	return true;
+}
+
+#endif /* _ASM_S390_KFENCE_H */
diff --git a/arch/s390/mm/fault.c b/arch/s390/mm/fault.c
index e33c43b38afe..52d82410486e 100644
--- a/arch/s390/mm/fault.c
+++ b/arch/s390/mm/fault.c
@@ -31,6 +31,7 @@
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/hugetlb.h>
+#include <linux/kfence.h>
 #include <asm/asm-offsets.h>
 #include <asm/diag.h>
 #include <asm/gmap.h>
@@ -356,6 +357,7 @@ static inline vm_fault_t do_exception(struct pt_regs *regs, int access)
 	unsigned long address;
 	unsigned int flags;
 	vm_fault_t fault;
+	bool is_write;
 
 	tsk = current;
 	/*
@@ -369,6 +371,8 @@ static inline vm_fault_t do_exception(struct pt_regs *regs, int access)
 
 	mm = tsk->mm;
 	trans_exc_code = regs->int_parm_long;
+	address = trans_exc_code & __FAIL_ADDR_MASK;
+	is_write = (trans_exc_code & store_indication) == 0x400;
 
 	/*
 	 * Verify that the fault happened in user space, that
@@ -379,6 +383,8 @@ static inline vm_fault_t do_exception(struct pt_regs *regs, int access)
 	type = get_fault_type(regs);
 	switch (type) {
 	case KERNEL_FAULT:
+		if (kfence_handle_page_fault(address, is_write, regs))
+			return 0;
 		goto out;
 	case USER_FAULT:
 	case GMAP_FAULT:
@@ -387,12 +393,11 @@ static inline vm_fault_t do_exception(struct pt_regs *regs, int access)
 		break;
 	}
 
-	address = trans_exc_code & __FAIL_ADDR_MASK;
 	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);
 	flags = FAULT_FLAG_DEFAULT;
 	if (user_mode(regs))
 		flags |= FAULT_FLAG_USER;
-	if (access == VM_WRITE || (trans_exc_code & store_indication) == 0x400)
+	if (access == VM_WRITE || is_write)
 		flags |= FAULT_FLAG_WRITE;
 	mmap_read_lock(mm);
 
diff --git a/arch/s390/mm/init.c b/arch/s390/mm/init.c
index 8ac710de1ab1..f3db3caa8447 100644
--- a/arch/s390/mm/init.c
+++ b/arch/s390/mm/init.c
@@ -34,6 +34,7 @@
 #include <asm/processor.h>
 #include <linux/uaccess.h>
 #include <asm/pgalloc.h>
+#include <asm/kfence.h>
 #include <asm/ptdump.h>
 #include <asm/dma.h>
 #include <asm/lowcore.h>
@@ -200,7 +201,7 @@ void __init mem_init(void)
         high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);
 
 	pv_init();
-
+	kfence_split_mapping();
 	/* Setup guest page hinting */
 	cmma_init();
 
diff --git a/arch/s390/mm/pageattr.c b/arch/s390/mm/pageattr.c
index b09fd5c7f85f..550048843fd6 100644
--- a/arch/s390/mm/pageattr.c
+++ b/arch/s390/mm/pageattr.c
@@ -4,6 +4,7 @@
  * Author(s): Jan Glauber <jang@linux.vnet.ibm.com>
  */
 #include <linux/hugetlb.h>
+#include <linux/kfence.h>
 #include <linux/mm.h>
 #include <asm/cacheflush.h>
 #include <asm/facility.h>
@@ -324,7 +325,7 @@ int __set_memory(unsigned long addr, int numpages, unsigned long flags)
 	return change_page_attr(addr, addr + numpages * PAGE_SIZE, flags);
 }
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
 
 static void ipte_range(pte_t *pte, unsigned long address, int nr)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210728190254.3921642-4-hca%40linux.ibm.com.
