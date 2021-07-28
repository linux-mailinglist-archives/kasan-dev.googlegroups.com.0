Return-Path: <kasan-dev+bncBCYL7PHBVABBB2GTQ2EAMGQEWWP5OSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 141AC3D95C4
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:03:06 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 64-20020a4a0d430000b02902446eb55473sf1545310oob.20
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:03:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627498985; cv=pass;
        d=google.com; s=arc-20160816;
        b=T3jn58lev7LQDPLeyeDZ/gdT+meQz+wfJj6Kr146mXSuVGwYNhJKuyD9Hn0esUMws6
         dHLP5I4oJIQkjmBAK/wIV6hmUNZai5/Xk++RT0O6EW01Q/5wJC13/jyW36LKWm2zzjsz
         N2V4IVCEBLagXKnNqw94kpSol1IBMhW330vGl8P1F0oXDR6gn9zgAbHCEmvPaTlZh7Ub
         EM8fKTKK3o/+MON+OfMi5y3+tERxbYGt2en0yuB48OKJMVpDoXiKe0X+v36Ggy0n9Q7X
         h72I2yKwaTn1rAh9MTO17SAiQYiz6mwqwLKNkFfHqTF/smsTroPmsEcy/xcZLrudEqvf
         BfJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QWfZY1SNkXsCK7bcCH/5uY3phRyIPGz7izzBW+oIL9w=;
        b=oReaK5a1dWpnQ63Db63jtQIDtFkRHn6mVchwcDYJTWOpvkF4uQCJLhSr95FsIWmDtt
         khtH+B9SWAghb8mnUz6vll50ljXJ2nUQqZnfE02HQgnA2LueijYBU01C4iLwEhif62AI
         ZtMgDQ6ME4nHilQRCdG1mjgqBC9kBF6RGZtLtx/Bq93fOjL60SraLxG6OXb7gEaDTHJU
         gdqcxs3woBh6ME4XNhnIXcju2cgJz1CufuC+xwJmI/+vIDPgzlx7upDzVdI82YmrJZqM
         JO5Z9POxXZmsQSUG7wG+fkPOzvCwjkvUFFw0oGpHxNxNw/zI8GOV3EFXigW4VHA7POL8
         0OMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iJC36z8N;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QWfZY1SNkXsCK7bcCH/5uY3phRyIPGz7izzBW+oIL9w=;
        b=Ejk4LATAxtzkreZOWFroPRnVJLK3T/oPJGqpM+7UObXAEoWYrExjUtP+RsDGpgQTWj
         +l0+LzER6xlVfB6OrVb51+ZTjUQWpeddTKUxG2OGapx+wkX/DUIjrGm7rRQ/Etj8aBIV
         AIu8Nm+Irw28kvDEjPhIfESlUhMbuD42Nls9m7wuKt5BbNqCrUv4AYURSePD1kxr1mli
         xSRqRBuzY0uP6VkpazsCLxy0IOoadmRVXOCwhM9QhaOxXgRCSSvCkTIXcTEsSYDhQAdk
         Yx/Cf2EF9IkwBEG9tKm8AhWPkSnYuwrGI+7F58cTct9x7WcC4MbGqCgjwRk+FUGVxySv
         ONPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QWfZY1SNkXsCK7bcCH/5uY3phRyIPGz7izzBW+oIL9w=;
        b=d5dVpxG27bXcmq991w3rt3tXlQbAWqCZKeSnCifxtvz8UiGNDsdm8B9azv0PkCMBBZ
         i/EAtbzLA9t3POU+WYJNKIbIwqRRTkLHT3h9zK9f3zpksh6J4Y7N1zj5EeNuib3QRqFv
         aO3195XtwLAkNmjEjyvGdQe+clGqTZMInqUBjwfhHp3H+OIHXrlcrxMCfY2kITkf9Bpx
         8BnczBtxAX2ZMeoBy2UiK6Nhe/T0KTCOdbR4s6oA6pEuRiws0PxeRouv6jkIsxTj14Jz
         v9K/j6aa/OJP0Afj++5/h+1tSgBPC5X91w+TZ3RIVHGcgI8kgWU16zqYb4RtsWHoKStL
         oMyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HTK5iCb3PFhqveZ3LBI0X4lNTj6HNb1ro7vW95wXdDOBpr79Z
	8fSIE+pLKKVUXegClHOr5Dw=
X-Google-Smtp-Source: ABdhPJyifkP43b5n0Kb3+w93mKmSuEITOXA+nZZmh0FZG2lBrFWf0FRRBpfvS6hG1aF3GNHgA0sT5A==
X-Received: by 2002:a9d:1b6e:: with SMTP id l101mr1056326otl.34.1627498984897;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1687:: with SMTP id k7ls839006otr.10.gmail; Wed, 28
 Jul 2021 12:03:04 -0700 (PDT)
X-Received: by 2002:a9d:7010:: with SMTP id k16mr1002876otj.298.1627498984591;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627498984; cv=none;
        d=google.com; s=arc-20160816;
        b=PUlH5wjWRgcLwwftBbYMVfri3/aJi3MT9QwKJyxqNdVLo3SVzziGPf7l9zYu7UKgRE
         4X1MwY1QzR0iDydAuErnMKU+tCx4JwdAZx7OzL8NmSadUk2kNcsyspdCtyNcoxaG++V6
         0/AZAJ9Vbqj7nN9XdP3RTtA5oxZkpTxVQqt1vqCnUv7sbuoLVjuslqJNftXuD8fLiR4t
         eM2xA7Doo+zJx7Iq3GeI/gdyK7fXNvd60two3vmo0oJHvUkeDu1rOFhjlH6/GZRC+anq
         xu1luy/KOu+wB5Qwwhk7y79C7boEUliNHZu5SQ8SiBa3+z4nzz8BmbDfS78m2Qbush7d
         AtxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lLMv06NdvqTmx5y8HUhXgPkm/QTRuWHf5/f5/uzWN8A=;
        b=DNMZueMPHqlIFq3dBCk8qIezjkBc7NMAZjVFZtSZyCJptJWZLsZoSRaJjuKppgA4Rr
         dVlEX11aIGvASHKf5r1czVziK6BU88ActGRH1rXBBQSjYQIaCX7q6TCmu4YsaJI2kyMo
         6UPhOhwBTYsBzbMSIlDSzvWGxPoXxo9tPYSjJLjDo+w+is+JLi4jpwwOWhgjmv9cKcUG
         jH7RbNR9NigxvfVYx1yqTjXiLA9XIvN7Ja8UXiW0zPbZnzxEuE4ywIlnAcwee8dVzFvb
         zyJMQwkLdtR9LUYYXIyA+Hs3WiTqMHO8fODzWsnOqsE8u/SjAibwedaF5J4oXYl8unM0
         8Gnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iJC36z8N;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id q1si97119oij.1.2021.07.28.12.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098399.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SIddcB085471;
	Wed, 28 Jul 2021 15:03:03 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b0xucf9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:03 -0400
Received: from m0098399.ppops.net (m0098399.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SIdgGc085784;
	Wed, 28 Jul 2021 15:03:03 -0400
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b0xuceg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJ30NJ001177;
	Wed, 28 Jul 2021 19:03:00 GMT
Received: from b06avi18626390.portsmouth.uk.ibm.com (b06avi18626390.portsmouth.uk.ibm.com [9.149.26.192])
	by ppma03ams.nl.ibm.com with ESMTP id 3a235yh8rv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:03:00 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJ0HAW26411392
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:00:17 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 660F6AE04D;
	Wed, 28 Jul 2021 19:02:57 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0424EAE051;
	Wed, 28 Jul 2021 19:02:57 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 4/4] s390: add kfence region to pagetable dumper
Date: Wed, 28 Jul 2021 21:02:54 +0200
Message-Id: <20210728190254.3921642-5-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210728190254.3921642-1-hca@linux.ibm.com>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: kBtBiiHRGC3KLk1NfivqjvaINgTK5QIE
X-Proofpoint-ORIG-GUID: -tcTXh2f0dP8OWuGmKumfU33hNOrvJ1w
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 impostorscore=0 mlxlogscore=999 spamscore=0 suspectscore=0
 lowpriorityscore=0 bulkscore=0 adultscore=0 clxscore=1015 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107280106
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iJC36z8N;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
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
Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
---
 arch/s390/mm/dump_pagetables.c | 14 ++++++++++++++
 1 file changed, 14 insertions(+)

diff --git a/arch/s390/mm/dump_pagetables.c b/arch/s390/mm/dump_pagetables.c
index e40a30647d99..07dcec925bf4 100644
--- a/arch/s390/mm/dump_pagetables.c
+++ b/arch/s390/mm/dump_pagetables.c
@@ -4,6 +4,7 @@
 #include <linux/seq_file.h>
 #include <linux/debugfs.h>
 #include <linux/mm.h>
+#include <linux/kfence.h>
 #include <linux/kasan.h>
 #include <asm/ptdump.h>
 #include <asm/kasan.h>
@@ -21,6 +22,8 @@ enum address_markers_idx {
 	IDENTITY_BEFORE_END_NR,
 	KERNEL_START_NR,
 	KERNEL_END_NR,
+	KFENCE_START_NR,
+	KFENCE_END_NR,
 	IDENTITY_AFTER_NR,
 	IDENTITY_AFTER_END_NR,
 #ifdef CONFIG_KASAN
@@ -40,6 +43,10 @@ static struct addr_marker address_markers[] = {
 	[IDENTITY_BEFORE_END_NR] = {(unsigned long)_stext, "Identity Mapping End"},
 	[KERNEL_START_NR]	= {(unsigned long)_stext, "Kernel Image Start"},
 	[KERNEL_END_NR]		= {(unsigned long)_end, "Kernel Image End"},
+#ifdef CONFIG_KFENCE
+	[KFENCE_START_NR]	= {0, "KFence Pool Start"},
+	[KFENCE_END_NR]		= {0, "KFence Pool End"},
+#endif
 	[IDENTITY_AFTER_NR]	= {(unsigned long)_end, "Identity Mapping Start"},
 	[IDENTITY_AFTER_END_NR]	= {0, "Identity Mapping End"},
 #ifdef CONFIG_KASAN
@@ -248,6 +255,9 @@ static void sort_address_markers(void)
 
 static int pt_dump_init(void)
 {
+#ifdef CONFIG_KFENCE
+	unsigned long kfence_start = (unsigned long)__kfence_pool;
+#endif
 	/*
 	 * Figure out the maximum virtual address being accessible with the
 	 * kernel ASCE. We need this to keep the page table walker functions
@@ -262,6 +272,10 @@ static int pt_dump_init(void)
 	address_markers[VMEMMAP_END_NR].start_address = (unsigned long)vmemmap + vmemmap_size;
 	address_markers[VMALLOC_NR].start_address = VMALLOC_START;
 	address_markers[VMALLOC_END_NR].start_address = VMALLOC_END;
+#ifdef CONFIG_KFENCE
+	address_markers[KFENCE_START_NR].start_address = kfence_start;
+	address_markers[KFENCE_END_NR].start_address = kfence_start + KFENCE_POOL_SIZE;
+#endif
 	sort_address_markers();
 #ifdef CONFIG_PTDUMP_DEBUGFS
 	debugfs_create_file("kernel_page_tables", 0400, NULL, NULL, &ptdump_fops);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210728190254.3921642-5-hca%40linux.ibm.com.
