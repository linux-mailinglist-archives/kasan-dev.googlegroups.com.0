Return-Path: <kasan-dev+bncBDVL3PXJZILBB4UO2KQAMGQEVKKKQHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5520D6BECE8
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Mar 2023 16:29:56 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id z8-20020a92cd08000000b00317b27a795asf2614565iln.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Mar 2023 08:29:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679066994; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ty1ZvdVCnrPQuuEgmD7daMhhJhEiR93dUKJLWX7pQfUQcWphoIaeBoR6S0PlJ4+sLp
         f5NiVmVZAvWgoWCQ0jEKhoComApOrjLkbpM7SbsI+eCdZiyWjGNLTg9VpPmFkP3qr02t
         OGHujKuGuHhVuGtr6Lk3xB04E2ZCx98QI2ok7Rn42AtwGi6TpZOgI8Msndm7eUj/KmPa
         DLy/jbpTpjO4Py01z5u0+YDKA/RiD/xO6/am6wtdTQ8Dis6rKbhkfq2s6V+YzOct6c1S
         yfQh5oMTWXdOtG/FoFD+Fdbx5JCKrZgg6ZixmUHpc6vb2a1cH5ldMAqTK3FRU3H3hPBr
         xYUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OqlU5WMZYpXhG1FI4j0iLrrh+6MvSvZZMFoaETt2WPg=;
        b=RzjhvUbS9B6dn5MWtFhvU5s2nJS7/StSFrCJAVJJwxJLeAEkf9/2Cso+LJcwmIbuM6
         2WGdigQNRnbWRQHAFIiWUanrJllsvt3+Vue7vCJkVGlcDTsesGGkVfOxbHiX2Bkl4pEQ
         pYi2vOccX3MDZQZeFL182aVCTEne6SauXu69b+HeB1emDHm588S+lt93SuKEIwkfVdKe
         sDIEyxiiLIIq9i9gpwFGy9Gb4/e5u+jB+DqeX0H3KRXrC/gaYog6DAqpeZzZm7C+qM9+
         cswWWtyUrFB3BsSKCLXj6PWmtj0wVOW9+Jz0J2xvomMCbP92DXVF6OgW6WIHX+efJjq2
         XB6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nCkK+Gt1;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679066994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OqlU5WMZYpXhG1FI4j0iLrrh+6MvSvZZMFoaETt2WPg=;
        b=bJh7AL5s+VBJrys3jJg+wB2KLKmk9HhAKawOzrTGQDAFT5o3B35LkfgW3ceYviyn2e
         y2VJyQ7R7lPQ4RMZTflRtL+perHa1r0+VymRYP/ajdmrqAm+H185MbEm3iJVCzd2xLgT
         iJe/OKMUJGKIv66g9kcJFWX5CjqS2ScM0bxercMML6wJYp0VqV0oULrtQfdanAwnMKvq
         TGYEmPuC9VR5Bdji8b6z2ujysiOF42zaQt2IpoBNgU/rCpgVTpQj3N2iVSyvp58DBQT5
         VJU5HbhhZiIt7zHHumHA8qrjlAZAUFj2s2fhSOafwxu1rUefLtIwonr3N0I6sMzx9mx1
         ODdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679066994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OqlU5WMZYpXhG1FI4j0iLrrh+6MvSvZZMFoaETt2WPg=;
        b=7jsL/6At4H0W2YjwggL6GEDYnu/4nx6HI3NfBgFs1l7rey6k77NPKx3QVvji5Mj+CT
         NOEhNVMWh0kF5624NQDkGHlyDyEp8YWagpyRVWXiY8a7aFIfkYIToWY4/0ORxWCMcqc+
         UKP9RlIOkyr9dQsDxwud0VrtKTCCASxb1IToIivWDT3W6JOk71vQgYAD8NVEbZC3S2Zz
         ST/y3kPQYc8NEjT9QuH3aBYbHaL5lssoHXs9ad4rF7leA7/Y5EBGcvJkFl5/i089QeTr
         1hh67TsJFCXMHK36K1V7s5wS55Mnc4lbPi3Uy+FouwAGOUPt1/3Ik0IaE0aapeFx1Xsz
         98XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXU3RkOXmUehYEJ5zcc9cTq9Qx2pa4joTLT2NTmQSwm6BnwxwM6
	GJ+BErPh9npJyJC4xtfXPWs=
X-Google-Smtp-Source: AK7set9ACwT0RDBhL4zP009hRLTYc18Yh/BssIAYwQ9Xj6wXGBcRRq6VzGNRaknOTgimzaU52P5B+Q==
X-Received: by 2002:a02:b089:0:b0:3ad:e796:8e0b with SMTP id v9-20020a02b089000000b003ade7968e0bmr1531092jah.6.1679066994736;
        Fri, 17 Mar 2023 08:29:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b01:0:b0:315:e39c:90ef with SMTP id b1-20020a920b01000000b00315e39c90efls1271178ilf.6.-pod-prod-gmail;
 Fri, 17 Mar 2023 08:29:54 -0700 (PDT)
X-Received: by 2002:a92:d64d:0:b0:323:833:91e7 with SMTP id x13-20020a92d64d000000b00323083391e7mr108999ilp.23.1679066994147;
        Fri, 17 Mar 2023 08:29:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679066994; cv=none;
        d=google.com; s=arc-20160816;
        b=wWUlSR8ibeQrmUsvb+s2n+uTov2uZcmcREM/0JA2PWEVA59BbD34lz01//aQbjIue7
         a6yqAxZBlLdT6onzSj/FvaBWnPsEtRaY6YtKn5LaVa1OURH0jEW+gVBN2w0cIvQhQ/Vl
         F6MJDL4AFT5GpMQlE1OUjnorMxgEDseNq44nMGe9348sASO9fu6dgyC2YAjmpXUIVOca
         0oEQLe5dqcF7ydM2JLSBRHLW0EYxWc2klUeKpfs6iW23Ak5TqUfhgrKxMFp0TBmGiynz
         oV6w0w7xlFC5x5C+DzO6E1q4Je7fh99/49XUq7kztEisr5OkfLrkJxaz31xZ1ry8hdMr
         Av6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=D076k6zPWRFN2i7SCz+jHyacOyB6kAw7Svyl0q2RvME=;
        b=Vo1fTTilBUcJay2NFnXv2FM4e0061sNSF/FgR/lXwP5pPprkAsXVrrNTbmEWAcrhUT
         had05OABCYWR0nmIFAnHDpTZxgibZlLq8m3+IYnGS0eOT37etWPim+kYk3iWHbDV2I0C
         SlMqDDQjmWLvti00wh2X2pGjH6seYCBulxjzLNKBFRtKeWTaibZnUzKrDEimy3Iq7PeP
         Hhd52eFgA5SVtBfg+yaN/ANuLLFHAYVPjclXiwTyGLSKmsoj8VsjYufd0mcM3cEtjlv4
         WkQFCKhunkqRt2ccvsmbnQMMrA+4VAKczTOl7oVOx4vV389ZK+EsieEB5z/T2+6QkOpS
         K1JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=nCkK+Gt1;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id c20-20020a056e020cd400b00316d99c8a18si105199ilj.5.2023.03.17.08.29.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Mar 2023 08:29:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32H7X3K4002676;
	Fri, 17 Mar 2023 15:29:47 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pc624kp4x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Mar 2023 15:29:46 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32HFTjxG015778
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Mar 2023 15:29:45 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Fri, 17 Mar 2023 08:29:41 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v12] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Fri, 17 Mar 2023 23:29:34 +0800
Message-ID: <1679066974-690-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: fqCLvLGU0VKMbTvmnaOJOasdRy5VLplL
X-Proofpoint-ORIG-GUID: fqCLvLGU0VKMbTvmnaOJOasdRy5VLplL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-17_10,2023-03-16_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 phishscore=0
 adultscore=0 mlxlogscore=999 priorityscore=1501 spamscore=0 suspectscore=0
 impostorscore=0 mlxscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2303150002
 definitions=main-2303170105
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=nCkK+Gt1;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Kfence only needs its pool to be mapped as page granularity, if it is
inited early. Previous judgement was a bit over protected. From [1], Mark
suggested to "just map the KFENCE region a page granularity". So I
decouple it from judgement and do page granularity mapping for kfence
pool only. Need to be noticed that late init of kfence pool still requires
page granularity mapping.

Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
platform. Like what I've tested on QEMU(emulated 1GB RAM) with
gki_defconfig, also turning off rodata protection:
Before:
[root@liebao ]# cat /proc/meminfo
MemTotal:         999484 kB
After:
[root@liebao ]# cat /proc/meminfo
MemTotal:        1001480 kB

To implement this, also relocate the kfence pool allocation before the
linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
addr, __kfence_pool is to be set after linear mapping set up.

LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
Reviewed-by: Marco Elver <elver@google.com>
---
 arch/arm64/include/asm/kfence.h | 10 +++++++
 arch/arm64/mm/mmu.c             | 61 +++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c        |  7 +++--
 mm/kfence/core.c                |  4 +++
 4 files changed, 80 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index aa855c6..a81937f 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -19,4 +19,14 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	return true;
 }
 
+#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
+static inline bool arm64_kfence_can_set_direct_map(void)
+{
+	return !kfence_early_init;
+}
+#else /* CONFIG_KFENCE */
+static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
+#endif /* CONFIG_KFENCE */
+
 #endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..9813f2a 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -38,6 +39,7 @@
 #include <asm/ptdump.h>
 #include <asm/tlbflush.h>
 #include <asm/pgalloc.h>
+#include <asm/kfence.h>
 
 #define NO_BLOCK_MAPPINGS	BIT(0)
 #define NO_CONT_MAPPINGS	BIT(1)
@@ -525,12 +527,67 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+bool __ro_after_init kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
+
+/* early_param() will be parsed before map_mem() below. */
+static int __init parse_kfence_early_init(char *arg)
+{
+	int val;
+
+	if (get_option(&arg, &val))
+		kfence_early_init = !!val;
+	return 0;
+}
+early_param("kfence.sample_interval", parse_kfence_early_init);
+
+static phys_addr_t __init arm64_kfence_alloc_pool(void)
+{
+	phys_addr_t kfence_pool;
+
+	if (!kfence_early_init)
+		return 0;
+
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!kfence_pool) {
+		pr_err("failed to allocate kfence pool\n");
+		kfence_early_init = false;
+		return 0;
+	}
+
+	/* Temporarily mark as NOMAP. */
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
+	return kfence_pool;
+}
+
+static void __init arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
+{
+	if (!kfence_pool)
+		return;
+
+	/* KFENCE pool needs page-level mapping. */
+	__map_memblock(pgdp, kfence_pool, kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+	__kfence_pool = phys_to_virt(kfence_pool);
+}
+#else /* CONFIG_KFENCE */
+
+static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
+static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
+
+#endif /* CONFIG_KFENCE */
+
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
 	phys_addr_t kernel_start = __pa_symbol(_stext);
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
+	phys_addr_t early_kfence_pool;
 	int flags = NO_EXEC_MAPPINGS;
 	u64 i;
 
@@ -543,6 +600,8 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -608,6 +667,8 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	arm64_kfence_map_pool(early_kfence_pool, pgdp);
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 79dd201..8e2017b 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -11,6 +11,7 @@
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
 #include <asm/tlbflush.h>
+#include <asm/kfence.h>
 
 struct page_change_data {
 	pgprot_t set_mask;
@@ -22,12 +23,14 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
 bool can_set_direct_map(void)
 {
 	/*
-	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
+	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
+	 *
+	 * KFENCE pool requires page-granular mapping if initialized late.
 	 */
 	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-		IS_ENABLED(CONFIG_KFENCE);
+		arm64_kfence_can_set_direct_map();
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..5abc79f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,6 +814,10 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if the pool has already been initialized by arch, skip the below. */
+	if (__kfence_pool)
+		return;
+
 	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
 
 	if (!__kfence_pool)
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1679066974-690-1-git-send-email-quic_zhenhuah%40quicinc.com.
