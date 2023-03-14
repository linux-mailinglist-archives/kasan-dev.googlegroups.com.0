Return-Path: <kasan-dev+bncBDVL3PXJZILBBNMLYCQAMGQE7QSLLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id B77ED6B8A44
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 06:27:18 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id w5-20020a253005000000b00aedd4305ff2sf15952490ybw.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 22:27:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678771637; cv=pass;
        d=google.com; s=arc-20160816;
        b=bzK1TaL7IVmoYiHT1ZOf8UZUUA6ygIaIJiI8ax9FronOJbquavIzJNZiv9bq5G1NuA
         kYN+U7kiG/hwzBgJOCw/L0kc1qfIQcIBUjbWZ6fMDAH1TFR/i/AQ+/87jYVQYBuSde4/
         DmoD6w7tK0B2rvU0LY3fUa8730qmc1ZsAPxdW+vxuMhgRFc90G7wwgGf968iXAJVclfv
         UzoeqEE94zpSKKegIIulzvlQNQGrYlzfCKCRJCIyDMggXScpsoGD5kti1BGTfVOJYmGb
         uLa80UXcD1g/j3t4RKXSqGCKqL+98PQZ4NgyWEZIHYJUj2up8fydCLBTG6qSaguJUNWT
         ggDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=eZvFqjqLWhfKNKu9PWmENBKOqFf3pK+W3EFMS59c1UY=;
        b=RKPZvnW70cxU/nFrqKvRjmVIdlTWAgL/MM66WeXQH/f/zFGBpDdZacz13yz+9XpcMa
         d9eyHqDhk5A6cDdvqTv9f4qBExmuXloBb8SAwD6FGb7bmkIDznl4iC5/peyd9KEADRyu
         SY7plcYOtpQqZNlmJLYxq8p4n0QYd5Jy+2FEyHGoynRBzkvGy4kUXe7oj3Olk8hw5usW
         3dw2xnEEaqa/2qdskeoVKh0WZe9ZL8/U4349cX7qJjprdOvDVXSoy/gEahrgq3NqK6Yl
         bi2lagkS4R0kB+jPk+I1JOJ2+WGHOfQkjAAjrpwiq6EsUz0PbxKBkgtlz+QhI1uVHRg/
         FW+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=grzBglCx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678771637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eZvFqjqLWhfKNKu9PWmENBKOqFf3pK+W3EFMS59c1UY=;
        b=NoPwQzPyzhUFIBOLKZvNdlrvSGNLdWbY7KDTysOFknnPEUrwA3J4XIfA6IgRWCw9jR
         9LjVj1+Ul6XdxsFoeD7Tlb7dfxI18N+awiL1t8ezgZTwtQQ5ISVNT9hBMdKdJptxYIG/
         Ar+Vd6W0D8jTQWqT77tqIjAVYipIf0LdBuEIR7GbDJB+EFkFR7V1oHnkm21NqXA8cAtP
         cmiJf1DwuFK7hUfmcVT+gE8FseTYa8HJ4h9H/iDZfmPGcHPpENsNzYgecDt8Todu6ITH
         tlsD9lNYHmaQL8sWFy7oGESOSDJGd/z5tMIKUrYtLhsVlnAOw+zjd1PUvSPjAa8iSvuA
         UpCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678771637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=eZvFqjqLWhfKNKu9PWmENBKOqFf3pK+W3EFMS59c1UY=;
        b=Wj5RWgXdDvZtvF8pYX44v8nGTKqST3rX7RAw8krjqef3MaTA8cLMszJZrPC4E3k+E7
         +y8pEyPcvj29/hC5+1cazv0GcEPnWrkrlaNtuGfz/hGHy8R/Fjl4ooni15eTa1cVLOXY
         btRwk1Di/4/QytZJLNDiriK01UgFTGPuPV8dFB0yGdjouJsc1sEB8u+LWCb3pPhWN2eZ
         bf6PscpL7xTKpFbZ+WeY9s13SIlgnyG0avBq82KzeP4f2iwqgkB0htwB+PpAiraOfMoK
         h2FTNoXBlvfdyr8EUt9LnAZSQN/Sz6WGxJJxh88mJs3qpT4LUWoic/gHXu3o+1fs7FGr
         27Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXgNdcEMlxvT1dOnbOPwD6MEvPIZs8oT2wGWrkfVykub2nqzijI
	n+aSnxEukBRp/5P3sz7yiRU=
X-Google-Smtp-Source: AK7set9zXiqRnduWEBHxoH8AUE9EdUAfrte42m5O5gy+mNAFfud+ZVB94/UfP87WcUAiE8iKmu1CFw==
X-Received: by 2002:a05:6902:524:b0:a0d:7f39:df83 with SMTP id y4-20020a056902052400b00a0d7f39df83mr17890868ybs.8.1678771637348;
        Mon, 13 Mar 2023 22:27:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5ec6:0:b0:b35:946e:c547 with SMTP id s189-20020a255ec6000000b00b35946ec547ls4336306ybb.4.-pod-prod-gmail;
 Mon, 13 Mar 2023 22:27:16 -0700 (PDT)
X-Received: by 2002:a5b:d07:0:b0:b30:f0da:dbd4 with SMTP id y7-20020a5b0d07000000b00b30f0dadbd4mr12703823ybp.30.1678771636759;
        Mon, 13 Mar 2023 22:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678771636; cv=none;
        d=google.com; s=arc-20160816;
        b=JrcfRWVKaYH5Ww5ZTRo+ha0GeGw6gF0QKEmLbs9CrE90FcxekWfohqGQMHu3NOr6RY
         1n7y7l9jbknBr3r+8M4GzZB6QYbJx4dzzvm1DpmHqJiqSnZtBGuP8yO55Kha1/pEN/g/
         VI8cS/01CyMIsVWRIq8EpqHhTyi6UUPR59fivOTzqRDqWV9nwtL44t0WlRJTrJZTLttw
         kmEjHlaniBLjf+SXcOxloSfz0ULpD9GNVMmCN2qapmamikfo3zVSuAD8cLUuRCnzs5bi
         RETobpd0OG7/aCB9pHC8+vfzYX6MW8CTGasuxmIBFYLZJipB3QB22PgJr5KmGwYLegHU
         vStQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TDhFd81vYdu4PpL7uxzDsKN7UxRWpp2IXOBz178vfEU=;
        b=YWrg8gpG1O5qv/cWM+cuCYkhWPD4D9EWmSwO7n4cBeW8JXHy0UalmUuW+BkQLdpUbp
         ZxjXAW74q+lOp7bzRdLbVNeHtQV4+49Okedz1uuu8Oyhk0pi5jj3mWEzAeoQHMqM2e44
         UAOmur6Xx7ypdNkSn/r0HGUIPllTAUm7vJNIfXVL9SRbRih9ZrrsF2YBnPJ2aleNqnHa
         cBvvUwuFtVB8HP41vXqaab2AjvmR5qygjNikX0u61EmdNVXY9mCIU9Lg8P+ncs7Jpffw
         QQIOXG6LHLX8uNQsKtWvGvbRZsayRxaNedCJ1MyToLeXR0W1cImHeFo00CstYABDDz8U
         EL8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=grzBglCx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id z67-20020a25a149000000b00b272e1c8acbsi69856ybh.0.2023.03.13.22.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 22:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279867.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3WNrG025296;
	Tue, 14 Mar 2023 05:27:08 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3paay393bx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 05:27:08 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32E5R7HN013612
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 05:27:07 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Mon, 13 Mar 2023 22:27:03 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v7] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Tue, 14 Mar 2023 13:26:26 +0800
Message-ID: <1678771586-13332-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: EWwki4VQwPVtiM3eeng_e1ztkXTfYMn7
X-Proofpoint-GUID: EWwki4VQwPVtiM3eeng_e1ztkXTfYMn7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_13,2023-03-14_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 mlxlogscore=999 malwarescore=0 adultscore=0 lowpriorityscore=0 bulkscore=0
 phishscore=0 spamscore=0 impostorscore=0 priorityscore=1501 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2212070000
 definitions=main-2303140048
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=grzBglCx;       spf=pass
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
---
 arch/arm64/mm/mmu.c      | 43 +++++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c |  8 ++++++--
 include/linux/kfence.h   | 11 +++++++++++
 mm/kfence/core.c         |  9 +++++++++
 4 files changed, 69 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..7f34206 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	phys_addr_t kfence_pool;
+
+	if (!kfence_sample_interval)
+		return 0;
+
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!kfence_pool)
+		pr_err("failed to allocate kfence pool\n");
+
+	return kfence_pool;
+}
+
+#else
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	return 0;
+}
+
+#endif
+
+phys_addr_t early_kfence_pool;
+
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
@@ -543,6 +571,10 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+	if (early_kfence_pool)
+		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -608,6 +640,17 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	/* Kfence pool needs page-level mapping */
+	if (early_kfence_pool) {
+		__map_memblock(pgdp, early_kfence_pool,
+			early_kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
+		/* kfence_pool really mapped now */
+		kfence_set_pool(early_kfence_pool);
+	}
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 79dd201..83f57d2 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -7,6 +7,7 @@
 #include <linux/module.h>
 #include <linux/sched.h>
 #include <linux/vmalloc.h>
+#include <linux/kfence.h>
 
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
@@ -22,12 +23,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
 bool can_set_direct_map(void)
 {
 	/*
-	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
+	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
+	 *
+	 * Kfence pool requires page granularity mapping also if we init it
+	 * late.
 	 */
 	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-		IS_ENABLED(CONFIG_KFENCE);
+	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a..f1330b6 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -18,6 +18,7 @@
 #include <linux/static_key.h>
 
 extern unsigned long kfence_sample_interval;
+extern phys_addr_t early_kfence_pool;
 
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
@@ -64,6 +65,12 @@ static __always_inline bool is_kfence_address(const void *addr)
 void __init kfence_alloc_pool(void);
 
 /**
+ * kfence_set_pool() - allows an arch to set the
+ * KFENCE pool during early init
+ */
+void __init kfence_set_pool(phys_addr_t addr);
+
+/**
  * kfence_init() - perform KFENCE initialization at boot time
  *
  * Requires that kfence_alloc_pool() was called before. This sets up the
@@ -222,8 +229,12 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+extern phys_addr_t early_kfence_pool;
+
+#define KFENCE_POOL_SIZE 0
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool(void) { }
+static inline void kfence_set_pool(phys_addr_t addr) { }
 static inline void kfence_init(void) { }
 static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
 static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..0765395 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if the pool has already been initialized by arch, skip the below */
+	if (__kfence_pool)
+		return;
+
 	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
 
 	if (!__kfence_pool)
 		pr_err("failed to allocate pool\n");
 }
 
+void __init kfence_set_pool(phys_addr_t addr)
+{
+	__kfence_pool = phys_to_virt(addr);
+}
+
 static void kfence_init_enable(void)
 {
 	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678771586-13332-1-git-send-email-quic_zhenhuah%40quicinc.com.
