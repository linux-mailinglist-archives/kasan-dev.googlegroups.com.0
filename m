Return-Path: <kasan-dev+bncBDFONCOA3EERBRWQZOQAMGQEEXSMJIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id C84DB6BCBB2
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 10:58:31 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-54161af1984sf10478497b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 02:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678960710; cv=pass;
        d=google.com; s=arc-20160816;
        b=wehXOQs7UVeuo+LDobvnat+1/F6XYnBdvg6Na5QdT78x5YvLHq1l03kHq8Ovqdgn7a
         6fhzFInH+slidJgTisxYtpv63ppXqLIdXyqbsUNX0QUG0wjatPkxoOU+ang8Jh5DkSww
         gwF0gf+L03RK6rA4dIh+xwpKqIoorWlGIOcbd+gAkGIgu1+pgcQot8YfZqZXfGEEYYkg
         TAhrWc/c1KsoMOZvT4hHayODr5z7SAGUeMng0X06TPiqLKcOZvJO8C1wsSOTb15T09+w
         BnV0lZABAxZbl7dsI+/KYPJMSTFZaxIUpsNyOQXtHovrOjtVEYD1LSlsKvFB/8lIkeSn
         liuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JhGm7vEIFRf4zhfXC+ZunGz7HKerFQw5ZfN0hwAOKJ0=;
        b=AK6QkUpP0AT8tkeG5x8/PBi6vViptvogsLq36o6BFvrAncWfCKCW8fpgTx7et1yrbk
         mqh6XOEz/E1ZMUu3YubtFAWU/sOk8dN6OW2X7KN8F+J3/Y8ShHS677Ahdv4cs9paE3jm
         Vf535nS0hfgzg8yIAPynwIWWyxfYTezdHhmeQ4JlZ07bLUkY7zXV2aBcJxV0098uScuH
         IYG/FpoIHnwLIqgD795IoA+gIoxtOEHlI+pxzmqJCwMOXdwVgqZj7xjzzl39v6SRMD58
         6CLLnHGu92VkgBxZt2m+HHlaUMQhH02iz63lM5eGxG8B+/wxB25ez3l6rTSthw85xxc3
         pruA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=D4hsQ4kD;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678960710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JhGm7vEIFRf4zhfXC+ZunGz7HKerFQw5ZfN0hwAOKJ0=;
        b=ttqYSnz6zou/J2xjDoHZgrnNpdQujFYYGpk4fhRXCtWTqOv9FNZRUpHbj0D8Sw2ypX
         xj1/Zsnv4bALhOJGvQPrRn2/xkwKxYlr3tGSpFjWGJzW67HtUpDaP0AXs3h9mj8wry0u
         g5FnTkyAXFGdaz97Yqq8AwYGJl/+ynng3D+9Jz5DvvhhK76vTqRMqUY8LPC1E+YVbxPU
         ZIR8k6jU+iT+6ZCSOjKWUMpgZIEf1H1LWq1FyKeyIm7uPcnBpKhuflQKUAc978p6aCVP
         EZR1Qhaoj/2GzWqRX7Umty7bfsnj8ur3rexyCA8By6CnzfwRO7M0e/nVNqvZ9MC+VlTt
         09rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678960710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JhGm7vEIFRf4zhfXC+ZunGz7HKerFQw5ZfN0hwAOKJ0=;
        b=qyDYnB6A7M96GPb/1K7WQviial6SofSTtz8c7BgzexkOrprq8G5Vf+dw/4D1Dw8hRc
         eqiHFmiFRPs6YKZB4ccV+i1KWB46FnuTb37PQ6cE6QYGgqETXNQDwd86pjSOYwzzrudg
         q0ASVoHJdgQfmFMmdzoPEqgNDQKTtroG8ujQE86ORGLdXMhKUtTIyWXSY8OnUFe0CNMH
         FB0MCW3R40E4uXhKeybx0hoWw2zcxdMcgMt+sEKkx5VhABcVhdvMOUZUAL+WF2dCusVN
         LJAkZsihAfnH13GuoHhi/Nsf8u/M0cQost856X6ThauaUX/HZsrY8hUtFMdvZhSd76Rf
         +FIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUEDcrooaZ7Sf6588IRr8qeV7Gbv/AzbpHy+E19BbyaL/bqWRkC
	GU5veZMn/a12d5iUyZYGp/Y=
X-Google-Smtp-Source: AK7set9wXHQHX041C3M2I0EEeg38kzTNrF//SeN7IG1KXHJCfcClWGmW+ymID6WZKKB30JxzigpOzg==
X-Received: by 2002:a81:a705:0:b0:543:bbdb:8c2b with SMTP id e5-20020a81a705000000b00543bbdb8c2bmr1793458ywh.10.1678960710468;
        Thu, 16 Mar 2023 02:58:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9a8d:0:b0:53e:849b:650 with SMTP id r135-20020a819a8d000000b0053e849b0650ls501503ywg.7.-pod-prod-gmail;
 Thu, 16 Mar 2023 02:58:29 -0700 (PDT)
X-Received: by 2002:a0d:ea50:0:b0:538:6093:3c6e with SMTP id t77-20020a0dea50000000b0053860933c6emr2944921ywe.43.1678960709856;
        Thu, 16 Mar 2023 02:58:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678960709; cv=none;
        d=google.com; s=arc-20160816;
        b=gJOX1S6Z9RXeo0j59jOaw5pqI862LJJkd4mLB2ZA37cUO38+bUtLa+Qf/luCCF8jtC
         L4t0Ldvr1P2nvyoUCoBRzQivgDuXK7fZU1DGsm+rMYk3HWqEfbY4phmi2rVYAsKCmOS+
         hB45pca5C4PQx5e+ErPSypHzLxr3Zde1Xg7oJ7s6W9R9tJElMH6lj6SQOOq0Dcud/V7U
         86y5w7acXXtEZehUoY3kXzW1H5w32ntnq9/Y6hC+TwBsXvm3JK4r8OruysYfF/BYsIOV
         HSIG0aFhwcmr9WDHeiaJxxzMhPWZEjoUY/DTj+CPNPZ92dSS0lA2Or8DvAwQXYsvLfZL
         ekww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/i8sE88y4FYJE1h5LheXEbG3SbjlercD8ty7RP0GvyY=;
        b=gauVXfY/PKHA9Fmg4n58GVCA3A/TDM+X44eNBNLNXcAyLVabb5mBKbq2dfXJnm/mwO
         hWodPa0iX0WMTTKFygBk+pje0vvhuj81GZd1yZRgWaCY7paT8L4bkcA0UlKZ+HiBUAGv
         k0HqXubU3paDz+68xmpeAFbql8WtYmNBLeVBLMY8U1xnSxafP9AXOUS/2vpWjdm5G8mK
         r6SS0gHnlpXVdtw44n9FdJrUWYEDbDxyBboZhg+hc177RJ8sVYQshkA7nmJrhR4aC2Ui
         P1JP3vgQm/qLxULLvrJHJaYSdzqOoido0FHNkzBLI6qfPXBJYbhj6/wgxG7SLA9vOZCW
         kAzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=D4hsQ4kD;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id bw10-20020a05690c078a00b005343a841489si612216ywb.3.2023.03.16.02.58.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 02:58:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279864.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G5F3cl020554;
	Thu, 16 Mar 2023 09:58:22 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpxnhedn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 09:58:22 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32G9wLOw027999
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 09:58:21 GMT
Received: from hu-pkondeti-hyd.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 16 Mar 2023 02:58:16 -0700
Date: Thu, 16 Mar 2023 15:28:12 +0530
From: Pavan Kondeti <quic_pkondeti@quicinc.com>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-ID: <20230316095812.GA1695912@hu-pkondeti-hyd.qualcomm.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 50vNI7lbbzLRFPvmqzRdmgBt9HurgfFk
X-Proofpoint-ORIG-GUID: 50vNI7lbbzLRFPvmqzRdmgBt9HurgfFk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_06,2023-03-15_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 phishscore=0 mlxscore=0 clxscore=1015 suspectscore=0
 adultscore=0 mlxlogscore=993 spamscore=0 bulkscore=0 malwarescore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160084
X-Original-Sender: quic_pkondeti@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=D4hsQ4kD;       spf=pass
 (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
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

On Thu, Mar 16, 2023 at 04:50:20PM +0800, Zhenhua Huang wrote:
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
> 
> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> gki_defconfig, also turning off rodata protection:
> Before:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:         999484 kB
> After:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:        1001480 kB
> 
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
> 
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/include/asm/kfence.h | 16 +++++++++++
>  arch/arm64/mm/mmu.c             | 59 +++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c        |  9 +++++--
>  include/linux/kfence.h          |  1 +
>  mm/kfence/core.c                |  4 +++
>  5 files changed, 87 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6..8143c91 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -10,6 +10,22 @@
>  
>  #include <asm/set_memory.h>
>  
> +extern phys_addr_t early_kfence_pool;
> +
> +#ifdef CONFIG_KFENCE
> +
> +extern char *__kfence_pool;
> +static inline void kfence_set_pool(phys_addr_t addr)
> +{
> +	__kfence_pool = phys_to_virt(addr);
> +}
> +
> +#else
> +
> +static inline void kfence_set_pool(phys_addr_t addr) { }
> +
> +#endif
> +
>  static inline bool arch_kfence_init_pool(void) { return true; }
>  
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..61944c70 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -24,6 +24,7 @@
>  #include <linux/mm.h>
>  #include <linux/vmalloc.h>
>  #include <linux/set_memory.h>
> +#include <linux/kfence.h>
>  
>  #include <asm/barrier.h>
>  #include <asm/cputype.h>
> @@ -38,6 +39,7 @@
>  #include <asm/ptdump.h>
>  #include <asm/tlbflush.h>
>  #include <asm/pgalloc.h>
> +#include <asm/kfence.h>
>  
>  #define NO_BLOCK_MAPPINGS	BIT(0)
>  #define NO_CONT_MAPPINGS	BIT(1)
> @@ -525,6 +527,48 @@ static int __init enable_crash_mem_map(char *arg)
>  }
>  early_param("crashkernel", enable_crash_mem_map);
>  
> +#ifdef CONFIG_KFENCE
> +
> +static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
> +/*
> + * early_param can be parsed before linear mapping
> + * set up
> + */
> +static int __init parse_kfence_early_init(char *p)
> +{
> +	int val;
> +
> +	if (get_option(&p, &val))
> +		kfence_early_init = !!val;
> +	return 0;
> +}
> +early_param("kfence.sample_interval", parse_kfence_early_init);
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	phys_addr_t kfence_pool;
> +
> +	if (!kfence_early_init)
> +		return 0;
> +
> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +	if (!kfence_pool)
> +		pr_err("failed to allocate kfence pool\n");
> +
> +	return kfence_pool;
> +}
> +
> +#else
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	return 0;
> +}
> +
> +#endif
> +
> +phys_addr_t early_kfence_pool;
> +
>  static void __init map_mem(pgd_t *pgdp)
>  {
>  	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -543,6 +587,10 @@ static void __init map_mem(pgd_t *pgdp)
>  	 */
>  	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>  
> +	early_kfence_pool = arm64_kfence_alloc_pool();
> +	if (early_kfence_pool)
> +		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +
>  	if (can_set_direct_map())
>  		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>  
> @@ -608,6 +656,17 @@ static void __init map_mem(pgd_t *pgdp)
>  		}
>  	}
>  #endif
> +
> +	/* Kfence pool needs page-level mapping */
> +	if (early_kfence_pool) {
> +		__map_memblock(pgdp, early_kfence_pool,
> +			early_kfence_pool + KFENCE_POOL_SIZE,
> +			pgprot_tagged(PAGE_KERNEL),
> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +		/* kfence_pool really mapped now */
> +		kfence_set_pool(early_kfence_pool);
> +	}

Why not wrap this under CONFIG_KFENCE ? early_kfence_pool can also go in
there?

Thanks,
Pavan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316095812.GA1695912%40hu-pkondeti-hyd.qualcomm.com.
