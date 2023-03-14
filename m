Return-Path: <kasan-dev+bncBDFONCOA3EERBK5OYGQAMGQEQHHN7BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC3D96B914C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 12:14:52 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id s15-20020a170902ea0f00b0019d0c7a83dfsf8669668plg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 04:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678792491; cv=pass;
        d=google.com; s=arc-20160816;
        b=jc+5H/3Hl1B+9d1yvnQUC3B92tmGMBFjvxjwvvQ0czUl0CwPzl7IigHvOHULuOQcKb
         SpxUOHgMZXOzjbzI3wODUxfAXDmx0//S1teaVLajZeoDbOIH/NbuoaNjJ8PDc+pZh5Au
         mkN8VhvXZJ4v4ZVYQRAUC+qXuAkIrVxwyFmJ5ZbcqIphsEUJnM8y08p4mipRM5oLMrHw
         epHAqzG5zRxk/2NF/m3GEbwcyuIkz0S2adDHBaaC5ijUO+EazigoMPLs0/6SCoOl2c9J
         BxLiJWk2tFas1Ys4L6Zf1M2L8Rugt4byp5uegQewBEEnTSIjTpxrpzAfN051/+cnK4Q2
         Bsvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=opO5/GUlUshYmFr5fGJ0KuziIJ4ythzThL4Pj2dEZmM=;
        b=woI7WNYnQXs8SjFXUjnhqfm9XRBY209tKUtfH/y4E3aL9nfNJz0bP5fPEIjvgXqHlu
         R4suzuYntLPnolMTFOJfcUtHym8FCa7ij7+oVkAwEudAZ5lsFbXUn6qWiDACb2PMl3Tc
         i1r+6u29LrwzbpzyUym16nquHMDyXFQNF0daYv7j4CabSBi8mhrs7MUQqx/G3VUm6LBI
         UBBdVKZIJuZvgG34dbvksMB/uAXWLKbZd+ylE66SUbiu707dbdnsszovegDh+ruF7LG5
         ZFHPOL5ICcdCN0R4I2zm1f/ETFUq6qpySXlIJCPltvCXRCHN0paeNKwUhDCLHVS7EsKI
         Kp2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=i8Huf3pr;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678792491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=opO5/GUlUshYmFr5fGJ0KuziIJ4ythzThL4Pj2dEZmM=;
        b=WDcKenF7eDF9etTLwm/v4C6BZVUxbVZADTBdjYGG7yXY8DkhH62g3nXCvhs+tUOhbq
         Dt5p0aXTBN6tXL6ewbxg3Q+eLX2q7BKMjWBjew2QjzQ5cUvmf2KGFhgR8KBlMPkmoCV2
         XZ/ATDeKd8IgcYT+HSSy0FyQFjdFT9kb5SfEw0jq7+KRNzGcQqrtyJ6Kxb4KPQ1j6b2i
         Fgo19AJpPUB53vXWQQ5YToBkH+D7mSs4L3OxSnz8qAr8ZaPxaTXpYPwiNyvMI3qMq9Ue
         zzTMeBjLSMj9O8dvpxcdgMFCF5VEboyZ/4qoWvU8qEB2GID8/VqoCnhfyDBvKCMl+AuM
         TM1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678792491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=opO5/GUlUshYmFr5fGJ0KuziIJ4ythzThL4Pj2dEZmM=;
        b=tXi+s7JZoWLXa3M4XVGCXE/VNRq1SGzjsp+tZ5nh39xbLMmoGLQIf8zUPkucHoVag7
         TVJFZm+3c8HAgQeXthXjJQVqTRUuG5VVgWozxjpYEqfjsSZoFrPZrC3aNOZ0r0TO+lmE
         w3Q9nsnZM8NKrDLgbGywgBXz17pRUz1LF+ZEMnbz01Lm1+GDn+y70FhYrtNaB8yP88lc
         HK6ZFSKmuTc/VOHgxmiUZ1ZTeEJaYj0JRMYL2gkOWpc+q9ls0bBzPNRjD2SuWw+YvKMX
         VHldSX+xKQqApw3XjVA6+RfbJvGAj+y4rfmubEFWJWPnz5e/5jBvFdbiSO6lHCU/FO6z
         W1AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWvZ+mZB/Ju7oRGM7z7UfYAwvA5RepisHvP7WlF5u6YbhPpWJKy
	684Q0RsnLzE/80gMqmwZH8w=
X-Google-Smtp-Source: AK7set8Dw0IC6kwnN8m0C6KBlrL9SiTjd0QHdu9DX1ExDWSzTP/sDN96CI91a9bD71eUb3BsTHU+tw==
X-Received: by 2002:a17:903:3410:b0:19f:3cc1:e3c3 with SMTP id ke16-20020a170903341000b0019f3cc1e3c3mr3128218plb.12.1678792491268;
        Tue, 14 Mar 2023 04:14:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a394:b0:234:2ef4:2e9 with SMTP id
 x20-20020a17090aa39400b002342ef402e9ls13191586pjp.0.-pod-control-gmail; Tue,
 14 Mar 2023 04:14:50 -0700 (PDT)
X-Received: by 2002:a17:902:d483:b0:19a:95ab:6b38 with SMTP id c3-20020a170902d48300b0019a95ab6b38mr47523939plg.1.1678792490449;
        Tue, 14 Mar 2023 04:14:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678792490; cv=none;
        d=google.com; s=arc-20160816;
        b=fal5Xu8BIDMU/OPnPkfOPTexBYwJesfdxNP9S1egn0BQKgFVe1qzwWbsU37Rk3mBIz
         RyT7oXk59z67QGcAo4hIwZNlerwWTyGwPvh/i/+6cjeLHbXB70PsywiEjbqiYzw6rTYZ
         /hyI5cwIdrTVM9O6KpQ8pURkRVqxFHClrIcCQw6NyEHivM0Eb/OSkAOmNqyHbBs2Tr+u
         yhW1GBeLLcfUANSv8px7ZH/p0ToFTS5aFI9Npi387yexgtdJ9lG5wqEV+gKEIqXYctHa
         Ov6yxh/9ygSOf2YZhZY49pj+p0BwFljJG4IShcgkE7pLhn9sG1p8noMQY61+h96Kecny
         ZP7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VujrT43HB6fJ6xXNFPnzBFZqIlXJL3kJIrIgS+iVKd8=;
        b=uAVXqBnXg/eFpfwJKdlEi9MxSLrdIm3+n+dR1N5J17+UcJ4oo8Ntcf93frA1Bajd1l
         CqqjKM0Ftr+WLdoyGjfG7MRzxbSNWHAcR+tpywE3AWHe0wNGRy4UdzEfl7BYWsJt0OIh
         5X3iifBHCJkG9KZpUPyiU0G4+ikJ6oxAHBvIlgaWiMu7aSTKc2Wfu2LlLUc2owQG+JP+
         h7QVeEEiULQ4kssWLVxCgnkqS+lxtdwN+Zf3hzC0g6nqYjD8VUHNznd8BkJ/7mgA/dnj
         dqLey9PdMlY/8kJD8S8FeCXF0y3jfKioPRpKliqoCBqMfCp0VdK8Ew6qYnV6flPQd5D7
         FSKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=i8Huf3pr;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id q23-20020a170902b11700b0019cc2dc4fd8si96980plr.10.2023.03.14.04.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 04:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32EASMjl010812;
	Tue, 14 Mar 2023 11:14:42 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p9yew3y90-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 11:14:41 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32EBEW4T024149
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 11:14:32 GMT
Received: from hu-pkondeti-hyd.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Tue, 14 Mar 2023 04:14:26 -0700
Date: Tue, 14 Mar 2023 16:44:22 +0530
From: Pavan Kondeti <quic_pkondeti@quicinc.com>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
CC: Pavan Kondeti <quic_pkondeti@quicinc.com>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <glider@google.com>, <elver@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>, <quic_charante@quicinc.com>
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-ID: <20230314111422.GB556474@hu-pkondeti-hyd.qualcomm.com>
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
 <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: zQqQQnlnQ1G2CzVEoY1uaOXmMFItH-8s
X-Proofpoint-ORIG-GUID: zQqQQnlnQ1G2CzVEoY1uaOXmMFItH-8s
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-14_05,2023-03-14_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 adultscore=0
 priorityscore=1501 bulkscore=0 lowpriorityscore=0 phishscore=0 spamscore=0
 clxscore=1015 mlxscore=0 suspectscore=0 malwarescore=0 mlxlogscore=878
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2212070000
 definitions=main-2303140096
X-Original-Sender: quic_pkondeti@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=i8Huf3pr;       spf=pass
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

On Tue, Mar 14, 2023 at 06:08:07PM +0800, Zhenhua Huang wrote:
> 
> 
> On 2023/3/14 16:36, Pavan Kondeti wrote:
> > On Tue, Mar 14, 2023 at 03:05:02PM +0800, Zhenhua Huang wrote:
> > > Kfence only needs its pool to be mapped as page granularity, if it is
> > > inited early. Previous judgement was a bit over protected. From [1], Mark
> > > suggested to "just map the KFENCE region a page granularity". So I
> > > decouple it from judgement and do page granularity mapping for kfence
> > > pool only. Need to be noticed that late init of kfence pool still requires
> > > page granularity mapping.
> > > 
> > > Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> > > platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> > > gki_defconfig, also turning off rodata protection:
> > > Before:
> > > [root@liebao ]# cat /proc/meminfo
> > > MemTotal:         999484 kB
> > > After:
> > > [root@liebao ]# cat /proc/meminfo
> > > MemTotal:        1001480 kB
> > > 
> > > To implement this, also relocate the kfence pool allocation before the
> > > linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> > > addr, __kfence_pool is to be set after linear mapping set up.
> > > 
> > > LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> > > Suggested-by: Mark Rutland <mark.rutland@arm.com>
> > > Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> > > ---
> > >   arch/arm64/include/asm/kfence.h |  2 ++
> > >   arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
> > >   arch/arm64/mm/pageattr.c        |  9 +++++++--
> > >   include/linux/kfence.h          |  8 ++++++++
> > >   mm/kfence/core.c                |  9 +++++++++
> > >   5 files changed, 70 insertions(+), 2 deletions(-)
> > > 
> > > diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> > > index aa855c6..f1f9ca2d 100644
> > > --- a/arch/arm64/include/asm/kfence.h
> > > +++ b/arch/arm64/include/asm/kfence.h
> > > @@ -10,6 +10,8 @@
> > >   #include <asm/set_memory.h>
> > > +extern phys_addr_t early_kfence_pool;
> > > +
> > >   static inline bool arch_kfence_init_pool(void) { return true; }
> > >   static inline bool kfence_protect_page(unsigned long addr, bool protect)
> > > diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> > > index 6f9d889..7fbf2ed 100644
> > > --- a/arch/arm64/mm/mmu.c
> > > +++ b/arch/arm64/mm/mmu.c
> > > @@ -24,6 +24,7 @@
> > >   #include <linux/mm.h>
> > >   #include <linux/vmalloc.h>
> > >   #include <linux/set_memory.h>
> > > +#include <linux/kfence.h>
> > >   #include <asm/barrier.h>
> > >   #include <asm/cputype.h>
> > > @@ -38,6 +39,7 @@
> > >   #include <asm/ptdump.h>
> > >   #include <asm/tlbflush.h>
> > >   #include <asm/pgalloc.h>
> > > +#include <asm/kfence.h>
> > >   #define NO_BLOCK_MAPPINGS	BIT(0)
> > >   #define NO_CONT_MAPPINGS	BIT(1)
> > > @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
> > >   }
> > >   early_param("crashkernel", enable_crash_mem_map);
> > > +#ifdef CONFIG_KFENCE
> > > +
> > > +static phys_addr_t arm64_kfence_alloc_pool(void)
> > > +{
> > > +	phys_addr_t kfence_pool;
> > > +
> > > +	if (!kfence_sample_interval)
> > > +		return 0;
> > > +
> > 
> > Are you sure that kernel commandline param are processed this early?
> > AFAICS, start_kernel()->parse_args() process the kernel arguments. We
> > are here before that. without your patch, mm_init() which takes care of
> > allocating kfence memory is called after parse_args().
> > 
> > Can you check your patch with kfence.sample_interval=0 appended to
> > kernel commandline?
> > 
> 
> Thanks Pavan. I have tried and you're correct. Previously I thought it's
> parsed by the way:
> setup_arch()->parse_early_param(earlier)->parse_early_options->
> do_early_param
> Unfortunately seems not take effect.
> 
> Then the only way left is we always allocate the kfence pool early? as we
> can't get sample_invertal at this early stage.
> 

That would mean, we would allocate the kfence pool memory even when it
is disabled from commandline. That does not sound good to me.

Is it possible to free this early allocated memory later in
mm_init()->kfence_alloc_pool()? if that is not possible, can we think of
adding early param for kfence?

> > > +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> > > +	if (!kfence_pool)
> > > +		pr_err("failed to allocate kfence pool\n");
> > > +
> > For whatever reason, if this allocation fails, what should be done? We
> > end up not calling kfence_set_pool(). kfence_alloc_pool() is going to
> > attempt allocation again but we did not setup page granularity. That
> > means, we are enabling KFENCE without meeting pre-conditions. Can you
> > check this?
> 
> In this scenario, early_kfence_pool should be false(0) and we will end up
> using page granularity mapping? should be fine IMO.
> 

Right, I missed that hunk in can_set_direct_map().

Thanks,
Pavan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230314111422.GB556474%40hu-pkondeti-hyd.qualcomm.com.
