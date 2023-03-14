Return-Path: <kasan-dev+bncBDFONCOA3EERBLPEYCQAMGQEGAWCCMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id AB3426B8D79
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 09:37:03 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id cp21-20020a17090afb9500b0023c061f2bd0sf2464863pjb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 01:37:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678783022; cv=pass;
        d=google.com; s=arc-20160816;
        b=gIvo9yRNHCfgFDQ7FIwljLEgGKZGzVZKkCbcdAhHt9ODkHsbwPdAwwKzsoou650r98
         WzO1H/ry9nG1oCo5NqOk8JNaCNUKR7DY51JSVLLoX1EFChpqRtQl+QJ9av2ClGsx/tPl
         4OKjTC3MWv1Ac8fTATGPH8+oXFArm7IRuCxD783V4n26qery+z196AgjqZcbPx3U3ZRt
         Qj74OoJYQknks09vddivBFkDmPphFTkIXlAutDVANRUaDmu5RrD7gdi4ce2wYj4f0nG4
         /FB/DtA22nnWVUXUBdMVnrrx5NwrGQtuL8KU35H3+WE6Fn6mCh7ox9oDJl4bpZ/zZqSl
         O4Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=m/XMmdVQFiKIkesW6mPPBMNRJbnqm047QHe92FFNIlc=;
        b=DFDq4kRCpnf6qss73rvKozCel/od5BboulV0rL73SERnEDSQWmTlwwqpZFIFFat4Q1
         odNTeCU6ispWWtnuHNWeCi00V8y0wuCLjIcr3J7fzdk8exZc0EYLX3Xo57hh7CwuWr2Q
         iA/x+uBnMtge8326kHOmZyqi1cDgBwFX79Qy63Yedn2S755shux/rOroA/dMcVvqz9FY
         AGjBNqKeZN4hKGDFdy2uAwT50DOpjQVIEhHtjYXzqBAn6Th+5GXO74Du8MYrLmORuUGO
         sGB/wjlNT8S5Q4P24nS/srDB1U+DjE/Qks8DArFNfas3dqYcXs2KapLd6Z3Fwala0E7H
         9qxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZFrEdbrt;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678783022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m/XMmdVQFiKIkesW6mPPBMNRJbnqm047QHe92FFNIlc=;
        b=Zzmx3fPE3BMOfgioNwiVd4MWkb0Kuqd1hlapxArDvaI031CdJ5q49B+4MK2SL+pUo3
         Wfa9yQzOtZ+4cn71J/3XNNh97EfSu8ji3IJxvNntFCb7D1Grk2Jeti1XA0trMSkdaelp
         QRlpb7N1IfKW6Mswy8go4jnganzx4My5l/fuqyqqiyzq3qrcXZukGvXElNmJygphSETM
         er/LzuibSKso4AP4piL9POADginKPG3RrJUyTRGY0iWeUYuPiTN6Ivwv6Ud6FQQV0rU/
         MWOxrSp9ECZivg360XKSHb/2X4kJlInkF/Rro9ntydty/9Cnrb5SkUo1vYHuI/Qpm7Bi
         EDfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678783022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m/XMmdVQFiKIkesW6mPPBMNRJbnqm047QHe92FFNIlc=;
        b=SGsgxEG79KDfO5K4zDjuZCYhqu6V+u63ciKQmwI0spCYcYwB0TqzZGxVZdH2Gg2kMk
         IU7tvE4TzqG03LLHL4p0+VJLe1ySHV4gik8A9s4VzGKcwPuyYk84h7jfQ3OqBrY4gmCc
         ZuSv7vNoLfwm8EQxxyP4afWXmGSlbJ1BGM1lWjeOu3ZAog6+NN0x3QG6HVdFoZgpZ6/8
         ODoi1dnsZ3TCqu9WMIRK/U9rz2dtQHoB65htg1QR3DuYR1QRNzNGABCycIVR5UKLFvuy
         dq0LnQXp521uBG6oHHIwQ7wrUilz7WhZ0XrA6hyG1dCcQFxvbc/NdsrtQ8ttIWiStdwO
         cvZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWi2on+O2P08sRl6cRAw9Ak7qHyifPAqhTgcUPR/wxo0331Ol4k
	f6a+jWnx/OtvNKoZ+pjAZZQ=
X-Google-Smtp-Source: AK7set8ImUzRyAAImmVDfWUe7GJI+uRE+YZQHAVO2SpISndOuztV+P/K+e5CJpXWx8CqEN/dwAKGdg==
X-Received: by 2002:a17:903:4308:b0:1a0:6000:7fce with SMTP id jz8-20020a170903430800b001a060007fcemr1180844plb.3.1678783021986;
        Tue, 14 Mar 2023 01:37:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5ac7:b0:237:7ef0:5b8 with SMTP id
 n65-20020a17090a5ac700b002377ef005b8ls15221990pji.3.-pod-canary-gmail; Tue,
 14 Mar 2023 01:37:01 -0700 (PDT)
X-Received: by 2002:a17:90b:1d90:b0:233:cd29:f168 with SMTP id pf16-20020a17090b1d9000b00233cd29f168mr38308895pjb.24.1678783021070;
        Tue, 14 Mar 2023 01:37:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678783021; cv=none;
        d=google.com; s=arc-20160816;
        b=K1icWkiMfI59MrwE6dO2SJPQj3FL7TNFW4/q3tzjsN5EaxCrJ9+cMU8HYw43J8ntrZ
         9jxZMkLPkjCrtlG32KZ2FtRe1v0WkhoFP/D9gYjGVH/9v625v8y7M7ib5J32yL81cBDg
         nAjw11H72gpbbFASBmfPhMPlj/ib2wMORHbal72i5pCxFlVS/KKoTggpgawfjKHoQaz8
         asSZR/odKhU1F9gTO2wjc2QHUc+jhCUsbxyTTirKteHohKn2Xt0am0mfNTmXh3hfSe0s
         2sdTAk4YKO8PSFpdZw7EGJ9K20Wqi4k3BFafxNsaDO5SkS+E85ZfN3c6zclhoK32c6PJ
         Ykrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=C84AymT5YACNpIpMYeYeDQHf7rfGkELQaUTQMnPM7QM=;
        b=h7tir5EA+b1htC2OblHFFjjBJByixBCJ2DkqU6lA5/vWl9AbZC/mce7SbzWrX0ohKB
         xe7NyT43VXhOxaOKEMir0HLGpIsC6sgruIEsaKkVI4ZWjdk8e4gCIt3gYpJS/BDYmaDk
         i51IzHqmVQJ8yFrbmTESWoEjv96woemY1GaX8jjvKtdnhz/wUnCMPNMFFHzcseahSHpi
         /TgXPjy20CAWVQ96CVtXdbDWbGWnMliGjdoHAbVNnLXHRFhIWlGZaiI/aIHK6DNFEKt3
         6WpA4HOVAHAlUKGT3UgD+fpR+aeaB4WZgJ2E3kYCzjpwkhbDiV9llxhmXQWtqg1JFyLo
         lwvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZFrEdbrt;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id n2-20020a170902968200b0019d20d70d5dsi81969plp.4.2023.03.14.01.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 01:37:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3X9vB012826;
	Tue, 14 Mar 2023 08:36:56 GMT
Received: from nalasppmta02.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pa6n32ark-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 08:36:56 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA02.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32E8atuQ012235
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 08:36:55 GMT
Received: from hu-pkondeti-hyd.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Tue, 14 Mar 2023 01:36:49 -0700
Date: Tue, 14 Mar 2023 14:06:45 +0530
From: Pavan Kondeti <quic_pkondeti@quicinc.com>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>,
        <quic_charante@quicinc.com>
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-ID: <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: gQ5B3sSY4clGrGX4snFkxFU3scPb7nQ-
X-Proofpoint-GUID: gQ5B3sSY4clGrGX4snFkxFU3scPb7nQ-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-14_02,2023-03-14_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 mlxscore=0
 bulkscore=0 mlxlogscore=878 impostorscore=0 priorityscore=1501
 adultscore=0 phishscore=0 spamscore=0 lowpriorityscore=0 clxscore=1011
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140073
X-Original-Sender: quic_pkondeti@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=ZFrEdbrt;       spf=pass
 (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131
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

On Tue, Mar 14, 2023 at 03:05:02PM +0800, Zhenhua Huang wrote:
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
>  arch/arm64/include/asm/kfence.h |  2 ++
>  arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c        |  9 +++++++--
>  include/linux/kfence.h          |  8 ++++++++
>  mm/kfence/core.c                |  9 +++++++++
>  5 files changed, 70 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6..f1f9ca2d 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -10,6 +10,8 @@
>  
>  #include <asm/set_memory.h>
>  
> +extern phys_addr_t early_kfence_pool;
> +
>  static inline bool arch_kfence_init_pool(void) { return true; }
>  
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..7fbf2ed 100644
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
> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
>  }
>  early_param("crashkernel", enable_crash_mem_map);
>  
> +#ifdef CONFIG_KFENCE
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	phys_addr_t kfence_pool;
> +
> +	if (!kfence_sample_interval)
> +		return 0;
> +

Are you sure that kernel commandline param are processed this early?
AFAICS, start_kernel()->parse_args() process the kernel arguments. We
are here before that. without your patch, mm_init() which takes care of
allocating kfence memory is called after parse_args().

Can you check your patch with kfence.sample_interval=0 appended to
kernel commandline?

> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +	if (!kfence_pool)
> +		pr_err("failed to allocate kfence pool\n");
> +
For whatever reason, if this allocation fails, what should be done? We
end up not calling kfence_set_pool(). kfence_alloc_pool() is going to
attempt allocation again but we did not setup page granularity. That
means, we are enabling KFENCE without meeting pre-conditions. Can you
check this?

> +	return kfence_pool;
> +}
> +

Thanks,
Pavan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230314083645.GA556474%40hu-pkondeti-hyd.qualcomm.com.
