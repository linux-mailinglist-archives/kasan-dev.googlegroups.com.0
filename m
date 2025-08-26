Return-Path: <kasan-dev+bncBCLMXXWM5YBBBD62WXCQMGQEO4TRZUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F11EB3567D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 10:15:13 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7ea01ed5d7csf582631285a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 01:15:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756196112; cv=pass;
        d=google.com; s=arc-20240605;
        b=V/KHwPTdwKCxivwXrzJ5idFK6RqHwED6n/Ubji9swwDxX0vQ756NDHcXxz22YJawTW
         ZIuxn1aVlPHnb3BGWrENCz78MrqSFD1XxWBLUXX3Yu3bkNq7hqXBDQ0qmK1Ji3NZTQo1
         N/kVgSOmMlyNK+aJKu06RoXIoyiyEDTEuFLQMcYbQcdBQ2OCKNos3h9daFjv7Lj4nm0t
         servZmF2jjF4C9WYlU2Zotz6324vW5TOwQyzUQPziZ4OI5WmF+HtFvg4PCvatC/4h2Vt
         hLP8yWlzu1422BJZekmsYCWSQrjKH8vt+ZZ+NlXktw41bQ6NQqZlJpDrEqkavUMHGIdQ
         cLFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H0Eey3PIW3EEx0EBzmJW5SygaXBahHjrf9hdtTqCN/Y=;
        fh=TNcF5B5go9iIvIFOijINIzkgSd3d0DnFbBzkLe1a2Gs=;
        b=KMcxdwAgW3FlbgZSwnIpQBfeGLu18WZmFVpH8W1SJ8g/glHZ7vQ532nOSu1ZaAMO5R
         LsX2jU1K58/UH6CpsVcjvTg19haCcgcCpDeGRQPMr3N36gAx1TzU8CKEn/xesWt9frIR
         qDXpz5Ovf768lBfrlvy1jcJGfDl7juKkD3LgRCkMzkj22Ru/yNmV3zbIXCezckcisKr+
         f8aEXz0Hb2uwxDTbKdiyx8NDHOUD8HGfgZuEXJhTRwbH6tJbKFJYBeqwxoNc8U+8TxlB
         E4u0QQhfOal1IxGJl9/B16toHkqkHbYyOZnyU7h7vk2y62sBpud3KT+zWVz3E/VO4Tf5
         +58Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=YT4UpLWN;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756196112; x=1756800912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=H0Eey3PIW3EEx0EBzmJW5SygaXBahHjrf9hdtTqCN/Y=;
        b=Gp7R6CAF3Bf45BI42L1Ibuipf2hhjT+2t0e/MoBhhFPS1hltnNnEjVLBD7j2JT84kc
         f4DA0xcm+POLJymNsD7kja8NGueb1pSNRg1OwcuxOLneYEqOb/I3qPuB2+5HsuiEAxwA
         26vI4dANa7Ri9tKjGUHBceBj6YYCYqEGDOySxo1R3HC/m3/fA1CXE7G0iReh4kFPUfEE
         IhUOLDM0inP1ZSgRQYCeQS9FzRTBqzX9lkeH5qFoC4Nqz6wb2o1ovbSVdzot0++qW81G
         4bdcctnqFX+sp3lCum30k4RnB0ZrUHikgYhVOr3Wo4hQl+xvR3ziJHOg9J7bxyDz2RDM
         DPPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756196112; x=1756800912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=H0Eey3PIW3EEx0EBzmJW5SygaXBahHjrf9hdtTqCN/Y=;
        b=M9E8sJz+j5oU/sON72ZDWXebRxBlRbOrqjDuCPreHI02+mFPYolc95w7LrVhSmjfVJ
         YwOmLVbkoaydDKICFB0Sywg5h2gn/SW8HJ5IJk3ZY7uVo6seujvsmGLpAPa6xokIxPry
         pNAiGR4RFDOh7T+kjhsbTMGpyy1j8P9q7pxr5As0iITVk6C2un6wo0DZ9VuNp8fwImF4
         RwX1Np8NO9YlO7NNJUoNDkoMslhejJ1HIYE0uKkeFO2kTrckPjoddOe70Yd9dv7mN1AW
         o9DeftaoEezo7noTg1589suD8YjM2VpaNw9z5MF9aqUk9WypMSb6+yGW4WdlGX4F/KQq
         wSEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVO7cEEEAu3A5gL680Q1jCKl3LpzCWPPtPSkqb2yJXV2h4z/FaO7F0PfmF0/luv5f5XygsC2w==@lfdr.de
X-Gm-Message-State: AOJu0Yzdy9+1RVqBYRtU/9zUUzFcGEd9WoNTw9eYCf5Z5PVHZdGajM/M
	PTt5V/7EO38fUWQZOxE0d8FOcGPoxXKj2cuK1coH/Q2liP41X/aycDN2
X-Google-Smtp-Source: AGHT+IGh/O+lxLZy5+Z/rhU6XiFsrpy7xzk12g9kJ+Y4NF7DMmxkZM2nnPk+GzNCOcgdSEzH/LmgGg==
X-Received: by 2002:a05:622a:1b0c:b0:4b1:1793:6beb with SMTP id d75a77b69052e-4b2aaa6efa1mr155254811cf.34.1756196111966;
        Tue, 26 Aug 2025 01:15:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZdWkhb+SvwTl9Hoxw/W8oJFPjOKY7qT5x0akh81ifPA==
Received: by 2002:ac8:5850:0:b0:4b0:96d1:cd63 with SMTP id d75a77b69052e-4b2c4bd6e22ls40284601cf.2.-pod-prod-08-us;
 Tue, 26 Aug 2025 01:15:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiui8GxQutwVGse+Dr5I3WJrB1BRNBhIgIv/lFU4hsKg+cBjWjl/6bZTPI7VkJSmkePNWAlABAhsU=@googlegroups.com
X-Received: by 2002:a05:620a:f05:b0:7e8:902c:7f90 with SMTP id af79cd13be357-7ea10f743a9mr1705147585a.15.1756196110980;
        Tue, 26 Aug 2025 01:15:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756196110; cv=none;
        d=google.com; s=arc-20240605;
        b=j+MitOjl/FEy37EM2eA7Bpq1SzbtfvdEPHdqnRFpHvws8OKYNtd409jmKoGUpLZ/eD
         Y6uu5S3o/eazNRUrQyCVhErZNw6TeWFa2N0wmjwxYTzqAr8D0WfAGGAm3cQ57/l/CMjx
         25khFqRzchBvD5IBGwk4qBZNe8mWaVNB91DG6n3N2/kkDgxw6ipuIYXEPdQOhzNVngXZ
         A0f4VBSubjNCD7VXmX6tZXeGejI8wQTMi6q5F7PcGqzhqHSpylDxxUlkYIceud5ZbGgv
         F/savfHsF1GTj0gUIGWpFgKitK5fdaHP1nF1yK+iHuJ3Zwvm4zGEW4fxOIbeP5PGc5mD
         NvPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QkrFFeLETaqUcgl2RWu3Vm4u63U+mrGd37t/D0+7cP0=;
        fh=893+WHAtf5KZmJcmDQX+R0tPo74j8bwx3ZbRHLc+E/M=;
        b=Ref744w/F53X+TocAG9tP4kWu2IGYiQdnOd6Ibo2SRIFtUqH8I3olTIunrUOnbgLL5
         m6SFZXsdcWD0gqURIhQS1DERGdVgWx8X1WVc+cxGwHbnXQ1eF7OUIyY4voudfy9Rm5Od
         sZnFvlcnmuxQKdc9aVSjaSIDJQ/cESTtA3kkFPNLIKFyA6wtLVZ2nZrZH9ScQ06Cx6+R
         nJelGO5QY7xCvsxpQsORePUPhEIY/SX+mPGNPcutv012rXgzPt6ILxqIsEPQ1fNaAoZa
         g/cqga1PuxXabT6+gQ7cU8iTT44RIJsWlKp0IK9rVGrlOmbXVubfYoPYxRZPTXOKCubp
         bhVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=YT4UpLWN;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7eeb4416f99si24308385a.3.2025.08.26.01.15.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 Aug 2025 01:15:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279866.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57Q4MQS0020705;
	Tue, 26 Aug 2025 08:14:55 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 48q6x882ee-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 26 Aug 2025 08:14:54 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 57Q8Er0W014651
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 26 Aug 2025 08:14:53 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1748.24; Tue, 26 Aug 2025 01:14:50 -0700
Date: Tue, 26 Aug 2025 16:14:47 +0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Alexander Potapenko <glider@google.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        <x86@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
        Aleksandr Nogikh
	<nogikh@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Borislav Petkov
	<bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Ingo Molnar
	<mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>,
        Marco Elver
	<elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
        Thomas Gleixner
	<tglx@linutronix.de>
Subject: Re: [PATCH v4 05/10] kcov: x86: introduce CONFIG_KCOV_UNIQUE
Message-ID: <aK1s9zuF72Ga36JR@hu-jiangenj-sha.qualcomm.com>
References: <20250731115139.3035888-1-glider@google.com>
 <20250731115139.3035888-6-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250731115139.3035888-6-glider@google.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: oQoaVk98TRuas7EobfPX8KtPJfo6az_l
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDA0NCBTYWx0ZWRfXywhCum6fZjGw
 RmYCSlBXOvkn6xV8cteZ/Cw3qCzKpjVxc+FwRC7RiAQDW7P/Cgh7Ran100r3fdUp2W+bneWSkK+
 h4SQR1Adg6HpusaeYsontEONr7z5HSsAhYwOpFDvTHig5eVGE6A024S5wRQOoPB4BhKswIMdVCZ
 ch+5vg69BkwzW75/X0jQ0sjfdvbeSLxdmUoKy7BfHuCeCjDip89m61NTH2HGdDJE5/J4J/EbOOM
 QmRCzYagkhxH7KF9GLjATkzxQyFw7h4SZo+ZBZ47LyohS918fwpWHSkTfmd6HeMOzlT0+G53hMr
 3vGmEi8rY/N2T3B/qC1MwPjZBS3X0YZ+PSf53zv6I1Sy9tW17bsYW/hbZNJ6iZpM9q19CUiA0Hj
 +qwOqN/w
X-Proofpoint-GUID: oQoaVk98TRuas7EobfPX8KtPJfo6az_l
X-Authority-Analysis: v=2.4 cv=Ep/SrTcA c=1 sm=1 tr=0 ts=68ad6cfe cx=c_pps
 a=JYp8KDb2vCoCEuGobkYCKw==:117 a=JYp8KDb2vCoCEuGobkYCKw==:17
 a=GEpy-HfZoHoA:10 a=kj9zAlcOel0A:10 a=2OwXVqhp2XgA:10 a=Twlkf-z8AAAA:8
 a=VwQbUJbxAAAA:8 a=1XWaLZrsAAAA:8 a=5XT1vE8ebdrwWjwh30IA:9 a=CjuIK1q_8ugA:10
 a=gIUsDA97qKwA:10 a=-74SuR6ZdpOK_LpdRCUo:22
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-26_02,2025-08-26_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 clxscore=1011 spamscore=0 adultscore=0 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 malwarescore=0 impostorscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2507300000 definitions=main-2508230044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=YT4UpLWN;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
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

On Thu, Jul 31, 2025 at 01:51:34PM +0200, Alexander Potapenko wrote:
> The new config switches coverage instrumentation to using
>   __sanitizer_cov_trace_pc_guard(u32 *guard)
> instead of
>   __sanitizer_cov_trace_pc(void)
> 
> This relies on Clang's -fsanitize-coverage=trace-pc-guard flag [1].
> 
> Each callback receives a unique 32-bit guard variable residing in .bss.
> Those guards can be used by kcov to deduplicate the coverage on the fly.
> 
> As a first step, we make the new instrumentation mode 1:1 compatible
> with the old one.
> 
> [1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
> 
> Cc: x86@kernel.org
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
> v4:
>  - add Reviewed-by: Dmitry Vyukov
> 
> v3:
>  - per Dmitry Vyukov's request, add better comments in
>    scripts/module.lds.S and lib/Kconfig.debug
>  - add -sanitizer-coverage-drop-ctors to scripts/Makefile.kcov
>    to drop the unwanted constructors emitting unsupported relocations
>  - merge the __sancov_guards section into .bss
> 
> v2:
>  - Address comments by Dmitry Vyukov
>    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
>    - update commit description and config description
>  - Address comments by Marco Elver
>    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
>    - make config depend on X86_64 (via ARCH_HAS_KCOV_UNIQUE)
>    - swap #ifdef branches
>    - tweak config description
>    - remove redundant check for CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD
> 
> Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
> ---
>  arch/x86/Kconfig                  |  1 +
>  arch/x86/kernel/vmlinux.lds.S     |  1 +
>  include/asm-generic/vmlinux.lds.h | 13 ++++++-
>  include/linux/kcov.h              |  2 +
>  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
>  lib/Kconfig.debug                 | 26 +++++++++++++
>  scripts/Makefile.kcov             |  7 ++++
>  scripts/module.lds.S              | 35 ++++++++++++++++++
>  tools/objtool/check.c             |  1 +
>  9 files changed, 126 insertions(+), 21 deletions(-)
> 
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 8bed9030ad473..0533070d24fe7 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -94,6 +94,7 @@ config X86
>  	select ARCH_HAS_FORTIFY_SOURCE
>  	select ARCH_HAS_GCOV_PROFILE_ALL
>  	select ARCH_HAS_KCOV			if X86_64
> +	select ARCH_HAS_KCOV_UNIQUE		if X86_64
>  	select ARCH_HAS_KERNEL_FPU_SUPPORT
>  	select ARCH_HAS_MEM_ENCRYPT
>  	select ARCH_HAS_MEMBARRIER_SYNC_CORE
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> index 4fa0be732af10..52fe6539b9c91 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -372,6 +372,7 @@ SECTIONS
>  		. = ALIGN(PAGE_SIZE);
>  		*(BSS_MAIN)
>  		BSS_DECRYPTED
> +		BSS_SANCOV_GUARDS
>  		. = ALIGN(PAGE_SIZE);
>  		__bss_stop = .;
>  	}
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index fa5f19b8d53a0..ee78328eecade 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -102,7 +102,8 @@
>   * sections to be brought in with rodata.
>   */
>  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
> -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> +	defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
> +	defined(CONFIG_KCOV_UNIQUE)
>  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
>  #else
>  #define TEXT_MAIN .text
> @@ -121,6 +122,16 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
>  #define SBSS_MAIN .sbss
>  #endif
>  
> +#if defined(CONFIG_KCOV_UNIQUE)
> +/* BSS_SANCOV_GUARDS must be part of the .bss section so that it is zero-initialized. */
> +#define BSS_SANCOV_GUARDS			\
> +	__start___sancov_guards = .;		\
> +	*(__sancov_guards);			\
> +	__stop___sancov_guards = .;
> +#else
> +#define BSS_SANCOV_GUARDS
> +#endif
> +
>  /*
>   * GCC 4.5 and later have a 32 bytes section alignment for structures.
>   * Except GCC 4.9, that feels the need to align on 64 bytes.
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 2b3655c0f2278..2acccfa5ae9af 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
>  #endif
>  
>  void __sanitizer_cov_trace_pc(void);
> +void __sanitizer_cov_trace_pc_guard(u32 *guard);
> +void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
>  void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
>  void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
>  void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 5170f367c8a1b..8154ac1c1622e 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -194,27 +194,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>  	return ip;
>  }
>  
> -/*
> - * Entry point from instrumented code.
> - * This is called once per basic-block/edge.
> - */
> -void notrace __sanitizer_cov_trace_pc(void)
> +static notrace void kcov_append_to_buffer(unsigned long *area, int size,
> +					  unsigned long ip)
>  {
> -	struct task_struct *t;
> -	unsigned long *area;
> -	unsigned long ip = canonicalize_ip(_RET_IP_);
> -	unsigned long pos;
> -
> -	t = current;
> -	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> -		return;
> -
> -	area = t->kcov_state.area;
>  	/* The first 64-bit word is the number of subsequent PCs. */
> -	pos = READ_ONCE(area[0]) + 1;
> -	if (likely(pos < t->kcov_state.size)) {
> -		/* Previously we write pc before updating pos. However, some
> -		 * early interrupt code could bypass check_kcov_mode() check
> +	unsigned long pos = READ_ONCE(area[0]) + 1;
> +
> +	if (likely(pos < size)) {
> +		/*
> +		 * Some early interrupt code could bypass check_kcov_mode() check
>  		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
>  		 * raised between writing pc and updating pos, the pc could be
>  		 * overitten by the recursive __sanitizer_cov_trace_pc().
> @@ -225,7 +213,40 @@ void notrace __sanitizer_cov_trace_pc(void)
>  		area[pos] = ip;
>  	}
>  }
> +
> +/*
> + * Entry point from instrumented code.
> + * This is called once per basic-block/edge.
> + */
> +#ifdef CONFIG_KCOV_UNIQUE
> +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> +{
> +	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +		return;
> +
> +	kcov_append_to_buffer(current->kcov_state.area,
> +			      current->kcov_state.size,
> +			      canonicalize_ip(_RET_IP_));
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> +
> +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> +						 uint32_t *stop)
> +{
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> +#else /* !CONFIG_KCOV_UNIQUE */
> +void notrace __sanitizer_cov_trace_pc(void)
> +{
> +	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +		return;
> +
> +	kcov_append_to_buffer(current->kcov_state.area,
> +			      current->kcov_state.size,
> +			      canonicalize_ip(_RET_IP_));
> +}
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> +#endif
>  
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> @@ -253,7 +274,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>  	start_index = 1 + count * KCOV_WORDS_PER_CMP;
>  	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>  	if (likely(end_pos <= max_pos)) {
> -		/* See comment in __sanitizer_cov_trace_pc(). */
> +		/* See comment in kcov_append_to_buffer(). */
>  		WRITE_ONCE(area[0], count + 1);
>  		barrier();
>  		area[start_index] = type;
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index ebe33181b6e6e..a7441f89465f3 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2153,6 +2153,12 @@ config ARCH_HAS_KCOV
>  	  build and run with CONFIG_KCOV. This typically requires
>  	  disabling instrumentation for some early boot code.
>  
> +config CC_HAS_SANCOV_TRACE_PC
> +	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
> +
> +config CC_HAS_SANCOV_TRACE_PC_GUARD
> +	def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
> +
>  config KCOV
>  	bool "Code coverage for fuzzing"
>  	depends on ARCH_HAS_KCOV
> @@ -2166,6 +2172,26 @@ config KCOV
>  
>  	  For more details, see Documentation/dev-tools/kcov.rst.
>  
> +config ARCH_HAS_KCOV_UNIQUE
> +	bool
> +	help
> +	  An architecture should select this when it can successfully
> +	  build and run with CONFIG_KCOV_UNIQUE.
> +
> +config KCOV_UNIQUE
> +	depends on KCOV
> +	depends on CC_HAS_SANCOV_TRACE_PC_GUARD && ARCH_HAS_KCOV_UNIQUE
> +	bool "Enable unique program counter collection mode for KCOV"
> +	help
> +	  This option enables KCOV's unique program counter (PC) collection mode,
> +	  which deduplicates PCs on the fly when the KCOV_UNIQUE_ENABLE ioctl is
> +	  used.
> +
> +	  This significantly reduces the memory footprint for coverage data
> +	  collection compared to trace mode, as it prevents the kernel from
> +	  storing the same PC multiple times.
> +	  Enabling this mode incurs a slight increase in kernel binary size.
> +
>  config KCOV_ENABLE_COMPARISONS
>  	bool "Enable comparison operands collection by KCOV"
>  	depends on KCOV
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 78305a84ba9d2..c3ad5504f5600 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -1,5 +1,12 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> +ifeq ($(CONFIG_KCOV_UNIQUE),y)
> +kcov-flags-y					+= -fsanitize-coverage=trace-pc-guard
> +# Drop per-file constructors that -fsanitize-coverage=trace-pc-guard inserts by default.
> +# Kernel does not need them, and they may produce unknown relocations.
> +kcov-flags-y					+= -mllvm -sanitizer-coverage-drop-ctors
> +else
>  kcov-flags-y					+= -fsanitize-coverage=trace-pc
> +endif
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
>  
>  kcov-rflags-y					+= -Cpasses=sancov-module
> diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> index 450f1088d5fd3..17f36d5112c5d 100644
> --- a/scripts/module.lds.S
> +++ b/scripts/module.lds.S
> @@ -47,6 +47,7 @@ SECTIONS {
>  	.bss : {
>  		*(.bss .bss.[0-9a-zA-Z_]*)
>  		*(.bss..L*)
> +		*(__sancov_guards)
This line looks like redundant?
I can boot without it both normal build and kasan build.
>  	}
>  
>  	.data : {
> @@ -64,6 +65,40 @@ SECTIONS {
>  		MOD_CODETAG_SECTIONS()
>  	}
>  #endif
> +
> +#ifdef CONFIG_KCOV_UNIQUE
> +	/*
> +	 * CONFIG_KCOV_UNIQUE creates COMDAT groups for instrumented functions,
> +	 * which has the following consequences in the presence of
> +	 * -ffunction-sections:
> +	 *  - Separate .init.text and .exit.text sections in the modules are not
> +	 *    merged together, which results in errors trying to create
> +	 *    duplicate entries in /sys/module/MODNAME/sections/ at module load
> +	 *    time.
> +	 *  - Each function is placed in a separate .text.funcname section, so
> +	 *    there is no .text section anymore. Collecting them together here
> +	 *    has mostly aesthetic purpose, although some tools may be expecting
> +	 *    it to be present.
> +	 */
> +	.text : {
> +		*(.text .text.[0-9a-zA-Z_]*)
> +		*(.text..L*)
> +	}
> +	.init.text : {
> +		*(.init.text .init.text.[0-9a-zA-Z_]*)
> +		*(.init.text..L*)
> +	}
> +	.exit.text : {
> +		*(.exit.text .exit.text.[0-9a-zA-Z_]*)
> +		*(.exit.text..L*)
> +	}
> +	.bss : {
> +		*(.bss .bss.[0-9a-zA-Z_]*)
> +		*(.bss..L*)
> +		*(__sancov_guards)
Need to include __start___sancov_guards and __stop___sancov_guards to treat them as local,
otherwise it won't boot on aarch64, error like:
Modules: module proxy_consumer: overflow in relocation type 311 val 0.

So, finally it should look like:
	__start___sancov_guards = .;
	*(__sancov_guards)
	__stop___sancov_guards = .;
> +	}
> +#endif
> +
>  	MOD_SEPARATE_CODETAG_SECTIONS()
>  }
>  
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 67d76f3a1dce5..60eb5faa27d28 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1156,6 +1156,7 @@ static const char *uaccess_safe_builtin[] = {
>  	"write_comp_data",
>  	"check_kcov_mode",
>  	"__sanitizer_cov_trace_pc",
> +	"__sanitizer_cov_trace_pc_guard",
>  	"__sanitizer_cov_trace_const_cmp1",
>  	"__sanitizer_cov_trace_const_cmp2",
>  	"__sanitizer_cov_trace_const_cmp4",
> -- 
> 2.50.1.552.g942d659e1b-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK1s9zuF72Ga36JR%40hu-jiangenj-sha.qualcomm.com.
