Return-Path: <kasan-dev+bncBCLMXXWM5YBBBP7TS66AMGQEPVUAFIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47092A10084
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:44:33 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-468f80bc82fsf104429731cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:44:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736833472; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y/rnzbSdFYdQB4YyLIoXg3wX2EolaC3LLUycAKKOFnC8jmECr2EnI2qjVysRyQXAYX
         dLPOlXo/7hC59rb9HYwEsZgwfyEt37fqX+2dbvnCX7+paxcMywwKlQgg9Q61KKT1G57Z
         Z7sqcFDj3kWq1JMbw+GIGbAbzQe/96AP3A9Ll8lQP64WUYTXil9MncAyJto/ain2oGnR
         hUiso2daRlltYabBmGx8G3Wvjkfgpi4LebEbVPa7clpoBjg/hPpsuJ+X9GUQTDuj+AKC
         i+X8cXE7f3c0WZArHtpL1lz6XyC9+NKAcu7tUBOpIVcYC1GnjOU7A80yrmEq4yf9Fsfo
         dgtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hHv3cFy4QpqrgUIdkMvUTZctLk071eKLp3Q/o6Jj8/8=;
        fh=+xPx9BXnhJLYrr7kBZd64KzYQsK7hv73isCA9RNGPzk=;
        b=Dl5T8FGN8Vto8Kysn+fiQMoXBmkaUF23YI6JxjJ97cbBUQM1HigiI+ma+97OuOC34k
         SFcY6vco5gMEdYR6VPoRRWhG6N+TAGH0cCOv1SanxS+fK/a9bULLT/m4+7hNlWtZooVp
         49QvswVu0AVJCI6y8DwfPvZPkv4CqGk+tgM07Niqaw3V8UWim3l/dF07CIjMZ5RNc+W9
         Z+wiCAt0/5lJLbRf2y2PK7J3/1UkPqTR+i0MuWEwG3NajgdEFJtbd4KbR7tO5KhdCTDl
         NmU7We1k+ZFL1/KLZwkOhROAp50m+PApD9JQzZ3a33DVm8MehzMJBIjVUdp+Rg3JQyov
         PSfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=DL0uxWQR;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736833472; x=1737438272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hHv3cFy4QpqrgUIdkMvUTZctLk071eKLp3Q/o6Jj8/8=;
        b=bKsdtMY0DnmuCxM4aDtJC4KXy2R1cbS0uz46fBll/D8FlMdyItjjTYJ5nPeQG7TKK6
         MNOxb4GLFQkQ39PVNgnykQbZ3vCTY6m5sMoP/wO/xB6rBPewK6OENtFusktDPEU05mAc
         0CgHpB15uO1FQwe1aifJA9cDVODTOrnfBXeydpvO76iAHxHQYw4YLHzr2fyz0H2pSf/R
         m4arN7A8aU3wGmwBcjXmGmi+OL6i+QWiUsz5M5GSfeRS/a+avvVm8sQN+5vx1qudODP8
         kw1+etHGMRL+hKr549aU+E41uQI435JfcBL/NxMrjrT+gDr09E5f1D0rD3JIuW9vCHfo
         vZtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736833472; x=1737438272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hHv3cFy4QpqrgUIdkMvUTZctLk071eKLp3Q/o6Jj8/8=;
        b=ZxqYa/aYPzF0OQFHX6ChsGVBOdnpiDIVIBVUM/uNyaGDqeNVGK4k6fTecSVlmv4rYJ
         p2a6njbYD/ItX/OkAXjOwTnyXthaJD1JptFwXKMOV8ggUzadoCTtDAp8v9YKIdPJ+6R8
         LHW+rRHoDOPuFfhj3CY0sWK3crHOBa0SVgTRxvSVA00Y86omqGBTYzdlHPf5IN4TIXsU
         Gi3UlT2aAKfrapPpI2y4T3hrLJa2rfKOC9NJ16+FpgdcOPYILVea3cAXFi+qe4V7r9ru
         wbT1cCOUpgM2Uca8zojKijozOTPi0swn2Z1BpOTPtnAnkWa9RVFOeKmMFoh3+iDZbmRN
         vSyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKgnUCoik/PJq7AOJmZP1jApJwrD19HKkZ7SPATOCojkI1Oqof9Plz2LTyXJF2iCroqN4CKw==@lfdr.de
X-Gm-Message-State: AOJu0Yx2N5M8ZInbgBzdSxOWtd398IQqP8pL+Xcl+i0eP0+sEWfa1Sks
	h/FvoUHsPJr1LzOpLpfLRG0NZxMGo/L2ho6pNLrXh4LnUZxOa7Av
X-Google-Smtp-Source: AGHT+IGnM5InPXVGyaZessSm7phPzUecciqQFmf0yhGCgxFr3mtGt7KG77hFBDEgBAgMQoEv9z3xuA==
X-Received: by 2002:ac8:5ac5:0:b0:467:43c1:f0ea with SMTP id d75a77b69052e-46c70ff7391mr392569911cf.16.1736833472066;
        Mon, 13 Jan 2025 21:44:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:620b:b0:46d:dee4:45d6 with SMTP id
 d75a77b69052e-46ddee447d4ls32427371cf.2.-pod-prod-03-us; Mon, 13 Jan 2025
 21:44:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXNFaSpAHICZNa5K0boCvGjJUVVqlGgJnns7SGfUcpkwIMoJUI3R4YMktjWwQBMi8d6T2jV9cqn8sE=@googlegroups.com
X-Received: by 2002:a05:620a:5dd9:b0:7be:2a68:6d79 with SMTP id af79cd13be357-7be2a686e05mr1394697985a.7.1736833471076;
        Mon, 13 Jan 2025 21:44:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736833471; cv=none;
        d=google.com; s=arc-20240605;
        b=YWKbo+xqbio8kenT7JdtAhrZW4h9DxFoemJiaiLptx8M1lVFG/tbXsaWVSEm8F/jvd
         ehWln15/phcG0uiKfRtjrZXC9qX9rzBR/JtTtsx0Qawx7CTMkZNqlW0Umzitfiz5IKn6
         nYDxYmC7XFKGdSJvhBvwST3seSTjp+bGwgJC7ZABFwTb6ZGvYLzoW4aalFhsG6ytLRIw
         Eo5BBfGCoquWejnOJbQgtO4kM+/4w8vuvVe3INqkT+O5Tp9tETOlYMb8fqHvIdXTmbIG
         bCNZHVYslQnLy54KqAo2GSNV7WhybtxULfpbJxwhoWGQHywsVTKynQzO7rnQMZH/+FLH
         OP9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1Ho/hzWqKaR7WmES103bnR+aCJ3CIJMTmRLpOr/yJsM=;
        fh=uGTHsIKaz8kalQlwssCp2W92aqGOEbs5Q3TkU3Es+J8=;
        b=AhqOUwdXOPXmG1P/eL/XIAMTTCT+AUtCVDp1hePtfRXt8FGFEttn9oLQ2i43vbh5jF
         akkN0nHExglp2Zo4uqIusUcGzPxE+XbQwJuxoE5Zv2HOK1Gp0pRMyDa59KfwEx6iFlQC
         TgVt1hbd46wZmqKH9ZH0PFqkUKxv/HEwn+tl8jQd6IZCUJ0jMWag4GLOfBE7MCZUy78p
         6agcoCKn/S6FOJ7JyZdqEBtCS4/9Cjh4dELPrK9yJTX4arzOkToW3lP6EqYTIH723/D8
         UWodTO9+2okoCbCWmPCkKSx7SrnZA4oJIrwvvMFjccDCvPIT7wX+obje0PVct5NdKohS
         W6Pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=DL0uxWQR;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7bce33006cfsi41686585a.6.2025.01.13.21.44.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:44:30 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E2h0wH003293;
	Tue, 14 Jan 2025 05:44:24 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445fcr8aka-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:44:24 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5iNHN001341
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:44:23 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:44:14 -0800
Date: Tue, 14 Jan 2025 11:14:11 +0530
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Marco Elver <elver@google.com>
CC: <dvyukov@google.com>, <andreyknvl@gmail.com>, <corbet@lwn.net>,
        <akpm@linux-foundation.org>, <gregkh@linuxfoundation.org>,
        <nogikh@google.com>, <pierre.gondois@arm.com>, <cmllamas@google.com>,
        <quic_zijuhu@quicinc.com>, <richard.weiyang@gmail.com>,
        <tglx@linutronix.de>, <arnd@arndb.de>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <dennis@kernel.org>, <tj@kernel.org>,
        <cl@linux.com>, <ruanjinjie@huawei.com>, <colyli@suse.de>,
        <andriy.shevchenko@linux.intel.com>, <kernel@quicinc.com>,
        <quic_likaid@quicinc.com>, <kasan-dev@googlegroups.com>,
        <workflows@vger.kernel.org>, <linux-doc@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
        <linux-mm@kvack.org>
Subject: Re: [PATCH] kcov: add unique cover, edge, and cmp modes
Message-ID: <Z4X5qyKmw03u91fx@hu-jiangenj-sha.qualcomm.com>
References: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
 <CANpmjNOg9=WbFpJQFQBOo1z_KuV7DKQTZB7=GfiYyvoam5Dm=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOg9=WbFpJQFQBOo1z_KuV7DKQTZB7=GfiYyvoam5Dm=w@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 1ocO8HRdM0OP4OGLu_yO60qlBwPczBE-
X-Proofpoint-GUID: 1ocO8HRdM0OP4OGLu_yO60qlBwPczBE-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 suspectscore=0 mlxlogscore=999 priorityscore=1501 clxscore=1015
 adultscore=0 lowpriorityscore=0 malwarescore=0 phishscore=0 bulkscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140045
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=DL0uxWQR;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
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

On Fri, Jan 10, 2025 at 10:22:44AM +0100, Marco Elver wrote:
> On Fri, 10 Jan 2025 at 08:33, Joey Jiao <quic_jiangenj@quicinc.com> wrote:
> >
> > From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
> >
> > The current design of KCOV risks frequent buffer overflows. To mitigate
> > this, new modes are introduced: KCOV_TRACE_UNIQ_PC, KCOV_TRACE_UNIQ_EDGE,
> > and KCOV_TRACE_UNIQ_CMP. These modes allow for the recording of unique
> > PCs, edges, and comparison operands (CMP).
> 
> There ought to be a cover letter explaining the motivation for this,
> and explaining why the new modes would help. Ultimately, what are you
> using KCOV for where you encountered this problem?
> 
> > Key changes include:
> > - KCOV_TRACE_UNIQ_[PC|EDGE] can be used together to replace KCOV_TRACE_PC.
> > - KCOV_TRACE_UNIQ_CMP can be used to replace KCOV_TRACE_CMP mode.
> > - Introduction of hashmaps to store unique coverage data.
> > - Pre-allocated entries in kcov_map_init during KCOV_INIT_TRACE to avoid
> >   performance issues with kmalloc.
> > - New structs and functions for managing memory and unique coverage data.
> > - Example program demonstrating the usage of the new modes.
> 
> This should be a patch series, carefully splitting each change into a
> separate patch.
> https://docs.kernel.org/process/submitting-patches.html#split-changes
Done in `20250114-kcov-v1-0-004294b931a2@quicinc.com`
> 
> > With the new hashmap and pre-alloced memory pool added, cover size can't
> > be set to higher value like 1MB in KCOV_TRACE_PC or KCOV_TRACE_CMP modes
> > in 2GB device with 8 procs, otherwise it causes frequent oom.
> >
> > For KCOV_TRACE_UNIQ_[PC|EDGE|CMP] modes, smaller cover size like 8KB can
> > be used.
> >
> > Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
> 
> As-is it's hard to review, and the motivation is unclear. A lot of
> code was moved and changed, and reviewers need to understand why that
> was done besides your brief explanation above.
> 
> Generally, KCOV has very tricky constraints, due to being callable
> from any context, including NMI. This means adding new dependencies
> need to be carefully reviewed. For one, we can see this in genalloc's
> header:
> 
> > * The lockless operation only works if there is enough memory
> > * available.  If new memory is added to the pool a lock has to be
> > * still taken.  So any user relying on locklessness has to ensure
> > * that sufficient memory is preallocated.
> > *
> > * The basic atomic operation of this allocator is cmpxchg on long.
> > * On architectures that don't have NMI-safe cmpxchg implementation,
> > * the allocator can NOT be used in NMI handler.  So code uses the
> > * allocator in NMI handler should depend on
> > * CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
> 
> And you are calling gen_pool_alloc() from __sanitizer_cov_trace_pc.
> Which means this implementation is likely broken on
> !CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG architectures (do we have
> architectures like that, that support KCOV?).
> 
> There are probably other sharp corners due to the contexts KCOV can
> run in, but would simply ask you to carefully reason about why each
> new dependency is safe.
Need to investigate more on CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z4X5qyKmw03u91fx%40hu-jiangenj-sha.qualcomm.com.
