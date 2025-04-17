Return-Path: <kasan-dev+bncBCLMXXWM5YBBBSX3QHAAMGQEHSHPIPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 880F2A9121F
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 06:04:28 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4767348e239sf7295441cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 21:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744862667; cv=pass;
        d=google.com; s=arc-20240605;
        b=FuTXzkmPW0vPoAbRTkjso4d8EJxKS4yqONAUfPOe1+0OsK70Qpk08jh930xJJ9Q8Jo
         LYlNceZ17+PswT5o1Uk7OdNrbo43p0jfgVtD+lsXw/8DCNF1F5QpkdC382sbLXiF6KX7
         WmlCaADLUzmgR+KbLnjakWqA9eYNi1kAs92vLkqIz+VYJkrE9nqg0RLYUjQE7UjqkwXk
         roDRTI+cWbbEQ2ACMsf+Wl5rzfMELYRPMlqSpJGBsSBYp9HCj4ue9WKAPWdCE6PZ0qLW
         pvdrmWTRTf5x7SeRfk77VWpTy72yrIICGEHng7mHKctcGs/exencrPZteCEhhDwX45uV
         dZNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aUp9Kbd4ZxqVrp9UDnWGmN4co/crUjSrzzz6YsKSfTQ=;
        fh=mvEzjwcVEOWHVfTjmw1tGa39LF4i0Jbo5gngWrvXUQE=;
        b=SJnrXIL+ZMRUAOIZzTf7hpkAnIcuZn/UGY1vcJfDR8hMLRgPX2zwbIz4Z77xv7whfQ
         n4vPb+6se9WPzxM3iXNifD2C7fFn8yO9bns3gAgVNKnT+K69+IzWaC2bqz90XwXs/FRD
         OuQyKNXPnxg3wmO3lJJlTuiNyLroFyoMhuXS5sZMU/HPVB6RKoiiBD2C9wQ7eCK/QCuz
         z7IPpbBpL4oVQ6x5ElW16BjedHHp7Jb+rtAIhsbw3XtKoc0aY0Xcr5xGoxbyVbm2Okz6
         aRwm/dymLMD3EwcL6eljdWnN1x94Hm7BVQ4ciZdrxq/091eLt3C5JUMim9irjTr6sQTQ
         2kvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Ebr9Zvck;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744862667; x=1745467467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aUp9Kbd4ZxqVrp9UDnWGmN4co/crUjSrzzz6YsKSfTQ=;
        b=kpoEDTJVjN+SmKh4/ldSI/UQhDroWD56tn9gsAuyemWaS4/+NrZRQnUieMmQZ2/Qlu
         MKOxqZH87kKMcPetgDEj5fYcryNlv5RpIbpPDXeMq4wZfIcFey0s0Cktr0l1lYciACD6
         RjVdRkoqNcMdTLrCNNwPBrsLBZf5smkxYejvh9EandL7F7qg2xLiKTBLP/3rmF9kTy5r
         jKpUKRiEDJ+YMWb7IDYDqf7OxvBbKWB27DoAmlhlp8qIq3q7FEAEB98ofMW5gWFPvCbD
         wvwz8FEmQjwEnhlM92oF1ud+BBKXdXfnsZSrKg/nBWIHSTr0pK3TjXou3vG+Z8ztrDfc
         KRxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744862667; x=1745467467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aUp9Kbd4ZxqVrp9UDnWGmN4co/crUjSrzzz6YsKSfTQ=;
        b=tDtlTIW4JY7m8bTIhseHe9PTj07ca5fR7zu4gy+6ihzmC03iFomWkM+5QLnhc88fkc
         9Q9ajq/wpET/FSLAuv/odmzYTkuPCNHxa4gR0fPhGIUOF+NUaWW892VqgBe6Vx90lkvB
         ZxQGQfxcW2+Ft8i4tbF2q2M+VFbKYl+TUFZZscGkhbD/dbGyLygnHartZ+LonJ1+G5ZZ
         J72eLCj+Tr40hbgHMGJZkV7tfM3TiHJO7VJUBgpRIRhzJQ+05OAO8x9tFvWOUZtFV0R1
         H+y5HQD903nlO0MItu/utmK6SIxkTVOxm4Co2akJppv4edbOCkcdmR5rdqOhEvfmrV9C
         mJpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWG78tXkHw0ohsSdAOeCXpzw6mhsxT3GgJumehk/QH44n62q3KpH2DbDVdA5kXd2WKScgMw9A==@lfdr.de
X-Gm-Message-State: AOJu0Yyfp0NdAYTLrC0yW6OPQ2cRPvcJ5bjcZYRvkBh3WV0x3mIsgnKi
	4uZT5PUs/+zWDtMKp12xj1f4tAFxW4LrPNEvTXhM0KMOdwrNV4qZ
X-Google-Smtp-Source: AGHT+IEfEDwvEA0unWjBmdbeoml6rjTRqaE7Sp2B4VKeEiaW5ly1a6pi3Elp6bpl6T8fC8KepSf9mQ==
X-Received: by 2002:ac8:7d82:0:b0:476:79d2:af58 with SMTP id d75a77b69052e-47ad80c24b4mr71231401cf.23.1744862667027;
        Wed, 16 Apr 2025 21:04:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIognP6Bbk0CnI4BMmbmxrRuVghdw7i14ctQD6GpE3fVQ==
Received: by 2002:ac8:5d0d:0:b0:476:b44f:8157 with SMTP id d75a77b69052e-47adda783c0ls9182441cf.0.-pod-prod-02-us;
 Wed, 16 Apr 2025 21:04:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbZ97KHhl20UQWLPn/vujFgONoC+MkX79/+xpEJSqWBhZKvBECOeA1eD2BbGusCU83W/uGLoVM6K4=@googlegroups.com
X-Received: by 2002:a05:622a:1304:b0:474:fab0:6564 with SMTP id d75a77b69052e-47ad810ebe9mr80017151cf.37.1744862665514;
        Wed, 16 Apr 2025 21:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744862665; cv=none;
        d=google.com; s=arc-20240605;
        b=W1Z+du6Dzj7awoFBUeh0f4AyrftCuM/H2Mc3RotYdMmoglHRtC/VVaBaPS4hQhBnrH
         exYjzyB3SJ+SYsU+xBwUlLqKuyVgJ4+iHGG2hcbZdmmoQfk3t4A8t9zwiV0i+c4P/X30
         ksyKjQSYgp9yOb9sKHmKkNrqX3E7Uh9dTud3/6RgVAAwBgRXpIMNmS5q8g4qiPpJy9md
         +Hu0aC+NphQ10Wxo7Bd8DRC/8jKmNswCSRXskZpaFBk5H7clRjB9Mcj0ikbC9KuYBmq3
         Oc2KiAi31fzxMX9oHzdpT+qurPox7QK5BWywhSoGs8Ae4AGmPVD8jY4+hSFM3LTL1ozU
         /bMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DuQ6vw1UigtHKVIvQTaQhmje30fGE5Ksa+r0AUhWdEY=;
        fh=OwKhG8UGzWgJpwlfldbq75lXbIYcbWbbr20b4dKRzcs=;
        b=MYyV7a6sZSv1IcJ1CuHObF8/TufR1TwSUTuMiSIYAHfzNGyrOw3YM13rIqgDtKvWZq
         qw1VA29NGIi2anIvsY0GNrZJTxQ3PPUqbhn+yJmD/IW89qLxHm2/2uf/svToBkFtJqvl
         tZSn/A4hps43vhXzdf/tO2tDphnoZ3Q6tl+cHDr9hsmAFGIOaD2vMRCOBwkw3oPNL+sv
         y5Umz+PdVF+yiKrPkAmK3fJ5GH9xELDywz1XG9i1JUYTceuqfWOw9S+dgusxGlSk8QXt
         eNUWiKQYqUo/ukPr+ok68g0dEdiYF0MaDcY4sXfxUX/nBh4Kfia7FbyKS2ZJQdEFUY7D
         rxLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Ebr9Zvck;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47ad7c1a912si1306181cf.3.2025.04.16.21.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Apr 2025 21:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279862.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 53GN6kUV029930;
	Thu, 17 Apr 2025 04:04:09 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 45ygxk5fjn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 17 Apr 2025 04:04:08 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 53H447Wa007204
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 17 Apr 2025 04:04:07 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Wed, 16 Apr 2025 21:04:05 -0700
Date: Thu, 17 Apr 2025 12:04:01 +0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Alexander Potapenko <glider@google.com>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        Aleksandr
 Nogikh <nogikh@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Borislav
 Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Dmitry
 Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
        Josh Poimboeuf
	<jpoimboe@kernel.org>, Marco Elver <elver@google.com>,
        Peter Zijlstra
	<peterz@infradead.org>,
        Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH 0/7] RFC: coverage deduplication for KCOV
Message-ID: <aAB9sUllq/xR/Maf@hu-jiangenj-sha.qualcomm.com>
References: <20250416085446.480069-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250416085446.480069-1-glider@google.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Authority-Analysis: v=2.4 cv=WecMa1hX c=1 sm=1 tr=0 ts=68007db8 cx=c_pps a=JYp8KDb2vCoCEuGobkYCKw==:117 a=JYp8KDb2vCoCEuGobkYCKw==:17 a=GEpy-HfZoHoA:10 a=kj9zAlcOel0A:10 a=XR8D0OoHHMoA:10 a=VwQbUJbxAAAA:8 a=COk6AnOGAAAA:8 a=Twlkf-z8AAAA:8
 a=NEAV23lmAAAA:8 a=6WkzK5_KCWnSRe-jCnIA:9 a=CjuIK1q_8ugA:10 a=gIUsDA97qKwA:10 a=TjNXssC_j7lpFel5tvFf:22 a=-74SuR6ZdpOK_LpdRCUo:22
X-Proofpoint-GUID: cWkygLtIaFXhDVZIryzvozcwrQSrmAIv
X-Proofpoint-ORIG-GUID: cWkygLtIaFXhDVZIryzvozcwrQSrmAIv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-17_01,2025-04-15_01,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 suspectscore=0
 adultscore=0 clxscore=1011 lowpriorityscore=0 phishscore=0 mlxscore=0
 impostorscore=0 mlxlogscore=730 spamscore=0 malwarescore=0
 priorityscore=1501 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2502280000
 definitions=main-2504170029
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Ebr9Zvck;       spf=pass
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

On Wed, Apr 16, 2025 at 10:54:38AM +0200, Alexander Potapenko wrote:
> As mentioned by Joey Jiao in [1], the current kcov implementation may
> suffer from certain syscalls overflowing the userspace coverage buffer.
> 
> According to our measurements, among 24 syzkaller instances running
> upstream Linux, 5 had a coverage overflow in at least 50% of executed
> programs. The median percentage of programs with overflows across those 24
> instances was 8.8%.
> 
> One way to mitigate this problem is to increase the size of the kcov buffer
> in the userspace application using kcov. But right now syzkaller already
> uses 4Mb per each of up to 32 threads to store the coverage, and increasing
> it further would result in reduction in the number of executors on a single
> machine.  Replaying the same program with an increased buffer size in the
> case of overflow would also lead to fewer executions being possible.
> 
> When executing a single system call, excessive coverage usually stems from
> loops, which write the same PCs into the output buffer repeatedly. Although
> collecting precise traces may give us some insights into e.g. the number of
> loop iterations and the branches being taken, the fuzzing engine does not
> take advantage of these signals, and recording only unique PCs should be
> just as practical.
> 
> In [1] Joey Jiao suggested using a hash table to deduplicate the coverage
> signal on the kernel side. While being universally applicable to all types
> of data collected by kcov, this approach adds another layer of complexity,
> requiring dynamically growing the map. Another problem is potential hash
> collisions, which can as well lead to lost coverage. Hash maps are also
> unavoidably sparse, which potentially requires more memory.
> 
> The approach proposed in this patch series is to assign a unique (and
> almost) sequential ID to each of the coverage callbacks in the kernel. Then
> we carve out a fixed-sized bitmap from the userspace trace buffer, and on
> every callback invocation we:
> 
> - obtain the callback_ID;
> - if bitmap[callback_ID] is set, append the PC to the trace buffer;
> - set bitmap[callback_ID] to true.
> 
> LLVM's -fsanitize-coverage=trace-pc-guard replaces every coverage callback
> in the kernel with a call to
> __sanitizer_cov_trace_pc_guard(&guard_variable) , where guard_variable is a
> 4-byte global that is unique for the callsite.
> 
> This allows us to lazily allocate sequential numbers just for the callbacks
> that have actually been executed, using a lock-free algorithm.
> 
> This patch series implements a new config, CONFIG_KCOV_ENABLE_GUARDS, which
> utilizes the mentioned LLVM flag for coverage instrumentation. In addition
> to the existing coverage collection modes, it introduces
> ioctl(KCOV_UNIQUE_ENABLE), which splits the existing kcov buffer into the
> bitmap and the trace part for a particular fuzzing session, and collects
> only unique coverage in the trace buffer.
> 
> To reset the coverage between runs, it is now necessary to set trace[0] to
> 0 AND clear the entire bitmap. This is still considered feasible, based on
> the experimental results below.
> 
> The current design does not address the deduplication of KCOV_TRACE_CMP
> comparisons; however, the number of kcov overflows during the hints
> collection process is insignificant compared to the overflows of
> KCOV_TRACE_PC.
> 
> In addition to the mentioned changes, this patch adds support for
> R_X86_64_REX_GOTPCRELX to objtool and arch/x86/kernel/module.c.  It turned
> out that Clang leaves such relocations in the linked modules for the
> __start___sancov_guards and __stop___sancov_guards symbols. Because
> resolving them does not require a .got section, it can be done at module
> load time.
> 
> Experimental results.
> 
> We've conducted an experiment running syz-testbed [3] on 10 syzkaller
> instances for 24 hours.  Out of those 10 instances, 5 were enabling the
> kcov_deduplicate flag from [4], which makes use of the KCOV_UNIQUE_ENABLE
> ioctl, reserving 4096 words (262144 bits) for the bitmap and leaving 520192
> words for the trace collection.
> 
> Below are the average stats from the runs.
Is there test without trace collection? Is bitmap only enough?
> 
> kcov_deduplicate=false:
>   corpus: 52176
>   coverage: 302658
>   cover overflows: 225288
>   comps overflows: 491
>   exec total: 1417829
>   max signal: 318894
> 
> kcov_deduplicate=true:
>   corpus: 52581
>   coverage: 304344
>   cover overflows: 986
>   comps overflows: 626
>   exec total: 1484841
>   max signal: 322455
> 
> [1] https://lore.kernel.org/linux-arm-kernel/20250114-kcov-v1-5-004294b931a2@quicinc.com/T/
> [2] https://clang.llvm.org/docs/SanitizerCoverage.html
> [3] https://github.com/google/syzkaller/tree/master/tools/syz-testbed
> [4] https://github.com/ramosian-glider/linux/pull/7 
> 
> 
> Alexander Potapenko (7):
>   kcov: apply clang-format to kcov code
>   kcov: factor out struct kcov_state
>   kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
>   kcov: add `trace` and `trace_size` to `struct kcov_state`
>   kcov: add ioctl(KCOV_UNIQUE_ENABLE)
>   x86: objtool: add support for R_X86_64_REX_GOTPCRELX
>   mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
> 
>  Documentation/dev-tools/kcov.rst  |  43 +++
>  MAINTAINERS                       |   1 +
>  arch/x86/include/asm/elf.h        |   1 +
>  arch/x86/kernel/module.c          |   8 +
>  arch/x86/kernel/vmlinux.lds.S     |   1 +
>  arch/x86/um/asm/elf.h             |   1 +
>  include/asm-generic/vmlinux.lds.h |  14 +-
>  include/linux/kcov-state.h        |  46 +++
>  include/linux/kcov.h              |  60 ++--
>  include/linux/sched.h             |  16 +-
>  include/uapi/linux/kcov.h         |   1 +
>  kernel/kcov.c                     | 453 +++++++++++++++++++-----------
>  lib/Kconfig.debug                 |  16 ++
>  mm/kasan/generic.c                |  18 ++
>  mm/kasan/kasan.h                  |   2 +
>  scripts/Makefile.kcov             |   4 +
>  scripts/module.lds.S              |  23 ++
>  tools/objtool/arch/x86/decode.c   |   1 +
>  tools/objtool/check.c             |   1 +
>  19 files changed, 508 insertions(+), 202 deletions(-)
>  create mode 100644 include/linux/kcov-state.h
> 
> -- 
> 2.49.0.604.gff1f9ca942-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aAB9sUllq/xR/Maf%40hu-jiangenj-sha.qualcomm.com.
