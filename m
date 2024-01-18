Return-Path: <kasan-dev+bncBCW35TVV54DRBRUWUSWQMGQEEZAS5NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 46163831870
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 12:28:08 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-42a130a11dasf17789801cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 03:28:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705577287; cv=pass;
        d=google.com; s=arc-20160816;
        b=bemcFDxaQ3D46ieugIdiy3wayNyZrJCg1Nt4MoljkXKeRRvN1aTTffe95Ap4GtaPBn
         km90uJ5qy/fT4DkloiKGkzWc3qhRvtIvHvfblTylH7vmdPCYDOiH3TGqGQaTAZUrK+9O
         Zmn/8IYJro0QzsyYiJtXQNKGjwRsTDkIP091Vf6f9l1wqlofoun83TG1jegU6BxqMgvD
         KtXsl6kyoanjn2MvB33jPLwL8uxM0krS96XZBlLxRGClA0RGPN98GRGBkM570ccjAer+
         R0PORK9qwLbNGflHJEsfoa6MjgyaiUZnRVeThtY8DyRsMcaujX4upOHxriFuYwvOx+4x
         sNMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=wqVw5rqmKrY89tL76QqmhfizSF4SBjia0xrE5u1zjfo=;
        fh=v0QH277E3x4mqXL97LdzNbQmRisQfuQx/MGnRp01MNU=;
        b=Rt0ym1AJ676fH0h8R7maf+ru+cTVSxoEKtTNh1gir+nP1IDJBi+pIKen2RqF8LffgL
         R2MalYstlB5SL84YtA53CQWvcLMATKnN5zONJJjgcBlqZWBl2NZn2nJ4+352WO+f4OMd
         E25Rbq2Srh8D8tdY/qLPyr9RYFvaDfKtZ2Nfnp5stttRyP6fNB1zaQr4jyw9bHmcQ1pa
         dNIC1KKX9QlgB+/bDrrh9ImQgOZWziQSQTSqi3F5ahfs40rQXeN0cdU7oF5s9ZMzbMHd
         LDU3tu/2BeOqrr1qc0aB7RV6qP/dKZxV4WHRKMY1D13gh/ty/L3b8QtQnOX52dYl6hip
         wZIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bqVveGw8;
       spf=pass (google.com: domain of quic_charante@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705577287; x=1706182087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wqVw5rqmKrY89tL76QqmhfizSF4SBjia0xrE5u1zjfo=;
        b=Ugm570UbGb7zYf2kxALPglutWVdyWFd0wUO2AyiudhcybgNmA2RjvE0H7qm9hodFiO
         +HOQQtjTMPJGO0v1qtwIPyQtPbL1tPrvb5DlRAlVixXjyr2PVDjbgTSNAOo5r+Q2HlQc
         KEKEOlUAYwwTV9FcsgP9Kf3yJIVfd1uetQLIchHTeXBTetd1LJWAKo7Ly8B3OcUh6i5M
         7SYDG4TQNovN8IbIqkdeELDl2FiJgPJdjAv0ZQC5N7dV21qram2JY8IXN38vOj/2/+ox
         Z7GuwvCbzAOOgfs/hLMrkNcg2u2QdeH7T3R6MESWH9ma6jmcspKw3ZJFwc1HzmqiY+ek
         F8Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705577287; x=1706182087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wqVw5rqmKrY89tL76QqmhfizSF4SBjia0xrE5u1zjfo=;
        b=fYrvSUUtVcMlBWfKuYK8po4fpIRMpukzqnTzACVbHjFXhyMql+g8DX5NiyWOyhScdd
         K14SZ0y/s1iK6sPXMmVW3CUXy7vA4oGyfmi8KjqS+Pecx/jHwPbA9DBntX4gRhiK/O7j
         /sIqw1ZqKv5gSMh84rohKVihthSANT7hFadkCXIF4F6wpx8D/8SZpXjAI0oMhKeamPNJ
         rM07Tcx7SWoAR8kSmGVar/H39omiy9kh0ZVb+zKkpvR8tJ+3D/o8Q54w5sOr0mUa9uwX
         OHK5pzto+S0Re93Pt6gXk1DtJbwtwQ3H64ml0E+pReHT1YkQunvxaYRVoXRxTr+c0Rru
         UguA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx63N1f/xvt6R7Pz71kxvX9cDL3f8MOJVpZ9x93T3jPBj9moIFh
	2BUYLbs++CGsfAkAygzZPX2ywvBADECxuZ48TJXfdEBXZq3xqoz3
X-Google-Smtp-Source: AGHT+IFEOV0NeuMWEUXQrjKS29oEwo7T9nZUvgEpENvpUk9ltEYTvtzakl9+IfyvGm8lB7F6IWW1sw==
X-Received: by 2002:ac8:5d8c:0:b0:42a:93c:be3f with SMTP id d12-20020ac85d8c000000b0042a093cbe3fmr608547qtx.29.1705577287031;
        Thu, 18 Jan 2024 03:28:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1921:b0:429:f35e:da72 with SMTP id
 w33-20020a05622a192100b00429f35eda72ls4198125qtc.0.-pod-prod-01-us; Thu, 18
 Jan 2024 03:28:06 -0800 (PST)
X-Received: by 2002:a67:f44f:0:b0:469:7f74:b2f3 with SMTP id r15-20020a67f44f000000b004697f74b2f3mr588519vsn.0.1705577286251;
        Thu, 18 Jan 2024 03:28:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705577286; cv=none;
        d=google.com; s=arc-20160816;
        b=CQ22C9mIXvHWGjDdJv4Ju+G1j2dRPqMufzMo5OzBMlUnzUfcr2Nqw9YZoa6cYuh8Y7
         zmTJUTPKA+i75NxM0NjdQw6yKpqrX/GEqYhPIK23d0bjNyQmtH7YJDSCt4y8bt7mPDoQ
         6GVatEIjatx7frJO39wetzuufGpS/OUmMGPRZinkoPJcYsvTPATlHA6ytehNUkY70N2k
         Hcrx/aIVp6vEGbhvSfcOttr/WpjN32ZaYcSP+EEet/rusFXX85VCuMMlgftCZ7q1NPP6
         RaXjxAWB1RpyW5zcWgLjGP9neJKqq1cbzGM8wR+zN7STmdG/BG8Uh3uDnvAtJ4SZbobc
         lXbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IoaCXp2bZnlOp0cjfLp4rHUzRkV2pKD6nav2X3Gxi60=;
        fh=v0QH277E3x4mqXL97LdzNbQmRisQfuQx/MGnRp01MNU=;
        b=eKCWzj+Ln0AZRo3fd7J3XusAc8rjafnmB+OdvS+QgIzyAciN+MyAwiExf4lAjwdER9
         ImTWytxImEIa/DLOeZ/ovsQ9jIZfNQ850kloiMNcq5I1kXDflul2Pd22SSxjEjJZEQDW
         hhWSWvN63gio7rjy/6XI9EleWAUpAGJqRUu06eLO3T4kza0tjZ/S/k0JBLxmAg+F2T+s
         qjJuJuNAbWoYZdY0jt4e+mmytKsXb1itdOdRTN1K/IFrObpv9iHW+JBYYz5iy9C5P6mO
         WUO1mz8izI1bwBKLm1l4p6yGQdqXZa9p8YCBqbzvN/qAo8nWnSqMj9vlmr2KZA4CA8Zv
         lp/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bqVveGw8;
       spf=pass (google.com: domain of quic_charante@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id l5-20020a0cee25000000b006815ec1421csi665785qvs.7.2024.01.18.03.28.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jan 2024 03:28:06 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_charante@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279864.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 40I602gl004450;
	Thu, 18 Jan 2024 11:27:52 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3vpx8sgsxf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 18 Jan 2024 11:27:52 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 40IBRpQX018662
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 18 Jan 2024 11:27:51 GMT
Received: from [10.216.49.108] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1118.40; Thu, 18 Jan
 2024 03:27:46 -0800
Message-ID: <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
Date: Thu, 18 Jan 2024 16:57:43 +0530
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical
 section
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov
	<dvyukov@google.com>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
	<mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>,
        "H. Peter Anvin"
	<hpa@zytor.com>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
        <syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com>
References: <20240118110022.2538350-1-elver@google.com>
 <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
From: Charan Teja Kalla <quic_charante@quicinc.com>
In-Reply-To: <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: Rh-3EVEcIoOAH_xbT10Yj9vRa3gg77-3
X-Proofpoint-GUID: Rh-3EVEcIoOAH_xbT10Yj9vRa3gg77-3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-18_06,2024-01-17_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 phishscore=0 priorityscore=1501 mlxlogscore=999 impostorscore=0 mlxscore=0
 bulkscore=0 suspectscore=0 malwarescore=0 clxscore=1011 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2311290000
 definitions=main-2401180082
X-Original-Sender: quic_charante@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=bqVveGw8;       spf=pass
 (google.com: domain of quic_charante@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
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

May I ask if KMSAN also instruments the access to the memory managed as
ZONE_DEVICE. You know this is not the RAM and also these pages will
never be onlined thus also not be available in buddy.

Reason for the ask is that this patch is introduced because of a race
between pfn walker ends up in pfn of zone device memory.

If KMSAN never instruments this, does it look good to you to have the
KMSAN version of pfn_valid(), as being suggested by Alexander in the
other mail.

Thanks,

On 1/18/2024 4:37 PM, Marco Elver wrote:
> On Thu, 18 Jan 2024 at 12:00, Marco Elver <elver@google.com> wrote:
>>
>> Alexander Potapenko writes in [1]: "For every memory access in the code
>> instrumented by KMSAN we call kmsan_get_metadata() to obtain the
>> metadata for the memory being accessed. For virtual memory the metadata
>> pointers are stored in the corresponding `struct page`, therefore we
>> need to call virt_to_page() to get them.
>>
>> According to the comment in arch/x86/include/asm/page.h,
>> virt_to_page(kaddr) returns a valid pointer iff virt_addr_valid(kaddr)
>> is true, so KMSAN needs to call virt_addr_valid() as well.
>>
>> To avoid recursion, kmsan_get_metadata() must not call instrumented
>> code, therefore ./arch/x86/include/asm/kmsan.h forks parts of
>> arch/x86/mm/physaddr.c to check whether a virtual address is valid or
>> not.
>>
>> But the introduction of rcu_read_lock() to pfn_valid() added
>> instrumented RCU API calls to virt_to_page_or_null(), which is called by
>> kmsan_get_metadata(), so there is an infinite recursion now.  I do not
>> think it is correct to stop that recursion by doing
>> kmsan_enter_runtime()/kmsan_exit_runtime() in kmsan_get_metadata(): that
>> would prevent instrumented functions called from within the runtime from
>> tracking the shadow values, which might introduce false positives."
>>
>> Fix the issue by switching pfn_valid() to the _sched() variant of
>> rcu_read_lock/unlock(), which does not require calling into RCU. Given
>> the critical section in pfn_valid() is very small, this is a reasonable
>> trade-off (with preemptible RCU).
>>
>> KMSAN further needs to be careful to suppress calls into the scheduler,
>> which would be another source of recursion. This can be done by wrapping
>> the call to pfn_valid() into preempt_disable/enable_no_resched(). The
>> downside is that this sacrifices breaking scheduling guarantees;
>> however, a kernel compiled with KMSAN has already given up any
>> performance guarantees due to being heavily instrumented.
>>
>> Note, KMSAN code already disables tracing via Makefile, and since
>> mmzone.h is included, it is not necessary to use the notrace variant,
>> which is generally preferred in all other cases.
>>
>> Link: https://lkml.kernel.org/r/20240115184430.2710652-1-glider@google.com [1]
>> Reported-by: Alexander Potapenko <glider@google.com>
>> Reported-by: syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
>> Signed-off-by: Marco Elver <elver@google.com>
>> Cc: Charan Teja Kalla <quic_charante@quicinc.com>
> 
> This might want a:
> 
> Fixes: 5ec8e8ea8b77 ("mm/sparsemem: fix race in accessing
> memory_section->usage")
> 
> For reference which patch introduced the problem.
> 
>> ---
>>  arch/x86/include/asm/kmsan.h | 17 ++++++++++++++++-
>>  include/linux/mmzone.h       |  6 +++---
>>  2 files changed, 19 insertions(+), 4 deletions(-)
>>
>> diff --git a/arch/x86/include/asm/kmsan.h b/arch/x86/include/asm/kmsan.h
>> index 8fa6ac0e2d76..d91b37f5b4bb 100644
>> --- a/arch/x86/include/asm/kmsan.h
>> +++ b/arch/x86/include/asm/kmsan.h
>> @@ -64,6 +64,7 @@ static inline bool kmsan_virt_addr_valid(void *addr)
>>  {
>>         unsigned long x = (unsigned long)addr;
>>         unsigned long y = x - __START_KERNEL_map;
>> +       bool ret;
>>
>>         /* use the carry flag to determine if x was < __START_KERNEL_map */
>>         if (unlikely(x > y)) {
>> @@ -79,7 +80,21 @@ static inline bool kmsan_virt_addr_valid(void *addr)
>>                         return false;
>>         }
>>
>> -       return pfn_valid(x >> PAGE_SHIFT);
>> +       /*
>> +        * pfn_valid() relies on RCU, and may call into the scheduler on exiting
>> +        * the critical section. However, this would result in recursion with
>> +        * KMSAN. Therefore, disable preemption here, and re-enable preemption
>> +        * below while suppressing reschedules to avoid recursion.
>> +        *
>> +        * Note, this sacrifices occasionally breaking scheduling guarantees.
>> +        * Although, a kernel compiled with KMSAN has already given up on any
>> +        * performance guarantees due to being heavily instrumented.
>> +        */
>> +       preempt_disable();
>> +       ret = pfn_valid(x >> PAGE_SHIFT);
>> +       preempt_enable_no_resched();
>> +
>> +       return ret;
>>  }
>>
>>  #endif /* !MODULE */
>> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
>> index 4ed33b127821..a497f189d988 100644
>> --- a/include/linux/mmzone.h
>> +++ b/include/linux/mmzone.h
>> @@ -2013,9 +2013,9 @@ static inline int pfn_valid(unsigned long pfn)
>>         if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
>>                 return 0;
>>         ms = __pfn_to_section(pfn);
>> -       rcu_read_lock();
>> +       rcu_read_lock_sched();
>>         if (!valid_section(ms)) {
>> -               rcu_read_unlock();
>> +               rcu_read_unlock_sched();
>>                 return 0;
>>         }
>>         /*
>> @@ -2023,7 +2023,7 @@ static inline int pfn_valid(unsigned long pfn)
>>          * the entire section-sized span.
>>          */
>>         ret = early_section(ms) || pfn_section_valid(ms, pfn);
>> -       rcu_read_unlock();
>> +       rcu_read_unlock_sched();
>>
>>         return ret;
>>  }
>> --
>> 2.43.0.381.gb435a96ce8-goog
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd742d1d-70a3-586b-4bf5-fcfc94c75b4a%40quicinc.com.
