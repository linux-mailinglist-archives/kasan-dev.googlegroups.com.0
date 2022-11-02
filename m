Return-Path: <kasan-dev+bncBAABBHNURCNQMGQESRYDGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 87025615CDC
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 08:19:58 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id s14-20020a05622a1a8e00b00397eacd9c1asf11792370qtc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 00:19:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667373597; cv=pass;
        d=google.com; s=arc-20160816;
        b=nj5FOcGfoOq7BjZngFIP3yvXmH9vmhv36XVJAdPGb9pKfpY9zJQx5YOaMQsZJCWtgE
         qslTPU8K826cTyxm9U4T+G6hWE26wQ+0rDyGjidzaGWsesKI82M/4l9Lvnw8wDe+8UWe
         EvGkqD786EWU18IkfZxS7olJXcmqohDq1Li7X8WA2Z7NiRaY/UfqHmi91cnvzzDh8TxB
         8u2Et/T4LGVq5CRK8yTcUSjJD3nLBciGvCuSyLT5fjEHlEPuDbE+55W0XW0K0XxnaPgP
         7n5T6eOXvkxvckJTc1z8E21SBxbeiye0NhBZ2ZWagDuEtZTeCJumTvWZMjlrhwynvFhq
         qTUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Q4Zw864jry1mNojaQMZ3CnCgD8tTCQ20Jrkgc0PVp7o=;
        b=ULECwNDpfLxsp0l3lhNnv0J1xXdu28pMIFQ0pTba2AHcXWKYdY8e3niIH37FfL9JVB
         EpxLXz6yqcniVKBdwqRZ8Hws7inbBph+87Hb7Jw0roKsifAXKiXEbEjjDaT0jJ1oRVF/
         XNXR4b3HJFw8HWjK1b7GYP+X5xPJOYE4VCgLgKgb7nmfeR/gOd70aCHs1/u32C/fBMfF
         Eq7aWKh/AZlp6KoSC+xBS7yfzMp5laF7XN6V5Ulq3AEDewaa/lD1dGlf/oddwq++CbCr
         qj/YZb5q002Wb5kbubrBVmzwG8ySL9grPnS+E4KrZJDZBsq2xhRUHoRJ/LqHDSoT01zw
         6GRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=Q4Zw864jry1mNojaQMZ3CnCgD8tTCQ20Jrkgc0PVp7o=;
        b=kT3sRQrq9Z56jyCxOuPJWFP72+BzVnhyJ7S2zJrThn58zAvEI9MRG2NMbn+eCotleK
         ToBNHpVB7unVe7yvrTdFCdjiJhAj0Nr5KecQbOpNBGIrGPncl/Tyd++7Fwj3ZDAVhguJ
         TqdPv1QMOYZlvmLIDGraKTVFrqCU0nwyBJbBfrDTSHZhFJsc6uDMDGiGFmj93VYIR8CB
         ZqsBLb2DWJnievMl+yFw7TxLH6p3UWOVc/Jz7hrWpcnesBpeWF8/mrEtlqJb4z40Nu6g
         uPSW9AvyHtfwGs8Fe1sYH0/kOXck7Vjgqm99RWnQklE/L3AVJDwfFrVlSnZXP9nSZ6x3
         przA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q4Zw864jry1mNojaQMZ3CnCgD8tTCQ20Jrkgc0PVp7o=;
        b=eDw99JSeOPmuEWlZ1EbXJyhboDjAzvX4nLq041R/+953+2JQWAsC7XrgAFC4exyVaT
         AHwSeUO2xzvlxtRQRh34USReDea08+Wj6TeUUtdXDtNghz/peSMvtT1LQD4zE2+nviT4
         WMiT/dKkP1egi/lYYvKrFcrERT5N76LrdMzxIcMVFwV2qJPGDO1Mf/X8Azw+GZe4QsjP
         TFseSvatbkXdSJhey4qRrb3GG/9Ik8/90tNrfIKwnF0ZvnEv5EVU3SidNzQYEKTvztUL
         JvEXXGC8HYAsbJPhrbRNXwvp+BArX3u5laxQ3XJcMWBQb0sx4Yfkxx8THWXUtp0nvSRY
         QCdQ==
X-Gm-Message-State: ACrzQf2F69lSrr40xQ14srQqO7WIsxhNl5Ko+/jbl/qe3E+Rwvyb892z
	Q8wUk/6oSqEdbehzPvVb5/E=
X-Google-Smtp-Source: AMsMyM5RzUEuX3B5HToZ72TqnNPwWrYNa//oTkeLOpBRA4sb0YDkzM1zyR+Y7NymRWTldB4JeLsySg==
X-Received: by 2002:a05:6214:226c:b0:4bb:93b8:ef9f with SMTP id gs12-20020a056214226c00b004bb93b8ef9fmr19777547qvb.91.1667373597190;
        Wed, 02 Nov 2022 00:19:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9b12:0:b0:4b9:d85c:f017 with SMTP id b18-20020a0c9b12000000b004b9d85cf017ls7148463qve.11.-pod-prod-gmail;
 Wed, 02 Nov 2022 00:19:56 -0700 (PDT)
X-Received: by 2002:ad4:5d6e:0:b0:4bb:6acc:e712 with SMTP id fn14-20020ad45d6e000000b004bb6acce712mr19699828qvb.57.1667373596683;
        Wed, 02 Nov 2022 00:19:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667373596; cv=none;
        d=google.com; s=arc-20160816;
        b=rqll+8u/EU5iq0tLm/3OTC9yNVMdl3ljxxAIHNHnWm7yrhgEP8a+PiKABHZ0Kl7Aa5
         0nM8d5BrZM3PyoEEwQ0+bEJJpPBi2xn2yo9QSRuMJA4vzZtHfSuxCS6O1C1aMe3cA8wt
         JuEXC4MRp0qqJU4JPzi29+tcQp53jjMUySIgp0+ribnuKSJUWSs81UXxvQuFZkjCRRo5
         QA+asqprrcCC4srCosLy2xA1rulFCvV4quda3acuyufGKuu2hjre0zRFGjKaZASPcBe8
         6FmVS1A0iQ8hk7y1wrkjoKCs4l0ej0Hu8jGGf5Gy2Z0ONCnUyIIytD6AUmwDb42oujVX
         H50g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id;
        bh=svIGRSS1VVolWkDV4P5xAip4g+IJTaNKZodS3fHx068=;
        b=rTV1CPNxHP4UeeVnQ/ikwrjGHPcqggSECpdQ1dOyQ+/RhCOmqYIdrrC++f6oUNPofj
         2VVvTSsUkdf/tvSKiiztUqbd4ci5iDG+p0m4z/Gq5iPHVnwPNy08o234gmcsqHEM0oUi
         hpyAFS4bgoLRrpFnCJ5/2NTnTxYObWzAcyMdDKPSXBYx14oxPp7ar1slnAPUzUd7M2xt
         s/8dMk1/z9O72uGy/uOLkFs9y9l1B2XRfkq0tuncbBP7zhLz2UO2raJQ2J1BNtkLFHQy
         SSwauKTtxh+C637qNg9xiAePc/Sl7ipOotPgwu/lhV49MEg94Af9awJX1eGYSg4E04BU
         PDVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id h22-20020ac87776000000b003a4f2725cd1si624127qtu.4.2022.11.02.00.19.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Nov 2022 00:19:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from canpemm500005.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4N2J740d2TzRnx1;
	Wed,  2 Nov 2022 15:14:56 +0800 (CST)
Received: from [10.174.178.197] (10.174.178.197) by
 canpemm500005.china.huawei.com (7.192.104.229) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 2 Nov 2022 15:19:52 +0800
Message-ID: <666b976a-8873-25e2-66dd-1398682c6cb7@huawei.com>
Date: Wed, 2 Nov 2022 15:19:52 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH -next] bpf, test_run: fix alignment problem in
 bpf_prog_test_run_skb()
To: Eric Dumazet <edumazet@google.com>, Kees Cook <keescook@chromium.org>
CC: Jakub Kicinski <kuba@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
	<davem@davemloft.net>, <pabeni@redhat.com>, <linux-kernel@vger.kernel.org>,
	<bpf@vger.kernel.org>, <netdev@vger.kernel.org>, <ast@kernel.org>,
	<song@kernel.org>, <yhs@fb.com>, <haoluo@google.com>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Linux MM <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>
References: <20221101040440.3637007-1-zhongbaisong@huawei.com>
 <eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net>
 <ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
 <20221101210542.724e3442@kernel.org> <202211012121.47D68D0@keescook>
 <CANn89i+FVN95uvftTJteZgGQ_sSb6452XXZn0veNjHHKZ2yEFQ@mail.gmail.com>
From: "'zhongbaisong' via kasan-dev" <kasan-dev@googlegroups.com>
Organization: huawei
In-Reply-To: <CANn89i+FVN95uvftTJteZgGQ_sSb6452XXZn0veNjHHKZ2yEFQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.178.197]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 canpemm500005.china.huawei.com (7.192.104.229)
X-CFilter-Loop: Reflected
X-Original-Sender: zhongbaisong@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: zhongbaisong <zhongbaisong@huawei.com>
Reply-To: zhongbaisong <zhongbaisong@huawei.com>
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



On 2022/11/2 12:37, Eric Dumazet wrote:
> On Tue, Nov 1, 2022 at 9:27 PM Kees Cook <keescook@chromium.org> wrote:
>>
>> On Tue, Nov 01, 2022 at 09:05:42PM -0700, Jakub Kicinski wrote:
>>> On Wed, 2 Nov 2022 10:59:44 +0800 zhongbaisong wrote:
>>>> On 2022/11/2 0:45, Daniel Borkmann wrote:
>>>>> [ +kfence folks ]
>>>>
>>>> + cc: Alexander Potapenko, Marco Elver, Dmitry Vyukov
>>>>
>>>> Do you have any suggestions about this problem?
>>>
>>> + Kees who has been sending similar patches for drivers
>>>
>>>>> On 11/1/22 5:04 AM, Baisong Zhong wrote:
>>>>>> Recently, we got a syzkaller problem because of aarch64
>>>>>> alignment fault if KFENCE enabled.
>>>>>>
>>>>>> When the size from user bpf program is an odd number, like
>>>>>> 399, 407, etc, it will cause skb shard info's alignment access,
>>>>>> as seen below:
>>>>>>
>>>>>> BUG: KFENCE: use-after-free read in __skb_clone+0x23c/0x2a0
>>>>>> net/core/skbuff.c:1032
>>>>>>
>>>>>> Use-after-free read at 0xffff6254fffac077 (in kfence-#213):
>>>>>>    __lse_atomic_add arch/arm64/include/asm/atomic_lse.h:26 [inline]
>>>>>>    arch_atomic_add arch/arm64/include/asm/atomic.h:28 [inline]
>>>>>>    arch_atomic_inc include/linux/atomic-arch-fallback.h:270 [inline]
>>>>>>    atomic_inc include/asm-generic/atomic-instrumented.h:241 [inline]
>>>>>>    __skb_clone+0x23c/0x2a0 net/core/skbuff.c:1032
>>>>>>    skb_clone+0xf4/0x214 net/core/skbuff.c:1481
>>>>>>    ____bpf_clone_redirect net/core/filter.c:2433 [inline]
>>>>>>    bpf_clone_redirect+0x78/0x1c0 net/core/filter.c:2420
>>>>>>    bpf_prog_d3839dd9068ceb51+0x80/0x330
>>>>>>    bpf_dispatcher_nop_func include/linux/bpf.h:728 [inline]
>>>>>>    bpf_test_run+0x3c0/0x6c0 net/bpf/test_run.c:53
>>>>>>    bpf_prog_test_run_skb+0x638/0xa7c net/bpf/test_run.c:594
>>>>>>    bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
>>>>>>    __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
>>>>>>    __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
>>>>>>
>>>>>> kfence-#213: 0xffff6254fffac000-0xffff6254fffac196, size=407,
>>>>>> cache=kmalloc-512
>>>>>>
>>>>>> allocated by task 15074 on cpu 0 at 1342.585390s:
>>>>>>    kmalloc include/linux/slab.h:568 [inline]
>>>>>>    kzalloc include/linux/slab.h:675 [inline]
>>>>>>    bpf_test_init.isra.0+0xac/0x290 net/bpf/test_run.c:191
>>>>>>    bpf_prog_test_run_skb+0x11c/0xa7c net/bpf/test_run.c:512
>>>>>>    bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
>>>>>>    __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
>>>>>>    __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
>>>>>>    __arm64_sys_bpf+0x50/0x60 kernel/bpf/syscall.c:4381
>>>>>>
>>>>>> To fix the problem, we round up allocations with kmalloc_size_roundup()
>>>>>> so that build_skb()'s use of kize() is always alignment and no special
>>>>>> handling of the memory is needed by KFENCE.
>>>>>>
>>>>>> Fixes: 1cf1cae963c2 ("bpf: introduce BPF_PROG_TEST_RUN command")
>>>>>> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
>>>>>> ---
>>>>>>    net/bpf/test_run.c | 1 +
>>>>>>    1 file changed, 1 insertion(+)
>>>>>>
>>>>>> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
>>>>>> index 13d578ce2a09..058b67108873 100644
>>>>>> --- a/net/bpf/test_run.c
>>>>>> +++ b/net/bpf/test_run.c
>>>>>> @@ -774,6 +774,7 @@ static void *bpf_test_init(const union bpf_attr
>>>>>> *kattr, u32 user_size,
>>>>>>        if (user_size > size)
>>>>>>            return ERR_PTR(-EMSGSIZE);
>>>>>> +    size = kmalloc_size_roundup(size);
>>>>>>        data = kzalloc(size + headroom + tailroom, GFP_USER);
>>>>>
>>>>> The fact that you need to do this roundup on call sites feels broken, no?
>>>>> Was there some discussion / consensus that now all k*alloc() call sites
>>>>> would need to be fixed up? Couldn't this be done transparently in k*alloc()
>>>>> when KFENCE is enabled? I presume there may be lots of other such occasions
>>>>> in the kernel where similar issue triggers, fixing up all call-sites feels
>>>>> like ton of churn compared to api-internal, generic fix.
>>
>> I hope I answer this in more detail here:
>> https://lore.kernel.org/lkml/202211010937.4631CB1B0E@keescook/
>>
>> The problem is that ksize() should never have existed in the first
>> place. :P Every runtime bounds checker has tripped over it, and with
>> the addition of the __alloc_size attribute, I had to start ripping
>> ksize() out: it can't be used to pretend an allocation grew in size.
>> Things need to either preallocate more or go through *realloc() like
>> everything else. Luckily, ksize() is rare.
>>
>> FWIW, the above fix doesn't look correct to me -- I would expect this to
>> be:
>>
>>          size_t alloc_size;
>>          ...
>>          alloc_size = kmalloc_size_roundup(size + headroom + tailroom);
>>          data = kzalloc(alloc_size, GFP_USER);
> 
> Making sure the struct skb_shared_info is aligned to a cache line does
> not need kmalloc_size_roundup().
> 
> What is needed is to adjust @size so that (@size + @headroom) is a
> multiple of SMP_CACHE_BYTES

ok, I'll fix it and send v2.

Thanks

.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/666b976a-8873-25e2-66dd-1398682c6cb7%40huawei.com.
