Return-Path: <kasan-dev+bncBCY5VBNX2EDRB7O6Y7XQKGQEMENFF2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B1C111C695
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 08:42:53 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id dd24sf893528edb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 23:42:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576136573; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZzpzrZqGGZvxpzvuE9zMROFY9LdPLbft98j8VOtKglsBDZYaGsukdL2WPYv6omEpiQ
         oiCfR71+pZlXE4YFtdv43fqZmwgPTcHXXt/VFbx8NFnpAjM/BPKIhTk4338zryTLFKhB
         CTN8ezteOKncvpY6R84umKSuJ5ARvWHlE/W1WeJY/1kN/ZeU0PxYMvaR8R2h90WXOa+o
         drjpe8jc+n8zKW0vibfoIFxbxZCaOBj4ndu37ti7RtowK2cGue4bwlcshad8Ig2+jUki
         ubnleJ+ZHd7mpIAEtKL0VLaBjpKEhmseXjho65tAy2AAJJIjWsPr2Aa4V5G3D1R85f5c
         Uj1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature:dkim-signature;
        bh=6YeH8hbcnsZl3DV2r0Hqainjo+NtqX+U91b6/W/8if4=;
        b=Mvc3speKDxv87Oe62w+jnKJt7xTNGAjnR3CbUdzpYL1Ru1B96SZlkjuP/iHjmtypm8
         jEaj31s5teXq6OT/wu8CrNl601UGXmeKAHb3X1Q/z7TnEyw1eUGd2l/G5gVMWeMMzuRg
         QiS0xzZahGPFjLHOPce9itVi9sPiw8vFWb+MRB8vYjayi3Ui7ZEeHe2L4NrjHY/hlbh/
         7JIhXGuWvmzIP3bB8VEb8Q25emVFUX788rkc3xPp2dkl/6hRK0epCjLKtIaI9qLuTs6a
         F0D+hxcTFQghI2EDUz2vxob4MofCpVdt5U0KxmD/bqnxnW8bf8RJEkBim/6ojQhf9YpY
         4mrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NMCNzYEm;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6YeH8hbcnsZl3DV2r0Hqainjo+NtqX+U91b6/W/8if4=;
        b=Rm/whzEE2ZRsIaUUg/A6f0vHwBGNn94qCEJe5rui1F5AI5LNDqLCm6IETo5aUnJU1F
         5eNreZNgXjxATryJqGwrz7QMX9XgBnmabAsC2aeJoHSIPXXLfo2rciCKFhAidRgvkKBU
         EapI3ehbUcrQvHVCLfmEnWIs4g2ITRMo4w/PHw1b9Tj/3nZNcp1+2HPYVn0b6mL45Q00
         IHP1zvHVcG7OcbU1vif6hvd4kNzKdVYP0mpAUdOdTzotTaULErc8yrnO0SO0lVwjoD5D
         L9EJGnfQ0XdLSp1spvS2APbGZaiEJOMT/S9OxWdA1TBcwnL1KYp79YVFuoPuOLKfKPNZ
         655g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6YeH8hbcnsZl3DV2r0Hqainjo+NtqX+U91b6/W/8if4=;
        b=SqVsNBE43mRSe+yBxvYgp4/yN5lSc0HLCNhhigByOSMY8EdZ9jUypPSSejqVGWzd9B
         8N9Gsw54l7WYcmKIkj9KTLXMIT7gcjIb4Wz0KXYIPjQuBRNEPIIHlA6W4vni6ykGyRd2
         XOyE/Wch1XRGqn70cU8TcnefUW9HwK3DxoCNk16D1EHWG4aLPwp+XvyEKAnuSPvcTw7h
         LvVNTpndg/7A2EqSwK2GYwwqvKdXr9rfkgwlvZmMdFTybQAUN/Kd9+GqFLf1SByEdvfT
         qIScliAM8PzS9kQkuHLOI7XI3J3GGDQ8jtACmwC5vGOpy538DN+oIdNR0oW922CgJO5+
         VtmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6YeH8hbcnsZl3DV2r0Hqainjo+NtqX+U91b6/W/8if4=;
        b=YMznT+JvxnLgpslEovTDSebx91HcK1WKVkfELNcj02caaoyXp48WCdSTSvMaj7bdz3
         WgOqcprCfVQ4f06haAelgYJA/uzox+1IYumzxE+dVUnSPtakuu0DMoabKebc1b8xoDX3
         Q7RIGlzECad9APPDrCJWR6ZalsiLZ1n/bLVE3iO4ILqk8SiDOALPvjfY0u3GelyyhlNd
         wBthhGogc6FLOvHE/TY0XJBTcWpJHO9BwgYM6MEJTLe5Fyh/yAMGaJLz27yCmpoS05UA
         R6Ae0GwmOzvJ/F+uYLaVgoSFStgavGGJ4jVRLZwEfOV2PEsIPqdwgfL3CzngyE/T+sT+
         DFig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWxIeCUUOvGEQFHiAjyA8WWWZcd1q1UVezR5Gt0hPjQWAhQSigR
	9llZ7ddfz/iWD1H3W/OyTSE=
X-Google-Smtp-Source: APXvYqytZjm0TrE5QrpqailyzIY9NGA9K9Oj/HSXXyTOTquZqtU4j3MiV10CG/vGyUz0UND141Qa3A==
X-Received: by 2002:a17:906:35ca:: with SMTP id p10mr8208257ejb.156.1576136573100;
        Wed, 11 Dec 2019 23:42:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:60b:: with SMTP id s11ls1254870ejb.14.gmail; Wed, 11
 Dec 2019 23:42:52 -0800 (PST)
X-Received: by 2002:a17:906:4e46:: with SMTP id g6mr8129226ejw.309.1576136572582;
        Wed, 11 Dec 2019 23:42:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576136572; cv=none;
        d=google.com; s=arc-20160816;
        b=zw843S6VDN2eoZKHQ77diLIlQTwtE0xqY4pLALeu7zddehLfCrOtNRmOV+cMymd+pj
         HYbM59dJcqrBR0WAHYE20ehyjk6pLYdB8k5de6IODTzgXz/1hyb4OQv8ME4fSPpdygEm
         WAaOAQ+nADXdTBxE96y63/xfyWJ4UcMvmvOK8U8EmPIpOFn0exAMYLZO24r3esdhDn+p
         PlFqrl00wnK/WISGWOIfRs57dB7T9aoARPvSo+KGZ6FRUOg1nwrr666n2dSXVZ+nx3A5
         YrN/5MygcIh0HXmuyFgVZSKB4/CGy81YiAEb4I9bBha8BZNQEVy2VKm65QsEdoMWJM93
         5QFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=PkUsNGoqFdl5gXqJP6bnP2J6yrhC8TrnSK9hjm92v8k=;
        b=xnqf9zrIoTQhwlV8vRx3iKRl6VeNa/pOPAD+jFf16ubqEetSS9wVzQfIigMCewUntL
         BftBMoMIjQQNhaTSmzlWNWwkE19hRrMUj6Tr4Q4eIUaGpFmQ5A4oFHTrgAQffz4GKk1Y
         dIJmkh9zP3ycdPnVHurG1DKkHIxtkTybRkni7IqDn6t6n/eLIhd7+Mb4edJSL+Q77fll
         MZcVRfcQFPlgMBjxHIkkuRE7Lary/z3EAwb0UY08OIpch6LFh/bHr1+8/HHlw9mGXoHj
         1+N22miaPqM5T9RW26HRv9ifg4ZC9HXlSDAn6OIaKHX25nS7ezj+DtQtwSpU7e7IOUuw
         kJEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NMCNzYEm;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id y72si155414ede.0.2019.12.11.23.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 23:42:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id n12so923751lfe.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 23:42:52 -0800 (PST)
X-Received: by 2002:ac2:5975:: with SMTP id h21mr4695940lfp.165.1576136571817;
        Wed, 11 Dec 2019 23:42:51 -0800 (PST)
Received: from [192.168.68.108] (115-64-122-209.tpgi.com.au. [115.64.122.209])
        by smtp.gmail.com with ESMTPSA id v5sm2444547ljk.67.2019.12.11.23.42.45
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 23:42:51 -0800 (PST)
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-5-dja@axtens.net>
 <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
 <875zincu8a.fsf@dja-thinkpad.axtens.net>
 <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
 <87wob3aqis.fsf@dja-thinkpad.axtens.net>
From: Balbir Singh <bsingharora@gmail.com>
Message-ID: <1bffad2d-db13-9808-afc9-5594f02dcf01@gmail.com>
Date: Thu, 12 Dec 2019 18:42:40 +1100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <87wob3aqis.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=NMCNzYEm;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::144
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 12/12/19 1:24 am, Daniel Axtens wrote:
> Hi Balbir,
> 
>>>>> +Discontiguous memory can occur when you have a machine with memory spread
>>>>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>>>>> +
>>>>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>>>>> + - then there's a gap,
>>>>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0000_0000
>>>>> +
>>>>> +This can create _significant_ issues:
>>>>> +
>>>>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, we would
>>>>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve the
>>>>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the shadow
>>>>> +   region. But when we try to access any of that, we'll try to access pages
>>>>> +   that are not physically present.
>>>>> +
>>>>
>>>> If we reserved memory for KASAN from each node (discontig region), we might survive
>>>> this no? May be we need NUMA aware KASAN? That might be a generic change, just thinking
>>>> out loud.
>>>
>>> The challenge is that - AIUI - in inline instrumentation, the compiler
>>> doesn't generate calls to things like __asan_loadN and
>>> __asan_storeN. Instead it uses -fasan-shadow-offset to compute the
>>> checks, and only calls the __asan_report* family of functions if it
>>> detects an issue. This also matches what I can observe with objdump
>>> across outline and inline instrumentation settings.
>>>
>>> This means that for this sort of thing to work we would need to either
>>> drop back to out-of-line calls, or teach the compiler how to use a
>>> nonlinear, NUMA aware mem-to-shadow mapping.
>>
>> Yes, out of line is expensive, but seems to work well for all use cases.
> 
> I'm not sure this is true. Looking at scripts/Makefile.kasan, allocas,
> stacks and globals will only be instrumented if you can provide
> KASAN_SHADOW_OFFSET. In the case you're proposing, we can't provide a
> static offset. I _think_ this is a compiler limitation, where some of
> those instrumentations only work/make sense with a static offset, but
> perhaps that's not right? Dmitry and Andrey, can you shed some light on
> this?
> 

From what I can read, everything should still be supported, the info page
for gcc states that globals, stack asan should be enabled by default.
allocas may have limited meaning if stack-protector is turned on (no?)

> Also, as it currently stands, the speed difference between inline and
> outline is approximately 2x, and given that we'd like to run this
> full-time in syzkaller I think there is value in trading off speed for
> some limitations.
> 

Full speed vs actually working across different configurations?

>> BTW, the current set of patches just hang if I try to make the default
>> mode as out of line
> 
> Do you have CONFIG_RELOCATABLE?
> 
> I've tested the following process:
> 
> # 1) apply patches on a fresh linux-next
> # 2) output dir
> mkdir ../out-3s-kasan
> 
> # 3) merge in the relevant config snippets
> cat > kasan.config << EOF
> CONFIG_EXPERT=y
> CONFIG_LD_HEAD_STUB_CATCH=y
> 
> CONFIG_RELOCATABLE=y
> 
> CONFIG_KASAN=y
> CONFIG_KASAN_GENERIC=y
> CONFIG_KASAN_OUTLINE=y
> 
> CONFIG_PHYS_MEM_SIZE_FOR_KASAN=2048
> EOF
> 

I think I got CONFIG_PHYS_MEM_SIZE_FOR_KASN wrong, honestly I don't get why
we need this size? The size is in MB and the default is 0. 

Why does the powerpc port of KASAN need the SIZE to be explicitly specified?

Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1bffad2d-db13-9808-afc9-5594f02dcf01%40gmail.com.
