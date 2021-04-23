Return-Path: <kasan-dev+bncBCRKNY4WZECBBPGIRCCAMGQESPKPJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5370E368A6A
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Apr 2021 03:34:53 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id o187-20020a2528c40000b02904e567b4bf7esf22433733ybo.10
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 18:34:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619141692; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOZXQW/8zCpifKA/ETVwclv8mS30IUFn4kfoDiIJF3mCVZVZUfMThkhxETI/3hW1tX
         yfO7BRIc4ruSIN1GaY7R0rvt3jAM+1xaeMv2aHRSv+9wuoI1XiVGMLB8PjbN44bEI/uY
         Fb6OkQtBuCLL9X5j65uvUErbeKFds1EZei6Kg/MmJSR5gWin9FhUFxufym33xawagxh6
         3aqeoDAMet+FbAbBYG+bZHqBUKHJh0qIV4u/ZnMlkTfU2jwn/X7dPRk6qz8D16VHoXtg
         tElGxTi89gdJA/wtgtxuQgulsdj5JyLfJkeG3OcMcEWIgxG1jp7mCCB+uqMDZlAfClfB
         /I4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=hkhmUwjqqniPAEXYWWY7Bjzp1egvB5tfUw0kWjbScd8=;
        b=wt50hBXYEk2mGZsVEP4gB9SSvzpvR8d6etZgyLpZtikIcdzyE/ur9S9NGLLnbJ5qwu
         WVNWxhCFBvtXeLZV91CtsaHW83IXN1klAoNWJIZL01ee934QOWkZtgF1dRmR1+0KYZTO
         rA8cAszgL/yIHrqTk4I2D1H+nqO3l8qeZpfNsWDj4N1sr84NFqa+4PRZV5KadBMzEChq
         nL/cZVNoJD3qYwIjMoc2HdQBy6guxECcdizQ6+bioU8Qm6LZGoAJP0o05jCWU4Vtxl8b
         mPZC/xooZTUqLyfeFpTTODLljbTP/Cp+OA/HoMicBnY2ZQT74KtHyGbpLn4V/5+dtU2+
         XNOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=kTIabuH9;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hkhmUwjqqniPAEXYWWY7Bjzp1egvB5tfUw0kWjbScd8=;
        b=ExdGp5wdmOgQTwFbxpYXVwQLimSiVQ3Jm2S/yf5aGnIuXuq7t37I1umxX3nHKoK4Ju
         gvLryeAeuJhFIL/+XrZgqXWKXfZc1r41lXOAGnycQmVgaDemzj9uS5uP9Ir291puT4uQ
         lliiFtqBYrB6pgMPSI4qTpCfLe+X+ZhLNRhC616o0lyuFh8xcpA/uhP1X6/Pz1ia6wPz
         lwkWB5845MHYHN0zsSe0l25BpslF7y+/ZSJRQhaucj0WUkCHtZOKfCnVmvibbsmJidUE
         zwZ5pUSdsFG7+rkXan3Bpm77v9k5IEiZZlyaQsL24E1So1DOWHDcqUB5ZP/pEzdSbThN
         WiCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hkhmUwjqqniPAEXYWWY7Bjzp1egvB5tfUw0kWjbScd8=;
        b=ImkHTW9I2rj63C/0Los17UJ/sznJ6Lpd2FEC7XI/YDP3EKPN6FjU6y2k6/28oouhFi
         QgolnJqxzpcVwpvNyQxB6F8V1QllDRhXOfeMYfCy9exCEjr2UcuWeQLonydg4kSj8XPf
         Vi/gi8HSI9gCy/MCBV+NNSVa7wS9jlY/lNDyuJNYVMDMIIxzgOI13KeC4E0Vrl3CXzb2
         asFnT3RAxdzjENGFvd5xh6VYO/KuF5UkgkuVPJiZxUde+cwaCYyMhwEOF58OT490LBQH
         uxCvY9Qpy92UDmRAMVtbMuT8Jx6GzImITy9wPWcfn8MsM1EpxzGfakcih9YyzFHobe8O
         jUGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533j5W0cf/5HrzWYSklgyRa7K9iNkw1J8MFOjNW/Nio3Mv6cZXYF
	8krp9fEiCwmVVXc+ZRf2FRc=
X-Google-Smtp-Source: ABdhPJwHb34Z8wIFlqn66eQCgsKt9gLvCYN6uQ3S/8PFhA2DjZF9N5Swc/wBqyLWa9VTgW1sVDFbNw==
X-Received: by 2002:a25:dc46:: with SMTP id y67mr2211363ybe.27.1619141692416;
        Thu, 22 Apr 2021 18:34:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:da84:: with SMTP id n126ls3565448ybf.3.gmail; Thu, 22
 Apr 2021 18:34:51 -0700 (PDT)
X-Received: by 2002:a25:188b:: with SMTP id 133mr2151551yby.65.1619141691770;
        Thu, 22 Apr 2021 18:34:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619141691; cv=none;
        d=google.com; s=arc-20160816;
        b=v7IubQ0iCYrLwQ8KUACKj51cWdb1eGFIwZy7fTH1oSExAsHXqdewZ8YmhyQKmqlgby
         4vm4l5Bcq2Ej/+klB+TRoWRYvd4WSE6EDvTK1Ds1HI0tmLadpr91HLl8GaiuZtDpLPvk
         6vD5S8mZoy2YAWGKMmXrKAvPWT37szETI4Kp2DylWfWUIFktcXhoBRpoZPKmvZgSnkHy
         g+ZP2SgTdb+2Jb7BmZ9RW+2r1vQtwza2ag7UkY241zQhE5z8YYGlWKLpRzTX2ki0r2BO
         T8u8T8YztogvGkcfO3mPVT7ZdNLebq13AC/cjGSyE267h7d3ZFmDsgAvHCo5K9J6q+QX
         Tkiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=2u9IVBbrQtK5nxCkY5Ql7e2S1s+pJgrMEaI8rlOVi1A=;
        b=GqgT1yLy45X0qioLGL9QKcY69ArPfC0L0e+oPousYUp18/LtlUJyF6wkG6VvU3/7lr
         ldeVxANoZh4FpdOlmGE8NZ6s4SHRM8yaMVndwlNfmk+9oimRFyOjOcVL14JvaSo0KMYH
         7tM8KvmC98YZPKY/jlI84jRB7pbtb9L9Dmr+2ZIHJ2Dgk1y6kK/lHetRnDxX+VeyPv9i
         JQring7YICae2Tm9fWUK5kUzEy1zThufAq0WPrVSTcMLcsfZbi5Py3KEdLR77xZyuWFW
         8bVB7MZOjiyHPxlMdH3Sk6ulpbZz2LiBPHQngHxnFOWK40yeffVUJJsxr/ECIhUJFzDa
         PWow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=kTIabuH9;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id f13si778635ybp.0.2021.04.22.18.34.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 18:34:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id j6-20020a17090adc86b02900cbfe6f2c96so389937pjv.1
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 18:34:51 -0700 (PDT)
X-Received: by 2002:a17:90b:950:: with SMTP id dw16mr3058402pjb.68.1619141690659;
        Thu, 22 Apr 2021 18:34:50 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id w140sm3106903pfc.176.2021.04.22.18.34.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Apr 2021 18:34:50 -0700 (PDT)
Date: Thu, 22 Apr 2021 18:34:50 -0700 (PDT)
Subject: Re: [PATCH] riscv: Protect kernel linear mapping only if CONFIG_STRICT_KERNEL_RWX is set
In-Reply-To: <72130961-0419-9b1f-e88e-aa1e933f2942@ghiti.fr>
CC: anup@brainfault.org, corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-45fde203-6fd8-408c-b911-3efbb83d9cf3@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=kTIabuH9;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sat, 17 Apr 2021 10:26:36 PDT (-0700), alex@ghiti.fr wrote:
> Le 4/16/21 =C3=A0 12:33 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>> On Fri, 16 Apr 2021 03:47:19 PDT (-0700), alex@ghiti.fr wrote:
>>> Hi Anup,
>>>
>>> Le 4/16/21 =C3=A0 6:41 AM, Anup Patel a =C3=A9crit=C2=A0:
>>>> On Thu, Apr 15, 2021 at 4:34 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>>
>>>>> If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different
>>>>> permissions
>>>>> to the kernel data and text sections, so make sure it is defined befo=
re
>>>>> trying to protect the kernel linear mapping.
>>>>>
>>>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>>>
>>>> Maybe you should add "Fixes:" tag in commit tag ?
>>>
>>> Yes you're right I should have done that. Maybe Palmer will squash it a=
s
>>> it just entered for-next?
>>
>> Ya, I'll do it.=C2=A0 My testing box was just tied up last night for the=
 rc8
>> PR, so I threw this on for-next to get the buildbots to take a look.
>> It's a bit too late to take something for this week, as I try to be
>> pretty conservative this late in the cycle.=C2=A0 There's another kprobe=
s fix
>> on the list so if we end up with an rc8 I might send this along with
>> that, otherwise this'll just go onto for-next before the linear map
>> changes that exercise the bug.
>>
>> You're more than welcome to just dig up the fixes tag and reply, my
>> scripts pull all tags from replies (just like Revieweb-by).=C2=A0 Otherw=
ise
>> I'll do it myself, most people don't really post Fixes tags that
>> accurately so I go through it for pretty much everything anyway.
>
> Here it is:
>
> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mappin=
g")

Thanks.  I just squashed it, though, as I had to rewrite this anyway.

>
> Thanks,
>
>>
>> Thanks for sorting this out so quickly!
>>
>>>
>>>>
>>>> Otherwise it looks good.
>>>>
>>>> Reviewed-by: Anup Patel <anup@brainfault.org>
>>>
>>> Thank you!
>>>
>>> Alex
>>>
>>>>
>>>> Regards,
>>>> Anup
>>>>
>>>>> ---
>>>>> =C2=A0 arch/riscv/kernel/setup.c | 8 ++++----
>>>>> =C2=A0 1 file changed, 4 insertions(+), 4 deletions(-)
>>>>>
>>>>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>>>>> index 626003bb5fca..ab394d173cd4 100644
>>>>> --- a/arch/riscv/kernel/setup.c
>>>>> +++ b/arch/riscv/kernel/setup.c
>>>>> @@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
>>>>>
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 sbi_init();
>>>>>
>>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KE=
RNEL_RWX))
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KE=
RNEL_RWX)) {
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_text_data();
>>>>> -
>>>>> -#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_t=
ext_rodata();
>>>>> +#ifdef CONFIG_64BIT
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_text_rodata();
>>>>> =C2=A0 #endif
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>
>>>>> =C2=A0 #ifdef CONFIG_SWIOTLB
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 swiotlb_init(1);
>>>>> --
>>>>> 2.20.1
>>>>>
>>>>
>>>> _______________________________________________
>>>> linux-riscv mailing list
>>>> linux-riscv@lists.infradead.org
>>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>>>
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-45fde203-6fd8-408c-b911-3efbb83d9cf3%40palmerdabbelt-glaptop=
.
