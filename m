Return-Path: <kasan-dev+bncBCXLBLOA7IGBBKEVZDXQKGQEIIYJC7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 87E8811C958
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 10:38:49 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id l2sf296929lja.18
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:38:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576143529; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4VXoGyN6PRKk1OaF+HUsFSebPf+vlVKWGtRCazPW49ZKRIG2VPzXyBlEmUTZ2Bj4z
         FYc7RRCsFgoJ7QDDBLogZgYLEFe/MNF6lGHoAEtbruNkr9NRvbMPtTghWihxhiBVLHUZ
         SNrRbAdHD8zPiWgqMkkoTo7woIKUJK9L4CoGm7B6Sm1sQLUNpwYghDoH3ndag/8XpCyu
         3jxsGTCZnUHBLQH8cmfyLKTZNlyUXaY968aBy3dFXSvj4zjBxKRfKTSZwG5RzdDmbbPA
         4s4wTp6ZmMFh2lex35/iyGErJlBLRdlLuogGcqpi4DrgFPJXoammeJ9kyCCJYbYJ8lgi
         XNkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=loAq94MmHGJ3VkUJWmbjE2ELiaOKxvAN6nEkK6Txy7g=;
        b=zDJsq7vj35FT27F15sBmeNwWPxRt4FpvEoaamaa+jxJgnY2QIRRzS8h8vehevMxuVY
         u6Uz5n+ojqKOkRvKoRh2OwrRVJuWBO3M0H7dA2aZi1OVgboC4UpVDu3agJiq1PJGSHKz
         8+ANlKD3t1r9+exYxyNT3llGrCa1SpqJK9xytVHHMh952x4aMaWKUYDgx2oYHoOSY0k7
         1Pv6qW/xj4VXVY943X9m8pnCthBI1OFnR+xezo4szUdAGKP2D3UapUIG8W2nEPc59FF+
         f/2NXtuNdayCP8SYPfPG5aqWjBiQG+1bQSxNCBU3n7Vcllwn5B8Q8UBjsOHg1hmHz1J8
         664w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=ud0LAurH;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=loAq94MmHGJ3VkUJWmbjE2ELiaOKxvAN6nEkK6Txy7g=;
        b=WewTZ8QrYMAE9ThbOtllUvixSh7GccDKPjVlYBlDEhtbkiWllx+e0N/OWuxKaaEPm1
         kYprBn3y+/oKtM2cwsKgUk/Bwblo+p0oOLNvgvGboac27rX0aiRMlTupw8ydqjzAc9Ox
         8JAPKbPzt+RLhU/mnaz6C9ElEKQyRywjyr2OVJ+N8FFceeRQFFTNWdxxmXWmVKyuKFc+
         4ItYsTeBftjfg2p0wqy6D/wRJZjNEYCesPRULO3RSYQEhtCZ3tJF5AfPL55fpnlKfX2r
         7vMgqf8OLWV/YrwdQxSVnuy4ou8nheLaE+vH8VlEw2YMKclrWt69K9ed6Fkx5CbRPrxn
         CLRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=loAq94MmHGJ3VkUJWmbjE2ELiaOKxvAN6nEkK6Txy7g=;
        b=nBv0IsvARwlt8WPoG6WcTp6AptixLHboVyNbVerzu7NhQo4597v/qreZyTN+G2R0ol
         UeVX4AaqK5ZyiL2/TIS56faewv16c4S0J/RCG7ZMw45dtXyjKYGc0EclosONogRWQjtV
         5BqFdgS2COToU8W4HHWEPe9XGxXPyQSwKj7hyUimmOdxmNVX/vC02kz/VYn+B0eU2iD9
         Hj/ROnIAadVozZHfYnQckKoP+w1LH2Dn8VN87VJRuZjDzkhGQvrbXfxOplDtvHXyOMMW
         qVAdn5us36OoNAoHbnObQnHsBUHQw5nWFHcyqgjVLrg7to5/9opActMoPDoYMkupt8Qh
         R9eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnvdx0hviqTsLbUwwURlJF+6lQhMtAOGaGLyRqV5nsSOje5wB2
	0PxYhD6asPZDh0cbUqgyktU=
X-Google-Smtp-Source: APXvYqwt+VAMLo9fY1qShnQKhOJ+7swTLnk753gLnYxBQDz+lxuzykVeEWdYQeKbOfWIx35H46y9cw==
X-Received: by 2002:a2e:9a8b:: with SMTP id p11mr5150542lji.5.1576143529064;
        Thu, 12 Dec 2019 01:38:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:915d:: with SMTP id y29ls472156lfj.7.gmail; Thu, 12 Dec
 2019 01:38:48 -0800 (PST)
X-Received: by 2002:a19:84d:: with SMTP id 74mr4982277lfi.122.1576143528388;
        Thu, 12 Dec 2019 01:38:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576143528; cv=none;
        d=google.com; s=arc-20160816;
        b=tLP1r/zmuSgJ22p22yRheLdJY+P0moRGScGtND9KQD2Wr/6Us80IRC038sZy27ASnu
         48PXJSlVucSs490qNOSE1qP9k+t27mNJM+ydazZAMsCKXxRByJ9F3HHobqjrDhs8TzKa
         XS0S58vSEu4LGFEnmtsz7Ag3/WG2DxbjivAZZDitSVf3+8Impz5Ark1ed7nZkaBNBjOm
         TO5O7h12d2a4WptQJr7E+o6RYNTvE9BF/Hqt0TBqvg956GJtHpGA2JK9Z8KZwTOp1s24
         Z/3UdoE022LNzV2SRuLvd0vzBe9FPX9E15PASkQ/WCyLzsSinctvMr3/VHYcA/wiO3f0
         EGeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=PmEFgaQ7Eo9rbAL5MPouRGU/8Glf/6NoE8/kyEXX9XI=;
        b=POz32v+BsovfSs/beQ7xDfTaOTQ07oH7ZMr4kcXymDxqcmEw5mS1PR5UHG68eqBncN
         f1xziI5EDIlHJI/sbPFWxoQWvpE8tPyQDy7PQcxmNPtU3/jMts+gqnVR5j3597yZC4KI
         yzLK692kX5m/ZYWq0rpoy3cOG0zjdkb9iGpOFrZKjswAs4nwoE8tRyO8d+7zRHh8gwW+
         xshefY5e4K/Pe1h9zQDT+Tho+aLOta/bYXItls4j1OoWR6v38EQk2FdwehZXOHMe4JBX
         c2CavKU+dSXLrLUWux64MABuLm5pDYmc8lxXTvyktAHO3/JLs1UO7Y7/ccB6NM2g2mfO
         O1Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=ud0LAurH;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id x5si194791ljh.5.2019.12.12.01.38.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Dec 2019 01:38:48 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47YTJQ19QQz9tx9d;
	Thu, 12 Dec 2019 10:38:46 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id PtgGjD3L2HhS; Thu, 12 Dec 2019 10:38:46 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47YTJQ04Spz9tx9b;
	Thu, 12 Dec 2019 10:38:46 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1E80E8B85B;
	Thu, 12 Dec 2019 10:38:47 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id kkSWjlcM3lXj; Thu, 12 Dec 2019 10:38:47 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 350948B776;
	Thu, 12 Dec 2019 10:38:46 +0100 (CET)
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Balbir Singh <bsingharora@gmail.com>, Daniel Axtens <dja@axtens.net>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
 linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
 aneesh.kumar@linux.ibm.com, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-5-dja@axtens.net>
 <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
 <875zincu8a.fsf@dja-thinkpad.axtens.net>
 <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
 <87wob3aqis.fsf@dja-thinkpad.axtens.net>
 <1bffad2d-db13-9808-afc9-5594f02dcf01@gmail.com>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <2f017b74-b6f4-5723-591a-fe7525b85419@c-s.fr>
Date: Thu, 12 Dec 2019 10:38:45 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <1bffad2d-db13-9808-afc9-5594f02dcf01@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=ud0LAurH;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 12/12/2019 =C3=A0 08:42, Balbir Singh a =C3=A9crit=C2=A0:
>=20
>=20
> On 12/12/19 1:24 am, Daniel Axtens wrote:
>> Hi Balbir,
>>
>>>>>> +Discontiguous memory can occur when you have a machine with memory =
spread
>>>>>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>>>>>> +
>>>>>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>>>>>> + - then there's a gap,
>>>>>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_20=
08_0000_0000
>>>>>> +
>>>>>> +This can create _significant_ issues:
>>>>>> +
>>>>>> + - If we try to treat the machine as having 64GB of _contiguous_ RA=
M, we would
>>>>>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then res=
erve the
>>>>>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as t=
he shadow
>>>>>> +   region. But when we try to access any of that, we'll try to acce=
ss pages
>>>>>> +   that are not physically present.
>>>>>> +
>>>>>
>>>>> If we reserved memory for KASAN from each node (discontig region), we=
 might survive
>>>>> this no? May be we need NUMA aware KASAN? That might be a generic cha=
nge, just thinking
>>>>> out loud.
>>>>
>>>> The challenge is that - AIUI - in inline instrumentation, the compiler
>>>> doesn't generate calls to things like __asan_loadN and
>>>> __asan_storeN. Instead it uses -fasan-shadow-offset to compute the
>>>> checks, and only calls the __asan_report* family of functions if it
>>>> detects an issue. This also matches what I can observe with objdump
>>>> across outline and inline instrumentation settings.
>>>>
>>>> This means that for this sort of thing to work we would need to either
>>>> drop back to out-of-line calls, or teach the compiler how to use a
>>>> nonlinear, NUMA aware mem-to-shadow mapping.
>>>
>>> Yes, out of line is expensive, but seems to work well for all use cases=
.
>>
>> I'm not sure this is true. Looking at scripts/Makefile.kasan, allocas,
>> stacks and globals will only be instrumented if you can provide
>> KASAN_SHADOW_OFFSET. In the case you're proposing, we can't provide a
>> static offset. I _think_ this is a compiler limitation, where some of
>> those instrumentations only work/make sense with a static offset, but
>> perhaps that's not right? Dmitry and Andrey, can you shed some light on
>> this?
>>
>=20
>  From what I can read, everything should still be supported, the info pag=
e
> for gcc states that globals, stack asan should be enabled by default.
> allocas may have limited meaning if stack-protector is turned on (no?)

Where do you read that ?

As far as I can see, there is not much details about=20
-fsanitize=3Dkernel-address and -fasan-shadow-offset=3Dnumber in GCC doc=20
(https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

[...]


>>
>=20
> I think I got CONFIG_PHYS_MEM_SIZE_FOR_KASN wrong, honestly I don't get w=
hy
> we need this size? The size is in MB and the default is 0.
>=20
> Why does the powerpc port of KASAN need the SIZE to be explicitly specifi=
ed?
>=20

AFAICS, it is explained in details in Daniel's commit log. That's=20
because on book3s64, KVM requires KASAN to also work when MMU is off.

The 0 default is for when CONFIG_KASAN is not selected, in order to=20
avoid a forest of #ifdefs in the code.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2f017b74-b6f4-5723-591a-fe7525b85419%40c-s.fr.
