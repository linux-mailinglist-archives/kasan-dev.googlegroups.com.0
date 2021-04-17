Return-Path: <kasan-dev+bncBC447XVYUEMRBUFU5SBQMGQEKJ55FRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D803436316C
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 19:26:40 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id 91-20020adf92640000b02901060747826esf4580075wrj.13
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 10:26:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618680400; cv=pass;
        d=google.com; s=arc-20160816;
        b=O/ZyJuP1HPyyTOsgjPJuMYVjirrWZEvlciotpDcNgDn7PBpXr+49flSUxY5QLjJZSg
         GnFZGPqegs3+BcOIlWtU8+2Iw9aHYK3Uu2ueEDTm9Q6qhtZUoDMFc4PvfOyUM9EojNmk
         tYL6hcSv7Z22ZC9TXitjNmCf69MgB5faDFHbtdxaAvgq+cIkEU0EtYYjsU88V5S1Lu1+
         rFdd/EEgy+PIf8/X+MKuid/H8uPDdbaNE2Fd3f1y1oRA84375sO+wXYwO7uDap44mB8x
         PxzF2mm30e+g/WCQSStO5l7A71Ae0TRTH13fjU1qEtPnOQqoF04QC5w2Ddd2aAkyGnxn
         bshQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=OnRFoxuce4HW8hBYZjOGFjhOy8Qh3c9vQ6rUePuFWCo=;
        b=VyRTkrZk+0nmvC8bqxZAynSuW7Dp6q1PEFU3WCptlkXqxLXsJUC5DiTLRHN8zVn24E
         r2R5n2A/hkaGSCUr1F1dAdZaNoSlygz3Bdq2OSMK2YNRfLnrw46x2Av2cmsAaXXDNohn
         Gh9TtOGUZHRTC5M1KtpjZnPMb9mSMtuARF8/wW3k1dNWxU9/S00J3HKGUUZBmhSACtqH
         HuuUXZ9FqgLkEMu6f/qy7VlZqNGj5ISvRB0y8fT8AYiTBDT+l9dhammat6DShexSgFkV
         +K5rTk3+rNaRhW5c9+Ky8GG+Xst27MfqZ4g0EVtzDL44NQU0bYxqDk3ifJ+ug0VilxaD
         LBfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OnRFoxuce4HW8hBYZjOGFjhOy8Qh3c9vQ6rUePuFWCo=;
        b=jFPt/5IKS4RqUj8uuyhvu4FZ2rT+YPiwFY1eMbyfdidyB/F+uSQaGhkT3aR+/11beV
         1VNzsJm43y8vjCo3uiZ2NvDJuw9sfTpYwr1L16lZS3EN+27zGxXVQBRiNfTUGxr3yac4
         an8+CxWuRZAOmam/4NYaZ2N2MpYgPFHjEaSa9/to01Z8FNSsIYsIhi6U5qdmu6BlcUos
         DWeZi8B6O6h2dNlbWtVkXFjeQHbSEyDBYj5zTkpnWJGNRZp+Hdhg0ku7ADULhZJfp1mj
         +JXPXWj+/8+bt6KdqhzOz5d8c3KnZX813XxeSJN7eBNrzs9U4nt2Z3B2NEOzGEpG7qUA
         HXGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OnRFoxuce4HW8hBYZjOGFjhOy8Qh3c9vQ6rUePuFWCo=;
        b=Eo+KPlzIsgCoY0ZvDNtd19tiueEFxtaxVVGcInRJuvGDR3YxiJ4TnPpwePsKbNEhVs
         HXx8XyELdpJJJGKguZdWkgTyY8yOuWG3VYMElIwprmc+IXlvEUc1UDVJUDSkd9xS3Mm+
         h2JXQ3ziEfFjUzH4dliC8WVqUHhpTbcoo0Z5xRkTMGYqWCmPbJ8UkRXdnHUypijyMI1G
         C0OgK35HMxhE0Odn/BwolhJQ2ybYNcAB5NiRqwFmMTnOSag8Zo+EAuHy7iwiaavkmsNQ
         S1my4+XhP43ny5BIbtK9HmuY0fu8+S5xLfLmYnN3+UM4YrVnmjjIpvPVQKyHt85Tr6o+
         972g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GH8R91kZ+QXrl/cXWwpnB+PHZ4e/RLSOrryCqWzoeWh49MV5w
	P3gNAJm4vJyUbMMkymq//4k=
X-Google-Smtp-Source: ABdhPJy5FXUUfu+ZIl83hI2Tn80vFyUrYo/M7mK6xL9DZoApQgpI36RwxN6LbdjaoApyYW+Xl2HoMw==
X-Received: by 2002:a7b:c20c:: with SMTP id x12mr13447392wmi.51.1618680400698;
        Sat, 17 Apr 2021 10:26:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6804:: with SMTP id w4ls2310293wru.2.gmail; Sat, 17 Apr
 2021 10:26:39 -0700 (PDT)
X-Received: by 2002:a05:6000:1567:: with SMTP id 7mr5078792wrz.47.1618680399936;
        Sat, 17 Apr 2021 10:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618680399; cv=none;
        d=google.com; s=arc-20160816;
        b=Z7ybRiaNrbF1nTJszoowlNnNEdexjYn2g65PLyVqSgNoyoo/xu7xNhZG6l+yJc9OVw
         Uub3Tualaok8Ya0CHM2Eji3AYNYZNUHweTlBSTWaRUOOEE8J2SMij1Tb3IygdtxP3sxA
         XPNNnSRu5ijCKFR5l+L2K44PnrLScJKv4iLFML0GEeZZxIhGBpVc0OalIi6GpTApnRMl
         nHJFmoO+gSktjTACorjQPaCuc6xKuPmZLcUqm3cDOTj6+E+NAhR/zHiJ9IGwphXwbOOP
         aAesN0HRo8/nvQz3wjQkpu7LjIjiXkJkkMjcoqqG3+jaSSQ1VIzAc1ah9oWXSpNaEk/l
         aNDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=On5c/ZGGJhSlObpkSo0BSTAa8iWyj8i8MJVorIMxnKA=;
        b=w6H4Hb+HXaUUL8l9kRQu1VpLPTnEn+jLCep5MpVPZJmeBX0/IfnFy7afWAetQrl3YJ
         Y6V3eF0hhc6W0WlXcyNoSGtMFmrmtS88DwcJBTKNpKqBKjN+qtolKRDv2y+9oaN6tYmG
         ob1RUrx5hsgoSko+Ln8zGZIoNWvSJptnrgZIRZlqMEkDar86c96KmrLVpnai3qHv931I
         9U4pMlHf6LCcYuyBzhI3rlC55Se+WYp+/12RWOChS27zrl2AtYqVjH4HxHtA4N+ajbbv
         nH3OKiFkViFH0abMDJBbsNINhv+H0tzDOtRIk298ySOY47qvgCG5RTRhdxKZLRqQ2g0T
         6jXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id i16si304865wmq.2.2021.04.17.10.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 17 Apr 2021 10:26:39 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 39881E0003;
	Sat, 17 Apr 2021 17:26:37 +0000 (UTC)
Subject: Re: [PATCH] riscv: Protect kernel linear mapping only if
 CONFIG_STRICT_KERNEL_RWX is set
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: anup@brainfault.org, corbet@lwn.net,
 Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
 dvyukov@google.com, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <mhng-9ab3280b-4523-4892-9f9a-338f55df8108@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <72130961-0419-9b1f-e88e-aa1e933f2942@ghiti.fr>
Date: Sat, 17 Apr 2021 13:26:36 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <mhng-9ab3280b-4523-4892-9f9a-338f55df8108@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Le 4/16/21 =C3=A0 12:33 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Fri, 16 Apr 2021 03:47:19 PDT (-0700), alex@ghiti.fr wrote:
>> Hi Anup,
>>
>> Le 4/16/21 =C3=A0 6:41 AM, Anup Patel a =C3=A9crit=C2=A0:
>>> On Thu, Apr 15, 2021 at 4:34 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>
>>>> If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different=20
>>>> permissions
>>>> to the kernel data and text sections, so make sure it is defined befor=
e
>>>> trying to protect the kernel linear mapping.
>>>>
>>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>>
>>> Maybe you should add "Fixes:" tag in commit tag ?
>>
>> Yes you're right I should have done that. Maybe Palmer will squash it as
>> it just entered for-next?
>=20
> Ya, I'll do it.=C2=A0 My testing box was just tied up last night for the =
rc8=20
> PR, so I threw this on for-next to get the buildbots to take a look.=20
> It's a bit too late to take something for this week, as I try to be=20
> pretty conservative this late in the cycle.=C2=A0 There's another kprobes=
 fix=20
> on the list so if we end up with an rc8 I might send this along with=20
> that, otherwise this'll just go onto for-next before the linear map=20
> changes that exercise the bug.
>=20
> You're more than welcome to just dig up the fixes tag and reply, my=20
> scripts pull all tags from replies (just like Revieweb-by).=C2=A0 Otherwi=
se=20
> I'll do it myself, most people don't really post Fixes tags that=20
> accurately so I go through it for pretty much everything anyway.

Here it is:

Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mapping"=
)

Thanks,

>=20
> Thanks for sorting this out so quickly!
>=20
>>
>>>
>>> Otherwise it looks good.
>>>
>>> Reviewed-by: Anup Patel <anup@brainfault.org>
>>
>> Thank you!
>>
>> Alex
>>
>>>
>>> Regards,
>>> Anup
>>>
>>>> ---
>>>> =C2=A0 arch/riscv/kernel/setup.c | 8 ++++----
>>>> =C2=A0 1 file changed, 4 insertions(+), 4 deletions(-)
>>>>
>>>> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
>>>> index 626003bb5fca..ab394d173cd4 100644
>>>> --- a/arch/riscv/kernel/setup.c
>>>> +++ b/arch/riscv/kernel/setup.c
>>>> @@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 sbi_init();
>>>>
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KER=
NEL_RWX))
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_STRICT_KER=
NEL_RWX)) {
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_text_data();
>>>> -
>>>> -#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_te=
xt_rodata();
>>>> +#ifdef CONFIG_64BIT
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 protect_kernel_linear_mapping_text_rodata();
>>>> =C2=A0 #endif
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>
>>>> =C2=A0 #ifdef CONFIG_SWIOTLB
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 swiotlb_init(1);
>>>> --=20
>>>> 2.20.1
>>>>
>>>
>>> _______________________________________________
>>> linux-riscv mailing list
>>> linux-riscv@lists.infradead.org
>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>>
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/72130961-0419-9b1f-e88e-aa1e933f2942%40ghiti.fr.
