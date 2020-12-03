Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGX7UL7AKGQEKQUISRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id E86932CD3C0
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 11:36:11 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id n9sf1075194iog.6
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 02:36:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606991770; cv=pass;
        d=google.com; s=arc-20160816;
        b=fj8zgsaJOJfs5S86VcL9CS3mQXxdO6Wy1dvL1Xoqvd8KVwfy/oFCSoST9rIA9vsO9t
         /l/tiWf1ryFx3uRhstjzYjzAmBDfEvGuZJtG3Z4ro5jALYo91kMRG7D97nEnzLi1NLMj
         HtGjnr0FN3vQSjcJ5Cy3bgKeo1IIiHiHyrosTuf23eW4/PRU+p7kKc4ngOlpZgPvIJqg
         GNt98BkNpjrixX/pKE4oKJ/vd1f4+IAi1Vq8ntWjOCUykp5iAwC8nyl21GjfDbyAqm5h
         Z8tPflajyqshjkGkE+LNPNYdejtlThhLSspr9GDGbY+CWGuoR7cqRV3LVt+rDMEkYZ91
         G3kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=uRct5je60sx+7j0G821JGpYQ2qhB44bScZLIGpdWZnA=;
        b=nwOAZQaNDFzrAUdsRgtxbcZIWeSg2DCqJTRgVxNPPmVfMXR6gShMFS0quO2OEOoy4E
         +gljsQecMCXaJo02XtgF4qZ1BR40j05Uqz/y8elhRZWQy7Wc6cwm5XXmZfOyrzHWKRiR
         AnFePqkFq6AJECQzZFDQ/vbztiJwGgyFiWG5WJf1nTM+dYnCUUT/Y/XtlLYrbsIv8WjV
         YsHK+Mpc1cRduUVInmM5rF2PWQcOZPkO7VuZw8HUBft+zeg3g/wzc3em09VLVpSrS8Nk
         0IXg77sNGiQlJ5LeHlRs65F9S6HHLIGXc+aZpA7V5rur5Yt+/6p+RctpvA6atHDN+DFA
         f1BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRct5je60sx+7j0G821JGpYQ2qhB44bScZLIGpdWZnA=;
        b=LVm+gX5uMfbeO038WkfBt9wHNFOqFCSq6LvAIJ9VL3MhB7ylDY1UZErrqlTq9pNXGO
         akGuNgzsP89O1FDo/gmh97u0AWw0np5ciaUBRzWeMf9gFvb/2JNCbe18LsqkoLoz7Dmk
         9y73ZP9vepANrkkheRDWuTt7CHFeIW+MoMlu3XhFFzH/6wMwmj2CZ5ySos9ua2RomPkf
         rnAwDHZvR0SJbE3PWEQSUxlj9mkLpEVoqbvrcNyLa4hWtXa+4nXDMUVwhU5dMpjsuv+m
         9FUt0xXeGunORKiBQwSLac9+c4g+b3nNNOdZPxh2+2IGkWSrf0L+51CYjTKl73OJq5+0
         eS7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uRct5je60sx+7j0G821JGpYQ2qhB44bScZLIGpdWZnA=;
        b=o0yIYXJqQE/n+PyZFmPmj9w4hBTtvxPkX0jvW+84kwB5Jb6pFpq510w159f2vMV/jH
         R2YwvZWV2xrV6wVdY8Nub33cBB9rd43nVQgKOpeLI7c9ZsMgwqyY3nVUBmcfzeBandBn
         nY3Z/uyse8+/i1rIxNelvQp674z6gO5lGnpLC+OVb12SOiyBunIEb3HBeoLFs55vx73U
         s6tuQb6c4wKYH6SpGAl0zE2VMPDfCxI7VDMDfzi35BYv235hQw2vJDQtDI772Zo8AaAc
         /UKhgrz1POZjym8ciHI9dzNG6sM9/2v/cmTEvl2+yO9iDsq+qnrG2i3mhGrIPlICtVSP
         8Liw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NCnfqcsFWg9oVLbn3BjUGmeflEze0nKXz6Sky5aCVQomBAr7G
	CgEQNaaRYwbNT1J7b6Pwpvo=
X-Google-Smtp-Source: ABdhPJyagybIN94trqtIEBfU2kokylJ04Jx69HSuDGUv0KkWulvB0ztklAsY4w5yejbWL1U+ei0GfA==
X-Received: by 2002:a92:4002:: with SMTP id n2mr2264073ila.293.1606991770569;
        Thu, 03 Dec 2020 02:36:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2d42:: with SMTP id d2ls831916iow.11.gmail; Thu, 03
 Dec 2020 02:36:10 -0800 (PST)
X-Received: by 2002:a6b:c94c:: with SMTP id z73mr2567728iof.95.1606991770231;
        Thu, 03 Dec 2020 02:36:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606991770; cv=none;
        d=google.com; s=arc-20160816;
        b=kDAu4pZlSBRxtSEUEupG6zkVfOnxya+S7sFnpLUx6YbBWogKmKR4wMjAGoXnQsSaqO
         kFYf6+iS+blfLVueVuU2jH+3Wrg3UGh9CDiA0O8kYNv8n+QLTJQcQr3SCD2SkOnI6Hh6
         rT5viHBvwUIn/ZqJ5p4G8RYnmjuKkPuOIVswjL+9ARzyrPaSYoEI2byjQEoiyTpdNqS4
         5BSlxXWQ3QplLUQHhOc9y9DtSmxMNHPsdUWs4G7BeF2c1haTGKOER7Xcjie951flVrJN
         bq/u7D7lVN1MgzPi1ADHwBwn7xK9gCdCbYYTJKcmGnnrqhVzeP4DTbfsC6DZPGgNGkAd
         R7fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IM8+GG6O5vbRIGY71EWezSM3Gq8UEYltyxJSFATZ3Yw=;
        b=WxfvRJfZ+qn5bVilvSqX6uedF5EMDfJzpvJ0ZOcWCDCQS+2/KKcbYOLu29jrH30Myk
         9xRaOlLgrsKukBQoyVjnp1bvyJvS6Wpc3QecTaWONHQMqjtpzLcZxJ8Go2jfdtlMlrBI
         3A4duGqR7259nnmUobwd1ob7SpXhMMxu8enCJyb7yE6JHWyit3aj2k+zS0i9zAvzhR3J
         aOiU4r4Oi+DnhlNvYgrpccniqN9+NoW74/pNeZADCCFCbfNSyrpuz7Xxu4ios2doP2je
         E212gKarfCHpA3PPppwZLTOBhIe1UL7t0jzubYsFru+UgqWTUePaZPVoN1GeiYoN5aLd
         n3hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y11si40140ily.1.2020.12.03.02.36.10
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Dec 2020 02:36:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B7987113E;
	Thu,  3 Dec 2020 02:36:09 -0800 (PST)
Received: from [10.37.8.53] (unknown [10.37.8.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 54BB33F575;
	Thu,  3 Dec 2020 02:36:06 -0800 (PST)
Subject: Re: [PATCH mm v11 27/42] arm64: mte: Add in-kernel tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>
References: <cover.1606161801.git.andreyknvl@google.com>
 <ad31529b073e22840b7a2246172c2b67747ed7c4.1606161801.git.andreyknvl@google.com>
 <20201203102628.GB2224@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c1e9c10a-c4d0-caf5-5501-6d676ac2abea@arm.com>
Date: Thu, 3 Dec 2020 10:39:22 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201203102628.GB2224@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 12/3/20 10:26 AM, Catalin Marinas wrote:
>>  static inline void uaccess_enable(void)
>>  {
>> +	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
>> +				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
>> +
>>  	__uaccess_enable(ARM64_HAS_PAN);
>>  }
>=20
> I think that's insufficient if CONFIG_ARM64_PAN is disabled. In the !PAN
> case, the get/put_user() accessors use standard LDR/STR instructions
> which would follow the TCF rather than TCF0 mode checking. However, they
> don't use the above uaccess_disable/enable() functions.
>=20
> The current user space support is affected as well but luckily we just
> skip tag checking on the uaccess routines if !PAN since the kernel TCF
> is 0. With the in-kernel MTE, TCF may be more strict than TCF0.
>=20
> My suggestion is to simply make CONFIG_ARM64_MTE depend on (or select)
> PAN. Architecturally this should work since PAN is required for ARMv8.1,
> so present with any MTE implementation. This patch is on top of -next,
> though it has a Fixes tag in 5.10:
>=20

Agreed, since PAN is required for ARMv8.1 we should not find any implementa=
tion
of MTE that lacks PAN.

> --------------------------8<---------------------------
> From ecc819804c1fb1ad498d7ced07e01e3b3e055a3f Mon Sep 17 00:00:00 2001
> From: Catalin Marinas <catalin.marinas@arm.com>
> Date: Thu, 3 Dec 2020 10:15:39 +0000
> Subject: [PATCH] arm64: mte: Ensure CONFIG_ARM64_PAN is enabled with MTE
>=20
> The uaccess routines like get/put_user() rely on the user TCF0 mode
> setting for tag checking. However, if CONFIG_ARM64_PAN is disabled,
> these routines would use the standard LDR/STR instructions and therefore
> the kernel TCF mode. In 5.10, the kernel TCF=3D=3D0, so no tag checking, =
but
> this will change with the in-kernel MTE support.
>=20
> Make ARM64_MTE depend on ARM64_PAN.
>=20
> Fixes: 89b94df9dfb1 ("arm64: mte: Kconfig entry")
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  arch/arm64/Kconfig | 2 ++
>  1 file changed, 2 insertions(+)
>=20
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>=20
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 844d62df776c..f9eed3a5917e 100644
>=20
> --- a/arch/arm64/Kconfig
>=20
> +++ b/arch/arm64/Kconfig
>=20
> @@ -1673,6 +1673,8 @@
>=20
>  config ARM64_MTE
>=20
> =C2=BB default=C2=B7y
> =C2=BB depends=C2=B7on=C2=B7ARM64_AS_HAS_MTE=C2=B7&&=C2=B7ARM64_TAGGED_AD=
DR_ABI
> =C2=BB depends=C2=B7on=C2=B7AS_HAS_ARMV8_5
> +=C2=BB #=C2=B7Required=C2=B7for=C2=B7tag=C2=B7checking=C2=B7in=C2=B7the=
=C2=B7uaccess=C2=B7routines
> +=C2=BB depends=C2=B7on=C2=B7ARM64_PAN
> =C2=BB select=C2=B7ARCH_USES_HIGH_VMA_FLAGS
> =C2=BB help
> =C2=BB =C2=B7=C2=B7Memory=C2=B7Tagging=C2=B7(part=C2=B7of=C2=B7the=C2=B7A=
RMv8.5=C2=B7Extensions)=C2=B7provides

--=20
Regards,
Vincenzo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c1e9c10a-c4d0-caf5-5501-6d676ac2abea%40arm.com.
