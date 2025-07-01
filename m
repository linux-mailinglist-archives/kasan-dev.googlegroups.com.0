Return-Path: <kasan-dev+bncBDLKPY4HVQKBB7P2R3BQMGQER2E2XZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C98B8AEF58E
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jul 2025 12:50:40 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553af0e0247sf2978010e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jul 2025 03:50:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751367039; cv=pass;
        d=google.com; s=arc-20240605;
        b=eU3PVr04Mgq18EkoL4zFgRU794s/oUqSuR/WIaCdKYaAPy/FitylJAaETgxQk4tY8S
         BiGMp4aEZDBPqsjMx0BzOtlGSYsUXNuRTPYlalYfezTysliLo2uz9Pi1j6Y9nM6W+jlQ
         u5s6YNed/rRej37s8lyiwjLpugEsXgkYpLT450c5Q3lnbHLjRAHuD0QxN/r3a+DRU3TQ
         DyTfgJZIzQddUDs655d5SibEmajqXZ12ewpAHWsf0jIfS7ncIjHWrrDTaEYV72TXRLRO
         IL52ITtaf/tPNdbrCn2MD1OtkV86icWM3h1XdhvdXhQCrELMRWHWLTO99CrFbh7fB32n
         I1tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=JpGZds01o3iRgUEOGlk0YN1xJSoVpg9BAPUtJDZggB8=;
        fh=lZhANm0RenqtRZiGP85C9kir07uNb1G1r1snj4LvLI8=;
        b=iGK2lLYtKkq75sC3O3ZxkUSkEJtpRxfqmX3ZMs/fpjDvsBV3Sz9mrL1dsSaKA2ugOr
         LHBdDyk0T72Gd+yqqUlpuW9+mFCj70CJ7S7HvwNF+yiFCYDFAih52KNLa3reEK6XnJpr
         0im52BsPz1CNF3F6ejprtJ64i17r8J+u5XQhlGBbL/Ga1lfYG+xWqMiXTOBDiQmtbvTG
         WpfAcG/QypYRRdsKIfFvnbwgN1z2Jdxo37ijgxr2WRHoZDKSEZ4UQqT9BzL96V/dsNTi
         l+ORRbRcZgr6CF8TvTxcvizrdcMxvF1o5vrzTNKnnthc2pPCkvAGOCR3S9wES4IIY35f
         58Yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751367039; x=1751971839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JpGZds01o3iRgUEOGlk0YN1xJSoVpg9BAPUtJDZggB8=;
        b=wzVB8QLp1WgbqqxBN4p+oYCv0ORLIJV121jdHOUZs5lYqtE0fINj0igYzd3zVy3CPy
         kFEXsB9iMa2pzBSWjnHV+/L/3xP5D79oCit7gnmwLbK2F6meMt1x7NBC7HREeWl5EAIk
         PaIkP61BBsnVhLl74WLgAXYNDA3E1D9ARhCh2wU3IqAf0GzHP24UVPS25MqhqjP3LqmX
         rHa5Dvl7UNWxHLnKGaQQmqLXmQFk3/rtsF9EonzjfqPU2kQS8ees2847y6TeE3hUqQi4
         auh3oayC2Neonn6MfqDTTi7TkrGd0FVisA9cyF01+U7zq7P2k1XGP5ph0paFvAMpDmBq
         norA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751367039; x=1751971839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JpGZds01o3iRgUEOGlk0YN1xJSoVpg9BAPUtJDZggB8=;
        b=lBUB3vQoVOdXBTVA7bfi3lXiSlQReDqpw73Q7njfmQHGrjSUToWl0WNYbbyZAIFgyr
         /lGE/zp9nnByMFGEctLmSpuXOgUhW3ypWx859awNdksPaHkCrkuBKNdpi42JQnXzOMHe
         RgeayWPmI4/Xzdjg+rXtr+zS9bYsqeVDLBIKuOVTcwX4uZyIIJvcqMS9LRRREtconxFm
         cSFaQoXJZUwZAOuVjaHi/TSrvX79pWVL6kpwHMDZf3n3lhEnE7HVaaHStSbDYgYrM8yk
         eENdvW6SJn4lqHRZbi2zOuRg6Ol+vblukMYg53NR0qexRH8WkmLXJfYbJ7RizDHdbRSb
         Ohtg==
X-Forwarded-Encrypted: i=2; AJvYcCX6uxvpYz0s5xSKV8PtX8sWzGPhTwM4LtMcMTrCVLa+PljGq1SOA5erBv6TJBCKix2GNG2woQ==@lfdr.de
X-Gm-Message-State: AOJu0YzBO+fcPTEsywbFeWVgLQhpgarUJ50OJPKlpbk4PcTRCLOtUSdL
	cFvxeMl554TM1IxNFaIIXXqew7whA9jAtLsM+Zgmv+9WlHvisEB6PnOZ
X-Google-Smtp-Source: AGHT+IEGlENCN0Q7D9B//ChW1iHSSj9mK7FGOQ97CRj1hus3ERb9w0bsUdo0Xtq9ZOD3TAZxmC65ig==
X-Received: by 2002:ac2:4e01:0:b0:54f:c1cc:1241 with SMTP id 2adb3069b0e04-55623530820mr646304e87.25.1751367038428;
        Tue, 01 Jul 2025 03:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnyuk48nRfBv6kaJBvpNUnW5M69S36YDXK3bDSbCAj7w==
Received: by 2002:a19:3805:0:b0:551:ee0c:ec5 with SMTP id 2adb3069b0e04-55502df3bccls1069555e87.2.-pod-prod-00-eu;
 Tue, 01 Jul 2025 03:50:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTEbhkniCLAc9znDjFPqoyYD53fcsFsj+PLlyPw3E51NowAsuyrWJwvDpClCBcmn3T2kxIU5/AJrY=@googlegroups.com
X-Received: by 2002:a05:6512:1591:b0:552:20e1:5b97 with SMTP id 2adb3069b0e04-5562351b748mr512644e87.18.1751367033819;
        Tue, 01 Jul 2025 03:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751367033; cv=none;
        d=google.com; s=arc-20240605;
        b=Wc78vxr6otXYj9BSetFviaIhIQMT4w/fBvTo7G0rUuoofhezLKJEsQBoWa8VOIfPmM
         WYennzFaU8ZChriIGlW/I1Lat7UxqwsclW0yQaC3NzjOsa9YNgRE7F4cGv1Xevb36I8t
         LFGIpYcHFxKjcc8KdeFjG/FAhUW6uJlRrb+JJ+B7733mnrtRVz0LkXDOkYD9rhHV770Z
         J4C8/OUkkBjqQ124sNs7C1HBM3Td7kG7d+hIjT6YNV/ctOkDj9VAYQYEnkqMwSlvvSQM
         EPJ+yX2JH3aCzNSkSII62zhdNl9W9Bm92G4fcqqWFGiL6eMoE21wy9oo/E0NVhxqWS89
         TNJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=FZO+OsXgSjWooz78m55Rukjz/YKVJGsEqTHDL1vBNiA=;
        fh=JVxOudQhMRhyKfjBLP0gmbt7OoQ6PjJrXxzsZz+uMwY=;
        b=Foaa1EPi3xd1fCDWJ5BE9/QySg5XLshMX1Y4fzA5WlGrKtHKE2qTtglfu4lLbV6ayi
         xZOi6dFEEjl3DWCIHkzQA+azoOqPhUMbusOoSZPLuMWgResV5ugH1g74nrFtgA/lJJf8
         pVFrRlheeAm+bClhbrxSzq/MwgJJCqN6ESbh38BqP2DQ6c2wACTp9boek2bqnf/OmPsX
         cck8D0ZRLw8cFJD3T3HByxywCaswA6GmY2Bt4yOlcw99KAc2n5qvcEJMIWJJdb0aW5EA
         /O0yvtVmA2M6Ws/Pd5d5AYNwSHVxL6KWuwc4u/IdjToet6jRawvIPNEzbw0/6noeCEJy
         mDng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b2b97d2si574562e87.10.2025.07.01.03.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Jul 2025 03:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bWfLS0w8tz9v4p;
	Tue,  1 Jul 2025 12:25:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id fGrApOKWjGf3; Tue,  1 Jul 2025 12:25:36 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bWfLR2br0z9tCl;
	Tue,  1 Jul 2025 12:25:35 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4A0538B766;
	Tue,  1 Jul 2025 12:25:35 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id jqdQfO1FQCoF; Tue,  1 Jul 2025 12:25:35 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C5E958B763;
	Tue,  1 Jul 2025 12:25:32 +0200 (CEST)
Message-ID: <0400f0be-6b63-4bc7-846e-8852e1d01485@csgroup.eu>
Date: Tue, 1 Jul 2025 12:25:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with
 kasan_enabled
To: Heiko Carstens <hca@linux.ibm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 linux@armlinux.org.uk, catalin.marinas@arm.com, will@kernel.org,
 chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, alex@ghiti.fr, gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org, nathan@kernel.org,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, justinstitt@google.com,
 arnd@arndb.de, rppt@kernel.org, geert@linux-m68k.org, mcgrof@kernel.org,
 guoweikang.kernel@gmail.com, tiwei.btw@antgroup.com, kevin.brodsky@arm.com,
 benjamin.berg@intel.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org, llvm@lists.linux.dev
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <CA+fCnZfAtKWx=+to=XQBREhou=Snb0Yms4D8GNGaxE+BQUYm4A@mail.gmail.com>
 <CACzwLxgsVkn98VDPpmm7pKcbvu87UBwPgYJmLfKixu4-x+yjSA@mail.gmail.com>
 <CA+fCnZcGyTECP15VMSPh+duLmxNe=ApHfOnbAY3NqtFHZvceZw@mail.gmail.com>
 <20250701101537.10162Aa0-hca@linux.ibm.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250701101537.10162Aa0-hca@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 01/07/2025 =C3=A0 12:15, Heiko Carstens a =C3=A9crit=C2=A0:
>>>> Another thing that needs careful consideration is whether it's
>>>> possible to combine kasan_arch_is_ready() and kasan_enabled() into the
>>>> same check logically at all. There's one issue mentioned in [1]:
>>>
>>> Hello,
>>> I've removed kasan_arch_is_ready() at all in this series:
>>> [PATCH v2 11/11] kasan: replace kasan_arch_is_ready with kasan_enabled
>>>
>>> Is it not what's expected by unification?
>>
>> I guess the issue description diverged a bit from what needs to be
>> done, sorry about that.
>>
>> The core 2 things I wanted to address with the unification are:
>>
>> 1. Avoid spraying kasan_arch_is_ready() throughout the KASAN
>> implementation and move these checks into include/linux/kasan.h (and
>> add __wrappers when required).
>>
>> 2. Avoid architectures redefining the same kasan_enabled global
>> variable/static key.
>>
>> Initially, I thought that s/kasan_arch_is_ready/kasan_enabled + simply
>> moving the calls into affected include/linux/kasan.h functions would
>> be enough. But then, based on [1], turns out it's not that simple.
>>
>> So now, I think we likely still need two separate checks/flags:
>> kasan_enabled() that controls whether KASAN is enabled at all and
>> kasan_arch_is_ready() that gets turned on by kasan_init() when shadow
>> is initialized (should we rename it to kasan_shadow_initialized()?).
>> But then we can still move kasan_arch_is_ready() into
>> include/linux/kasan.h and use the proper combination of checks for
>> each affected function before calling __wrappers. And we can still
>> remove the duplicated flags/keys code from the arch code.
>=20
> FWIW, as Alexander Gordeev already mentioned: this series breaks s390,
> since the static_branch_enable() call in kasan_init_generic() is now
> called way too early, and it isn't necessary at all. Which, as far as
> I understand, may be the case for other architectures as well. s390
> sets up the required KASAN mappings in the decompressor and can start
> with KASAN enabled nearly from the beginning.
>=20
> So something like below on top of this series would address
> that. Given that this series is about to be reworked this is just for
> illustration :)

I had the same kind of comment on powerpc/32. Allthough this series work=20
on powerpc32 as is, it is overkill because it adds code and data for=20
static branches for no real benefit.

Your patch below is simpler than what I proposed, but it keeps the=20
static branches so the overhead remains.

I also proposed a change, it goes further by removing the static branch=20
for architectures that don't need it, see=20
https://patchwork.ozlabs.org/project/linuxppc-dev/cover/20250626153147.1453=
12-1-snovitoll@gmail.com/#3537388=20
. Feedback welcome.

Christophe

>=20
> diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
> index 0c16dc443e2f..c2f51ac39a91 100644
> --- a/arch/s390/Kconfig
> +++ b/arch/s390/Kconfig
> @@ -172,6 +172,7 @@ config S390
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>   	select HAVE_ARCH_KASAN
> +	select HAVE_ARCH_KASAN_EARLY
>   	select HAVE_ARCH_KASAN_VMALLOC
>   	select HAVE_ARCH_KCSAN
>   	select HAVE_ARCH_KMSAN
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index 2436eb45cfee..049270a2269f 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -10,7 +10,11 @@
>    * Global runtime flag. Starts =E2=80=98false=E2=80=99; switched to =E2=
=80=98true=E2=80=99 by
>    * the appropriate kasan_init_*() once KASAN is fully initialized.
>    */
> +#ifdef CONFIG_HAVE_ARCH_KASAN_EARLY
> +DECLARE_STATIC_KEY_TRUE(kasan_flag_enabled);
> +#else
>   DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +#endif
>  =20
>   static __always_inline bool kasan_enabled(void)
>   {
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f82889a830fa..1407374e83b9 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -4,6 +4,13 @@
>   config HAVE_ARCH_KASAN
>   	bool
>  =20
> +config HAVE_ARCH_KASAN_EARLY
> +	bool
> +	help
> +	  Architectures should select this if KASAN mappings are setup in
> +	  the decompressor and when the kernel can run very early with
> +	  KASAN enabled.
> +
>   config HAVE_ARCH_KASAN_SW_TAGS
>   	bool
>  =20
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 0f3648335a6b..2aae0ce659b4 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,11 @@
>    * Definition of the unified static key declared in kasan-enabled.h.
>    * This provides consistent runtime enable/disable across all KASAN mod=
es.
>    */
> +#ifdef CONFIG_HAVE_ARCH_KASAN_EARLY
> +DEFINE_STATIC_KEY_TRUE(kasan_flag_enabled);
> +#else
>   DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +#endif
>   EXPORT_SYMBOL(kasan_flag_enabled);
>  =20
>   struct slab *kasan_addr_to_slab(const void *addr)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index a3b112868be7..455376d5f1c3 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -42,7 +42,8 @@
>    */
>   void __init kasan_init_generic(void)
>   {
> -	static_branch_enable(&kasan_flag_enabled);
> +	if (!IS_ENABLED(CONFIG_HAVE_ARCH_KASAN_EARLY))
> +		static_branch_enable(&kasan_flag_enabled);
>  =20
>   	pr_info("KernelAddressSanitizer initialized (generic)\n");
>   }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
400f0be-6b63-4bc7-846e-8852e1d01485%40csgroup.eu.
