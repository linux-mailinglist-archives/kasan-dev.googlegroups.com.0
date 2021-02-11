Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB34PSWAQMGQEC4T3MSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A23318DD0
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:06:25 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id y18sf2971019otk.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:06:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613055984; cv=pass;
        d=google.com; s=arc-20160816;
        b=iXutGexlcNm/wIdfSXEyLI71EdcpROfJOiOl2Q40cSG6Jkat9EfEJk5nSNiHBPuU05
         OZL0aGGVW2fpAvL8G2vpPa8Oy9S6zk/qaf4FsdUWHl8qVpx2FS6C2x/kx98jn2phHre/
         f5L5G6FqSoDZ4/FFeq47gblFl3KyP4N0C9RoRAFe8SLCdKAMa19eq8rSOX5CEQINGk79
         O3bPWiU/zRb9g8o+nT7WSZCyDrCaqsLaXA/DLNdaQRi9xEaRQbm/Qhj3c154lAohJQrw
         HeGJI78DzmcboKgNqt5mZluwEbzyPWeMuTqY75LnUnsCzgspzSZDeSyFh9GM/IbdXFrt
         YJCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=/JdpefWpi0FNMg20xR90xrMg22i3fmt1feCir9lt03U=;
        b=rgDOVaTShLgaTv1CccGjhCU9w/c0aK2tuDcElmV9Nk6lBBC0SGfV5+iTOPTGlFJUBF
         f1/W6U0L3ld8v6zRpmL4TNR/oIPG5GyxQa+LBe+XjxYwxdktluPQ6Ws4bZdHlnvRFBpf
         aaAeW7EiCqWmarol9MmrqWEvdIV4+5+g9v7K0f0U3WSVMw7dTI2dtRFhb05zIit9MX2p
         Xx+VFKnb40O0orJXgAMto773nLS7FjCmRTfNO6+bAVKKc1RMDGV8+YMK0BNJwMamiz3d
         wF881HeT+ZN2+qmbh6dMrQ5FFBaTeZ7ih1rgRmPiA7Ds02ZqiMOdUpmS5yfjK/9V6ZZp
         MiJQ==
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
        bh=/JdpefWpi0FNMg20xR90xrMg22i3fmt1feCir9lt03U=;
        b=ChaGaliGDYaL1m0lIke1FYwBzpSPT/CXen1OpbxHd3+O/7dIOq7hLe9VJGkkDXN59m
         Gbcy7BwzRbsfja2CfHv/CL31j4eOf/fK5XoF6Xmu394xZ4lQcioblpTyJu2F/42Ldumr
         nuORLfdTdss3qPx077UvGYsdps+iTh1eE/A9Pbejawb7c0FMoXxbobkgjENkx6F8g7jc
         jGUjPFt/vQSCbl3CK+k36YO0wZM+7IVMYXoP8xmMXAV4x55odwHAs6jDQ+dzQnJy6YAb
         ECymX75ZcwPs4H9u0tAMYypI/15K/DJi/OpsFBEMY6pwxMn1H4A+mrD2u3f4wCSirwZD
         14Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/JdpefWpi0FNMg20xR90xrMg22i3fmt1feCir9lt03U=;
        b=b0hDs7gfibTMYRzDGum0icfSlqVQkLzLZAWaOK2oKzVMim4dQb3MkOytxFRAbV4J2E
         qNO5MnMmJhZN+NBsiSjhRW+5scrm4gXabYAqHO2srjwI60H8aSZGyiPkqbwE/6lzMRGt
         7YT4QTh39y/SlYrXTv3HdAYuEH/f78xhEX6iUbsCeyQWeo6k67QjzkWUk9glFNHFAtqG
         sqwocA1QOiI1qAvi7eWTuUPDECuREa4nf3bEZFe/PReL9DZ65nk5SPLtRw88I6HqHVzE
         T09DDkwwOEPWmjadK0ch8Ud6Bo2WEahmtdnT1ZoTG4uJrNW2Z6QMbVCw2ygLdj25RapV
         qOLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MrAW9nLR7ll9mXlh4gK7hNaRGVtV1gQNPBaQZtXSGomO4nd2N
	ZzzzitZHKNdQEoSOjJzaGK8=
X-Google-Smtp-Source: ABdhPJzxIVhG1jtilrDmZNqY93Rl7Y/XkFqfoBDEva8nlXvUw6xQV8xE8luPVsl2ief77fvtmIo3DA==
X-Received: by 2002:a9d:7d12:: with SMTP id v18mr5929888otn.205.1613055984065;
        Thu, 11 Feb 2021 07:06:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7cd2:: with SMTP id r18ls720653otn.10.gmail; Thu, 11 Feb
 2021 07:06:23 -0800 (PST)
X-Received: by 2002:a9d:1d64:: with SMTP id m91mr5887727otm.290.1613055983700;
        Thu, 11 Feb 2021 07:06:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613055983; cv=none;
        d=google.com; s=arc-20160816;
        b=uRwpsObmGvw0ofUlppw+qR6YzMnWs6/XQ6UQ71TkIJbXVLe+WIv8HtBqEvQFjVbfxq
         AAossMEreD/ljj1r/CDn6nXO7GNkulq2m9EBDOYmvhuqEXeouIcFH6kpu0qtEvh1npDG
         suJUwdfiPsM2O6P5XpZjzZgBATFLdTLeubkUMkLmuJNVND/5iHaNFe59RuRFjQcwyoiT
         7yxwsI5AKEZTI3QGYySMUM4oDOq/67u8OxHr3ezHA+GHVmSHw3CFUmHAc1+jYJJIYQkQ
         E96wsMs8WHtuhB0ctqw7wWz7owZnAZORQ18iQcaKpg3EBK5krsqw6z6WhsqGtMqMRGnc
         9mKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=4jnYlWTtQFlB34Ez/gXD1N1TiaPk4fdjzoA+ugvfYPw=;
        b=RGKTeKAIRQNZvrCE8UKtDlEjkwLBeWQsl/9miyQ+X5cvbAuKfV185Uwrr6jHn/u9op
         pBdqIB8IHp6eeVTV/CQL6a6VOQqXiI5/S6IJFt5qQ8sLrutSiAHbrR2M8e+dZ2Gdb/3q
         OUS7+kNX7xBFffax4ijO57n4K+4wtMHkLUTWAMhMFuAaE+og+sPikJtJJC3AuDO3Yhp0
         9Gg/9tiJ5wvBEjcwaXSLaXR3AoS3tkkT8NoT43xxMv2pHai+Wmsn4pWufLdjzWzQTISY
         qdiTjd2PvyVkXY8/9PhHbmJMH6Ec7x3TStMt4EBrQxF2kTpwIjAaQO8jUFlXsxo71/6K
         F/FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e206si477860oib.3.2021.02.11.07.06.23
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:06:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0EC95113E;
	Thu, 11 Feb 2021 07:06:23 -0800 (PST)
Received: from [10.37.8.13] (unknown [10.37.8.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D20EA3F73D;
	Thu, 11 Feb 2021 07:06:21 -0800 (PST)
Subject: Re: [PATCH] arm64: Fix warning in mte_get_random_tag()
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210211125602.44248-1-vincenzo.frascino@arm.com>
 <CAMj1kXHED=O4uXzRAKiD8kE1Vb3Dr=oU-shLQ8UBBDn2N-1nuA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <49a080e6-4482-0d8a-2360-eba698b92457@arm.com>
Date: Thu, 11 Feb 2021 15:10:27 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAMj1kXHED=O4uXzRAKiD8kE1Vb3Dr=oU-shLQ8UBBDn2N-1nuA@mail.gmail.com>
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



On 2/11/21 1:35 PM, Ard Biesheuvel wrote:
> On Thu, 11 Feb 2021 at 13:57, Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> The simplification of mte_get_random_tag() caused the introduction of th=
e
>> warning below:
>>
>> In file included from arch/arm64/include/asm/kasan.h:9,
>>                  from include/linux/kasan.h:16,
>>                  from mm/kasan/common.c:14:
>> mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
>> arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99=
 is used
>>                                          uninitialized [-Wuninitialized]
>>    45 |         asm(__MTE_PREAMBLE "irg %0, %0"
>>       |
>>
>> Fix the warning initializing the address to NULL.
>>
>> Note: mte_get_random_tag() returns a tag and it never dereferences the a=
ddress,
>> hence 'addr' can be safely initialized to NULL.
>>
>> Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>
>> This patch is based on linux-next/akpm
>>
>>  arch/arm64/include/asm/mte-kasan.h | 7 ++++++-
>>  1 file changed, 6 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm=
/mte-kasan.h
>> index 3d58489228c0..b2850b750726 100644
>> --- a/arch/arm64/include/asm/mte-kasan.h
>> +++ b/arch/arm64/include/asm/mte-kasan.h
>> @@ -40,7 +40,12 @@ static inline u8 mte_get_mem_tag(void *addr)
>>  /* Generate a random tag. */
>>  static inline u8 mte_get_random_tag(void)
>>  {
>> -       void *addr;
>> +       /*
>> +        * mte_get_random_tag() returns a tag and it
>> +        * never dereferences the address, hence addr
>> +        * can be safely initialized to NULL.
>> +        */
>> +       void *addr =3D NULL;
>>
>>         asm(__MTE_PREAMBLE "irg %0, %0"
>>                 : "+r" (addr));
>> --
>> 2.30.0
>>
>=20
> Might it be better to simply change the asm constraint to "=3Dr" ?
>=20

Indeed, did not notice the "+r". I will change it accordingly and post v2.

Thanks!

--=20
Regards,
Vincenzo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/49a080e6-4482-0d8a-2360-eba698b92457%40arm.com.
