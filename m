Return-Path: <kasan-dev+bncBDLKPY4HVQKBBAG43DCAMGQETVKXQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC59B1ED98
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 19:04:01 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3324dda6611sf12958131fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 10:04:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754672641; cv=pass;
        d=google.com; s=arc-20240605;
        b=gbfXYdWXFJnZK/xBjrng4b4ctEqzNmXQ7QftLcKv3aBzv6iHVUYO48IUSygSVPs060
         gJVjO0kqIPWryts9eRYOszP58AhNA0Lnf+1IoaJsI8gcHLErfF8V2xZ+dRhARLO1/cRs
         tHF4np+ILyjgrEpoeCK1xpzhWMN92zw78W1RuZrPcj3lQd2GmHrbbiu2pvU6poE4QgCU
         90mgsjH3eAS811/zglqMG8ReA8DSdvgDYHctUKZI+D0duPJNAJWLZEdM3tBRZEt1qawz
         qKCJjK4DRnrQjAtgyn997M1yD2HsiKf17EizvQd/AVKn2JwvihuB+nVx96P7IqP7/n1h
         sKKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=elsd0tDDOlHpbutJNyiQihgSTbk+q0NrM7XpZl6DbW0=;
        fh=auIH/AFX9UVf2Dr2qlnUKNA8CNjARhYvzthhWMspwrQ=;
        b=ccMXw7wWUwklmfsjRuwN/gh7Lja1Yt6qPY+fB+Z7OzhKTuFvjU0nK/PvThzUqO5Geu
         7I9w0HfKpnm8Z7z7pwy6upt5+P7c2RJR+pQbv4gYVZWeDUz4jGJSqRiZCwf2RNWe2EUT
         4kGK7dpt+M3ocDErDgYZhigTMTW6NStYUWVgr8BectqX4+ejP2ivYosMZgJu7LzOqzFD
         ttrQRQLJOBlJliqmuL/nrI3BnBbEk7TY5fWU1ISishAfLERYa66ku2XbYPHeJkMa3JI3
         22lMzEAJd2QYbkZqsLxLBr42ohwQQNYKftv2iE8T3e/YiNdzCLVkvgW/pnemSL1MIEGq
         Cjtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754672641; x=1755277441; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=elsd0tDDOlHpbutJNyiQihgSTbk+q0NrM7XpZl6DbW0=;
        b=TgsJW2XoqnIKwY7AJQ9EmNG/jPA1ss/2q2F8CI3HQXBXtab6eAqRxMVgYbr1U5RNCL
         afShgexUYMtZIFkBuDgYU8w+JoodYIPosl7Hyn8unwAkIVERperYdxx1GtSgm4vyWw+T
         b+glsk77vPJ9F7UfO7CMkoZFXrs89vr9Yc+gURpOU93cr2Cbfx/R2SJUQ5l6eo44KrsT
         MbUA0c2sSIIRdkNofK/Y0xVMWN+krPdEWaPhsQZstm16azVRpxgdzvB7Ablws5srsDX5
         kI0SXq/5anIf7S5hdd8At34lpn7x0xPdHEa3R+Js82Wrnk740YG+fXZA3D+bCpMpexWR
         vMBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754672641; x=1755277441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=elsd0tDDOlHpbutJNyiQihgSTbk+q0NrM7XpZl6DbW0=;
        b=BZ9oqlvNLRocicfqzYSQDPzH6AMOvyYpyfLFTno1YshurY6AxE8744lJmkMBdO/mCz
         TnCqSRRABTxrXikQTsyN1JGG+DVA0LK+LCCORwjIMpFubwnm1C9w0ofrZIzE+jAJxmzi
         lpZ+ASw3gPJ7rAu7kuEYEf5p2Hu0HXldTcWCoXt6be+RPADDHxZK+GsNanTpTE/g8dhi
         QKPa7v8A1yaHLoQFa47/ojfI2Pg4KeEaxI3QAUE5DCEF/78pMZ3vmwxkU101EHbcqIVn
         vvovxSnUKy1rjBapphlv5LfgmfY/OOir/Mm7ugZX/VNgMC9bEGiPw7ZvFUYSgSXC8NRe
         upig==
X-Forwarded-Encrypted: i=2; AJvYcCVP4I/ep8lBB6GmvFcgyWcWfnQF2F4WDUsB6rA61ZVV58TXxvikaLumROqUIIAE1jYtKZt3lA==@lfdr.de
X-Gm-Message-State: AOJu0YwkJWVe7qml8syXnOUQtUixWSY05tE/nESFkotNEi2KUNFmlLU9
	FY8X3vEn4OSwrgBcLreIGFXBFZ/95nQfk6JZX8PW0wdwb/CaQ7ml7AF3
X-Google-Smtp-Source: AGHT+IHIXxmIlFnHjyjiy466WcS2mahaw4ujwYoRMA4bgBvn626w4CGulcYG4ekQD/L5kWsPB/2ZFQ==
X-Received: by 2002:a2e:a98a:0:b0:32a:6cab:fd75 with SMTP id 38308e7fff4ca-333a263c947mr9065181fa.11.1754672640828;
        Fri, 08 Aug 2025 10:04:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcGYxyMHArmn8gXKX9x7o66t1YgIG+2hgB+yLElI81v2w==
Received: by 2002:a05:651c:418d:b0:32a:7f90:fd84 with SMTP id
 38308e7fff4ca-3338c5db6f1ls877221fa.2.-pod-prod-00-eu; Fri, 08 Aug 2025
 10:03:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUt+Z21dxGy52mGFqepldyZlUImld/HG9zYXosUwH2gIze4/euoLJ9ulvydJjsG1XIESJzq/ea/gbQ=@googlegroups.com
X-Received: by 2002:a05:651c:408b:b0:32b:7811:d451 with SMTP id 38308e7fff4ca-3338d1b8e35mr13825401fa.16.1754672637763;
        Fri, 08 Aug 2025 10:03:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754672637; cv=none;
        d=google.com; s=arc-20240605;
        b=VEwSQcAij2clOchW9K5Htz8T3hdMAFDmjwUBvBRlhSm9Tk2kC7V/a5o+UqOC4yquo1
         +CuxqN5bZ4fyty7xOIirVYMM6GahUeY2GVRlYbRSI6H6u/aQvcvwu0NGsZ6c0xL2odoo
         ABZrZMOluGeSfCrR3Z1XGGU/5aOVlTS6qEJoMrqyeisqM07ZM2VNRxqYIbJexJgESOqE
         N7V88L1wiFRI0EWf4J1/6x11SoFUX49K4UGSHDNh9KMDfxftZZdYqQeKpXRkbmp0Ke/S
         CqsUNFAGt6ofot29+7rdnZuv5iMbuQSi4fKPZSziBsZTkcXrREjflQLzYhDW2TwUSkd4
         /B2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=bro5Z1PL2eLig5Q2ncFtimJM/b9sdMd4TeRUxnnShL0=;
        fh=Fy7HURfPayN4njpWusNf2JiZBSb47ze1MFHJWEsNmW8=;
        b=RMl6VB1NBdhGw6kgPieyPRk7d9cA1Hy76PnVXMUEAf9Yty6eMI7K/pN/OTb/6oat4R
         tr3mCbAaJmBR+U+7Hy8X/LdLlKw9tIxWiPQYMB48vgjgizvmSKouYhMfqPE9upy14sKb
         /H9TJhwnSWVXw+ZCkERHZ2tILfFjQxRYaksU4hAOv886PibV8nAo8flvg2yi2K43DRzU
         s1CWY8l2FABWBsmmxM6PjYX9joffMO5/dccWQ9X2frwuwQt1t+Vdkxvk1kygGqK1RNsw
         0YYk6reiD9OAnX2KqDYwb88Pvcl2NP27bZiYm33qGJFx/aN0ziySg8cD0hgYnLSp/jNf
         T8EQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3323815f77bsi4591141fa.6.2025.08.08.10.03.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 10:03:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4bz9NX4Hmyz9sSb;
	Fri,  8 Aug 2025 19:03:56 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 4LtEzBBocysS; Fri,  8 Aug 2025 19:03:56 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4bz9NX36z3z9sSZ;
	Fri,  8 Aug 2025 19:03:56 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 55AF68B770;
	Fri,  8 Aug 2025 19:03:56 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Z2c0fwWGRIPg; Fri,  8 Aug 2025 19:03:56 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 20F878B763;
	Fri,  8 Aug 2025 19:03:55 +0200 (CEST)
Message-ID: <af677847-e625-43d7-8750-b2ce4ba9626c@csgroup.eu>
Date: Fri, 8 Aug 2025 19:03:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, bhe@redhat.com, hca@linux.ibm.com,
 andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, davidgow@google.co, glider@google.com,
 dvyukov@google.com, alex@ghiti.fr, agordeev@linux.ibm.com,
 vincenzo.frascino@arm.com, elver@google.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250807194012.631367-1-snovitoll@gmail.com>
 <20250807194012.631367-2-snovitoll@gmail.com>
 <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu>
 <CACzwLxjnofD0EsxrtgbG3svXHL+TpYcio4B67SCY9Mi3C-jdsQ@mail.gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <CACzwLxjnofD0EsxrtgbG3svXHL+TpYcio4B67SCY9Mi3C-jdsQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
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



Le 08/08/2025 =C3=A0 17:33, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> On Fri, Aug 8, 2025 at 10:03=E2=80=AFAM Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>>
>>
>> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
>>> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that ne=
ed
>>> to defer KASAN initialization until shadow memory is properly set up,
>>> and unify the static key infrastructure across all KASAN modes.
>>
>> That probably desserves more details, maybe copy in informations from
>> the top of cover letter.
>>
>> I think there should also be some exeplanations about
>> kasan_arch_is_ready() becoming kasan_enabled(), and also why
>> kasan_arch_is_ready() completely disappear from mm/kasan/common.c
>> without being replaced by kasan_enabled().
>>
>>>
>>> [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
>>>
>>> Closes: https://eur01.safelinks.protection.outlook.com/?url=3Dhttps%3A%=
2F%2Fbugzilla.kernel.org%2Fshow_bug.cgi%3Fid%3D217049&data=3D05%7C02%7Cchri=
stophe.leroy%40csgroup.eu%7Cfe4f5a759ad6452b047408ddd691024a%7C8b87af7d8647=
4dc78df45f69a2011bb5%7C0%7C0%7C638902640503259176%7CUnknown%7CTWFpbGZsb3d8e=
yJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIs=
IldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DUM4uvQihJdeWwcC6DIiJXbn4wGsrijjRcHc55=
uCMErI%3D&reserved=3D0
>>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
>>> ---
>>> Changes in v5:
>>> - Unified patches where arch (powerpc, UML, loongarch) selects
>>>     ARCH_DEFER_KASAN in the first patch not to break
>>>     bisectability
>>> - Removed kasan_arch_is_ready completely as there is no user
>>> - Removed __wrappers in v4, left only those where it's necessary
>>>     due to different implementations
>>>
>>> Changes in v4:
>>> - Fixed HW_TAGS static key functionality (was broken in v3)
>>> - Merged configuration and implementation for atomicity
>>> ---
>>>    arch/loongarch/Kconfig                 |  1 +
>>>    arch/loongarch/include/asm/kasan.h     |  7 ------
>>>    arch/loongarch/mm/kasan_init.c         |  8 +++----
>>>    arch/powerpc/Kconfig                   |  1 +
>>>    arch/powerpc/include/asm/kasan.h       | 12 ----------
>>>    arch/powerpc/mm/kasan/init_32.c        |  2 +-
>>>    arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
>>>    arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
>>>    arch/um/Kconfig                        |  1 +
>>>    arch/um/include/asm/kasan.h            |  5 ++--
>>>    arch/um/kernel/mem.c                   | 10 ++++++--
>>>    include/linux/kasan-enabled.h          | 32 ++++++++++++++++++------=
--
>>>    include/linux/kasan.h                  |  6 +++++
>>>    lib/Kconfig.kasan                      |  8 +++++++
>>>    mm/kasan/common.c                      | 17 ++++++++++----
>>>    mm/kasan/generic.c                     | 19 +++++++++++----
>>>    mm/kasan/hw_tags.c                     |  9 +-------
>>>    mm/kasan/kasan.h                       |  8 ++++++-
>>>    mm/kasan/shadow.c                      | 12 +++++-----
>>>    mm/kasan/sw_tags.c                     |  1 +
>>>    mm/kasan/tags.c                        |  2 +-
>>>    21 files changed, 100 insertions(+), 69 deletions(-)
>>>
>>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
>>> index f0abc38c40a..cd64b2bc12d 100644
>>> --- a/arch/loongarch/Kconfig
>>> +++ b/arch/loongarch/Kconfig
>>> @@ -9,6 +9,7 @@ config LOONGARCH
>>>        select ACPI_PPTT if ACPI
>>>        select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
>>>        select ARCH_BINFMT_ELF_STATE
>>> +     select ARCH_DEFER_KASAN if KASAN
>>
>> Instead of adding 'if KASAN' in all users, you could do in two steps:
>>
>> Add a symbol ARCH_NEEDS_DEFER_KASAN.
>>
>> +config ARCH_NEEDS_DEFER_KASAN
>> +       bool
>>
>> And then:
>>
>> +config ARCH_DEFER_KASAN
>> +       def_bool
>> +       depends on KASAN
>> +       depends on ARCH_DEFER_KASAN
>> +       help
>> +         Architectures should select this if they need to defer KASAN
>> +         initialization until shadow memory is properly set up. This
>> +         enables runtime control via static keys. Otherwise, KASAN uses
>> +         compile-time constants for better performance.
>>
>=20
> Actually, I don't see the benefits from this option. Sorry, have just
> revisited this again.
> With the new symbol, arch (PowerPC, UML, LoongArch) still needs select
> 2 options:
>=20
> select ARCH_NEEDS_DEFER_KASAN
> select ARCH_DEFER_KASAN

Sorry, my mistake, ARCH_DEFER_KASAN has to be 'def_bool y'. Missing the=20
'y'. That way it is automatically set to 'y' as long as KASAN and=20
ARCH_NEEDS_DEFER_KASAN are selected. Should be:

config ARCH_DEFER_KASAN
	def_bool y
	depends on KASAN
	depends on ARCH_NEEDS_DEFER_KASAN


>=20
> and the oneline with `if` condition is cleaner.
> select ARCH_DEFER_KASAN if KASAN
>=20

I don't think so because it requires all architectures to add 'if KASAN'=20
which is not convenient.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
f677847-e625-43d7-8750-b2ce4ba9626c%40csgroup.eu.
