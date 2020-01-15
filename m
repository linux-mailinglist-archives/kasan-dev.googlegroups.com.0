Return-Path: <kasan-dev+bncBCXLBLOA7IGBB4GL7TYAKGQE6DEMTKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CDA113C66F
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 15:47:12 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id y4sf3275741lfg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 06:47:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579099632; cv=pass;
        d=google.com; s=arc-20160816;
        b=ls9gHnNym0DTp0i9ysNvb29+6SmYZbMSOZd3uS2Tdpn8AVEp6lqtFjUl7tswCaBk5a
         hgCWP4e3QT4Cm5obZwsllWMo1Y3F8QiJj81gBV1XEjPDo94H97+eXPuSrBxml3MnbP1Z
         9bvxPkj309nw4d5e0x4YOxF5Ol9NAjnuc1g2QQ6cKjKmwz8PK+nFxUcPUxzS/nqKn+sU
         hxVk+KTOMp1rbDdCLD94jNfq1392pXncEpFN+H8LdsCVQaDO86L1bv/WM9QZtKvIcdTc
         ekcOJvyvgddBtXGMWuoi07XibYaaADQCNNZOTx1GUi5SL8wzQ+wblGGM7WG6MSv3D1hw
         aE3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=b6K5grqeBteKCcZP3ZYhX4jBHI0xsmQUDbtfLsBE25o=;
        b=RDYe6iwsFmqWsBlFPq3Gnn2cnN7YtJjL2oXvcfkADeRsMP4IpXHD8vbts3T6S5AN5r
         +xRX622Y1iJqlQJRbNiUxCzUmQvaEpGCLpVfKaNElJ14r1MC4LIfPnjZ8iSRESgVWPnT
         Ki55WPenF4aeVk9jqwJHv57xlRZW/Y+zdfsTB7ByYx77lCLJ4PGJ944+JNUVV8CtnA6o
         jsM7Y3jB/9IjIdYTmpPkMFFTs+bugOTuw3pxrbyeqjXNea5WN1bJzHV9OpsXbkIkiqQj
         uzjb/yl43tnKo/VVLOenSqcI8RN9dNss9284F6wIj1GDFAD4F1vQqQXSft0ZzG8BSq2q
         zrBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=v0ZdT0Jh;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b6K5grqeBteKCcZP3ZYhX4jBHI0xsmQUDbtfLsBE25o=;
        b=US7pEf8WlMCyzMy+FgF1NyhF4ouX7ukmwytN2+6RBPzKRACM0PMDkoShT815+0tWez
         //R0oLVY32FnJ0MclszT8jo1nPB3FSWH92KJChr5wLv9RDzCWaXgYUAUCiZVORUCr5Yg
         dCRjgGQYj8f7gIA3ehdbiSyJL7cCd01mZawgbDyoBZWseTJy25GOnUssXfMMAQh0QIcx
         YIoB64P5T8K8khSXkL+Dg7Ayl6K/filv/auvWkPukgEK51cxUE9+yP0/7bpcy0mxDrMX
         CePMz98OtwPdsG2nwC6tjWDrj9nLPwoKt3Q7d6OtDfDmPsvBwZ+9gAt0AVv7q/lAZFVM
         plhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b6K5grqeBteKCcZP3ZYhX4jBHI0xsmQUDbtfLsBE25o=;
        b=cW1GIJagpzcjGsWxgFjqJsC1TmqKoQAyuGhor5W9MYzcM1Y4pL28JUX+7sryQze+aC
         Bn+DQsC9O5kR+cysVDxzokVgaKXou7aEuKeKIZ5BRnz+tdBNiLClyrYl0rnseWecGH0c
         lTj6jZhVccjs8e/yXlsUbsX8ifshZZr0dRhH+0pyWTi7h9PiP6zY71xuzhOOP8GIGZC9
         IAfxMGCVbYiJfpbwY5G94R6AqcUgH2PJX3ffbVuhwV2dvmkUj0qBErD4z6XSfEWYzz7w
         D8Zz0rTXnxd1KZgfFuB4X9zNy5GBuqftcGnX4LMUWvdnS1LPA3N24lR0QHf8QsGe+Ajj
         xDUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWNaqIYcu0w0lMpg+22Wo6EGMcGdDVrJHC5fZ2T2nBnfx3whQJW
	I4salA6Nmv6l3O5wl0c6ChA=
X-Google-Smtp-Source: APXvYqxNsiq4hR/WPNR5PKRfd2Lr++TsRa0ZVSG6Dv7TvJkKRq0C+35uC05H7oxKa+v/EnIEnmibyw==
X-Received: by 2002:a19:c210:: with SMTP id l16mr4925269lfc.35.1579099632167;
        Wed, 15 Jan 2020 06:47:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2247:: with SMTP id i68ls1834708lfi.5.gmail; Wed, 15 Jan
 2020 06:47:11 -0800 (PST)
X-Received: by 2002:a19:7b0a:: with SMTP id w10mr4971436lfc.90.1579099631602;
        Wed, 15 Jan 2020 06:47:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579099631; cv=none;
        d=google.com; s=arc-20160816;
        b=vik1eGvVkODpRfNS20ytbHbWEUEpHin96hjFFYtsXsUrkOqbF5jPk8ZEa+9PEz4Fk5
         KCiIitZkiiKElzWmLEeU7dWed0cIwMn4HIhUp1JBs88bWR1ZYKCciwrxQ58wroTU2ABi
         gBMHnomp9vg9ironGZnpJTvfqJiyLjrbJsNtaxzwiL9S5VpHAJyrlkISWDXMsMTc60Ux
         BdB00lrHVwRF1WtOnR9eF7gFGp4Ei0ughZXbRvn+FYg0mw4o8X/CLoR+H7r/qiSTOJiI
         aCSvL7W9SfegTgphDkR6EeH8zWun6VPsVzItEu7KJDc7htpx6G8fcEYYFQGpuPuxShz2
         bkww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=GvjzXQnIL+hCqDUkI7JAeG4AEubHEzQxfXAYFm1+LnE=;
        b=ncglssBi2s7h6semYXiYGZwTQwdA/uS7qjOlqEDqZIJii13+9md8xBBE9QwdqJCAx1
         WiY0Gu4V50vroDnPuHrH3saCgGHPZCfgmwt2epAo5CWms9SIfk6PxHWMsls9UUKCvLcZ
         Au34zLYdfmA8heN0PzdzortxpU8S7RozdP9Kt3mHb9Cre25e+NnPYMJKafaAttzJXUsA
         TiweSOqBcMozUWoJePJLm/fyKSYh4kTInZNBatDWy0IMks0u8LzVK/IxIiOhUaXvEhRf
         XD8FYibrkEh+T8CLft+YgkxKypnBY18cGmvFtmDa85pmVfJiLF72P3Fq4vDhKyDxUCOL
         F+yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=v0ZdT0Jh;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id u5si731395lfm.0.2020.01.15.06.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 06:47:11 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 47yVXY1sjBz9tylP;
	Wed, 15 Jan 2020 15:47:09 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 1yEnk5s5C33f; Wed, 15 Jan 2020 15:47:09 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47yVXY0mmhz9tylH;
	Wed, 15 Jan 2020 15:47:09 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6E61F8B774;
	Wed, 15 Jan 2020 15:47:10 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id BnOhqHOrMIva; Wed, 15 Jan 2020 15:47:10 +0100 (CET)
Received: from [172.25.230.100] (po15451.idsi0.si.c-s.fr [172.25.230.100])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 15D4B8B805;
	Wed, 15 Jan 2020 15:47:10 +0100 (CET)
Subject: Re: [PATCH 1/2] kasan: stop tests being eliminated as dead code with
 FORTIFY_SOURCE
To: Dmitry Vyukov <dvyukov@google.com>, Daniel Axtens <dja@axtens.net>
Cc: linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org,
 the arch/x86 maintainers <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux-MM <linux-mm@kvack.org>, Daniel Micay <danielmicay@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>
References: <20200115063710.15796-1-dja@axtens.net>
 <20200115063710.15796-2-dja@axtens.net>
 <CACT4Y+bAuaeHOcTHqp-=ckOb58fRajpGYk4khNzpS7_OyBDQYQ@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <917cc571-a25c-3d3e-547c-c537149834d6@c-s.fr>
Date: Wed, 15 Jan 2020 15:47:09 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+bAuaeHOcTHqp-=ckOb58fRajpGYk4khNzpS7_OyBDQYQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=v0ZdT0Jh;       spf=pass (google.com:
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



Le 15/01/2020 =C3=A0 15:43, Dmitry Vyukov a =C3=A9crit=C2=A0:
> On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
>>
>> 3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
>> memchr, memcmp and strlen.
>>
>> When FORTIFY_SOURCE is on, a number of functions are replaced with
>> fortified versions, which attempt to check the sizes of the operands.
>> However, these functions often directly invoke __builtin_foo() once they
>> have performed the fortify check. The compiler can detect that the resul=
ts
>> of these functions are not used, and knows that they have no other side
>> effects, and so can eliminate them as dead code.
>>
>> Why are only memchr, memcmp and strlen affected?
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> Of string and string-like functions, kasan_test tests:
>>
>>   * strchr  ->  not affected, no fortified version
>>   * strrchr ->  likewise
>>   * strcmp  ->  likewise
>>   * strncmp ->  likewise
>>
>>   * strnlen ->  not affected, the fortify source implementation calls th=
e
>>                 underlying strnlen implementation which is instrumented,=
 not
>>                 a builtin
>>
>>   * strlen  ->  affected, the fortify souce implementation calls a __bui=
ltin
>>                 version which the compiler can determine is dead.
>>
>>   * memchr  ->  likewise
>>   * memcmp  ->  likewise
>>
>>   * memset ->   not affected, the compiler knows that memset writes to i=
ts
>>                 first argument and therefore is not dead.
>>
>> Why does this not affect the functions normally?
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> In string.h, these functions are not marked as __pure, so the compiler
>> cannot know that they do not have side effects. If relevant functions ar=
e
>> marked as __pure in string.h, we see the following warnings and the
>> functions are elided:
>>
>> lib/test_kasan.c: In function =E2=80=98kasan_memchr=E2=80=99:
>> lib/test_kasan.c:606:2: warning: statement with no effect [-Wunused-valu=
e]
>>    memchr(ptr, '1', size + 1);
>>    ^~~~~~~~~~~~~~~~~~~~~~~~~~
>> lib/test_kasan.c: In function =E2=80=98kasan_memcmp=E2=80=99:
>> lib/test_kasan.c:622:2: warning: statement with no effect [-Wunused-valu=
e]
>>    memcmp(ptr, arr, size+1);
>>    ^~~~~~~~~~~~~~~~~~~~~~~~
>> lib/test_kasan.c: In function =E2=80=98kasan_strings=E2=80=99:
>> lib/test_kasan.c:645:2: warning: statement with no effect [-Wunused-valu=
e]
>>    strchr(ptr, '1');
>>    ^~~~~~~~~~~~~~~~
>> ...
>>
>> This annotation would make sense to add and could be added at any point,=
 so
>> the behaviour of test_kasan.c should change.
>>
>> The fix
>> =3D=3D=3D=3D=3D=3D=3D
>>
>> Make all the functions that are pure write their results to a global,
>> which makes them live. The strlen and memchr tests now pass.
>>
>> The memcmp test still fails to trigger, which is addressed in the next
>> patch.
>>
>> Cc: Daniel Micay <danielmicay@gmail.com>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Fixes: 0c96350a2d2f ("lib/test_kasan.c: add tests for several string/mem=
ory API functions")
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> ---
>>   lib/test_kasan.c | 30 +++++++++++++++++++-----------
>>   1 file changed, 19 insertions(+), 11 deletions(-)
>>
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 328d33beae36..58a8cef0d7a2 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -23,6 +23,14 @@
>>
>>   #include <asm/page.h>
>>
>> +/*
>> + * We assign some test results to these globals to make sure the tests
>> + * are not eliminated as dead code.
>> + */
>> +
>> +int int_result;
>> +void *ptr_result;
>=20
> These are globals, but are not static and don't have kasan_ prefix.
> But I guess this does not matter for modules?
> Otherwise:
>=20
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>=20

I think if you make them static, GCC will see they aren't used and will=20
eliminate everything still ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/917cc571-a25c-3d3e-547c-c537149834d6%40c-s.fr.
