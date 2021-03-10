Return-Path: <kasan-dev+bncBC447XVYUEMRBPVUUSBAMGQE7ZYKVMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 48F5E3347A2
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 20:13:03 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id n16sf7327639wro.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:13:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615403583; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDix8lWcZ2bLwVmbYs9gPVcVYh3FTF0UsZqgccDiR827UCUVN5TZOFCBQvpLVFf5IQ
         UOqbjKra5ISfHNOSX7kQfRKoCYHgn0QdjmXwPD3rteHGXojPBit3O3o/kaq2Q3CCEoRM
         breQsjhOBRpwf/bjGisCIgyEohOyaVYIDxsifYfgyl6I0Y99qwZVV0uBHBMNIz8F9lzi
         UDprBs9aTIRo5xwXTVU1ViOF6XZYQ7yxQdnDASCN2cNNEe8lN2yGVBOeBGeU7RSz1j4t
         R3el/7RnRToYTts7IFqaTYq2LjQVP0o2LBlsNh6h+iuvj+d7LaYy0fBbMejNbNpsimSL
         9OOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ZXH5BBOsDEGmyfI/NVzvqCxv/szs/mgEDyf2YivoTjk=;
        b=0sfvDxgchcoUG+6IjvCfIbGhVgdVj50TXa+uxH9NuSetXeLCLxcS0yWtrurpjWVlj/
         OOeb77zwSVcIwWTzK1Dj81rgEZAosSH9SjFA1YEE/kA0gPhmMWYoZLdiHimV4BwmX1hb
         gR5PTOrEDIeyiyjohf4flK9iyKfVz9Z3+1yqWjHuudjslRsnY8f96psDWIMiHlmny6Cq
         65A6N28MPR/HiNqXlRkjsX+dtK8edRzjPpx3Pd/9Mrw2kExIrOq9fNxfJCQdm5BvTVL3
         f5miBM+fIgoIaVG88Y/FTVHE302La65eA8SUfPnx+0h8KkuMvL0iHkD1IRN/DwY7ISrh
         PENQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXH5BBOsDEGmyfI/NVzvqCxv/szs/mgEDyf2YivoTjk=;
        b=fnKZdvXkJRiD2hARF0UmUewLKVIcbVQHYcAElE65IOcTf4pp1MUggcfBDXMwncNrx5
         SvKtoDZEzRN8Jy0+2202+TvQsdKBAC++eobCRetIN0AdrYUTc5CPy1tdO+JidfN9mKfN
         QVXmiFq2IgrJP+pstxsAYrxBBs3ufeFSSppbpWLPavSKVUd/AZpQnIZoRSOIQaHh9nm0
         d4/9ErAXIuykwKFCzUR4/O6YbilTXG8M8Us91VvNjc0z/eBy6ap5cJLCHU+qItSKfdsz
         7Dqq4J4F3O7I0ItmlvYOT0AEwfwRFxOs/cX6PtdxVhewp2hMGtqy39NQBhEqtf6Gwltj
         crqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXH5BBOsDEGmyfI/NVzvqCxv/szs/mgEDyf2YivoTjk=;
        b=WbFgkRKHlTBm+MjYGmOzljYEgwNf8Zw6YcVm2+kEbuPdxRLppjG7zlV+Xsp8aSdJST
         /y1O9VbyfRY5UEqGKg4SUcPp4yf7lZRshFQoUx12TFmvbBA4hTrNtYjJDHeChPzv3xaS
         O6aw51ObwdZ91zWJJ3NjQ2qJaHWK6y+m+qun8HgaOyogdt7g/Ffd052tgh5K9iZrHvsB
         xHSzPQYMKfVcUj9Rt6IOOozHX9HdRycpUtcma34VdsgnAiRRpCSfEAcNGNdT5H4usMMC
         GutIWs5GMpPOvpt1OWykNcyxrTtpOlk8UCrKA2NzOapVETabO3yaGU95JMqpypBwS0zq
         bFOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WkL8nqwYGSq+KvmPLW981I6FNIgsaEkm4qsGFD4ZuzKDk7Nyu
	s/6bNaWSYKKnormeuj8zNZM=
X-Google-Smtp-Source: ABdhPJwbyFuGFqVbwSzqoCj35/kBnA/6yEDD/k1xrMPETl7r5yXqLdxm7uHz1sR63ET3ItlJEvkNbA==
X-Received: by 2002:adf:dd0a:: with SMTP id a10mr5143069wrm.145.1615403583070;
        Wed, 10 Mar 2021 11:13:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e6:: with SMTP id g6ls2774422wrd.3.gmail; Wed, 10 Mar
 2021 11:13:02 -0800 (PST)
X-Received: by 2002:a5d:4ac4:: with SMTP id y4mr4953851wrs.86.1615403582232;
        Wed, 10 Mar 2021 11:13:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615403582; cv=none;
        d=google.com; s=arc-20160816;
        b=aZ7fKjRgGTvIjKrDhcbhUZqNrtRDZmYpMmU830FWB4hH6oxPOrmOERexpBaK0TtB+q
         6XjqX0T0lWFsWY5xVmCROpfiWtp4CjUxRc56m1WVO4YSMZeO17ESBYtyon72zdO3ND3Y
         U/oN5cdutWJcjuVmncB0NWBrvxVPwFIINeipdWYPNYk1DhGZgaYx6ZY5BWGuJFXqzu6S
         hlRg5RnA2bJol4ajuVt2gywkNn0MIW9x0E2c7TJB5zixBGSHj9xGM18AeT4VrNWsh7oZ
         5mWf9J3Jspzrka9AOjXkFfpuimhCdeO0WcZgvoo+Chn/b58k+1E1XIwSoFpVcYE0N7ZB
         dukQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nHlVRETe4AEbKPNmvv7gLydt0lu0ZQ8TOIuigAPHvo0=;
        b=x+pgb1DFCXqJeDil0ionqTTK8xJklkc6GOAD5FwAEulj7Pge56LtTQaZBRc7SgRDiM
         zaaRVScEeV9yp/ErZDyDfRK8kUrgaRn9BBMwUHMzlWfZTf2VmCxass0hOiYp28qoldqI
         pNyG+8nRDBJWx7WR3XQ6TMCQ4b4fun3b+2dtrRDlaw8BMK3WoGvD8TG+dRNq0S/2QKM+
         Am2KljyHe8Bdsul+XibXdSBScML3GXhJCvXvI/0yeaRcnX5TG2YQjBO4mG+5zIW8iibR
         1LJZK3OsviJ1zCnzH0FkyRqZp1x0xZT7JRFuMk6IbuyYKlNoogxekA0rGVUB49wCDLXF
         Cqcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id k83si12644wma.0.2021.03.10.11.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 10 Mar 2021 11:13:02 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id 9F5FB100006;
	Wed, 10 Mar 2021 19:12:55 +0000 (UTC)
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Arnd Bergmann <arnd@arndb.de>
Cc: David Hildenbrand <david@redhat.com>, Jonathan Corbet <corbet@lwn.net>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 linux-arch <linux-arch@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linus Walleij <linus.walleij@linaro.org>
References: <20210225080453.1314-1-alex@ghiti.fr>
 <20210225080453.1314-3-alex@ghiti.fr>
 <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com>
 <7d9036d9-488b-47cc-4673-1b10c11baad0@ghiti.fr>
 <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <236a9788-8093-9876-a024-b0ad0d672c72@ghiti.fr>
Date: Wed, 10 Mar 2021 14:12:56 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CAK8P3a3mVDwJG6k7PZEKkteszujP06cJf8Zqhq43F0rNsU=h4g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
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

Hi Arnd,

Le 3/10/21 =C3=A0 6:42 AM, Arnd Bergmann a =C3=A9crit=C2=A0:
> On Thu, Feb 25, 2021 at 12:56 PM Alex Ghiti <alex@ghiti.fr> wrote:
>>
>> Le 2/25/21 =C3=A0 5:34 AM, David Hildenbrand a =C3=A9crit :
>>>                    |            |                  |         |> +
>>> ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
>>>> +   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixma=
p
>>>> +   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI i=
o
>>>> +   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemm=
ap
>>>> +   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB |
>>>> vmalloc/ioremap space
>>>> +   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB |
>>>> direct mapping of all physical memory
>>>
>>> ^ So you could never ever have more than 126 GB, correct?
>>>
>>> I assume that's nothing new.
>>>
>>
>> Before this patch, the limit was 128GB, so in my sense, there is nothing
>> new. If ever we want to increase that limit, we'll just have to lower
>> PAGE_OFFSET, there is still some unused virtual addresses after kasan
>> for example.
>=20
> Linus Walleij is looking into changing the arm32 code to have the kernel
> direct map inside of the vmalloc area, which would be another place
> that you could use here. It would be nice to not have too many different
> ways of doing this, but I'm not sure how hard it would be to rework your
> code, or if there are any downsides of doing this.

This was what my previous version did: https://lkml.org/lkml/2020/6/7/28.

This approach was not welcomed very well and it fixed only the problem=20
of the implementation of relocatable kernel. The second issue I'm trying=20
to resolve here is to support both 3 and 4 level page tables using the=20
same kernel without being relocatable (which would introduce performance=20
penalty). I can't do it when the kernel mapping is in the vmalloc region=20
since vmalloc region relies on PAGE_OFFSET which is different on both 3=20
and 4 level page table and that would then require the kernel to be=20
relocatable.

Alex

>=20
>          Arnd
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/236a9788-8093-9876-a024-b0ad0d672c72%40ghiti.fr.
