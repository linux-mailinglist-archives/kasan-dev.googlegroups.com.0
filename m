Return-Path: <kasan-dev+bncBAABBSPXSWIQMGQEXOK4ZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5873C4CF02E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 04:28:10 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id y1-20020ac87041000000b002c3db9c25f8sf11480877qtm.5
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 19:28:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646623689; cv=pass;
        d=google.com; s=arc-20160816;
        b=fUZIK9q11+Op23NyTOP2kBpBc83oYYOoTE3/CxN67f7jCK31N7nq87Xre4dC1UqHj8
         VqayxcVtTT92e9rAbZUddctIipCtbazNGgy8qY3tgOYa740USiEbcxs385BnzU6VQ5fd
         GIEZxvFdfU8rj72OE2U6fCZktL9hddZdp5o21DCV8giZ0Id5k8dNzlpGYQY3xBLHVPNA
         b1IGbviodtwkKME0H2Rei2HwKW1sSb7vsOUJlRdzv9FiALIBlBxrnq9r2zgkuWgVfYxV
         3mkXenvYjAf0gf33zsGzyn7RERqEZv6tgDbgbMKmz7/pM9ijM7Vig5qhHAKJTxsKAHF9
         zP1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=KqnUz7u8d7TrfGjAGl/zvKsD1SMMJTqMk2cbjJe1xvw=;
        b=a5W6JfVdYfidaKtbuFtlpugUJ2UiWynOXN981CNqp/m5/M6ySG+x1JxrFEclwaMRef
         w4R+y/a89MaSoGmi98+isaCVmEA8zw2WbE9Y/+gU36mZ5X6xhjhAakdG0WKCJqK4Rse2
         leX8QI3dTROSg5O3U3ERMXr8Gy5mZ8jA2CoVsi3W5j2OvxPDYgZkUuRojHN7uoDZFT/c
         gcX7WgIx9Rh/JmnXX96acJ9oN67QBb62kKAv3BqSJETZeB2Yf/bFpBQ1ErnIsfTtGy6b
         ZQ0nRh71tF3XLBUJNN9OZleupWvTGXKK8SUiQ+NqROl0DVDKrLbzEdf+XaTDPxRuLFqm
         JVtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.12 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KqnUz7u8d7TrfGjAGl/zvKsD1SMMJTqMk2cbjJe1xvw=;
        b=nWjeXSP+p2sYy8dWdOJwYaW/AFsDf/Q/S2qEKCUMX1MpdllxBx8wVcWxhW/jxNHLgJ
         qyLeq4GgfxuvPl3NNDPVUJJAu+ssS1hbqE7Ps54vBW9eBkVPkGJlm7NP1qHjtA9/RQr7
         c4L8iiLf7f/irbgqboAoMkaQvFeLhNy4dg340+vwQfj4lQOrJyDaZFEe5ugWbEKNfT52
         wylo1IemOYE96Bnc56u+Byx3QjYosnse7weFKA8KCCCLMSbFxvcnzNf9bH2o9RQN7EdE
         7rYSuAoACCEjRXx7DU1xLYt69RdgtQ7JQXQcpgm6fwynYk5NISZnv3LnuIbBtiQZXe0b
         XTJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KqnUz7u8d7TrfGjAGl/zvKsD1SMMJTqMk2cbjJe1xvw=;
        b=Zz5l39NqJK+sKt8JpriX3ETqgitAO86o7TauW+SONuZpAs/UTjsVOUOxGgLE9IwpZX
         bprz8q8otJaV4sq5DUrufEwZsDwjWwWIi5ZIFLG7e7JqO3sIjnwBSS91DbkiNC6bVEnD
         NiJBzKxJ/SGrYF/Uo+/Y5g3FYcPJTBTSdnDReLViE5yXiUGgBcbJR9BtNUxs2UP7jCKi
         esVjkLQEp/37PBqGWsYaYQJlVtGoc0moN2lq9ypFJ5hFnc2D8gt7o6iKI4J1CVMhhIvu
         4ErRpTieSpYbzfmpzlrIN0G9MSp4QAjBwXYvb57Rb0S9C/SvR4t1bIl/CW+pnqr4Y2F/
         UJTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nKFIjBryuZy/NQ6UK8Nj/ZPNm17SR0gsUHeiRj1rlOy5TiaAP
	GAxXs2rnONY60EYEcZPWiYI=
X-Google-Smtp-Source: ABdhPJx2CwgQS3VFgNmoeatfUrs2VrZ/zVWoOPCD82UGyobyh3D5SLwcF+V531M/ZknnFTKY67q3YQ==
X-Received: by 2002:a37:4550:0:b0:47f:55f2:7e86 with SMTP id s77-20020a374550000000b0047f55f27e86mr5865175qka.384.1646623689214;
        Sun, 06 Mar 2022 19:28:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a45:b0:435:7c50:5a27 with SMTP id
 ee5-20020a0562140a4500b004357c505a27ls1173518qvb.0.gmail; Sun, 06 Mar 2022
 19:28:08 -0800 (PST)
X-Received: by 2002:ad4:5946:0:b0:435:3206:7f75 with SMTP id eo6-20020ad45946000000b0043532067f75mr7149718qvb.8.1646623688842;
        Sun, 06 Mar 2022 19:28:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646623688; cv=none;
        d=google.com; s=arc-20160816;
        b=hPDeljI7mVCO+T5iogkcKUK24ehXujudmI998S/gVxIuA/q6T/NDR2Frnk2A19VOG1
         3xL9zW4qDEvepdxUbTVGgEA4tgeAOGPbhz3oa6ZScmbfILyYY7OkrNIyFpy2X1ipDoQZ
         p2pdo3twcUQ9xE7UEVy1kjgi6Gk0xVzduFOjiWSUv6YimdL8G1n5g/JmWBUD/8uo0/80
         bGh72QWBouaT7ZH7f/MlTAmtmlblIeo/RBJIbzxbpJrhwXpKIPUEtcGncra86WU6O4qA
         LVZkDuFWl0hDf9yw0ciflFxA6HjGjQ/R3PvNdfx3w2gaZV2z0x5T7o7C9UiE+KuaZsPx
         vf5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=kenPuWsYOwXh5E49XNzOqXBasWsQqxQdsbktpHIKb7Q=;
        b=zd95Z6AhkQEUwDb04lJykvnpyOZTkrk870ZRqHeYCCma/IGVUnkijn/vbgtoCYCRPr
         o8HfAMmkwLAYFv5/75PQceiOeaEMdcmI0xFCATT1MBJ5lU5vXs1J50TN++gux/J7bDLR
         ztQc44fjrXKC46iOY/IRwmHaxvbZdAKj91PxrMoSlxKJ7l96NwIsjRMHk/IxbGCYm67n
         JIcnnV0R/ecaQuuFuVpxSgXymbCIZAshBZYGnsRCCTdyxsS48v0UKuy7j2qayV8B35WD
         D8LSfvQsi7Zs5/5dXu7yQa5770m854yU6V6OgQjDNQNLDFzIc3B9fUSSZdA3akkYqzyx
         An4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.12 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out199-12.us.a.mail.aliyun.com (out199-12.us.a.mail.aliyun.com. [47.90.199.12])
        by gmr-mx.google.com with ESMTPS id g11-20020a05620a278b00b0067af44a3800si314255qkp.2.2022.03.06.19.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Mar 2022 19:28:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.12 as permitted sender) client-ip=47.90.199.12;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R441e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04407;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6P0CTe_1646623680;
Received: from 30.97.48.243(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6P0CTe_1646623680)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 07 Mar 2022 11:28:00 +0800
Message-ID: <44ba7c68-d2a5-5bc1-b8e1-1a9dc6619369@linux.alibaba.com>
Date: Mon, 7 Mar 2022 11:27:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.6.1
Subject: Re: [PATCH v2 2/2] kfence: Alloc kfence_pool after system startup
Content-Language: en-US
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
 <20220305144858.17040-3-dtcccc@linux.alibaba.com>
 <CANpmjNM+47dfjLyyuQwUWZyJgsr1Uxd72VPe9Vva3Qr2oiXRHA@mail.gmail.com>
 <fab45904-585b-0c59-a426-9ebecbd9d26f@linux.alibaba.com>
In-Reply-To: <fab45904-585b-0c59-a426-9ebecbd9d26f@linux.alibaba.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.12 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

On 2022/3/7 10:23, Tianchen Ding wrote:
> On 2022/3/7 07:52, Marco Elver wrote:
>> On Sat, 5 Mar 2022 at 15:49, Tianchen Ding <dtcccc@linux.alibaba.com>=20
>> wrote:
>> [...]
>>> +static int kfence_init_late(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 const unsigned long nr_pages =3D =
KFENCE_POOL_SIZE / PAGE_SIZE;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct page *pages;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pages =3D alloc_contig_pages(nr_p=
ages, GFP_KERNEL,=20
>>> first_online_node, NULL);
>>
>>> mm/kfence/core.c:836:17: error: implicit declaration of function=20
>>> =E2=80=98alloc_contig_pages=E2=80=99 [-Werror=3Dimplicit-function-decla=
ration]
>>
>> This doesn't build without CMA. See ifdef CONFIG_CONTIG_ALLOC in
>> gfp.h, which declares alloc_contig_pages.
>>
>> Will alloc_pages() work as you expect? If so, perhaps only use
>> alloc_contig_pages() #ifdef CONFIG_CONTIG_ALLOC.
>>
>=20
> alloc_pages() will be fine. We could free "tail" pages after inited.
> Will send v3 soon.
>=20

Oh, I remember why we use alloc_contig_pages()...
alloc_pages() (or alloc_pages_exact()) only support pages less than=20
MAX_ORDER (default 11). The alloc would fail when KFENCE_NUM_OBJECTS >=3D 5=
12.

So the design would be:
ifndef CONFIG_CONTIG_ALLOC and KFENCE_NUM_OBJECTS exceeds MAX_ORDER, we=20
do not support alloc KFENCE pool after system startup.

>> Thanks,
>> -- Marco
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/44ba7c68-d2a5-5bc1-b8e1-1a9dc6619369%40linux.alibaba.com.
