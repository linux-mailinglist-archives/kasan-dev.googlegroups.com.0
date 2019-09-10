Return-Path: <kasan-dev+bncBC5L5P75YUERBB4A33VQKGQE5KTO2HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EAAFAE8A3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 12:50:47 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id j10sf8821016wrb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 03:50:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568112647; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmzDqff47cg6XTFSjqxtm67YnSbmugGploiOkXX/LzSqNzHN1tbmDx4+soAb9890XL
         vntEC1YD9oakEOvfD9TmXGm72j5aVwJjOci960kNrLvn0VxUdUULMePxZKPl+qPDdlyA
         60qanlPTJ3jLA9D6dXi/YUn0gWMi7TMeU8O0OPFRKo9+mIyGOJvLhqjZle6zNzql/IdB
         Rt4ygRIT/+iy4s7pS8sBvK4KI6l8C9GHSSlKNpeYM6fOaaZlYI0jZQ2ElK95fqwBLuSB
         J1QOygbXtiUeuRPROebEm82hcdOgw6dlPkAaJGWaND2Gw/uW4mqdRFGdZ+e3I0PxiP4D
         iQAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=XsN0A485BBzrg33ywbqf0AkBSwEMn041uv6wLcbGthU=;
        b=uuTtLrU+3/gZhn5irFr+Y0d9UDXKjuAbwpl5OjIPVvI3hz5Boto8gAZXLj8iyBTOvh
         g5dLyq5At3+Wswr4ywC5bzI6z+vbvKzxNc3Nmv83bu4WMF7GFkG0SSyiAaFmfpowIwTr
         dMxVcSEMzK50u8FVUTDGqItoEwekMFxdcJBXvM2TTGZtF+OKWVnDVinPXnQIYOKjQepf
         QAmm4lHBKw1Cz0RPSwwiOhofcp2hOkNqTjftW8/8lBz42N7eeADL/gpDxMJo/BiTBTr2
         AvgB6RWPQiVuwT7yeB1fo+RhiSidWHEcQt0svuZyEWbSJLbdpS5GKL2/qDOaz830quU5
         CxDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsN0A485BBzrg33ywbqf0AkBSwEMn041uv6wLcbGthU=;
        b=cS6Jo5A2GftjhHkBlEY483RCDt71kbFLo+prhVsCxKGjwM2N27gqFuzBEIPTufkfYX
         XnVOiKZ4CRodbVXixMDVkUWqPJmrJl44w77bsgZFJ/gmV/n2bGm/1vJKdTN8EOb/PY6B
         u2uwuuMjUXVfVxWOfAmtcqWD8Db+y5MtLySCaNI9wGsjOKIyuxv9heJc2M1AKEUYk6Ip
         +pLmQidppquYzXJFXH3C59+4mmc53F7mjt1Cb7iTfR3EN/AV21BfkalnCyrj5daubvDt
         otfOD2D01f7f9mXKTuCfkInZizA0s08uBk7Qss3qUfpVs51pMluyTZhyR8DutlAOWylT
         XhDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsN0A485BBzrg33ywbqf0AkBSwEMn041uv6wLcbGthU=;
        b=qEs9rYrYis1hbnEex49o6WLHbPjTtORz3hz+N10dLYMvu7Y8FTyku49lmCyVtYnann
         c+o8fC9znZCXScFnnn75ey3wBpuK0ygPpgWUj9QZcQ8V7UtqJp/oAO8V6nT5w3Q9559Y
         2bastB4Wd5CpKs0H2kFP4936T5AZoFOhyhhS4D56WrTY+oqyQmeBg2JfBswjiaJ/kGuM
         U74iCVzrZsWaX0ggVJAa3NQ+nOL0yywumDw9eKqGc2DndFXa+QUuQn9KLI1IFLOvTEaj
         J5CmzjJn5il4xhbkThLfmEr5EEVlOJdA4+Uf+1iqfXk2+zimHhrDH3Vnm/pKEvTd4pwm
         Qtnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUg3EGgQgiPMLKpP6So90vXPa/3ncHqNqXfS2ormsD8v5yy4yEl
	msjrF9yvAI+2fVtgiNPfkjo=
X-Google-Smtp-Source: APXvYqxFTJDL5ArVRyzSt4P7wOoCFqg2W/K4O+AedXLVz7PF2CBhdl5QEScfZbMvR+dMprbB9aOsQg==
X-Received: by 2002:a5d:6506:: with SMTP id x6mr5769894wru.22.1568112647189;
        Tue, 10 Sep 2019 03:50:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:df82:: with SMTP id z2ls5215682wrl.13.gmail; Tue, 10 Sep
 2019 03:50:46 -0700 (PDT)
X-Received: by 2002:adf:f20f:: with SMTP id p15mr19364931wro.17.1568112646818;
        Tue, 10 Sep 2019 03:50:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568112646; cv=none;
        d=google.com; s=arc-20160816;
        b=YyRpyWLDaNE2IgCY6UyYyhCc4sMxRNLp2VQspQeKHQ/IFwEM7PUJ2IP/Wu12BQyk+J
         rl3941RkoiKIXHccvcDbxIlsLAZW59guGo9qYeSrS+WuaqpG9EySP+PnepeV2iLJ8iG2
         DEGX/HMr4Mk0h22Cq8wvpOjfORnLAL0tlw3h0+YmT2DfexoKPIA4/hT9nYHLGnrrFtWu
         hN0vDVECT2pKKV6+e9dHaZKnRDsJiNq5B9me0tz4jE9Q/FZwXYt/KbDf3XRjc+T/uk0k
         tZf0UlRk8z7JXtFAXQnlXfvCMzk5HYOCCAzFGM5pfJjwG/lwN7gVVm2VHSN/RKC06kVF
         mF+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=mCcrdxpTjYNMqPwu5a0++sL0igTDvXz8dnP5yhSCASQ=;
        b=Uytr0w0DjiwbU2Tn7UurXn6Sm66Zbr2hi9n7nZAWDT8m9noGh6X8OA9UXQoQt9xpAI
         p3y2gM7xtP7lbtni/+DqmWufRjFkqv3v++ydyobmjtZxyDjJ6CwL/43dL4Iqyue9rwJ3
         QM/Hj9CeGS37TITs2B8j2Bhp+P+wDUHlDKCGll3uteRr44f8vEelE9btrTaBW2gwKMY3
         jWZJieQPO/CM6vUeYI+iByOM2XsgmaCY+FO0ipqwLbALTFZXQxvbBwi+m9On8my3zM/M
         0y11gT77XinRPJwXFAw7gcMzGy7v7oCgh8cD7Ikz+KbwRl2+Hnti0xGIY4r4NJfQcn/v
         BnbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id m20si109366wmg.2.2019.09.10.03.50.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Sep 2019 03:50:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i7djC-0007sY-TJ; Tue, 10 Sep 2019 13:50:31 +0300
Subject: Re: [PATCH v2 0/2] mm/kasan: dump alloc/free stack for page allocator
To: Vlastimil Babka <vbabka@suse.cz>, walter-zh.wu@mediatek.com,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Thomas Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
 Qian Cai <cai@lca.pw>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190909082412.24356-1-walter-zh.wu@mediatek.com>
 <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <a7863965-90ab-5dae-65e7-8f68f4b4beb5@virtuozzo.com>
Date: Tue, 10 Sep 2019 13:50:29 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <d53d88df-d9a4-c126-32a8-4baeb0645a2c@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 9/9/19 4:07 PM, Vlastimil Babka wrote:
> On 9/9/19 10:24 AM, walter-zh.wu@mediatek.com wrote:
>> From: Walter Wu <walter-zh.wu@mediatek.com>
>>
>> This patch is KASAN report adds the alloc/free stacks for page allocator
>> in order to help programmer to see memory corruption caused by page.
>>
>> By default, KASAN doesn't record alloc and free stack for page allocator=
.
>> It is difficult to fix up page use-after-free or dobule-free issue.
>>
>> Our patchsets will record the last stack of pages.
>> It is very helpful for solving the page use-after-free or double-free.
>>
>> KASAN report will show the last stack of page, it may be:
>> a) If page is in-use state, then it prints alloc stack.
>> =C2=A0=C2=A0=C2=A0 It is useful to fix up page out-of-bound issue.
>=20
> I still disagree with duplicating most of page_owner functionality for th=
e sake of using a single stack handle for both alloc and free (while page_o=
wner + debug_pagealloc with patches in mmotm uses two handles). It reduces =
the amount of potentially important debugging information, and I really dou=
bt the u32-per-page savings are significant, given the rest of KASAN overhe=
ad.
>=20
>> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
>> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
>> ...
>> Allocation stack of page:
>> =C2=A0 set_page_stack.constprop.1+0x30/0xc8
>> =C2=A0 kasan_alloc_pages+0x18/0x38
>> =C2=A0 prep_new_page+0x5c/0x150
>> =C2=A0 get_page_from_freelist+0xb8c/0x17c8
>> =C2=A0 __alloc_pages_nodemask+0x1a0/0x11b0
>> =C2=A0 kmalloc_order+0x28/0x58
>> =C2=A0 kmalloc_order_trace+0x28/0xe0
>> =C2=A0 kmalloc_pagealloc_oob_right+0x2c/0x68
>>
>> b) If page is freed state, then it prints free stack.
>> =C2=A0=C2=A0=C2=A0 It is useful to fix up page use-after-free or double-=
free issue.
>>
>> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
>> Write of size 1 at addr ffffffc0d651c000 by task cat/115
>> ...
>> Free stack of page:
>> =C2=A0 kasan_free_pages+0x68/0x70
>> =C2=A0 __free_pages_ok+0x3c0/0x1328
>> =C2=A0 __free_pages+0x50/0x78
>> =C2=A0 kfree+0x1c4/0x250
>> =C2=A0 kmalloc_pagealloc_uaf+0x38/0x80
>>
>> This has been discussed, please refer below link.
>> https://bugzilla.kernel.org/show_bug.cgi?id=3D203967
>=20
> That's not a discussion, but a single comment from Dmitry, which btw cont=
ains "provide alloc *and* free stacks for it" ("it" refers to page, emphasi=
s mine). It would be nice if he or other KASAN guys could clarify.
>=20

For slab objects we memorize both alloc and free stacks. You'll never know =
in advance what information will be usefull
to fix an issue, so it usually better to provide more information. I don't =
think we should do anything different for pages.

Given that we already have the page_owner responsible for providing alloc/f=
ree stacks for pages, all that we should in KASAN do is to
enable the feature by default. Free stack saving should be decoupled from d=
ebug_pagealloc into separate option so that it can be enabled=20
by KASAN and/or debug_pagealloc.

=20


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a7863965-90ab-5dae-65e7-8f68f4b4beb5%40virtuozzo.com.
