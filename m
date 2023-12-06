Return-Path: <kasan-dev+bncBC7PZX4C3UKBBQEQYGVQMGQET2G762I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 93A07806B51
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 11:09:05 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1fae1c8d282sf9486013fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 02:09:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701857344; cv=pass;
        d=google.com; s=arc-20160816;
        b=pEa06BZzO6E2KRStPqxRW8GC79e/BUp5hL3G+cjc/Exp1qUQhRDCgm5tzTaGr8Do7B
         KuP8rtvzkSET3K2cwf0bxqr9E/0pdY6gY9gF8MvzWu8qPojukFyDYLWAcFZJVQuJM5I6
         /U7GyyXNRh2FfdixSzKmQy/oed9Iziqk3uOa6pLsycHtiZNSSCq20Ooq6TSG5KUcI49L
         7fZWXAsm5ioklUN4rKPxI/8VhZlXFIQyjK3rIKbe6zFh0s5kEWXSTHewVdrOl/hOLAx7
         CyFzZctBAvUaES1tHnF6INdMLiHThu1wrtrA7q0oYfU6NSExXihQoe/JSCEQDYbJ6HFb
         UJuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=G5e0sLHVz8d61y0Gci9RVtjbQQ9bN2vkusCDRw7G+jQ=;
        fh=RD4T+d0NUvkOK9nuRNUtGBJeG+kgCpkicCsErEpvzic=;
        b=TQRkRwa7UwhsRkSNbBlIJGc/aEVILEv+KryO1YWMxV4zyLxBeW9lXtZqMHgQlGbdcp
         LhebJLSmIFWR6+EIFu4G/lzF2DDBHnRV1aD6mVmzls2liYnnYLIB6nwmpwKGWhHeTU/R
         4d35FU0pxhsq0p09fDXkMUzIavlVoKYT0KkGQm/uOmbGFvLsk7zHigRFKOmanLHH5CNO
         34QZAVi0NbqEVQWSqGI3of32b4ukGA7Ykqxf4JrDZV5BESWbhfu1B6oDNllHhguEEUQz
         L0qOSmZnmLHBzi0s/PK9bm6mCV6/fyKiaLLZNUUlra4jRBUWEADnXdfHXNvg/XFzWy31
         L9MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::223 as permitted sender) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701857344; x=1702462144; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G5e0sLHVz8d61y0Gci9RVtjbQQ9bN2vkusCDRw7G+jQ=;
        b=cA3F+GIG6Lj9ovREIiVkFvwBbmO9Sggt38ZT5YmTBfsI8M9ttODd1TVu5a1WL8qdCI
         /0s4n7YhtsH6da6yBcgNLoi2a2bXbUDO1GL2wj/kh8XJwNaZ5Mx1l8fllhPRRsjRV5S/
         Hlgr9VUmtK0XEYRi6s5VldFPlJYMT3mPGuVuC37ZZfJAKg8n1cMAqk/Cmg4r3HymvuBa
         3g8uYyh86F3HzdvBkJ2QmdZxzf5bdJGiSyMmFdQHAzIdyw8UCmqyLLXZEanYq+ExN1ZX
         uZzFlaynsGm47sCcu4kYeCQYww9DZxhZmiuvUPrfBIBXJzKoD1Fvt4B+qHE6ggrwQ4Dn
         Na9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701857344; x=1702462144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:to:content-language
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G5e0sLHVz8d61y0Gci9RVtjbQQ9bN2vkusCDRw7G+jQ=;
        b=tZde+IxWyuxwHYnhZ9msvNbXfQod1d/9NTgx2e47K517d06XP7WXuPfQ39lsbzY4JS
         JPKC7zlGKfRRN6A2nXznQwfDb28ItCEUAeCaAnpTKN70yAHT11ERqSjq2uqQdL10k+hk
         a3lmYQ3cfnOcljP1C5GcrYxAtMKtdRg91rJl6kLBZrz7n05IesgoQB/rvlzwnnjItMM/
         +gCN5LjYjdCCy3XjYGw97IJEoxyOj8D6nxcU95clp4jnz3N92XJ0Mf+0GQ8OleokVSVI
         DJWLDAmZseJV0o6xd8uJjjKMKauOMZ68t0kebZrC9jd75biec8NWNGEXzjj4YmQktFU1
         cIMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzBVqbZpb2ykw+Ta9alZQEwnVqgeTMoTX9BSi5+8y9G8ZAfXTEP
	7GBdj2AU8NjUlevH2c1+FqA=
X-Google-Smtp-Source: AGHT+IHTMtbveXYwhIUyG6EBT8XAfeS0xiEbTFSqyyFQcZC+0qSZW7VTp6BytakCszDmKr/bS/3lDA==
X-Received: by 2002:a05:6870:14cc:b0:1fb:75a:6d4f with SMTP id l12-20020a05687014cc00b001fb075a6d4fmr701592oab.118.1701857344500;
        Wed, 06 Dec 2023 02:09:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4d15:b0:1f4:88df:8b64 with SMTP id
 pn21-20020a0568704d1500b001f488df8b64ls964989oab.1.-pod-prod-09-us; Wed, 06
 Dec 2023 02:09:04 -0800 (PST)
X-Received: by 2002:a05:6870:e410:b0:1fb:24bb:20ba with SMTP id n16-20020a056870e41000b001fb24bb20bamr768725oag.9.1701857344233;
        Wed, 06 Dec 2023 02:09:04 -0800 (PST)
Received: by 2002:a05:620a:3182:b0:77d:cfff:33fb with SMTP id af79cd13be357-77f1ae4b27dms85a;
        Wed, 6 Dec 2023 02:08:28 -0800 (PST)
X-Received: by 2002:a05:6512:3d03:b0:50b:e4ba:b07d with SMTP id d3-20020a0565123d0300b0050be4bab07dmr551742lfv.75.1701857306203;
        Wed, 06 Dec 2023 02:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701857306; cv=none;
        d=google.com; s=arc-20160816;
        b=Mz9b0ZmuX7uKtx349bP/VjrMZ9hyGkguAZtfs3NSx1DA7NsDScQ78SeiKN/ZH+ONSt
         GdSyrnjhTEOgsAKCdm0VDXiUTOy4zxB7knYy/W3e80fuzlkzYAEfryJK4jkmdxKW9YDZ
         cPNWoL0GvYc8ndm5bkxTBpb2Z6vIaKNrt3c2ED6ojJs5DDYkwBsJ/Uk0m4skLduYY7TV
         HKxcpWYulMOWy5p7vsaoGpvBSX69fZ+T0GGG1dyIgOXX193f7hAJ75Kiaj1I6g094eh7
         No78gYRlc5jgx21lTxtKttWvsZJi1q96pyKki1pO4Td1Cd5l5YshAHWQ6spbyeaj/ECk
         KIQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=nzPtJSstrz43lOMah6a0IQ0FeQVV1HLyQOAK6AjcRVg=;
        fh=RD4T+d0NUvkOK9nuRNUtGBJeG+kgCpkicCsErEpvzic=;
        b=yIuyMVLwUqY2lVFP95PIit6UI13T31AyHcYIDHiItC4HPH/qptZ7hCwVDd21vtdPbz
         0GbSV4IfyodvBKnG9UqP8i4HsF6Sh7dZxgMajFQY44xIFxxqi2G851F6btjqd4m+jZW1
         39vF7XZUlfAAYPElJ/GQ8yTgGnRAhZfjT2Y1J9gtPvuY/kxPpaLoqcIC9dc6KTQoA+Il
         gmozFDGzsIyfERavq0GSzXjPCIJVD3bdBiZtWnLCGFjx60g0uQm/TqjygobgU0wbHDfS
         3MqNM46ZYoXfQiShnZSeVord4/K+2IXA8HaMZn3bAor3Ykcr1GWLJFd6Xxdf/ZKvPqNK
         Xr8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::223 as permitted sender) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [2001:4b98:dc4:8::223])
        by gmr-mx.google.com with ESMTPS id be6-20020a056512250600b0050bee864003si479243lfb.10.2023.12.06.02.08.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 06 Dec 2023 02:08:26 -0800 (PST)
Received-SPF: pass (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::223 as permitted sender) client-ip=2001:4b98:dc4:8::223;
Received: by mail.gandi.net (Postfix) with ESMTPSA id 7AB216000A;
	Wed,  6 Dec 2023 10:08:21 +0000 (UTC)
Message-ID: <f259088f-a590-454e-b322-397e63071155@ghiti.fr>
Date: Wed, 6 Dec 2023 11:08:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/2] riscv: Enable percpu page first chunk allocator
Content-Language: en-US
To: Alexandre Ghiti <alexghiti@rivosinc.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Arnd Bergmann
 <arnd@arndb.de>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
 Christoph Lameter <cl@linux.com>, Andrew Morton <akpm@linux-foundation.org>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <20231110140721.114235-1-alexghiti@rivosinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-GND-Sasl: alex@ghiti.fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alex@ghiti.fr designates 2001:4b98:dc4:8::223 as
 permitted sender) smtp.mailfrom=alex@ghiti.fr
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi Tejun,

On 10/11/2023 15:07, Alexandre Ghiti wrote:
> While working with pcpu variables, I noticed that riscv did not support
> first chunk allocation in the vmalloc area which may be needed as a fallback
> in case of a sparse NUMA configuration.
>
> patch 1 starts by introducing a new function flush_cache_vmap_early() which
> is needed since a new vmalloc mapping is established and directly accessed:
> on riscv, this would likely fail in case of a reordered access or if the
> uarch caches invalid entries in TLB.
>
> patch 2 simply enables the page percpu first chunk allocator in riscv.
>
> Alexandre Ghiti (2):
>    mm: Introduce flush_cache_vmap_early() and its riscv implementation
>    riscv: Enable pcpu page first chunk allocator
>
>   arch/riscv/Kconfig                  | 2 ++
>   arch/riscv/include/asm/cacheflush.h | 3 ++-
>   arch/riscv/include/asm/tlbflush.h   | 2 ++
>   arch/riscv/mm/kasan_init.c          | 8 ++++++++
>   arch/riscv/mm/tlbflush.c            | 5 +++++
>   include/asm-generic/cacheflush.h    | 6 ++++++
>   mm/percpu.c                         | 8 +-------
>   7 files changed, 26 insertions(+), 8 deletions(-)
>

Any feedback regarding this?

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f259088f-a590-454e-b322-397e63071155%40ghiti.fr.
