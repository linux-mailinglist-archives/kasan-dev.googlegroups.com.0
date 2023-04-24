Return-Path: <kasan-dev+bncBAABBGG7S6RAMGQEXT5VQTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C46D6EC3C7
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 04:55:22 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5452b6c69e1sf2762232eaf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Apr 2023 19:55:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682304921; cv=pass;
        d=google.com; s=arc-20160816;
        b=wySLbyIpxniRhi+ckmnTmL6yg5l4YCD5NPtEs+ojzDni4aSIlgpGD5kPoicgKlmdJt
         tHukm44yxwx1q/L5ZhFzk465idKY86pMQLg8Z73NrDE+Dk4KDJny4izJbDoMn1M0fpSM
         4BeWD4nVv4J12gFsuAMeC3kdfG5yJqHF7XAlf/mPGxYbQrmXZT0zGBuHxiELIfEPeUw7
         itrjv3+sIJoNLcY0Ki17kKwDqeodRHFG37vg+incUxPJII8Pnr0b/OSU9msdiYlB657X
         dnOSadY6Yp7nH46yyqYGjt6kfSoC4HS4YBM4m+YfX8TCHiqKSFzbDvm4tnNyIJ1W1Agd
         24LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=3elQ43JOQScjox60naG6cBS1g7naGEsJQClcgvxebSs=;
        b=T55SJoi/FOsKEgNxTGVWBxoQB12W9wWdmbbokMtJA9uyLoukGMTeoFWo482tprP1Ba
         evwk8p7AnyzPvrhE/Wpm0vyiBU6Nc4kR+qNx8k1aEVVLEPdO+NFGcOoyioXQv/0Z1ne0
         kxEG5fa+oWHj8n6Ya11Rn5PoY958ok0TB3iqpNfaI1tgXWOdtKkt6nNrd6JDWjmct8jR
         Ed4bUN2QeELZIchOIiT9Czk4DBXTyIVwUuiDYgDOYTjqekmDqsygYXNZyGgFsJ2sU9tY
         WTZFmH4EK0RlT1pZAR+7EZZsN1anijzyVQaLpxZjHq5KxhNG1CBAYklrOMgdsuq9GGjn
         tvEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682304921; x=1684896921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3elQ43JOQScjox60naG6cBS1g7naGEsJQClcgvxebSs=;
        b=hYBTxIJNjuv1lixM+74g0FCC3xR0pvsNo6z2oe3maIZpa/MKq2mnblmC+oprBxyFsc
         fXgdFKPBdMy8WYHTKEE8hXYfCxW3/hx7IDB6zLJ5R4tRxHOJnJq8LDVk1d1kHWKu0RIp
         pwIDtL6jI8O8wzbTKMjF/gDf6vEijOkRaG1TL7WhQ1KvTatXEEk4OsSlWzlo8re9qWAN
         4tYCfKZro4cPejOdJKElueB85tlAyLXAnTeU9I4yJ78LlM5nB5ADodbhNCNgn/2+ARBq
         FGIkCMQH06/tKREELnWi73UAeA9R6QvhGvwTo/2ET9Qqb9AY9OYKzWpCTMrOnc1bn2pu
         2aUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682304921; x=1684896921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3elQ43JOQScjox60naG6cBS1g7naGEsJQClcgvxebSs=;
        b=LE+FQgbhsBGFp2ADeJ/mhJ1i8PVHYTSDCLklyPp7lCAEeMrmCc1+YbD3biC/TBUVEF
         vM798wCbGDZSUDcnYFYM2HjMub4/WqRdEHzjVqs+sNw23YvTiagZ/D1OWHWPVvk/gF8M
         7/kHmuOC313njv9ARBeMOlaicbYun05zJRpwh5qZcy0AWLBocIx+kgJeQMVLMabHaPGb
         wNZbgF0g1fZ5HOr/4zrslErCI5iSWuPG7Y6/15H2gTgdADqWQuUwxAjm4MZvKLmKGzaC
         fjwPxiD5XLXLmlIapoT51oSdqmttyoTeXZgWXK0qy5qDcMJO0UXpcqFYIxibwQUCleDD
         muPA==
X-Gm-Message-State: AAQBX9eBwQFiyvrjNv4hxg1nq9kiuArNC+hNvABLAHRD6He5cdoJw+bX
	qB2JXHY7B6CgAUYD3ohCOcc=
X-Google-Smtp-Source: AKy350Zlm2rJMa2pEL7fvBQkbR3XSNCWNhbPdaHDAebeXY0dHc87WBmp7utRUmAZr57j9qMJxDNdGw==
X-Received: by 2002:a4a:dfb9:0:b0:546:b865:38b0 with SMTP id k25-20020a4adfb9000000b00546b86538b0mr3103628ook.0.1682304920940;
        Sun, 23 Apr 2023 19:55:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d3cc:b0:18e:1d3d:3ee3 with SMTP id
 l12-20020a056870d3cc00b0018e1d3d3ee3ls2061263oag.6.-pod-prod-gmail; Sun, 23
 Apr 2023 19:55:20 -0700 (PDT)
X-Received: by 2002:a05:6870:7020:b0:187:e563:77b9 with SMTP id u32-20020a056870702000b00187e56377b9mr9933205oae.45.1682304920581;
        Sun, 23 Apr 2023 19:55:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682304920; cv=none;
        d=google.com; s=arc-20160816;
        b=avOxMgOPXlFpGFhWUxbP9acgUVHHrIukghzWaFW0bb1xkAIawiC7JWJN8GhxDCJmva
         ZTneSd3LzKf575Yht/5HJRUBy9xJvmm54eyMqSM2YWWm9eDbl6CbeBHRZnc1MpR3Zkb1
         smZMn1h2sIjHaVSIe4oykpOcCaDxp7I01PIMyOyXrSLz57DDLgCxgVETTHxwModC2joD
         6nfJhsit2ET0k26kCoqnpAS3NewWcUuI+wzuK9IKpSvLQn5wIlI3l4+2f19Sl0KLtkIl
         ouhFZZsryAbLYbqMmt/BYp0S0lTdw0mqHRR6RsFJ5wNVtlaCsqzmhD4XNAMjW3F882s0
         bWig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=tnCy/UcgBl/iEkJX0S+3K775J/JM+AfzODLWb9zfbck=;
        b=gI/eUS5hIa3uHjRN3ijo1klqXaVTAFjPXJIsJ3RtPgA4GnLaVHlR0b2iftzKkKMXPv
         ylAIquXw9Q0HhE65Ds0Vtoiq8t93zPt5aYLNru4EqF8eWoKck/eOTlArhsPqLG2R5OIm
         bgSVZDFnJwlJPdyV92R+E+kAadY0yftncojyLzZjJOR3M91N/tl7csWfAAnlTPKldeGY
         NYgX6lMegYpBhcI9SKHFFY1GlCWsfyPD35UCcdIZGvuyKUG9tneRd+Vr3MtmfpU0SWSv
         HsPRafmEkFZlnX4p/OPGG+K+IPCK6jTzYL/uyu4xOUiqa3vHgChV0rQFPQPLOkcmgmdw
         t27A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id bm7-20020a056830374700b006a42f0f76f4si826775otb.2.2023.04.23.19.55.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Apr 2023 19:55:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4Q4V7z50zBzKtrQ;
	Mon, 24 Apr 2023 10:53:51 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 24 Apr
 2023 10:54:47 +0800
Message-ID: <f5b23bbc-6fb5-84d3-fcad-6253b346328a@huawei.com>
Date: Mon, 24 Apr 2023 10:54:33 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Alexander Lobakin <aleksander.lobakin@intel.com>, Hyeonggon Yoo
	<42.hyeyoo@gmail.com>
CC: Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph
 Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton
	<akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
	<roman.gushchin@linux.dev>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>,
	<linux-hardening@vger.kernel.org>, Paul Moore <paul@paul-moore.com>,
	<linux-security-module@vger.kernel.org>, James Morris <jmorris@namei.org>,
	Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
 <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
 <36019eb3-4b71-26c4-21ad-b0e0eabd0ca5@intel.com>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <36019eb3-4b71-26c4-21ad-b0e0eabd0ca5@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Gong Ruiqi <gongruiqi1@huawei.com>
Reply-To: Gong Ruiqi <gongruiqi1@huawei.com>
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

Sorry for the late reply. I just came back from my paternity leave :)

On 2023/04/05 23:15, Alexander Lobakin wrote:
> From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Date: Wed, 5 Apr 2023 21:26:47 +0900
>=20
>> ...
>>
>> I'm not yet sure if this feature is appropriate for mainline kernel.
>>
>> I have few questions:
>>
>> 1) What is cost of this configuration, in terms of memory overhead, or
>> execution time?
>>
>>
>> 2) The actual cache depends on caller which is static at build time, not
>> runtime.
>>
>> =C2=A0=C2=A0=C2=A0 What about using (caller ^ (some subsystem-wide rando=
m sequence)),
>>
>> =C2=A0=C2=A0=C2=A0 which is static at runtime?
>=20
> Why can't we just do
>=20
> 	random_get_u32_below(CONFIG_RANDOM_KMALLOC_CACHES_NR)
>=20
> ?

This makes the cache selection "dynamic", i.e. each kmalloc() will
randomly pick a different cache at each time it's executed. The problem
of this approach is that it only reduces the probability of the cache
being sprayed by the attacker, and the attacker can bypass it by simply
repeating the attack multiple times in a brute-force manner.

Our proposal is to make the randomness be with respect to the code
address rather than time, i.e. allocations in different code paths would
most likely pick different caches, although kmalloc() at each place
would use the same cache copy whenever it is executed. In this way, the
code path that the attacker uses would most likely pick a different
cache than which the targeted subsystem/driver would pick, which means
in most of cases the heap spraying is unachievable.

> It's fast enough according to Jason... `_RET_IP_ % nr` doesn't sound
> "secure" to me. It really is a compile-time constant, which can be
> calculated (or not?) manually. Even if it wasn't, `% nr` doesn't sound
> good, there should be at least hash_32().

Yes, `_RET_IP_ % nr` is a bit naive. Currently the patch is more like a
PoC so I wrote this. Indeed a proper hash function should be used here.

And yes _RET_IP_ could somehow be manually determined especially for
kernels without KASLR, and I think adding a per-boot random seed into
the selection could solve this.

I will implement these in v2. Thanks!

>=20
> Thanks,
> Olek
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f5b23bbc-6fb5-84d3-fcad-6253b346328a%40huawei.com.
