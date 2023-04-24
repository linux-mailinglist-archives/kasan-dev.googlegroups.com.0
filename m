Return-Path: <kasan-dev+bncBAABBDHJS6RAMGQEKCWLFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A4216EC3DD
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 05:16:30 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-38eef8f6aa7sf13452b6e.3
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Apr 2023 20:16:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682306189; cv=pass;
        d=google.com; s=arc-20160816;
        b=TjDBgMH36GX9yWSpPtbmcNHwN0ocBdGqwbFZydqVuxOEWCh/6MUuOEBVJDeEPePzNU
         ImwXY6ySgE/a54AmBzra7dAVC2FvhiRfdnapdiFT/V2MHu1VYHg3Jl2Ijz1yjXBpn8Ga
         seaYQ3lvTPNoHuPNwSTXhw4aTbaJ69MCSERRNVGT6pG6nJeTfjDhIIyHTgDvV++Z4ZJU
         L5HpHgKLAqPBPHEQ3nY2ewoNifFjek1NJBeGhdHJ+bb+LwCetOtGkcft+5zBsmMpBVZs
         xTLnVILEWc2nWvdgvS2I7STY57yd3Cu2JKcbCrWyf17n3OIMaKI6GFcQvIkqGG6f2sBM
         C/8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Pi/kJXZ/t9JSVHi7UBuh0clbIKbFYTaDDcZDVZ2FYAU=;
        b=wVOhlkUeaHUGclERqfTsmm6cXYiIMh1C6MARAM13nVbMx+1DiZZGqtLd+ypuL8AcWw
         fJLZmzWFFrgEAquM5ibPZe0MWRYGuuaQVjDoRDLfINN5I0C1ZVlJYEMPVGxJDCyCNtAZ
         dVsnQA58BOkQxCQr0osgAdsUflmEkvePBM9jPAla5Slff20amoYmKDegP0kRC6ByZsjj
         WoTIESuXX3oH+hDPp7LK+a1iDRCzmXtOcHSWCqo5TSnD2Xkcfsa/XaN7HNb3Qy019Jxo
         vZkLEewDoPnqw3yoLHpNyreFwEzrmubYDrTZPhT/JkNlVk7IjSgL8a6A44zr0hWpghj5
         Q4EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682306189; x=1684898189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Pi/kJXZ/t9JSVHi7UBuh0clbIKbFYTaDDcZDVZ2FYAU=;
        b=Oyz6bfgoSoLwpQ0+GSKT1PGysJ+e8sQV2q25qN54asCNnHW0imUDrnuJDisWHJuUVI
         evogH2UTS5ORmIBXZvGNpiK7IoWhEc1dX0OAkg0sGvslGltpwS/PgVgBkqNfpKpXEglE
         PBGcbll0i1BGcWxc9nI77D17oMjwCIb4WJEeIaNntsdElAWHXgzNVnH8tBD5ndMegCcd
         Uvf0JVYF73RRyCwDy+FnwlRsvCbBFGKmuXH+wXDX3ROwdvcjl/XWmmDNv03j7wuCTRAR
         kRDtXvB8zKzSECj0mCEb41Tfjw6tYWsqMlmX8lY7VEbigzWWlwOLGFh3m7KnvXVZTxvg
         i7zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682306189; x=1684898189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pi/kJXZ/t9JSVHi7UBuh0clbIKbFYTaDDcZDVZ2FYAU=;
        b=Af+qbXozmhxiDPR7VoJ7VQl+DOVzNknCxw6oOlJQE67b711Y2CmkaagQrQFpKAGrno
         FSW/fI1x7bXRyLvtR9qoJwWCESe6kgo6M3oGRqklVa4CsAiCJcfz26lLfW4c/NSZZW87
         toQpgb0XUMulKHrne6sI8u4I6j+cN+RcnQLAo9VWnK8jTfvgUe+qTtLOuqJYhJDvTWOD
         KGRQSEW+R8bj0rlRAWKy/eIWlW9C09wZgL1e01b3dlsIWI4fN0O4MUNnw2H03rrXu148
         uUh4DbkAOC3h2S2y6z4EeAlfQxOR0XpqXbD1DNH0u0c7IxDwIZUymGTB/OoPx+m0no5S
         MlMw==
X-Gm-Message-State: AAQBX9cAZgVsSfyYG2mb3fP1J/qf08B/q1fmJzsaXKpi+6RPmggZ5IHQ
	HhCU7Av9zoOE/BverAirEUU=
X-Google-Smtp-Source: AKy350aBu7dYxbXsO8BZTXdxa8IRGXQ9tNAB5iHsZcc1oOAyMIaOdRi4cwMnweMynMx2gx9SeX8FvQ==
X-Received: by 2002:aca:3c88:0:b0:38e:839f:a658 with SMTP id j130-20020aca3c88000000b0038e839fa658mr3092647oia.9.1682306188972;
        Sun, 23 Apr 2023 20:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e552:0:b0:51f:f7a6:4288 with SMTP id s18-20020a4ae552000000b0051ff7a64288ls436582oot.2.-pod-prod-gmail;
 Sun, 23 Apr 2023 20:16:28 -0700 (PDT)
X-Received: by 2002:a4a:e715:0:b0:547:6a95:2d79 with SMTP id y21-20020a4ae715000000b005476a952d79mr3367884oou.1.1682306188541;
        Sun, 23 Apr 2023 20:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682306188; cv=none;
        d=google.com; s=arc-20160816;
        b=Iu4mOGjYhL9Div1j1NCZHJL0QmN+ht44SJ3Hmyqi6q6oQ4C+SWymLkSxgrwlkHTd7O
         0TcbmXtwLopOBxG9XKgUEDm/Od8QxinL73GUIh7r+8rrdFa5ZlhckldU4N59cyvKYdz6
         eK0mCnfjhry5dXijj5hdeF8a5Y50hSC974aFnx7/I2WKz3/8wR/YSzHpIsR05oq3mycK
         hHfC4beYdHrx8fenTyD3X3SF0lDk8ApIkJu3gKJztFzt9g41e7I+aC3M2JzSYgdVWmQy
         TGuBq8V8njpX6mPerz4DsTQDfKSk+76N5VXhNYxn+3yRb8L09a6YSOTot1+eU/0po7RO
         DksQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=a17Y1mkD7zYjtgGethq1jhAAN4YrghYJaAI1EJlV7Nw=;
        b=P7Qx8j+N25N1sPH1iIBDrt6jrdmGdVXLcOzd3vLYc92m94FxAXwqnN9b+9Gz1acvNQ
         j1cTpeoQVXTjj9P0plsbT01xFDKYjPHiJC1mYtOK2sLE7bxEJJBoiErTHzANaS6Z7Kok
         iOZvs3L2o+/ZVrLCk0W6gtYQirR8iHISmDZqOT/EAqrjfal5YTPA3TZwf2t4mVjhR/jE
         f+fbkbz4FK6oNp4LzDvx4Cd0nOLsoXjI+/fbny2IE8cCPuVWwpt1VzPgvMsz/EGghb/0
         F/+bdnaw0QFLSGcLSOpoP/LuoOXubNHlNhplVl0bBMbFLiqRaq2qlOOA7GZwoRtZufDz
         HF/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id bd10-20020a4aee0a000000b005472fa9aa03si402176oob.2.2023.04.23.20.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Apr 2023 20:16:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Q4VXY1krXzSvPZ;
	Mon, 24 Apr 2023 11:11:41 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 24 Apr
 2023 11:15:54 +0800
Message-ID: <8768d2ae-99ea-9890-83d9-7e1a35521aa3@huawei.com>
Date: Mon, 24 Apr 2023 11:15:54 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>
CC: Roman Gushchin <roman.gushchin@linux.dev>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>,
	<linux-hardening@vger.kernel.org>, Paul Moore <paul@paul-moore.com>,
	<linux-security-module@vger.kernel.org>, James Morris <jmorris@namei.org>,
	Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
 <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.188 as
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

On 2023/04/05 20:26, Hyeonggon Yoo wrote:
> On 3/15/2023 6:54 PM, GONG, Ruiqi wrote:
>> When exploiting memory vulnerabilities, "heap spraying" is a common
>> technique targeting those related to dynamic memory allocation (i.e. the
>> "heap"), and it plays an important role in a successful exploitation.
>> Basically, it is to overwrite the memory area of vulnerable object by
>> triggering allocation in other subsystems or modules and therefore
>> getting a reference to the targeted memory location. It's usable on
>> various types of vulnerablity including use after free (UAF), heap out-
>> of-bound write and etc.
>>
>> There are (at least) two reasons why the heap can be sprayed: 1) generic
>> slab caches are shared among different subsystems and modules, and
>> 2) dedicated slab caches could be merged with the generic ones.
>> Currently these two factors cannot be prevented at a low cost: the first
>> one is a widely used memory allocation mechanism, and shutting down slab
>> merging completely via `slub_nomerge` would be overkill.
>>
>> To efficiently prevent heap spraying, we propose the following approach:
>> to create multiple copies of generic slab caches that will never be
>> merged, and random one of them will be used at allocation. The random
>> selection is based on the location of code that calls `kmalloc()`, which
>> means it is static at runtime (rather than dynamically determined at
>> each time of allocation, which could be bypassed by repeatedly spraying
>> in brute force). In this way, the vulnerable object and memory allocated
>> in other subsystems and modules will (most probably) be on different
>> slab caches, which prevents the object from being sprayed.
>>
>> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
>> ---
>=20
> I'm not yet sure if this feature is appropriate for mainline kernel.
>=20
> I have few questions:
>=20
> 1) What is cost of this configuration, in terms of memory overhead, or
> execution time?=20

I haven't done a throughout test on the runtime overhead yet, but in
theory it won't be large because in essence what it does is to create
some additionally `struct kmem_cache` instances and separate the
management of slab objects from the original one cache to all these caches.

But indeed the test is necessary. I will do it based on the v2 patch.

>=20
> 2) The actual cache depends on caller which is static at build time, not
> runtime.
>=20
> =C2=A0=C2=A0=C2=A0 What about using (caller ^ (some subsystem-wide random=
 sequence)),
>=20
> =C2=A0=C2=A0=C2=A0 which is static at runtime?

Yes it could be better. As I said in my reply to Alexander, I will add a
the per-boot random seed in v2, and I think it's basically the `(some
subsystem-wide random sequence)` you mentioned here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8768d2ae-99ea-9890-83d9-7e1a35521aa3%40huawei.com.
