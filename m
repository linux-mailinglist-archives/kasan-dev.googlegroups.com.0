Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBIVXUSTQMGQEXLWB6SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 17A87789052
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Aug 2023 23:22:44 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-50092034189sf1503181e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Aug 2023 14:22:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692998563; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvTaZw9lvCrEnRXyEHADHL89Xm6yzBLFgdsTXaqffjEpoX8G0OBfC/TGEZmUTTZT5F
         4woeTzLjE/5PzYd6dh6bTuEBXfRVXhE3C3WZIRCg/NAizscmfbuu2v7SGhaOYiZhiJpB
         iVT/OxBPKzoj3I4ncT2lhPjUxSRvRo+4BX9bSL4lERGfhh1M1+AMzp6+qgd/LvJaVQnQ
         1CoIyq2RNuGe5DKAKLPYFFbqE/tChcU2BNnE+Bxh3N5T9JEGiG4f2uJWp0lfly1yxHw8
         jaZcylFZULZmNK5fW5hu+JVO12nlnK2rjjVhyuDdE3sZc5pf4N+c4FGckxA12H1pvXsm
         9x1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OvnqCVStw0sCcjC8WVH5F/nlU0nxLMnw+Epsdk55Kts=;
        fh=WszcI7rX9NMnnhXXYal61IL+Bi3vfpDZzDeRe01b33w=;
        b=TFMYj/oYAvlAhZqX96XXTzriEeBEm4fV+nkLuyrvfiwj5mB2OEnoQ5b8GGhf9dB/4F
         BN2ILQYIij1mkIyeM8Np46G3H2wK5dPVuJqZK1288ayF1KwJCXEbi1wXWUFWnk56Ened
         ScEbAikQr7vLDR0MNFWM+LB3wTobokXN+0fBGPgNcORBnLQSE7CzcNWQIVzfhxI1bvee
         qrMNzLY7jcJpcjcEv6aZbmM1+P7IaVpkaWR6hregBXfOML/tR03Rc36QX2AwGZ6DQUke
         iR6NXZ7XulUvicGHtzooxRReU1Ck/ou5VUd2MAE2ctVs43dFPwjLNYf/SLmXJ1smnHrc
         iPJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4hAOWcLo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692998563; x=1693603363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OvnqCVStw0sCcjC8WVH5F/nlU0nxLMnw+Epsdk55Kts=;
        b=Kkxs8zuaomLPX95KHDQPSS7aGu0hR0DbFRvW66CMyIF24P73GsC5j+mMW2l7pPjUJc
         WbLwJIbv3Mw2oHtqSNtoEhp5eUEYD+KEnmJBcPiEFfbKFUR0gugJ9sbymf+52M3mfYg9
         cjdaPcZUOj/Cve96jQT5QXudfbMt3Ie5f/AbfP8PIMxzpmmeQqCY6vd4H6zL3GF0/hVA
         vIfcDTh9gPRH3GFIWuZa0r7DsAxII42ObO6+XE3tHbW2wyoaCS4bsGGu5rLajvD59kgB
         E/OaxtQNJcsWC3ycFiC4FNl89pK7INzwAIpcMEV6fOAnyXHVXhdlm6gb6lMgFpXSc/yk
         z8gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692998563; x=1693603363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OvnqCVStw0sCcjC8WVH5F/nlU0nxLMnw+Epsdk55Kts=;
        b=AGosBdZT3epep+OpfMrIVRKq2OUemV97jquxqaq4lstVwq+XiSRRxJ3sxCRHmSQhS0
         vik30var2mTkhxluceMJHdGbMnxkmuKtLp6Nca/OG2lfBbKw1Mp2lsatCVrIEMLxTYg+
         7H18ydATgcaNe2YhBjMRaU+r8slY16gCX5SmZH1EEdb+kse8Zc0I/nvw9t0Ohj0+3aSU
         2DuiPoivHsh0YRG1AadhHntIZBpn5ri6Jo/JIabKhy9kbeOagcWUwgCLhrNoWaamRdEE
         4YOrRqb5kGumc1n3w1JQNzzbEsOHxDDDHTduyNNufJo5xaoHsvw6qFAa4UDNnsI4I+kZ
         Gqjg==
X-Gm-Message-State: AOJu0Yxr+6QlnVgv2oyMtDGCSiUBxira091/dng5d539+sB8k4kv4LK3
	iefVVtSmZelSA6U83YmZeS0=
X-Google-Smtp-Source: AGHT+IHZphQtPEyh9BXAd67MH358D8+/xZoEMYFEySYJRUkOCupJWd8xtGcJ8EkbVQmNf2Y3I66hqg==
X-Received: by 2002:a05:6512:282c:b0:4fb:889c:c53d with SMTP id cf44-20020a056512282c00b004fb889cc53dmr16048948lfb.10.1692998562321;
        Fri, 25 Aug 2023 14:22:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4f07:0:b0:500:83e8:9d2c with SMTP id d7-20020a194f07000000b0050083e89d2cls236312lfb.1.-pod-prod-04-eu;
 Fri, 25 Aug 2023 14:22:40 -0700 (PDT)
X-Received: by 2002:a05:6512:b28:b0:4ff:8f44:834f with SMTP id w40-20020a0565120b2800b004ff8f44834fmr15977220lfu.38.1692998560627;
        Fri, 25 Aug 2023 14:22:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692998560; cv=none;
        d=google.com; s=arc-20160816;
        b=j3yUmGmBxDvajzxwznGkpMjQw5LeKwmk7NxfoBbYbQG6JAIhvCTJ1l6M+4C/g42m0+
         1p1HkWrZMXVN5BIiQMPgBVUekoFyeTGp06o4Mt1f46VXLl6V9SkNhjywXcgHKDBSwYkw
         AczHSXmPQDbIVq6rj2PWmsgOfcE/0I2E+Ruu3YgyjcmYm+SXzulS3tYPFgFng9p88X0m
         OeXArVTXLdP31nsXfBQyUOFW2eRNrIDG8DIkExiCTMO6HJpuFoB1eYc8T3l29UtkzYEv
         aMksOrC2bmapHAGlVdEpR3F0FwKy271rEKitzIMBfTTj43fWb0kDS0fnKyKnzjeQ3UB1
         XQdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sY4XdT0afbZqJDMtqEzLCUjgr5ro7J2PA8+3Z9sf64I=;
        fh=3g8IvveQYAwrVqp9zrENuWFEb5g9HNr9+nprfD67q9k=;
        b=BAvC/aEqF9x077+m/QXpVSimrRv0DmQlzOt3wytjoF6c9HzZIpCQBQjOdk/u/QtPu8
         k14Y6Og09p3nTVQtYG9paT49VXNnUnT7HIFJl/xg3JfzINeaY6L7JjuI2U8uJoZ1mIDU
         /mfAkePVeObedLgWnH7vBTl1MnkbptUXPssXEmLpqvz/GFyfIu76cFpojonmGrZl9pSS
         eXqXOSMZVs2odhQJsg3b9DiRMbHECdLQAlLYliDRd+T+kbT0RBS03qP+Xf1Y4IfRU7Os
         HAhtpKFmcRFj7IWrQhAgThQFeF02NmH9pK6ObBjJwdUo6mo8CoG/yICwAtgkuxdnWe78
         Ayjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4hAOWcLo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id n20-20020a05640205d400b0052174fd486fsi291908edx.1.2023.08.25.14.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Aug 2023 14:22:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4009fdc224dso8505e9.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Aug 2023 14:22:40 -0700 (PDT)
X-Received: by 2002:a05:600c:3b8f:b0:400:46db:1bf2 with SMTP id
 n15-20020a05600c3b8f00b0040046db1bf2mr83152wms.2.1692998560041; Fri, 25 Aug
 2023 14:22:40 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
In-Reply-To: <CAG48ez2OrzBW9Cy13fJ2YHpYvAcn+2SbEmv_0MdrCufot65XUw@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Aug 2023 23:22:03 +0200
Message-ID: <CAG48ez1OHWSnsPTg5BnNBiawkVVhuoTCx6Y4ZOE-HYJaRVnhHg@mail.gmail.com>
Subject: Re: Kernel hardening project suggestion: Normalizing ->ctor slabs and
 TYPESAFE_BY_RCU slabs
To: Kernel Hardening <kernel-hardening@lists.openwall.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Linux-MM <linux-mm@kvack.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=4hAOWcLo;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Jun 23, 2020 at 8:26=E2=80=AFAM Jann Horn <jannh@google.com> wrote:
> Here's a project idea for the kernel-hardening folks:
>
> The slab allocator interface has two features that are problematic for
> security testing and/or hardening:
>
>  - constructor slabs: These things come with an object constructor
> that doesn't run when an object is allocated, but instead when the
> slab allocator grabs a new page from the page allocator. This is
> problematic for use-after-free detection mechanisms such as HWASAN and
> Memory Tagging, which can only do their job properly if the address of
> an object is allowed to change every time the object is
> freed/reallocated. (You can't change the address of an object without
> reinitializing the entire object because e.g. an empty list_head
> points to itself.)
>
>  - RCU slabs: These things basically permit use-after-frees by design,
> and stuff like ASAN/HWASAN/Memory Tagging essentially doesn't work on
> them.
>
>
> It would be nice to have a config flag or so that changes the SLUB
> allocator's behavior such that these slabs can be instrumented
> properly. Something like:
>
>  - Let calculate_sizes() reserve space for an rcu_head on each object
> in TYPESAFE_BY_RCU slabs, make kmem_cache_free() redirect to
> call_rcu() for these slabs, and remove most of the other
> special-casing, so that KASAN can instrument these slabs.

I've implemented this first part now and sent it out for review:
https://lore.kernel.org/lkml/20230825211426.3798691-1-jannh@google.com/T/


>  - For all constructor slabs, let slab_post_alloc_hook() call the
> ->ctor() function on each allocated object, so that Memory Tagging and
> HWASAN will work on them.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1OHWSnsPTg5BnNBiawkVVhuoTCx6Y4ZOE-HYJaRVnhHg%40mail.gmail.=
com.
