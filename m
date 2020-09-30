Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEMV2L5QKGQESJ6PYEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3152D27EA19
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 15:39:31 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id ct11sf1016901qvb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 06:39:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601473170; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5HGykOO7HEK5EfB9ZXzJW91dV4sXFZxH/LmzJTHuvW1dYKfBahMMu9z6gHHJGQHx5
         7+e0lmW1y+/nrxEhiJ/UOHqph4Rb6OeEddBbDHC/Ue1kHT3tNZAQ3Yw3Kj+Ls98g01Yh
         tNu+vd8hKtW+s10zm2aJsUJbDCHlPyen1NMArMt97rpZX8TuNZDLtMWHPusWdFFedbnc
         ToBQVKsuZ3Qalc5o3VFzuzWbRm0SqOlmCRkDqOOc/l1Jkzc48ctaez32MOJ9GAQNqiGy
         fgRHcFV9COIqQCTTv0tR3cD5vGrs0rnRw0nSBEdKbO+cDK/N8hhCbohgS5m54ndQg0Lo
         zvwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=RLbYXXUKAiGWyM7QrQz8OjHT6gUXmhovbkfK1DsBj7k=;
        b=a8PgguyTi/siA/swvJ4zKFNGqqO7x2osAo/J8kskmAnFU0LsbUO/NI+7UOB7eEQqCO
         vv6NA0yBf6n2QDTnMhwzzy5L2ha4evpS35YOoDSFiaXYWFLva3EvRVrxHLiV5NA6eKPo
         3Kb9+uVLjhJPHcZKpnfsj7Ms/F1orA9auFC+GBW+YeXBNEiuslxq5sAIGlQd1mI2OR5w
         NYAfBAsuxFyljNZAJ6ywR/bOAkbT/iEn798qgZcyhQOlaUCkgIIN6VZVV/P8TArxnNjT
         uaoUZFZ0qFoA3V1xJWm54bIV0bKzcG/X+XG8nGf+1Aq2w8L/ecp7cUzmJfp3hFfBzJqO
         Okow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HhPoVGuI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RLbYXXUKAiGWyM7QrQz8OjHT6gUXmhovbkfK1DsBj7k=;
        b=JtaPhiWD+QIkcXqQE9URG4q0NqtKOfTRz9xJVZ5lMMd28b3mqABg2yXl+DJLbITO5F
         GU08VL4jZl3aTB70NmqahQQ8d/GaWaKqBFEwKEa2jnODpGcOVXQL+SXROkHheViKHECP
         ahYnOavgLWEFlNBzwBiFWMM7nBUwf5UZXj6DYz4yE1DUh+gcKqlaLrJ+ou8NtkSMJbJd
         wrXpGljGkZy84gRwe8fMHKLfTPVe5ZsOcmjIlrZzzCljKCA6WnB0ga128NHOpUa+XFG+
         C3QQyEYO7LoPRGBdz2oCEc/N0o0y33VkA8mlDyaawxc5UIuwMZ8XlU6TJiG9SNb6qVED
         dWtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLbYXXUKAiGWyM7QrQz8OjHT6gUXmhovbkfK1DsBj7k=;
        b=jk1ZzWlauBpRQOyZAWnzN8ypfc+Qd76bwkJaRbc+lJlzcIBV6USJMh0jdQ0zSOrp7q
         D/FOcLZMm7CZDsphaavejfjz14nCBIef/dTbkyd2rzDkal/MXzO8IiScXM/N7dDbCJLt
         YphFp219ZNXqYI+HTe7C/kHltey/QEYlmwKFoaGPlYztT1jvi1+7fMvB9agzk2R6HlPp
         iPYEQjKD4ySiddaWmJCRccigcqSb9oxk91qXXNnktK0c4s/IRpO4KbUnJNbI/o5vVD5j
         IH+phZ2z3WkEIdDev2r9/VgPnSk/xV13TQfTBQh21XX8GqhT8PHSiHNJeq+YoBsg/sgA
         3GXQ==
X-Gm-Message-State: AOAM533zrBUnWlOipD0utLj7rWzKk4B55ayNL6+peRPPZLtcWaJub5cF
	CQT47lMgoqi3lOCoWuOJ/9s=
X-Google-Smtp-Source: ABdhPJwlgBYvLJk0JMjIdExMXtDxpYp76w5qNYHVSDUhs++lEJSfJ1BzGidGFgZc7lMm8IgSgoyYDQ==
X-Received: by 2002:ae9:ebd0:: with SMTP id b199mr2633813qkg.39.1601473169945;
        Wed, 30 Sep 2020 06:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:146b:: with SMTP id j11ls854494qkl.0.gmail; Wed, 30
 Sep 2020 06:39:29 -0700 (PDT)
X-Received: by 2002:a37:897:: with SMTP id 145mr2722918qki.82.1601473169252;
        Wed, 30 Sep 2020 06:39:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601473169; cv=none;
        d=google.com; s=arc-20160816;
        b=iOkgXJRfsxdwg4Zo0aivsUcKf5s3NHqzzfLnIcdu+H72f411tAphe/ezYS2wV6TaiV
         tbMq40TwzEgSmmtsmyAn24vaT85fEyOt/Ovn9BwSTatL9NPf10JxpZN3iNK0M3Ipa4Uo
         cN6Mqmg9i9S/a4Wbr0p2hf3cUbbxAPk8wBzlB7qmir5Dkq0RamMks25rUnJsxNAYyaam
         I3YI5KDWB1R0mZzUw+W9L0uctqqYp3jh67Bp/t4VEPolImqli/3/bQmjBUumMlOGkqXr
         qyIey1HjJsJ2wiaGgOiZajvKMKZ5i6kbomcz5wj8hU0WgGxx3GTMs/S6AkL1KuuPua7j
         WvzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZrsrzRQ4TVpvn1p7qcL/McYkzWe/Nnh3yNr0R49Y7kQ=;
        b=Sqq8ed0/VW+pKcTr295Wrgtvjozi6KQsXf8TOCu4QrsUyAo+UVK13j3Qv9vokjFOmQ
         +blw71GOMQURVrpbbEjWGBHbYI1zVK5VEmFu9bSjLXzsB+TDJT172VkmsMSSm9Z1N0MM
         2OXrxFSjwerxbQrszgdveqvSgJH0MtjRI8LAoVLMp0ge0G2RSxusssKGFdmo1FGxMkOi
         UBIsEi+xf6GsW1sUkqQ+NqFEmfWfY7bUjpeHV+lkT2d1TXivf36psIv6x3dU82JPkWvn
         vc/DK5LF5r8xQjp1qOOTN9La9Yq0nF1asQL7pCnO2eL5lS7f/W4Li6of9YlfpP2O7AFO
         F5bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HhPoVGuI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id x13si117363qtp.0.2020.09.30.06.39.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Sep 2020 06:39:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 185so1685970oie.11
        for <kasan-dev@googlegroups.com>; Wed, 30 Sep 2020 06:39:29 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr1494476oib.121.1601473168566;
 Wed, 30 Sep 2020 06:39:28 -0700 (PDT)
MIME-Version: 1.0
References: <644ba54f-20b5-5864-9c1b-e273c637834c@gmail.com>
 <CANpmjNNBGjjJyv+6QZm9hm=vQ3vHuAOTRYDs-T25X91AQxxyyw@mail.gmail.com>
 <626733c1-7e1b-6e45-69db-f4d6cc67fe97@gmail.com> <1fe27f01-d54c-6237-c91a-3731c84e9d33@gmail.com>
In-Reply-To: <1fe27f01-d54c-6237-c91a-3731c84e9d33@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Sep 2020 15:39:16 +0200
Message-ID: <CANpmjNOQg53dAwuZd4m29vc+cdizFZA-Dgf6DEOJ_=5UR4G+UQ@mail.gmail.com>
Subject: Re: [v4,01/11] mm: add Kernel Electric-Fence infrastructure
To: Andy Lavr <andy.lavr@gmail.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HhPoVGuI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 30 Sep 2020 at 15:31, Andy Lavr <andy.lavr@gmail.com> wrote:
>
> Hey,
>
>
> So, build linux-next 20200929 + patch KFENCE  (Clang 12 + LTO + IAS)
>
>
> If CONFIG_SLUB=3Dy then kernel TRAP, TRAP... HALTED no write log... (
>
>
> If CONFIG_SLAB=3Dy then kernel boot fine, if start kde then TRAP and HALT=
ED.
>
>
> Attached all log.

Nice, thanks for testing!

Does this also happen with Clang 11 or GCC 10? I know Clang 12 caused
some inexplicable problems for me a couple weeks ago, and switching
compiler solved it.

Thanks,
-- Marco

> 29.09.2020 17:48, Andy Lavr =D0=BF=D0=B8=D1=88=D0=B5=D1=82:
> >
> > Thanks, I understand. I will build linux-next + KFENCE and will report
> > the result.
> >
> >
> > 29.09.2020 17:30, Marco Elver =D0=BF=D0=B8=D1=88=D0=B5=D1=82:
> >> [+Cc kasan-dev, Alexander]
> >>
> >> On Tue, 29 Sep 2020 at 19:22, Andy Lavr <andy.lavr@gmail.com> wrote:
> >>> Hey,
> >>>
> >>>
> >>> https://lore.kernel.org/patchwork/patch/1314588/
> >>>
> >>> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/c=
ommit/?id=3D6ba0efa46047936afa81460489cfd24bc95dd863
> >>>
> >>>
> >>>
> >>> And how will this work together?
> >> KFENCE is for heap memory only. We do not touch the stack or rely on
> >> any of the features mentioned in that commit.
> >>
> >> Or was it something else?
> >>
> >> Thanks,
> >> -- Marco
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOQg53dAwuZd4m29vc%2BcdizFZA-Dgf6DEOJ_%3D5UR4G%2BUQ%40mail.=
gmail.com.
