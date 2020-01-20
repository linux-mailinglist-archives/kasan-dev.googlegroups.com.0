Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEGS7YQKGQEGGXRP6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CF6EC142E72
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 16:11:13 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id 144sf20085690iou.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 07:11:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579533072; cv=pass;
        d=google.com; s=arc-20160816;
        b=rjmCvH+pGPfkzHbCAI7eYvSQleievy2xYCAIeVp2G8PZ6UiTrQg1YyfSQvTSsdNJPD
         LmJp63ITTVmBvjEIwPUZG5nsTp2KhG87Y5buxGs2V8s86lL4cGQP31J+dmERO37rQlMD
         S8VdQP4TPtGlZDvl6f3dztS4RFjvMHhNU3rCIo/xupHOvg9Ds1NUvxUb0H8UmP4UPC94
         RXfpdxvl5ac21fZBCncwNvc3BgIwcowsfH3q934/xFYqfUVbrw6QZdUecrZN+MSYCxYp
         5w7UCA7mq4EOZx40eCWdiS2pP1tEphNe6AePzE+YlpIbnPzVYP+nNwUNK6Y7L0GkQLDB
         p80w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6L77JCqhk7w2nvGMByCrPTBIHyxAqV9UsCMyWQ6hUnw=;
        b=tXTuBwhYpr4nyVYViHyTvVCuKvHb6SSMj2revzTkyYIzpC2Jw39L10npfxY8CFcA2W
         AlCxsdGS038QtNKuUH+kaTwnIfa6Y3omMRKWYTOH3CD1GYo42/cXn2suVyh7BMe/KyPQ
         iwsYbJJf/BgApmbraA+shX2uKv041HDStLZoofR4U3WFDRrEf/X7EgtGh+uRKKTBd7ph
         UeAjhIlCEBgVCjkK0W67HSaHkeF3xlPXCQNAhDltJ/m6QVRpcvz/E9o0UitGATVCyJT0
         TFFtkdrZ1/Riet8Ko3CZaWk1EpYmzdrfHm2oV5vieVY27qnnMwUJe5rOLq45gZ9J1veJ
         7tgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vQchanyu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6L77JCqhk7w2nvGMByCrPTBIHyxAqV9UsCMyWQ6hUnw=;
        b=oS78xeznVlhvH4KEY30Qh3yqdU0TbU475Yw/t/6DGYwzWb/+7jF8wq0pZRa35FYfJR
         00IKUZDN4baCgRIOOL6AUFoysyyRrPORADjYmtyo7UWsQYrqhpQHv433GlQUu5k0b3h5
         mypSrPaLJA7LMi5kUCQMQ/r/6wDp/ft8XzLgEz0ni9Ra5P7YC2rHQtf/UBk4wlGAMK1i
         f9v0Z7fsFBCgT3bC+zp6LB2eODwxAspljfOM5oyDe+v7/gllfBPOT9Gfo7+EEdLWYHMf
         z0i4JYcg+rem/K5vxycr5za3QHn/nMz+kSatBfJwFpBnNACmNh0BZqH0yBLIXt5fnGxn
         GIwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6L77JCqhk7w2nvGMByCrPTBIHyxAqV9UsCMyWQ6hUnw=;
        b=L5tWqyNq3XurpivlDlMabG16PS2JRevPTlmAzH2qxIta5cWTTarHXy74kk7xXQn508
         x8XeT523W2UYUkSgSlqcViHy4kLOSIQpgKPDKVkiAivezoKE0JX2Ue1Jp52d+2ELVaAY
         MR4sycSaUzjz1fV0/S6DRjiimEI7bsXgU79BsVB38Un0UyOKn9yhsbQPio/L1Gppm7wa
         jIxiFjcNFIZc0mSayi5FXNsVE0lIEJM8JcfSCxW/uvoRnmF5CjRFUe9fa7f3OLpab1q3
         aNGhQGmIutGPBLA1/fwFBBMqoDQuor7xDbFX1laSGKiW4u6ZKQv2JNXK3O4fhSZLAU7w
         uWew==
X-Gm-Message-State: APjAAAUFzLnSW77QJBoLV2Vnl2f/2bAonXkPJr8VMbeCz1obAoMQeOwq
	UTbSH+4JCB4oNWe9YsmUW58=
X-Google-Smtp-Source: APXvYqytG7rlsA2QgDlIS030lXr2YfIyQc6okQ+ej0GJOsv3pZqUA64N4CtctXicuGT7FTcU/xLjgw==
X-Received: by 2002:a92:8511:: with SMTP id f17mr11708679ilh.255.1579533072668;
        Mon, 20 Jan 2020 07:11:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:90f:: with SMTP id t15ls5126565ioi.15.gmail; Mon, 20 Jan
 2020 07:11:12 -0800 (PST)
X-Received: by 2002:a6b:ba06:: with SMTP id k6mr43018621iof.70.1579533072212;
        Mon, 20 Jan 2020 07:11:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579533072; cv=none;
        d=google.com; s=arc-20160816;
        b=U9t5I69d0x8UI9TYOBjb8UINyOk25RCTf6brjCYuGAiWHW0/zGQU5rCix5FbK3hpYk
         WRp2OD+KIbQWimg6B3T4mcbfR2gAdRtV5QAfFfWEN7+Sg8WFcp+aZWaBepbxOqpqfLA4
         +j2WOYNHxEOWLNwXuENbLgclZxVg5SxJ0wBO+eKQpEv7qfTJQujjxKLVHVHwFMVm1mbp
         goKNutcYRaPbkVM1CDxxe4zTYAFMyREdu1gBq5GxNmQ7xR0iu20+S5E9mh/PsXfYTdI+
         IKhq/DuIHIV553KMrblXvbSU1NZUbi8ocPQG8K4tGuM0pIc9HlDk9rSefTm60jH07YIY
         P2Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TQoSylkDTjGNW+otOWNEut12k2291qZWwUfCl+hYpEQ=;
        b=wZzjjVf4IYVv0XVJAuPlYfGkzleHobtixNHuggDrmByon2c9c8u2q6UEBIW+hw3VI1
         hswAzu54xz7OZ24puFxqHjydGg4OLJewudqc/W2sENvJtqYAQDkb46JzObtTpXO06ESq
         /+s3tyoc+VcNEHxkA+x92/MfIXg6kPaCeYO7RfjmhqcXVDYtO2c0K14/ZZRZmlbtB0B+
         RMuuHwW67jOvQZqQ27yCq1EMlVltb9NFejmjMSnobF13rI0rJT0j+oQH17kvC/upTeqU
         hFUQuYpxcEmB4xa+q76wDC3DpqkjZFWK2MNFk2G8UQBA1qwLdw7JZs6jvZ7LLYp5tw2x
         uRDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vQchanyu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id a1si1609716iod.3.2020.01.20.07.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 07:11:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id z64so28786437oia.4
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 07:11:12 -0800 (PST)
X-Received: by 2002:aca:d4c1:: with SMTP id l184mr13228717oig.172.1579533071637;
 Mon, 20 Jan 2020 07:11:11 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
 <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
 <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
 <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com> <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com>
In-Reply-To: <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 16:11:00 +0100
Message-ID: <CANpmjNOUTed6FT8X0bUSc1tGBh3jrEJ0DRpQwBfoPF5ah8Wrhw@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vQchanyu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 20 Jan 2020 at 15:40, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Mon, Jan 20, 2020 at 3:23 PM Marco Elver <elver@google.com> wrote:
> > On Fri, 17 Jan 2020 at 14:14, Marco Elver <elver@google.com> wrote:
> > > On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
>
> > > > If you can't find any, I would prefer having the simpler interface
> > > > with just one set of annotations.
> > >
> > > That's fair enough. I'll prepare a v2 series that first introduces the
> > > new header, and then applies it to the locations that seem obvious
> > > candidates for having both checks.
> >
> > I've sent a new patch series which introduces instrumented.h:
> >    http://lkml.kernel.org/r/20200120141927.114373-1-elver@google.com
>
> Looks good to me, feel free to add
>
> Acked-by: Arnd Bergmann <arnd@arndb.de>
>
> if you are merging this through your own tree or someone else's,
> or let me know if I should put it into the asm-generic git tree.

Thank you!  It seems there is still some debate around the user-copy
instrumentation.

The main question we have right now is if we should add pre/post hooks
for them. Although in the version above I added KCSAN checks after the
user-copies, it seems maybe we want it before. I personally don't have
a strong preference, and wanted to err on the side of being more
conservative.

If I send a v2, and it now turns out we do all the instrumentation
before the user-copies for KASAN and KCSAN, then we have a bunch of
empty hooks. However, for KMSAN we need the post-hook, at least for
copy_from_user. Do you mind a bunch of empty functions to provide
pre/post hooks for user-copies? Could the post-hooks be generally
useful for something else?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOUTed6FT8X0bUSc1tGBh3jrEJ0DRpQwBfoPF5ah8Wrhw%40mail.gmail.com.
