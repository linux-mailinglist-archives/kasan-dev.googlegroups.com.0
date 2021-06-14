Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FPTSDAMGQEYRV2OYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id B3D013A5E8B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 10:48:41 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id 62-20020aed30440000b029024cabef375csf3946460qte.17
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 01:48:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623660520; cv=pass;
        d=google.com; s=arc-20160816;
        b=BG+UI5N+XcJ2uCl/uGORtnWEktdogOaQhwHQtBL79MWRbVyWl4LCx5IhCVRQvoYZ28
         vvwI2Svp4jyO+0jHkw//F17MkXBO45hOgY1cQOqZJscmb6/WhIg9FhxVGN+NzVTbLQ0G
         iLFLzXnEBVb9ajDatjsOl2INx88IgHHPh68pgD1GUtaPCxp5ne8lnCuOf+YHnX7rvgOk
         abLvKkj69G6vcUlwOySj8SE97uKrJlIS70KN1gh7MpHmoo1949i70JBd3obr+TIRWkpd
         UdFiEjSStw01iY+cRFLpZgAVLP4/ufTXMA18OGTIYyvI5poDEHxiIBLQaP6beIHmnYZK
         Xrrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fzbF3ewwSbyXs3hv4dVxOI9yZe3KKhbDQ6LKq0J5tD0=;
        b=SuDDHgW8xZnEIUiI/LEUNPbR5lhl0Pp2dOvoH/m0b4ZlYYWWNb+qUlRpiXBfiNPuZr
         1KFtYmo1BtCzAFkNikT9M+83G2TTTvMWr4e5pTW2hqfOQIwlvRM/8rIdYoByHLTpSPBH
         a6v8wUB0yqg6xOAMKIJ+XZ+GD1+2HqbfJQNbUj71xFJ4fShxcGo2ywtB3t74SSFsBPL9
         1qYcuqhFyFo/fuM7PlbP1hsW97/LFJfDdzxcACeDt3qEHz1rGh7wba7FMMmvhuyZWcfP
         4uKldBa/jkEblGAv7ERwbxs+VLxVlWkPSJ5jx+8EuK35OfIEbF5jfQGuxbswarNny4Eq
         GeJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VWEYtLKR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fzbF3ewwSbyXs3hv4dVxOI9yZe3KKhbDQ6LKq0J5tD0=;
        b=E8lz5OE7thc9A0SVt68lTswM6Tz8YOnhbzXjo023b5vTZmKPpE/nc/2xg5SKoobU+i
         t0ezJy8oNtF/upDDmw/Fz7IfexqybEvHwWmFrHHD4oqnYp9hmzkJkd8A2fAeGO1Fuwx/
         PjPVFM3ndR09t7z6M/jVTyn2tCjeY5aCYaOvK/3h9Mim3kC2m1aXMhXcgtupR/NBUJQr
         F7+CwkpK+0E38jaqRaSGZMVBauNs2IT9WgdHD+rPtpjHqEVnDQLLd/ARr30ySvWiXsGb
         bs9VSqeE4CVyjYqRV6ozHsshVLb66Ib02V/FEMIrKuXzaNMd7RCSGaBx1SdV5SObdnix
         uxIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fzbF3ewwSbyXs3hv4dVxOI9yZe3KKhbDQ6LKq0J5tD0=;
        b=dPxpBwP/6pYFZWlZXz/Pn1hY5aNw3C3eT+uurOr6A7XelGEmJY6mRNpFnNf+piHphu
         Pno7bFAVOfJauSbEeKTgCM+2gSIsg8SreofFrx1rEK/GxHb9xmpngr7BYDhAuJTcest9
         Fv/tfcffyK0n+OVhNWMOfksYfhegk0E1hGNzgaV/YNIvZjb0MSqPtEmFuP4JH/YPFGdX
         emKw2A3TXTv1RRnJNt1j+YdV7CCZNdgdUK5NzQ7V6zhBzAsUG5wiK61rh1p6JFPM6BDU
         udlSqAQ1ZJ2OlQHXEay7OrhhbI5YSLGl8e7LTHlk7UBrwjdPWrmmaaCa1pBJTROmE67L
         KnGQ==
X-Gm-Message-State: AOAM532f4Xcj03S1uNhWwEA34rPlK6GylxVqRVGW07c4GtPD0qOpcWxV
	cicj7HThT2rQCJsATwZ83Uk=
X-Google-Smtp-Source: ABdhPJykSI9HSpimXSn6noGvu91mWF8rDtHMPRPkvnbR8adQ3Ll4QncLajxg0bgStIz7ot0Bt/HdFw==
X-Received: by 2002:a05:6214:7f1:: with SMTP id bp17mr17473695qvb.29.1623660520532;
        Mon, 14 Jun 2021 01:48:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e40d:: with SMTP id o13ls5451332qvl.0.gmail; Mon, 14 Jun
 2021 01:48:40 -0700 (PDT)
X-Received: by 2002:ad4:5bc7:: with SMTP id t7mr17505754qvt.3.1623660520120;
        Mon, 14 Jun 2021 01:48:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623660520; cv=none;
        d=google.com; s=arc-20160816;
        b=JiCTqXMHKsrvSWYV6eHTLjwhR0SeMYQb0T6hJfimouY04IrmktA98D1/NFxhkPdqTv
         u1BgcIcjDfEIQT8SAlqKFUrZrhbSUMyzRggMB2Ol/5uvrLTSJj0FEHmuZRsI91A7sizI
         HzcDCmCXDz1lvJQi6Z1CJNX4hqB8J6QrbEv+3WL9yRSI9ul4ZsaYARqm9q89HHgOixxc
         JnwtSuuEAAVOUtZRtUewDgX+DK/NmQg5WzrdkhRiWlap9j0y1Ri0sqV1FELbgTsVXfk1
         4lGH2fkpsL312+0qHYl1bc/pGH4WdlaHFTXwgS6c70oq6JNmm/tzgghORHYhkRpZxCFM
         +VmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g5pXCAj2QuRES1o2pFYr1kobiKA7QQMUK/Q0IqCq9h8=;
        b=nwBOJWQ+3BI09ISJGdU2aIOReXOZFF49TZHMQ5k34d/Jv732ls2NJ4eXUgj2WowcWD
         Ii0H4/1VU2kWqXKyBsrZWzk+aXCkppYXB+WoYJ1i4gsNOEn8Q0jCRrzXGam/s5WT1RGL
         RT2I5ukxV2rKJTSjYM/8hANUnNHGsR0I40xpAiIL+kH5kc9xajJ9YEK4ZYNF8aM6gxp7
         PY+NVjApuF9qZv+pZ5yGnl3j5+KmaxLMZAm2ufO2g1+dWEXqpca/jfKN5WEsTNKfuMiu
         zqGx29SGU2gKmdN6GDAfhCo43ue4P31uMkSvYkOndBbThjE+KcdvXv1c+Wm6DD/7fd1p
         BRCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VWEYtLKR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id d10si1399054qtg.3.2021.06.14.01.48.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 01:48:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id q10so9414984oij.5
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 01:48:40 -0700 (PDT)
X-Received: by 2002:aca:120f:: with SMTP id 15mr3849142ois.172.1623660519486;
 Mon, 14 Jun 2021 01:48:39 -0700 (PDT)
MIME-Version: 1.0
References: <20210612045156.44763-1-kylee0686026@gmail.com>
 <20210612045156.44763-3-kylee0686026@gmail.com> <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
 <20210612155108.GA68@DESKTOP-PJLD54P.localdomain>
In-Reply-To: <20210612155108.GA68@DESKTOP-PJLD54P.localdomain>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Jun 2021 10:48:27 +0200
Message-ID: <CANpmjNOf8i6HPxFb3gjTrUWMh_6c4zdsh29izrSrHDi9ud4+gw@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <kylee0686026@gmail.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VWEYtLKR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Sat, 12 Jun 2021 at 17:51, Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
[...]
> > > diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> > > new file mode 100644
> > > index 000000000000..4f740d4d99ee
> > > --- /dev/null
> > > +++ b/mm/kasan/report_tags.h
> > > @@ -0,0 +1,56 @@
> > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > +#ifndef __MM_KASAN_REPORT_TAGS_H
> > > +#define __MM_KASAN_REPORT_TAGS_H
> > > +
> > > +#include "kasan.h"
> > > +#include "../slab.h"
> > > +
> > > +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> > > +{
> > [...]
> > > +       /*
> > > +        * If access_size is a negative number, then it has reason to be
> > > +        * defined as out-of-bounds bug type.
> > > +        *
> > > +        * Casting negative numbers to size_t would indeed turn up as
> > > +        * a large size_t and its value will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        */
> > > +       if (info->access_addr + info->access_size < info->access_addr)
> > > +               return "out-of-bounds";
> >
> > This seems to change behaviour for SW_TAGS because it was there even
> > if !CONFIG_KASAN_TAGS_IDENTIFY. Does it still work as before?
> >
>
> You are right. It will change the behavior.
> However, I think that if !CONFIG_KASAN_TAG_IDENTIFY, it should be reported
> "invalid-access".

There's no reason that if !CONFIG_KASAN_TAG_IDENTIFY it should be
reported as "invalid-acces" if we can do better without the additional
state that the config option introduces.

It's trivial to give a slightly better report without additional
state, see the comment explaining why it's reasonable to infer
out-of-bounds here.

> Or is it better to keep it in both conditions?

We want to make this patch a non-functional change.

[...]
> > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > new file mode 100644
> > > index 000000000000..9c33c0ebe1d1
> > > --- /dev/null
> > > +++ b/mm/kasan/tags.c
> > > @@ -0,0 +1,58 @@
> > > +// SPDX-License-Identifier: GPL-2.0
> > > +/*
> > > + * This file contains common tag-based KASAN code.
> > > + *
> > > + * Author: Kuan-Ying Lee <kylee0686026@gmail.com>
> >
> > We appreciate your work on this, but this is misleading. Because you
> > merely copied/moved the code, have a look what sw_tags.c says -- that
> > should either be preserved, or we add nothing here.
> >
> > I prefer to add nothing or the bare minimum (e.g. if the company
> > requires a Copyright line) for non-substantial additions because this
> > stuff becomes out-of-date fast and just isn't useful at all. 'git log'
> > is the source of truth.
>
> This was my first time to upload a new file.
> Thanks for the suggestions. :)
> I will remove this author tag and wait for Greg's process advice.
>
> >
> > Cc'ing Greg for process advice. For moved code, does it have to
> > preserve the original Copyright line if there was one?

Greg responded, see his emails. Please preserve the original header
from the file the code was moved from (hw_tags.c/sw_tags.c).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOf8i6HPxFb3gjTrUWMh_6c4zdsh29izrSrHDi9ud4%2Bgw%40mail.gmail.com.
