Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY4ZWL5QKGQE5BWMDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 00E402770A6
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 14:11:16 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id l9sf1135574wrq.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 05:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600949475; cv=pass;
        d=google.com; s=arc-20160816;
        b=ljBl+KpnP8ZDSVW9Na32Nam79E3gvrnQ5TsycVw4OIA1IDgAle8uNxZXw2ZBgIo3s1
         jRlsqXapgDKmAIVElK4bwLZqHc1oAqmMCDqZc/D1OSNMjPp9v5zlqhVGumOC7b5tDjOV
         7+uy8KcdWE8xg+lnGPgK1/J+4IuXIfUD2URlxVlHe/cdWvKeGx8XXIP9XzBzvg+Sk1Y8
         jGSxDDcBPbda8FFz8QQhk8nJypHTFqAVQ+4ykX3oyMSx7gmH4U/4z9PYY0GLuMpYJjW2
         OuacgpJkMW4oZut8tSyeMBsUKgqtXG9B6M9yGIKpxGbbcyV1qmIXlCmuiXt7NUSAXa0X
         bIkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TobS94F6d/pYqjxIk3qXLKAkjQAkyk+bkN296la/E6M=;
        b=rCm+9jeuDtl0Ibn/hZhps7RGdVRUm1RWCrY9jzHQwe1Rlx71PEqiFyKJnNPts8dpl9
         QHje12ObIxCEIrbRQ1ypVH7zW9SR/YxlGWftUwfPd717r0O0fi//dy0JOFbjan9fWM0T
         3kApE9l9BDP/rQvXFssw6X/K9dwc1pdJiirI3ieJftF4JZoQl6BFOscFEbgVKi+y6dUb
         3bEsZb3m4yTr5N57wAcLH7Gxy1qsNvWpS0N7EFKkKPi68sZoaAkLrN0upU6gS7BY3EZX
         XS1ADaj67rkTUZZTyqq2oiyf45mjy14n/qGx69Ov2hRp6bt/EQBUut9ehUleE8kVbj57
         myMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=amEBg3Sa;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TobS94F6d/pYqjxIk3qXLKAkjQAkyk+bkN296la/E6M=;
        b=FN/pq0J+Mv/2uypTTHdPaIFikfuvz+19VssG5AdxeIYFtq3nHn8JOQ2ikdyJaEW4Oq
         scEZQPld3vH33n8e6Te4UJ0H2s5u9PsmEVhiAuI0KbSKKAqsdHbcDb2T1LEaXWOX2oGV
         GGs507ZyMXfscg1fO/MyXDFGapBgMtxYbvMYnXHFXxs8N2VzqOFlf+jLuntImcTr2p1f
         0M9+/WauegnIZNizepAx8BKIxu3mfgUE9HpxrTyONQ8TeDY2SP2++x+TJxo7cJo/zm1P
         X5LCWr9sq2ElEARnZyc7xZIrT/cJCF1n95kEEpkt/eiStwgtG96OTBXfX3J86JH8DRyt
         2bTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TobS94F6d/pYqjxIk3qXLKAkjQAkyk+bkN296la/E6M=;
        b=VnwY15lFkho1cP4rseJf1+8AWXBSVoNbyWxRrRL4goMmueuOBplC4S7/KEWcwmXM95
         hEN46WNG4XV/1Jk/C2Tk7iXbNDitN5+cnR2WL2H13Rmx/MUzu8sTU89TjOLXn2hVfK6J
         aN4x5e7e9h0nOwjshq00GDeHiFsjvTmXrc5FS4mw1y12XxzkjLqNLpjdwqYlGHMNo4v3
         QdZjTYo8ligHUkEb9TF0Q5MTFkBJ8qDgcjn2nUQ4+fazZYBUCWgA2feujtGPk12u9KRQ
         JfI6+5l3qwhsVfnemF9H7IrsOrP+uMVdJD16l9qaoUpLzKnCsvjaKVNW0r2Lx4JCKynL
         uvBA==
X-Gm-Message-State: AOAM533ehk+oOFz1sq9AuBH75Nb0oKdQizHrorDf9kQGfDkWv8coGmiU
	0wlyEzVR7fwBnY5hLnp2r1A=
X-Google-Smtp-Source: ABdhPJx7NkimKXtmDjDMjeBhstWKegZwwFFm+6+5DlxcCDArLFa1Wyo+h5hHyX48ijdr4+9tW37M1w==
X-Received: by 2002:a05:6000:11c5:: with SMTP id i5mr4865467wrx.18.1600949475706;
        Thu, 24 Sep 2020 05:11:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80d7:: with SMTP id b206ls1426707wmd.1.canary-gmail;
 Thu, 24 Sep 2020 05:11:14 -0700 (PDT)
X-Received: by 2002:a1c:ed09:: with SMTP id l9mr4477149wmh.89.1600949474877;
        Thu, 24 Sep 2020 05:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600949474; cv=none;
        d=google.com; s=arc-20160816;
        b=RodsdN55jwKmxjYdd7g+beRp7bO+rjsLhrKlVJZW1yJQNlMpQEafqLxW9nh6emnY1p
         9H5x6Svph6A0lnn5Dambf19liMg8gXTCvNzJ9keGLqZ4aj5+A47vJo9taiRMDcPLYOsL
         3TACSNBYZkxBCWoDVdv1I7rq6x6WRx2dIAYvAvEBLlPDHTMR4lEYKt2MZyFqR/E/02em
         YY/YqppWgCY0wux/hAuO/mxpNVR4oK4oSgUjMk+Q9Bo4NR1V0b3k8i/ejLSx2vUX88Pz
         ekR3ifwXNUrSQuQIgHonPkpii/380N4aWH6DtZi7/z6SsJ15vHvw6xCrb/vbPnAIzgkr
         Y0ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TiwIu7mMni6DjsCfBHchRdA5CVaKLnFCdFVAp2ZYt6o=;
        b=tlQeS7aPQ+biF8nKxy6hU0i/WDBz+RYt+byTRvjkjzH760T8Ri9C/xfIanYC1KWpib
         5mwg7QZV660JDyGehx/trjGwuIhoslcNryXJvctuqysPwthRfizD+3N0fdD06Lz5bCJm
         5IWWD8b17pTY7NsQUECx0zQlqKJmj/GnBEnLGEFp1MCNe7P1CzCuZe7P4IIRbogNS5An
         Z+bYgxchq7w5s4vPTmuarE3jqHO8aXiRbOAW39NbsWmL7/CcgmIcbgL9i+MMp49wxayN
         hcrYbfXxEMjdVeXGOtiGptHLEFp/IrzAYeKtPZdu9iXZKC5qQfLYJnuhkw4ZePW0tr5P
         dO6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=amEBg3Sa;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id h2si318239wml.4.2020.09.24.05.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 05:11:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id y15so3368350wmi.0
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 05:11:14 -0700 (PDT)
X-Received: by 2002:a7b:c182:: with SMTP id y2mr4671696wmi.21.1600949474250;
 Thu, 24 Sep 2020 05:11:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200924040513.31051-1-walter-zh.wu@mediatek.com>
 <CAG_fn=W2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ@mail.gmail.com> <CANpmjNNmeqfMLZ0aFC49fHTYS5k7BqTZHP4FmDc=sfZe+j6bOg@mail.gmail.com>
In-Reply-To: <CANpmjNNmeqfMLZ0aFC49fHTYS5k7BqTZHP4FmDc=sfZe+j6bOg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 14:11:03 +0200
Message-ID: <CAG_fn=UFnju7qBw2FC8nGxTKQ5VB2QeG-DKik_t=eWzu6p+H6A@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] kasan: print timer and workqueue stack
To: Marco Elver <elver@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=amEBg3Sa;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 24, 2020 at 1:55 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 24 Sep 2020 at 13:47, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > On Thu, Sep 24, 2020 at 6:05 AM Walter Wu <walter-zh.wu@mediatek.com> w=
rote:
> > >
> > > The aux_stack[2] is reused to record the call_rcu() call stack,
> > > timer init call stack, and enqueuing work call stacks. So that
> > > we need to change the auxiliary stack title for common title,
> > > print them in KASAN report.
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Suggested-by: Marco Elver <elver@google.com>
> > > Acked-by: Marco Elver <elver@google.com>
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > ---
> > >
> > > v2:
> > > - Thanks for Marco suggestion.
> > > - We modify aux stack title name in KASAN report
> > >   in order to print call_rcu()/timer/workqueue stack.
> > >
> > > ---
> > >  mm/kasan/report.c | 4 ++--
> > >  1 file changed, 2 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 4f49fa6cd1aa..886809d0a8dd 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *=
cache, void *object,
> > >
> > >  #ifdef CONFIG_KASAN_GENERIC
> > >                 if (alloc_info->aux_stack[0]) {
> > > -                       pr_err("Last call_rcu():\n");
> > > +                       pr_err("Last potentially related work creatio=
n:\n");
> >
> > This doesn't have to be a work creation (expect more callers of
> > kasan_record_aux_stack() in the future), so maybe change the wording
> > here to "Last potentially related auxiliary stack"?
>
> I suggested "work creation" as it's the most precise for what it is
> used for now.

I see, then maybe my suggestion is premature.

> What other users do you have in mind in future that are not work creation=
?

I think saving stacks may help in any case where an object is reused
for a different purpose without reallocation.
SKBs, maybe?


--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUFnju7qBw2FC8nGxTKQ5VB2QeG-DKik_t%3DeWzu6p%2BH6A%40mail.=
gmail.com.
