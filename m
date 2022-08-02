Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTWGUWLQMGQE73M37KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 875DD58814F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 19:47:59 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id q29-20020a4a301d000000b0043564a5afc3sf6881691oof.14
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 10:47:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659462478; cv=pass;
        d=google.com; s=arc-20160816;
        b=j8pdBiILV7jbVVIP6NIn8VfI2FB9yhDMU+2/5WA/PAUq+VM7x3sbD7t9Rc5rxL48xY
         i3o11jlk2SiAOLfgSMKE2c6/0jexYz5KVda++8yaJabm62cB0iemBOlHepSLygeWEm5X
         AuFKmVLKBOAHLVuNwM0n/PGudMcsijTrAeP+9EfWdx1UHvtnWM7QDtSafrhlZc7Sh7EI
         bS5neOUqrcXiQXcN1CnTX7gdo+iIUSiuHfKSYZwyGaBTljqvOXNa6fkxqO8A/xJpReFK
         l6lhEqkyLpqqyFW3zQycGQQgytsTouKnYsDIdwIaBWfYOuCZaM2lliUqBg5u/M2yqcVW
         NnPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aN8giZGPY7N4KT6xbfI4ksOuI5bRUMbgkDo0wNPrHG8=;
        b=jnW9k84jnlYEREm+zNC0cZKm4NAAHmJ+M5IczksJSdzct33aXjk1Q8ltl/wH0vJlyj
         skHrJexCjp0mBS6znMd3U1C7pHuVa0E2eXVjhgo7vmNvIj1tbmV9VdrFCvkHy2AbnMqp
         xqUK6zblCGUkLJ9X9NN5ZVKBklQzQaFGYFSDYJV2Yk2llXItrvVHHJIBC1HicCkj24rN
         imzjQC/GkFEbcH7q/Rdcr6hP0oyVZogcjm+jnx78X74Zmdn3H+bD0CUXBlxwoUbHLmSC
         4uFRdZ0WTf0/47CabGbQD6ihXT9l2FjJsf5vtmON09sZsVCjIXZgWG5M0L47qmEzoZrG
         +IEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Vi4b18H4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aN8giZGPY7N4KT6xbfI4ksOuI5bRUMbgkDo0wNPrHG8=;
        b=TKAxLM748sEjUkw2h+woPIhcgbjZMCVSPcyIqojaLyUYE193fCAUmJRYDh8EteasUY
         QdlbW8t/PjgPm3vJ1BKui6+mKsgWqXHhN7Mq204BttSPYeHHo7ePxe7f2tRql6q2cQMI
         CgXjzg29Q2aIWtJVsvZF/gCzHzzhsRov9K5T114ZSUF2GGeTEHlAhphYAinGikLovfJr
         u68jVEXeyyRmYfhLMSXtQ0e1yqLTxT/mu0SouKwnqP981XeLfQuoAdn2EmjMcU0gb4LU
         xC2OX7dDLrIW337OMk2rakyLo/Qlho+G9m6jM3C04j9pn1kafbUGSEAv8AFcIC742sqP
         bJyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aN8giZGPY7N4KT6xbfI4ksOuI5bRUMbgkDo0wNPrHG8=;
        b=rfRYysMpJyyYpodTRRQa2HF9QmuSGq7/IpK4wLo65goRon8HHs7sJLBD16nqMhJmsf
         AMpXdkhRUk9tDfZ+j8C0khO4i2iOCSJasDw8y8D1FMu87t8Likuf2YzYVRLAsLOmU4JT
         9gxe+A1TRr4IfQfHYSMC9AEC2v54tfsi5S/yJYUcQaoBhId5cE2hm1NOTOXJ8MpWOYnt
         0iuUi3xFCWQiVLzVnBey+lVMky/SiQeyDrbjL8TgJJwbuKj2R6j9JIHT+firiZECi+Ac
         hwxJ/s3UbTXPytggcg19uE69IqeEHifrQKY8pEaRB/Toi9S9X4srkFR6nreLDktFczMB
         9jeg==
X-Gm-Message-State: AJIora/KiIDADiCahAtvtP39A8JgAl75T9GEcjWRI869WMQWzQRc8o5W
	EEi7KAaMsNXsll1ZvlktmjA=
X-Google-Smtp-Source: AGRyM1uKk11ygopp13rXAkc61GbGxqaq2098ZIwjcW26JqW3SE+ThjFB8AsCdEKWnwJgWxJ+cigiLg==
X-Received: by 2002:a9d:6e83:0:b0:61c:f67c:556 with SMTP id a3-20020a9d6e83000000b0061cf67c0556mr8090753otr.221.1659462478429;
        Tue, 02 Aug 2022 10:47:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1992:b0:342:6547:bf34 with SMTP id
 bj18-20020a056808199200b003426547bf34ls666059oib.2.-pod-prod-gmail; Tue, 02
 Aug 2022 10:47:58 -0700 (PDT)
X-Received: by 2002:a05:6808:1385:b0:33b:1552:1765 with SMTP id c5-20020a056808138500b0033b15521765mr248215oiw.159.1659462478090;
        Tue, 02 Aug 2022 10:47:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659462478; cv=none;
        d=google.com; s=arc-20160816;
        b=UskWCsPrDiaQUU2A9UwHsWvEylUkRdAfmNxVaLsxNVuN2RRSPVsW+mtHo9HNWRYacP
         1/ZpWjFmjp3O/MeUAlcL2+IvSoiidAE+ySuV+Y9qIlWA6aheRZNPDKnh6uLmXOCdrRzm
         ZRfG52lAazMRVzHq94p/iexvFmDz6qU1rT9tZC2YrHURDVJKxFXA/9t5iJ8f19jhf203
         +DQlWYKPf5iXpbUgS4eBpwCYTJQpn69pYMue4SPnJp5ZKQVb4fXJfUvTChHa4VI0ThVU
         Bp5m+WT3+zUDa47MKaXlF79UaIXLsUJ+OWue6wGk5dYJwtp9JCMKiQ3isV3Qqo3xfXWA
         +6sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CyPUbDaavl0pxtUchWqOoJ+rGYNrTSx7Qsh7yOX4nqk=;
        b=rzCnnL7potI+BjWzBnX7pXFYRiq0afn9mJDmznn8e93K1577TkA2ZMqFrm2/5o4lTv
         GLNdGVbBuL7E86GKHv/AxO3szN9zx2mxMqrbEdu9BRTTrTx2e6GE2aBb/JjYzWOuNWYQ
         PH6dMBTFtWERSSqF62nMcBNTytMUg4Xs3UfMqWJc9Ltc46rZq8yrafQWKSAxoBk21kna
         x8ZekoadtStDKhaVBWLGQ71sFvyZPc0X6gCtPt5ZITuZq0w0pqUcdBbl2kXO6Xg/gA+9
         T8GS9mjIfFCuAFwC9Ro2yNXmVK99pKxHoal8lv2NE1Iior3lvVZMqZFmcOpDGchgZfEs
         Tm1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Vi4b18H4;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id q19-20020a056830233300b0061c67f83202si577424otg.3.2022.08.02.10.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 10:47:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-324293f1414so113857547b3.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 10:47:58 -0700 (PDT)
X-Received: by 2002:a81:5ca:0:b0:31f:38d6:f59f with SMTP id
 193-20020a8105ca000000b0031f38d6f59fmr18721968ywf.324.1659462477479; Tue, 02
 Aug 2022 10:47:57 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-30-glider@google.com>
 <Ys6c/JYJlQjIfZtH@elver.google.com>
In-Reply-To: <Ys6c/JYJlQjIfZtH@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 19:47:21 +0200
Message-ID: <CAG_fn=V_0Jw_mKpj0P5-hUeCUZZzC2u1LCD8Nvp8FvCy_x=wqg@mail.gmail.com>
Subject: Re: [PATCH v4 29/45] block: kmsan: skip bio block merging logic for KMSAN
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Vi4b18H4;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jul 13, 2022 at 12:23 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Jul 01, 2022 at 04:22PM +0200, 'Alexander Potapenko' via kasan-de=
v wrote:
> [...]
> > --- a/block/bio.c
> > +++ b/block/bio.c
> > @@ -867,6 +867,8 @@ static inline bool page_is_mergeable(const struct b=
io_vec *bv,
> >               return false;
> >
> >       *same_page =3D ((vec_end_addr & PAGE_MASK) =3D=3D page_addr);
> > +     if (!*same_page && IS_ENABLED(CONFIG_KMSAN))
> > +             return false;
> >       if (*same_page)
> >               return true;
>
>         if (*same_page)
>                 return true;
>         else if (IS_ENABLED(CONFIG_KMSAN))
>                 return false;
>
Done.
> >       return (bv->bv_page + bv_end / PAGE_SIZE) =3D=3D (page + off / PA=
GE_SIZE);



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV_0Jw_mKpj0P5-hUeCUZZzC2u1LCD8Nvp8FvCy_x%3Dwqg%40mail.gm=
ail.com.
