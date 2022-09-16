Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMP4SCMQMGQEEQTKOGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id B06115BA914
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Sep 2022 11:13:22 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-348608c1cd3sf186658627b3.10
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Sep 2022 02:13:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663319601; cv=pass;
        d=google.com; s=arc-20160816;
        b=tzkuMKEOBga7uV+/j/81Lu1RNyTLpgdUKolv1IoPa9Uorxj4QAVcHVNJ3K0sy1XBUo
         3/JIFOTo3d1B/8bMaQHFbPX2dnLjs6PXs9pn8KTTvLyVoWJJIhlsSOH0O1YpWWHgDEKb
         flRk6lRcyRbk8jIqC96iSON8zmIhzxRfjf1M3AkGukmGkM+Q8KCfMJjw98J/72wMRs/s
         q6ZepGrZJZSahgxjh2b0eJVnkWzs88WZlI6XKliRnBDVDdYVXE8x7qYAtljbd9MmvgKE
         6kGyCNRlqNakt7IPn3dz9xt6LUOOGuT4iSOcVyJtUM/wZAMd1XovlRNEmK1XyJzgYht9
         DlTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+byV5uSSbwNlJmWVvzpiN6gMiZKlklIas4cUCtiPprU=;
        b=IUmxjyAbmCJtbsUe9gMKy0DaMX/OiNoA3drChtYZ94CiyS+v3Ue8V+WCGrNWrX/R7K
         tOgOmkA8Qg/BEZvyRfTRw53HebwlLNvf6HSrMT16EgCyRuGBePs779f1b08aodZ9l1/r
         LGwInwoXQPTezpU014SA/8vD+az6z5eiS6001wPdB7usCOTLdpCYob2ufw7leSzpGKeP
         ND1jJbLJ7+JAgklykGyO7uCv1V1QX6QSVHGGbJvQbFvn8n1+lpjNPkWvsJroGGvNHVov
         9stmtUxZ7zeN+hMA533h55PmeoQpKuoaM5+W7xhSQactuWxGBC6iyokIGbs+9rutDIjH
         yWiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tq8+3NsA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date;
        bh=+byV5uSSbwNlJmWVvzpiN6gMiZKlklIas4cUCtiPprU=;
        b=PGr/0tmNuZjnB4W1nZEQ1vTVA+YGYOaJ1vWpbCCecitk3OigtWcg9l7tJzf3Ybjaca
         7vJv6MCEjYFiVmc4yl3kwN2U/5v/TOiKscJhJgTKLH2+RYJR+oKxYZwUJPNG8jUiV+S/
         gIK6Izu/5O1WJCFRLx54GffylqK8RkZxFW0U3jRiTqCTcyInX2G2a0zOxredAqoTrvHo
         5IcyqUQxJrbD8rX2O9oEoHvGZO2r48+7Ovam6m993btB8c0QfJveAETKyIlBsts43zd7
         pQA+iXFB8HpZKyIB3jeO7CWssj9txoZp4CHTCWss52QCmaXe8VVxj9v2san5S9GwSxZe
         QQGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date;
        bh=+byV5uSSbwNlJmWVvzpiN6gMiZKlklIas4cUCtiPprU=;
        b=N5JS+bTNUB3m6pL0BeN6LGddnOMrbI5HG/Vm1vg0Q2PeDBTEgqn96F7qgBrY3hPh8Y
         St6yNiRvYRVowT0Ucv2ysp1lE3lC5dHyoNc3xnlXU5THMhKQVBgBhwvd2YpNkR6qnuv8
         dvMunSen4qbLKlO4Eq93blJKZ6RrTklTwHmYdehXnF3NKcd8bwG40dM24PimRKqErUb/
         RwPAG55GnofWH+iJvepS9clBRfBpJgkdFlqm6Xiz6TezNJhMdj4EU1o/v4wCed82rY2K
         TTtyUBo0ANjt08CtrY/bVRwvsRVTBQUIbOlopdkCVjaUrh7Vta7Apk91l+Zkt9uJ47Ow
         pPdA==
X-Gm-Message-State: ACrzQf3oGJxRyxd0pe+d7wiEF+pwavqNNBzWzDBsscJ1Kb9k32DtQDnG
	lQABxoYonKr0aV+O9pWTRhw=
X-Google-Smtp-Source: AMsMyM6URcRxMwwf1AnBKxi31ztMKwbXbfERnggDSEJ5SPka2SZOXxLGI7eegqym81Q6L1zSWaUUPA==
X-Received: by 2002:a81:13d7:0:b0:324:7dcb:8d26 with SMTP id 206-20020a8113d7000000b003247dcb8d26mr3626887ywt.452.1663319601549;
        Fri, 16 Sep 2022 02:13:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa32:0:b0:6b0:3560:d21f with SMTP id s47-20020a25aa32000000b006b03560d21fls2701987ybi.0.-pod-prod-gmail;
 Fri, 16 Sep 2022 02:13:21 -0700 (PDT)
X-Received: by 2002:a25:40c7:0:b0:6af:ee2:25aa with SMTP id n190-20020a2540c7000000b006af0ee225aamr3512238yba.326.1663319600996;
        Fri, 16 Sep 2022 02:13:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663319600; cv=none;
        d=google.com; s=arc-20160816;
        b=cA1o5A1rpAOPZ73bnEZZyBc46TXF9X1BYkoN93r+06DpvUwvgZ/ud67S9FYucj4udv
         T/eNQ0Cf1AZ08a4Tz/oQHC1M9Ws9o3NZSsQSyEZGRzCi6mISx/iHBaj9jkf+E0EBmInq
         5oZLkAyvV3Z7bWflQThIZJUqpyAWk5Q5t2b4NX53jL2s/z4ggwab75g013r3NadwBWZO
         AuSN/rWdCEVCcSTqA7k30vDSm16IFnOLhmiVn3G1gPAm+DblpUqAKYtvACYY7q71AwAj
         j+MPia75z/EmCN0kdLF8PqxXkiL7AfldyhJ1hUGAvkP/qlF+Q4g7kbYTrZbcgWZy/8XK
         m0sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=St+IQCWJacJKbPUwjmk2zZiPvZUfUUJhCu0g3DwZrPg=;
        b=OKrSKZr5Y0oXuukuRxeNBFVop5SiSuTY6GhZvlfi5DhKGonzPMK1MoK5y/BpQaIRSR
         OU7xK0QnA709puyGFsfs9KuEKpMN13VpvAqzdiTTXsi1GaTp5akq6y4MdqHLPojiGh1S
         P4r1Lo+QJh0gOhU/JI3GtjEUnOl/zT1gaubFoWjMMFpT/Up0T2r66yyYQvpbApVDDRXt
         2skUMCddXyo9FW8LCSZw2li3zOxnXsVxWE2/yZLIGfrbdi6RVr8Ld9gVcHBLFVLrQBMX
         XY1SQXYpyoAoOcMUsqWbcDTV5blLzUmPF//ybnR4WlNeUC3sMNnSmjxD4avrKaorReQh
         LN7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tq8+3NsA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id l77-20020a25cc50000000b006b017518025si241053ybf.4.2022.09.16.02.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Sep 2022 02:13:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-3378303138bso252110847b3.9
        for <kasan-dev@googlegroups.com>; Fri, 16 Sep 2022 02:13:20 -0700 (PDT)
X-Received: by 2002:a81:1409:0:b0:349:e8bb:1fdb with SMTP id
 9-20020a811409000000b00349e8bb1fdbmr3573010ywu.299.1663319600558; Fri, 16 Sep
 2022 02:13:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-1-glider@google.com> <20220915150417.722975-28-glider@google.com>
 <20220915135838.8ad6df0363ccbd671d9641a1@linux-foundation.org>
In-Reply-To: <20220915135838.8ad6df0363ccbd671d9641a1@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Sep 2022 11:12:44 +0200
Message-ID: <CAG_fn=WJZBK_xypJ-D7NPjGeaQ8c3fs8Ji+-j+=O=9neZjTUBw@mail.gmail.com>
Subject: Re: [PATCH v7 27/43] kmsan: disable physical page merging in biovec
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Tq8+3NsA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c
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

On Thu, Sep 15, 2022 at 10:58 PM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Thu, 15 Sep 2022 17:04:01 +0200 Alexander Potapenko <glider@google.com=
> wrote:
>
> > KMSAN metadata for adjacent physical pages may not be adjacent,
> > therefore accessing such pages together may lead to metadata
> > corruption.
> > We disable merging pages in biovec to prevent such corruptions.
> >
> > ...
> >
> > --- a/block/blk.h
> > +++ b/block/blk.h
> > @@ -88,6 +88,13 @@ static inline bool biovec_phys_mergeable(struct requ=
est_queue *q,
> >       phys_addr_t addr1 =3D page_to_phys(vec1->bv_page) + vec1->bv_offs=
et;
> >       phys_addr_t addr2 =3D page_to_phys(vec2->bv_page) + vec2->bv_offs=
et;
> >
> > +     /*
> > +      * Merging adjacent physical pages may not work correctly under K=
MSAN
> > +      * if their metadata pages aren't adjacent. Just disable merging.
> > +      */
> > +     if (IS_ENABLED(CONFIG_KMSAN))
> > +             return false;
> > +
> >       if (addr1 + vec1->bv_len !=3D addr2)
> >               return false;
> >       if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_pag=
e))
>
> What are the runtime effects of this?  In other words, how much
> slowdown is this likely to cause in a reasonable worst-case?

To be honest, I have no idea. KMSAN already introduces a lot of
runtime overhead to every memory access, it's unlikely that disabling
some filesystem optimization will add anything on top of that.
Anyway, KMSAN is a debugging tool that is not supposed to be used in
production (there's a big boot-time warning about that now :) )

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
kasan-dev/CAG_fn%3DWJZBK_xypJ-D7NPjGeaQ8c3fs8Ji%2B-j%2B%3DO%3D9neZjTUBw%40m=
ail.gmail.com.
