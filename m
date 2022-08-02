Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNEIU2LQMGQE7RLM5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id D45E75882F1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 22:08:21 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id i16-20020a17090adc1000b001f4e121847esf3450024pjv.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 13:08:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659470900; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7jKd4DHZS+EpcvNV5cgnOFLYDSvDll8zxPzcy7PZw8oYrfgM3WCmHyE/7HNiRXoyn
         C2eaPAtaYsEWVR2bxPLWkMwM/tpg+GHiUpRnSviOyISywcODURn7O/yZ+4l2WIu9hUOr
         loSCrIj7XuaKaxbS6D9WoyX3owZxWueBbiR64gJGBXk0VRd+VOWI6ciW691JZUeMPZe7
         BfNN2IpxqX9baYK1sA8nR02CZp+iFGtxbypWN0XsOlhqv291N6/cHW+QSkl1rZxYLUp9
         YqqzeEgZEUcvF0LnGD+ULkP8T+rGFVUrF/Ks7oIzSGtCnVCiuJgIBB9qAB79trjeR6Tm
         DJdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jSGcIw8qU0gOdvWo/SpzxJdUD8CeqbQh0FWmdVMoqds=;
        b=urxtp0nhE98Od0pcGp2LmE/Uab5YrdoxWs8d0KsVmSpYg8ANEz9FKj0lh2dKNpOLez
         rpMmiKmZ+WauqEaArOLDzxxrvjrDGYYhRMxv1MUkNuO/TwpK2NXSnAdpjHfnXPaOxPYd
         AFXeF6pivWIeeorAxlLtOQjpPOHX2I3B/y7tbkj9SB+5ECPAcg2atFenYaYyq9JNg32o
         uOxLOm3BHJO/J2JZyAT/oNddVxe1mgkq5FitKtoaFq7MEQvcknvSr6nbQnv3AvfjWhA4
         W0ZBYpL/yJpOVKfMMV0/Thcto9a5SgMt/Ocmp4FM+Hqv+JOLzSBhTJ1STF89+JMjUtYm
         2S1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jpPabckj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jSGcIw8qU0gOdvWo/SpzxJdUD8CeqbQh0FWmdVMoqds=;
        b=dnG3G5lqshHgVXJuKrwa1IE4GGFw/zXoGG47syWOkwHBiLofNVPOgHUb/2Wgh+G5xn
         gtPPTg7IRatM4IiLErbDEkeKxTHLwjWuO6YeZBYutcLxVUOhJnRVZ9qQlua22LzeWBk7
         Q5YAUoTEzIsbH2nMPYXmTPgTozz7jIuiOK13n6RXls1MGlKiBzZNGy9XMII/8WMcVCXD
         J2TqdJY5a+MYzWF7XIYcd4570IqCSK/zsDgWBjfYHLqiM8vdRIwx0Hwkv/8m4HLeX/mh
         o3sjh9Cj7R1g7+8gpDquGqNUuN4FjBBc/mFjPXv+VkX78OZKtPgl+/z5qMrklGJCnGJS
         97bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jSGcIw8qU0gOdvWo/SpzxJdUD8CeqbQh0FWmdVMoqds=;
        b=weQGGWebjj3UkyrLqfoNWVtB6SErsabdOTNW9ZngZe/TnS7+GyPhd64stS+fq6jq/q
         0NszirWLEyav8ZBJrHmJwQL6M/Kk9lxJ797Of00TxHa2qX5sUkHlu9vCQc6qa5Nevx+i
         ge7/49Dx91SB92cSl+7QIS8SVEZ8LMR2iuQzqDxMCnEfdEVsW0QYx9nCQhxNTcYdDxqe
         LUTyIA6z9N8gl2Ji+AuFK1tvKVPgl24JecC+6aUmTyPwDen2PoUM/8xDul6vyLQ1AvbX
         oMyuezqsASRkhxzUJj+RxwTVxXYhOGtTSrBcnVpuKTALmmrQY+juLLrR8aXkvn9z6HOp
         Z+4Q==
X-Gm-Message-State: ACgBeo049oPhBqhHhlOXmoHJcRQxrQWcjYhCwCGGbA/t28rTJnghd/s9
	+JtA/IdNVBq8NYcfeBoHIq4=
X-Google-Smtp-Source: AA6agR4BtfQbvw9h9sjhcQ8j7BtPluM0QXRBs/kOycDlaBnN3F3LGm8Vix00t5o9E/vb6F0zD8XJKQ==
X-Received: by 2002:a05:6a00:2386:b0:52d:7472:208 with SMTP id f6-20020a056a00238600b0052d74720208mr11286426pfc.8.1659470900293;
        Tue, 02 Aug 2022 13:08:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a15:b0:1f4:df71:aa14 with SMTP id
 w21-20020a17090a8a1500b001f4df71aa14ls6068781pjn.0.-pod-control-gmail; Tue,
 02 Aug 2022 13:08:19 -0700 (PDT)
X-Received: by 2002:a17:90b:3947:b0:1f5:104:f8cd with SMTP id oe7-20020a17090b394700b001f50104f8cdmr1175213pjb.26.1659470899581;
        Tue, 02 Aug 2022 13:08:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659470899; cv=none;
        d=google.com; s=arc-20160816;
        b=aHhc0w7Vp35/lHB4zEth8Sg2syvS8HAMtFGSDEIjO7sHW+ZpbzvNNdNikidOV5/oyz
         117vvD7bxxv3IPDYwl0VZy+DkupL5loyEuqP6HtJTUvC6LHuT1aTTjNTIVqx4kYFBQ1S
         1o7odKj/dYAu+E/lrT7ahyaAWizMDnOAHFSbpe4FrVDOGuWIZ1+zzpOgotMweKx7HHzB
         tL/CQjssSKFTxiFce+0Az6vOhs/7BH82Py7rpFdQMYSeD3MLfq9YeN6LhmhJC2Gp3qIF
         d/O+wx8Cf0nijz/l+o42zqu+0ZHMPwQT6zuuQkeyidwE1zE8A0amcAtF7i4ntrJSaBq4
         vPgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0+45JLGnZfMHQQnDGOsiLF2twVwamYBrdFCbJu2NgIA=;
        b=CgS7bzYp9wO2rtU6PAdwjdDOpLQq0Yk5aKgF+y9Ucpk1KXJLXr+NldjnnR7qfs9htS
         c9qtr+zpiSwxQsGualT6MdK8NtGqBVDFBWVoGcx2wSLZhi2JyL7N0gypZUIKreDs9zO/
         LydRT37ciqPy7/pCBvRNyvbO6kFrggtXsahxW4UaCuW34LjxlIzXS6+Wquz16XMiaTqq
         Gw+RU+NXwJck+hg6p/xVKCy6jSqAMtgQgixm48Ata+HPNTdYXwLUhAB8r1vDeOPVUZqG
         E7KLMrHkRDbCp/Vy8SWBm3oLegIVLBAG55LZTLncmgd0KKx+Q3qBiOaASDiUykuYEqzM
         RG+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jpPabckj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id a14-20020a621a0e000000b0052e0354e5c0si41684pfa.2.2022.08.02.13.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 13:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 204so24088978yba.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 13:08:19 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr16344277ybl.376.1659470898706; Tue, 02
 Aug 2022 13:08:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-18-glider@google.com>
 <CANpmjNNh0SP53s0kg_Lj2HUVnY_9k_grm==q4w6Bbq4hLmKtHA@mail.gmail.com>
In-Reply-To: <CANpmjNNh0SP53s0kg_Lj2HUVnY_9k_grm==q4w6Bbq4hLmKtHA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 22:07:42 +0200
Message-ID: <CAG_fn=ViHiYCWj0jmm1R=gSX0880-rQ-CA3VaEjiLnGkDN1G4w@mail.gmail.com>
Subject: Re: [PATCH v4 17/45] init: kmsan: call KMSAN initialization routines
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
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jpPabckj;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as
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

On Tue, Jul 12, 2022 at 4:05 PM Marco Elver <elver@google.com> wrote:
>

> > +/**
> > + * kmsan_task_exit() - Notify KMSAN that a task has exited.
> > + * @task: task about to finish.
> > + */
> > +void kmsan_task_exit(struct task_struct *task);
>
> Something went wrong with patch shuffling here I think,
> kmsan_task_create + kmsan_task_exit decls are duplicated by this
> patch.
Right, I've messed it up. Will fix.

> > +
> > +struct page_pair {
>
> 'struct shadow_origin_pages' for a more descriptive name?
How about "metadata_page_pair"?

> > + * At the very end there may be leftover blocks in held_back[]. They a=
re
> > + * collected later by kmsan_memblock_discard().
> > + */
> > +bool kmsan_memblock_free_pages(struct page *page, unsigned int order)
> > +{
> > +       struct page *shadow, *origin;
>
> Can this just be 'struct page_pair'?

Not sure this is worth it. We'll save one line by assigning this
struct to held_back[order], but the call to kmsan_setup_meta() will
become more verbose.
(and passing a struct page_pair to kmsan_setup_meta() looks excessive).


> > +                     struct page *origin, int order)
> > +{
> > +       int i;
> > +
> > +       for (i =3D 0; i < (1 << order); i++) {
>
> Noticed this in many places, but we can just make these "for (int i =3D..=
" now.
Fixed here and all over the runtime.

> > @@ -1731,6 +1731,9 @@ void __init memblock_free_pages(struct page *page=
, unsigned long pfn,
> >  {
> >         if (early_page_uninitialised(pfn))
> >                 return;
> > +       if (!kmsan_memblock_free_pages(page, order))
> > +               /* KMSAN will take care of these pages. */
> > +               return;
>
> Add {} because the then-statement is not right below the if.

Done.

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
kasan-dev/CAG_fn%3DViHiYCWj0jmm1R%3DgSX0880-rQ-CA3VaEjiLnGkDN1G4w%40mail.gm=
ail.com.
