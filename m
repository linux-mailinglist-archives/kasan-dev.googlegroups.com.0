Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYHURCKAMGQEZAEZL3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A6406528386
	for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 13:49:54 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id p18-20020aa78612000000b0050d1c170018sf6116726pfn.15
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 04:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652701793; cv=pass;
        d=google.com; s=arc-20160816;
        b=TUV2XPGJGIkPP16k8lXLavhlGbUYcRxmhVjo0sZRmTBuxAYef1Ks5ia3DG7EKDY/XC
         bIRRRJ2hZbx5g+QL5soeaUED+1HHOfujRu5iZ6SxMm98MlBpM/eJqkPDQtpt7NC5WvcZ
         Mtd/VxlDYflirzkuEWLx3swbzKKpM+93aQW4jTzsi8O8Sssgx9IEoqzK7I6vaWcrWpYN
         HdQX9fH5GXJsdpv2nOhcRHYWmJtZT+Qyg2HzXSZ94pCptAlw2kY76q9vyg9VSULNAVeC
         nD4C2hmEir4/Ky2lqLwvIxvZ9ECDqZTf3SXGBijJx8bGjgNUsmWi5Z6xOp8CrZOwKOvu
         daOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4dKiv/nTMmAI7HW4EFIcUlbiSPWJIH1WPvkZ6WwCM50=;
        b=T01oWp4wQkbb5C023dtyX300pkjAXKY3VtxFwAV40TXuQozg8U96tK8VNg/LK+B2q3
         3uBaGy9diW5T7IVDTBXlJga8dLdn8lO/fL8l+/SQQPuhTieZrUVAkaP8lo9E63xL4eCC
         cXK+Gky1sT9nlPg6nZkLE7IQs2IOhVNZK1Kak9u11pACBun/KAPOBFE16Jpw/eK2ZTE/
         5hP8RFdol3PGJMTggN4Mgxc2enkiTlHqzi0QNeGUGZJanDEHOQ40SPEvIty5O/KelWJF
         s4LRxVX4WwG3RYoIr6Jd1ImtXZML0XP20rZpe3iCCPeN1oO5fF68mPtRPMXo69OuuVQQ
         WuTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tR2WwLJQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=4dKiv/nTMmAI7HW4EFIcUlbiSPWJIH1WPvkZ6WwCM50=;
        b=MYUw6t4AYvU3LEjYbEkOQ5cBzw0TjUMoPVD79sm6B/SvTsPOY28ohx/dwxTNN0Bp8u
         jqOqEKdtHzY9KKYFo2RfqTNmRR72DUGZW23y246Gxa+zhKIWS9vJ0ggAUh66SVndmo8p
         DLn4Ybs7mZMTP7fTqfemCGa7L6jCDv4zvgGL7mxy4sDEkEF5sRdJ16xRxNc5NRGlOsYW
         gUrlQBxmvla7zicJTtl4EIPaWQeA/xp+v7obVVgXlU5vEazWwaFEjlwvQIb/OX00tuqv
         /RrKXRdFlVTsAmt/iDASBQiuj5vOw3bs/B98FnRSsSfOD9Df60Zeba6w/oyqUiuyeuXX
         g4HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4dKiv/nTMmAI7HW4EFIcUlbiSPWJIH1WPvkZ6WwCM50=;
        b=4gC0iPV+5DUF66LPSLY8S70fjJ2JPwJ5qoh0J68XDJludVtVE5/OSE+JDa6rjJfGPn
         OVhsI4zHErg49lHnKhz/Fu/7OAMXAKYnqxnFGONUjrvvsPEs577ZKKErxcZqhWTg4KvK
         dMlDE2J5g4b8u3YKT1ofW2aZ7jzQRwYDOj0/qDvwTZgomv+SDRYVUJQx67CpNHpE1WB2
         fa4W40oGOnKQxtRGQ/N59ymGGMtdjEwbx+lGyQ7uDi31sEVOc/HbngkHhqp/rRN1o0/3
         nGFysnasRaCYHuRedd9crjy3QecqyHALNpVsxoQ0kFzaGo9ad/T8612/azXJLZH+ToOa
         2Iuw==
X-Gm-Message-State: AOAM532V/e4iJLDVT6I39GU8oZP0g8+8snCWs9D6ghEuBHVR0M3+SiPX
	PrEYKjazGml5CuO+ItbcIIE=
X-Google-Smtp-Source: ABdhPJyOBBqnGLqk2ZLX0RxCDeJYoeWTG5RvgZ4RiRAD2kerkDYpKFZsUy6uphFelDNPirWRvEMb6Q==
X-Received: by 2002:a05:6a00:e8e:b0:4fa:a52f:59cf with SMTP id bo14-20020a056a000e8e00b004faa52f59cfmr17073084pfb.84.1652701793101;
        Mon, 16 May 2022 04:49:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f249:0:b0:39e:17ca:8abd with SMTP id d9-20020a63f249000000b0039e17ca8abdls4188280pgk.7.gmail;
 Mon, 16 May 2022 04:49:52 -0700 (PDT)
X-Received: by 2002:a62:b60f:0:b0:508:2a61:2c8b with SMTP id j15-20020a62b60f000000b005082a612c8bmr17046596pff.2.1652701792441;
        Mon, 16 May 2022 04:49:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652701792; cv=none;
        d=google.com; s=arc-20160816;
        b=dR50bmG+8URLhRRPN1hAN3611Opb3CUEKBZdhJqSKS71bSuHP6TJgkPsdtuqwNN8+B
         dC+1/+baYwm84beQQnrJOTIa3Ugd90HgnECORoR5GSE4YEneqwuwXcBoGmAZ6PRRBrfN
         gKuxxvPXi4azQ9MalxIp2gWOMrYTHhCyO399wU+lUzoCmdgcErw9X+ENoEj+fYn2Vxp8
         UEWfJOO7r1lWWUxytbH12Gz+UxfgnYcEbZXKHssdkId6gHWAmjH+zdIvGFvX7njnSL7c
         Ma/9WgV3kPfTjYgQdc3n9ryApBxPgUhKZkTC7jtzfKEEQrksF5ynUQ8ORkAAuEZnRTEb
         2C/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4XtkkgDY70ODUGHGl87xJIvARSTddMeTRl5MzriSEag=;
        b=mPY7kWKtMKF4uqMzscO0uE2/Mo0nMAFtrSf7/ywv6mHUwJ+jHBzF4m6RCmyjxGmJJd
         J9knLgGfZJjUcWwRdRrxM0QFC8oZ9Z1AidBgQc5NJYDKvPtwsO5KKyqSIQt62xemNQY7
         XSUEW2vIjFvxqiC9s/PfnNKAb0jMJsi6ImT27hZmDZ5w1ZruWoTjbU7YqlwhxLalUhx6
         jdWyHMKSbnoFfBxEJamcbUXFuBLCUlctJdRiy8C/8QLVgR0gWs9TDsOE8rf5WQ0Kr7SM
         py9M4K9X4mrQIiKO9WmaKpCGU0z0g9aebrXa6VBv2YcbmzmCdmoLa3OjIydYaQOP8lRZ
         WpYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tR2WwLJQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id p22-20020a1709027ed600b00156542d2ad3si567353plb.5.2022.05.16.04.49.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 May 2022 04:49:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-2ebf4b91212so149566617b3.8
        for <kasan-dev@googlegroups.com>; Mon, 16 May 2022 04:49:52 -0700 (PDT)
X-Received: by 2002:a0d:f0c3:0:b0:2f4:d291:9dde with SMTP id
 z186-20020a0df0c3000000b002f4d2919ddemr19141054ywe.437.1652701791936; Mon, 16
 May 2022 04:49:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-28-glider@google.com>
 <87bkwmy7t4.ffs@tglx>
In-Reply-To: <87bkwmy7t4.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 May 2022 13:49:16 +0200
Message-ID: <CAG_fn=WhNZ8+7RXvr_2nGa-mCpLYxBK=cw3wFg6bxOqgXTOH0A@mail.gmail.com>
Subject: Re: [PATCH v3 27/46] kmsan: instrumentation.h: add instrumentation_begin_with_regs()
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tR2WwLJQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134
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

On Wed, Apr 27, 2022 at 3:28 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Tue, Apr 26 2022 at 18:42, Alexander Potapenko wrote:
> > +void kmsan_instrumentation_begin(struct pt_regs *regs)
> > +{
> > +     struct kmsan_context_state *state =3D &kmsan_get_context()->cstat=
e;
> > +
> > +     if (state)
> > +             __memset(state, 0, sizeof(struct kmsan_context_state));
>
>   sizeof(*state) please
>
> > +     if (!kmsan_enabled || !regs)
> > +             return;
>
> Why has state to be cleared when kmsan is not enabled and how do you end =
up
> with regs =3D=3D NULL here?
>
> Thanks,
>
>         tglx
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/87bkwmy7t4.ffs%40tglx.

As discussed in another thread, I'll be dropping this patch in favor
of the new kmsan_unpoison_entry_regs().

I'll also ensure I consistently use sizeof(*pointer) where applicable.

Regarding regs=3D=3DNULL, this is actually not a thing.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWhNZ8%2B7RXvr_2nGa-mCpLYxBK%3Dcw3wFg6bxOqgXTOH0A%40mail.=
gmail.com.
