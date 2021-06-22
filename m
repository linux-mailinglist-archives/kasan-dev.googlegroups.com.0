Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEFY6DAMGQEK2QPQVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 65A0F3B021D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 12:59:37 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id v142-20020acaac940000b02901f80189ca30sf12427715oie.22
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 03:59:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624359576; cv=pass;
        d=google.com; s=arc-20160816;
        b=SqbMetWhLxaau76emoKmtlRVN+vStYzIMMtFCx/DwSRfBgxZhoYAFYh3XQti9Kld38
         OrWaKQVhJc5LMU/F6LtkB/oH8MfCFqpxpc0LioTO8Xzr/eqX/pO9u6cMJss3Hm6+KFp/
         oDqKOgO2bRaw4C8sPvk1VH+FOjZ1Zh7SCemoaxwArdBvNTdi4nClLcgkKBJk4w8AD61Q
         fA/vKbsAxLGkaEMquPqzS7MhuVj5VnRZb0I71R4ixfuMMobfTaZUn5h+ett1bKxTsj4y
         1uPyPvbBzijo5gUXbOiNz+fBjsKHtCi3PiogOhkanbP2IZprtp6yI44eHr6MW8oU8Ajd
         vGpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GgdJoZzM44nyZ3W98/EMi3BQ5bDRsEaxXM8fOhr+DzM=;
        b=XyPjy+Q0tfKqr/TPJvNUdNdxtJKFudaMDb5qfShDON3vI6jXxQ+H9n9ea4YlKQbc7e
         sdWm5sayPfbkcv7tHo53c+gtpTj8tumcvhIrCEzxm26I4+gmUFkusAT/GVVpZ+DCS7D4
         c4RY5R6oeSN/dgCjR1oK5v6yTzjPAc1ghrgeefN0/iAO0aoaPfCNk94ztlguS4PSevIU
         rIXibvt9kgof9Sh+x63aLbyfcpOOfgn305eHX1RnNSnKgg5FPX+xIF3fw9AWsow4vgNk
         jqF6MiMBQy+yGvqNJvnPXmo9C6gKIXzamRcNb1vTqZbv+iHXszENtbRx1+fy74iD2hVE
         sjyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nj20QEq+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GgdJoZzM44nyZ3W98/EMi3BQ5bDRsEaxXM8fOhr+DzM=;
        b=TA+cFI6D1kwJz3mV1Dz9REQwFIqrLy83moOue3Q/yaVEc4nRuN9Nu+4VzZFF/4R6HQ
         6GAtgZ6edYMCtQNAboqUoFlnkIJ6crA3yHETmeIclF9VIIm3ghWWqXoIyNiW2KKIU8Jm
         4imW6j3X1bwfczQslh7+XqVQsWvIsH6cg32SHlD4LjXT+sX3jR0tHyNKvvFX+qqA9lCg
         Yzs0QuPCMSIWwhNgyZnEqshIzijF34lJMa8L65XTzHYXwhRRKk1L3L1ypOdUiXw9vRsH
         nWDIxVJeCtBefYedZjUGp0LCLTZeXtbXyojV5CHIMjwEtOW4zmi3aXPAEtA9sOypxdmr
         ct5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GgdJoZzM44nyZ3W98/EMi3BQ5bDRsEaxXM8fOhr+DzM=;
        b=Ji8n4oZL6SGPmVA8/m/ajJdYE3J70TeGwCtWX9jxWdCU2XGl9oOJSgvB5YZMfqzKEx
         zNh9rXgcBXXH44H/C7lkkOcWW3gRiK0P1e9azBqDftu7Dx0ZoTExnereerak0zWl943q
         3PXKfCNSl039SgpC8qRv1yxpqkF7P+T8pYf1BYFgMWC8T4Kvf2zvSNqanSSTwWljnT8h
         lw6VA9hDYnINTGAokh7qyWOpdpd7NH1QPwLK8FQlkaBjt6TgcG0rgtMqw0jhBZ8FgxDs
         XUcDj5+I4TMGvI+umQZcHDxTT1WVBTzEIATqSNAczNYi4CG34QH/XqfwSdnCVLOdn/Sr
         UfDQ==
X-Gm-Message-State: AOAM5302brPfK2KTpq0Jtfe/CnK9jpWmcbTW7+ZspSLtq6zTJsxk8qbo
	xZt+m/4y8tBYzzSYzbvVLEw=
X-Google-Smtp-Source: ABdhPJyoIjrJeLExIaaFiwZuzlk5Mm4QoRj2A6H4wPvwox8RQRAM/K613SIEEgFHEEAWDyh/nUU4jw==
X-Received: by 2002:aca:b509:: with SMTP id e9mr2542989oif.66.1624359576424;
        Tue, 22 Jun 2021 03:59:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a84:: with SMTP id l4ls7903106otq.1.gmail; Tue, 22 Jun
 2021 03:59:36 -0700 (PDT)
X-Received: by 2002:a9d:715c:: with SMTP id y28mr2665147otj.275.1624359576090;
        Tue, 22 Jun 2021 03:59:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624359576; cv=none;
        d=google.com; s=arc-20160816;
        b=DgTijQl9jq7AZT5wU0DIctNi7R9+AxjGIb/317uK1iCmyrM2MLNli9pqg9phuQzaz0
         zld/2ko8Xj3oBhYhXKhvlUjpQiukejH7wgV3LVqDiFumVH6Zb1jsxrRIibolMwKg1wez
         Y8OA17iINyFZqgQwwsuSKjm7DGDyLw71VET0jnSvNDpJmUJJSIdl4qIEYSZSNcSYMVXj
         a/KNqVy/VEk8B6u6aijYoXZej9VLou+DxDRB4zo9OTizZcYSTfGniW4Jz3VIGd78lgFN
         iCwHHm2A+Lys3nSRHdqRA/JChLn8V2g3be7+I8j5GFpspqetLuHKWvec+9yOErx83Myk
         BlmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ST43GppbGqjxXxYbgPLZB6WISUmWZ5bTKVdHwZJ0LK0=;
        b=V+tBYawY8hiT5OEm0EKEySC8xHN43KW8a4Bf7JTHRxifw5Oh8JK+XtQ9KBPmprWhsv
         Hz7ojPOIdWVPA5bcXcBTPfgQQcNMMu1PlgWjmDwa63vJV6olaJWs4ezcp62EyVplEaPZ
         UcZCPfINgzAr85c2Ibcr6aXSHs7mfO5opFu2NiC4WjFQhhjJJaNMEHVqLKweEJRr5Rsq
         y/bVWINym8q9IrkjDP/JloWILtJoZyZPfbSKS4dRzV736CNUaeqFrPD6SqKSyUIIokYO
         iVlv7rk0CGbAGe60mvdfy8KbKJ0tWATuOMdG8JAK6TNvqsgb1F/FqoMmQ2Mzla+CEJFw
         mGsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nj20QEq+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id d13si222952oti.0.2021.06.22.03.59.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 03:59:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id n99-20020a9d206c0000b029045d4f996e62so2015703ota.4
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 03:59:36 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr2616280oto.17.1624359575598;
 Tue, 22 Jun 2021 03:59:35 -0700 (PDT)
MIME-Version: 1.0
References: <20210622084723.27637-1-yee.lee@mediatek.com> <CANpmjNPyP2-oULXuO9ZdC=yj_XSiC2TWKNBp0RL_h3k-XvpFsA@mail.gmail.com>
 <46b1468146206e6cef0c33ecbfd86e02ea819db4.camel@mediatek.com>
In-Reply-To: <46b1468146206e6cef0c33ecbfd86e02ea819db4.camel@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 12:59:24 +0200
Message-ID: <CANpmjNNOkPAHvZv2nJgv_1AfxpQ7c2oFXJAUrWGJAsMKaUEy-w@mail.gmail.com>
Subject: Re: [PATCH] kasan: [v2]unpoison use memzero to init unaligned object
To: Yee Lee <yee.lee@mediatek.com>
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Nj20QEq+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 22 Jun 2021 at 12:48, Yee Lee <yee.lee@mediatek.com> wrote:
>
> On Tue, 2021-06-22 at 11:01 +0200, Marco Elver wrote:
> > On Tue, 22 Jun 2021 at 10:48, <yee.lee@mediatek.com> wrote:
> > >
> > > From: Yee Lee <yee.lee@mediatek.com>
> > >
> > > Follows the discussion:
> > > https://patchwork.kernel.org/project/linux-mediatek/list/?series=504439
> >
> > The info about the percentage of how frequent this is could have been
> > provided as a simple reply to the discussion.
> >
> > > This patch Add memzero_explict to initialize unaligned object.
> >
> > This patch does not apply to anything (I see it depends on the
> > previous patch).
> >
> > What you need to do is modify the original patch, and then send a
> > [PATCH v2] (git helps with that by passing --reroll-count or -v) that
> > applies cleanly to your base kernel tree.
> >
> > The commit message will usually end with '---' and then briefly
> > denote
> > what changed since the last version.
> >
> Got it.
>
> >
> https://www.kernel.org/doc/html/latest/process/submitting-patches.html#the-canonical-patch-format
> >
> > > Based on the integrateion of initialization in kasan_unpoison().
> > > The hwtag instructions, constrained with its granularity, has to
> > > overwrite the data btyes in unaligned objects. This would cause
> > > issue when it works with SLUB debug redzoning.
> > >
> > > In this patch, an additional initalizaing path is added for the
> > > unaligned objects. It contains memzero_explict() to clear out the
> > > data and disables its init flag for the following hwtag actions.
> > >
> > > In lab test, this path is executed about 1.1%(941/80854) within the
> > > overall kasan_unpoison during a non-debug booting process.
> >
> > Nice, thanks for the data. If it is somehow doable, however, I'd
> > still
> > recommend to additionally guard the new code path by a check if
> > debug-support was requested. Ideally with an IS_ENABLED() config
> > check
> > so that if it's a production kernel the branch is simply optimized
> > out
> > by the compiler.
>
> Does it mean the memzero code path would be applied only at
> CONFIG_DEBUG_SLUB enabled? It expects no other potential overwriting
> in non-debug kernel.

Yes, if the problem only occurs with slub debugging enabled.

> By the way, based on de-coupling principle, adding a specific
> conditional statement(is_enable slub_debug) in a primitive
> funciton(kasan_unpoison) is not neat. It may be more proper that the
> conditional statement be added in other procedures of slub alloc.

What do you have in mind?

Well, there is kmem_cache_debug_flags(). Perhaps there's a better
place to add the check?

> Thanks,
>
> BR,
> Yee
>
> >
> > > Lab test: QEMU5.2 (+mte) / linux kernel 5.13-rc7
> > >
> > > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > > ---
> > >  mm/kasan/kasan.h | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index d8faa64614b7..edc11bcc3ff3 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -389,7 +389,7 @@ static inline void kasan_unpoison(const void
> > > *addr, size_t size, bool init)
> > >                 return;
> > >         if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> > >                 init = false;
> > > -               memset((void *)addr, 0, size);
> > > +               memzero_explicit((void *)addr, size);
> > >         }
> > >         size = round_up(size, KASAN_GRANULE_SIZE);
> > >         hw_set_mem_tag_range((void *)addr, size, tag, init);
> > > 2.18.0
> > >
> > > --
> > > You received this message because you are subscribed to the Google
> > > Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it,
> > > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit
> > > https://groups.google.com/d/msgid/kasan-dev/20210622084723.27637-1-yee.lee%40mediatek.com
> > > .
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46b1468146206e6cef0c33ecbfd86e02ea819db4.camel%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNOkPAHvZv2nJgv_1AfxpQ7c2oFXJAUrWGJAsMKaUEy-w%40mail.gmail.com.
