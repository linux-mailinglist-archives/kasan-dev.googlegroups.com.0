Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQFY5SGQMGQENPVZY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id AB471476F53
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 12:00:18 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id v15-20020a17090a0e0f00b001b10461f2f6sf1497919pje.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 03:00:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639652417; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJGk8kIW3K5yoG0DnrjGxKYL0x/FwNEJDn4UvaxjX/7Gx4HmtzXB2xPY0AWPJGiwWA
         UvvTs/AitD05PnVQ3MqEJ8qqNDTPzwjFRNNl/BhIg6b72pYGxj0qhJPFgyLM57ZOoRoC
         Ynstj9OcN9/ImrWCINB3c91eKt1zf5wsdJuu82SEKKMVokNH/lwV2Rpl5LYfy24WcXYc
         2kh5/Y00lpjZ6FAOEVoBJfdK2siGSyG/h2SVduoB0YH6ankRQPmKUG6J3vQmj/z+vcKV
         UvtmiFQlxOfBFUH/mBENlNLrBr0SRm0d3scGcfiKbyspJFKxiFCrt8PvJ3VLYhQ/js4i
         Exkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ubOctvjX5CEV4QcmJOp6CrRKtHttaLYoUx/WHoaj8G8=;
        b=fWVUFb3OhKeYn0LNPxm44Y2JdTlWXqRl7B9A5mdRQCu6uag8E7OzLqKDiue/ZEzk4l
         8IvnxRNJEcmA3wIJU1waujBDFG3SrPdn0FYTSaHkk/oPO257WI8dP3MnbNs/ixz4Cleq
         pGk9262s43AjgXgwZEChPBVn6mOMi91Qdtl4BS2OO3eik5v1aMavX9W2/qdsvfLJkkAm
         GfJP1Rcu3F95KI93Wy8IypRX7J23+UMSvIPqCbaIRB+Ai4VXqWDJF+IsZIihplXPtST6
         Tk1N4nSyZ1cYVjdnNwbJJt7/JGUn1Qn4CYt2q0YCLWRbHKrObIytkE/TYTzbg9Yd49L1
         nD4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GezK35ON;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ubOctvjX5CEV4QcmJOp6CrRKtHttaLYoUx/WHoaj8G8=;
        b=pY1+8zgLC21NEbiWltZ27zomqlnHEvsEsiSIem8NPBPSv4v28FhMINU5CGnMGPk5jf
         YwI3Ky1s6yCR0RSP6ZjyzvRaj8EiS5zQyHzHtgjn95FsWxgHExCeIfd+yttm8vo1VF4F
         U7u9g70Bi2dAu0F4cmyqFRoB6cl9dfoPQqOowjuuZZ/iXGo51XfjGDBH5E+IyvQ+fkzG
         ivVIk1Sy58q2ahlqMfJ7CnF1Hbv79az9/RrTZmM3oIalTfEhsq4m0O7tdshP55Dg5thW
         YPi3DKZIe3DNKuXA4Hu8sHVcvWQ18qsk69kjDSEczPEygRQJLsp9nmRY9mKb1Br2/GAy
         GWtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ubOctvjX5CEV4QcmJOp6CrRKtHttaLYoUx/WHoaj8G8=;
        b=FZVZw8OYlR2c4qzvY25RRJYbc1jGkxY8QlaonSc/SPZPiJ+Cp25UXlBaq/6J5j9oGc
         mB/RfRphETNFioTz5CARfUTrAlM7sZIWANwPUzXzxXk6hnm021ADkBWzeGgJngXpASiX
         dLOIO0pb7IMPL1JI/fha2nCJ8KdEdBc469b/mhYERbFydXKa4xFiuU5tqKMTiuDALayq
         UtmhEYfprPCMcaF0oJHojjvJCtozq7mEkxSQbB3Wd3RE0vSaS7tUl/tSYJ44EJaQGf1a
         vTjDKZlnE+HLxwSRcPXdTCutgO6bfCCk7M8EeamO1TyYhBP5UYQSkcdXZxTv20TTOul4
         zH6g==
X-Gm-Message-State: AOAM533YSoZsSSoJve59GMgWQ3p0priXIof17VjuefAZ//lHiZ+dTLov
	qinlDv/pnpYEyXcNA6uQ+T8=
X-Google-Smtp-Source: ABdhPJxpTYpDRyvRjnyhA90jNmk10maRgNOQLbUFlwdXoSclbPJ0FT3cQksoP7s5IbHyloxBR2CNzA==
X-Received: by 2002:a17:902:f781:b0:148:ada1:e913 with SMTP id q1-20020a170902f78100b00148ada1e913mr6597984pln.97.1639652417012;
        Thu, 16 Dec 2021 03:00:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4cc:: with SMTP id o12ls3568003plg.11.gmail; Thu,
 16 Dec 2021 03:00:15 -0800 (PST)
X-Received: by 2002:a17:902:f781:b0:148:ada1:e913 with SMTP id q1-20020a170902f78100b00148ada1e913mr6597843pln.97.1639652415185;
        Thu, 16 Dec 2021 03:00:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639652415; cv=none;
        d=google.com; s=arc-20160816;
        b=wZVSOMmtZV4otgIvJcPk8q98apN8ZbZDN3SL42aW/DxpN7sRq/1ssaRoCQOPSVl8RD
         NNuzHEAzpRvAjM8jqvSb/Ash6yN3ax36tnoQXklKYG5QcMdM3vnkPEwE+ihaZnDV54e3
         CCNrVU88gcssOpZKX1mv9wxpcEkexKE00EP/tsYo/GWBbkXskZ3oDOhsMCOxXzk3nuBb
         LwnoHZsw0naYV7IHLYzvfcQjY9WpwOsnusRRKxhlbNDNmYF7JP9Aq0zNLMcKKxhAh6c9
         hgRtzNNg4247jQ+Z9rlH1GnH9+4LeclM0GXJNcdDFn1EV5QLM3VjUYEWeG3NeBLeOKLF
         nGAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KnBQJR/TMzh78I8yqUIjs7VdtqfCQRZRo/Chv253Z68=;
        b=qvgdS/U6DwKiJgxCva4RsV5t3vQkf63QtbqN0uunDfM7SRJZNNjPtHoqRIG6HV8FPS
         T55wgFqKXudvcK3Z3bWtIzbsXBQIXlv4nWFjwn45S1EN5ULLy8D4lzvhFw7DcR7SN2up
         G8ykmm+zuIqMguO6mVjL4HdWoiZoZMtXNHjMLmNtrdt5vI+ecquF3YR2WQs9+Y8V+A9m
         c9Yz51VRusFoVvUVYdz1BXU+McVWYOJ+QE0e2SKi4IahdYQXxussWS7b9qzAHvCfQOC2
         9iI9jD7CPWPjSQFY1vzHvw/e2XZTIL4aZA9FLmpJW9LhnKVkC0a5eZP5IZ4VfeJPdWMi
         OcFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GezK35ON;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id ls15si137552pjb.1.2021.12.16.03.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 03:00:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id l8so25001620qtk.6
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 03:00:15 -0800 (PST)
X-Received: by 2002:ac8:4e56:: with SMTP id e22mr16609220qtw.72.1639652414512;
 Thu, 16 Dec 2021 03:00:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl@google.com>
 <CAG_fn=U71Yn-qCGMBR=_uOt0QCEu9skGzhgRBJjpkQCjZ=dKiA@mail.gmail.com> <CA+fCnZfto82vg3vGkZGNxJKOOqsOp_bpmHEd0Z350PfPJ7Y=1w@mail.gmail.com>
In-Reply-To: <CA+fCnZfto82vg3vGkZGNxJKOOqsOp_bpmHEd0Z350PfPJ7Y=1w@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 11:59:38 +0100
Message-ID: <CAG_fn=UHVhTSj9=eA8XikF2JhRM3WHitjedinek1wUayStP_pQ@mail.gmail.com>
Subject: Re: [PATCH 08/31] kasan, page_alloc: refactor init checks in post_alloc_hook
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GezK35ON;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

On Mon, Dec 6, 2021 at 10:09 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Thu, Dec 2, 2021 at 5:14 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Tue, Nov 30, 2021 at 10:41 PM <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > This patch separates code for zeroing memory from the code clearing tags
> > > in post_alloc_hook().
> > >
> > > This patch is not useful by itself but makes the simplifications in
> > > the following patches easier to follow.
> > >
> > > This patch does no functional changes.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > ---
> > >  mm/page_alloc.c | 18 ++++++++++--------
> > >  1 file changed, 10 insertions(+), 8 deletions(-)
> > >
> > > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > > index 2ada09a58e4b..0561cdafce36 100644
> > > --- a/mm/page_alloc.c
> > > +++ b/mm/page_alloc.c
> > > @@ -2406,19 +2406,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> > >                 kasan_alloc_pages(page, order, gfp_flags);
> > >         } else {
> > >                 bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
> > > +               bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> > >
> > >                 kasan_unpoison_pages(page, order, init);
> > >
> > > -               if (init) {
> > > -                       if (gfp_flags & __GFP_ZEROTAGS) {
> > > -                               int i;
> > > +               if (init_tags) {
> > > +                       int i;
> > >
> > > -                               for (i = 0; i < 1 << order; i++)
> > > -                                       tag_clear_highpage(page + i);
> > > -                       } else {
> > > -                               kernel_init_free_pages(page, 1 << order);
> > > -                       }
> > > +                       for (i = 0; i < 1 << order; i++)
> > > +                               tag_clear_highpage(page + i);
> > > +
> > > +                       init = false;
> >
> > I find this a bit twisted and prone to breakages.
> > Maybe just check for (init && !init_tags) below?
>
> I did it this way deliberately. Check out the code after all the changes:
>
> https://github.com/xairy/linux/blob/up-kasan-vmalloc-tags-v1/mm/page_alloc.c#L2447
>
> It's possible to remove resetting the init variable by expanding the
> if (init) check listing all conditions under which init is currently
> reset, but that would essentially be duplicating the checks. I think
> resetting init is more clear.
>
> Please let me know what you think.

Ah, I see, so there are more cases in which you set init = false.
Fine then.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUHVhTSj9%3DeA8XikF2JhRM3WHitjedinek1wUayStP_pQ%40mail.gmail.com.
