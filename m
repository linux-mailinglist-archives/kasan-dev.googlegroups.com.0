Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDMAWL6QKGQEZZRLAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id B6E032AFBC3
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:21:34 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id c18sf3017589qkl.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:21:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605140493; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWwcL3jieYFcO4OMtlxTiIv/JdEuCEacbxfkr7DScUcVKpUfMGAlGaJflHHiMhImP7
         1c7ydOZEYFNUYe+xDTSFu5vNvyl6Xk3NbHBII7GJQTDKGl8tfVULRceryvXp7nOLI+XZ
         7Q2o8Xh4zssb+Kpw32AjgIndmMs7ldThqsW28TgwhU/mYO3JIYGDlO5cAA9agkmCuFhU
         DImJDWfXmGkzFgvRM9Wg1hzHrFwzw7Bz4xELnikMlOkrK9KtvVJ9pLOxhHSQLzop0Uq1
         rUGYpJHCuhgG0bt3g3kRtWCVJKjIbVz0thyX4IuJEDuD4KyXpRx+yL24CQyP8l0eUVOr
         UG7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OFwiRfR7LTAZOQBe628JomPIeumIF31dt4ifYgoBu7M=;
        b=GaWBOmo8IqN1dCr15yox7fzc78HwKfn3PVaMo8BBQwSlHGw+tHYTQ/72o8S1sTBuWw
         ZvXQ78RaxmLey2Rj/77d5ZmZBv6N4Z0MS80TVxd3nYWLExu/ZQMWEhL00rkIvaGobacE
         b5hKWxTy4OrzzjHpYam4iB7VSD92xXOGYx4QbyVK7ZcwsniUajTfEXmiEqKei6BRYrLy
         FISjhryx1rAGv1UmTq97cI+DB1BVpvLGfjmZIhpmy6rD4QkMIQEcMjJ5ojQtjW/SPxp5
         zYyBc585Rb8QlZt88cOgj+nh5VbNYKYX53NxeRa0MFKAn2zZFIChmC4z6DJcPRMJtfHo
         KGMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rPQm3cbR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFwiRfR7LTAZOQBe628JomPIeumIF31dt4ifYgoBu7M=;
        b=mXG39y5scHGZxqFyVoYrUQrkPSQaJRaTlymyg/b+63O7alKdCNtfaikCy6sQYIuHN7
         RcmhLwVc4UxzZpEYxnPpb1m75xWjcGdRIENbstCB3QbRODr9pKimjY4aHQ9WG17yJ2pG
         Ph4PBC9CoPbSNTIxruDhyUFkyJ8WNHyt+lwLRR5VBv9yOlq/ztLSx1hftHGT9VGr9Zjw
         OZ3ofgcpOuBbOC4i0u5mXtFB8ukDVjSxqbH59aOXgQwXWSuxtCMrBZuPETRVlJtJzjal
         Fxm2jyABqOxGlwy1yCo2DIVEeDUzmqiE8VQYkrK2R76miZFYWT44UiWF8jXPcF4OKs7n
         rFSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFwiRfR7LTAZOQBe628JomPIeumIF31dt4ifYgoBu7M=;
        b=aD7Dy0aEv2sGDLxIElSKpf8nr9ZGuvIqEpm9836jDAaPKHyLpBEhB3EGLlB0xQEO4K
         8+VG2HoYcwEnSwMEorZgAkIT6+ROicCdhUp1eO0Q0osXbWFppAYO71Mt9Khk8PPV6yyC
         8uUx49c2hb3dULqwbG4nFfrUfvHUn8Tnik8XfXijoTmGVADUaeWpxjs9EPv/KYCSK1tH
         uYnV8vBr/Ga7BxocGCGmhXJphiX3KzZXUL7FyzdLCW1pVMMOc8/AYhsQfR3qpOj9IQxS
         /oWp0b0wRwpT1w6Cs3zJZxt9i8XA039RSI06vwrEO013gH2LBMEOM2iOWeYCtv01ntiK
         1cxw==
X-Gm-Message-State: AOAM533hAO6Phc9+VCrGcEO7B/p0vT1tiAB0YY9+UJa2tw6DdbEaki+g
	IoY4QPZZ1VnOzX4o2OjU3og=
X-Google-Smtp-Source: ABdhPJznD0YuKCs0fGSWO4u0vw+Ol7H4eWdm/GQaiiyjECu+n6Hu7jMsz3B3m6svS5ncGoe4oZ9uYQ==
X-Received: by 2002:aed:3ba6:: with SMTP id r35mr26364483qte.269.1605140493597;
        Wed, 11 Nov 2020 16:21:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7805:: with SMTP id t5ls523516qkc.9.gmail; Wed, 11 Nov
 2020 16:21:33 -0800 (PST)
X-Received: by 2002:a05:620a:f95:: with SMTP id b21mr19628358qkn.403.1605140493148;
        Wed, 11 Nov 2020 16:21:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605140493; cv=none;
        d=google.com; s=arc-20160816;
        b=LDh3hd9x1x44DF2ifwPiWvA3A8EJ2o1ZHv7XpbddBVPLgnPPknsfmj2kqjwRy/rOsE
         zRJzDKMkAguSkleIFjgxg6GFKqsEny+rAIcpZOl0YjfV7P6sa1yyu3QmU/Ac/pjnbiCk
         Frwg04rmt+hsbFR46+ynwxrclTWf2i+oXTVd5fUd5JyaxubyYQR8joMOYU0DZdVItMkd
         0G1sFwl86vfc1qSHULDVdrQ1WO1AhgUiQy+eVamnGBDj326S6Rieui2vqL/RwOKkddfH
         aRiiZ1diGsXNhhi8phc5K4jf6hcwP2qXEWuWiPsoTvwBdF0Tppp3X/o6r83w4jNu4puz
         iONA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8MZFMCDMJdh8yBoOAogISYylpvG5r3umSSn0ihSNDmU=;
        b=qFRuzAuiZWRoMdYwj0Hm1HgzQ2IFbaa8GzpZgoN3UhwrHr/KqBYHLw2NnIsMZovf2X
         oFcNovqtTk3cV9lCuRAArvTZkfAnkYfiFzswTeOP8ATYCjjeoaAz3fdkJMhfbJyFG97n
         7IcxRO4v/Fmio7BfZlLMtQizajSaofsAWgfLO4vy2GvGiTFxE2b8OLfT5MAMTJxsCvX7
         8jSswsuFCTGWTNM9RQ22TcZDAekosG/d0asP9CvJ9oapKPqg8aEZYorRw4Nieb7bSl5c
         MX2/n9Q4adzlh+GPwAFOBp7gQ/8v2qhfusFYBpBq4WeRkyy3QvUd2NCkv32EasK89YpS
         Pq0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rPQm3cbR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id p51si231894qtc.4.2020.11.11.16.21.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:21:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id f27so2651011pgl.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 16:21:33 -0800 (PST)
X-Received: by 2002:a62:cec6:0:b029:18a:d620:6b86 with SMTP id
 y189-20020a62cec60000b029018ad6206b86mr24239448pfg.2.1605140492153; Wed, 11
 Nov 2020 16:21:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <73399d4c0644266d61ad81eb391f5ee10c09e098.1605046662.git.andreyknvl@google.com>
 <20201111170213.GJ517454@elver.google.com>
In-Reply-To: <20201111170213.GJ517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 01:21:21 +0100
Message-ID: <CAAeHK+w4mXJxrerZc0YLXPV0sx6-uadocRHhkrq-4UYRkuXs8g@mail.gmail.com>
Subject: Re: [PATCH v2 08/20] kasan: inline random_tag for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rPQm3cbR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Nov 11, 2020 at 6:02 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Using random_tag() currently results in a function call. Move its
> > definition to mm/kasan/kasan.h and turn it into a static inline function
> > for hardware tag-based mode to avoid uneeded function calls.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> > ---
> >  mm/kasan/hw_tags.c |  5 -----
> >  mm/kasan/kasan.h   | 34 +++++++++++++++++-----------------
> >  2 files changed, 17 insertions(+), 22 deletions(-)
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> But see style comments below.
>
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 49ea5f5c5643..1476ac07666e 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -42,11 +42,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
> >                       round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> >  }
> >
> > -u8 random_tag(void)
> > -{
> > -     return hw_get_random_tag();
> > -}
> > -
> >  bool check_invalid_free(void *addr)
> >  {
> >       u8 ptr_tag = get_tag(addr);
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8a5501ef2339..7498839a15d3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
> >
> >  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> >
> > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > +void print_tags(u8 addr_tag, const void *addr);
> > +#else
> > +static inline void print_tags(u8 addr_tag, const void *addr) { }
> > +#endif
> > +
> >  bool check_invalid_free(void *addr);
> >
> >  void *find_first_bad_addr(void *addr, size_t size);
> > @@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
> >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> >  #endif
> >
> > -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > -
> > -void print_tags(u8 addr_tag, const void *addr);
> > -
> > -u8 random_tag(void);
> > -
> > -#else
> > -
> > -static inline void print_tags(u8 addr_tag, const void *addr) { }
> > -
> > -static inline u8 random_tag(void)
> > -{
> > -     return 0;
> > -}
> > -
> > -#endif
> > -
> >  #ifndef arch_kasan_set_tag
> >  static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> >  {
> > @@ -279,6 +268,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> >
> >  #endif /* CONFIG_KASAN_HW_TAGS */
> >
> > +#ifdef CONFIG_KASAN_SW_TAGS
> > +u8 random_tag(void);
> > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > +#define random_tag() hw_get_random_tag()
>
> Shouldn't this also be a function?
>
> +static inline u8 random_tag(void) { return hw_get_random_tag(); }
>
> Or is there a reason why this was made a macro?

No reason, will turn into a function in v10.

>
> > +#else
> > +static inline u8 random_tag(void)
> > +{
> > +     return 0;
> > +}
>
> Could just be on 1 line:
>
> +static inline u8 random_tag(void) { return 0; }

Will do in v10.

Thanks!

>
> > +#endif
> > +
> >  /*
> >   * Exported functions for interfaces called from assembly or from generated
> >   * code. Declarations here to avoid warning about missing declarations.
> > --
> > 2.29.2.222.g5d2a92d10f8-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw4mXJxrerZc0YLXPV0sx6-uadocRHhkrq-4UYRkuXs8g%40mail.gmail.com.
