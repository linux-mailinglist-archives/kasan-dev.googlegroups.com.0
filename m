Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBIXMYOPAMGQEUGIS3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id D1A0167ADCC
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:28:04 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id n93-20020a17090a2ce600b0022beeabcf6csf845112pjd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:28:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674638883; cv=pass;
        d=google.com; s=arc-20160816;
        b=0nWzyNMbikAU0XqjyLRFQ3cZgvishwWoY4QM2emLxwbCI/eKQx+1MUlY9Gd4Vb875n
         edqcn0bB4Z07PcHys+B3hrzY+aaalevX7UV2wrQZhFRbBUY334yg5joJFhwCheKY39/h
         vxq/zwB0n8ZcwMcFACvnh5KTzTrkZO8+Zx0wNjsoVeRFs3+TYhdZdmZ1oEpCDfEVZNus
         owe+Ess4Y6eyNyxZewq95tEbQp199KapoALcbq8oQyZIFYvSSiuKLlTJkaX4T9UzA99C
         b0FaY4h/tHpsiCarjXxfZR+7ZrMFgtwdchzNa6W7wl4i2G8mcDqZL/FauZ5Uim5/ON1y
         XG8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q6SXOQnaVru96/+kw5XZjk3tOD/1NXA3A0neH5+xuX8=;
        b=l14zH/OQZt/3RFkzXTf5hC88b4QmG0Ot0Lnr/jFCsRXeD5wHrojINnV4XBcYufy4VC
         ZhUph+QTaFqhqyyufv1ldYYuCp60zQWPBSEGcH03pNNZ+nxI8CDyX5yF1kaf5kcJHpX5
         hsRuLnsgU2ize9bS36PxHdHUIZrWplD7LWPcgwntR+qu7a6DC1l5wF4V2+5wTAWtra60
         6o4DKFg09AgekIHhN4K4OlRJdF8vo9K5i6V7Hfyzj+jFlVnHdYzkxKsbU5YM2Qu3kzf9
         RzkG9nuafPjHfECkQwD3jsdcQLCmn4K68TTAvucI3BgkNYpKyfVmEm4JTuc37zq4iE2a
         fRcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S24ranaz;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q6SXOQnaVru96/+kw5XZjk3tOD/1NXA3A0neH5+xuX8=;
        b=H13+re4K3jrCoIO81JCF0R1HMNi9GHsu8qThd1M1khSlL67VoHCfKXCJJ6sRSDWyub
         TXx3csFO5gD+/RbBK6OpeBIb6baa8MW16MizRcQEdX/GQM2CroVOXjQDRvX9a6IXzFfk
         TQNqMAHYyTMdAyuAu1hUc4nJS5ddd5tgWFQTr3gOdCKXAUHN6uUM6F99CQ6o2c2Vk0AD
         /lc1VMyoEVpXZIb60RtOOz4nXR/970OdYrmV4USAYW16AT1ZkQkA4asJtEREk/rqi4V2
         l26AzlFOpi3R1tIAkyXRq695Gv7eWvQA51mfDkLp9VQ/wBxH23uH9en/IRqcSGOTMv1I
         WY0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Q6SXOQnaVru96/+kw5XZjk3tOD/1NXA3A0neH5+xuX8=;
        b=f5xMXmQjqTqCgBMDk6ZLZZ2SIQRhXqUGatgHxp/sYgF11NAorhiS13UozSZfqDNPm1
         tSdx3Gkgt3jPzC5P+V66zCIfMecAf0PL1ZtQGih3kiYXP2QeiSJSbXsUfZ7+qBOC3RZ4
         XRIpmmv8Vqc733B10VlqppptjlP15l9z80FJsoFVgYXYx/BIkRuXDSqmt9sbS2CqS4QW
         Vty9dqHQ7JqpJj1hgv2w+bwEecycL6Xy818+weTRqebidbNaUs6KVh1AMaD88ISQJefN
         db0NYrv9tzLDqzTpaRAurAXQ/ud67fYYFORr4m2eSHqvdYjj1Kqx1BHnIyjynLcnx+np
         UkXg==
X-Gm-Message-State: AO0yUKX2NeshE1LHXzSx2oFDTDD1MDyHJt5cGMfo6Qgx1mvR51LzG0ni
	mcLqiU6FNFYy3cGqIpePkR8=
X-Google-Smtp-Source: AK7set/XUpH1bDBit23i7mYzvLKLJwfml+dlzOMHLGh16NBarujDmP18QOTMq8TIj+xS4Qc+Mcvn+g==
X-Received: by 2002:aa7:8754:0:b0:590:18a5:9fb9 with SMTP id g20-20020aa78754000000b0059018a59fb9mr432528pfo.37.1674638883064;
        Wed, 25 Jan 2023 01:28:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7149:b0:227:1b53:908c with SMTP id
 g9-20020a17090a714900b002271b53908cls1966547pjs.1.-pod-canary-gmail; Wed, 25
 Jan 2023 01:28:02 -0800 (PST)
X-Received: by 2002:a17:90b:1bcb:b0:229:dcec:bef with SMTP id oa11-20020a17090b1bcb00b00229dcec0befmr25165490pjb.33.1674638882347;
        Wed, 25 Jan 2023 01:28:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674638882; cv=none;
        d=google.com; s=arc-20160816;
        b=hA5MAFHn6WbZtIj0wjOQNsj9cOGd4wnostuutRpoVXDgTyZdCB2qLiE6U62RICyJqk
         /p0cRPiNYUBsOKk6b5C4hbgqW7GmoRRZgNp3Eh6dsFfT5ot49HNEu2maoLbVFEkzqopd
         d3PyrQzWbd9hIjUeAxxJNiT8ioQ1idgNwIFADzqUZRyN9nlHlEj8gsUAPg2dW9p2KeQR
         IWtjIuaN/XSD2lB52ONHTT9rmU6NKzuQgzIxLDg1UJFPjsZbwniPb67zutK7cLvD/K/a
         iIqQboxq4vl/UmGdtSR7RoszvlNrzoIDotUNAcwFfsyVNklqj8EgygPrrJxrZHcv5XNA
         eghg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3vAoXdS/YoRTyt2xMAeJZRk1CWXWTFAex8XSq5QFxAI=;
        b=kbNKgqYDwPA5RhCWrTfT3NusGC1sZfw8kAjwcd8dti+y8nkrlj7PzohHf6Coqk79K+
         Z0EWFE6CjepekWzUayogJIQjtWiFLmcFlf90hSabdrUEUlZSnmh/a8hOJGjtvDJTQxjg
         nzYUJwrXXxe+pt3VXMUuD5JZc19vw/mlBTKRcx+Vz6t4cVEvfhEgcfOJj5XoH1Z3tyHh
         NnwC2dd9dMxyzi1biZ2lIoLE8JxyfPle0C50YljUWtCDiYU4vMN4iZ2676yE5AFC9bVM
         MI0zGyNu3ZgCa1RctGfwOFH49yEonTViIr5XIrQMcLSt0hBP2uc8a9t1IgPlA8E2sY7Q
         iqvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S24ranaz;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id g2-20020a17090a9b8200b002295c9ea1a8si124094pjp.1.2023.01.25.01.28.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 01:28:02 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id i1so8530088ilu.8
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 01:28:02 -0800 (PST)
X-Received: by 2002:a92:ca8d:0:b0:310:98bd:dbf0 with SMTP id
 t13-20020a92ca8d000000b0031098bddbf0mr583597ilo.128.1674638881876; Wed, 25
 Jan 2023 01:28:01 -0800 (PST)
MIME-Version: 1.0
References: <20230117163543.1049025-1-jannh@google.com> <CACT4Y+aQUeoWnWmbDG3O2_P75f=2u=VDRA1PjuTtbJsp5Xw2VA@mail.gmail.com>
In-Reply-To: <CACT4Y+aQUeoWnWmbDG3O2_P75f=2u=VDRA1PjuTtbJsp5Xw2VA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 10:27:25 +0100
Message-ID: <CAG48ez32X1WKryh5ueQ0=Mn=PMKc6zunOYsMHhwMMMxKKaMfqA@mail.gmail.com>
Subject: Re: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, Andy Lutomirski <luto@kernel.org>, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=S24ranaz;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::136 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Jan 18, 2023 at 8:36 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, 17 Jan 2023 at 17:35, Jann Horn <jannh@google.com> wrote:
> >
> > KASAN (except in HW_TAGS mode) tracks memory state based on virtual
> > addresses. The mappings of kernel stack pages in the linear mapping are
> > currently marked as fully accessible.
>
> Hi Jann,
>
> To confirm my understanding, this is not just KASAN (except in HW_TAGS
> mode), but also CONFIG_VMAP_STACK is required, right?

Yes.

> > Since stack corruption issues can cause some very gnarly errors, let's be
> > extra careful and tell KASAN to forbid accesses to stack memory through the
> > linear mapping.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> > I wrote this after seeing
> > https://lore.kernel.org/all/Y8W5rjKdZ9erIF14@casper.infradead.org/
> > and wondering about possible ways that this kind of stack corruption
> > could be sneaking past KASAN.
> > That's proooobably not the explanation, but still...
>
> I think catching any silent corruptions is still very useful. Besides
> confusing reports, sometimes they lead to an explosion of random
> reports all over the kernel.
>
> >  include/linux/vmalloc.h |  6 ++++++
> >  kernel/fork.c           | 10 ++++++++++
> >  mm/vmalloc.c            | 24 ++++++++++++++++++++++++
> >  3 files changed, 40 insertions(+)
> >
> > diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> > index 096d48aa3437..bfb50178e5e3 100644
> > --- a/include/linux/vmalloc.h
> > +++ b/include/linux/vmalloc.h
> > @@ -297,4 +297,10 @@ bool vmalloc_dump_obj(void *object);
> >  static inline bool vmalloc_dump_obj(void *object) { return false; }
> >  #endif
> >
> > +#if defined(CONFIG_MMU) && (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
> > +void vmalloc_poison_backing_pages(const void *addr);
> > +#else
> > +static inline void vmalloc_poison_backing_pages(const void *addr) {}
> > +#endif
>
> I think this should be in kasan headers and prefixed with kasan_.
> There are also kmsan/kcsan that may poison memory and hw poisoning
> (MADV_HWPOISON), so it's a somewhat overloaded term on its own.
>
> Can/should this be extended to all vmalloc-ed memory? Or some of it
> can be accessed via both addresses?

I think anything that does vmalloc_to_page() has a high chance of
doing accesses via both addresses, in particular anything involving
DMA.

Oooh, actually, there is some CIFS code that does vmalloc_to_page()
and talks about stack memory... I'll report that over on the other
thread re CIFS weirdness.

> Also, should we mprotect it instead while it's allocated as the stack?
> If it works, it looks like a reasonable improvement for
> CONFIG_VMAP_STACK in general. Would also catch non-instrumented
> accesses.

Well, we could also put it under CONFIG_DEBUG_PAGEALLOC and then use
the debug_pagealloc_map_pages() / debug_pagealloc_unmap_pages()
facilities to remove the page table entries. But I don't know if
anyone actually runs fuzzing with CONFIG_DEBUG_PAGEALLOC.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez32X1WKryh5ueQ0%3DMn%3DPMKc6zunOYsMHhwMMMxKKaMfqA%40mail.gmail.com.
