Return-Path: <kasan-dev+bncBC7OD3FKWUERBGEEX2MAMGQESFR4QHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 70BC05A8211
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:45:29 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id r28-20020a056830237c00b006392b014be9sf7670004oth.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:45:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661960728; cv=pass;
        d=google.com; s=arc-20160816;
        b=NcSVFYMP5mkCG7M+80w1+0nLqSUiLyILcYVXUFWkfXq+vccyKl6XwezUviaUz1qPOf
         ybwMZwH99scYwId/HDIjyLm4SZLu8e0N0luMEVlWQv/LfpvZvg7qFvbvx3drzF2CSZNZ
         2oJ0fbQv27N9pImrz4hVBaMIHehhKAj32rX4+s9bdXzXhy6dzZNT5SRnlcy0howvOUZC
         ZPAoizxnNuRsWQYH/HRHYLmaBZdwvfg7FPrE68i9svxjUF0eEgsHfQOnJMkHpWYejoVj
         RThtXCvpj8g4H/RE4NdF2/sSDtVEnrJqUuIQIJtOm1VYyoKOGuIiWJ36KS6XxVNJaCUD
         rWMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TluurHYSLrZL6cccxcH13D3RkQJQRsP410ZM2kQoOgs=;
        b=MYmq6rHMRknC5IzRinovEbFewVDD2zjvEFud+CghoevbuHIwL79srzPUN7ArR1u9vr
         CEmdIV1DBaJMHM8CL98PQe+4OzlCfJ9pzAaNijK6BrFnh0AYHqFmPj8y3bOsNgLH9DSN
         S8/P6XbeR9eOazYwMKG6VZ1mdFcGW6clPF/smENAxdi3f51cbZUId+OTrpUfqeQ4ATqv
         qQOjnQp/tHxZtLqAHjRdGCANgTYuWBJ+4JbFFWr/K/K4Nk4VZkHQr087VCQwbwnkOWyu
         8N7jziF+yGgo/D6kYcn164Qh9amD8q2by7+wHG7Xriah4csrpObYcS6L0UsA2oupr49Z
         +WPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="f3+0Eh/W";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=TluurHYSLrZL6cccxcH13D3RkQJQRsP410ZM2kQoOgs=;
        b=FgJRxcLAdoZj+rv4VYLIxbD/txvsULzs/cf/bVZ56yH+X0afgXUHlhCm5LfzLVxlbJ
         hiGTkq99rsUy9kqkhcQ7qYw0W5PMxr3orrvlchTDIx/5PBtYa6gzBPxH1aDR4Pr/ju7c
         WbbguZvlFQ6Do7CeOEWQlVydye1pcONHH0kJqTKA6b2kpVgYqJwfurQ+5NosDkHQhStz
         47KYzvxGUAy3mESpy0oQkUHMXrwIIEMAoWPr/52GiQWUTO4QOoKLt4MMMqbfQdTrIxlJ
         z3lrBEysOROnBlR8dPp2FKzyq0UsEOEvjfC95jPr83z2dTUcadAVWbRFGQusuYpyI4Df
         2oWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=TluurHYSLrZL6cccxcH13D3RkQJQRsP410ZM2kQoOgs=;
        b=1fV41xVyu4Qono0o+EM+Kji0yij9eluKXhnLCo837KPIgMwVdoDG0JGd+ksPyf82TI
         MtIzu+NAB3B6hAqR8ZjZm4RRxi3wLyrp1yrrkE8eqo0NtWWo5NVjQ8N6pwIZH78e3sLp
         SZx2ljGCd5I6Ay10BdIjzflLmni4O/pOnwI64B5E1EJpZd3XldxljOfUmeWtKo0Sk/ep
         S0yyzFW0qi8xumVygj4zHMsGNKwFRqN5FPC8tAGgcvfxXE/ZKFv+UINYJo11XrbMC0co
         KDt/wdyEULCUkSES6iZc44f6E2UUhcW2ihwVXMy64BQY4fmu0WXADxnQnCCUtj5Vk0iK
         k/JA==
X-Gm-Message-State: ACgBeo2zOBPN31XQOoZow/KRlRn645ufitl2pq+6lxntH4uwm88NPXOe
	19UjxNhhC9s5IaCjOoqh2Y8=
X-Google-Smtp-Source: AA6agR5zm5RqZaxH6CnlFP8e/nrtlahFnJWArGjt8dtHHvHwuCcDCEmYMG9oV78/P7EnnIYKuE6zYg==
X-Received: by 2002:a05:6808:1183:b0:345:d23f:9276 with SMTP id j3-20020a056808118300b00345d23f9276mr1555340oil.43.1661960728218;
        Wed, 31 Aug 2022 08:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5c2:b0:11e:4e2a:2481 with SMTP id
 v2-20020a05687105c200b0011e4e2a2481ls435296oan.4.-pod-prod-gmail; Wed, 31 Aug
 2022 08:45:27 -0700 (PDT)
X-Received: by 2002:a05:6870:831d:b0:10d:a96f:8bc with SMTP id p29-20020a056870831d00b0010da96f08bcmr1687016oae.143.1661960727814;
        Wed, 31 Aug 2022 08:45:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661960727; cv=none;
        d=google.com; s=arc-20160816;
        b=uZEtcB5Kd4YQFqgUL5aA2QRTFQyGW+a15podPLXhpdmv+x6f/7VzbYKgAEKUwWmNAc
         P11/YwX9EPrxoguh9ZwZZX3Q7qx8FDzzbbWunnjAFuTam36mXF4Ip7e1LFETwUR8PfWL
         gZFkEmZFiLpbInGOwAF8dOCsxyX/8ytS26DXNKvTVlAaGmUY7RkwVEPGUSocoETEBbr1
         86Fo70hrf6OpwKL3+XfjnmWZlCF3mdI6lzmfvz5MZcbwN8Meua3SNn9CPAsuWlYLwqse
         EAF2P1b/75Daa8vgr89mY7hp857jPts8dRUFV6o7M4pf0a/LMYnstahQXfs1tJCXVZ6y
         voOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yg5lEIxwkC8L9g2KyGsqswRBhk4gAo50nJ7nWIpcdXc=;
        b=k8aS/HFoCFXdj2b0SuY9EBrnvFJjJgymItnRuYSwliEPcgEFnQQtOLbF1SgEZwlqr2
         5FoFq8Iz+690aIqGVnTGQU58KTVemre1qW9JbvwCK42UmJUgHNy6EmJk1rB5MbrY1Ilo
         A81n/X7ZqHA6Ciswq1jU/bCbL3/f5A613NYXaaumFFJPpf62AWZhN9yf3oJhJ5wU02ah
         CATC7FrFtaO7GMTPXSs5lVpVCwAmA/u63RDPWCBoinBjre7oghzUxi058JGL2sqf1F/D
         c+h8l1+kxZrJ6tDvq9ay6E+9XRSOPlU0z8K37gfRFgCNf8plSMyVDOPgnknqiH6iAdV6
         Aekw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="f3+0Eh/W";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id r187-20020acadac4000000b00344d0712829si756229oig.5.2022.08.31.08.45.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:45:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 11so4741601ybu.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:45:27 -0700 (PDT)
X-Received: by 2002:a05:6902:705:b0:695:b3b9:41bc with SMTP id
 k5-20020a056902070500b00695b3b941bcmr16070987ybt.426.1661960727041; Wed, 31
 Aug 2022 08:45:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-11-surenb@google.com>
 <20220831101103.fj5hjgy3dbb44fit@suse.de>
In-Reply-To: <20220831101103.fj5hjgy3dbb44fit@suse.de>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:45:16 -0700
Message-ID: <CAJuCfpHwUUc_VphqBY9KmWvZJDrsBG6Za+kG_MW=J-abjuM4Lw@mail.gmail.com>
Subject: Re: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
To: Mel Gorman <mgorman@suse.de>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	dvyukov@google.com, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="f3+0Eh/W";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Aug 31, 2022 at 3:11 AM Mel Gorman <mgorman@suse.de> wrote:
>
> On Tue, Aug 30, 2022 at 02:48:59PM -0700, Suren Baghdasaryan wrote:
> > Redefine alloc_pages, __get_free_pages to record allocations done by
> > these functions. Instrument deallocation hooks to record object freeing.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > +#ifdef CONFIG_PAGE_ALLOC_TAGGING
> > +
> >  #include <linux/alloc_tag.h>
> >  #include <linux/page_ext.h>
> >
> > @@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
> >               alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
> >  }
> >
> > +/*
> > + * Redefinitions of the common page allocators/destructors
> > + */
> > +#define pgtag_alloc_pages(gfp, order)                                        \
> > +({                                                                   \
> > +     struct page *_page = _alloc_pages((gfp), (order));              \
> > +                                                                     \
> > +     if (_page)                                                      \
> > +             alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > +     _page;                                                          \
> > +})
> > +
>
> Instead of renaming alloc_pages, why is the tagging not done in
> __alloc_pages()? At least __alloc_pages_bulk() is also missed. The branch
> can be guarded with IS_ENABLED.

Hmm. Assuming all the other allocators using __alloc_pages are inlined, that
should work. I'll try that and if that works will incorporate in the
next respin.
Thanks!

I don't think IS_ENABLED is required because the tagging functions are already
defined as empty if the appropriate configs are not enabled. Unless I
misunderstood
your node.

>
> > +#define pgtag_get_free_pages(gfp_mask, order)                                \
> > +({                                                                   \
> > +     struct page *_page;                                             \
> > +     unsigned long _res = _get_free_pages((gfp_mask), (order), &_page);\
> > +                                                                     \
> > +     if (_res)                                                       \
> > +             alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > +     _res;                                                           \
> > +})
> > +
>
> Similar, the tagging could happen in a core function instead of a wrapper.
>
> > +#else /* CONFIG_PAGE_ALLOC_TAGGING */
> > +
> > +#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)
> > +
> > +#define pgtag_get_free_pages(gfp_mask, order) \
> > +     _get_free_pages((gfp_mask), (order), NULL)
> > +
> > +#define pgalloc_tag_dec(__page, __size)              do {} while (0)
> > +
> > +#endif /* CONFIG_PAGE_ALLOC_TAGGING */
> > +
> >  #endif /* _LINUX_PGALLOC_TAG_H */
> > diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> > index b73d3248d976..f7e6d9564a49 100644
> > --- a/mm/mempolicy.c
> > +++ b/mm/mempolicy.c
> > @@ -2249,7 +2249,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
> >   * flags are used.
> >   * Return: The page on success or NULL if allocation fails.
> >   */
> > -struct page *alloc_pages(gfp_t gfp, unsigned order)
> > +struct page *_alloc_pages(gfp_t gfp, unsigned int order)
> >  {
> >       struct mempolicy *pol = &default_policy;
> >       struct page *page;
> > @@ -2273,7 +2273,7 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
> >
> >       return page;
> >  }
> > -EXPORT_SYMBOL(alloc_pages);
> > +EXPORT_SYMBOL(_alloc_pages);
> >
> >  struct folio *folio_alloc(gfp_t gfp, unsigned order)
> >  {
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index e5486d47406e..165daba19e2a 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -763,6 +763,7 @@ static inline bool pcp_allowed_order(unsigned int order)
> >
> >  static inline void free_the_page(struct page *page, unsigned int order)
> >  {
> > +
> >       if (pcp_allowed_order(order))           /* Via pcp? */
> >               free_unref_page(page, order);
> >       else
>
> Spurious wide-space change.
>
> --
> Mel Gorman
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpHwUUc_VphqBY9KmWvZJDrsBG6Za%2BkG_MW%3DJ-abjuM4Lw%40mail.gmail.com.
