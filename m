Return-Path: <kasan-dev+bncBC7OD3FKWUERBP4HX2MAMGQEMVEOCRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B5B05A8245
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:52:33 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id c7-20020a056e020bc700b002e59be6ce85sf10752942ilu.12
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:52:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661961152; cv=pass;
        d=google.com; s=arc-20160816;
        b=YqTx67qSfpClV/scxOKD8/9lvddQeShBD534qu5v7QFzoLIFZhloFR+R9HoplM3W9Y
         M7zfx4V+eFLA95p8LvRlG/NhLfe7s3eMcxRBmRJ+YxfNTjgr7Oeu6MavbaZm+qHSDgkP
         qkA0ZKnHBdeaboTB/rVnjHdPNOAvgiAtqoRGKNdU/2AMbbE10jKjatsA2MfIgHaVy6Lj
         sooSJAz7VzAXikhaCmRsPH9JDBCHTkD64bA9LQMSn3xCkVzJOU0C2sapElLEEW7biy/J
         5qgaty/uZYS7nopVbbbVuWc4hgtStK5yAn1MSvDV9b8kYoSm9l/zh8tRgzVYevc7leEv
         qdgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fuMz4hKwJDKn7iW3/DcHpr3x/0LZvUCvzBm6k93x+bg=;
        b=H4Bpk5l/I0I73T/87exzTC2gYJocctSdNIKqrWY/y66Bgmi+YuXKxsw5NXlXg+uw1x
         v4YXnpXzwfMji870PMhpXOiS5+TiUDvTP7/6+XH/GSpKhyfkThk5NhG07peTChN4odMr
         YkzDpTq9AJGdn+YLB76hpYPaSd8dk4p+a8flvkmYOmZIDljo7Bkq5L5U3je4vD/ANOUz
         crOlnC/P4TqKrnFIpLtSF4bWsnntUlPhIjALQFJKclxUJFobu4PsIKYrm7s6w37AOGjW
         YOws5+EEZS51uLEj4ZpZMP3p5kuMvJHjNjYdrmQVOFa8M5ynEY6KqVkMSoVHRGhQ7Okz
         9FLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ib8pAgAX;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=fuMz4hKwJDKn7iW3/DcHpr3x/0LZvUCvzBm6k93x+bg=;
        b=Yi5zzsF3AsFvGXKYTqkp/GcMyz6U4FV+B1jFzgWqr/d5TK0nYSXCBHQPJP+TOh+eSd
         t0tH6ZVfeZIoZ2iCoyK5KSzvzgogNPY1oaULWStvUxiCbMcF4xzwLgYMR25bQsFxYj42
         BnKKWb+7K0tWJUIrwF1df4qaJIUsq0a7QWNx29SqNncZM5MohKVWePBD/cQ8isevn44f
         Z8irFq7OllGnvMJRz1/bMFYZJAxYEkQ7ZEHVdePWg3lDeC8jSpkI+tVzPO8T38KiqFJb
         01Awv/M84kaZvxs9xedh+uAmZSOaL7MhdjMY3TYAwWD58fda8RFgKanoO1jQ56hPJFHo
         X3lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=fuMz4hKwJDKn7iW3/DcHpr3x/0LZvUCvzBm6k93x+bg=;
        b=4mDAIpLIt/A9Q0f4fYaxgOsnZ4GcvECxZKX+JDSH6oHYdYJfVRtbosP1/ASVpGj2tP
         vU++KxBtgmudiwON3KCu03S3XkmbvumIwyzK85WvyHdC7G7Sx4jjE+5i9xzCnTjT8SC0
         nJ5NScMbv1fN0qpHSOHPF9cJ1fzkhYtvY1VdzaKq60ODGEze9wuWlohrdcSruBCWvrVh
         BkHT5tyCiwTrwTinPA9KIIw2iGeE1aCB9D9oaolOA9FxzxCXmPPVOiOiZ/kg2eIxOaei
         pqcvgmOcsS0kS1Y/JSbg1KcSkXZWCLdrnCh1gzF00fPymMy+C2UzTN4SlRjlpGOYxVab
         96YQ==
X-Gm-Message-State: ACgBeo0j8N+fnBS7tKpe1MOzIR63patmfHCKxkhMVgz1RDuRQIbIZ30c
	3Mku4jcdCfy6Ak7JUSGobDQ=
X-Google-Smtp-Source: AA6agR7R0aVsQ8JeGsqE/aHKF+sJPuDAo3qn1mGl3YInjom3hu1xtiP7+KdJezZUZFp/HX3YKn9wQQ==
X-Received: by 2002:a05:6e02:1e04:b0:2ea:f1b2:bb17 with SMTP id g4-20020a056e021e0400b002eaf1b2bb17mr8336454ila.172.1661961151860;
        Wed, 31 Aug 2022 08:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:848d:0:b0:34a:4271:878f with SMTP id f13-20020a02848d000000b0034a4271878fls2246303jai.11.-pod-prod-gmail;
 Wed, 31 Aug 2022 08:52:31 -0700 (PDT)
X-Received: by 2002:a02:9509:0:b0:349:b6cb:9745 with SMTP id y9-20020a029509000000b00349b6cb9745mr15442837jah.281.1661961151376;
        Wed, 31 Aug 2022 08:52:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661961151; cv=none;
        d=google.com; s=arc-20160816;
        b=nzHhaEaj2TS+mAIEceXuyI/s3IdOdleplEhjRQ0enjUc2Q9/p9gpythPu/c8UT+dTY
         NDyUATQtrYsCHRVEaWsbo8QOzs53aqbtET2jmB85s7ML7nE8QU7pZtWZg7IU1O5P7v6B
         XdtgbdZ25SaA2GSxh4mlVn3F4DSDLyEeLEDK1zSwMnJ/MAxaPe2a5X7XWTWGDoZFDXO0
         9tEW6/sfRPk0iMSFii7Ni/NuMPknMWZ6S1w3FBbpVGF8VhjdPGZzIegVJJBAKOe+GZPH
         2eSjVoVpP5Gle6lHP8tQLcLj/r3zunvGBQ1k936Gstl0K8jLK/FJh+PGq2Hpe0ikJrbb
         v8cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DPh7ToX/xZeKd5sie6f3GwYv1dgrGEWOsdwYUdRqOV8=;
        b=qrfosXGgS8HjnNxZZmO0lbsjwRZL9wgKmU1chd7VJbo8pJG5w8M4LfXXSRfX7a/ex4
         wFFICT8Uj8c9TDHB10c2Sl0mhOGPYofuFv/tft+cMWKJ/SbZZjf1x+CtCMyq8syB9J1Y
         y1VCYaUt3C7Q5iBcGCDn+AQ3D6hN8F0QBISqJSwlCH+Thlie/S3sItQclH9+fL/nK/wi
         juv1+EYLs2Nwt4CqRzZNVi+0Clkd8kUmrgOdqTMo36ER66ASKackhDpEWsb1JwZ4W3HZ
         NNR0e/jY3AxEp9/f2VN+n6Fck65dfY2kRwKCsdPfPzGTaeka7THNIPAv86dTNj9WsKdM
         D6jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ib8pAgAX;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id t9-20020a02ab89000000b0034a5b140fc4si227008jan.3.2022.08.31.08.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:52:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-334dc616f86so311107767b3.8
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:52:31 -0700 (PDT)
X-Received: by 2002:a0d:d850:0:b0:340:d2c0:b022 with SMTP id
 a77-20020a0dd850000000b00340d2c0b022mr16260868ywe.469.1661961150716; Wed, 31
 Aug 2022 08:52:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-11-surenb@google.com>
 <20220831101103.fj5hjgy3dbb44fit@suse.de> <CAJuCfpHwUUc_VphqBY9KmWvZJDrsBG6Za+kG_MW=J-abjuM4Lw@mail.gmail.com>
In-Reply-To: <CAJuCfpHwUUc_VphqBY9KmWvZJDrsBG6Za+kG_MW=J-abjuM4Lw@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:52:19 -0700
Message-ID: <CAJuCfpGy_RrQBUy2yxvcZzAXO5cJU5BHxRko+b8p7wWLjQwXvA@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=Ib8pAgAX;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Aug 31, 2022 at 8:45 AM Suren Baghdasaryan <surenb@google.com> wrote:
>
> On Wed, Aug 31, 2022 at 3:11 AM Mel Gorman <mgorman@suse.de> wrote:
> >
> > On Tue, Aug 30, 2022 at 02:48:59PM -0700, Suren Baghdasaryan wrote:
> > > Redefine alloc_pages, __get_free_pages to record allocations done by
> > > these functions. Instrument deallocation hooks to record object freeing.
> > >
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > +#ifdef CONFIG_PAGE_ALLOC_TAGGING
> > > +
> > >  #include <linux/alloc_tag.h>
> > >  #include <linux/page_ext.h>
> > >
> > > @@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
> > >               alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
> > >  }
> > >
> > > +/*
> > > + * Redefinitions of the common page allocators/destructors
> > > + */
> > > +#define pgtag_alloc_pages(gfp, order)                                        \
> > > +({                                                                   \
> > > +     struct page *_page = _alloc_pages((gfp), (order));              \
> > > +                                                                     \
> > > +     if (_page)                                                      \
> > > +             alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > > +     _page;                                                          \
> > > +})
> > > +
> >
> > Instead of renaming alloc_pages, why is the tagging not done in
> > __alloc_pages()? At least __alloc_pages_bulk() is also missed. The branch
> > can be guarded with IS_ENABLED.
>
> Hmm. Assuming all the other allocators using __alloc_pages are inlined, that
> should work. I'll try that and if that works will incorporate in the
> next respin.
> Thanks!
>
> I don't think IS_ENABLED is required because the tagging functions are already
> defined as empty if the appropriate configs are not enabled. Unless I
> misunderstood
> your node.
>
> >
> > > +#define pgtag_get_free_pages(gfp_mask, order)                                \
> > > +({                                                                   \
> > > +     struct page *_page;                                             \
> > > +     unsigned long _res = _get_free_pages((gfp_mask), (order), &_page);\
> > > +                                                                     \
> > > +     if (_res)                                                       \
> > > +             alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > > +     _res;                                                           \
> > > +})
> > > +
> >
> > Similar, the tagging could happen in a core function instead of a wrapper.

Ack.

> >
> > > +#else /* CONFIG_PAGE_ALLOC_TAGGING */
> > > +
> > > +#define pgtag_alloc_pages(gfp, order) _alloc_pages(gfp, order)
> > > +
> > > +#define pgtag_get_free_pages(gfp_mask, order) \
> > > +     _get_free_pages((gfp_mask), (order), NULL)
> > > +
> > > +#define pgalloc_tag_dec(__page, __size)              do {} while (0)
> > > +
> > > +#endif /* CONFIG_PAGE_ALLOC_TAGGING */
> > > +
> > >  #endif /* _LINUX_PGALLOC_TAG_H */
> > > diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> > > index b73d3248d976..f7e6d9564a49 100644
> > > --- a/mm/mempolicy.c
> > > +++ b/mm/mempolicy.c
> > > @@ -2249,7 +2249,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
> > >   * flags are used.
> > >   * Return: The page on success or NULL if allocation fails.
> > >   */
> > > -struct page *alloc_pages(gfp_t gfp, unsigned order)
> > > +struct page *_alloc_pages(gfp_t gfp, unsigned int order)
> > >  {
> > >       struct mempolicy *pol = &default_policy;
> > >       struct page *page;
> > > @@ -2273,7 +2273,7 @@ struct page *alloc_pages(gfp_t gfp, unsigned order)
> > >
> > >       return page;
> > >  }
> > > -EXPORT_SYMBOL(alloc_pages);
> > > +EXPORT_SYMBOL(_alloc_pages);
> > >
> > >  struct folio *folio_alloc(gfp_t gfp, unsigned order)
> > >  {
> > > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > > index e5486d47406e..165daba19e2a 100644
> > > --- a/mm/page_alloc.c
> > > +++ b/mm/page_alloc.c
> > > @@ -763,6 +763,7 @@ static inline bool pcp_allowed_order(unsigned int order)
> > >
> > >  static inline void free_the_page(struct page *page, unsigned int order)
> > >  {
> > > +
> > >       if (pcp_allowed_order(order))           /* Via pcp? */
> > >               free_unref_page(page, order);
> > >       else
> >
> > Spurious wide-space change.

Ack.

> >
> > --
> > Mel Gorman
> > SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGy_RrQBUy2yxvcZzAXO5cJU5BHxRko%2Bb8p7wWLjQwXvA%40mail.gmail.com.
