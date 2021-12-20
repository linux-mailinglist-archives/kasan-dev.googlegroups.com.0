Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNPWQKHAMGQE55CP3UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B37347B201
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 18:19:50 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id c22-20020a9d67d6000000b00567f3716bdbsf3511698otn.11
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 09:19:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640020789; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2EZk0xS+WZUQGgeAkY4yW/HrDkypFh76debHeaFEMfybdcgEYRWfuaz/W771dQbm0
         vFAONl9QYWp47ySmVIjq+Xz+yApiloz93M2FKC+nC50VX/j+E4LZo5/L6lnKfI4Vz1qD
         z3rytGSUAAC02pGpHaL82oLAFs0Czypy/PKiUrpx3OZKATBjlJhAzb9ige7YpKiEAEkP
         abAZde4oR29LADRWlAEkQHLbKvVi8ZDf4PcUczsRDSldzV3PxSkd+4otD8tjxTFfZgw/
         SeX5Toxeurni55LRCzqMhPGP0PeEnigxvu4LGjPbjU21q0O+x8Z4KYRpSzOa3CoU5Z9V
         +44Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5+xwFwg27tDUKys3NNkE+sFGcS3BhSm5CyHUXiR6WuQ=;
        b=Hb/w+PrdM3l32DhDyO27XU/4lKKk81vuCiIKS5we6Z/wPxsB/OH4scFt5o1QKKrv8I
         S/gELMXv7YScOlQlvDjTksmCAugQiJRORh+wXGEFTwH4+nnkwgf2kA6kcQppHEqEq8+i
         gTVR95QlWUKS89My2gRNxDygDblx3hsEH8XrJMyadOOooJwgCjKJK0RR0qP7OqjQ4L2I
         behY4HPt27fLi99C//flfXX1V2BNpwjTE1YP3PY4vL9cV0oXBcIxW72hg6vuc67V+Vfx
         jJFsKLUj+Uw5hveUkjL7B9bx4OZki8JERC3t5r28Ez9XWLQX8i+FGhCxAW9dIadZquBN
         uDfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVrue8Ou;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5+xwFwg27tDUKys3NNkE+sFGcS3BhSm5CyHUXiR6WuQ=;
        b=MOgnbNVuwbsnPLP2mtdHPo6T0zgBQnJ+4SKXfwP0cznJW0rdfFI0JFcmZ2N/pS/xBs
         nwqPxK7J1P7/3nkk1IHjwr6NGFVtPl9TFF69A5lt7wS/fGtwsN7AlXZc0qs+XmOCnubg
         5emHvoiRWOSgxRTK2l6UQRvzphCnuVqicEg7XNnlqghSoUgSg4N2lMImDxFePFZ0BqmE
         NjvJNOW4XkRYY+T5bb+PSADlV1lHzMkt9R8T5hMyqVOjCUS69NM1yarn/vbKZnTRaeah
         oebOivuoroM1CTDGBpPS9N0z5W1hPB9darhPVQPqekGNXHLu0BK7pnc7KU+k/Qx4rmZ3
         Xp7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5+xwFwg27tDUKys3NNkE+sFGcS3BhSm5CyHUXiR6WuQ=;
        b=nSlcJyHDRjrampsgbPlPQ95d21yInQxQhZkF6qnZimHbTlvIaN7YrKTgAWznHH9ymI
         YIGJBPVENkynWTNJAIHzF92h6Lh9SVcxXcDa1R+atAb3GMqcXu2khP+uLX3CiWBY+cEU
         koXDVPq2m63pB/iyRWJT15B9KNjbl38pX6WJ8fJ9etzwfJTi+a9fjObKOB4wDIw+7B5Q
         cg5VXDvHOS9DpWJy6k57SQ2vdcJU6Si7PydnQKGrdU1ZoSCqBaAu4hCm/BS1XGO+uBYm
         H+D7zWdx7Q8/zlYyPzBZXIVnpxkxTXLWVHzvQKGAdnNcgX+HetyFe3htQGrtvJScH9nz
         2Gtw==
X-Gm-Message-State: AOAM531z0MDzJ6i1OE4qagRAsi+i+MU8QuRuWZ9uedClJ4hOWafXLdRq
	9gTA3q0k+c9AZYEYLKEXTnU=
X-Google-Smtp-Source: ABdhPJy7Ab3ROdgYOnSRw0lCdqIciNphQKghfyhASQREHRIJ3V4GaSSRGrv7o88LHZ9lgf1tsCozOw==
X-Received: by 2002:a05:6808:210c:: with SMTP id r12mr17793178oiw.104.1640020789452;
        Mon, 20 Dec 2021 09:19:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:25cd:: with SMTP id d13ls2632331otu.11.gmail; Mon,
 20 Dec 2021 09:19:49 -0800 (PST)
X-Received: by 2002:a9d:68d9:: with SMTP id i25mr12398072oto.189.1640020789045;
        Mon, 20 Dec 2021 09:19:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640020789; cv=none;
        d=google.com; s=arc-20160816;
        b=OpMOs5MzhzHG9dxzlAiWw+4aP3rcJLkvvZOcqzG8Es/uOYbGnPv700Q/ecE2AJ6aIw
         OVovRwDByoXvpE4K3CS9jzPrLyDrNxJLWnTJNLBQEuBPSuZkiLH9/aK5hi6Jx95VXk7D
         sRwtbfjgriT3r+5zsgSalFQJ20NvostcgUZLgrsIsmGLOEiGBHLB42SvgFBkDb0KYdDH
         +xenADKuACc5PfAgnyWxhO9HffEFZwKNVEiDRfx7zMdorMkacR5UdAKLK07zi965qhLa
         BBAhhtwWsEbfhj4DRg8m0f48YJ42X/V5eA6syX04aK/r7xjVo/8h5wvUgafTma0xR91+
         2v4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ilrvhX4adeXJIaCdTInuQBtNPjTZg76k+bbb32ZDvfA=;
        b=miz0Hhc3E1T9fyUt/Fx4c0oCRy28ie1+zEaG7np3fnKBc0GEpQUKxbnhIMut3J2Sjd
         Yx6GnfKBst3Y00Hqm36Vih+lFbMvlPXOu6Gu+3c6ibbKEq2kKssORrbtSNPWnLFWF6zn
         9RgWVv9uHOQ8nxt9s1mHBz4AFmnAsdbiH0YKdEnsHIu4zN7SXnHHzc+6R8bxcnQcuFl6
         i9q0pIWPrQM8ukcMaQsZtTkJQ4X/PEVmzkBBxIgVudE2+uZUBONp0SplMrJHB9F6vU+L
         Wo7S6dztZLL/74BtXOPJynRVpzoSqQE5HUWMkIlx/FdKc2uXgVveidwb5fxsRicgbzgj
         l6+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVrue8Ou;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id u27si1502161ots.2.2021.12.20.09.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 09:19:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id u74so16799073oie.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:19:49 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr13111576oie.134.1640020788502;
 Mon, 20 Dec 2021 09:19:48 -0800 (PST)
MIME-Version: 1.0
References: <a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl@google.com>
 <CANpmjNP11JKCEE328XomcReP7uBwZ=da=SD5OS09N4co-WPhMQ@mail.gmail.com> <CA+fCnZcMWA_VT83dXqD-bFJGG073KWPnULAPYK1=BhQkGsHzUQ@mail.gmail.com>
In-Reply-To: <CA+fCnZcMWA_VT83dXqD-bFJGG073KWPnULAPYK1=BhQkGsHzUQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Dec 2021 18:19:37 +0100
Message-ID: <CANpmjNOgBVoUiqK809CsUzo_eb_04+Vh3w1GWxS+VLAh7JBk9w@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix quarantine conflicting with init_on_free
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oVrue8Ou;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as
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

On Mon, 20 Dec 2021 at 18:16, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Dec 20, 2021 at 6:07 PM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 20 Dec 2021 at 17:37, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > KASAN's quarantine might save its metadata inside freed objects. As
> > > this happens after the memory is zeroed by the slab allocator when
> > > init_on_free is enabled, the memory coming out of quarantine is not
> > > properly zeroed.
> > >
> > > This causes lib/test_meminit.c tests to fail with Generic KASAN.
> > >
> > > Zero the metadata when the object is removed from quarantine.
> > >
> > > Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > ---
> > >  mm/kasan/quarantine.c | 11 +++++++++++
> > >  1 file changed, 11 insertions(+)
> > >
> > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > index 587da8995f2d..2e50869fd8e2 100644
> > > --- a/mm/kasan/quarantine.c
> > > +++ b/mm/kasan/quarantine.c
> > > @@ -132,11 +132,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
> > >  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
> > >  {
> > >         void *object = qlink_to_object(qlink, cache);
> > > +       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> > >         unsigned long flags;
> > >
> > >         if (IS_ENABLED(CONFIG_SLAB))
> > >                 local_irq_save(flags);
> > >
> > > +       /*
> > > +        * If init_on_free is enabled and KASAN's free metadata is stored in
> > > +        * the object, zero the metadata. Otherwise, the object's memory will
> > > +        * not be properly zeroed, as KASAN saves the metadata after the slab
> > > +        * allocator zeroes the object.
> > > +        */
> > > +       if (slab_want_init_on_free(cache) &&
> > > +           cache->kasan_info.free_meta_offset == 0)
> > > +               memset(meta, 0, sizeof(*meta));
> >
> > memzero_explicit()
> >
> > although in this case it probably doesn't matter much, because AFAIK
> > memzero_explicit() only exists to prevent the compiler from eliding
> > the zeroing. Up to you.
>
> I've thought about using memzero_explicit(), but the rest of
> init_on_alloc/free code uses memset(0) so I decided to use it as well.
> If we decide to switch to memzero_explicit(), it makes sense to do it
> everywhere.

memzero_explicit() is newer than those existing memset(0) -- new code
should probably start using it.

So I'd opt for just using it here. Who knows what other optimizations
future compilers may come up with.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOgBVoUiqK809CsUzo_eb_04%2BVh3w1GWxS%2BVLAh7JBk9w%40mail.gmail.com.
