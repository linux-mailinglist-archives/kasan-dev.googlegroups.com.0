Return-Path: <kasan-dev+bncBDW2JDUY5AORBV7UQKHAMGQEUHECALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EADF947B1F5
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 18:16:08 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id b18-20020a621b12000000b004b0a6f9cf38sf4126568pfb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 09:16:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640020567; cv=pass;
        d=google.com; s=arc-20160816;
        b=o5oH2L+MaN0mTLc7a51j1FgdpGRuZqyPsgbCaZ/cnLc7dSrrWngjVBgwLIZnW+nltF
         casqExFLAjlshOp0qusEwfBojz9WlDoKeA2HrkTMcJyQyswTLtjAf+tbk4UBeKl6rAxp
         n6WyLLv4mqBv8KaClM0P0HVFAK2sRVsiBk3ro3uqeIoAYjKP/HJTRwAe3iT0y+JNxM2j
         WBTx1mK5N2QhdPnXjI+TnJKXt2wFpq5UTIgNd6emFXpORgfIzGhPrgPYGZWULDFuBuXI
         Yl8HHdF5fEWU/7+af2lGQtLTqIkeDP2ZThVjgc8Zl+tHakVgHpdVPtj45JDLt2LoSu7I
         vwgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=81+73dyrxWKUq5dAVKucCIl6bSw0BgrMaAlFQRPR0kw=;
        b=f6fSBoG4qVvLNLayBWYH1uNRMq1iFCxf7ip4eX6gCImaM3MqJ293WhX8C1zLXv8X0p
         8tLFk5SJeSMRBmQUXexVrjnZSkUrVbyc8gSjnrrmMrZ1jnlaQEn3yZOjeYOsB/4YgjjZ
         JMXSoyBFoN6WZNG5SrvYxppe+nDCxW1NnmmbqHJNRxG+Iw2xATQPzAlhsF4qgoMNI/mZ
         vm1MH+f6+WEZe2yf+EYzpA1K5EFbIQKgon/55h7hcK2sIliB6kVRHyHxVl6tKqzQn64h
         GeghrGtPIDDaux+87+d3PHWKlUBwsJoutkFr25esEL/wfvLD8fAztm2L/i4GO1crBwz+
         N+kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Za2uc0Zj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=81+73dyrxWKUq5dAVKucCIl6bSw0BgrMaAlFQRPR0kw=;
        b=mnQcfzx4iODunNjvfwoL/vwa8sKU2ZBiy5fzdyVhdOych1uXzC9kvb+Po3l2+8mDYp
         nIc1zaZ0kE/RwAOqT80XIhEFE7IALHM3yDMQ0D8g5RsiDQkZc2+s+6ZuTg6tXoZ3sYDl
         fFuXK8Ica0Vy+8nkwTqcbvnwZrn+r1Qij9qX1Rw0SLg61agDYr+VHLWdNe4AwOD/vinG
         GG1Kjrf03u0oCVgI8Ihu/wrn4lr3UB/RW9FlJdnvBmZcHwOs8Rp3U6mGeJnJmIYe0fFH
         9E8qtXyZRMW9IUqY8S2viMmVvUG5oWgW0sxZR6SXLNfvVpIZ6rXl/O+YNvbrqAEcG+8a
         BKaQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=81+73dyrxWKUq5dAVKucCIl6bSw0BgrMaAlFQRPR0kw=;
        b=nHRTBJRGSCpEj/820rgQ2hwL6beqoyPJ7QjIkzmokZqNxW9DdEScTsLJ2YmAwLxw6n
         8GHTqVp7mKWq7Wfon4U9JQypE586J9cvUYQUWTgJBEgGI+HPPlQG2qiuzIzNeTWGQ3mT
         khgjypjSu5WprRC3TmOKwVnYwm4kcgtAXHh6dn7vBCsIekldEYupqqAFzzf6prm9aBvn
         Bk5L7Sid4qJyN6nDQQAGd1K2/iRaIp263TBKBRzjqWsRFqwsohLdiqKcuJFIMwo6QOTX
         FJZ5eyFH4EwFUHdT4Rs43v32OcxCtI8YbCa5NgwGf2RxqhgeKU2WbIz28zQYeROyKlZ+
         kn+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=81+73dyrxWKUq5dAVKucCIl6bSw0BgrMaAlFQRPR0kw=;
        b=IsmeqhcoJPlxwjNdzvhlADnlyKtiOP9Ytg77Hjb324kETYy5eTL1zUqLSdAt0yK8Wv
         U4/P+5qRd1rHQy/ZF/Hzp7oZc6aDFM+DGp+qbz0HuVLqZmTwNS5W6IdEFsiRGWJOzxRe
         M/KvthYqTVyVAQsmHBjovCBVBV/VtvpGj7vJvqcaRtg5iDi9EOV+lINofZpFZ0u2qjav
         E73BwKhxHT83xaYi7XkLaazKxfog+lvmS7it8sexPVl0KFe2n2CcEuswn9scSyeMXDtR
         uqdb2UL3RykEwAkTY/h/CZUMWF22grHnhqpuOJa+Iro2sMQ+8pz0tbvll6059zdlWInj
         VLqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xz5A7stQBIu8cCXYNYhLMRSQSz71cx156zk5hCDqENzga1vgh
	1dS9w/4q0i09tCNultV52us=
X-Google-Smtp-Source: ABdhPJyqvNiC4GP0qNHK2yUvtm/4YqaAMO5317Bc7c1IdzKY6GNFA8Z8tD4oo1eo4v/pbN6Sx3aYyg==
X-Received: by 2002:a05:6a00:1591:b0:4ba:7886:a552 with SMTP id u17-20020a056a00159100b004ba7886a552mr17136652pfk.45.1640020567590;
        Mon, 20 Dec 2021 09:16:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:114f:: with SMTP id b15ls2418863pfm.7.gmail; Mon,
 20 Dec 2021 09:16:07 -0800 (PST)
X-Received: by 2002:a63:1422:: with SMTP id u34mr15780057pgl.135.1640020567051;
        Mon, 20 Dec 2021 09:16:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640020567; cv=none;
        d=google.com; s=arc-20160816;
        b=M6znt+BatODcL+NTunDhN8UbtFTJX/oscYCOdh6oQ/eD8ewlbd43iSvnnDtce56cJu
         C4eOcxQ7WujnNghFIlRkkf2D+6wJLIMkyD9wDdyCpBLZhi6YLOfnoMYhwsYvxz4Au1pK
         8AhXLDjWk5pwgc6/MJQeJ+5c3gFdVylfVajxkw/cZ/10U6svpvwKpqftmfm8ZZgDmE3m
         7TTr/41+pHPgprddJN+1/cVr/grAm1mKW3UMAn4DIqvZyeKF9Lx8r6hcSRISucPWFeGw
         6OHvjfTHK5NzUWQLbENWdeH5+pMeb0L60/p3HeeEvcjIx9MtrwXawgiURhZS6odH9p7b
         qWvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v5//0K87lk7Jc0WpZqUISoaFtZRXpKHfv2jyt4Plt/w=;
        b=c+3g1YAVgJIxwMD8OUZ5Hi5IGts5InHKlJ9dMRFm49U1RFjZSk4nZPnS0h6gHUoY3z
         SVpbxCmIGWh7fQbsKEFmgyQjc1gxb53Q4CddNjiLtJOXy4NKfJUtGGToD5OqBMxLP8fN
         08tcX3ZlWsMThDy2EMxC6ivgBVn6AcNX5te34Pi3y7z/OcyHaRAqoK/6kRFB5luuwck/
         5MxKXTTzbEqXLcuTnp4qX4X0he0CLhK+68JF2DmEhTrq9ROK2hvjnjybgDdiZiLjF8hQ
         8mKSw2wwB/0ZvHDOu2wxSWgnPKC/y4W5/Svu7Wk/VK92DgdzzgLW1+sMUY8XVFe8TM2x
         U9iQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Za2uc0Zj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id il17si56491pjb.3.2021.12.20.09.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 09:16:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id y16so14206286ioc.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:16:07 -0800 (PST)
X-Received: by 2002:a02:864b:: with SMTP id e69mr11110608jai.9.1640020566762;
 Mon, 20 Dec 2021 09:16:06 -0800 (PST)
MIME-Version: 1.0
References: <a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl@google.com>
 <CANpmjNP11JKCEE328XomcReP7uBwZ=da=SD5OS09N4co-WPhMQ@mail.gmail.com>
In-Reply-To: <CANpmjNP11JKCEE328XomcReP7uBwZ=da=SD5OS09N4co-WPhMQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 18:15:56 +0100
Message-ID: <CA+fCnZcMWA_VT83dXqD-bFJGG073KWPnULAPYK1=BhQkGsHzUQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix quarantine conflicting with init_on_free
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Za2uc0Zj;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 20, 2021 at 6:07 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 20 Dec 2021 at 17:37, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > KASAN's quarantine might save its metadata inside freed objects. As
> > this happens after the memory is zeroed by the slab allocator when
> > init_on_free is enabled, the memory coming out of quarantine is not
> > properly zeroed.
> >
> > This causes lib/test_meminit.c tests to fail with Generic KASAN.
> >
> > Zero the metadata when the object is removed from quarantine.
> >
> > Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/kasan/quarantine.c | 11 +++++++++++
> >  1 file changed, 11 insertions(+)
> >
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > index 587da8995f2d..2e50869fd8e2 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -132,11 +132,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
> >  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
> >  {
> >         void *object = qlink_to_object(qlink, cache);
> > +       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> >         unsigned long flags;
> >
> >         if (IS_ENABLED(CONFIG_SLAB))
> >                 local_irq_save(flags);
> >
> > +       /*
> > +        * If init_on_free is enabled and KASAN's free metadata is stored in
> > +        * the object, zero the metadata. Otherwise, the object's memory will
> > +        * not be properly zeroed, as KASAN saves the metadata after the slab
> > +        * allocator zeroes the object.
> > +        */
> > +       if (slab_want_init_on_free(cache) &&
> > +           cache->kasan_info.free_meta_offset == 0)
> > +               memset(meta, 0, sizeof(*meta));
>
> memzero_explicit()
>
> although in this case it probably doesn't matter much, because AFAIK
> memzero_explicit() only exists to prevent the compiler from eliding
> the zeroing. Up to you.

I've thought about using memzero_explicit(), but the rest of
init_on_alloc/free code uses memset(0) so I decided to use it as well.
If we decide to switch to memzero_explicit(), it makes sense to do it
everywhere.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcMWA_VT83dXqD-bFJGG073KWPnULAPYK1%3DBhQkGsHzUQ%40mail.gmail.com.
