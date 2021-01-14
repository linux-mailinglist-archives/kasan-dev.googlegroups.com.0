Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5GHQGAAMGQEPKFYUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD6752F64A5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 16:32:05 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id v21sf8993359iol.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 07:32:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610638324; cv=pass;
        d=google.com; s=arc-20160816;
        b=FT6tGz9CLOtH0eJwRETDP9ABTBpqSa9gBMPMNSvwRwTOQtuN2LmQRtAi6lpewM4dUc
         uS9xS7WYnvDimQ1H8Zef1h64z5MKTmZj2EsaB7Y29JZmcngaW87Gzj/3UuWH1SG18P/D
         2UT8kqmAZykFf5EfQ1LPbBSfEUFfahwIKkQA08avR7pQ/g8GgtQmOcdloqNkZOwG5wNd
         q17NHpfTPbiERRhcrwpR0UxWCqIlHY230I83s0RQd4Vii7wUywmQtH6hLNkgbEzJCI8v
         0bYgwHlS2WZFh9uMDVwgQkziR6Rb8WxAglemKVdrBAPfybp8QbKOLrqaBJsIS6kSu/ji
         M9wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S3msy9wGQSsV4jXUClEhdnFzU0oKfBWnwywqhs5dBKo=;
        b=TXjptnZZeRAzUVggIEGdai6uqdTEZWx6fEtkrR/P14kWKRdF9i6LgG7d9hyB7CngLC
         1Qsyx+0sTUCu2dg8UwdVJlynK5N5VZ+RS7undpfRfHD0GX0iA2UfYvP1ce5JjGA8qkyK
         4foSDfYKmFPJtekZXMrEQibDj2QZUwDreSUz55c9KAbSB/gBNZUcPesM+vQVXcBCj6W6
         V02viWLkG/NvdsB1FOFcXLERJx2YR5F2SxBEZUYhpNIcYvgrQRxuGTbsWdplQh8ekrUh
         wAdd/lMw+6h/YhQuL8Of8L1hPqE2GzVPyI3gGjPxgQDm8CE81H+Q/RZNroMH5jV0ve5R
         pTFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tkj04O8N;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3msy9wGQSsV4jXUClEhdnFzU0oKfBWnwywqhs5dBKo=;
        b=otPk5GAMj4a6A+vJ16ywcMgapeCgKkgp4SQEOQBas89yk9TBo0iao7U+tuW0IbMxei
         TFq8XHyQH7EAAA1O51FWXZHoeFJG+bUjG+NL+NOHAR+SW3BditJ1pIq3k7/8rj26ghJf
         ILAuBX0dus/e9FUgdUW0dCnFcuwdvTfxEb7ri0BI+gJng3qn2cD37x4OclaFBMjQh52s
         teRsT0aMORl5CCQH9xC0/R9LhcLV+BOIPyhXb8bQk2sZ7M/+OiPgdsxaTLCygI6wOJTT
         6zMQDvr/vDKilixwwACu3wwsqo2Jk1oAScuNkxnUrKp2CKwils2GvtbqMyaVEy1cZj29
         vJJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3msy9wGQSsV4jXUClEhdnFzU0oKfBWnwywqhs5dBKo=;
        b=S8MfzVju2lv8LjaPC3lucBV9JYzOWVYcR8fDCjePyFX9/l4ZwqzapLsbLp6czQR2X9
         snTVtFrZXMT6YuXnjtP3srhrKQz/W6GEJX6nazvomPFPGrQW4Y2uFKRJkNp1zgxSbtLh
         2+IGeK8msLYt5Uhcaj3BvzEsEU/hLL8mUXLcgtqtGG3Ixt20QdE71oBC4NsxlIAxF7lh
         wZom/17WVdHfpp6xOx9qo5Hsi3RoBwpo3N5+sYZs6Os0MSr+BAaBZOxOfU23GF45ypxa
         4eV+iIW9kRqZ8+Ucm09TdovldBqw6mIPlvTo76BE4BBEgtlMT7Svp67EkLR971dLIWge
         iEnQ==
X-Gm-Message-State: AOAM533qNCJI3hhAXT5WOuYYR3gJRDVZ6C5fpUqOGdEu7ajicq4x/Cfa
	2mwsSZI7Ih0Eao6lKO+xrkM=
X-Google-Smtp-Source: ABdhPJy2+66ShpvFS/wzYVgn3Vd3cjLlZQv6GI+A8aoCP8bc/gMgWIvd8I+2JjnWobpU3uge9M8fKA==
X-Received: by 2002:a92:d44e:: with SMTP id r14mr6991193ilm.299.1610638324633;
        Thu, 14 Jan 2021 07:32:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:25c6:: with SMTP id d6ls883673iop.8.gmail; Thu, 14
 Jan 2021 07:32:04 -0800 (PST)
X-Received: by 2002:a05:6602:2b01:: with SMTP id p1mr5504079iov.156.1610638324201;
        Thu, 14 Jan 2021 07:32:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610638324; cv=none;
        d=google.com; s=arc-20160816;
        b=jGoJ9baeoPApTZCxJzyXQV9tQLd+oQGCUZ85e2cmSepJuYDtxUFkGqixmBhsX/EpAf
         mTjc+nMKL+EqvGW7sPdRNuhDdZFXi496jQhE/yBelSSmB8VSidcwHNdUZCQAmYncjnLs
         fLK7xfmBEO3QMoshS0K4/0tPRPBi0o+9laiAczQxkHd5akYWDJk8nRH2h7S/LsZqXSa3
         XCHRXtyx/ystX4x/CLU/pjjqPbeJbrY3GJ2Zh31co8M14UKCmzz+8dWQqUYJ0ZsZ7TDY
         s6qvbPYC7ZlH0MLrzug+zOOGiSMLTtOqhX1+je5xtcWvm7mNbtqBL1pECPu2Y5Dtn7lr
         gZsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b1a4WcSAwlYzo0UVF2lRgmzbjdobg4wJJNHBjscc+aU=;
        b=X1MjsSCLkbdipuuoRARJC0MloLR/DG4/WdAQsCFKTFTVd2p0K9EobP4zw/tRNz584H
         kz/0Rh8Vp/nlu7NaOteQwYpm1dVrzf6yCdD74uM7rDyFApZMZNd4AtWMG3uPTBLES7yK
         LDUVR5+WxQI+qB1cxh8WA6d4q0gCcbWz0c4HNAHL23ZGTYQxBE0KSmWMlHw9NHioJW/w
         VNnmmzU/oQC3oYWL8CimQ7Z/MALSrwpHg6DazJzNElZjxn5LgMBmKLuBOv271cQTxWz2
         t6/l36r1kCh8SSk80KlzVeCit2hAU5b+BPVc5I336v5fsi1cz347MaU/ywud7Or0XAu1
         q0tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tkj04O8N;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id f8si469628ils.4.2021.01.14.07.32.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 07:32:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id v19so3984388pgj.12
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 07:32:04 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr8086639pgk.440.1610638323387;
 Thu, 14 Jan 2021 07:32:03 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <7fbac00e4d155cf529517a165a48351dcf3c3156.1610553774.git.andreyknvl@google.com>
 <25aa25d6-080c-ccfa-9367-fc60f46ff10f@suse.cz>
In-Reply-To: <25aa25d6-080c-ccfa-9367-fc60f46ff10f@suse.cz>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 16:31:52 +0100
Message-ID: <CAAeHK+xgdS+vSTN81uLzahB9BYf=+iJdckwS=v7AwRACAf0wfw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan, mm: fix conflicts with init_on_alloc/free
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tkj04O8N;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e
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

On Wed, Jan 13, 2021 at 6:25 PM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 1/13/21 5:03 PM, Andrey Konovalov wrote:
> > A few places where SLUB accesses object's data or metadata were missed in
> > a previous patch. This leads to false positives with hardware tag-based
> > KASAN when bulk allocations are used with init_on_alloc/free.
> >
> > Fix the false-positives by resetting pointer tags during these accesses.
> >
> > Link: https://linux-review.googlesource.com/id/I50dd32838a666e173fe06c3c5c766f2c36aae901
> > Fixes: aa1ef4d7b3f67 ("kasan, mm: reset tags when accessing metadata")
> > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
>
> > ---
> >  mm/slub.c | 7 ++++---
> >  1 file changed, 4 insertions(+), 3 deletions(-)
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index dc5b42e700b8..75fb097d990d 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -2791,7 +2791,8 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
> >                                                  void *obj)
> >  {
> >       if (unlikely(slab_want_init_on_free(s)) && obj)
> > -             memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
> > +             memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
> > +                     0, sizeof(void *));
> >  }
> >
> >  /*
> > @@ -2883,7 +2884,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
> >               stat(s, ALLOC_FASTPATH);
> >       }
> >
> > -     maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
> > +     maybe_wipe_obj_freeptr(s, object);
>
> And in that case the reset was unnecessary, right. (commit log only mentions
> adding missing resets).

The reset has been moved into maybe_wipe_obj_freeptr(). I'll mention
it in the changelog in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxgdS%2BvSTN81uLzahB9BYf%3D%2BiJdckwS%3Dv7AwRACAf0wfw%40mail.gmail.com.
