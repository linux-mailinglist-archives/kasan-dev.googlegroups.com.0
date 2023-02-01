Return-Path: <kasan-dev+bncBCCMH5WKTMGRB55E5GPAMGQEPNXZKVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id CC5B5686595
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 12:52:25 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id b10-20020a5ea70a000000b0071a96a509a7sf5457025iod.22
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 03:52:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675252343; cv=pass;
        d=google.com; s=arc-20160816;
        b=HrGLYgXkso72tgfJ8hsPTeBeolrh9ja9F17S6lPMMFYwdPdaWlsI9V0Z8kSB0HZ7Cr
         b3V/ol7FvDxztT4VYjl2C9WE2EYp0kocGYpMN9T4L5FDt7ClOXX6pQu4L1BUYPe6k/DS
         PCC+NvfbZuIXdmMVq4cP9yjlnCiC5yNNhMx+lhzN64iu5dEQwr+eqtd7BDuBg2wFAFod
         848vrYFvISvF4f4UBujdhELSfRuzBJxIiGkCniEaiGbzr861rCoNL8Of2qP5PSxVILVI
         94XoU7zFT2WQHgGWBRv51yjBP0UKDjzjhVJNKE/k4tVdQCGI3MS69Vb6Pc4Ga8fMPOWm
         sh4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aQlWjYa2N0rEoM/SdfQqB7ojuEzsd8w29+785q5+Z6Q=;
        b=UoW7UAemn20yMzx/V+XpDzsf3bqJb9eXWQBct76+GcHdxnfbJ2nEHPb/vFrYu5a6BO
         48wy8Gje8F5ylPrleRcYmZ5YRKDr2xQtAdKv5E+hbRtwSgpIvoCqtb9CpfYLYxzP6jmC
         BQHU2iJWw9FspfWNTNhpv0icWB0Rwsd2r00kB+3+kfXwOv2CLD2mksOZ9KFKYKOOeL6v
         GqF2vc3KrKo8YEyPzA27i4KrzvCjsJdkKS3Z4gvIg0/rwuAm9Idbs+J5dWH/gVC4c+pc
         wgGHM02HqkxBgRFFgFvpQujvw4AFiIf3Iyn656OsIwDr5HJ2F7r2N4pUCLUg9DFRhMry
         6faw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W8qEklfT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aQlWjYa2N0rEoM/SdfQqB7ojuEzsd8w29+785q5+Z6Q=;
        b=A1vODwCDLoaKQFGcZD0k5ovkNFo0n5OSDGn+rfgnwPGY0JbcMMNgYO71s7ufC3POUh
         dwqKABbXcwvy06TBh8LnJSadlhDNLs4nwhcq8qLU1uQB+9ohjpKiFD767kkbU7wjmeWE
         J4huoT0kunMqxXj5fRd6j+ZfEVxHqacf2oRrXvZGL1BTB5xJn2v6ZM9DXO3CWBbnVafj
         103p6CukrpCW2GmR+idhYml1RBiys/NMtZd6DKL4VmbSbvxunIdpRdZxDmB6UlVjy+C9
         s8OeAA90af/FUIiLjqUOghRvUBUFgMfv1MzSTLnYbKpG58RoHjT3gy2y2G9JAPBFDNtG
         X+aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aQlWjYa2N0rEoM/SdfQqB7ojuEzsd8w29+785q5+Z6Q=;
        b=DvEPGF7wBuV1v8OiFlMdtvl03E3bdHNUp5+ye4DVjqZBvBMjha+2MvXLpmWW2lJLrw
         7kZ1bwrqIf4Nrglp2tSysyUU+qbtxfqqhodpGWiPxHlO2++VhbC774C3SLcY5byD+6Ok
         U8jPJFqiLilrxor1TtnBBIA/h7zhzdyvxKTR7ITq3xNZfcLpjCFgurnTibm9Eax/AJl+
         pefH52aikzX3T+m6FC+CQ6BlqpKIZidsaroSOI9NEbUzNvBH7tJ4+YZ9OIeJBWUxY13l
         ORirScYuiNnMig6OUYWV03ajh6NeF0GpLAv82niQ43tCGwPo0JKs+NZHAIyWZcLADQ5F
         FFdw==
X-Gm-Message-State: AO0yUKU+HYwgMvLQGUf4F/G2PrIK1aFZyJMx8MGdEAGLGZL1DpV5SZOI
	gwHVHgK0kCAJwiKr3x8Qj6w=
X-Google-Smtp-Source: AK7set8B0g7l93GKN85k+lCN8e4TD8duB0Ekfm4wXz3Z8qZPL7L8uqJU19mjxbxDkKHp18XhcW5QlA==
X-Received: by 2002:a02:ce82:0:b0:3b4:a974:4af8 with SMTP id y2-20020a02ce82000000b003b4a9744af8mr462819jaq.19.1675252343209;
        Wed, 01 Feb 2023 03:52:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7c04:0:b0:6bc:6044:840e with SMTP id m4-20020a6b7c04000000b006bc6044840els3797831iok.0.-pod-prod-gmail;
 Wed, 01 Feb 2023 03:52:22 -0800 (PST)
X-Received: by 2002:a05:6602:2149:b0:718:932:945a with SMTP id y9-20020a056602214900b007180932945amr1224771ioy.13.1675252342660;
        Wed, 01 Feb 2023 03:52:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675252342; cv=none;
        d=google.com; s=arc-20160816;
        b=AZiFOI4oVpB93FTFTew5ocI4GBQR7bgjPGeXkd9d8YPZTcZep/xbc1oy5DqlQCsrBS
         QVjvecuoH+l+f6XaZY23mf/AINuU/VqSMfFV91pLitKL12VmH+pIw4hyPrJIhdEx3YlC
         q+02b1m6GCoEA6A+HF+/0GNecH5PhpDUSDgUkPvyOgrUxhZKT40qUbeZX5prqD42DBMh
         OCARUY28/DlQYFM9pJDfH5TMMHibs11wGU89ivnq7gp7PWGMeqnHg/xjtLY9hZhvHBR/
         PrxRU72FlTEfMZAKfI3WE66mEatqhqKwQtPcLwlNinX4AZM8gw1kJQ9M7/9uaW2cWiE0
         j31A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CGX+681ImZAUmW/DwliVbohDwG+nNs9QfeFZlVbxCEk=;
        b=D1yjbN6rtWwicrvDKvdGr9VH66FedQCOtKGO4VVIwTmN429z5jwPhv7teFlKCKTnAx
         /8Wh+714O2lbyTZ0R5kotxlWQ9qXC6P+yKBNp/ObWvdex2JGlJnXjbAeDg6VZxFQGJLP
         /zH6qVl/7+y4PAuREQSHzXHAvKNBVlYoPkC5tgnem/yXkSK3CD6Png8BHXmSGpkRs/na
         z+gHo7OZmPDguL67dkLTkOBLHAs/+oOJPaMAog/HxGJVZ63PcKnHuKhUtMHJxrqbLAOg
         Lz9nqiip91C4iMS+ldRUEfI7qzceTRxv3e7MukZmIKqQAr9dgC5E/FmX3JDu6WtrO/8x
         4FyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W8qEklfT;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id f24-20020a056638329800b003b1f379322esi695214jav.6.2023.02.01.03.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Feb 2023 03:52:22 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id i188so19316564vsi.8
        for <kasan-dev@googlegroups.com>; Wed, 01 Feb 2023 03:52:22 -0800 (PST)
X-Received: by 2002:a67:fa01:0:b0:3d0:a896:51da with SMTP id
 i1-20020a67fa01000000b003d0a89651damr382789vsq.44.1675252341983; Wed, 01 Feb
 2023 03:52:21 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
 <CAG_fn=VO0iO4+EuwDR0bKP-4om9_Afir3fY6CExKGRNad+uPLA@mail.gmail.com> <CA+fCnZfjbHaS9So6gO_3ZkgLazJXYAtw-PNV5C0xhAjzVE3p-Q@mail.gmail.com>
In-Reply-To: <CA+fCnZfjbHaS9So6gO_3ZkgLazJXYAtw-PNV5C0xhAjzVE3p-Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Feb 2023 12:51:45 +0100
Message-ID: <CAG_fn=U-r7Pb8356Uio69zmy5FDQp6nCs6eM2TXcnXaaR4_hMQ@mail.gmail.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=W8qEklfT;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e30 as
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

On Tue, Jan 31, 2023 at 8:00 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Jan 31, 2023 at 10:30 AM Alexander Potapenko <glider@google.com> wrote:
> >
> > Wait, I think there's a problem here.
> >
> > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > index 79e894cf8406..0eed9bbcf23e 100644
> > > --- a/lib/stackdepot.c
> > > +++ b/lib/stackdepot.c
> > > @@ -105,12 +105,13 @@ static bool init_stack_slab(void **prealloc)
> > >                 if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
> > If we get to this branch, but the condition is false, this means that:
> >  - next_slab_inited == 0
> >  - depot_index == STACK_ALLOC_MAX_SLABS+1
> >  - stack_slabs[depot_index] != NULL.
> >
> > So stack_slabs[] is at full capacity, but upon leaving
> > init_stack_slab() we'll always keep next_slab_inited==0.
> >
> > Now every time __stack_depot_save() is called for a known stack trace,
> > it will preallocate 1<<STACK_ALLOC_ORDER pages (because
> > next_slab_inited==0), then find the stack trace id in the hash, then
> > pass the preallocated pages to init_stack_slab(), which will not
> > change the value of next_slab_inited.
> > Then the preallocated pages will be freed, and next time
> > __stack_depot_save() is called they'll be allocated again.
>
> Ah, right, missed that.
>
> What do you think about renaming next_slab_inited to
> next_slab_required and inverting the used values (0/1 -> 1/0)? This
> would make this part of code less confusing.

"Required" as in "requires a preallocated buffer, but does not have one yet"?
Yes, that's probably better.
(In any case we'll need to add a comment to that variable explaining
the circumstances under which one or another value is possible).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU-r7Pb8356Uio69zmy5FDQp6nCs6eM2TXcnXaaR4_hMQ%40mail.gmail.com.
