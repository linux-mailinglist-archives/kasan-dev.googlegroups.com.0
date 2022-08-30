Return-Path: <kasan-dev+bncBCT4XGV33UIBBQMTXKMAMGQELGGBRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 418155A7058
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:05:55 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id z14-20020a170903018e00b00174fff57d17sf2877808plg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 15:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661897154; cv=pass;
        d=google.com; s=arc-20160816;
        b=d1kOMbWVE9vueazj9K5Zj4MzaqWGPbRIg/xuS4pfWtuk+0e9a2IwMj/g3HAFBcri9L
         UzZafOeo/k6U60KgDgm/HfccKVJOIyE6zkW15UxRRPqxVndUWfiLKRYCbxRyVrKllqu+
         HWZHDqlTnuwSAZVlHIYncOBqWQ8FccHx6cAR+LtBP3CRB5JwcbH817UlqaBU5tGFkao9
         6jocCZl8u5BVtkuuBi0nXPrR/Vy+hJCSdUdb3eY0Ewzjf1eQZAyCzp22kZq4XLjOQsHU
         XQO065hfe3IFtxC5jrmoTRp5DZHXzWWGe/JPsBUi5csVNLdZUOLdpiBv756ey9nR5ILd
         UIGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=WhvtSfYi9Sua1KW7J62cKyl1i5WKGRytFqUvCn/v/LE=;
        b=XxuEehjobysPOMAqY3LD3VDGU4seSEwHb6rjDMxg4DtWto4F3V6RYNOiUkKAhfXX7S
         Uztskq1+8nEqgb+jopDtcA/tdEKTBVGWHskl5r5ox6efRczFnQwWBvtNd5LU1l2EtL9C
         rmCA8dpE4N/LOGsEQ34R2I18lgMq5uYPt24c2UbyRJMUbKtwv+8Bo68HBaoEmx0KOgSb
         c4z5wHAy3KKpAmeJcGvs9sbmE1RRluM9cN017bhWq9ZKIwXJNnHM5a7DHiiqAgJ+sSkl
         u7+szaHLam8t1eV8+k5XsQ8cTNnChi20X4DekeaEMXmYez7GSgl8mOqJGUp5i0XwPnMU
         dhtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zdXxZEBC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=WhvtSfYi9Sua1KW7J62cKyl1i5WKGRytFqUvCn/v/LE=;
        b=RjBn1e57qyQa51cS3xatkuOzf47ogSuz0tTK3Augtg89P0iHTVOW7iq4h6YEDban9P
         Q5R2G/gM11YSf/3rzM+FpoGYpOq/zpWAqJV9d35SbNw6LLZ2cmVzBg72W60R3Lb9YeVv
         ybU3G3Gu/lTfb4xKOUIbxugsdtM6ui2n4sN7Y/LFqlJaXQ2GZ8dZgCKoiq0CD6eUq7Mu
         rpv7NcNSmfJCcXCdz8FLJgGvgOQo6pmDRGNVzfU52lb3iqJR0L52O60HcsAq2iboZfSk
         PjNW4mbTauz891IEvq/sKbQhh38gKkpRO/0JiGx+/Mx5FxZZfyf+umYJsLjrX/n7YIXq
         aW0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc;
        bh=WhvtSfYi9Sua1KW7J62cKyl1i5WKGRytFqUvCn/v/LE=;
        b=UnL40UjAbYJHrjRWx3K9qoLXXxsSpJRsnh47+3/3XZwHLGuz6vEzZ5dF49g8i2FSFR
         +q4NwhhAwKZhRcWxYeVfT+BCk5ipgdz+FAGBbFdpUtZnV9RUa0nN1w+ucf9NLaj8l/kL
         FBSfvVvLI/mdvyKPVx17T9+I9sSrN3ZMwlm43ZndaFlf1c7PQydYsJU3qRBtyRFWk1pN
         8jV8cLREVGjNBVaG7RjDyWvIei3oKGHDY13FFNOHpsb3asFz1imSYtviIwrAdqDDNi34
         d3ErXjM/M4sekTc6BrIVYXKoAMc1K/LY/ukrAve6Zn9s5+v57Jv4+Y43P8KdumS+MtNo
         TvOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo21nCeqx9Hdn+1unw0hstbqP0YI7lV7pM5jy3itkT+dU8NeXrr0
	R3C75hRfJ22E95GvJnDOFpA=
X-Google-Smtp-Source: AA6agR4tBNhkh4W5/O4cEYcHQNV4fPD5gfhpiOpJwn0mJ2Vgnw9O5+Ge89d1xnNavU9qw8F31OoUSQ==
X-Received: by 2002:a05:6a00:22c6:b0:52f:4d67:b370 with SMTP id f6-20020a056a0022c600b0052f4d67b370mr23709360pfj.58.1661897153868;
        Tue, 30 Aug 2022 15:05:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6f41:b0:1f2:da63:2f68 with SMTP id
 d59-20020a17090a6f4100b001f2da632f68ls2288372pjk.3.-pod-prod-gmail; Tue, 30
 Aug 2022 15:05:53 -0700 (PDT)
X-Received: by 2002:a17:90b:3911:b0:1fb:1f53:fa5 with SMTP id ob17-20020a17090b391100b001fb1f530fa5mr91866pjb.233.1661897153001;
        Tue, 30 Aug 2022 15:05:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661897152; cv=none;
        d=google.com; s=arc-20160816;
        b=YmiL5cSMTgvjOAI58L98ZPHsGt3CwlD9iJrjfqsx5fSaaM3dBpiw6whrnlzASFw9pd
         M833jVqrBBQ97TH/4eNYFm38PmVgBxKwakefR20Gf/Z1SUUKukBVTV104sp0wK+B1+5y
         s9svTk6+QXOckTnMPZPGDfGV511IJ94aQy9cu2uai4uXND71+may64uut1NeRVsl5jH/
         6uz7Moq4OKizce4wwOtMnAYt27EU8V5uTVB4Qw8EPdKp7JhQ4cfxX1TDtfnalJfb1x+2
         7Qczcg1KUbJ9VxSVhZL0iTSoCF/GAbAoZb9mqcBBVCyyWoBNYEFrFeaNptQUNUOyXn+X
         ukIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EsbLKIYTJSreJOGprEFnEf3JNlSaWAcAhph4+iue+0g=;
        b=D5bVOvDP3y3AKGQDh5Eh2OnL8Op9ekFAQ9BnB85uSWtsEEN1A3yVe2kH9CvvgXcMbC
         GkBqsQYq/VNF+B8PEwSoNVqyuZ6aI9qUp+3iJryTk/t4xiRd9NvK9NHnh6vEv5FrI1Fq
         SNr5vN6p9kg3yFF5kiqN+7f2aI/cG2YC1tUacpkLPlYb2BM9HEnlX7vHpWkpl4e7HPju
         o7By/e1dwxVWnGVlcWVQJAOKaboGkLJq6ICQzQsB004jI5vVBVs1wtpr4IM3IuaFNW5U
         HI8H6QyQp4VIeAnQJWb9ix+CFQm+h5BNoR4cyzflmGMMrGZLRDWYcaQpu5Erv863Rn5X
         djLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zdXxZEBC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k71-20020a62844a000000b00536698a4975si507302pfd.6.2022.08.30.15.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Aug 2022 15:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5BA6360DDD;
	Tue, 30 Aug 2022 22:05:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82260C433C1;
	Tue, 30 Aug 2022 22:05:50 +0000 (UTC)
Date: Tue, 30 Aug 2022 15:05:49 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>, Yu Zhao <yuzhao@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro
 <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, Andrey
 Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd
 Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Christoph Hellwig
 <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet
 <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich
 <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
 <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
 <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, Matthew
 Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka
 Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr
 Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas
 Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard
 Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user()
 and put_user()
Message-Id: <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
In-Reply-To: <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
References: <20220826150807.723137-1-glider@google.com>
	<20220826150807.723137-5-glider@google.com>
	<20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
	<CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
	<20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
	<CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=zdXxZEBC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 30 Aug 2022 16:23:44 +0200 Alexander Potapenko <glider@google.com> =
wrote:

> >                  from init/do_mounts.c:2:
> > ./include/linux/page-flags.h: In function =E2=80=98page_fixed_fake_head=
=E2=80=99:
> > ./include/linux/page-flags.h:226:36: error: invalid use of undefined ty=
pe =E2=80=98const struct page=E2=80=99
> >   226 |             test_bit(PG_head, &page->flags)) {
> >       |                                    ^~
> > ./include/linux/bitops.h:50:44: note: in definition of macro =E2=80=98b=
itop=E2=80=99
> >    50 |           __builtin_constant_p((uintptr_t)(addr) !=3D (uintptr_=
t)NULL) && \
> >       |                                            ^~~~
> > ./include/linux/page-flags.h:226:13: note: in expansion of macro =E2=80=
=98test_bit=E2=80=99
> >   226 |             test_bit(PG_head, &page->flags)) {
> >       |             ^~~~~~~~
> > ...
>=20
> Gotcha, this is a circular dependency: mm_types.h -> sched.h ->
> kmsan.h -> gfp.h -> mmzone.h -> page-flags.h -> mm_types.h, where the
> inclusion of sched.h into mm_types.h was only introduced in "mm:
> multi-gen LRU: support page table walks" - that's why the problem was
> missing in other trees.

Ah, thanks for digging that out.

Yu, that inclusion is regrettable.  I don't think mm_types.h is an
appropriate site for implementing lru_gen_use_mm() anyway.  Adding a
new header is always the right fix for these things.  I'd suggest
adding a new mglru.h (or whatever) and putting most/all of the mglru
material in there.

Also, the addition to kernel/sched/core.c wasn't clearly changelogged,
is uncommented and I doubt if the sched developers know about it, let
alone reviewed it.  Please give them a heads-up.

The addition looks fairly benign, but core context_switch() is the
sort of thing which people get rather defensive about and putting
mm-specific stuff in there might be challenged.  Some quantitative
justification of this optimization would be appropriate.

> In fact sched.h only needs the definitions of `struct
> kmsan_context_state` and `struct kmsan_ctx` from kmsan.h, so I am
> splitting them off into kmsan_types.h to break this circle.
> Doing so also helped catch a couple of missing/incorrect inclusions of
> KMSAN headers in subsystems.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220830150549.afa67340c2f5eb33ff9615f4%40linux-foundation.org.
