Return-Path: <kasan-dev+bncBCF5XGNWYQBRB4XKRKOAMGQE6QAT5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C303639917
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Nov 2022 01:55:16 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id y10-20020ab0560a000000b003af33bfa8c4sf3556716uaa.21
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 16:55:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669510515; cv=pass;
        d=google.com; s=arc-20160816;
        b=sIG6Dnm75KnZGCWTzuDmH05mMd4ktQENtX0qZ6y4ITLXwvX1opDNxMaDxjJzUaeUBD
         6NWEBzlBRDLK/AB0kzRYAE2sPmwiAD29UxSGM9BGCq3wMauvDZhJxymQFMk1DMrkh+Yu
         32GvvbvOFGYsb8KUO+EOsjeyRd6AMpOO0F0P5tEiRoQXqh2rJo93Ms5+oGnlNcUlsJiz
         glz9hFPPGiMgetg1usg5nDvHt7FD8FSpajpLZYodefmwzpy2ZaI2tDyvrmNeMfZG4j8y
         jO/28zoGOsbUCuIsITyvv6t0a8qQeCzbRiAybBf9Dd59IkVdXP3IHyNnQ5Q/+pmJSDYl
         IlqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wU5fU6FddVky8j8NwjjUnfk0emWmnE0hbjBx5wp7QfQ=;
        b=W67vg16af6icyPUQq7507lvMygiHLrYTG4l8fwpSTRkRE/kalIAFco9M+ds1Vb/k26
         VDmYVItArqBRdZ/0ydI55zbKU7UfAqQTZnv9X1wUACoRDrQy5lHW3oOnoOsTJMzlLNHq
         OfTbCsoSCLgfuLRI3I+vmsIYL96fbS/E+uB5Dgn2o4ewpHm8kRZsVDxP2oalVMmVk78m
         i/UDf5YKibhfDqWJMCXbgauUuUUq3lwOKGpD691pNXTsqH55vuxP65iFp0wZdihddrd1
         T1qRWmEIhXsstrLr/6CrePGlKEHTXcVX7twfCkE006E+FHMev+tUZCuaCJB7JnwzWMI4
         4MYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TX4xrszZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wU5fU6FddVky8j8NwjjUnfk0emWmnE0hbjBx5wp7QfQ=;
        b=HL8iojm5GtEn7ojG4DqiOBx/khn30lE136R4dWgbTHYxkKSlFmgGA/Py2B7egxnfJc
         YwDQbaSQJtj4/mxXR5uKrno+abnSmxdtvCCbmGmjvlSl6udbYXk3z9ORiGaIWKPfAlyY
         83P4Tp6wvyzhpox7kOCbwxiK7GWNlmw254UBMPYgPL7ZVpmktpU8RRoH9zZWo7I/pPIS
         AnFN5rvxizysnVVqqbldxSZsnecSUbK+gY7pN6oWTtAKghp0zi3nxObpoFuC1JtDlHJx
         /GP+Sfu4WUyjZIoqu+Yhd+2FLnYIvg652/BQZmUdNqyKtt8wvjFiAamh+U64FOQTSFXp
         w4kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wU5fU6FddVky8j8NwjjUnfk0emWmnE0hbjBx5wp7QfQ=;
        b=wocuTAEBCTI/LeRx9wkCMkC9p5PuvzC5SZFtJk/64ZYzgbJMof0XmlOAE7fkGbd1RS
         FDxj4qWMph1QB5X9SEWL5EoXQsfH0DzhGTTzQiZEE3JiDk4OvSx2xdGQhhhgX7DaivwH
         57D39FrxM0Ga2Jd0SrubL7m6Msxc27visPDcIg6gM37UnabqxRFJT+KIfjLTPkENSTbM
         pnD4fd02D9xLDubBexRXIe4P24iSrjfJgAXogczVzuUCFyUTKLZcyYsiWCaWEx3mFw32
         eNCcmdFWyalIe/Hvwsqo35Tb3eOzNCGUS2tCjqEzrDYAXHQHhLafHJYUDvCmieJ1IKh3
         odJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plqb+e74BB1GJECBTorYXp2sCqVBt8QCcIPBcs9upnHxKkvWSSD
	i7AvkT3ZeArA000K6J/ShAI=
X-Google-Smtp-Source: AA0mqf6zqsRjBuqXAa8q1sXrcUUv+5nUr8OdJzNXdi/AwQnnhCtsdZPB3e4XEMl1Mn/X9KXoL1/HkQ==
X-Received: by 2002:a05:6102:e83:b0:3aa:13ef:1400 with SMTP id l3-20020a0561020e8300b003aa13ef1400mr25993233vst.28.1669510515070;
        Sat, 26 Nov 2022 16:55:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d902:0:b0:3af:54e7:dbd0 with SMTP id t2-20020a67d902000000b003af54e7dbd0ls1607871vsj.0.-pod-prod-gmail;
 Sat, 26 Nov 2022 16:55:14 -0800 (PST)
X-Received: by 2002:a05:6102:1606:b0:3aa:1249:73d3 with SMTP id cu6-20020a056102160600b003aa124973d3mr16116620vsb.5.1669510514397;
        Sat, 26 Nov 2022 16:55:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669510514; cv=none;
        d=google.com; s=arc-20160816;
        b=asdVrfl5fgot1GoaNt8AyJzFs+6IoZnIPXaMtN79UHqDNy6gef+y9ULwBGHtPdYJsy
         5hEX02SNb/Vi6IdGCMSeB7hrQktN/tY0a1wl7+BVZjcACrV39RCSifgTxfmWqeDPstyp
         xeSilTVhgBDUDFhaLLH/4tIBHTqQJ2CnEjirRXcOvK8qQDG7zwDIVG8neDHPQ4fQMgA3
         Ijo1jZOBgCWVRskLanc+pqE0r0uvqt8QuUpYUMKuSKZIzF8tBJ3YG3YALO547zgOZxhG
         Ti2p47D67+cJGtAahz1jSWzh9ovGGP4AaSgJFzzUmonQ9BobtDtQS14b4M3BeE5OZFU9
         gclQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FsLJX0InAbt1kTuvXLVor2ZX32CfM2qEUmM/5HpvT0k=;
        b=JnttUIrsCCtESGfWHyZ4NbjUoX9L4PbPoIj047oKs/RDmtdBlyFgTfd8kwplWFJjaX
         AdXaQzjkuiptI0rCLrSNxeBa+nCCqCwypRrrXPOrns/Nir9yYZb58ap2Nn+Ur0d54xKU
         HvHfLoW2jbpoaySHcZPqQt7BSOi3FKH8uwTj1GVyIu4ejfmsDQBSlAE47VZbsuKL9f/a
         3efzyAFNL2tnUKGaq3KEamIMv3xqG4gyYroyygiKmXKKWOnfQ+k0TwqdLNFNrbgk8x63
         vPTUw6pN8Gc4OLnUdjygs0gRbpzFiAu7WhLkJKpQDlmj3BFo53Bt2tdJhqK5sJ65mjvg
         NwlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TX4xrszZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id az5-20020a056130038500b00414ee53149csi496753uab.1.2022.11.26.16.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 16:55:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id y10so7087239plp.3
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 16:55:14 -0800 (PST)
X-Received: by 2002:a17:903:1ce:b0:186:a2ef:7a69 with SMTP id e14-20020a17090301ce00b00186a2ef7a69mr25665561plh.77.1669510513461;
        Sat, 26 Nov 2022 16:55:13 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 70-20020a621749000000b0056da073b2b7sm5250323pfx.210.2022.11.26.16.55.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Nov 2022 16:55:12 -0800 (PST)
Date: Sat, 26 Nov 2022 16:55:11 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
Message-ID: <202211261654.5F276B51B@keescook>
References: <20221118035656.gonna.698-kees@kernel.org>
 <CA+fCnZfVZLLmipRBBMn1ju=U6wZL+zqf7S2jpUURPJmH3vPLNw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfVZLLmipRBBMn1ju=U6wZL+zqf7S2jpUURPJmH3vPLNw@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=TX4xrszZ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Sat, Nov 26, 2022 at 06:04:39PM +0100, Andrey Konovalov wrote:
> On Fri, Nov 18, 2022 at 4:57 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > With all "silently resizing" callers of ksize() refactored, remove the
> > logic in ksize() that would allow it to be used to effectively change
> > the size of an allocation (bypassing __alloc_size hints, etc). Users
> > wanting this feature need to either use kmalloc_size_roundup() before an
> > allocation, or use krealloc() directly.
> >
> > For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> > some of the partially open-coded ksize() in __do_krealloc with ksize()
> > now that it doesn't perform unpoisoning.
> >
> > Adjust the KUnit tests to match the new ksize() behavior.
> >
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Christoph Lameter <cl@linux.com>
> > Cc: Pekka Enberg <penberg@kernel.org>
> > Cc: David Rientjes <rientjes@google.com>
> > Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Roman Gushchin <roman.gushchin@linux.dev>
> > Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Cc: linux-mm@kvack.org
> > Cc: kasan-dev@googlegroups.com
> > Acked-by: Vlastimil Babka <vbabka@suse.cz>
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> > v2:
> > - improve kunit test precision (andreyknvl)
> > - add Ack (vbabka)
> > v1: https://lore.kernel.org/all/20221022180455.never.023-kees@kernel.org
> > ---
> >  mm/kasan/kasan_test.c | 14 +++++++++-----
> >  mm/slab_common.c      | 26 ++++++++++----------------
> >  2 files changed, 19 insertions(+), 21 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 7502f03c807c..fc4b22916587 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -821,7 +821,7 @@ static void kasan_global_oob_left(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> >
> > -/* Check that ksize() makes the whole object accessible. */
> > +/* Check that ksize() does NOT unpoison whole object. */
> >  static void ksize_unpoisons_memory(struct kunit *test)
> >  {
> >         char *ptr;
> > @@ -829,15 +829,19 @@ static void ksize_unpoisons_memory(struct kunit *test)
> >
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +
> >         real_size = ksize(ptr);
> > +       KUNIT_EXPECT_GT(test, real_size, size);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> >
> > -       /* This access shouldn't trigger a KASAN report. */
> > -       ptr[size] = 'x';
> > +       /* These accesses shouldn't trigger a KASAN report. */
> > +       ptr[0] = 'x';
> > +       ptr[size - 1] = 'x';
> >
> > -       /* This one must. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> > +       /* These must trigger a KASAN report. */
> > +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
> 
> Hi Kees,
> 
> I just realized there's an issue here with the tag-based modes, as
> they align the unpoisoned area to 16 bytes.
> 
> One solution would be to change the allocation size to 128 -
> KASAN_GRANULE_SIZE - 5, the same way kmalloc_oob_right test does it,
> so that the last 16-byte granule won't get unpoisoned for the
> tag-based modes. And then check that the ptr[size] access fails only
> for the Generic mode.

Ah! Good point. Are you able to send a patch? I suspect you know exactly
what to change; it might take me a bit longer to double-check all of
those details.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211261654.5F276B51B%40keescook.
