Return-Path: <kasan-dev+bncBDAZZCVNSYPBBV4GTKSQMGQEZO6QJTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 69CC17497DE
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jul 2023 11:03:21 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-77a1d6d2f7fsf17043239f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Jul 2023 02:03:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688634200; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKvdvyKzSn4/CUlmk621yThn4pseVwN9bbYvgsUPBbNBabWyRDoOgJ27xVU1DqTksn
         fAFVgEas0YZ/c6pJR9nrT1n4a/odFQV81HONJR5pU85s8m7kCEW1tpNw5Ze5OAotkTDy
         Y6Squ3AAkXmGHrbfFj5xiIVvI6+jdfySnu3wkzVPOJni5/epHmVrwV7XaXc4Csg0c55t
         xv3wt1Drka5pB6MH+LauowOlYTB/UoVWWjLPBRCZWwGJ/njCU42MsurNhhvLpq5THeDu
         MWwCDHnTNPlWuFM7meTXPgoKmLsH3G1JUkJzBKNarWNms7wVRxwr4uqVi5yxowluRND9
         Lq7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0DjpQN5Oa/X2VjP2NHKNkPrm4TH28laaMkzB+cvEzgE=;
        fh=kjNqJjZQxZ7McQkFUg/p0a124a1y1npHY6ij6kne6Po=;
        b=1K1APpKiQUBULCC09QWB3SaHB3OqX1OY8E1st1oG5IM3flXRhuOgBH8fuLHhvoOipK
         yi4l0Pml4hOIBQn49Lx+ascEYl/t+L1uwTYDujMo3Na3kxg+YHeOzUuNQQOv+w9aB0Zc
         AzvNqRbHZR7O1UyN1PYTnQ70dlf0CRknKGlR8d6CR3YSwTKPTaRRvNrcZ0pvQzdCqbJw
         1wDkRIyaiMCZ9XgFejqP1rX2SXGmTZEHgER34EZKyzrQJ9CYVzGLCxL25dNffgvNq3Rs
         Jriin6G9n3EjF4Y+UYHoCTAXYpyiN+GnOVEKh8w6290MZOcv53+5y0TiiwKsRlxGLi6A
         lPWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rePQVRdZ;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688634200; x=1691226200;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0DjpQN5Oa/X2VjP2NHKNkPrm4TH28laaMkzB+cvEzgE=;
        b=HET6Mf7x+IkTl4TKJK7dFAz4xaQikOic86dY64LT4EZMRXaaCMHlUxRLr3AXmyTJvl
         P1cyV1evBsOHaDSsPVqQI0vRrLoMuoB4/C1kB8uaGqQcP4oL+twyoVYTLkl9NGdkhVZ0
         ikCj7kbOSBP+k80zZXLFSGpx3X2aIWTleQ9lqnIV0AoHO3nr0yJhT10CbZqtS475Cdww
         sIm8ih8yQdhFMSHuUxemgfqtYr1DKGejT52sSB+uPDYs0rzIM3U0MyeyD0XOsanGO6y7
         CqlVkuDCZr2p4qOIg4JKjNDU9g6ifblJAccoV1Vtryavtb+xiGmDWX7Uo/MJ7DyQafoI
         LIFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688634200; x=1691226200;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0DjpQN5Oa/X2VjP2NHKNkPrm4TH28laaMkzB+cvEzgE=;
        b=eT5kSHrg36dUFhcIamehN8jQ/WqCdv0PLEmQxsDjGXsiPwaHnEtuXjHn52yLW+PS4Z
         mkLINDH1VFOLZBLORPivuwzXBmB7C32fQtKfHTQQg26d2hOLjVMTlBmW2q88TPK/+j67
         X2AKSa/XintiB57gCig5svAcGbrU3KgUn5regnF1ru7Fzrriru+siMzSZTNlNmdofWl/
         lUdMv/QqRHhsbwCAd6uAxSIslyL6slg2MBFiRPs4rzM5VkN63SvuAD8UAy4OV6mXMTIC
         p84G3P593NdXun7PJ3azq22kkngEb/RPl0FbxyxJjWTj/sP4Q60vLQeD9fRLMg84LGLS
         4A6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbrkMd+cFGyyaJC/NUZ4gJeE786mNrwYcA5meJ0qbOdfoFyMSbO
	/VCgmqHRY5wDY2QApAhA67M=
X-Google-Smtp-Source: APBJJlE7GQdQocLZfvhHRIQ44aEI7uBlklEy+z5bpVDJGhhwlhkB+SVATEDkvVwjLgpRW/aqCV85/g==
X-Received: by 2002:a05:6e02:686:b0:345:b6d7:854a with SMTP id o6-20020a056e02068600b00345b6d7854amr1633369ils.10.1688634199819;
        Thu, 06 Jul 2023 02:03:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c07:b0:345:b082:4ee with SMTP id
 l7-20020a056e021c0700b00345b08204eels257498ilh.2.-pod-prod-08-us; Thu, 06 Jul
 2023 02:03:19 -0700 (PDT)
X-Received: by 2002:a05:6602:155:b0:785:cfa1:fcac with SMTP id v21-20020a056602015500b00785cfa1fcacmr1412004iot.20.1688634199227;
        Thu, 06 Jul 2023 02:03:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688634199; cv=none;
        d=google.com; s=arc-20160816;
        b=aId7l9+aICw3sO0zyUxbElTUpOXdJy4aAoGb+IjZNN0n0KEK1pQlGJ27WDlkaRSd2d
         BRZbw6yrfU9COCg+nK8OL6f7Qh38FHJW9fFNpfbA8r7/P+Lw0MQ5PeGy/qpbixA0J6gJ
         q1gBox5/psqg2u+Wx7RJKOpC9hBFurZSD5ifHxhZbd4F35xWayxFpAvASyWA8b8ycX7q
         IYJABKU+mDHLX+xwO1lAREqB/CvxjJkGQHJAxr7Xl0Fm4My0WbwTcAjoaZoyB2tTAt0U
         w7ZeLZLg2g0lK0i2Xr/raXdFHaFRY69TH3EQcAkKQpi6mzML7zXeRRyb7SpYXw+HBrjx
         8szw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aR7wzPTAeYXclNZiycSvdfYf/LLIfVq6+SCpN6+MKFo=;
        fh=kjNqJjZQxZ7McQkFUg/p0a124a1y1npHY6ij6kne6Po=;
        b=KIznZUNV0UFA9gNqgMX4RmIK9TrtaSV82MneuQ297SZfV16EuNiw6hbsVBY7BIdtwj
         A5vrS3HA9XIKfG/2IPX1ppa1sBbKbOzxwObzPS4jBodIogG1pBdSEibvhiIJMgDZCNNo
         HaRJHGMahjOSUwiQmiybJpGfQKP7/oQGm3ShnPEC3WucyyqjCjx3QXgkwVcugRTImuYt
         n2ScIonhos/Q+prkx1b6w9W8Y7GfLDQ0J2JSaZoATytJgiw9PVBY8KeUApuXDJuWpI8F
         hZgDiqYMwWxiGVJOZdVqwsCRMCJQd81MeqKxdVgjmzUDcR5LR9PIABv1cI77F1JX0Ugy
         DK2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rePQVRdZ;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id eg13-20020a056602498d00b0078369ced497si69355iob.2.2023.07.06.02.03.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Jul 2023 02:03:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D963261458;
	Thu,  6 Jul 2023 09:03:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 41383C433C7;
	Thu,  6 Jul 2023 09:03:14 +0000 (UTC)
Date: Thu, 6 Jul 2023 10:03:10 +0100
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Feng Tang <feng.tang@intel.com>, stable@vger.kernel.org,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH] kasan, slub: fix HW_TAGS zeroing with slub_debug
Message-ID: <20230706090309.GA29243@willie-the-truck>
References: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
 <CANpmjNO+spktteYZezk7PGLFOyoeuFyziKiU-1GXbpeyKLZLPg@mail.gmail.com>
 <CA+fCnZenzRuxS4qjzFiYm05zNxHBSAkTUK7-1zixXXDUQb3g3w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZenzRuxS4qjzFiYm05zNxHBSAkTUK7-1zixXXDUQb3g3w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rePQVRdZ;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Jul 05, 2023 at 03:19:06PM +0200, Andrey Konovalov wrote:
> On Wed, Jul 5, 2023 at 2:51=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> >
> > On Wed, 5 Jul 2023 at 14:44, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocate=
d
> > > kmalloc space than requested") added precise kmalloc redzone poisonin=
g
> > > to the slub_debug functionality.
> > >
> > > However, this commit didn't account for HW_TAGS KASAN fully initializ=
ing
> > > the object via its built-in memory initialization feature. Even thoug=
h
> > > HW_TAGS KASAN memory initialization contains special memory initializ=
ation
> > > handling for when slub_debug is enabled, it does not account for in-o=
bject
> > > slub_debug redzones. As a result, HW_TAGS KASAN can overwrite these
> > > redzones and cause false-positive slub_debug reports.
> > >
> > > To fix the issue, avoid HW_TAGS KASAN memory initialization when slub=
_debug
> > > is enabled altogether. Implement this by moving the __slub_debug_enab=
led
> > > check to slab_post_alloc_hook. Common slab code seems like a more
> > > appropriate place for a slub_debug check anyway.
> > >
> > > Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocate=
d kmalloc space than requested")
> > > Cc: <stable@vger.kernel.org>
> > > Reported-by: Mark Rutland <mark.rutland@arm.com>
> >
> > Is it fixing this issue:
> >
> >   https://lore.kernel.org/all/20230628154714.GB22090@willie-the-truck/
>=20
> Yes, my bad, messed up the Reported-by tag. The correct one should be:
>=20
> Reported-by: Will Deacon <will@kernel.org>
>=20
> > Other than the question above, it looks sane:
> >
> > Acked-by: Marco Elver <elver@google.com>
>=20
> Thank you, Marco!

Cheers, this seems to fix the splats for me:

Tested-by: Will Deacon <will@kernel.org>

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230706090309.GA29243%40willie-the-truck.
