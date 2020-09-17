Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXHBRT5QKGQEMQKTEAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D732726D809
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:48:12 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id o6sf675877wrp.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 02:48:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600336092; cv=pass;
        d=google.com; s=arc-20160816;
        b=mjdUwiNnWmncazyqZ6OEVB8s++QhYVjxpT1um3arvBQtjAPrEpMeQ1+/R2cIYXPMgQ
         XNhNXU+lKYQOUzn3o6xONe3qnfj/7nvWhUdo2tpFyGmVKlw8SKjPEX+U5Tp7m+aLNr/D
         PLmfallXAoRB2NRFzilRLlkCzvililJhY7yEZrVG+iDxdwh6VCFDdLnUbOKaCrrwHkuE
         4CjNjTB+CB3jD4G9opb5ywyrLWEhbem6QriCsdqNNl+jfb9omw9T8mroDL4uDsPmkquv
         2XWhuzKEZO3kLAUsq1ao+U2HTQtkS/R9lJs4DasbO1vmZm0UYuMFXVnI+gzS44HIfzrs
         xCBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=auFV+ejy3ndYbL8Pe+LWr+TOY3Vi9eDG5ohf+duE/ac=;
        b=jH7VIdK9U83QGrCm88BngF1rWWTpbyD4IHo9IH+yMmyi3P71eFrH6iFdBYmYSWjlEM
         VngR72b6mfeuULzNLYfAZOCtfBFIQ5jSFz65SKkHcTcGF6GGksD9LbvYLvENkdbHKQoj
         MJc9aGeuYM5rNv3JoXSm+7tIQEwZ6chPRnuG6QRciOXN0nCVxmrDHLg0Lgq8onl+U+sx
         M0Zjd0XXys5FcSBX0Njz3/ZxvCtRIeltS3AThXXsALCxE0kfJGe1PoKnp5gBchmwepW+
         Xn7E6x7BFxpNuSqASlPIUjS+IW770QFKlTqyfGbUfL2j4pZ0RRiGCJGGqwqALWa4gZND
         /WSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fGUjulhI;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=auFV+ejy3ndYbL8Pe+LWr+TOY3Vi9eDG5ohf+duE/ac=;
        b=hJk1ZXcqXkyuIOtedVRY7yeoMCTsVJIC9nHJmaepxz+NpNy1lQKfFPM+Pch9Awwv9h
         jw9tjSesr0dHVJUu3u73YO9cf+i0GoPhSu/A78a7O9XVzBNhY+Xurv3I3xKxobNHEb3q
         UT1yFGBTsmO7SlUV2fX64T0s4gSoE0YUAyQo84ZyPXk9XSjs3s/7kkrcAwdD3j6Eig2l
         q0gG45Hv2uQqGbF8+WGg19g/14MbgXCEWN1tvRFW9iNei7l23J+4EmaJ49Noyh+PK1PW
         T4wZ5s4bH8niO7JQMqC3mMZ3bSaDk8WSiLiPikiaMHb/K7lXlw+YMiVl0l6o8td4pXDR
         rhbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=auFV+ejy3ndYbL8Pe+LWr+TOY3Vi9eDG5ohf+duE/ac=;
        b=l2zCjRuyT8e1BPPoR5jLfz3AvE+jZN4x6Glk1S8iGiWnPTx9jD0jtb0vW8+pcR/NyN
         sgtOUlJuo3e0e4jCzZNWqukcjvXXUVjatixSgOOgTPnFMnb+hlffWcygqoBSFflVkPKx
         LirvFXzuE+dwiPXuKtjOxvQ/lH3eWb1wOKXexPR9FBi37twZJnaf/9Cr26c3TNXf4tRq
         isEtcUWmy4KKM4FDBx9s0xYyuQGK8GsFJ4g3Yzh7cPvejQ89JkZhws2++eoy+EiAwBOo
         77rZkL9h1xeQ9j3h79ufFoFDTVjiggFaRct9ps+j+ENlXwJ5b/C8MtAY2Vmip2jrqcZM
         rbLg==
X-Gm-Message-State: AOAM530rayMxfcO+WC8MSQJV71XnJBi5RrpAQJIm1DBHxtensZJr6sTh
	MtgTsmkpkbdiO7qWhBbBi9Q=
X-Google-Smtp-Source: ABdhPJwQEMj2YL2Lepe92VMZUG8SLRfCK8d+gtPHb8HIjoUR9QkOhbpKvM1kOFiUQxKp88hzubLD8Q==
X-Received: by 2002:a1c:2c85:: with SMTP id s127mr9502409wms.31.1600336092603;
        Thu, 17 Sep 2020 02:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls156947wrm.1.gmail; Thu, 17 Sep
 2020 02:48:11 -0700 (PDT)
X-Received: by 2002:a5d:6886:: with SMTP id h6mr32419364wru.374.1600336091767;
        Thu, 17 Sep 2020 02:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600336091; cv=none;
        d=google.com; s=arc-20160816;
        b=Fchf3CyMMlIVukBh9Ut9e29xrXVBE3aDXM87kkH2NN+kSgIL1T9M6kVu7I9jTO1gz9
         G409ZO6ClAB4JK7a0DJlS0jRe3im6khmfivHmd1dbJBadrYhxcZ3OgSdNMn+7CT0cU0P
         8/soUUpk9nuhugkCfIYS+ozLKMlBvS/WuV5nxmQDAZdKnGjbi/JFX04DliJSl13FAUO8
         St/ubHllPTaslWxT+z16TvhZNky2yeITTCFCBR4DrKXh7TjxPVz6dumS8/0to/pHtKLh
         aiQ1jkdbFIPY+bhhYtRG5ktt75TGsaYYt0Wfyn0ZniT+yh4IlLax/dfWWkYtXHqKgilN
         p4zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EWVAkK9HAhFT14dUOAujUtY5YcpFnxpT4fxJHTF5BOY=;
        b=ecuA0AZ6kIhks9iJRGOf0Dq2ElbDuurhB3c2rVGnIYSjGPsjHDhKSy8wg4i+C0dtN4
         fsVh3tLAgFPO1YSDoXxsRnP8MQtwTfcx96nEG9R2Tf1F0yWFdTX5UIFCB7pdxTUPADlY
         pfGdI81bU8FZ7iCaxuqxFE6WlJ07TKBx3RG1V/Skbs84ub/zgPrsJF4kaOq4RoSYh/uv
         txn8dMdLHhPX9Jo1cL1dZyLyjUP1lJx0VXTPdoPKuMDoD04TYtLsTpWAWwpG7V2gM8tz
         oYs7gttTc9c6RXp7gOaJfNKvMhUitRt1pqzTJCbCwSkg6lbD9UhjKF6zPSuqfLgtU9g6
         j6Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fGUjulhI;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id x1si222309wmk.2.2020.09.17.02.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 02:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id z4so1342876wrr.4
        for <kasan-dev@googlegroups.com>; Thu, 17 Sep 2020 02:48:11 -0700 (PDT)
X-Received: by 2002:a5d:60d0:: with SMTP id x16mr30836644wrt.196.1600336091166;
 Thu, 17 Sep 2020 02:48:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com> <20200915132046.3332537-5-elver@google.com>
 <alpine.DEB.2.22.394.2009170935020.1492@www.lameter.com>
In-Reply-To: <alpine.DEB.2.22.394.2009170935020.1492@www.lameter.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Sep 2020 11:47:59 +0200
Message-ID: <CAG_fn=XMc8NPZPFtUE=rdoR=XJH4F+TxZs-w5n4VuaWKTjcasw@mail.gmail.com>
Subject: Re: [PATCH v2 04/10] mm, kfence: insert KFENCE hooks for SLAB
To: Christopher Lameter <cl@linux.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Rientjes <rientjes@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fGUjulhI;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as
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

> >  static __always_inline void *
> > -slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> > +slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, si=
ze_t orig_size,
> >                  unsigned long caller)
> >  {
>
> The size of the object is available via a field in kmem_cache. And a
> pointer to the current kmem_cache is already passed to the function. Why
> is there a need to add an additional parameter?

That's because we want to do our best detecting bugs on
kmalloc-allocated objects.
kmalloc is using size classes, so e.g. when allocating 272 bytes the
object will be padded to 512.
As a result, placing that object at the end of the page won't really
help to detect out-of-bound accesses that are off by less than 270
bytes.

We probably need to better clarify this in the patch description.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXMc8NPZPFtUE%3DrdoR%3DXJH4F%2BTxZs-w5n4VuaWKTjcasw%40mai=
l.gmail.com.
