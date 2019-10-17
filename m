Return-Path: <kasan-dev+bncBC6LHPWNU4DBBGXKT3WQKGQEGBYIKRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF251DA2A7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 02:26:03 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id a130sf294180vke.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 17:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571271962; cv=pass;
        d=google.com; s=arc-20160816;
        b=jFuLG7Ynp7wa09FHwCpObxkWR9ybch0soa5x4+EiYkgKWkQvO9J3IppUd4tSr+nmoP
         0C9xPuK0+zzaxIip6V/4dyTsw4GVeXSxW54Dw2cV/6KA1Z6E2tH9cNhWnVoIYnUEvYXi
         maZrrWN5ASfPjf6uVfkMq3Et+EGuXxPloNohqh1PIcCD3P5XmUn4PAYsBxh0ijax5nrN
         vv8HNBsnUBlkSiKBRr7SOE8J/iXAVeX5GB4AaVTgAJMQ+8XHQa1gm7g4kTqJCluyc2za
         jUUqImo2r/Zo6ov02NEYQcLqS1YzCW4vV0J2pJsjUcf1o1XQfU/jSoYhtLIuI2PR63ON
         GeTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=fRYmMNUYZVO9LpSfsSorGqVt/2nEYmYidDv7B9d0zQY=;
        b=XGaYAabpqs+n/2bZtaZZ7L8CCdfl9zi59W5SsnFKllZ035Yy6Vxgcpt1Pv09GfP0ap
         40aAfYo2UUZvnY+5DSKDV8Q/YGv+l3bg6hBmpR/m5ye/XCtgRk5kt4mUalR9sEWOZK0P
         yY1QRFnXd/K1yJFKOwY5AbavJ66FmxvmzQ7RjLv7r41Vnc1ePQBXY+JYE+5LEmjNd9sw
         hBXa1n6Qn0NCRJ9AuPsR7jOfSkezuBe07mPsP8fnjxkOwnVkcplnRDEKFtWzxUPjOvW0
         tvKrBIzpl4uyj2Y4mQg/U8qvAqTH4Q42rUvAM4rCdfdOM1bxDZLnYfoqKQBVTkOsiatQ
         afhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="csQqSPN/";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fRYmMNUYZVO9LpSfsSorGqVt/2nEYmYidDv7B9d0zQY=;
        b=YqECpwlSuvcSOfr3NPeiT8N4ix+k/CXioL7poF6cbsWkY1Qz8LD3BC1VpDvqjjGe+R
         UYqgeaNAXgx105ObI5PXsM5BuksFyv8sJ12RTon2ILCbYUU0b5VNj8ccWKaK7p7SRfwO
         4ZoC7VSJWjyCpt0sEDC9gAG8Bf4JoTcD6dw1oCivXUdLmi7JcpDY6qFBQ1t399clpX6S
         wW0bIs8SeN0GcJanumvjVg7+Gx6fUZwvWY+xH9gHiAxw+WlPlK+tktZ9JdR9b/NwvqHZ
         Fz7iCYxOJbWuZ6FBjBpUAOlfjkgfq+kUDPBilx9w9EbRGBQAt8KSKsyDJtDKPCG4/Eqp
         Fegg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fRYmMNUYZVO9LpSfsSorGqVt/2nEYmYidDv7B9d0zQY=;
        b=rAEBAHhkK+TMgJFGTdsl18lRAYdFS/zShM8HM2ptKY5JmF3FaC58hwaktdQcuesSmM
         7RYGG7OxEh52bfkpysCIl5OABh5GQEbKCHo0m9mVGMAIr/qnJ4vHzN0P8EgTnDzl6+lH
         H08H/iBS/1RWf3/0564oucQ1KAmNveZwaniF1AHPLZeztE16jYm2fajTO0tIlQswSMYb
         YS64JuhiIWcF+34GoCtc8dhdt2Yk76hfcnm50aLm9v60gDXtg5QlIbJGEcI08X1WeTAP
         tNss8OGymoaMT6LV9Pq1qUQpXyTFqrbPVM/bM64nRiumDss5zMrBVb+iarW50G+Xn40x
         /ncg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fRYmMNUYZVO9LpSfsSorGqVt/2nEYmYidDv7B9d0zQY=;
        b=nTmpZUUbPX8CCHfBM/G1R5FPxrg2/u2tgmjfoWbUYJbEOhLraru75O9turJD3rZyny
         METrCk2OLRzWzc8OH5Ud3KVAqrenByFnfbMOd2BKO4wZcVYGXpwVszfVECohf9RNyVI4
         EjMZSvII7r6ako/aJwEs0KTpdZ/M8axrmOt7vXY0vveCbSrWzT1sb1xSI53OyqDz3cxu
         R24DqMLUJVBfmeis5sLxIbX5txswJkcY4GdCnDgD2eRDC+hbLoIrEA0WWFXQr6UyDHcy
         wBF0V/5BNpvEk23LZ3AVWx0y5fsFxeu/jCNSWwupW6LEDQggkORmgjgXWqODfXwiFMYs
         1JKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX1UZysOgkzRxxprQXn57A3NZUC+kFXV36rJpuri6sk6NE7ai0/
	IphNTLXYPjZTelJYTlwaaQo=
X-Google-Smtp-Source: APXvYqxPv63TUN3cmFlsReeSfvRV+P524mD3sgOHHhYk11gcwyVlqEbiQ3+cOdY25FS9GTEY6UxpXw==
X-Received: by 2002:ab0:1553:: with SMTP id p19mr757897uae.80.1571271962746;
        Wed, 16 Oct 2019 17:26:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c883:: with SMTP id v3ls44581vsk.2.gmail; Wed, 16 Oct
 2019 17:26:02 -0700 (PDT)
X-Received: by 2002:a67:bd0d:: with SMTP id y13mr367838vsq.109.1571271962276;
        Wed, 16 Oct 2019 17:26:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571271962; cv=none;
        d=google.com; s=arc-20160816;
        b=vEQZBmU2UK+5DNkR7FWBAKItVUYBBVre2Ok5OECu1kc9YWXNl48elolOAEw+IFg2Mu
         aRNTZWRQPj60QnuiLReALltu/iViFwOM/9Rjbw3l020aEI7JegVlfIIMfu3vJ4Kov4dF
         Ydouxb0XVrKNsnJA5s/+xSLdJKsSilsTVdYKOHVPMB43hDaFxemhL/3P5/Y0YvoaFJ75
         ksAghUQK8Za78Ii5wBYl3w2aPlBLKMBZmGN6QTts9PMKtcAZk8B3OmfhvkID+Kbjgrqa
         iE3qBxPXfF5W1lh/09Tra7YfXb2B74Cpv4NvB6usp7fqlL7A9zWBVD3l2zis7h4R9+N8
         IK3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=c4Hjken7XU2rfPp3dnVy1MaKiaTDJ8xCPdPitHymU3c=;
        b=QRZicwrlh6N5NWgxgHruFyeRMcdjEBMufAl45WRMb9nfyQY1VRkgmX0yHTv7xw3ipG
         2koRgaW0JV33Cb62pwQ7G7Gdkzhjp8e1D/iaoAfIXZ7xtj34dYScYETAXIhC5x8VfMbk
         UZc/IVcGfN7veX0NlF5zlekIkuP+TxEttG5v464egJtlV5y3uqT4p9Iy5UmSl0TBnOIu
         Yv2gbl6SL/eNwFM971/8CABaPtg3l0Vd344Qsyc2mjeFNMrok3ZNerdGl2ddxcQhAluS
         ZYYo3x9jpO5YYie04oK2pdJEMSKI1t6xTUlk5/7LYtphRN9eNL9rBJa+DCXtQnVJN5Gi
         c2JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="csQqSPN/";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id i13si24602uan.1.2019.10.16.17.26.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 17:26:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id 3so1012157qta.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 17:26:02 -0700 (PDT)
X-Received: by 2002:aed:3847:: with SMTP id j65mr1055138qte.124.1571271961879;
        Wed, 16 Oct 2019 17:26:01 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id y5sm333254qki.108.2019.10.16.17.25.59
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Oct 2019 17:26:00 -0700 (PDT)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id A11A621D75;
	Wed, 16 Oct 2019 20:25:58 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute6.internal (MEProxy); Wed, 16 Oct 2019 20:25:58 -0400
X-ME-Sender: <xms:FLWnXSxe46wrvL0VHqF5V2Ftj42Nf9hCqNC4-vIa5pbRXW7LwZKVWQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedufedrjeeigdefudcutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujggfsehgtderredtredvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecukfhppedutd
    durdekiedrgedurddvuddvnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquhhnodhm
    vghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudejjeekhe
    ehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrdhnrghm
    vgenucevlhhushhtvghrufhiiigvpedt
X-ME-Proxy: <xmx:FLWnXVRhKT-ELDdbHCzUD4h16wZdhG07nxKVIzY0GK3e0T7AQAQ_lw>
    <xmx:FLWnXZX2aRHtB7FOPmJpE0Vt6fX-FF8krlsUle2XV1odHISlIxcovA>
    <xmx:FLWnXXbpI_54bhxEulyOPPPIzzBXXBx2l_kZQlorezepl81GJumBIA>
    <xmx:FrWnXV97T3hNSRFPeBAYdtOEaxoLxandJ9m0BIPe1jkzxQkvR8MN13GMnGY>
Received: from localhost (unknown [101.86.41.212])
	by mail.messagingengine.com (Postfix) with ESMTPA id 25DF68005C;
	Wed, 16 Oct 2019 20:25:55 -0400 (EDT)
Date: Thu, 17 Oct 2019 08:25:51 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, ard.biesheuvel@linaro.org,
	Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>,
	Daniel Axtens <dja@axtens.net>, Daniel Lustig <dlustig@nvidia.com>,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	Dmitry Vyukov <dvyukov@google.com>,	"H. Peter Anvin" <hpa@zytor.com>,
 Ingo Molnar <mingo@redhat.com>,	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,	Nicholas Piggin <npiggin@gmail.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191017002551.GC2701514@tardis>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-2-elver@google.com>
 <20191016094234.GB2701514@tardis>
 <CANpmjNOxmQDKin=9Cyi+ERVQ-ehH79AaPjRvJNfFfmgOjJAogA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="oLBj+sq0vYjzfsbl"
Content-Disposition: inline
In-Reply-To: <CANpmjNOxmQDKin=9Cyi+ERVQ-ehH79AaPjRvJNfFfmgOjJAogA@mail.gmail.com>
User-Agent: Mutt/1.12.2 (2019-09-21)
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="csQqSPN/";       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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


--oLBj+sq0vYjzfsbl
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Oct 16, 2019 at 12:06:51PM +0200, Marco Elver wrote:
> On Wed, 16 Oct 2019 at 11:42, Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > Hi Marco,
> >
> > On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
> > [...]
> > > --- /dev/null
> > > +++ b/kernel/kcsan/kcsan.c
> > > @@ -0,0 +1,81 @@
> > > +// SPDX-License-Identifier: GPL-2.0
> > > +
> > > +/*
> > > + * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
> > > + * see Documentation/dev-tools/kcsan.rst.
> > > + */
> > > +
> > > +#include <linux/export.h>
> > > +
> > > +#include "kcsan.h"
> > > +
> > > +/*
> > > + * Concurrency Sanitizer uses the same instrumentation as Thread Sanitizer.
> >
> > Is there any documentation on the instrumentation? Like a complete list
> > for all instrumentation functions plus a description of where the
> > compiler will use those functions. Yes, the names of the below functions
> > are straightforward, but an accurate doc on the instrumentation will
> > cerntainly help people review KCSAN.
> 
> As far as I'm aware neither GCC nor Clang have documentation on the
> emitted instrumentation that we could reference (other than look into
> the compiler passes).
> 

Yeah, I don't find them either, which makes me surprised, because I
think the thread sanitizer has been there for a while...

> However it is as straightforward as it seems: the compiler emits
> instrumentation calls for all loads and stores that the compiler
> generates; inline asm is not instrumented. I will add a comment to
> that effect for v2.
> 

Or you can push the compiler people to document it, and we can simply
reference it in kernel ;-)

Regards,
Boqun

> Thanks,
> -- Marco
> 
> > Regards,
> > Boqun
> >
> > > + */
> > > +
> > > +#define DEFINE_TSAN_READ_WRITE(size)                                           \
> > > +     void __tsan_read##size(void *ptr)                                      \
> > > +     {                                                                      \
> > > +             __kcsan_check_access(ptr, size, false);                        \
> > > +     }                                                                      \
> > > +     EXPORT_SYMBOL(__tsan_read##size);                                      \
> > > +     void __tsan_write##size(void *ptr)                                     \
> > > +     {                                                                      \
> > > +             __kcsan_check_access(ptr, size, true);                         \
> > > +     }                                                                      \
> > > +     EXPORT_SYMBOL(__tsan_write##size)
> > > +
> > > +DEFINE_TSAN_READ_WRITE(1);
> > > +DEFINE_TSAN_READ_WRITE(2);
> > > +DEFINE_TSAN_READ_WRITE(4);
> > > +DEFINE_TSAN_READ_WRITE(8);
> > > +DEFINE_TSAN_READ_WRITE(16);
> > > +
> > > +/*
> > > + * Not all supported compiler versions distinguish aligned/unaligned accesses,
> > > + * but e.g. recent versions of Clang do.
> > > + */
> > > +#define DEFINE_TSAN_UNALIGNED_READ_WRITE(size)                                 \
> > > +     void __tsan_unaligned_read##size(void *ptr)                            \
> > > +     {                                                                      \
> > > +             __kcsan_check_access(ptr, size, false);                        \
> > > +     }                                                                      \
> > > +     EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
> > > +     void __tsan_unaligned_write##size(void *ptr)                           \
> > > +     {                                                                      \
> > > +             __kcsan_check_access(ptr, size, true);                         \
> > > +     }                                                                      \
> > > +     EXPORT_SYMBOL(__tsan_unaligned_write##size)
> > > +
> > > +DEFINE_TSAN_UNALIGNED_READ_WRITE(2);
> > > +DEFINE_TSAN_UNALIGNED_READ_WRITE(4);
> > > +DEFINE_TSAN_UNALIGNED_READ_WRITE(8);
> > > +DEFINE_TSAN_UNALIGNED_READ_WRITE(16);
> > > +
> > > +void __tsan_read_range(void *ptr, size_t size)
> > > +{
> > > +     __kcsan_check_access(ptr, size, false);
> > > +}
> > > +EXPORT_SYMBOL(__tsan_read_range);
> > > +
> > > +void __tsan_write_range(void *ptr, size_t size)
> > > +{
> > > +     __kcsan_check_access(ptr, size, true);
> > > +}
> > > +EXPORT_SYMBOL(__tsan_write_range);
> > > +
> > > +/*
> > > + * The below are not required KCSAN, but can still be emitted by the compiler.
> > > + */
> > > +void __tsan_func_entry(void *call_pc)
> > > +{
> > > +}
> > > +EXPORT_SYMBOL(__tsan_func_entry);
> > > +void __tsan_func_exit(void)
> > > +{
> > > +}
> > > +EXPORT_SYMBOL(__tsan_func_exit);
> > > +void __tsan_init(void)
> > > +{
> > > +}
> > > +EXPORT_SYMBOL(__tsan_init);
> > [...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017002551.GC2701514%40tardis.

--oLBj+sq0vYjzfsbl
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEj5IosQTPz8XU1wRHSXnow7UH+rgFAl2ntP8ACgkQSXnow7UH
+rj4IwgAr1ZTnb6a5VMzzEFJsOsttb8ZWdPW5m/sNmxxMh6TIPZzl1rWAzFMMC7R
52lRrsSAQ+3JsII8i8lMPGPFo4Fc4g1ivQa604Zf+KjqHPtM4bBOigkNgRmFkM5r
gsrimY5mX0B4O0hg7CtV0kn3FAJKsFTE+daVXj6W0p18pshZ3HgulHPKDH7qrMnh
Hc/9JhxxvcnRAN9uUuukBr4vGHq+iDJqqGZqOuykwTufSRnGNlQk9BoGczLX+7+2
zJ+dLh8nSVw+R2tV8eVAZ+84dHfNRTFa+iBPMSW1UQ27RFR0iqY9UmwAgYmUU3YD
4F9k35sBc8/lxL1IGFblpg3dSS/4CQ==
=9czZ
-----END PGP SIGNATURE-----

--oLBj+sq0vYjzfsbl--
