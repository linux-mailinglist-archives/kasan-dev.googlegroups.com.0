Return-Path: <kasan-dev+bncBD63HSEZTUIBBZ5OUX4QKGQEOEVZ5TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 117E723BA82
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:13 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id k3sf13860355ooa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544871; cv=pass;
        d=google.com; s=arc-20160816;
        b=T09zs8zx0pAW6gN5Qi91QBlf68+l4dkaMYNkE8fmeDAAZOWzd1FmzzXULskvYrzu1s
         MME+TzesKcAE8EaH1p60MJXDyiaOHPh8IFiRLw+UiDmF7OvTm9vKc8eizuqOW4CcurK0
         qbuQsSwxRc4m2XcxfM3GwW1z2K4BidQpTlnnKVCBR8+uSsCA2gKhutwpRQEIKzvBy3rF
         PHM6rgqZm2OYIDeI1RbvtovMsjFYaTra2elhzSNjWKGED8MuhhZPlfzjV+RJIzeU4CFA
         QyKCZG1SvhSJl+z25e56GTH2Zz9mrLF3A5T9fjcE0i77PERnGthcjUOKrfx8G7Me8XS7
         fGDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ME/G+wKBkQhGXn57crf1/b2wH0PPu1rJWVGswGvIN+s=;
        b=USgh+P80CAugwhWVUeniPVokVo0pRszehxl5QabyxrgxnjNfjw9crKv8mETYTLoiig
         la+YKu91qiWRHdqmcTghNYNwpPkWiCr2Rp/mt4yn/f6Fq9dojCzhBaZ91pjfZ9GtxP/H
         4pB9UztP7RiCZIUsUKj/CHBfDbSnLjmGkR9aJotK+drwXfUReb2o2+NRdfZwN5wHawVD
         bbjplz1/RzP1U6vV1bFeWa77thg6yjNlXdFafPiw3d8pF+0Yf6wbwOAdsjQ7s7XnbOUu
         COcZKxleFXKmClmJFJwfl/C8270U1UwW1h88UHZg6zXf/lc5ygYu0hPcBMttN9q84MG0
         re5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FSLS02wm;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ME/G+wKBkQhGXn57crf1/b2wH0PPu1rJWVGswGvIN+s=;
        b=mVmVvh6ejwK+M9TyXSac+1mgd4QYwGQrUGwau249uv/B5UFKgAZDHT5GwYZ8NSefcs
         TqXyHHcejDEvFmF/4CB5sA64nAU7pcRIUd7PvnOb4MlZAtgY+gyOr3IIFeV/IQQ4wptZ
         XwlvIafXmP5jkNtn/o6/OKMOvWkrreEc9ylowwB7T+yH2DMYMRRC+1jVTeFx2oJzY+I+
         lASoRcH876BjthvDinEybiXRNGHtyDWCWeombBV9KZJ5KqQE5HXHe/SPJkWwxIS6MNjF
         rW8rZT0oaXqI51bXPp5wv8NNgVQ/BdF9c2mdAjMzLFbNSmrVXJpbG+WHUtVlbtJIzbxQ
         +TSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ME/G+wKBkQhGXn57crf1/b2wH0PPu1rJWVGswGvIN+s=;
        b=bDJK0vqlZn+ED288rqJZcVTzkRKFwIVb9QQst6EN6qXRmFxZ5YvQ0XMzsKmJh1Yd+G
         J0KSzVOKXOjcZrujn2yBny3Mgy75sdfoRizT6R9s3cCuaMpEXeU9T7MHoKORtZkgXjp4
         bdsw8yUJltx11SoNiOqioKKb+TkCAal37tSxzRSvbf5X9du75NjM4MKX2xHTwZVG1855
         NabqSvze4aCSdtLCII+UuiivmZ+eTJ8bUKfruPhbldi5Z8/Kt4FZdS8eG2aZ2CDcXwA7
         rhKYUoOCRMmzNc6iqHer18YkoMnc40oIE667Z3r7bv9DQtRjhjwORpIw/tUo30yVajR9
         Moxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jipeR0p8oB6MaE1r9MBNkVofyA/cx7qjyjFciYKgkWWUmtZPz
	rwoUXB95BD7cCD7PZFt8CVA=
X-Google-Smtp-Source: ABdhPJxWFChN2AUD2WmA1blf7lU8tyO/8L+eoqjD0WW/+BGWlXcDSmxXEM3hsIj4r2JAuoNGMbqlPw==
X-Received: by 2002:aca:130b:: with SMTP id e11mr3008207oii.140.1596544871753;
        Tue, 04 Aug 2020 05:41:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d658:: with SMTP id n85ls2921050oig.7.gmail; Tue, 04 Aug
 2020 05:41:11 -0700 (PDT)
X-Received: by 2002:a05:6808:da:: with SMTP id t26mr3296380oic.72.1596544871520;
        Tue, 04 Aug 2020 05:41:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544871; cv=none;
        d=google.com; s=arc-20160816;
        b=Ci1MxSp3T05LWR4BtuRBdimLkxTYwQLHUrR1SBjLkj1ZAQVtZZshI7KY4zuvJ8phWj
         2nY8bOD1sBo+hIaZfSaBi4gFN/FHHxxvqEsfa87+FKtLHYzcBWc2E6zP971VUjXKmZZ4
         Do2s3h1R8rNWr7yPpKJwbMeaQTMazcEPt0eSXi0hNpONCVneBf4tiA/rlNfon6q8NFsf
         CSV9/LFa4CtG8bkOBkw1EjuiRLvmd7QFNTAyx+j0CJVeSyqoYwqot+sfmJFzPjptky4p
         l7vyMVGd+7dLQ0nUFvBxLMRDl4/MRk2Mn8BSudFh/0argUFhY7cVlEcdb3q1uy2Mh2s3
         +B0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zjKLT/iOsCh2Rf+Zfr9v7xIxNMSfYl5wgTWtETOahFI=;
        b=jOYMyUNFadLbqJnujhjRHRGIXZQ4iNczhtcS6e3TtAsinV1ZF0NqNePHdVCR1eMVa+
         VcBoeFHVRJdSm+lwXtOLDbWZYdwjP6u77BO2mi9cAHxyZZRNsP4EQTWITObFYpUUsp2e
         kV2MDBw4DJrLy/PYYSIh/ZK9ufYfKUsCb9RZIRT4kIbRPzcBeKd7w1C1urSvIVyGyceG
         9RdAbe4PGPZZgC2zMZ6fzKvEIB2wwMSj3eSQNmEbtFNHQxz55uqjyVBWjeg1O3c4GHzo
         kEIarolf/iJbiqlhOAH++z8n16hkXR3FyprJ48yP4/nw6sxaDMp5+eVO5snr7rmxaAQM
         llVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FSLS02wm;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c142si1120461oig.2.2020.08.04.05.41.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f170.google.com (mail-oi1-f170.google.com [209.85.167.170])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 96FCC21744
	for <kasan-dev@googlegroups.com>; Tue,  4 Aug 2020 12:41:10 +0000 (UTC)
Received: by mail-oi1-f170.google.com with SMTP id k4so36205195oik.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:10 -0700 (PDT)
X-Received: by 2002:aca:afd0:: with SMTP id y199mr3015769oie.47.1596544869896;
 Tue, 04 Aug 2020 05:41:09 -0700 (PDT)
MIME-Version: 1.0
References: <202008020649.TJ8Zu7ei%lkp@intel.com> <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
 <20200803180358.GA1299225@rani.riverdale.lan> <CAAeHK+wobK72fWK=v7JosQL3UEe2HG4n2wwVpf1PN30Xkra6rA@mail.gmail.com>
In-Reply-To: <CAAeHK+wobK72fWK=v7JosQL3UEe2HG4n2wwVpf1PN30Xkra6rA@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 4 Aug 2020 14:40:57 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEp0pc8UN-BnJPT36KAKNLOL1EUBHgLABJwF2qwLrz6KA@mail.gmail.com>
Message-ID: <CAMj1kXEp0pc8UN-BnJPT36KAKNLOL1EUBHgLABJwF2qwLrz6KA@mail.gmail.com>
Subject: Re: [hnaz-linux-mm:master 168/421] init/main.c:1012: undefined
 reference to `efi_enter_virtual_mode'
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Arvind Sankar <nivedita@alum.mit.edu>, linux-efi <linux-efi@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kbuild-all@lists.01.org, Johannes Weiner <hannes@cmpxchg.org>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=FSLS02wm;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Tue, 4 Aug 2020 at 14:27, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Mon, Aug 3, 2020 at 8:04 PM Arvind Sankar <nivedita@alum.mit.edu> wrote:
> >
> > On Mon, Aug 03, 2020 at 05:37:32PM +0200, Andrey Konovalov wrote:
> > > On Sun, Aug 2, 2020 at 12:25 AM kernel test robot <lkp@intel.com> wrote:
> > > >
> > > > tree:   https://github.com/hnaz/linux-mm master
> > > > head:   2932a9e66c580f3c8d95ec27716d437198fb4c94
> > > > commit: 7c0265f304de3c3acd02d0015b56a076357bcce3 [168/421] kasan, arm64: don't instrument functions that enable kasan
> > > > config: x86_64-randconfig-r036-20200802 (attached as .config)
> > > > compiler: gcc-9 (Debian 9.3.0-14) 9.3.0
> > > > reproduce (this is a W=1 build):
> > > >         git checkout 7c0265f304de3c3acd02d0015b56a076357bcce3
> > > >         # save the attached .config to linux build tree
> > > >         make W=1 ARCH=x86_64
> > > >
> > > > If you fix the issue, kindly add following tag as appropriate
> > > > Reported-by: kernel test robot <lkp@intel.com>
> > > >
> > > > All errors (new ones prefixed by >>):
> > > >
> > > >    ld: init/main.o: in function `start_kernel':
> > > > >> init/main.c:1012: undefined reference to `efi_enter_virtual_mode'
> > >
> > > Hm, I can reproduce the issue, but I don't understand why it happens.
> > >
> > > +EFI and KASAN people, maybe someone has an idea.
> > >
> > > This is the guilty patch:
> > >
> > > https://github.com/hnaz/linux-mm/commit/7c0265f304de3c3acd02d0015b56a076357bcce3
> > >
> > > The issue is only with efi_enter_virtual_mode() AFAIU, not with any of
> > > the other functions.
> > >
> > > Thanks!
> > >
> >
> > After adding __no_sanitize_address, gcc doesn't inline efi_enabled() on
> > a KASAN build, even when CONFIG_EFI is disabled, and the function is
> > just
> >         return false;
> > and so it isn't optimizing out the call to efi_enter_virtual_mode().
> >
> > Making efi_enabled() __always_inline fixes this, but not sure if that is
> > the correct fix?
>
> Ah, makes sense.
>
> We could also do #if defined(CONFIG_X86) && defined(CONFIG_EFI) in
> start_kernel().
>
> Or provide an empty efi_enter_virtual_mode() implementation when
> CONFIG_EFI isn't enabled.
>
> Ard, WDYT?
>

The latter seems more appropriate (as a static inline in efi.h), since
we could then remove the ifdef altogether afaict.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEp0pc8UN-BnJPT36KAKNLOL1EUBHgLABJwF2qwLrz6KA%40mail.gmail.com.
