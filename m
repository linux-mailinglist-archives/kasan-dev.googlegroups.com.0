Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPVQUX4QKGQEH4OFATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EFB8F23BA9D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:44:47 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id f131sf9138163ilh.10
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596545087; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y5Qwa/K4IVuoze/aiaHh0QUu4UMoYawVa4hO2zTzkqtBvQ1daLBjenW82pTahKJ+N/
         lW/d04OqspO11pWbkiPcXuaH6qLCTTZidAClegatDmpWjF3k59SOo533gxTtYhlqigoO
         CVVgKtxphVBD8D2x84hDo0ti3zD+oZtRmw3MLBdsRAsQxY2wqthFblxzFPKTdQvkK/pX
         hnWH1w2jyHbJp5roBmH1Nyje5YzcuCwrAw5K69FNy7IyBKPasH30MWEZKC7T2BY5KM30
         aHDS/Qd3m/J+KNhVF6aOumglrPhM53Y0UftldNTXJrlaq6gImMK5eaTWdpkJSDoMTchm
         sXrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C3vLGj5RMl0SpsjnrUKJP0UCNCZpTMhdZtKVoa+lVpM=;
        b=iEmw2F9rwjF0AvGXDDM66Re2Squb/t2WlhfEZt+8whswI5Zecyq/8bPVEjWHTmpm82
         pWRJ6qsJN5lJ8IwPu+dj7Y3rvPbtVRFwpz8RgORkU7dGgdsKPDtkdIbHto4ZqOKPUT1E
         F/gG6REu2eqHIEykAig5SJxUu5MK03GK2vrHY0iPaPu9+jxf4pD7iOOU45HW/PwP/Owy
         CIc+RbTNR5odO/zdHucnc5+4TcSnvhphcFy6ZCR/CGG5Dzx16v99hDLQ+WWudVZdRXD3
         /FqAkmu2jveH97yfABJ7Z6z6lbVj9twpgYo74KNX9wHna3oaQuoFde1g/Q5e6ESOmZ08
         JTlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hN+ZgtJj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3vLGj5RMl0SpsjnrUKJP0UCNCZpTMhdZtKVoa+lVpM=;
        b=syAz62on2EyYkCTBDIbMuyw//nh67ehsit/dLK5qxqsK1aY4g00EgFt4Q3e0/XiwYs
         scJabJINM1dzoheG9eZEZqsBEpmzxcB0qno6gU3CR4r/+eDHl+0iTq7R0xINDvJsNPRD
         VgbSKcupQpshRN9Jmb2YTZyk4HaNuLG5l6mjonWyGKCvW/wNw4nSgty5RUvSf0A5qrhz
         UyeLBCXuo53mC4JTwk6tS1qy3inRAABMnKOQR9+AxJfYaSGnwBtCh7QdxZjkC5mcIIxE
         3y5hEJLWNQ+5M4t18JgZdnQxsNPl2Xm2FXl7TGIh5LWuYqlLD9CODs+LVjRPZ3ZQ9HN9
         3SLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3vLGj5RMl0SpsjnrUKJP0UCNCZpTMhdZtKVoa+lVpM=;
        b=X2qfj+kg+YGQ9/8qPaS6+edqhxwZb2VPdbmKZpCbIEe2hgjDVuGNHFXZlbLtpWKbmw
         HqID9rx4CI86HdbnWAeEL39XLqEV+7OQkecUc4GmXbyxC/IUdJtoSIct6ei7EUIagxlr
         kx2UrCrCKQUXRHBb8HJXYLXKjFLavSKMAVfFNEeMvrXfK7O0q0/fzwfVJz094JNQRbkw
         mr4PcWnANaRRJOab8Pl9BBdhdA97I1Z2WRiBAtjlRYuhndh9LTDiTmeDb3da9sx7Kwhv
         hwrvbtY4kcaSMbzGlijihiCBsizqHHYbs19FRHQ9fau2iqrwJGFuEYBTZWWiKjT1A7FX
         GWmQ==
X-Gm-Message-State: AOAM533KusUgQ6KrW+oB3C56o7awwshWpWUTAvRYF4s8q+Wfin5rCaT2
	ar5o6WgkMVS9Ndxy/ULE7pU=
X-Google-Smtp-Source: ABdhPJxhJDQu1yixB3d8fLcobUNyY4exLtafKwnpjZdLMauIr6ckJOFg6SUAsVp2bxt7TIjGJzZpNQ==
X-Received: by 2002:a92:6a07:: with SMTP id f7mr4672816ilc.271.1596545086929;
        Tue, 04 Aug 2020 05:44:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a1d2:: with SMTP id b79ls4072294ill.0.gmail; Tue, 04 Aug
 2020 05:44:46 -0700 (PDT)
X-Received: by 2002:a92:d611:: with SMTP id w17mr4705836ilm.103.1596545086655;
        Tue, 04 Aug 2020 05:44:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596545086; cv=none;
        d=google.com; s=arc-20160816;
        b=b/P04+S+QpHBolm3kyWJfm6Bmds+X46SnfzLOx9IxnQZ8wt4OfZ0CfdqwZujdAyGQJ
         aBoDq1M5+kM/O7F2kj5xQGyds3WstFHNBz0Y7T5hVf5GHgZcfysVVfYQQMsT7fMfLhcw
         Hwd0M0JRy0U3VSR1mSkBXWDERMUY5JAtj7LPVRB+1A1zwP+s/i+/wJzC47ApaKaUzDSw
         WQfqCWwI4mSBjw+6FyJEFR8nec0tOjrlGVod24aQHyEp17Vtd9aarRhe5ftctd00Qutm
         R2yqHyM0O2X1r9sLxocz5vFecWaNrzFvlvk3zdHKhaGCmJQSeo0Vhmssf6STFaAMFvZ6
         WgLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ryvLjVG1MrLc1WL5a6i4V+mIwati9JdZFbrWPVnD1eA=;
        b=kVfoypK3X/oTSJnQuFFeEcHG5rvVsGERsPjqK1EoQIKwRfTO3N1jsyvQhgGlUBKKoI
         Bhpwycv8yrBkSjdOHIC9rLD6G+HOBww85MvyrfZIYp6XTqHZN64dBtrOK224wg6On1vd
         VpYVe4kZD7KjvkiW959bmVlRRNc939FMeqKAew7u2RgjBfN0B6yLdIMustnNPY02qYxb
         a/8W4sjFxtD/trtmSkwbxEI8Syrvh8qZZxs7nQ5pkw2EtbC5nbRQmWQxBLwf7769na5K
         L8vk6ubR+nf8VYcI4WVsVuWVa3dXkPVLjMA0k4B3XI87c6EzLwMp/a2qsvIWdh2UuzMs
         GVZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hN+ZgtJj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id k8si1294981ios.2.2020.08.04.05.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:44:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id 74so11858483pfx.13
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:44:46 -0700 (PDT)
X-Received: by 2002:a62:a101:: with SMTP id b1mr845628pff.306.1596545085771;
 Tue, 04 Aug 2020 05:44:45 -0700 (PDT)
MIME-Version: 1.0
References: <202008020649.TJ8Zu7ei%lkp@intel.com> <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
 <20200803180358.GA1299225@rani.riverdale.lan> <CAAeHK+wobK72fWK=v7JosQL3UEe2HG4n2wwVpf1PN30Xkra6rA@mail.gmail.com>
 <CAMj1kXEp0pc8UN-BnJPT36KAKNLOL1EUBHgLABJwF2qwLrz6KA@mail.gmail.com>
In-Reply-To: <CAMj1kXEp0pc8UN-BnJPT36KAKNLOL1EUBHgLABJwF2qwLrz6KA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Aug 2020 14:44:34 +0200
Message-ID: <CAAeHK+z5jv58tXC6JuNseFOYoNq6y1Q6SZArjB_jbrQ_peBhzA@mail.gmail.com>
Subject: Re: [hnaz-linux-mm:master 168/421] init/main.c:1012: undefined
 reference to `efi_enter_virtual_mode'
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Arvind Sankar <nivedita@alum.mit.edu>, linux-efi <linux-efi@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kbuild-all@lists.01.org, Johannes Weiner <hannes@cmpxchg.org>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hN+ZgtJj;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Tue, Aug 4, 2020 at 2:41 PM Ard Biesheuvel <ardb@kernel.org> wrote:
>
> On Tue, 4 Aug 2020 at 14:27, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Mon, Aug 3, 2020 at 8:04 PM Arvind Sankar <nivedita@alum.mit.edu> wrote:
> > >
> > > On Mon, Aug 03, 2020 at 05:37:32PM +0200, Andrey Konovalov wrote:
> > > > On Sun, Aug 2, 2020 at 12:25 AM kernel test robot <lkp@intel.com> wrote:
> > > > >
> > > > > tree:   https://github.com/hnaz/linux-mm master
> > > > > head:   2932a9e66c580f3c8d95ec27716d437198fb4c94
> > > > > commit: 7c0265f304de3c3acd02d0015b56a076357bcce3 [168/421] kasan, arm64: don't instrument functions that enable kasan
> > > > > config: x86_64-randconfig-r036-20200802 (attached as .config)
> > > > > compiler: gcc-9 (Debian 9.3.0-14) 9.3.0
> > > > > reproduce (this is a W=1 build):
> > > > >         git checkout 7c0265f304de3c3acd02d0015b56a076357bcce3
> > > > >         # save the attached .config to linux build tree
> > > > >         make W=1 ARCH=x86_64
> > > > >
> > > > > If you fix the issue, kindly add following tag as appropriate
> > > > > Reported-by: kernel test robot <lkp@intel.com>
> > > > >
> > > > > All errors (new ones prefixed by >>):
> > > > >
> > > > >    ld: init/main.o: in function `start_kernel':
> > > > > >> init/main.c:1012: undefined reference to `efi_enter_virtual_mode'
> > > >
> > > > Hm, I can reproduce the issue, but I don't understand why it happens.
> > > >
> > > > +EFI and KASAN people, maybe someone has an idea.
> > > >
> > > > This is the guilty patch:
> > > >
> > > > https://github.com/hnaz/linux-mm/commit/7c0265f304de3c3acd02d0015b56a076357bcce3
> > > >
> > > > The issue is only with efi_enter_virtual_mode() AFAIU, not with any of
> > > > the other functions.
> > > >
> > > > Thanks!
> > > >
> > >
> > > After adding __no_sanitize_address, gcc doesn't inline efi_enabled() on
> > > a KASAN build, even when CONFIG_EFI is disabled, and the function is
> > > just
> > >         return false;
> > > and so it isn't optimizing out the call to efi_enter_virtual_mode().
> > >
> > > Making efi_enabled() __always_inline fixes this, but not sure if that is
> > > the correct fix?
> >
> > Ah, makes sense.
> >
> > We could also do #if defined(CONFIG_X86) && defined(CONFIG_EFI) in
> > start_kernel().
> >
> > Or provide an empty efi_enter_virtual_mode() implementation when
> > CONFIG_EFI isn't enabled.
> >
> > Ard, WDYT?
> >
>
> The latter seems more appropriate (as a static inline in efi.h), since

Sent out a v2 of my patchset with this exact fix included at the same
time I received this response :)

> we could then remove the ifdef altogether afaict.

I didn't do this part. I guess this can be done as a separate patch,
and will probably require some more testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz5jv58tXC6JuNseFOYoNq6y1Q6SZArjB_jbrQ_peBhzA%40mail.gmail.com.
