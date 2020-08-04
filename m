Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOVIUX4QKGQEQCGUQ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id F277F23BA4E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:27:39 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id w25sf949373oic.17
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:27:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544058; cv=pass;
        d=google.com; s=arc-20160816;
        b=WaklaOa0GxNk5Z8CQEYxnqVjkgCQEASEN7X562dQHA3rYkuu4G/fmQVe9rOixeFxKS
         6fYJpgDQB8A3uBHqlnpSSKDKOTnUm9gNIcWtEB6buVQsA5AAtUUuJ0BM7E6NGOiGIhua
         dUiwkI5kRrhuMP03CBEAd+XDlPVkK1RBrlJ9vZVGQSNRT6J1f+q+dR6VlJgplMLYE93I
         Viv8lHZonj/ML5xLeWyTYxtQEEd0zB2sdAuHyF74q4uIXPlgqhxbdD9j3vgAMgzNZUdY
         ROo6Tv6oUbmlZrv663Sdc2pf/ZcQUeDAYFU8ArE2AGOBZeD3nb8GTRZCB+3f1CrxAmV8
         UVOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bOY0uUeCe9LxnGLubgawKCT/wp6/oR9GaSP2W82gVsE=;
        b=ZirxXkbanweMt7jJvlho2Q8sA81vmzMzzAVldft9RbgnMha3RlOm7KERAb2FKlhvnF
         ZVTWdbqyPXHRY5q6qvycs89sR8HZDf3ipv0UbpDErqeM0fXW/iWQb+gmte/TNXo6446y
         Lf0ONSRWfDpNX/MNuucFQyjtWBw1aWL/htqPCYQn2bsjKEFP1ZCbGVNZ0e+yG2q6bSq3
         wqPLB90Hp0a0pYKZ6I18eXLTt4RN0MR+tJSd1ctYQYfESTTmBqsBPiLWCLiClEwE3YdT
         aJ71y2MlslPFPT21Xn+m6RWlDpJzBD5OjEe6HTw9lwdQH4JbhmysiXxcE+Co8vQf3Jga
         npmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NcQ2Qf6i;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOY0uUeCe9LxnGLubgawKCT/wp6/oR9GaSP2W82gVsE=;
        b=ZdsdZFxglAAP5+Ypv9swqHJhT+p8WZ3fbANgW5XDreogvvYjf6s/B3Wp4kEH93eLuE
         yl/spilFwXD4XyQCx3OB685eRzCwQzhofUHDAaSNM9uBhck6v254RI3cL3yLEi+uEnDL
         lasN/uclnsRI+bb9icTZk46tTRT3V+G6YiR9SsJ7v1ljut5ciHV2MSMevRlZM0AcKoE1
         AN9H8dW7i7fRiLcyRaivChM7vnZEYCiEOToUwbUrKJ4DUxTVX7koEMmaBV1aypcWQJEV
         lGtUp+tQY0VQRx9GwtdXU7llpoWYUzVbOvKGbn199CodnQdMvDyQWhxFyqxkwSNWR4C5
         DL+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOY0uUeCe9LxnGLubgawKCT/wp6/oR9GaSP2W82gVsE=;
        b=kZdiTHPOyU06tl540AwbZEGbYs/zaes3bioPks5uA9XE3xs/t5lHWN9QiQfNNAo0Uw
         qq6m0PhwratycRJ/bADPcSn98ufjNL+hUvd+XNmK6j98p2SPWgHwPIQzHUFT103SrjVn
         8f2B3/MpIkVdB+Rrgyfkz/NiB6NLX9uem400qbvBmNXH8pUgUj4c6dNnbhRTU3sxAQV9
         /6RucnjYvZYSHiiNqLbWJNU6XHwJoOOkDmJSN7mnZ9FJe2StqxJqai0RYYngkxvrbSUw
         gB2a7ydalpZM4g5nq0+0Ae98e6S5859p/bZtWYfVOH8h/6D2dX4TqsPupthTpzW9D2bc
         Y+rA==
X-Gm-Message-State: AOAM533p6QLDqJYuTLFuQoLhjirud1MHBJCJwt4xfFw1JeqmtT/3oCf5
	6fW/KhUObZp8rLeo0ZPnN7k=
X-Google-Smtp-Source: ABdhPJxSUeUdpDcsj1Sa4b3tlyk7loJJvO+FOw3dabVlflcqmjq5jK2uvmebwx0vTPeamLv2jzZkJg==
X-Received: by 2002:a05:6830:1bc2:: with SMTP id v2mr17854098ota.40.1596544058488;
        Tue, 04 Aug 2020 05:27:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2103:: with SMTP id i3ls4060556otc.3.gmail; Tue, 04
 Aug 2020 05:27:38 -0700 (PDT)
X-Received: by 2002:a9d:7d83:: with SMTP id j3mr4794601otn.339.1596544058168;
        Tue, 04 Aug 2020 05:27:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544058; cv=none;
        d=google.com; s=arc-20160816;
        b=Ku2CSFa1oKiqvZv8flvjxH5HVFXhvsE8MD/Tx/eoS2FUxKcrxfGvj4PvvRqvcN0aF9
         aVRGahSDS/JykUBJWIU13vLACrAJ9RE75wjinFSobSNsuxariysEexgYifmFtgpazo7e
         2oSPpUjbMYGj+dBDquWobL7IiHpJ9cdQxQd2xYXkgmlGhs3efAvuwEVOO/gtUCdqu0FU
         I5qCk/jxHs0tjSPSNr3ze4nTpGVwOAE4TGXbgR156NIpNPDdgNZzRbw4robQ65eGnBIK
         AGsDVnII5FwQxvhb4cp8TDt0xfwzSpZ5uc6ERjQMFYaXaOuNIbeuMvP5z3Nv2/gPMxqh
         hIIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BSEtcZMeEfd836sEUlnMwgLoZphV8omnRj5UAHtlG3M=;
        b=RC1wt/hg4WWP6OsDdi/cF5Wd6K/VQerrx4F3S2wYa1Xe25/CruEqD7P0zEb6onKVgP
         nrGFd7Q4YK+m4tEwgTx9fTmx1lT9EY3VWLowcxXl7gNx8mNhAPmtqPIIrRHygCY8s9Us
         BscyFn+zJEZT2Ck/88dUVkfKOOLRxxIm9IWRIWzboWM0Gk7JVrh1EXH7IKtwXTsjZspy
         rKu+lqxfFRz6LCHaZADG8PMcjIAfWTG/A3ru1spXjhx6jxjmkvRWUITa5rWIsq7mrzc0
         jsa9lVjj38j3cLoyK0On4jPdyWmKmqHvhAIHAZo34U2zBpaa64DQGEwrsgQg/bX38SHn
         QpwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NcQ2Qf6i;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id n22si1451407otf.2.2020.08.04.05.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:27:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id m8so13237258pfh.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:27:38 -0700 (PDT)
X-Received: by 2002:aa7:97a3:: with SMTP id d3mr20240734pfq.178.1596544057176;
 Tue, 04 Aug 2020 05:27:37 -0700 (PDT)
MIME-Version: 1.0
References: <202008020649.TJ8Zu7ei%lkp@intel.com> <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
 <20200803180358.GA1299225@rani.riverdale.lan>
In-Reply-To: <20200803180358.GA1299225@rani.riverdale.lan>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Aug 2020 14:27:26 +0200
Message-ID: <CAAeHK+wobK72fWK=v7JosQL3UEe2HG4n2wwVpf1PN30Xkra6rA@mail.gmail.com>
Subject: Re: [hnaz-linux-mm:master 168/421] init/main.c:1012: undefined
 reference to `efi_enter_virtual_mode'
To: Arvind Sankar <nivedita@alum.mit.edu>, Ard Biesheuvel <ardb@kernel.org>
Cc: linux-efi@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kbuild-all@lists.01.org, 
	Johannes Weiner <hannes@cmpxchg.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NcQ2Qf6i;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
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

On Mon, Aug 3, 2020 at 8:04 PM Arvind Sankar <nivedita@alum.mit.edu> wrote:
>
> On Mon, Aug 03, 2020 at 05:37:32PM +0200, Andrey Konovalov wrote:
> > On Sun, Aug 2, 2020 at 12:25 AM kernel test robot <lkp@intel.com> wrote:
> > >
> > > tree:   https://github.com/hnaz/linux-mm master
> > > head:   2932a9e66c580f3c8d95ec27716d437198fb4c94
> > > commit: 7c0265f304de3c3acd02d0015b56a076357bcce3 [168/421] kasan, arm64: don't instrument functions that enable kasan
> > > config: x86_64-randconfig-r036-20200802 (attached as .config)
> > > compiler: gcc-9 (Debian 9.3.0-14) 9.3.0
> > > reproduce (this is a W=1 build):
> > >         git checkout 7c0265f304de3c3acd02d0015b56a076357bcce3
> > >         # save the attached .config to linux build tree
> > >         make W=1 ARCH=x86_64
> > >
> > > If you fix the issue, kindly add following tag as appropriate
> > > Reported-by: kernel test robot <lkp@intel.com>
> > >
> > > All errors (new ones prefixed by >>):
> > >
> > >    ld: init/main.o: in function `start_kernel':
> > > >> init/main.c:1012: undefined reference to `efi_enter_virtual_mode'
> >
> > Hm, I can reproduce the issue, but I don't understand why it happens.
> >
> > +EFI and KASAN people, maybe someone has an idea.
> >
> > This is the guilty patch:
> >
> > https://github.com/hnaz/linux-mm/commit/7c0265f304de3c3acd02d0015b56a076357bcce3
> >
> > The issue is only with efi_enter_virtual_mode() AFAIU, not with any of
> > the other functions.
> >
> > Thanks!
> >
>
> After adding __no_sanitize_address, gcc doesn't inline efi_enabled() on
> a KASAN build, even when CONFIG_EFI is disabled, and the function is
> just
>         return false;
> and so it isn't optimizing out the call to efi_enter_virtual_mode().
>
> Making efi_enabled() __always_inline fixes this, but not sure if that is
> the correct fix?

Ah, makes sense.

We could also do #if defined(CONFIG_X86) && defined(CONFIG_EFI) in
start_kernel().

Or provide an empty efi_enter_virtual_mode() implementation when
CONFIG_EFI isn't enabled.

Ard, WDYT?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwobK72fWK%3Dv7JosQL3UEe2HG4n2wwVpf1PN30Xkra6rA%40mail.gmail.com.
