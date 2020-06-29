Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLEQ5D3QKGQENKSIA4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ECA720CFA8
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 17:26:38 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id a12sf2895132oia.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 08:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593444397; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lz7n2Fgknn5tjDbsLflcA5lEqV1q5ZRQHm4JY+xZdfbdJgvXW4Lx4EgEiXowiw2SNQ
         3eV/rTJN26LFv/m9ZZ39ZBgXq+aRAyicBEVlhkGG78ly0PLyrrJh6XGVsHjUAkh3EuoG
         ejbHxbZ3coZR8lbZ0AgJuX5CHNW16wDKsaPoJJSeJtMdbH7/PqUjRasggNlQseYIPy6F
         i1SYkX0E5b3PKLRMt7u99zW2FjuSGFspHxSlnFwugMkcH+wzU0EXuaF3Tadb6jDkpptC
         hT5lc7mxgggnKEgyOEfhf/bz3II8jH8blYa58IoNTBuPFVnhr+my7Ins3h++in9dGzfI
         GLPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JJ7N71H0OZKPuvNb6N2ATTZQ5O+dmeSN4Va8eimBQ6A=;
        b=Y5TPiBlzefPLCD6h6CBi9YkR0s7uNFmMt7yNZF3wFjwg9YmmGTjzL22hxRXqlFZheo
         RsR55e65DANTce4su3LE6JvMaOYm6a6YRtrD0jIwRkNKnhVqzNYfshHyzN7IdrMTKhdz
         1WgIjqpmnndDa64zMtShmVcfcS0hEQqbZtBLeVcmi1qJiWJ6LKuxX5GFMSWbCoyx630R
         VjJuHZAqGQlM6C8wwzHA8fsJbt7o9PnZIM7WGOry2o1enUuMZfG8cI5sKjDD8oButO57
         G/NY5/BSO0GoiBFDmKmhjyaTZt/Duab9DD51lTwC6z7zjpXoMHIyt/sSnr86irfvuWno
         53gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qf7Kj9RQ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JJ7N71H0OZKPuvNb6N2ATTZQ5O+dmeSN4Va8eimBQ6A=;
        b=DhxfoQK1YtUPFT4yeQuMakmnZBugi0PbDNcWpwiqG9KnbWXti7/4nvqEuaa8oURmJe
         jadQJ0n7OOU5yW8x/8NsGdCQvr+99DYA8zeW2iYZ2d7ll4PKeVXBCYEmGbC+Ev3uS6kL
         z2NlsAZ2oZl7eRNFKEuQ6Rb5be4G/NNFfE1zB8hQTU7EneYDuEesJcsOtqJXoaYXWKNy
         anNTnSm4sD+Ar5l/IIgQv5ajx1GT2j27ZFSVkgJXrzTvmUixtLCXCgcyPedoqyE+r7+F
         ewE8/kv9MhsetVzofEWJ6HHHrirZ/tVV2c3DpWSHEz0ULPvMkXhd9anzUb4CfQTbqCKg
         aogQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JJ7N71H0OZKPuvNb6N2ATTZQ5O+dmeSN4Va8eimBQ6A=;
        b=Pr20Nkl5cTSBHnjz+0ied0T0BjbWJbsBTCrB5zY3CTu2y5gFaYFqUALRFzqAt4UQzJ
         MHCyDBkkSQKFFzbMKCcabxtd+xHSzBRRvMyganOPuM2lvc5jMlle0fnkXE5KEr7LumE5
         sgnKMyP0iEV4HA/15rp2PGrDKIdp/xj6g5UMdOUF+LGfMnkRWGhlf5DZYDiM7Q3S4yrs
         D2WeiF/2jbolSsHiFsZ2bty3FpzLa9ZhQbLNBMFaPN61ep+EJ5Rtawdrj2xoqe22BbGO
         5JBP5HHEzEfavcAsw0iJnpJJjcb5IMYSfZJB8m9B+PcQ1xkTsyg7GyPEgNPrt0wiGrzd
         8YKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531p/HIKVQz3jfrP3H1VgQ/7V5JcIOyuGOjyz4hyCzLd01HInlk7
	s9+tipQN504Pp8U1lMTwbrI=
X-Google-Smtp-Source: ABdhPJz2NBSysRbiIdX4wYoLkkRc303m5vq8ihdsgeCQYGWG3MYIb940JBfuyoYRVu2rRr3gIMl6XQ==
X-Received: by 2002:a9d:6546:: with SMTP id q6mr13360467otl.365.1593444396879;
        Mon, 29 Jun 2020 08:26:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cfc3:: with SMTP id f186ls1158814oig.11.gmail; Mon, 29
 Jun 2020 08:26:36 -0700 (PDT)
X-Received: by 2002:aca:d884:: with SMTP id p126mr12843728oig.4.1593444396550;
        Mon, 29 Jun 2020 08:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593444396; cv=none;
        d=google.com; s=arc-20160816;
        b=EomwGSvjA6cEC7r1ZAYomOXAaVIMqt2UNsG1WoRoXg9Ul7qHkPCH13Ccor7Zz6iq5O
         aBYLB3mMKCP0sy20yUPYgc8bIZF2tweXdAt5JakLYTB9L1xFzJ8t+q625d9K8bp1QpEV
         U0qew8uqAB3D65tAcnkWo/C14yKoDkOXdYgUHt/QRTe3wGKRqb+cffBiYmkaUWMfGPXd
         GANkF9VHXijPKy1emyj8E+ZlGhX2naYdjiJp4gLMck8CEMDwI2yU8SfKRU+T4FlY6N+O
         imaaS29VmIK3W07Az/jwg5d7P6EmWnym5eKlRxndisOn1WXMKsg/EEbKevoTwVA20Wrb
         A2Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xYRvEczki6SokBOpOA5suBGpzozsRhEF1obfHkhFJwc=;
        b=KR6NSOuyQ0BD3+A7bykqUcFAV3xsMlI4qUd1gUHtagZDkNt3WyV31xA3Q8AuM5ETH6
         QtULsS2j2WQI/HE3nS4hfq0jWT45eOMoJe9zeT+Drwb8FA2VKeVM3mbtflhbvjxC6FWZ
         mMKnAAVPR8um1GKPa5VjE5XF2bQ154P2NXKbtpWVci4o7CJeNzsMEU15Lcsr8q3lAMEt
         vAceg2zWF+IT0ConZWK93TLoWCLtsKprjowNIR9GMNs6J5reFe+KoGDN3OhXd3ctWbC+
         N2ol+3MeSGSX3zItK35nQ79Lw7lL6Y8JF4adeXfUNnn9me2r7uUJMGh/w4X7BmBOXepM
         l25Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qf7Kj9RQ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id j2si6781otr.0.2020.06.29.08.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 08:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id l63so8432654pge.12
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 08:26:36 -0700 (PDT)
X-Received: by 2002:a65:63d4:: with SMTP id n20mr11219744pgv.213.1593444395814;
        Mon, 29 Jun 2020 08:26:35 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id p8sm174642pgs.29.2020.06.29.08.26.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jun 2020 08:26:34 -0700 (PDT)
Date: Mon, 29 Jun 2020 08:26:34 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: kernel test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 4/9] x86/build: Warn on orphan section placement
Message-ID: <202006290819.955CF6743@keescook>
References: <20200624014940.1204448-5-keescook@chromium.org>
 <202006250240.J1VuMKoC%lkp@intel.com>
 <202006270840.E0BC752A72@keescook>
 <CANpmjNMtFbc_jQU6iNfNx-4wwQF4DY3uaOB1dCPZ3dMqXx6smg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMtFbc_jQU6iNfNx-4wwQF4DY3uaOB1dCPZ3dMqXx6smg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Qf7Kj9RQ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544
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

On Mon, Jun 29, 2020 at 04:54:13PM +0200, Marco Elver wrote:
> On Sat, 27 Jun 2020 at 17:44, Kees Cook <keescook@chromium.org> wrote:
> >
> > On Thu, Jun 25, 2020 at 02:36:27AM +0800, kernel test robot wrote:
> > > I love your patch! Perhaps something to improve:
> > > [...]
> > > config: x86_64-randconfig-a012-20200624 (attached as .config)
> >
> > CONFIG_KCSAN=y
> >
> > > compiler: clang version 11.0.0 (https://github.com/llvm/llvm-project 1d4c87335d5236ea1f35937e1014980ba961ae34)
> > > [...]
> > > All warnings (new ones prefixed by >>):
> > >
> > >    ld.lld: warning: drivers/built-in.a(mfd/mt6397-irq.o):(.init_array.0) is being placed in '.init_array.0'
> >
> > As far as I can tell, this is a Clang bug. But I don't know the
> > internals here, so I've opened:
> > https://bugs.llvm.org/show_bug.cgi?id=46478
> >
> > and created a work-around patch for the kernel:
> 
> Thanks, minor comments below.
> 
> With KCSAN this is:
> 
> Tested-by: Marco Elver <elver@google.com>

Thanks!

> 
> 
> > commit 915f2c343e59a14f00c68f4d7afcfdc621de0674
> > Author: Kees Cook <keescook@chromium.org>
> > Date:   Sat Jun 27 08:07:54 2020 -0700
> >
> >     vmlinux.lds.h: Avoid KCSAN's unwanted sections
> 
> Since you found that it's also KASAN, this probably wants updating.

Yeah, I found that while testing the v4 series and updated the patch
there.

> >     KCSAN (-fsanitize=thread) produces unwanted[1] .eh_frame and .init_array.*
> >     sections. Add them to DISCARDS, except with CONFIG_CONSTRUCTORS, which
> >     wants to keep .init_array.* sections.
> >
> >     [1] https://bugs.llvm.org/show_bug.cgi?id=46478
> >
> >     Signed-off-by: Kees Cook <keescook@chromium.org>
> >
> > diff --git a/arch/x86/Makefile b/arch/x86/Makefile
> > index f8a5b2333729..41c8c73de6c4 100644
> > --- a/arch/x86/Makefile
> > +++ b/arch/x86/Makefile
> > @@ -195,7 +195,9 @@ endif
> >  # Workaround for a gcc prelease that unfortunately was shipped in a suse release
> >  KBUILD_CFLAGS += -Wno-sign-compare
> >  #
> > -KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
> > +KBUILD_AFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> > +KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> > +KBUILD_LDFLAGS += $(call ld-option,--no-ld-generated-unwind-info)
> 
> Why are they needed? They are not mentioned in the commit message.

This was a mis-applied chunk (I also noticed this in the v4).

> > +/*
> > + * Clang's -fsanitize=thread produces unwanted sections (.eh_frame
> > + * and .init_array.*), but CONFIG_CONSTRUCTORS wants to keep any
> > + * .init_array.* sections.
> > + * https://bugs.llvm.org/show_bug.cgi?id=46478
> > + */
> > +#if defined(CONFIG_KCSAN) && !defined(CONFIG_CONSTRUCTORS)
> 
> CONFIG_KASAN as well?
> 
> > +#define KCSAN_DISCARDS                                                 \
> > +       *(.init_array) *(.init_array.*)                                 \
> > +       *(.eh_frame)
> > +#elif defined(CONFIG_KCSAN) && defined(CONFIG_CONSTRUCTORS)
> > +#define KCSAN_DISCARDS                                                 \
> > +       *(.eh_frame)
> > +#else
> > +#define KCSAN_DISCARDS
> > +#endif
> > +
> >  #define DISCARDS                                                       \
> >         /DISCARD/ : {                                                   \
> >         EXIT_DISCARDS                                                   \
> >         EXIT_CALL                                                       \
> > +       KCSAN_DISCARDS                                                  \
> 
> Maybe just 'SANITIZER_DISCARDS'?

Sure! I will rename it.

> 
> >         *(.discard)                                                     \
> >         *(.discard.*)                                                   \
> >         *(.modinfo)                                                     \
> >
> > --
> > Kees Cook

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202006290819.955CF6743%40keescook.
