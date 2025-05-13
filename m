Return-Path: <kasan-dev+bncBDT2NE7U5UFRBZ5ZRXAQMGQE677D6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C65AB57A7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 16:53:29 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-30c21be92dbsf4965211a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 07:53:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747148007; cv=pass;
        d=google.com; s=arc-20240605;
        b=PhzGH+dPyhgq/GgzVzHBhddMFzy1o7jV+0hUHDUZCz7wzTsernO5gx7NW8ZPXNH9/P
         +wFoBOzHhkv4jMPZIuOx+Fsm2rUQYbT5ctfQBRYeMDXdVmlZliqX2Ne3IuknqpV8WhSs
         vvVPiRsj9ivkPJQAtl4164BCuYD+lxaysp7I6ivClRiPhSbGomIxy+OY+yLpFkIss1Oc
         u6fIPu3pvsykEBKpIEk9dWv8GbKGkKD1Y2TZc/fjTpCPL+Us+x3GX0WUqNyCGG+6PLno
         o/5qAPRFhYsJWjo18z9lauJ0pLJfVLSLVMHycQeEOEGrTbSDNJK3GKFXNRm2y3zc0jGx
         uSUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IHRxmcsq/LO8gYg5XPgOM/zSgW1FKNTbUYabTnjREBE=;
        fh=wdbS2h8Yzl4bbn4ya+30HSyNe8A6Vt3Ie+1Crq5fM54=;
        b=Mxm7QD04QndJo59pEmPbx/PiEnNnfczFAU3LktfeZgYR6/4UNaYGVEnlJLCT9dyC+p
         g3qs6FqZU1KQuL/bFlfDaFNr8fDoeFMhR8VzIk42OMSIleWyZ+YW5+03g9FxGDHHdVPE
         t1dEkgTl6papCcc80Ik2rDXCWJ4KiX4wZXNxY+/mh1L7dVtYNW2QWIewwLN6HVymK9qd
         aN59KFficzQrI7DbEhS4hhdF0J178IypMtAx9gEFjCysqbIrKmreTidUmfIUHQdBvnvP
         5F3R5TosbxNhFwirLBIKppwq/NmjLX7MEINpQ0mc977ZJWbeAchkDqJRpZR8f/8xPgco
         6zZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Idosnr1F;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747148007; x=1747752807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IHRxmcsq/LO8gYg5XPgOM/zSgW1FKNTbUYabTnjREBE=;
        b=GjoYo7dtg20bQeqbJ/hes+uGL89rgofnzgTdBvRSc/r/KOrt5qoSHTKp1ddG4A63k8
         BR6NN+lBiJBUguRDfBHYeD+KYHXJGloRzlKr/qSFO5MNnmZtK0R1OYti8nqRR+ztJzJX
         DD79r793ept2DIy34TaveWeQilXXW0i1suhYxv6MQAStAIjZnxq6aUPcZTNxWDP7UWQa
         44NFkX8Oe1ygKHWKXDOIr+L9LAvIfdy1lG2Pt16B17PNsu8pNGLCJgYxCDIc0aBbD4pS
         jLxwUjplTF5eGy91YFFWhPspXWdsdPAi8afL27/fMd/jteIGP6JUw4ddgXQcB16Bbn4P
         4bMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747148007; x=1747752807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IHRxmcsq/LO8gYg5XPgOM/zSgW1FKNTbUYabTnjREBE=;
        b=jFHxK30ZFDJryNwcmgD5kwwRew8zlIBarJ/Ka4Dw8U+qa/HoXRnFcKN02N5cCSungJ
         iXFY7lXZWVSReGefUB7vKCUj8AXAnozIcSZhVpbpROGbBoUzJk4gonga1HoU2eNza1eU
         qWf6wazGAF6bSIvIM/ysMgYcO5AxZCPJJ/EzJtL8/UJ7i9ZVwpfEAJsa6ZD7a+cENYq9
         Ycg7Bv2xLv5Z1xwjmZzOhLvDIB7pIle561ch+gekIaatCVpY3mqwFsW+XIU0ld5Cjksj
         zd2p/FqMWFpRXwvlMGolrir3QxMSqmb+gSQ0yMDpzUem7AGIzcbcbbLUzE0PTbwf5Trj
         WDig==
X-Forwarded-Encrypted: i=2; AJvYcCWmWPgZ0OxvV8H9p45jji1wQmCsXROy7MWsnHP+EoFplYFo0TRIynHuepkGBnjOvM9JiMia8Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzr1IjbaTnwev7VTwo4pDg/WdPkpzhS29Q8JSO2e0g/48VjOz/4
	AUtaO926DeJsn8H2P53l+jQetjl54ExkVcbTiGGV9cPnLs8TyyGw
X-Google-Smtp-Source: AGHT+IEzbQa7BVMsehtz4cc5AuzGjfq0TwRLw2mqTtGTNAfWU3RHha7NPYj/qo6m9JobwTnHuckc1Q==
X-Received: by 2002:a17:90b:544e:b0:2fa:562c:c1cf with SMTP id 98e67ed59e1d1-30e0daf57a4mr5526339a91.1.1747148007399;
        Tue, 13 May 2025 07:53:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGgTMVY7Zj0Uk3H00EXD7siMzQ84nNyYaymhRbbwQa8ww==
Received: by 2002:a17:90b:2710:b0:30e:f92:97a3 with SMTP id
 98e67ed59e1d1-30e0f929881ls767426a91.0.-pod-prod-00-us; Tue, 13 May 2025
 07:53:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEMpOEzsMxDFKhTJN0y3/0m+30u/qHD2Uv9qRZqwrYFF2gT5C1E/dWVdtRcSfgJu3WHrCK76pckk0=@googlegroups.com
X-Received: by 2002:a17:90b:51cf:b0:2fa:42f3:e3e4 with SMTP id 98e67ed59e1d1-30e0daf5dd2mr5115100a91.3.1747148006006;
        Tue, 13 May 2025 07:53:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747148005; cv=none;
        d=google.com; s=arc-20240605;
        b=dVVXNCpAkTnjtFbr8jUYbxTKhto1h0AKFeOqSNXoexiG97rt6uGnCcKCWsVQQ+g5pB
         z3UV2hPThGpIpvtJ8PzfjO1H4Euc33BnRPhg8AVq0b8vt5I6R8Jwy70Ca4gsUAqgr+Cu
         6UVYhapQKygpxyZ7i/yutkBftTu1s1lVdAeAVWsw81oeLfc0NjzJjIRjIg/61ozEIcMR
         5Knx1mWn2QBDwMEpT0KgQQTpfHGLXkcWLJHgwno9F4ywT9CeZzwvRXch0FwcSYE5im2U
         wbY6/6zavxhzB7jcEMplFCjEcUoyHYsjRBmDKCqsvmLAz261NFvA2bflFmRFEa9C5zJI
         IQOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xYXWIGZUa9iD4M5Vxipvhs4dP+FyKofHObmUxNweb+o=;
        fh=FmrewSUaEnlVt3IXKsSwMZlgwUSD3wYe3psqZvdcsgE=;
        b=bPSYHAJvfn6DQMmsdDLYQwVjV/GlsI+j0+MQJClqJGZeUk5uC1X/m1hnFsOGemggHy
         RXWjObppi0GsGav/PSHCUVZAo3PQCz7P81EXJL7YhGNZd/3vUYXtgjyqAP9fme7YIODD
         2A+It587C8E3LfQ7n3nxXxLtfxpKxfcIcdEdpMX5c4VJQ7ndr+dSW/Ip3y71p/FZ/esl
         PZA2uOFttbyhNhuz5BxUXIESyVMQi7O5XaS12kf00Vugu0JHHiNlHcwgKTF1hkLP0rx0
         d8lpVeqmRUusHwgJamRi6DfDcE/7rBMm8KCcZRoQxwuIkTK2RuGini5+2YeA/5ztyNk0
         D5XA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Idosnr1F;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30c39e132adsi62980a91.3.2025.05.13.07.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 May 2025 07:53:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 28E56A4D939
	for <kasan-dev@googlegroups.com>; Tue, 13 May 2025 14:53:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C1D99C4CEF1
	for <kasan-dev@googlegroups.com>; Tue, 13 May 2025 14:53:24 +0000 (UTC)
Received: by mail-lf1-f49.google.com with SMTP id 2adb3069b0e04-54fc29f01c4so5765454e87.1
        for <kasan-dev@googlegroups.com>; Tue, 13 May 2025 07:53:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUDY03p8XabUvHp5hauJkSh70h3O7YO/Nq81jYnzumbzGHeL/6Q8sQ3HU8UIRI+F0IU+XAWXf95Cks=@googlegroups.com
X-Received: by 2002:a05:6512:2619:b0:545:4cb:b25d with SMTP id
 2adb3069b0e04-54fc67b7bb6mr4265580e87.13.1747148003495; Tue, 13 May 2025
 07:53:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org> <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
 <202505031028.7022F10061@keescook> <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
 <202505080953.789B3381@keescook> <CAK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q@mail.gmail.com>
 <202505081651.EAF0C6B@keescook>
In-Reply-To: <202505081651.EAF0C6B@keescook>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 May 2025 23:52:46 +0900
X-Gmail-Original-Message-ID: <CAK7LNAQa_ZX=ULUgu+_YNe=A+4kgaZakzdM2Y6QPSWWfnEA2JQ@mail.gmail.com>
X-Gm-Features: AX0GCFuWQSZF1ok9-cTyrGeb3aw8P4Ea1DCgPaNu4qIZQbEPezGGKicgvHdcmqc
Message-ID: <CAK7LNAQa_ZX=ULUgu+_YNe=A+4kgaZakzdM2Y6QPSWWfnEA2JQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] Detect changed compiler dependencies for full rebuild
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Petr Pavlu <petr.pavlu@suse.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Justin Stitt <justinstitt@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Johannes Berg <johannes@sipsolutions.net>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Idosnr1F;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masahiro Yamada <masahiroy@kernel.org>
Reply-To: Masahiro Yamada <masahiroy@kernel.org>
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

On Fri, May 9, 2025 at 8:59=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> On Fri, May 09, 2025 at 08:13:18AM +0900, Masahiro Yamada wrote:
> > On Fri, May 9, 2025 at 1:56=E2=80=AFAM Kees Cook <kees@kernel.org> wrot=
e:
> > >
> > > On Fri, May 09, 2025 at 01:44:09AM +0900, Masahiro Yamada wrote:
> > > > On Sun, May 4, 2025 at 2:37=E2=80=AFAM Kees Cook <kees@kernel.org> =
wrote:
> > > > >
> > > > > On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> > > > > > On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.o=
rg> wrote:
> > > > > > >
> > > > > > >  v2:
> > > > > > >   - switch from -include to -I with a -D gated include compil=
er-version.h
> > > > > > >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kee=
s@kernel.org/
> > > > > >
> > > > > >
> > > > > > What do you think of my patch as a prerequisite?
> > > > > > https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-m=
asahiroy@kernel.org/T/#u
> > > > > > Perhaps, can you implement this series more simply?
> > > > > >
> > > > > > My idea is to touch a single include/generated/global-rebuild.h
> > > > > > rather than multiple files such as gcc-plugins-deps.h, integer-=
wrap.h, etc.
> > > > > >
> > > > > > When the file is touched, the entire kernel source tree will be=
 rebuilt.
> > > > > > This may rebuild more than needed (e.g. vdso) but I do not thin=
k
> > > > > > it is a big deal.
> > > > >
> > > > > This is roughly where I started when trying to implement this, bu=
t I
> > > > > didn't like the ergonomics of needing to scatter "touch" calls al=
l over,
> > > > > which was especially difficult for targets that shared a build ru=
le but
> > > > > may not all need to trigger a global rebuild. But what ultimately=
 pushed
> > > > > me away from it was when I needed to notice if a non-built source=
 file
> > > > > changed (the Clang .scl file), and I saw that I need to be depend=
ency
> > > > > driven rather than target driven. (Though perhaps there is a way =
to
> > > > > address this with your global-rebuild.h?)
> > > > >
> > > > > As far as doing a full rebuild, if it had been available last wee=
k, I
> > > > > probably would have used it, but now given the work that Nicolas,=
 you,
> > > > > and I have put into this, we have a viable way (I think) to make =
this
> > > > > more specific. It does end up being a waste of time/resources to =
rebuild
> > > > > stuff that doesn't need to be (efi-stub, vdso, boot code, etc), a=
nd that
> > > > > does add up when I'm iterating on something that keeps triggering=
 a full
> > > > > rebuild. We already have to do the argument filtering for targets=
 that
> > > > > don't want randstruct, etc, so why not capitalize on that and mak=
e the
> > > > > rebuild avoid those files too?
> > > >
> > > >
> > > > efi-stub, vdso are very small.
> > > >
> > > > Unless this turns out to be painful, I prefer
> > > > a simpler implementation.
> > > >
> > > > You will see how .scl file is handled.
> > > >
> > > > See the below code:
> > > >
> > > >
> > > > diff --git a/Kbuild b/Kbuild
> > > > index f327ca86990c..85747239314c 100644
> > > > --- a/Kbuild
> > > > +++ b/Kbuild
> > > > @@ -67,10 +67,20 @@ targets +=3D $(atomic-checks)
> > > >  $(atomic-checks): $(obj)/.checked-%: include/linux/atomic/%  FORCE
> > > >         $(call if_changed,check_sha1)
> > > >
> > > > +rebuild-$(CONFIG_GCC_PLUGINS)          +=3D $(addprefix
> > > > scripts/gcc-plugins/, $(GCC_PLUGIN))
> > > > +rebuild-$(CONFIG_RANDSTRUCT)           +=3D include/generated/rand=
struct_hash.h
> > >
> > > These are in $(objtree)
> >
> > Yes.
> >
> > > > +rebuild-$(CONFIG_UBSAN_INTEGER_WRAP)   +=3D scripts/integer-wrap-i=
gnore.scl
> > >
> > > This is in $(srctree)
> >
> > Yes.
> >
> > > > +
> > > > +quiet_cmd_touch =3D TOUCH   $@
> > > > +      cmd_touch =3D touch $@
> > > > +
> > > > +include/generated/global-rebuild.h: $(rebuild-y)
> > > > +       $(call cmd,touch)
> > >
> > > Is this rule going to find the right versions of the dependencies?
> >
> > I think so, but please test it.
>
> The patch was white-space damaged and wrapped, but I rebuilt it manually
> and it mostly works. There still seems to be some ordering issues, as
> some stuff gets rebuilt on a record build:
>
> # Clean the tree and pick an "everything" build
> $ make O=3Dgcc-test clean allmodconfig -s
>
> # Make a target normally
> $ make O=3Dgcc-test kernel/seccomp.o -s
>
> # Touch a gcc plugin that was in .config
> $ touch scripts/gcc-plugins/stackleak_plugin.c
>
> # Build and a full rebuild is triggered (good)
> $ make O=3Dgcc-test kernel/seccomp.o
> make[1]: Entering directory '/srv/code/gcc-test'
>   GEN     Makefile
>   DESCEND objtool
>   HOSTCXX scripts/gcc-plugins/stackleak_plugin.so
>   INSTALL libsubcmd_headers
>   TOUCH   include/generated/global-rebuild.h
>   CC      kernel/bounds.s
>   CC      arch/x86/kernel/asm-offsets.s
>   CALL    ../scripts/checksyscalls.sh
>   CC      kernel/seccomp.o
> make[1]: Leaving directory '/srv/code/gcc-test'
>
> # Build again, but more stuff gets built
> $ make O=3Dgcc-test kernel/seccomp.o
> make[1]: Entering directory '/srv/code/gcc-test'
>   GEN     Makefile
>   DESCEND objtool
>   CC      scripts/mod/empty.o
>   CC      scripts/mod/devicetable-offsets.s
>   INSTALL libsubcmd_headers
>   MKELF   scripts/mod/elfconfig.h
>   HOSTCC  scripts/mod/modpost.o
>   HOSTCC  scripts/mod/sumversion.o
>   HOSTCC  scripts/mod/symsearch.o
>   HOSTCC  scripts/mod/file2alias.o
>   HOSTLD  scripts/mod/modpost
>   CALL    ../scripts/checksyscalls.sh
> make[1]: Leaving directory '/srv/code/gcc-test'
>
> # Third time finally everything is stable
> $ hmake O=3Dgcc-test kernel/seccomp.o
> make[1]: Entering directory '/srv/code/gcc-test'
>   GEN     Makefile
>   DESCEND objtool
>   CALL    ../scripts/checksyscalls.sh
>   INSTALL libsubcmd_headers
> make[1]: Leaving directory '/srv/code/gcc-test'
>
>
> Note that scripts/mod/* gets rebuilt on the second rebuild.

Hmm.
OK, my code did not work.

I accept your patch set (although I am not a big fan
of the added complexity...)

Could you move the normalize_path macro
to scripts/Kbuild?


--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNAQa_ZX%3DULUgu%2B_YNe%3DA%2B4kgaZakzdM2Y6QPSWWfnEA2JQ%40mail.gmail.com=
.
