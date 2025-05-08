Return-Path: <kasan-dev+bncBDT2NE7U5UFRBN7V6TAAMGQEH4TYAAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A243AB0666
	for <lists+kasan-dev@lfdr.de>; Fri,  9 May 2025 01:14:01 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-605f8bca0e3sf1345689eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 16:14:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746746039; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xqaj0EGBomZKtlyEPkNySZSriK1BDOTgPJU2BiST76c1apws73Lj11q+UZOcJj/qbR
         fsliCIiyMA/hGwuNVWjZVtrBR1AOCk1ZAF1eNKpq027X72sSCqN8+5PmYwsIjphR8vRA
         eNXiVLPt5XsIju2aewuCaYKWc8/mdMpgcYqbmGs3+ql5SZ6sG6o0Owx1OZCaKsFDx9kL
         gS3ElRN1Vx2okWYWQa0aaL5btRDTgTKRqB61ptS4IZ0ti7xRKtUZI/4YJK4/rWjAfk7r
         BvSPq4h1NkumjWEM1Rjhx5/KCgR4W/yToDcDXz60gmtbJtVEB0EtoFY463U/WD4YInZ5
         Q3oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H60Sw97hiWPy6sUy6P+pV76l7iaaaepts+lwU3/TwZU=;
        fh=6ehMyvfIBPQuR3iftZ0Dz5Xv+0mLWTHuUgMvZai+CH0=;
        b=Ia/tSkHhOvXmuQI8zYqJjymIqpJ45bwf2OJ8Zdhky7f0IFDb53pvBCVtBqzv894Wcr
         YG1hgqdBn0Llr8I6OE3ZzfyD2dzAtfM7Lhst7zAQ2tgEwTW0aKsb+z8h5gD6rDrNWPBC
         oI0oCr6pVLvEe5cwPms6/YXbeV5hSfuATTh5TMAEf6LwrKbL3CNjUf5+zzFQqD2aCWRh
         ccD+0nt7FnSP9F/bbOudUuMzgD0dCxGBYrS/ofjQrJDUtnBgvxy+zOR80MVNHkiBshbw
         cdXoHioqURNmfAxZO9K1T1yt0nL5ViZZ6l9uIXWYqyvFl/BtrDaYY1pC5f0hODh/NwNZ
         eEfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=X22twWfq;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746746039; x=1747350839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H60Sw97hiWPy6sUy6P+pV76l7iaaaepts+lwU3/TwZU=;
        b=q3ETFDakNaIjOd+TfSWqG3BGRpZgLbHqOOtY8ZJngjeL98K2+RwR7LrPP4KBfhYLx/
         RnCntuDMiGESR96gMJpg4j+BGO0tdWy1r+DSJ5IEukTSxtUGspMkDxNG2jF4dT0Y/qge
         SS/qsVbFz68PFWOat1XgfTDhAlLl0U0m9UM1PFDT0x/on+IrqL8dCUjlKFB76GiIf4So
         LWueeF5Sl+r9clSAw5rPcV6nCRP6mJL0OaYh0Xj1+GRniUav/1MhunWLD1alYECC4QMe
         OuskMS3afrbv7NK25wSYSzyiz+UcFwNCQCF86yHbcpL6vNp/F8j4HeNpNOm7OdCiIZ8Z
         BetA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746746039; x=1747350839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H60Sw97hiWPy6sUy6P+pV76l7iaaaepts+lwU3/TwZU=;
        b=BOysXJOLjlAj0FgTdKv4eQCbWoWLKOk1G1BIi5umzD1i2YMnDwWkDc8N8JqXeBSmUC
         gLVaN7xDF39mSZN253ijGGVwekYvH2coeyTDR1AZ3TS7cJ01avUWIWdFmMgfZEFiOaCD
         aYbLMCdyl8NRX4Ov0lMJss+l2Yu9rbPucKlSz12maI/eDeKrxa0hnN45m4/2WNsYiWg0
         dJlvesXsoNSD1USEWDTpzUpsj1/mqOhqAIA2iwf2tZh30c8IL9mJO31hyT0ivIBJCdVm
         uJNLuJupBethgAAm87KXTj+AcMKNSkqYMGFtx1CPz5j1whAW4A2jNRCyqBPkQix3DOrI
         Dd8w==
X-Forwarded-Encrypted: i=2; AJvYcCWhjo2vpIGQjuFeOHz+sZiL2/QFRroz0h1rskjfmldtfw6aVooXJ2NTtXXwWQh8l0ghpWi1MA==@lfdr.de
X-Gm-Message-State: AOJu0Yz8ETq9lDW3GUm/1eu03aGmxlPw1v7MndnEAbQJwI12iBJ2PUwM
	b/m4s5uO37445ttdp+K7jhEgyoIH44ZzCfsRI+gEbrD4j17cV8jE
X-Google-Smtp-Source: AGHT+IFJjMaqGm8fALf98OjScrnLAb+TU3MsOeozSqDMxedaNr9aKk9hUbUz/sJE1ovUBdWlgQAGJQ==
X-Received: by 2002:a05:6820:207:b0:606:6384:555c with SMTP id 006d021491bc7-6084b63ecaemr886143eaf.8.1746746039351;
        Thu, 08 May 2025 16:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGIar0QrbdbeeJDgvJcMHACVpjEtfDL2diN44n4INzL7g==
Received: by 2002:a4a:d442:0:b0:601:afcc:166b with SMTP id 006d021491bc7-60832ee1b82ls787477eaf.1.-pod-prod-09-us;
 Thu, 08 May 2025 16:13:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQsLb7kQZcAgv0iebv8xr93c5MBsDtsm+bmS/+lsopcl7mJ0mbVqV8GQrYUrjL2sbbrwmzGsB8SMs=@googlegroups.com
X-Received: by 2002:a05:6820:450a:b0:607:8929:4502 with SMTP id 006d021491bc7-6083ff17192mr858132eaf.1.1746746038404;
        Thu, 08 May 2025 16:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746746038; cv=none;
        d=google.com; s=arc-20240605;
        b=KVx9CBqhIzYBUXvS4TmSWcM+kxts4zyq3L7TG86uqDUVHx/EoCmvp2epz+JTBgMTOO
         IHKaP6CBq4NIA6jE5QiaEbQyUWN4x1hMVldceVDtYlFDNRo0e7iNxZpt2m6MNL8T684/
         byn/2dc6hAq7X+DmPp0clcbswmxbC/F9jyLY7SwiqtSit3u+jm47wHhmZHqRJ1TpBakb
         Znw7xbs7lez9bIUEehT6+Jl6tDuDnIaOGRfSYDCEjYslOcnRaXlChKA5Tx2X2ImsMYNV
         CbcY4l1GdKrlA822cB/IstAekULxKWhXYYsbd4UUf34ik0C+aG/pp4B+mW+Jkr/OjZvU
         v33A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0qizmcVgeWhq7Q3Ee4oIEwFn2+ipGsqmBbwSEApIvT0=;
        fh=grU+6oY/68+6K0TtPd4/xUJcYeHvXjGikdq5vZGk5HQ=;
        b=abWfYRrT7MS/POXBp3fwGOLgA1QvJ08zNfXOo2bELCYitQ3wwoigci4MiBuE5B2Jlq
         ftjIZPIKcs4c3UQFUxaywiez5OuPWE095x406zBL2LQamNn2qbAMC1H2C624wXhhDnZo
         9R76CmhI14+0fFJelQaugENvSJ38cgtNyHs5AVOf9HdCOwbcLgOnmaH8X/DskX+XElsX
         st+kzjCOOieahWK6FbuC7VQldexdgNhhw1RBvqxE8jbKPbtneu84liQ+P3zKYz3HvmKO
         1akb4ljn17P6zzu8TeiMxr3rovSAWqof2DL3NCwTB8ygcw5ANusS5NRJ05OO8yC7O65D
         5MfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=X22twWfq;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-60910f4261fsi8704eaf.0.2025.05.08.16.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 16:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D678C44667
	for <kasan-dev@googlegroups.com>; Thu,  8 May 2025 23:13:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 71193C4CEF1
	for <kasan-dev@googlegroups.com>; Thu,  8 May 2025 23:13:56 +0000 (UTC)
Received: by mail-lf1-f54.google.com with SMTP id 2adb3069b0e04-54d65cb6e8aso1930586e87.1
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 16:13:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZAVKSB35LM4RbbVtNVFJV7s0d1e6cbCF3ECq9wfVSnWOjspbLL27oAa5g66a1o/nkudz9QNL6B+Y=@googlegroups.com
X-Received: by 2002:a05:6512:4201:b0:54e:81ec:2c83 with SMTP id
 2adb3069b0e04-54fc67c2180mr349351e87.18.1746746035073; Thu, 08 May 2025
 16:13:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org> <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
 <202505031028.7022F10061@keescook> <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
 <202505080953.789B3381@keescook>
In-Reply-To: <202505080953.789B3381@keescook>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 May 2025 08:13:18 +0900
X-Gmail-Original-Message-ID: <CAK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q@mail.gmail.com>
X-Gm-Features: ATxdqUFSFahQS2gL_GajBAPbhaxcYoPZIWvSTLFfjfLaxGsmrigaOf0HpL69dgs
Message-ID: <CAK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=X22twWfq;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
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

On Fri, May 9, 2025 at 1:56=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> On Fri, May 09, 2025 at 01:44:09AM +0900, Masahiro Yamada wrote:
> > On Sun, May 4, 2025 at 2:37=E2=80=AFAM Kees Cook <kees@kernel.org> wrot=
e:
> > >
> > > On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> > > > On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> =
wrote:
> > > > >
> > > > >  v2:
> > > > >   - switch from -include to -I with a -D gated include compiler-v=
ersion.h
> > > > >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@ke=
rnel.org/
> > > >
> > > >
> > > > What do you think of my patch as a prerequisite?
> > > > https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-masah=
iroy@kernel.org/T/#u
> > > > Perhaps, can you implement this series more simply?
> > > >
> > > > My idea is to touch a single include/generated/global-rebuild.h
> > > > rather than multiple files such as gcc-plugins-deps.h, integer-wrap=
.h, etc.
> > > >
> > > > When the file is touched, the entire kernel source tree will be reb=
uilt.
> > > > This may rebuild more than needed (e.g. vdso) but I do not think
> > > > it is a big deal.
> > >
> > > This is roughly where I started when trying to implement this, but I
> > > didn't like the ergonomics of needing to scatter "touch" calls all ov=
er,
> > > which was especially difficult for targets that shared a build rule b=
ut
> > > may not all need to trigger a global rebuild. But what ultimately pus=
hed
> > > me away from it was when I needed to notice if a non-built source fil=
e
> > > changed (the Clang .scl file), and I saw that I need to be dependency
> > > driven rather than target driven. (Though perhaps there is a way to
> > > address this with your global-rebuild.h?)
> > >
> > > As far as doing a full rebuild, if it had been available last week, I
> > > probably would have used it, but now given the work that Nicolas, you=
,
> > > and I have put into this, we have a viable way (I think) to make this
> > > more specific. It does end up being a waste of time/resources to rebu=
ild
> > > stuff that doesn't need to be (efi-stub, vdso, boot code, etc), and t=
hat
> > > does add up when I'm iterating on something that keeps triggering a f=
ull
> > > rebuild. We already have to do the argument filtering for targets tha=
t
> > > don't want randstruct, etc, so why not capitalize on that and make th=
e
> > > rebuild avoid those files too?
> >
> >
> > efi-stub, vdso are very small.
> >
> > Unless this turns out to be painful, I prefer
> > a simpler implementation.
> >
> > You will see how .scl file is handled.
> >
> > See the below code:
> >
> >
> > diff --git a/Kbuild b/Kbuild
> > index f327ca86990c..85747239314c 100644
> > --- a/Kbuild
> > +++ b/Kbuild
> > @@ -67,10 +67,20 @@ targets +=3D $(atomic-checks)
> >  $(atomic-checks): $(obj)/.checked-%: include/linux/atomic/%  FORCE
> >         $(call if_changed,check_sha1)
> >
> > +rebuild-$(CONFIG_GCC_PLUGINS)          +=3D $(addprefix
> > scripts/gcc-plugins/, $(GCC_PLUGIN))
> > +rebuild-$(CONFIG_RANDSTRUCT)           +=3D include/generated/randstru=
ct_hash.h
>
> These are in $(objtree)

Yes.

> > +rebuild-$(CONFIG_UBSAN_INTEGER_WRAP)   +=3D scripts/integer-wrap-ignor=
e.scl
>
> This is in $(srctree)

Yes.

> > +
> > +quiet_cmd_touch =3D TOUCH   $@
> > +      cmd_touch =3D touch $@
> > +
> > +include/generated/global-rebuild.h: $(rebuild-y)
> > +       $(call cmd,touch)
>
> Is this rule going to find the right versions of the dependencies?

I think so, but please test it.


> > --- a/Makefile
> > +++ b/Makefile
> > @@ -558,7 +558,8 @@ USERINCLUDE    :=3D \
> >                 -I$(srctree)/include/uapi \
> >                 -I$(objtree)/include/generated/uapi \
> >                  -include $(srctree)/include/linux/compiler-version.h \
> > -                -include $(srctree)/include/linux/kconfig.h
> > +                -include $(srctree)/include/linux/kconfig.h \
> > +                -include $(objtree)/include/generated/global-rebuild.h
>
> Instead of adding a new file, why not just touch compiler-version.h?

Because the compiler-version.h is in $(srctree), which might be
in the read-only file system.


> But whatever the case, sure, I can live with this. :)
>
> -Kees
>
> --
> Kees Cook



--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q%40mail.gmail.com.
