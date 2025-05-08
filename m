Return-Path: <kasan-dev+bncBDCPL7WX3MKBB64K6XAAMGQEG3HJKMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 92AC8AB06E5
	for <lists+kasan-dev@lfdr.de>; Fri,  9 May 2025 01:59:57 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b23eb54d921sf109272a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 16:59:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746748795; cv=pass;
        d=google.com; s=arc-20240605;
        b=fwHpniBv8pUCYLaLzzBbmDfGuL3sCXYt2MOlxBQr/OXpMjdvOYiYbMMVDV7MgZTyfc
         olJuwsvX2ozGTv6yXr533/fADWy7CPiSLmiYQN+BZ1ZM5cxkf1Uq+f5mN5vWtEzrj3B9
         fGi83mmEJPxD74ltrqoZNHOwq3UcXxU6ZlfgTx5VXHUf7EZWsta16aIe4E8JFjpT13O4
         v1ghw3Be/J0B5dlf4ZRIFNnW1zkF6OhGaovV3Z3rcWbvsJ+yhy9XuTx6lulGWBLFHqLc
         FJrZ03yj21IDYjM7ZCY5S2nJ+b/2qZwdqe7ebQlfGljWnMKwzEcqM9deLB1yMfu7Ed5l
         OkpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EtUAVsKYhzdQLbXjVXJbaXENTW4NipGyg4QUrldy7D0=;
        fh=7hl+v+R5UyX57OaTdeOhOc8qvhGqEn43naPLE251Zx8=;
        b=MUR/Dje6J2nCvc4gD52PBEaDETLVY2P4E+gmBzoYG0sKEMZ5CCjFuV/jcEXYUEcDTG
         G4jDZV1xfQeCux4xcXjLVb0LK58ihkESvYFzvpcJFmO6ilQ93TmofwdHLn7X4UN4Zmhk
         UShVLCF6faW3ZMgZE1SRJSe50vx2qNmGMddFcENkaia/HQq82xgIthk2o16fl/7Ycs2Q
         Pd2Ao0akrqqr0Ys3yftCVppHd8bMJiWc9bEDk5Rvm/ywbsKAvL9V4gl2D2JeHV13asLE
         O4Ck/GdLG0d/poqzARbdH3TjdB86vjjzG5F3IJxaqZz4EWJqo1JMq/FyGUsHvPIiibQL
         mpAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UjxuE3Ma;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746748795; x=1747353595; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EtUAVsKYhzdQLbXjVXJbaXENTW4NipGyg4QUrldy7D0=;
        b=iFUnCMMMk5F1CnqhtAI5895YEgqKuQk1NdnjA2p1BLckbrX57jPtzk0YO4hIPyCUUD
         FndRqiUJMd7wKvdTmKZcc7/keO6D5z8Q30Ijxw8d2a+yBZBMxHhe4I93qwPy6SEJWoXz
         Lwp/ngJQAMWQBs/mq3eHOXEH0a6vK60azY9P5ah7vHzT/n9LgRJyF/KA0J4HxtUGc1QI
         R6gnbqHxveaxxMJLpaBFNZZ1r5QqBgygt67csjjb+u9WDEuof+Xg6O7Lrsf/ZZ75kzDk
         OIuVOD8W+4fFbuqSx+y7+IWojS8w5dLCZdsCYL4BkYoKgW1GTuRUxgq3jK2LkqDZg4kM
         YabA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746748795; x=1747353595;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=EtUAVsKYhzdQLbXjVXJbaXENTW4NipGyg4QUrldy7D0=;
        b=tyv5d0M8j7cONbgNA5tARurfcNMv+vtD9ji/iJgidAtJeBpkR3bLSmaQNputhQDVBx
         iygTYmYpuUxS0FaJcuRWWlGH40+olfohNgrSYRSUe6QNLbTTB5D4x/oivSd9sfQzE8sq
         P8Yw1tWFVr1b/UcyXlFvAM8By1hNhy3fu20/ventDDb1Yc4vfEpRSG/zdhJT/PZOhDNP
         YOGjg5DGZESMazObmwdlWbLPlGNw0bwHmqPC82Ka4hXQxPm23EwkEWM/pjs/IeMj+LHB
         JM11dXKvl2wIodMfAydYlqRlQoNVUaeAsqGxqhYSjHMttunkVQnSVrAcufgP1sEmc6+J
         8SaQ==
X-Forwarded-Encrypted: i=2; AJvYcCUOuvYnbgrGT9FGeQ6g4LyF7BZj/AXsuo5znHXBJOAUP4oUeOOVZMxanDv8QXXAhL9XLuLXAw==@lfdr.de
X-Gm-Message-State: AOJu0YxT6Xue2D8WKKqnJJhOHZ1ouXenLdsGX1jGMdX1Do7WP8bnpIF0
	RJ32Agpovii5cfNWP5vr8e1JHZ+Al+gy4Hu99RKVHIc9Rc8M0u62
X-Google-Smtp-Source: AGHT+IF6b8ym83WL45jeGEaevEaQ12FM3LMRka6JAa9Bk3+bX58ztDUFctL7JII1qcikHhcVLbbZeA==
X-Received: by 2002:a17:903:244b:b0:22c:336f:cb54 with SMTP id d9443c01a7336-22fc8b5976amr17469045ad.29.1746748795482;
        Thu, 08 May 2025 16:59:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFzYS6xAWeNLLXUxAC1IbWXN2n+MTwM+PHBrdPyBqCnVQ==
Received: by 2002:a17:903:f56:b0:223:ff9c:d2ab with SMTP id
 d9443c01a7336-22e8470695als10628565ad.0.-pod-prod-03-us; Thu, 08 May 2025
 16:59:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxsPy5dUCA01qw/ysZcIL3pqiqkz4W5goTf2Yv6ud6bSGPnwWW5tzZLLEDujYaHm2ftsZqpVKDbNg=@googlegroups.com
X-Received: by 2002:a17:903:190d:b0:224:13a4:d61d with SMTP id d9443c01a7336-22fc8b57193mr18959915ad.23.1746748794064;
        Thu, 08 May 2025 16:59:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746748794; cv=none;
        d=google.com; s=arc-20240605;
        b=W2rZqTpWBxswrdoiyYUpkRGe5crCdRJMFazLmIesI3GIaIi9V7vCgL6Ln0yRS98/t/
         J8Wng2gBNPsOnUvRDwSkJk3lJQsO2EJk9ITHaYF1jrKt4w8nIRnl3ahFHhqWpTHZLpTf
         Uej+3U1V0Qge6KJz0Lq10wFNP7AhplZwxBd2skOfIpasWG1GY4P0+NTaqMewYUNqFvs5
         zZMJEeAhSbe0KWzsJ7JFgGoDrSnP3f6M90l54bQ03K/miI8Xi3S2YbVujpgutnmi0OEJ
         e7of0TYSVgNC9rza+A0kg31OICsBdwZVN+F0VVMgSEWBqUb+psof/jbbxB/1Ol9qkTrF
         hghQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RJffRbbgB2mmArflowq3rHRTwEaLVFDXijNwI2PHBf4=;
        fh=BxgzT0MZsSp477MtR51PGrPYIDC1oavm6ZTCuFIEh1E=;
        b=KPbMIcl8HULKX9BDXjX78D9B3gsiF9TH3Zt9Ep2PBcr/RlnE/YWOI2e9Fle/J8xdSK
         6NuZG9AWaOixwML7e4EIMYKrCkKVdJ2Us3WzBb1PXVvxstDgjH3uplQLcu7jmFqgzYPt
         Zi7lkIOqpXPQ50Aw2PV+kqBmMKc7Qj1BVpJighz8yQrcbtA4Msi3pYgZ2AuO5jUWwQos
         nEyY4zNJD/AzKSj0ULh9kIZYeq6eynQpfgR62GBPCdPRwVBbY4XytEEFxBG7bjG9U/O/
         1zv3vIL8LDN8nSpVfbojw280X4Q3RYXNL/gEeWNKIePy823Wrf36mEXKQH11+lkv5dIn
         L3qQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UjxuE3Ma;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc8225d16si420165ad.10.2025.05.08.16.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 16:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B94475C655A;
	Thu,  8 May 2025 23:57:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A06FFC4CEE7;
	Thu,  8 May 2025 23:59:51 +0000 (UTC)
Date: Thu, 8 May 2025 16:59:48 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: Re: [PATCH v2 0/3] Detect changed compiler dependencies for full
 rebuild
Message-ID: <202505081651.EAF0C6B@keescook>
References: <20250502224512.it.706-kees@kernel.org>
 <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
 <202505031028.7022F10061@keescook>
 <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
 <202505080953.789B3381@keescook>
 <CAK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNAQpGXmWNhoE9wLoP01dn2o7KjhedoqHXm474CoCgwHp2Q@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UjxuE3Ma;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, May 09, 2025 at 08:13:18AM +0900, Masahiro Yamada wrote:
> On Fri, May 9, 2025 at 1:56=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
> >
> > On Fri, May 09, 2025 at 01:44:09AM +0900, Masahiro Yamada wrote:
> > > On Sun, May 4, 2025 at 2:37=E2=80=AFAM Kees Cook <kees@kernel.org> wr=
ote:
> > > >
> > > > On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> > > > > On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org=
> wrote:
> > > > > >
> > > > > >  v2:
> > > > > >   - switch from -include to -I with a -D gated include compiler=
-version.h
> > > > > >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@=
kernel.org/
> > > > >
> > > > >
> > > > > What do you think of my patch as a prerequisite?
> > > > > https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-mas=
ahiroy@kernel.org/T/#u
> > > > > Perhaps, can you implement this series more simply?
> > > > >
> > > > > My idea is to touch a single include/generated/global-rebuild.h
> > > > > rather than multiple files such as gcc-plugins-deps.h, integer-wr=
ap.h, etc.
> > > > >
> > > > > When the file is touched, the entire kernel source tree will be r=
ebuilt.
> > > > > This may rebuild more than needed (e.g. vdso) but I do not think
> > > > > it is a big deal.
> > > >
> > > > This is roughly where I started when trying to implement this, but =
I
> > > > didn't like the ergonomics of needing to scatter "touch" calls all =
over,
> > > > which was especially difficult for targets that shared a build rule=
 but
> > > > may not all need to trigger a global rebuild. But what ultimately p=
ushed
> > > > me away from it was when I needed to notice if a non-built source f=
ile
> > > > changed (the Clang .scl file), and I saw that I need to be dependen=
cy
> > > > driven rather than target driven. (Though perhaps there is a way to
> > > > address this with your global-rebuild.h?)
> > > >
> > > > As far as doing a full rebuild, if it had been available last week,=
 I
> > > > probably would have used it, but now given the work that Nicolas, y=
ou,
> > > > and I have put into this, we have a viable way (I think) to make th=
is
> > > > more specific. It does end up being a waste of time/resources to re=
build
> > > > stuff that doesn't need to be (efi-stub, vdso, boot code, etc), and=
 that
> > > > does add up when I'm iterating on something that keeps triggering a=
 full
> > > > rebuild. We already have to do the argument filtering for targets t=
hat
> > > > don't want randstruct, etc, so why not capitalize on that and make =
the
> > > > rebuild avoid those files too?
> > >
> > >
> > > efi-stub, vdso are very small.
> > >
> > > Unless this turns out to be painful, I prefer
> > > a simpler implementation.
> > >
> > > You will see how .scl file is handled.
> > >
> > > See the below code:
> > >
> > >
> > > diff --git a/Kbuild b/Kbuild
> > > index f327ca86990c..85747239314c 100644
> > > --- a/Kbuild
> > > +++ b/Kbuild
> > > @@ -67,10 +67,20 @@ targets +=3D $(atomic-checks)
> > >  $(atomic-checks): $(obj)/.checked-%: include/linux/atomic/%  FORCE
> > >         $(call if_changed,check_sha1)
> > >
> > > +rebuild-$(CONFIG_GCC_PLUGINS)          +=3D $(addprefix
> > > scripts/gcc-plugins/, $(GCC_PLUGIN))
> > > +rebuild-$(CONFIG_RANDSTRUCT)           +=3D include/generated/randst=
ruct_hash.h
> >
> > These are in $(objtree)
>=20
> Yes.
>=20
> > > +rebuild-$(CONFIG_UBSAN_INTEGER_WRAP)   +=3D scripts/integer-wrap-ign=
ore.scl
> >
> > This is in $(srctree)
>=20
> Yes.
>=20
> > > +
> > > +quiet_cmd_touch =3D TOUCH   $@
> > > +      cmd_touch =3D touch $@
> > > +
> > > +include/generated/global-rebuild.h: $(rebuild-y)
> > > +       $(call cmd,touch)
> >
> > Is this rule going to find the right versions of the dependencies?
>=20
> I think so, but please test it.

The patch was white-space damaged and wrapped, but I rebuilt it manually
and it mostly works. There still seems to be some ordering issues, as
some stuff gets rebuilt on a record build:

# Clean the tree and pick an "everything" build
$ make O=3Dgcc-test clean allmodconfig -s

# Make a target normally
$ make O=3Dgcc-test kernel/seccomp.o -s

# Touch a gcc plugin that was in .config
$ touch scripts/gcc-plugins/stackleak_plugin.c

# Build and a full rebuild is triggered (good)
$ make O=3Dgcc-test kernel/seccomp.o
make[1]: Entering directory '/srv/code/gcc-test'
  GEN     Makefile
  DESCEND objtool
  HOSTCXX scripts/gcc-plugins/stackleak_plugin.so
  INSTALL libsubcmd_headers
  TOUCH   include/generated/global-rebuild.h
  CC      kernel/bounds.s
  CC      arch/x86/kernel/asm-offsets.s
  CALL    ../scripts/checksyscalls.sh
  CC      kernel/seccomp.o
make[1]: Leaving directory '/srv/code/gcc-test'

# Build again, but more stuff gets built
$ make O=3Dgcc-test kernel/seccomp.o
make[1]: Entering directory '/srv/code/gcc-test'
  GEN     Makefile
  DESCEND objtool
  CC      scripts/mod/empty.o
  CC      scripts/mod/devicetable-offsets.s
  INSTALL libsubcmd_headers
  MKELF   scripts/mod/elfconfig.h
  HOSTCC  scripts/mod/modpost.o
  HOSTCC  scripts/mod/sumversion.o
  HOSTCC  scripts/mod/symsearch.o
  HOSTCC  scripts/mod/file2alias.o
  HOSTLD  scripts/mod/modpost
  CALL    ../scripts/checksyscalls.sh
make[1]: Leaving directory '/srv/code/gcc-test'

# Third time finally everything is stable
$ hmake O=3Dgcc-test kernel/seccomp.o
make[1]: Entering directory '/srv/code/gcc-test'
  GEN     Makefile
  DESCEND objtool
  CALL    ../scripts/checksyscalls.sh
  INSTALL libsubcmd_headers
make[1]: Leaving directory '/srv/code/gcc-test'


Note that scripts/mod/* gets rebuilt on the second rebuild.


--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505081651.EAF0C6B%40keescook.
