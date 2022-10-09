Return-Path: <kasan-dev+bncBCLI747UVAFRBQFKRCNAMGQE3DTMRUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AD5E5F88A0
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 02:26:42 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id lk8-20020a17090b33c800b0020a8e908e98sf6975141pjb.9
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 17:26:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665275200; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5W1YQeFZBJVzLMpBetOZdPWPvbrNLzGnd+keYVnEowQjDGR0CujwxHw8Pp5gjOHdY
         lwYBsIoS01Cye6cy89fyIhid5sv1eXGKKcWgKA03IDnnvXuNunHeToQFJ+ZJg38w7HJs
         kuScYrVmWKw9mzC/MUQErtPW70WkgNAPavcTAyIfjOsAyXdtYSp1MAZiqfQBE0wOYMGp
         b5qJ1JNSHiOBgpWP7GAwWxVi+EBcLiq9bQ+uqmQDeir5kCZSeLyokWk5UPjzB53Mx3a+
         q2OFB3Mbk0lbTSdVB6lCjDympsSIzs3JeYhIkKgbGmtDNQhpe25hAgjbxLNZVRpiryO5
         UHJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4B/YeJZ0zFTBVfHutckszVKVVoI0fHa5Bx53jdqUYes=;
        b=BUJKlxjR42iOXW/Hvo7MqPwhnx/gC1BzkvexPaP2/bu+rQXTP5ymDR8lPzjchEZ+7y
         hhF3dnqbBhnqXRHh7bei8TDXzaUtA/+5bpyLH/39/STXgtLA4mIB+Y3MWKgZBFul7Rwi
         FEVG2WiBLovMUovFeCQgUVCmDKxggveeg0ppQj7Wwk3hlJ5lmpNxVUbAdrpulyGK+B47
         9aoP7dsOig14bZfCflIqJQvc2r1WugfTh3YSb26VHopF9fIgej/RFfhrLnx4aWfKhpko
         3R4BToWi9MXCCTwV0QMyyImaESk0B4yIhAazGy74DgSaUyqiv2kw3gUcs2OGUM0VPKXy
         tqRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=eXcn74ON;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4B/YeJZ0zFTBVfHutckszVKVVoI0fHa5Bx53jdqUYes=;
        b=kOrBPI9noPYTOsFyjJwypTMPR6yK5Fbuw2XdbHZZRlCOuFYuvc0hquJBznguZCRcMP
         n80R8uvPse2IiQyJ1LxDZUUmk0hbEkXm1BQaXK12QRZJ/UULwHGhOTj6f8oix8npGlkR
         fYcNUup2ay+I9Xx2ys3QdZYGdbK643cG+Rjuufxs8m/B4cXKxUFXeVb42WndHrgzdkmp
         X8Mdupx5XGE6DqhRiALhNLsfjWjj3ouT6OhnCA/2JU1BiBn6UJaYSrU1Ylv7jcHLeaKf
         RV6oBery5+O5f5e8dmFqj7cj1W+MKv3yh5RVc7IRCavvz3exc3dwBIpoQ0KSp5u1n1Dw
         3wWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4B/YeJZ0zFTBVfHutckszVKVVoI0fHa5Bx53jdqUYes=;
        b=O3KfknCHS1xhoyc1orfDqr1vRdGe3hYftgoTfQGeeK8aMhKfQQY6ovnWn2dkWGpzkc
         HojwPsBVDD0dcpmszZdvxJ6J3Ll+QoTpml+Hyw1Z+ASybOiX4N5D/BQNb/WKnwkxGPez
         0uWpEAWTmHTlnaV6mxhvATK4nq7iD11ZdMvKaABYufIWqb5CXxQTfhM+R7+u2BJfPzCe
         BDieQfjHtK8otG4LZO+wyep2YiBaCeOmNcNJAUbw/OQXzdl0cH+1rP/8ROIRV3dZIgdp
         rikPyOkpxZY/56rhNGSNEqCvSYImIm/JkHBsa0Yc7myjrT7GkJ7GuU2YhzBf/qNN39ij
         vHRw==
X-Gm-Message-State: ACrzQf09q7JXsjL/emKhbs0QMT5KN9WUdiaMHooaQZdH/aC6rPydKOXF
	eP88TnOnAEgWQq0wbYrTQ9E=
X-Google-Smtp-Source: AMsMyM4FRLs/96hGpcWx5CdgmuYciuKG8SPmvlRSkKNlAfAOX0V6YSq9Qhv/tjTtnMNBgAhnaU4iug==
X-Received: by 2002:a17:902:b18e:b0:178:3484:f45e with SMTP id s14-20020a170902b18e00b001783484f45emr11689641plr.166.1665275200550;
        Sat, 08 Oct 2022 17:26:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f90:b0:20b:5cfd:2180 with SMTP id
 o16-20020a17090a9f9000b0020b5cfd2180ls3998702pjp.0.-pod-control-gmail; Sat,
 08 Oct 2022 17:26:39 -0700 (PDT)
X-Received: by 2002:a17:902:6b04:b0:181:5dc6:5348 with SMTP id o4-20020a1709026b0400b001815dc65348mr3401734plk.69.1665275199781;
        Sat, 08 Oct 2022 17:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665275199; cv=none;
        d=google.com; s=arc-20160816;
        b=Swahvwwac4lOJO9qAUp4ONgOq7zH/4Wk0ivouap1ps0dHCRdQDqcdZM8zSxRgjimRs
         wN4CZiPpVIn8NTPSIlGkipsWeWQ3fvj9wCnSBcrmKmX0b0hXZ0yd17zF1BF0SudEwNuf
         aKFyqWfTvomvZ0DneKBg6C0vDB0eutj3KA0hdkmez6zpWdHKyliqC3xuYWzPCTrAW3+Y
         79E3HBRpPi4JNssFjDyKAGQeHWfR9OcVGHwbL2rLZ8GWuIWrVMewbIiml2/7FIiKItX9
         No2kUUABxpW8A9oKVwADF8Ugyr+4EMrGfOuUPPm3k+taEZGCFHmIw5PjDMpFwnb+3nn0
         d67A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7zZXtzJcFLYkSrXJJYKIVFffp4v7t60F00p3NU1sSks=;
        b=ohiQFyAgJyVMguJ0vGCc74HujCOrIVTashmgw4sRMKR8gERfIWkIznzRRU9QXlYbVf
         sAhgrCzs8d+N7MqEwXSBTGDHq7CRApq/XCShlPnxY3xAUm94ouSFRvx5CmPWtRShVFIC
         NemnOjxUHLx2UvLQzDfsaIKlPL5ukEJu4oELm4LJ+kg1DBO5A8eD+9pyQOVZ5iuJuFlh
         9MFi3rQ4xBAmZZJZTBaMjyP2Au1aM6+yYt6XWMqCjud9fc5EOnTdILbGu1DkHRUw3K0I
         k+erUVZ8I5O4Hcwgv70IxPvpAMNLyclAa01aClQ8JQF7PkWWMEToahdrXQuEkKhX+BXs
         wr9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=eXcn74ON;
       spf=pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g24-20020a056a00079800b00562bba09b90si189425pfu.0.2022.10.08.17.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 17:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4108D60B3A
	for <kasan-dev@googlegroups.com>; Sun,  9 Oct 2022 00:26:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7152DC433C1
	for <kasan-dev@googlegroups.com>; Sun,  9 Oct 2022 00:26:38 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 3ce0fa56 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Sun, 9 Oct 2022 00:26:27 +0000 (UTC)
Received: by mail-oo1-f51.google.com with SMTP id c17-20020a4aa4d1000000b0047653e7c5f3so5907650oom.1
        for <kasan-dev@googlegroups.com>; Sat, 08 Oct 2022 17:26:27 -0700 (PDT)
X-Received: by 2002:ab0:70b9:0:b0:3d7:84d8:35ae with SMTP id
 q25-20020ab070b9000000b003d784d835aemr6771029ual.24.1665275171232; Sat, 08
 Oct 2022 17:26:11 -0700 (PDT)
MIME-Version: 1.0
References: <20221007180107.216067-1-Jason@zx2c4.com> <20221007180107.216067-5-Jason@zx2c4.com>
 <f1ca1b53bc104065a83da60161a4c7b6@AcuMS.aculab.com> <Y0H7rcJ3/JOyDYU8@zx2c4.com>
In-Reply-To: <Y0H7rcJ3/JOyDYU8@zx2c4.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 8 Oct 2022 18:26:00 -0600
X-Gmail-Original-Message-ID: <CAHmME9ojgUnrp+Mys3pzJZ=0C7RHbgsm-wOkWk-GdW2dnJwf8g@mail.gmail.com>
Message-ID: <CAHmME9ojgUnrp+Mys3pzJZ=0C7RHbgsm-wOkWk-GdW2dnJwf8g@mail.gmail.com>
Subject: Re: [PATCH v4 4/6] treewide: use get_random_u32() when possible
To: David Laight <David.Laight@aculab.com>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever <andreas.noever@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, 
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, 
	Jonathan Corbet <corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, 
	Russell King <linux@armlinux.org.uk>, "Theodore Ts'o" <tytso@mit.edu>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>, 
	Yury Norov <yury.norov@gmail.com>, 
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-block@vger.kernel.org" <linux-block@vger.kernel.org>, 
	"linux-crypto@vger.kernel.org" <linux-crypto@vger.kernel.org>, 
	"linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>, 
	"linux-fsdevel@vger.kernel.org" <linux-fsdevel@vger.kernel.org>, 
	"linux-media@vger.kernel.org" <linux-media@vger.kernel.org>, 
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>, 
	"linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>, 
	"linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>, 
	"linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>, 
	"linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>, 
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>, 
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, 
	"linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>, 
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>, 
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, 
	"loongarch@lists.linux.dev" <loongarch@lists.linux.dev>, 
	"netdev@vger.kernel.org" <netdev@vger.kernel.org>, 
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>, "x86@kernel.org" <x86@kernel.org>, 
	=?UTF-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>, 
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=eXcn74ON;       spf=pass
 (google.com: domain of srs0=aaew=2k=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=aaEw=2K=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Sat, Oct 8, 2022 at 4:37 PM Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> On Sat, Oct 08, 2022 at 10:18:45PM +0000, David Laight wrote:
> > From: Jason A. Donenfeld
> > > Sent: 07 October 2022 19:01
> > >
> > > The prandom_u32() function has been a deprecated inline wrapper around
> > > get_random_u32() for several releases now, and compiles down to the
> > > exact same code. Replace the deprecated wrapper with a direct call to
> > > the real function. The same also applies to get_random_int(), which is
> > > just a wrapper around get_random_u32().
> > >
> > ...
> > > diff --git a/net/802/garp.c b/net/802/garp.c
> > > index f6012f8e59f0..c1bb67e25430 100644
> > > --- a/net/802/garp.c
> > > +++ b/net/802/garp.c
> > > @@ -407,7 +407,7 @@ static void garp_join_timer_arm(struct garp_applicant *app)
> > >  {
> > >     unsigned long delay;
> > >
> > > -   delay = (u64)msecs_to_jiffies(garp_join_time) * prandom_u32() >> 32;
> > > +   delay = (u64)msecs_to_jiffies(garp_join_time) * get_random_u32() >> 32;
> > >     mod_timer(&app->join_timer, jiffies + delay);
> > >  }
> > >
> > > diff --git a/net/802/mrp.c b/net/802/mrp.c
> > > index 35e04cc5390c..3e9fe9f5d9bf 100644
> > > --- a/net/802/mrp.c
> > > +++ b/net/802/mrp.c
> > > @@ -592,7 +592,7 @@ static void mrp_join_timer_arm(struct mrp_applicant *app)
> > >  {
> > >     unsigned long delay;
> > >
> > > -   delay = (u64)msecs_to_jiffies(mrp_join_time) * prandom_u32() >> 32;
> > > +   delay = (u64)msecs_to_jiffies(mrp_join_time) * get_random_u32() >> 32;
> > >     mod_timer(&app->join_timer, jiffies + delay);
> > >  }
> > >
> >
> > Aren't those:
> >       delay = prandom_u32_max(msecs_to_jiffies(xxx_join_time));
>
> Probably, but too involved and peculiar for this cleanup.
>
> Feel free to send a particular patch to that maintainer.

I guess the cocci patch looks like this, so maybe I'll put that in 1/7
if I respin this.

@@
expression E;
identifier get_random_u32 =~ "get_random_int|prandom_u32|get_random_u32";
typedef u64;
@@
- ((u64)(E) * get_random_u32() >> 32)
+ prandom_u32_max(E)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9ojgUnrp%2BMys3pzJZ%3D0C7RHbgsm-wOkWk-GdW2dnJwf8g%40mail.gmail.com.
