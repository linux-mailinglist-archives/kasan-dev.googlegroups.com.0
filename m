Return-Path: <kasan-dev+bncBAABBTXH7DYAKGQEWUYSCCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B77A13B46C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 22:34:08 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id e128sf18127875ywc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 13:34:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579037647; cv=pass;
        d=google.com; s=arc-20160816;
        b=gsplAEd+KEcAgp1a/S2f6nl6KZfiM8CP/JaKjQvAz4LZSGOB00Z7FkR7ipH9YVMd4D
         YbGN9+5ICsRRyuEA7kcz5NHd7KJc4UawqiEV0gf5RKtqI/iDsDM7uEB10wW75y9jK5h2
         PwBHxQ4m6wIcz9/9eYJkS/4tMSH30sG73MEfKiVWiwSaeVJ4FAHjtk/b55l4GRhki7gp
         bJm6x0KXSRWRlci4Aa+dgad3Z/GT0wDnmPtko+yw2muNV8QEOhJ7EirnErN56477DM5J
         TkBe5oqOguqIWmfEX/1zp3T6VJsIorv1KOJY0IZtCaofNIsgcPvXhIwEKDFJlyTJuV6j
         tYsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=84m3Lgmy81X7eFRnL1qptMyXl0QFuSazA2Ts5IXCyVQ=;
        b=CMjIOTPZ8zCKjcGmvNEkgCRgFWyYQ1AMd/FII0oqiLJhxCqzjDoe5U45y0V3vNsYN8
         Sh21eDHfk/jnkmCjq07wkqGCI0cJQ3CSvURlG0CD/WA90O5cmU5K9Kg6LF0nD84JDMyb
         Xcii5qWT0Tan8P5lcjNLLjd1dfsJzXRm6picGph4DYq6CIGbVVDwn/HrazwqWH35UxAA
         iw+UJn9mlhGfwMZoS+DUpzJAqEwhoPOTmg1UL9xx9601mxiH22fGjRWkjuM1TORTunuU
         z144Bnj60oX/JpkvqzQkwUrOzDaXJzU+vlBlax/SIiFKLOYALUN4YOJXRuIp5HFxGj5m
         6oCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E19ztN87;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=84m3Lgmy81X7eFRnL1qptMyXl0QFuSazA2Ts5IXCyVQ=;
        b=CZ9T9MrbYxjjd0pOXvYByLqKXYElvsTNnkgexnBrP2MsqWdPY+8H6jDpiidtjvDOy9
         Dbh+CeZMDGlcmnwsEh1WWw6CfxpUB/3x3LHo2Jm3x3DefAs9H8n8byOzSo5aylTUHXv4
         uwN34rPqjDNJANE23L53ifZbAYEJyoX6JEMFNUegotGIiCSH7LEyTHPvYPh3q17S+iQz
         TCbAwY7EbaJPjZnA0/E7Wnhkw+oDECmXMxVIta5e+Z5xnpT+rHrvciZWcgc4E1YU6aCZ
         8SIqIqaRKbrQw/Zk0NA2etgQ+sWR7/3id1krFmKiD/qf7YdBJ28ewCIjSOaINzpypT0w
         uB8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=84m3Lgmy81X7eFRnL1qptMyXl0QFuSazA2Ts5IXCyVQ=;
        b=r0Tv2cDmZidGIzj2zdaljyaDPH+nTm6q6gxzfrS9cXPAUteaL8Gol1q7l/hhT6AU0o
         aC1neXK4Hg6fObh3zyjt7oqZ9cpIZx01VXzG2TX9X93KfT99vNR9i5EyLuFgNWtdzo57
         Mxry8ysjfWMwPGDw5dX6c5UoazJi0MBpC3TNDNbBFCrw93wj5FQibIiAUxh5CVjThDz1
         XSMYZU/2G8sbngvACyvjsGHFyLaCObYiLO7Hiph+n2T4rHtc5i3zWp55k29U3rAa6kbH
         kOkmAePKSFpe52BUhPVsjwr/g/aGQ8tr7EIORE5vfRykZJQ0Jl4B7US98ZKT6dQTMM1u
         uz4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZrTs61FDAqopdEq82+vVOZB5hcoc9NZZmMGEzehjpz0ux9wzx
	SZBWx3q7hraKsfMd6osJyIA=
X-Google-Smtp-Source: APXvYqz5YVcpG0Wn2l9orfcorNdw7HK+gdfP54kwqvvWp2kNzpdZd1SbqwnrVXmWOfr3ynrq3+aP3g==
X-Received: by 2002:a81:5056:: with SMTP id e83mr14771252ywb.414.1579037647012;
        Tue, 14 Jan 2020 13:34:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9b07:: with SMTP id s7ls2651240ywg.14.gmail; Tue, 14 Jan
 2020 13:34:06 -0800 (PST)
X-Received: by 2002:a81:1911:: with SMTP id 17mr20189541ywz.226.1579037646671;
        Tue, 14 Jan 2020 13:34:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579037646; cv=none;
        d=google.com; s=arc-20160816;
        b=xZTrpRHZQPr7IhLaSXpnwZe3HC2XBWjhJX7bsXjQzXDpeWSzAYpe2wAtxMSURoQf6M
         ipQRMoF94wFvwjwYE+H0jEF3M0UT52RC0raoOy4bnCi7Lmm1jNInhpTU1+jXlgtqZGZL
         C9vschrglJaS2Rz5nU6wxfaaml/zIT7vXHSaxe8m5YRdF1xf5vLSk0dudxsl1WRoITiO
         yOnn/PRDUA3drLGuF3+C4eO046UT0md+ylNsCoLYcR+WgHXU/JNMTipMPIG2YA2azYbx
         koFuGXDFFy/x7lAX/7Bw4yGuylPuisw/E9yM5E0HzTrqXuGlIBEsI2y32Gn8EqqHF3jS
         83XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wZ1qTmUi5pLxh6yPDVdW6e7XG8pHHeDQLwj51Ieu9NI=;
        b=KWhzGs/S1M0oQQjM69fu82xNOEkbsW/phlJ0wn6WuS251k9hIB+KOAcqJCJkLIzLY/
         YeUZF4aisOOIJo+HblNe4gkV0qdxeYoR6g2PqOsqs5hdrtZTqZaap2EznE9itFNPJVEv
         lXGhnF9IlAx30vS5acPBu+v/doGPuOEFg9bPF4tSoyC2usiVyhqQ3u67fqGw65Sn5mmw
         wKnYTL1dcIBxkTr6F7cHMrD7O3i8XzkbNHqbxnnUnk7c4sgad/pZrEjK1jfz+i/n7S2A
         ubMniDF1CdtOf6qhmFDOFKMV8xG1ybAwzuPXT/snDz7BH0jY/9EqCgae2WDUFAHqFWiA
         Wvsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E19ztN87;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y3si725264ybg.3.2020.01.14.13.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jan 2020 13:34:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A7F3924656;
	Tue, 14 Jan 2020 21:34:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 597AF3522755; Tue, 14 Jan 2020 13:34:05 -0800 (PST)
Date: Tue, 14 Jan 2020 13:34:05 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <Mark.Rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Eric Dumazet <edumazet@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20200114213405.GX2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200114192220.GS2935@paulmck-ThinkPad-P72>
 <F185919B-2D86-43B6-9BEC-D14D72871A58@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <F185919B-2D86-43B6-9BEC-D14D72871A58@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=E19ztN87;       spf=pass
 (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jan 14, 2020 at 03:30:53PM -0500, Qian Cai wrote:
>=20
>=20
> > On Jan 14, 2020, at 2:22 PM, Paul E. McKenney <paulmck@kernel.org> wrot=
e:
> >=20
> > Just so I understand...  Does this problem happen even in CONFIG_KCSAN=
=3Dn
> > kernels?
>=20
> No.

Whew!!!  ;-)

> > I have been running extensive CONFIG_KSCAN=3Dy rcutorture tests for qui=
te
> > awhile now, so even if this only happens for CONFIG_KSCAN=3Dy, it is no=
t
> > like it affects everyone.
> >=20
> > Yes, it should be fixed, and Marco does have a patch on the way.
>=20
> The concern is really about setting KSCAN=3Dy in a distro debug kernel wh=
ere it has other debug options. I=E2=80=99ll try to dig into more of those =
issues in the next few days.

Understood.  But there are likely to be other issues with KCSAN, given how
new it is.  Yes, yes, I certainly would like to believe that the patches
we currently know about will make KCSAN perfect for distros, I have way
too much grey hair (and too little hair as well!) to really beleive that.

As an alternative, once the patches needed for your tests to pass
reach mainline, you could announce that KCSAN was ready to be enabled
in distros.

Though I confess that I don't know how that works.  Is there a separate
testing kernel binary provided by the distros in question?

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200114213405.GX2935%40paulmck-ThinkPad-P72.
