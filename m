Return-Path: <kasan-dev+bncBAABBA7Y7DYAKGQEGOO2QKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05AF813B51A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 23:09:09 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id h2sf8888451pji.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 14:09:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579039747; cv=pass;
        d=google.com; s=arc-20160816;
        b=dZ2ArsK/pTPpJM6uREVLbpyCtxZAmsQmv6HCaDRL53nPvs2st06ALHktU7yo251wRM
         3t6IvghmpqKTQ/koUhK0Qhk8IjjKpHjFkagrrqwZnJHEY5v0zcmmFXLXyoc2nCUeZYwi
         kRI1zEmIvYgpLIlKFudSaSJktnCApfA45UHsxj1+050sSvS/Yay6xaH6Pk5PJX/xZbhY
         KbqR2wwLRXrfZyoEOVcO+TK76n57eiEqoIzwgAvaWlJGpAYSOaXIgXtcBqqKVPefsVba
         2LieGL3pJPN6S19cu1L/oW9ei68nkU5ZZGNftIXIvlfHpPE0aRuHh/t5FEVUrNTEc2gF
         cBpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=phxOJHdy0Nn6sz5C8eWE0O4kYfdVoVqzLp2Ssj5ETUg=;
        b=GuwfN4f9gcdPsZfb4pJdzDdXVeApXZfNLiCPJmhlitL/sEppa97wZ50ZtTlOGcKAvL
         DvsrwF8edfP0jLCP2AhCtbO2xNs5FJcvJ22QBkrOZiq3Z3SX4bFFn1Yi6uAn5GRaJPfT
         xmZn/m4TyRK924qiPHIY1aUiHLKgTswNole/tLsn4Zobm7L+EPXWpcPJ2wPLCSzlQHy/
         veCb+pTfYWUjufUa5HS+TQavtfjm8/8Zhg3VTLV/Q/mVjERH7oZfCeMl/1qkEBbVAx5M
         +2A3wQnDEvJhPOivCH6bBLRnmLhUSCMBXAPnpKf6EwdQGTE+6dFpZLgL+XZzYS/MnIo6
         30dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eHTtZBZK;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=phxOJHdy0Nn6sz5C8eWE0O4kYfdVoVqzLp2Ssj5ETUg=;
        b=ocQLwpKo7fzvCqtaPI+W/94pxPw+rlW6bilp0Tkyn5oK1q8A/8LSg3x4zSGEYiD7gQ
         doYCxWN45l/7h/Za/kAsZTD2pVzyuGxL5H9/7cQ26QnBbq0/mx+l5OX3IzrzKhCeZHsW
         G4JL8S/FPTz5Un03neEWXUyeMvSAMvjA4BENg0mKjkBKeR8Bt29greRon1KvSRecAUFz
         D8344xCWfiSGy5NzLKfBfzp5XdTcL4W/q/H3BGWwlB3S30kGYXv4YLE7aAEGEIO6GZ8n
         CShd7BjtsfE6Ix6p/79pyTcfEP7d8AsSIDOsGE5HgSlN5rEybOeG4uvwjLS+Cl3/QKe9
         ebsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=phxOJHdy0Nn6sz5C8eWE0O4kYfdVoVqzLp2Ssj5ETUg=;
        b=X9K8dZ5mIbvjpqKRSqSiToeJr8f6qFRe/m2Dmy3mFpnAnGoLOEjbVkx9qq/Zq5uCaO
         wBH9M2R0zrhMcJRTZQ51gLlCnsj17X1xpE6mYJtvX+hHNYMXBef8XKSjRPa1xpW0Blrw
         5Cesmmq8lJjq47/1dzLzC1W1dcxC7EgEGsGk4M/h+AZWZifgbkeRPaN4417U5+08HXpJ
         fI+HZnqa0JBJSzBz2r9qhXbqhE8UqHl6kwBDReXgKYBe0n7dH9/0S2MQiFpLbZ59aJRt
         aiQ3gQSMtAinBmlqA3DP1IzJiYSDhIwyETvzsjvCkm6iNwHtxQN4q9bOsPidQ4oamW9G
         hwbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUqL6IXxuA/tHCV2QM8MOE05nR99IiG+HHO6b+O/tya8IzaL5u9
	KwmtysKUotUxRChI4WEwWkg=
X-Google-Smtp-Source: APXvYqx0RKcwpg0lE5/FvkT0824KnnjFOv6gg5UdUPcSHysHxEB+qz2COII4qBfB+DWfaYaL1hN0Vg==
X-Received: by 2002:a17:90a:b392:: with SMTP id e18mr32303870pjr.118.1579039747488;
        Tue, 14 Jan 2020 14:09:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d207:: with SMTP id a7ls4701113pgg.1.gmail; Tue, 14 Jan
 2020 14:09:07 -0800 (PST)
X-Received: by 2002:aa7:9629:: with SMTP id r9mr27879135pfg.51.1579039747088;
        Tue, 14 Jan 2020 14:09:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579039747; cv=none;
        d=google.com; s=arc-20160816;
        b=lw/k21vleoa/KTsGWuEfmHE89vwgxQ16NHpujRDkYva7d7R11qCNDCv99v+UJLwSEA
         sq5mieepchp1D2HxrHufl0paXGeHBDPrnQFeBeU3ZpvB7euoYETt5+FWozqnDj6XJNI4
         pb1PsqOTK14apjDom/z9DhUhQvsRzeAbG4qg14m2PXILJADBPHKYLvsv7Hv/2KgGcwGN
         rD0F0DZ0RQ/2eMRXVZOMQO3HkRArd5SZDzCYFVpuezJxefPplJCTVJXO2aEqKPnCnkeZ
         t4Irw0ou8vQ1yTMQ2r4Eri2SaO42fEdy9pVzZnQGa45sQd2APVgLP2chjPmBAHKYHZGO
         ihgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=MHzLEUX3vmkSFBns6Ut9COUFISJHhu946uaIZQRx0us=;
        b=xF4FPYgmTO5oS0ZUQxEtAOGsWnHv3GCSzNi6q2j1oPABB0gUwXtneXBIEry9EdRaB7
         AEE+8pl2MgDBQObyIYW+J+24nXcqU7cBfGadoVW0C/vICnRy9quiStmQ3iZwPb7++KgO
         yUDQLsfvAXX81dF1uEtEoL5NjU10UUjVFbSNGmgira+GGQ2QuJSj7pj4nH9rslVJPado
         V4G21+HQfBlLcxX26+SVBEmybRiL2nk3LUit+Z5TWSCn3zSFLrMZ0wNk+WLD5T9S6TMt
         /Y4tDJB67xh6NzrfrtlylvDtDZ/4jRs1uzQnj7n7yicJwey2aG8n8wg1Tg9duvwbYrle
         ckaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eHTtZBZK;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n20si704067pgl.1.2020.01.14.14.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jan 2020 14:09:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B8E4324656;
	Tue, 14 Jan 2020 22:09:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 6CBEA3522755; Tue, 14 Jan 2020 14:09:06 -0800 (PST)
Date: Tue, 14 Jan 2020 14:09:06 -0800
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
Message-ID: <20200114220906.GZ2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200114213405.GX2935@paulmck-ThinkPad-P72>
 <9970E373-DF70-4FE4-A839-AAE641612EC5@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9970E373-DF70-4FE4-A839-AAE641612EC5@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=eHTtZBZK;       spf=pass
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

On Tue, Jan 14, 2020 at 04:48:22PM -0500, Qian Cai wrote:
>=20
>=20
> > On Jan 14, 2020, at 4:34 PM, Paul E. McKenney <paulmck@kernel.org> wrot=
e:
> >=20
> > As an alternative, once the patches needed for your tests to pass
> > reach mainline, you could announce that KCSAN was ready to be enabled
> > in distros.
> >=20
> > Though I confess that I don't know how that works.  Is there a separate
> > testing kernel binary provided by the distros in question?
>=20
> I don=E2=80=99t think I have powers to announce that. Once the feature hi=
t the mainline, distro people could start to use in the debug kernel varian=
t, and it is a shame to only find out it is broken. Anyway, I=E2=80=99ll tr=
y to edge out those corner cases. Stay tuned.

Very good, thank you!

And you do have the power to announce.  But just like most of the rest
of use, myself included, you won't always have the power to make people
actually pay attention to what you say.  ;-)

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200114220906.GZ2935%40paulmck-ThinkPad-P72.
