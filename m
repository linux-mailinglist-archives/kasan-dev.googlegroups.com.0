Return-Path: <kasan-dev+bncBAABB3NJ7DYAKGQEKJSHXOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6D913B2DA
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 20:22:23 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id a2sf11342573ill.13
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 11:22:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579029741; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjIxDiGr7BmonFCP63g2mQki1R1LCC6PcpPNTaLMebTc54SIQS2SluJFWNa5IYy/PQ
         ZrHJuJS+zmW9+0twWw5bphka0z//4zi0gvL4OhHWEDFTfWcAM/LcfIEQR9yUhh0d1ATG
         qiy3nKAoV1FxyuVCeetOGDpuAH1BvrugXFiVoG5JbySF2rXnItF9FXbsmCUg5Rtq1QQg
         8XD1dde4sTEFmAiF4FKqnBS0rYqb/6U5xPJ4W2iHeUHgNbYoad3c3SFrNxOIYtENiU3C
         e5Ure8xGGOE1e1P9TiuT2Lh4K24hQ/l/9ZTXa3W+gG95WBvKupg6Vd++dwVEv9+dFofu
         FKZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YViT8lMOOCqlhFFG7bW8pXpJSm5ORS9+1gOt1SNNtdE=;
        b=KplV42TepRZB0Wk6cXhHQ3cU6JHbLQDV9ABw0QsW5z35ZZLCtWaymzkCjTiJa479nb
         saHsxGjqBln0CHjoEWnddJ+DC49L1rVQOEt62UaIrcV2ySd36uRwJYkI/rlT7W3DC8/m
         6NjTb9aup/fNJtmJZw2KM5bJPg40IKB4WnmNQOx19vdItBNCBu5m8Rser8cA0KlxELzp
         o7sd97PgtwRQcjGGVijm+7moJ4s61Mwd2LIa9oI1DGr9FKKACFkQaAxsXThvmes7LyUY
         MBia1/fcoNb18x4v/EXM80I4W5xLO2bbLqw3ayww0He+k+mKu1vvUQVNhfbUNZ8gaw/8
         pS6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=117MId6F;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YViT8lMOOCqlhFFG7bW8pXpJSm5ORS9+1gOt1SNNtdE=;
        b=c6TiHH7Gu9rYQ2Tb0h5lS+vcbWAwabIEtl6WlyhN3BtGI8PRYbIXPfI8qJBAcLKhUb
         ixbuhmXnz7uutZJzObzUfy6m4YJT3VQq9XKV2LhBHroz2OPrGEnXwxPpii1YQj1+GMmJ
         C8Z7X++J4Hk/dNLdxf+G49GpEinx0bdMI5M0/I75/DiVYoszpUB0kPerYfxQNwYIvzP7
         eH2W5xvtfiACBOVvIx5l1zcCVQNHUqulvgLwvEB+xc12auYcu7qr2tK66gv51/Yqku9t
         xSrp23xxGoKEA8theaR7RSdY5f3px8ynVMAoptb1N67HIjxXUcMWBIuBdzfjig+6lghV
         qcng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YViT8lMOOCqlhFFG7bW8pXpJSm5ORS9+1gOt1SNNtdE=;
        b=SwDPytflcievprSgsr24iCYfza6aF5m/MDhXAJm9jxuiqTisc+bytoqhYAofcNEpg1
         cD/JFFCkgRyADyLk29kl35nrGhT/1ET3H+kl+3qmgMcKKrR/e9cQ8zekUeDJVNFb3qcq
         uhtfp/SZ4/zex1NxJsNg3AzMDOdF5+5xpy8CEyW7p3osu/iGAM1UqfenYBSRRsD6bii7
         Ry5HwAMVKpEPjQBNjZlfgK7uV+Z5pS9wGnKWw5c/0WAFFLAJwOijcd3s+io1b7gA0BW9
         PJGFhHonSkV8m4SnHD/kI6HwWG3Svis+64pngHqjFlcfxrF0DP2RUulTvIvOT9HyJmNq
         4gyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXW+CGImXWIYpFoXT2kG98Zkk5TOpskHHy9dTlMBJ8+H/zlLArA
	96BTRRDexuA6nHtF3bnLvp8=
X-Google-Smtp-Source: APXvYqwriYXyp3x+n3elB8xsPLjUBa1WUJ4tKF9R1XZemuBF6/loAJRUquwmaCXgMUtmTot9tDpPPA==
X-Received: by 2002:a6b:ba06:: with SMTP id k6mr19095098iof.70.1579029741709;
        Tue, 14 Jan 2020 11:22:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cc85:: with SMTP id x5ls2845008ilo.12.gmail; Tue, 14 Jan
 2020 11:22:21 -0800 (PST)
X-Received: by 2002:a92:2904:: with SMTP id l4mr5038190ilg.166.1579029741406;
        Tue, 14 Jan 2020 11:22:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579029741; cv=none;
        d=google.com; s=arc-20160816;
        b=pQrBxAFwUb9FgDC4+UnDGz5/FK1xAk55ysLTPTPSybDrLZUoMianA1Twd/eW2koEdF
         14DaOmjeKr3h+4m0I5xgSAAexY5wXTifQaZFIjRDnl21djRohNXJXjNvKZ+/oI3kRUPV
         neA2IbxBvkf+7K6YOuvqcb3+3j0kRl+Y2VZNHej7Y+UdZpi5/2mHyImKxbaJTmR4DJDC
         Y5lfgRbiMm3w1LSeawS1wLzNDwX/cHvPJhE+Ot4BTaMAcandN9c+kQqVWtW8jTHjco0W
         MMXSHMcSS2xGSB1j+lVGNSFaCunJ+Sm5o9TUMhsZyiI6D5K0GnJdzaZ8m+kMPe7Wofnv
         8smw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=uIwYTxNVWerAZwbeNa6ISjoYovb1/y6c7j41i7QPOkg=;
        b=VczMhLC9hLPXKFEGcB2T+5WjRDbPdfysaLI/QXJkuL83hszxKC6hvIW9B2t+0iqXnu
         gqbgTs2j3vqi9kcStJNi7FZSe1vYjlHuMqqi2CJ3IMkyF/8yW7pJbuxwK1K6m0j69lka
         BQ7cFPEqNJ7K8PJjj69+H8U3gj1cgYM15+sy9hFjIW7RvFh6Ka8Fe231G9Xny0jUc8bF
         wpYZa55TatDjsLLQpREAKVNmUVbRcUO8Aks1guOJ6Yc/2k0wHAiMNqgzmE8kS0AX2uxQ
         SgYLdwUK9aG/jxRM2xpbYk91294Dqn5W+S/QN+6eS7l+HDRHd4oMJIiOLRysxK24JZ7e
         2KkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=117MId6F;
       spf=pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z20si669926ill.5.2020.01.14.11.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Jan 2020 11:22:21 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9888124658;
	Tue, 14 Jan 2020 19:22:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3FB583522798; Tue, 14 Jan 2020 11:22:20 -0800 (PST)
Date: Tue, 14 Jan 2020 11:22:20 -0800
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
Message-ID: <20200114192220.GS2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CANpmjNOC2PYFsE_TK2SYmKcHxyG+2arWc8x_fmeWPOMi0+ot8g@mail.gmail.com>
 <53F6B915-AC53-41BB-BF32-33732515B3A0@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <53F6B915-AC53-41BB-BF32-33732515B3A0@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=117MId6F;       spf=pass
 (google.com: domain of srs0=i/tj=3d=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I/TJ=3D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Tue, Jan 14, 2020 at 06:08:29AM -0500, Qian Cai wrote:
>=20
>=20
> > On Jan 6, 2020, at 7:47 AM, Marco Elver <elver@google.com> wrote:
> >=20
> > Thanks, I'll look into KCSAN + lockdep compatibility. It's probably
> > missing some KCSAN_SANITIZE :=3D n in some Makefile.
>=20
> Can I have a update on fixing this? It looks like more of a problem that =
kcsan_setup_watchpoint() will disable IRQs and then dive into the page allo=
cator where it would complain because it might sleep.
>=20
> BTW, I saw Paul sent a pull request for 5.6 but it is ugly to have everyb=
ody could trigger a deadlock (sleep function called in atomic context) like=
 this during boot once this hits the mainline not to mention about only rec=
ently it is possible to test this feature (thanks to warning ratelimit) wit=
h the existing debugging options because it was unable to boot due to the b=
rokenness with debug_pagealloc as mentioned in this thread, so this does so=
unds like it needs more soak time for the mainline to me.

Just so I understand...  Does this problem happen even in CONFIG_KCSAN=3Dn
kernels?

I have been running extensive CONFIG_KSCAN=3Dy rcutorture tests for quite
awhile now, so even if this only happens for CONFIG_KSCAN=3Dy, it is not
like it affects everyone.

Yes, it should be fixed, and Marco does have a patch on the way.

							Thanx, Paul

> 0000000000000400
> [   13.416814][    T1] Call Trace:
> [   13.416814][    T1]  lock_is_held_type+0x66/0x160
> [   13.416814][    T1]  ___might_sleep+0xc1/0x1d0
> [   13.416814][    T1]  __might_sleep+0x5b/0xa0
> [   13.416814][    T1]  slab_pre_alloc_hook+0x7b/0xa0
> [   13.416814][    T1]  __kmalloc_node+0x60/0x300
> [   13.416814   T1]  ? alloc_cpumask_var_node+0x44/0x70
> [   13.416814][    T1]  ? topology_phys_to_logical_die+0x7e/0x180
> [   13.416814][    T1]  alloc_cpumask_var_node+0x44/0x70
> [   13.416814][    T1]  zalloc_cpumask_var+0x2a/0x40
> [   13.416814][    T1]  native_smp_prepare_cpus+0x246/0x425
> [   13.416814][    T1]  kernel_init_freeable+0x1b8/0x496
> [   13.416814][    T1]  ? rest_init+0x381/0x381
> [   13.416814][    T1]  kernel_init+0x18/0x17f
> [   13.416814][    T1]  ? rest_init+0x381/0x381
> [   13.416814][    T1]  ret_from_fork+0x3a/0x50
> [   13.416814][    T1] irq event stamp: 910
> [   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f=
3>] _raw_write_unlock_irqrestore+0x53/0x57
> [   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba7=
6>] kcsan_setup_watchpoint+0x96/0x460
> [   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>=
] copy_process+0x11fa/0x34f0
> [   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>=
] 0x0
> [   13.416814][    T1] ---[ end trace 7d1df66da055aa92 ]---
> [   13.416814][    T1] possible reason: unannotated irqs-on.
> [   13.416814][ent stamp: 910
> [   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f=
3>] _raw_write_unlock_irqrestore+0x53/0x57
> [   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba7=
6>] kcsan_setup_watchpoint+0x96/0x460
> [   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>=
] copy_process+0x11fa/0x34f0
> [   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>=
] 0x0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200114192220.GS2935%40paulmck-ThinkPad-P72.
