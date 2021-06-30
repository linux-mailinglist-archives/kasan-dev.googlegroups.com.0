Return-Path: <kasan-dev+bncBD7LZ45K3ECBBDPI6GDAMGQEQBUEXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 974C33B834A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 15:39:25 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id p19-20020aa7c4d30000b0290394bdda6d9csf1165151edr.21
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 06:39:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625060365; cv=pass;
        d=google.com; s=arc-20160816;
        b=fTHYcIMhNM5+4b0gx1bbOfMqedMI440FQIpq/Xqq6/Hskc3LIhxTrfA2KhnjRkSaLM
         yPrZkbUc5gqt49CVJaAAtuy5DcXxrvgzpL9+WMkBYlgkgdufkPVYWIZ0yiYmftJ9DxVz
         Jzsp2NlewpEpYb55yGKesND/eGr0BGWs1p2Ij6parQNKuCuTQ+E8rn0h1QQ536m9xiDA
         20ndVRIq1htMqUqN5Lrmu0+rOq4KJRC3bXG3reRPrmbCEWevDGvluP+Cc9tnm05FddKb
         HDNJifoTIdRYSicSR2+/pn59J0K2BvVIG+3U6IPoE1IY1M+jGbX/7GHm8HDAHOfS4gHD
         o6qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YNtdHAC4JcXSEx38maoe7xT56UT87fBC5SWM5v8Cc5U=;
        b=e6cJdVI3rgQiGDJ/iDqQQnN2CwDO7ieux9oF9QVyZmaQebaZMoX8aqct+1TxmZpT32
         z9Pe3EdyELkq0ObNPGoN7S/FoESHQ95LgPrIdbvZx3//dIzMMP2jr5clHcM2GKypGhDG
         HS22zif2s0zqXTjuoyOVGgFWLs+D84MP6RAt9kVbbOCBPYKWjFgnH3hgVs5mC1Ygsp9W
         fH4S35DQGAky2sXNuY4GVsDziEOY8GkkspfIduxReYrc/wSpaoqjMsuR6JQ4KwtPuui6
         W8/tisIiD9+EzAXrP5RA8XspJAWE7UBNCvGwuHIS/tT21z70ZvWx6PMVUx5kvgFTgkHw
         GagA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vL++g7o7;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNtdHAC4JcXSEx38maoe7xT56UT87fBC5SWM5v8Cc5U=;
        b=SrYUxmlhzVtwMmIJpnPGOtvDGhoVJ/i/B6VZFcfZtiHvglvdwgxvA43+9ubTcGVmKE
         ySti6mM3KUg/VhwjeI084vSKfG4FVKmWzh345SE9h2Peo8dB3QUnpysYWtl3n57OwBuz
         sQqt0ZOKyzqTT0rkIOsnp1BGxsRPsVS9rHCcjjmJ6JxmkO98Y5bbuBBDdYu8i6qcrJ6I
         qqjsqdYWsUOudGBQ8+a1w3GFxdgS9/o6eve/+Hs6Wz15D3Of3PVU8I96lBam4T8qpgQM
         3xXJGbIjbjNe+vklorgIIYYtWBBco5C5EtInQST5eFD6UsLl9MkTbUZQnG+xJGQwpMIB
         0Pgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNtdHAC4JcXSEx38maoe7xT56UT87fBC5SWM5v8Cc5U=;
        b=aJ4A3S/blsI8fqFwF+bbdD3R6ntmoaBFoHAU6YbcwL6og1pZ7j+waYH9GhEdIbhpRC
         BreUjrDDS7LDRkhkhB5rR4OhWDGPlHZxIU/PXFau2R9LhMSTr333YI9Q9rzE/ICo+aTI
         n2JzE3Gh3/0TuCZ3NyMSuZHMpg5tHlZ1swjnJRd7OxNsiA71TxzuYWcBuuGXcoDqptg/
         u4D+hvIPEzoTOY16D/6OG5RB+DQPR8IMz6VTn5pDPfQcq0clfVscl+wOWQJh5lj18d56
         yxKUFglCBY4ek1XVps6F0k76dfv4uLEQBMJfIAMMdj5JZn1bTXEn/S+ywTE+VbnA92O4
         BGpA==
X-Gm-Message-State: AOAM533BUduKvHVa6CMR8RCHlr/YLR4bPfedcY36aYJ9dTsc/CBGrPyu
	KEcdOGVd0jP9accf5eTITvc=
X-Google-Smtp-Source: ABdhPJwMe+qD+XI80ZOdXc66ZLEkhORc1HINvs2ydOCRY95xqd4XFUFXBxS62qT24IlO3gOsiPmnkA==
X-Received: by 2002:a17:907:9719:: with SMTP id jg25mr35310237ejc.82.1625060365269;
        Wed, 30 Jun 2021 06:39:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7fc5:: with SMTP id r5ls159946ejs.3.gmail; Wed, 30
 Jun 2021 06:39:24 -0700 (PDT)
X-Received: by 2002:a17:906:474e:: with SMTP id j14mr36341913ejs.9.1625060364160;
        Wed, 30 Jun 2021 06:39:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625060364; cv=none;
        d=google.com; s=arc-20160816;
        b=gOHnSFacCJLfaEvgLUxAoEq6twKhU1a9REcZDAPO+aq+/GeOwjOyT/321gVh0U3vqT
         TvV5xiZ2KNeHic9Kqkal24zxohoGWsj1ib625z7Np4PO2HJ2db/EdTYAD4kddjdOD6AJ
         p8/3GpASK5ojVhwSRft4q9d2W1OCMPuUriEjKQFkaw+gk8kkudIpuN3MCv2gQGAUheyr
         WLE0Kz4fV765CNhLo6b1Kdrk8pFVO/2H7idjiuxiKBj3b4oQG+nto1kYPqxke1l2JhPU
         /FDF4kKt5gdDnf2wEGZ3jP/5L474CB0gKObwoVHE47DzwF1iQcXvLTl9vtax/1guc3Mf
         kiHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P6YkXWwp9vzsor2WzBqGvKiFhq9S2OEkbMs5Ffp5U0c=;
        b=YmKBBDWAV8sKdTW9WRbN1rqiF8w6yZ+HRh7O4jlClbUYtKR0hRnquzLGm5+a6FmGsW
         oyxa8OO+Mb04shXlLYPZmYJwJ76cxMr+84r8JslT5B423fUJ+aWTpFHKjLZoz++K5oVT
         /LoNXcqELeSAvFDsX/1PCU5qdFk1rp8PZXRldsWZoQ+je3Y3SSzmSJk817zxahpJePXh
         zXOy7qnQoTcZy5tyMYwbYqSz8rJFlviHoiyC6qIW/RqyrZUcrma/ac9sSDQr3+tjAKZM
         5gEQONRMV3NI77uA8qd1htP5vEPr6ypK6lCE8d7QomeAQED0YgaZ7KkCxA/5BGL5tWVB
         RvYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vL++g7o7;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id u19si1227003edo.4.2021.06.30.06.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 06:39:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id i5so3347449eds.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 06:39:24 -0700 (PDT)
X-Received: by 2002:a05:6402:781:: with SMTP id d1mr47535736edy.32.1625060364019;
        Wed, 30 Jun 2021 06:39:24 -0700 (PDT)
Received: from gmail.com (94-21-131-96.pool.digikabel.hu. [94.21.131.96])
        by smtp.gmail.com with ESMTPSA id ml22sm7755328ejb.71.2021.06.30.06.39.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jun 2021 06:39:23 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 30 Jun 2021 15:39:21 +0200
From: Ingo Molnar <mingo@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: eb@emlix.com, frederic@kernel.org, jbi.octave@gmail.com,
	maninder1.s@samsung.com, qiang.zhang@windriver.com,
	urezki@gmail.com, yury.norov@gmail.com, zhouzhouyi@gmail.com,
	mark.rutland@arm.com, elver@google.com, bjorn.topel@intel.com,
	akiyks@gmail.com, linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, tglx@linutronix.de
Subject: Re: [GIT PULL tip/core/rcu] RCU, LKMM, and KCSAN commits for v5.14
Message-ID: <YNx0CaT2ZTyuNYCK@gmail.com>
References: <20210609232926.GA1715440@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210609232926.GA1715440@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vL++g7o7;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Paul E. McKenney <paulmck@kernel.org> wrote:

> Hello, Ingo!
>=20
> This pull request contains changes for RCU, KCSAN, and LKMM.  You can
> pull the entire group using branch for-mingo.  Or, if you prefer, you
> can pull them separately, using for-mingo-rcu to pull the RCU changes,
> for-mingo-kcsan to pull the KCSAN changes, and for-mingo-lkmm to pull
> the LKMM changes.
>=20
> The changes are as follows:
>=20
> 1.	RCU changes (for-mingo-rcu):
>=20
> 	a.	Bitmap support for "all" as alias for all bits, and with
> 		modifiers allowed, courtesy of Yury Norov.  This change
> 		means that "rcu_nocbs=3Dall:1/2" would offload all the
> 		even-numbered CPUs regardless of the number of CPUs on
> 		the system.
> 		https://lore.kernel.org/lkml/20210511224115.GA2892092@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	b.	Documentation updates.
> 		https://lore.kernel.org/lkml/20210511224402.GA2892361@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	c.	Miscellaneous fixes.
> 		https://lore.kernel.org/lkml/20210511225241.GA2893003@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	d.	kvfree_rcu updates, courtesy of Uladzislau Rezki and Zhang Qiang.
> 		https://lore.kernel.org/lkml/20210511225450.GA2893337@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	e.	mm_dump_obj() updates, courtesy of Maninder Singh, acked
> 		by Vlastimil Babka.
> 		https://lore.kernel.org/lkml/20210511225744.GA2893615@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	f.	RCU callback offloading updates, courtesy of Frederic
> 		Weisbecker and Ingo Molnar.  ;-)
> 		https://lore.kernel.org/lkml/20210511230244.GA2894061@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	g.	SRCU updates, courtesy of Frederic Weisbecker.
> 		https://lore.kernel.org/lkml/20210511230720.GA2894512@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	h.	Tasks-RCU updates.
> 		https://lore.kernel.org/lkml/20210511230924.GA2894768@paulmck-ThinkPad-=
P17-Gen-1
>=20
> 	i.	Torture-test updates.
> 		https://lore.kernel.org/lkml/20210511231149.GA2895263@paulmck-ThinkPad-=
P17-Gen-1

Pulled into tip:core/rcu.

> 2.	Kernel concurrency sanitizer (KCSAN) updates from Marco Elver
> 	and Mark Rutland (for-mingo-kcsan).
> 	https://lore.kernel.org/lkml/20210511232324.GA2896130@paulmck-ThinkPad-P=
17-Gen-1

Pulled into tip:locking/urgent.

> 3.	Linux-kernel memory model (LKMM) updates courtesy of Bj=EF=BF=BDrn T=
=EF=BF=BDpel
> 	(for-mingo-lkmm).
> 	https://lore.kernel.org/lkml/20210305102823.415900-1-bjorn.topel@gmail.c=
om

Pulled into tip:locking/urgent.

Thanks Paul, and sorry about the late response! Will get these to Linus=20
ASAP if you don't beat me at it.

	Ingo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YNx0CaT2ZTyuNYCK%40gmail.com.
