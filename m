Return-Path: <kasan-dev+bncBAABB4PSVHZQKGQEBQ4RRHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB41183828
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 19:03:31 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id t193sf2664257vkb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 11:03:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584036210; cv=pass;
        d=google.com; s=arc-20160816;
        b=JSWf1t93QAyPE0VQgEn1axfp/g9hmVuTLPSQ5IPmGKpUuhql0qiwaUWzB1alR9A8hi
         tDHP1pj6aiazM1KHYjGRYkOMzC3tPA6lMvFzy6hIUrBAs5EzKpaCOhMC+50KEFbeQVrh
         TIYIwUJb4ZLD1hD2sC5zUbC7huiO3/6mUrw4SREIKeHP0z5cgScscM5dgHuvNnd2Vyvp
         jR/bCY9wcScX8HMXUnxB+jCy5Tn667QEh2I5z/ybyfLNrStDB0PDD5nAvPEjiGM1el2p
         9wKiWB0l+HzNV+OEdsNptmVsbnqX6QlQ6FJ1snKmFoUnC9U2t5MEqt01K8Ds/Wfbe5Lg
         CnYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GEQBj8AgjA9H1kfeUFOzkYKdZktiB20xs2MlRFb5UBM=;
        b=hWV4Mwc2aRZlK/VtAoFxVl+0JiQwyg2wBmknJtDt6I+3Ksc7Fwmn/+CEIoBB5ZDAVG
         sgJ9UkDKwTHVJFsMU74sppvmM5XW54BwBgEsotyKGo0wPvltN6Ok07vrV2EIBs0hpAtQ
         40QOStg2jU8dLspo/1+VqIO6WHFtQC8Q+P0xWjW8bAqAYA4QFuvLYDHOP6l+SalxJL1g
         zY7M1z8kmfj6YHLM59N59TjUNUPT+ATl/5Oeu4R6W51+9ItLu9epUcoRnB80LH7Usv41
         RX6NEV6gJcVoqHaDVpSbsOo5gByIsDY444xySmObQnUuyV8Fj9W8IgqrK4eYewpcKTp7
         UVgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fihPR0qN;
       spf=pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GEQBj8AgjA9H1kfeUFOzkYKdZktiB20xs2MlRFb5UBM=;
        b=n2yiQFKz9QOlb1/yIf21nGbDNzxdkDD7o9jr77CamAg3dSLi42J/At0ePs7okXScnM
         KB8Qu/wgg/aYSL3/VNng5YOTsRqlKnMA48NWXsV7OE9y3BydzWCvI99qk3d2A4BjIvKq
         FKrtn/jQjLprOBr8t0OBRPXdyz6k6hA9DCol9Ye1V6ErPYzfSvCK04xzsLEnid/R76jS
         Q+ilYCXToyS2D3tZZifch1DYy6IYoB0qPxD+an1vcbFfJnqx4xBC0JfLUw62HM343awZ
         PDGIa3OWk/VUU2H2xhIZ1FZ7vnDdVHVJmCzdTNnFX3Kkm7ltYWYjebxkdfzMqBMfWjnN
         lMIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEQBj8AgjA9H1kfeUFOzkYKdZktiB20xs2MlRFb5UBM=;
        b=gBfOfHOWUSJIva+YjryZacvd9XPd02FQe3koeDbTZEWmnZ/EJNf37kPs4ITG+Rtce8
         lowJjNjy8H0gVh3Rz+DjagGaL7b2PcInabDX6n4tUow86ZlAbWdmnegGFThpZDhz13An
         afzBmR+YF7cIgGy2gqb1tS8JRb68buAfp38zLxsDhHRzd8VGkCv1bLBY4LYsVvhTIw/1
         j9VKIsNSubxpxw5804dZF2qa3Q816GblJLacyPwEXlfKJ2cqwUVPcaZawBaCUfUXNMzo
         Uq9sXuZtW9nderP/RTE0VQR22YxhW7QMJkacwSUNLxsMgVaKBUpo72Xxx5jVQzv7iNW0
         J0fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3W3DOXlg/aPLdaFxXMFQTBc9Nu2z0/p0WQPRmXfyYtRSo7AaOL
	kCibVWBdaOcEuWwXtBD6Isk=
X-Google-Smtp-Source: ADFU+vvPUoEuePaYj4jYgl5cVJhQYcdvY1IXMdJ01zj0E1HZIb8HqCHxv/2NCdFkIMcEeXtCB+nv1g==
X-Received: by 2002:a25:bd45:: with SMTP id p5mr3722808ybm.493.1584036210123;
        Thu, 12 Mar 2020 11:03:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5789:: with SMTP id l131ls1794474ybb.9.gmail; Thu, 12
 Mar 2020 11:03:29 -0700 (PDT)
X-Received: by 2002:a25:34c2:: with SMTP id b185mr10907735yba.57.1584036209649;
        Thu, 12 Mar 2020 11:03:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584036209; cv=none;
        d=google.com; s=arc-20160816;
        b=gY4Zf375JikLL97J+FOr9RL3nwkuNP10/WaCmlHASwpKJe9HxBBoVIJG3znyaYMD2b
         XHAPSmnaO0yqv8Fiv29xU9YYv+HC/TFf/PkA/IMed90g8VATd2rMSgjzqIrSm67i+PKV
         10Ukc09s/ttmsegFEiZouYjiFz34j3DOeJsuxqYo2MekkMsmy41E4C+V3QFSI7JFS+zx
         5pr4Luaf461LdLWIa9z6r3BeNrBxvE760IEA7owbJqA4v9qBycVxCfzJLMY1fbfeKcSP
         CGGPnA27q55Vo84F+lufYqdi6QxdgJ1qFVhW+iQ3FhyG8kkV25ERhrymZcopWQrxiPtx
         /r2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SrNiB2O+fvN7g09NnS890RCqAZRKkOTWljkaXxNtXQU=;
        b=BzNJdRrlZ5WYxx5vGrZBvERBPwiQnfWGXUkKfe69DXfwr3RxJqVHXxRAa9rWR19Cna
         P6ILZH4uFm84WgSUlwQvUCw2GS5VrgFq30DlQ7W/LyK3vy5o0BVWaWjVAs0wwl6Xtpv+
         bIuwsov7UYlBFkMLQY9FuScSmZ1yVVKoHQMvCGPvpSVZOpQpZ+pA67FYZBF2imDZFt+O
         knOprtOnHr3ZZaXBTUnHTMtvMPEI5C7HYFdihBAIgslSQVqAKRKMO6yjlAp5LMWQCeWV
         Ct6S0JB47Jbb6T0tNo6xxcSsJAijRWiexF+bzJEbfbnsi+bIDG9PBiMEMypZOf7xuFQI
         xqzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fihPR0qN;
       spf=pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w18si484959ybe.0.2020.03.12.11.03.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Mar 2020 11:03:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8DCC620663;
	Thu, 12 Mar 2020 18:03:28 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5980835226D0; Thu, 12 Mar 2020 11:03:28 -0700 (PDT)
Date: Thu, 12 Mar 2020 11:03:28 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 27/32] kcsan: Add option to allow watcher
 interruptions
Message-ID: <20200312180328.GA4772@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-27-paulmck@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200309190420.6100-27-paulmck@kernel.org>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fihPR0qN;       spf=pass
 (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrote:
> From: Marco Elver <elver@google.com>
>=20
> Add option to allow interrupts while a watchpoint is set up. This can be
> enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> parameter 'kcsan.interrupt_watcher=3D1'.
>=20
> Note that, currently not all safe per-CPU access primitives and patterns
> are accounted for, which could result in false positives. For example,
> asm-generic/percpu.h uses plain operations, which by default are
> instrumented. On interrupts and subsequent accesses to the same
> variable, KCSAN would currently report a data race with this option.
>=20
> Therefore, this option should currently remain disabled by default, but
> may be enabled for specific test scenarios.
>=20
> To avoid new warnings, changes all uses of smp_processor_id() to use the
> raw version (as already done in kcsan_found_watchpoint()). The exact SMP
> processor id is for informational purposes in the report, and
> correctness is not affected.
>=20
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

And I get silent hangs that bisect to this patch when running the
following rcutorture command, run in the kernel source tree on a
12-hardware-thread laptop:

bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --duration 10 =
--kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_ASSUME_PLAIN=
_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONFIG_KCSAN_R=
EPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_INTERRUPT_W=
ATCHER=3Dy" --configs TREE03

It works fine on some (but not all) of the other rcutorture test
scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The common thread
is that these are the TREE scenarios are all PREEMPT=3Dy.  So are RUDE01,
SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammering
on Tree RCU, and thus have far less interrupt activity and the like.
Given that it is an interrupt-related feature being added by this commit,
this seems like expected (mis)behavior.

Can you reproduce this?  If not, are there any diagnostics I can add to
my testing?  Or a diagnostic patch I could apply?

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200312180328.GA4772%40paulmck-ThinkPad-P72.
