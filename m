Return-Path: <kasan-dev+bncBCS4VDMYRUNBB6OKXONAMGQEY7AJ3AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 038FD6031B9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 19:42:19 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id il7-20020a17090b164700b0020d1029ceaasf12160236pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 10:42:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666114937; cv=pass;
        d=google.com; s=arc-20160816;
        b=ve3P6fcYTHxesJD4+V4hmXacJlQKyoxE/ru7GRvz3Kw2xPObuTezCmC1a62+jciPxt
         Y/UJ7Z7soq0lubWNs6y4Ix1oIjfNnbZQ89k/KWd0pYUwrtU9tlqq2faQvqBd84iLkohI
         vR5MDm5taYKVTYTrh2/HqggUp77hdNlA1GLt6cRWN3A2jRzv+5qjopo3DFhcWdh0dSWy
         Ydb+FXV9CX1mB+iIG206JblA8pfCu3WCYTuBklyAEfYdciYxPeJZDZppHW7qPGw2gC8T
         VLS2X9C7nft1YLpy+MeGURaaK+gcJ8ugDGIEPWFXQzZRHSJplotz1CWIffXMUlSQ5LqW
         49dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=sDnw3wHoeWkyHvv6LNzFHMpTdO+voRZyWf/MbQEFMAo=;
        b=SXSbuvZMG7QvoVZre3XTAwoz1VXiC055JCy2qIsH0j4oNnNt9LQC5APQckMKQDa1AG
         jYcW2/+ojWahluyFBn+R5qPaq8EvcUadiQkYkaxXxtKRdVJEtA676EQQ+FASrD1gePx5
         bsWhrY2obnVA6KJ4HRT0IvEQAoFVHqvlEjrSllixKUvY7IH6TyffrgviDOf1nahFFWWG
         k4+m3lBwjc7cY3XkF/Z6xbdZrXKUSDo0GaiyDf7QYyWsUpALzAA2ZS+BSU8Fa7+guXxQ
         FcmdtnkVoMHUxdHazVNNi9rjzDPfAp4Bg7rmqTGiaxgkYs8MEwC8gXAIHDx4dMcwPdU4
         FkFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="UPvVi/ss";
       spf=pass (google.com: domain of srs0=p8tk=2t=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=P8Tk=2T=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=sDnw3wHoeWkyHvv6LNzFHMpTdO+voRZyWf/MbQEFMAo=;
        b=Ph5HY/m40GzArTQw32rPrv8l9cLgpAnFgG8CYGjVZjgkJaDXkkrquEESn7GNgtXhyP
         JS/Y7RXLzGTeDJv7hoZdVTH0GJHFECgrxzhVmrPCqj4wMgBafpsd5UL6SQVrKIBmOymp
         +5aGnug8i+WLzp3F+eW44jqssLqqLYoVNqwKbArC88KxEx2onNPLABQhJNcD5RJkwIl0
         ALaHB10Npw+ulOykD6TMNSsYLUdJAN5TAWNxpyDvdAHA2lV6qxqYfYLwHPa2N57Bb89c
         CIKv/GiAVOLmoqxdNDyiJC9Xm3PedokCPM1u6nHej269SAAci0/x9wufzur/sGzv1Q05
         8Tgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sDnw3wHoeWkyHvv6LNzFHMpTdO+voRZyWf/MbQEFMAo=;
        b=kLkGxrDmQJG4KMrWhSfVHTPqvzyqJoOcbjB0lfAyz+Wf33r77vWECN0d30QzSgaBLg
         zIfu7hRXqWI9jMqkOjXoYmGVJ1t0MqjcdhTXnu9fBXc+vM+aplca7+sOpCdcU3qj/gon
         MJIqT2YAAx0D91mNdn5wbHpsE52b2Cdn/fzV2g7K6NUv5PwrDBrB9a4vszRldcAc4O2x
         Jx73O1KdWIqtcwSOTQ1T+MzEOpSxP/zdMyr4PQBYGhARYpFST5oWiuoUN44VMgJ4gf6Z
         HIUZ2cdoi+8rxX86bw77ASXqW1oE0X+GOQ2YH21JyuBDU/LpJ69CGZv1r6ukRBsAXoi3
         JFbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3yoavlYQVLAoKcL6LHce9yoVhL2sHjmZkzd0MbBLiPPDdyB/3K
	w7g+IvHWoYFmT0tnnsiY8+I=
X-Google-Smtp-Source: AMsMyM4WW1+QkliIrTWVpslE++hW0BJGKP15Em665E8lb1YOGsXPRIqOAvYoRjrcR5zoUDEHCXUdZQ==
X-Received: by 2002:a63:942:0:b0:43c:428d:16a9 with SMTP id 63-20020a630942000000b0043c428d16a9mr3444038pgj.423.1666114937189;
        Tue, 18 Oct 2022 10:42:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a58a:b0:172:8d81:7e5b with SMTP id
 az10-20020a170902a58a00b001728d817e5bls10932551plb.6.-pod-prod-gmail; Tue, 18
 Oct 2022 10:42:16 -0700 (PDT)
X-Received: by 2002:a17:903:2447:b0:185:4165:be52 with SMTP id l7-20020a170903244700b001854165be52mr4289304pls.100.1666114936299;
        Tue, 18 Oct 2022 10:42:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666114936; cv=none;
        d=google.com; s=arc-20160816;
        b=FN1X2Ako46/SvSVPR0KRF2KVwHYOQTVtiVDqwK0ccn7Ren5ICRPLHoYXnjQr18Yfer
         zLV4Z9gPhLL9A5ty4leNRKrrrzvaIySAayxepIjN6XgPXAWLfstUgSEMs/xDzoIeGwU9
         dq07tfEElbRLPHXvCAieEYdEf1N/KIea7sbBMhMVa2oW08equjm+EmSL4OityF4MsTZW
         StH3ytEBdP+q/m4VIUl6Xu5RbUbGvlqIMtHtLHNdP9rlaVA3JUmkd+E1cqq1xy4hCrrk
         fzp0uXi1xlWKvi6je5v8fft8Xjd+dR2W/g6VazwgaOsfeiQV7tNYVlISkuj6feo8ChVi
         IDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wfBmTO96UgXI5IM20aXCho2kWYxewSrwJmlN0cACtTU=;
        b=HwzC0K5CWMdZ9fPe/Tic5eghOfOHceJlgutFLB3B7QyveuAiVGYLfc1h6s9vMSebj5
         uTzEOPPWlG0adIn4bKGOvP4pN6sAjPVEegxxWtEs++aeRNJxyqBLtVFlK83dH2eg/20U
         sAmAoNWlzpfPS/9948V0NhPTeFxrGht1woIIEtiJbvmr05NOeddIUlDKiK2wKDplZNyB
         d5qyXmhS01ptmxEBHK6Tn6JQ/VMXQCIFGXtQnUJDHLWcCBbCGPytM3A49wL+XPRmSJvt
         PX/V9bHylxLvy2VFL5YBl7aGujQpwpNKlePWoeEgR20bVfGK0BSIh+4Gll8dYTVgnOw9
         ZcYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="UPvVi/ss";
       spf=pass (google.com: domain of srs0=p8tk=2t=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=P8Tk=2T=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z19-20020a17090a541300b002025f077b2csi63196pjh.1.2022.10.18.10.42.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 10:42:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=p8tk=2t=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AEDFC616A0;
	Tue, 18 Oct 2022 17:42:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 17039C433C1;
	Tue, 18 Oct 2022 17:42:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B24285C0528; Tue, 18 Oct 2022 10:42:14 -0700 (PDT)
Date: Tue, 18 Oct 2022 10:42:14 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Ryosuke Yasuoka <ryasuoka@redhat.com>, dvyukov@google.com,
	nathan@kernel.org, ndesaulniers@google.com, trix@redhat.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] kcsan: Fix trivial typo in Kconfig help comments
Message-ID: <20221018174214.GS5600@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20221018102254.2424506-1-ryasuoka@redhat.com>
 <CANpmjNMoZ6X-bPHg3pfWrnBfP-khpwXNvHxxrwXf2R27_PuSZA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMoZ6X-bPHg3pfWrnBfP-khpwXNvHxxrwXf2R27_PuSZA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="UPvVi/ss";       spf=pass
 (google.com: domain of srs0=p8tk=2t=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=P8Tk=2T=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Oct 18, 2022 at 08:15:26AM -0700, Marco Elver wrote:
> On Tue, 18 Oct 2022 at 03:23, Ryosuke Yasuoka <ryasuoka@redhat.com> wrote:
> >
> > Fix trivial typo in Kconfig help comments in KCSAN_SKIP_WATCH and
> > KCSAN_SKIP_WATCH_RANDOMIZE
> >
> > Signed-off-by: Ryosuke Yasuoka <ryasuoka@redhat.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>

Applied, thank you both!

							Thanx, Paul

> Thanks.
> 
> > ---
> >  lib/Kconfig.kcsan | 6 +++---
> >  1 file changed, 3 insertions(+), 3 deletions(-)
> >
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 47a693c45864..375575a5a0e3 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -125,7 +125,7 @@ config KCSAN_SKIP_WATCH
> >         default 4000
> >         help
> >           The number of per-CPU memory operations to skip, before another
> > -         watchpoint is set up, i.e. one in KCSAN_WATCH_SKIP per-CPU
> > +         watchpoint is set up, i.e. one in KCSAN_SKIP_WATCH per-CPU
> >           memory operations are used to set up a watchpoint. A smaller value
> >           results in more aggressive race detection, whereas a larger value
> >           improves system performance at the cost of missing some races.
> > @@ -135,8 +135,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
> >         default y
> >         help
> >           If instruction skip count should be randomized, where the maximum is
> > -         KCSAN_WATCH_SKIP. If false, the chosen value is always
> > -         KCSAN_WATCH_SKIP.
> > +         KCSAN_SKIP_WATCH. If false, the chosen value is always
> > +         KCSAN_SKIP_WATCH.
> >
> >  config KCSAN_INTERRUPT_WATCHER
> >         bool "Interruptible watchers" if !KCSAN_STRICT
> > --
> > 2.37.3
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221018174214.GS5600%40paulmck-ThinkPad-P17-Gen-1.
