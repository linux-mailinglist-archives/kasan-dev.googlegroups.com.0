Return-Path: <kasan-dev+bncBAABBR43332AKGQEUFD7G2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 478FF1AB3E4
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Apr 2020 00:42:18 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id z8sf17299657qtu.17
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 15:42:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586990537; cv=pass;
        d=google.com; s=arc-20160816;
        b=jdDsfz8eo4Tp/n2lA908b7FHK9nbCZaIyvxECr+TF9TjgiTHeyucdt5lrP5M4UIy8S
         IKclxw8535cTJlojRl3zQQLRK/V8U4ndopMLF6NbPSki4gxO36QeCu61MR6S71COVZto
         xbTH3BANIr1ga+u8TbGzHQcxT5d6/Sf04Njh09ScTUuhEe1Cln342pxdcVq02u2tzpbZ
         n6emT7yG5DOyS3cpRHTB9Ky9/osCIQiZNPCr9jliT3a9IICO/o9pDWgmyaTAcjV2tSHC
         4bdLEpK3JjgWCaoiVi7SPodxnTkFoQi/ewLg/l16wi9dG6B/iAcWmDI3AwfzsdorDIqE
         18CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=UyhyAPfTo1KXOxcAOas1xTfAeQwgO2fiQ/dx/i7My5g=;
        b=H1ChHAb9Ae1VZmEbFowhCguWbrCY66GBrVSSc42OnoWVLlxqcT/o6JC6RmjvPGr1i4
         Kap8gxhrQ2C2suNq7L6SOPCRpRtiWDk1AEl5Uo7Hvq0VmgX/BEi5ANA1K1mKx30R1BLj
         aACcaBNxcpadd9vXWCpqwEPJVxuJCymauseuF3lMyFbShJAMpj3Ew6UTIJlWLqDDv+y7
         JP0dexxxrGZ/xKpRPLdkg/FHld4/E3RiC0POJub1mxQTRKFwXsnFlnmj5qh1CgBnaPdT
         I7vaKB9WZ9023VmSRqd2pSLKPDs+AVBIYSmFEPB2hY/bSknm//VTRgbg2DJSXDAEtGre
         zm4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=n2O6Urzf;
       spf=pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Xozv=57=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UyhyAPfTo1KXOxcAOas1xTfAeQwgO2fiQ/dx/i7My5g=;
        b=mQixdpzTwZRJ7XiJDiVelZN+Nm/ViNBtqMVOTfGMXXFSwg56IMyNAYmurdXYHVwGsF
         FzBlbY0EggHnuwYxPFGseBraNuIARjTAlXz/RVJB1cZUxyZmsxK5J1/ejaGIZuHXd/T6
         26V57XOKh6Gg5H8aNO4MH/W/oj8E5AlWbYAJlfGcwnwYdwAz0Dd/68bMhBSjgCiwQ5iM
         p+raTiVYll6Pb5z+W3EoOl9Nh+UZM8NovV+lBTkT3w9V4ALB6JPC3oqIeI8cVqMM5t+g
         tamwHb33FfqCX0kNdieremIcb0ZS3DP1hdrvPvpzYk58aZn3RmUi9E68YIQ+CAcgWsUN
         yBSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UyhyAPfTo1KXOxcAOas1xTfAeQwgO2fiQ/dx/i7My5g=;
        b=tFld0RDF3udXIiyNXSeAWqdywLQSaSRi7Ha89Jhc5J3o1mK9fyXsnguJvFNeOpKRob
         X/PW5vxkqLJthnhSKpVMPBACZ+B1EQ4pXAy3OWoP32lNrVwzbBlxgvtu4DUsUZc1+PA9
         PbRQKfZPUV40IjysQMzS7Cre092RlF34ULKomqOlms1DkoqxKrMQMVrZa5pus3zKbniA
         pXxnRe6lUhNjOZL0OGmCqQzlmhIwqpia+TCstuKPhKVSOmVcGIdowVQrGsckv3CRdRSd
         bd5Ci0sDHdhqGcY7ZyODuLUOn6I3o1V8HTRttysOSunnDeNpqF0hnjLuBwmhfJPPxWC/
         MDjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ+KIqWFDx6FK6zUF9AJZeJUZSyQJxnq8ClQPpXn0oerkR1mC4l
	7/hCt6kyFfqQSFJDieZdqk0=
X-Google-Smtp-Source: APiQypIZYmgy8BpXvc+sA6QknQppuQ8l34m+LgDnPB0gxa6jeqZbPXfD/CAQBnKdk2r9ih/woFtaBg==
X-Received: by 2002:a37:5d02:: with SMTP id r2mr25588953qkb.57.1586990535633;
        Wed, 15 Apr 2020 15:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:524:: with SMTP id x4ls2873605qvw.5.gmail; Wed, 15
 Apr 2020 15:42:15 -0700 (PDT)
X-Received: by 2002:a0c:ef12:: with SMTP id t18mr7425747qvr.9.1586990535341;
        Wed, 15 Apr 2020 15:42:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586990535; cv=none;
        d=google.com; s=arc-20160816;
        b=fKpqdr6irgBcw9qWCu+/hOGRyzWwfUmwl7tsxk5C1r5CvRLnovt7vyjveAP2+KwLSo
         zHErEAnHuiApuUmk9dWT5oMjZxMoF0gmscAJi07EsJCpWjq4YyvrIpvMGGvb5Ua+10EF
         I2a6LStaUr8RaL87H6XX6yOptirIVaKYlx/nDsvURav4Mj2aNx1uIwfYavC28aPKPFqS
         0Dgi6Q2v+ZnBVs+8I8HmWcFOB/tyE7/sksJoeko6qsCqY6zRyvW52phCrgFHwTfEsDx8
         bpq6rYLS7/EnhMmmnUYxJvJkXfo+ViLU70pvK5Msd8edMxJUOmipvMrDHNmwss8zGNT8
         eU2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KY9AFW0lAZBQodgJCrUgG1A5MJnfaqVhgfpYoyQIocA=;
        b=ZJNzYlds+yzs/q7TbUxK93qdvWy42xcLOumcfEBetMq1iBNZMLfb2Zc4MMzdsUPxsn
         2WVoSue70cuDpzl1KSBa7UJGxdC67kxtHf1EVJjh7sP5trtPx5HqRK2NElXYqSd6y1jt
         v4IjpGRFIseaHVQ844tEUW30Z39FyLZcFl38uer8o6G3O2qxFK31yz7jzwxjc25zztu/
         mAUz9w5tZi0BdvjS4sruOR1T6vN+Hw7X9NLWBOsn/NcEytL1Bmwc0LiGhi/A1HvZOq22
         5Nk19/u5Wn1dOL6M20I3BPDWJ6uzgvijPrPo+kA+CXlzVG8hhBuHsluH6d6qto2WCwHO
         BGtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=n2O6Urzf;
       spf=pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Xozv=57=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a3si601050qkb.3.2020.04.15.15.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 15:42:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 31D9020732;
	Wed, 15 Apr 2020 22:42:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 092E93522AD1; Wed, 15 Apr 2020 15:42:14 -0700 (PDT)
Date: Wed, 15 Apr 2020 15:42:14 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Message-ID: <20200415224213.GA26058@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200406133543.GB19865@paulmck-ThinkPad-P72>
 <67156109-7D79-45B7-8C09-E98D25069928@lca.pw>
 <20200406195146.GI19865@paulmck-ThinkPad-P72>
 <3B06DA7F-DCAF-4566-B72A-F088A8F0B8A9@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3B06DA7F-DCAF-4566-B72A-F088A8F0B8A9@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=n2O6Urzf;       spf=pass
 (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Xozv=57=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Apr 06, 2020 at 04:33:27PM -0400, Qian Cai wrote:
> 
> 
> > On Apr 6, 2020, at 3:51 PM, Paul E. McKenney <paulmck@kernel.org> wrote:
> > 
> > On Mon, Apr 06, 2020 at 09:45:44AM -0400, Qian Cai wrote:
> >> 
> >> 
> >>> On Apr 6, 2020, at 9:35 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> >>> 
> >>> It goes back in in seven days, after -rc1 is released.  The fact that
> >>> it was there last week was a mistake on my part, and I did eventually
> >>> get my hand slapped for it.  ;-)
> >>> 
> >>> In the meantime, if it would help, I could group the KCSAN commits
> >>> on top of those in -tip to allow you to get them with one "git pull"
> >>> command.
> >> 
> >> Testing Linux-next for a week without that commit with KCSAN is a torture, so please do that if that is not much work. Otherwise, I could manually cherry-pick the commit myself after fixing all the offsets.
> > 
> > Just to confirm, you are interested in this -rcu commit, correct?
> > 
> > 2402d0eae589 ("kcsan: Add option for verbose reporting")
> > 
> > This one and the following are directly on top of the KCSAN stack
> > that is in -tip and thus -next:
> > 
> > 48b1fc1 kcsan: Add option to allow watcher interruptions
> > 2402d0e kcsan: Add option for verbose reporting
> > 44656d3 kcsan: Add current->state to implicitly atomic accesses
> > e7b3410 kcsan: Fix a typo in a comment
> > e7325b7 kcsan: Update Documentation/dev-tools/kcsan.rst
> > 1443b8c kcsan: Update API documentation in kcsan-checks.h
> > 
> > These are on top of this -tip commit:
> > 
> > f5d2313bd3c5 ("kcsan, trace: Make KCSAN compatible with tracing")
> > 
> > You can pull them in via the kcsan-dev.2020.03.25a branch if you wish.
> 
> Great! That should be enough food for me to survive for this week.

And I just put it back.  Please accept my apologies for the delay, but
the branching process fought a bit harder than usual.  I probably missed
today's -next, but hopefully tomorrow!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415224213.GA26058%40paulmck-ThinkPad-P72.
