Return-Path: <kasan-dev+bncBAABB3UNZD3QKGQEEQZLC2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A12CD2053B7
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 15:43:11 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id y4sf10389393oto.15
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 06:43:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592919790; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUfXBDGD/IlvcSDHTvHBIDZbN1RTetrNVs96hpTb4NucpWEln9BoBvW7frKZUa7yGa
         Rv/imvfSkW+ITSxcpcHhJN35TI3BA00s0ZkYJj3j/hB1uVJdgq+BJcMbq8cseM7JXkL/
         Jy2uzvXqhPHfNRBABAYHa7A2mHAWCXjF1Y950eXin2EIVwcsu2tk6sA/gTtpT8UwHFdY
         80DyIw+96BonsNQLFJUPRT21+kZHJSBZm6z2z0vonvRBpqMW25oiXcS17cN3iRcKmosk
         wYCo+rTR8GdL2DOut1cRmII1iSuLOq5bOWkzT0uOzxD0IS8aJZh+SC8Tq53Q1eduR7D4
         mOJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=NPlNohNePLxFckLgIaSSjD3dYwKtWDn5toFikCb0yZY=;
        b=Bo7WujSBgS+kNCp41MXCTwhnfr4SI0Hj2m+n1OGwsjxhKeMZXVYVffihPlr9/VNa6S
         OyBWVeOc6cuC7NgtNSWQNLY25cb56/YgSjUBguMR3qmhKDHRD1zkcqFekuu8REmbO+Mp
         0biRT8Q1WV/j6WRYHHldZmWIQnyIYf5DBfpLv1uj9PyAysR4IBt1rQL7/ndh3v6yuZyQ
         Y6Bk1iKpfkFmWMpvB5vqIB9Wu38eUSlwW7apOp+ugGy/W3r92SakZmSga/QIYFyTc30h
         YP7ftAhgPOMPgJJmiBCL247RViTFIloPmPRbU16a9sbHsxxNtCWnY04/0OKpwjDJnlmT
         Tn3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qcAuHWsD;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NPlNohNePLxFckLgIaSSjD3dYwKtWDn5toFikCb0yZY=;
        b=fZbR/VgbkRA27wZrI71injlvdg9PudOcJHra+74XwCR2vJWY0OkSvwWa2LTDvFof/D
         r7srYCFqlsv3A2pfg8O7OvvkpY3EI/ocj9pkluz/ckgyprqV+0ByYSm5OtBVqhKaiONY
         FUBZYZsA/SpTL0HDdcyTv0fw+dc+xTT8iuC45cHSqT64o2jOkTviR71KC2Vjo9Wnm7W0
         ByArX9ZZSEF3RVAScxg1mG6jZv1XGB1Xg0mgcnf2uSn+5YqC7Rl0H/EfVp0CZFtGBI3/
         WCWl1lxd32rI6zJzK7sUOw0f3R1l/ewBjigF3t84FqOxXu19oE/3GViIxVWGYv6ICONr
         04GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NPlNohNePLxFckLgIaSSjD3dYwKtWDn5toFikCb0yZY=;
        b=DtYC9a5rh/dpC7FVhlYdo3F6yGlVO6q+KZ5cIEQZnvQqP2KxzJO4QuU+USq9fSM/Mt
         6bqPW2WsMsMPtR6zbtTU2Tz0INNWT7hvpxOVzzelkoA1Jue7beF+/A0Y7oT1OJ2lOwS0
         0rcYePQHJQ/mvDNunFGVkHy2ciwqNXbBNqQH4WytzWbsBAaHV1XPw/db07i1TTBv4qn9
         xurkZUZ+X+VCVI5vJxJRn4V9q5hsAIK5EX5nKAiMItqqLgEcbxdKlwWLnTSxR83HZwfT
         +9O5c2TgzbA8MmwiR/OwQFNaQtV2ZVqy0U6OBsRPK+0sjd47HYVSVcykoKyeuPL+H6d9
         JxNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tvC6ALXXB4a69CJ0YoEdIKE+RwlFCl6Pv5UiF8KLUaDOu8PPb
	RCmlT4un1kGAMg0qscPKXhA=
X-Google-Smtp-Source: ABdhPJyzXNGJ4xvmzcaExPPRnlzyC89Vz7YKThIfkYGoXkbxvPuhIFv85HHcHxUs/gL6gJH29pBSrA==
X-Received: by 2002:a4a:d219:: with SMTP id c25mr10714509oos.32.1592919790317;
        Tue, 23 Jun 2020 06:43:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d0d:: with SMTP id v13ls4408764otn.3.gmail; Tue, 23 Jun
 2020 06:43:10 -0700 (PDT)
X-Received: by 2002:a9d:2038:: with SMTP id n53mr608190ota.22.1592919790071;
        Tue, 23 Jun 2020 06:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592919790; cv=none;
        d=google.com; s=arc-20160816;
        b=WQSc3R2EcU05E49WQbo1UyDiltNwNym6G0U8NKmiRnMbHPuJ4+PhWL/n9zsdEiPFMi
         mV4vIBMAjDPP6ECUkCXsZn/q7bWqPvo2ltkgIjhEoWTenz7YyE0PVlGSXrY2pPrGyYh2
         5uQ1pAnb7S8LPPel9i3CixFs41UJV87qlijtFgDsLB2Rho8xQ2P/5u4ZsPseZfr5NuZD
         rHPWVlLrp7uGzWjYhY5eDQxQivQyqHYiHXjLkjefVNHg1Go1Z8vqpDUGMLlyEn0PMxX1
         Kz6WE7lHNmjAoEgM3Cs8edC/pxA+vkrgP0LfFDJn4l68bf2bUShdfpanNBs+Fkb28IW/
         Bndg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=jYaH5qV6XOSouH9EkRcv6eW6o/aQlJgcY7OIxPWY/B8=;
        b=zYxQVI7eUlOR0mA+eBn+TVtsw6vusV1eidRF1DFjMxsFSCaOIUjqYoisvLhwj1NqOy
         kCmR+ZZJA4k7+IQQhCFjmmtSVKJCyGGauRAD41oYj6shoGdVOodLNAvhkMViMS/OhB14
         xpzsVc/OjY5Vy6v0wPVAgqMsF7/bE2h6EL7Vat2hmzq9DnCP+8JX6b5gvqtzwKbjM/lC
         VvcBi243D0m91Q4xrtKTipSb1Gc/IsqDMaC4EHp+g7p1sJ9ZqoERt1JJ30D42q2PNHcj
         BituOty4pN30d5Ia7b19wJP2sav9HDL6JTvkgOxpt4QUIKXgzLwkzep8UhGoviMV5iuN
         Fyeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qcAuHWsD;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c22si1469399oto.3.2020.06.23.06.43.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 06:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 391BF2070E;
	Tue, 23 Jun 2020 13:43:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 1E5CE352265E; Tue, 23 Jun 2020 06:43:09 -0700 (PDT)
Date: Tue, 23 Jun 2020 06:43:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>,
	Boqun Feng <boqun.feng@gmail.com>
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
Message-ID: <20200623134309.GB9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200623004310.GA26995@paulmck-ThinkPad-P72>
 <CANpmjNOV=rGaDmvU+neSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOV=rGaDmvU+neSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=qcAuHWsD;       spf=pass
 (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jun 23, 2020 at 08:31:15AM +0200, Marco Elver wrote:
> On Tue, 23 Jun 2020 at 02:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello!
> >
> > This series provides KCSAN updates:
> >
> > 1.      Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
> >
> > 2.      x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
> >
> > 3.      Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
> >
> > 4.      Add test suite, courtesy of Marco Elver.
> >
> > 5.      locking/osq_lock: Annotate a data race in osq_lock.
> >
> > 6.      Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
> >
> > 7.      Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
> >
> > 8.      Rename test.c to selftest.c, courtesy of Marco Elver.
> >
> > 9.      Remove existing special atomic rules, courtesy of Marco Elver.
> >
> > 10.     Add jiffies test to test suite, courtesy of Marco Elver.
> 
> Do we want GCC support back for 5.9?
> 
>    https://lkml.kernel.org/r/20200618093118.247375-1-elver@google.com
> 
> I was hoping it could go into 5.9, because it makes a big difference
> in terms of usability as it provides more compiler choice. The only
> significant change for GCC support is the addition of the checking of
> (CC_IS_GCC && (....)).

Very good, I will rebase the following into the KCSAN branch for v5.9:

	3e490e3 kcsan: Re-add GCC as a supported compiler
	03296de kcsan: Simplify compiler flags
	d831090 kcsan: Disable branch tracing in core runtime

Please let me know if any other adjustments are needed.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623134309.GB9247%40paulmck-ThinkPad-P72.
