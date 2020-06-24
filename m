Return-Path: <kasan-dev+bncBAABBTWGZ33QKGQELJNEVSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 325AD207BEB
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 21:02:39 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id d64sf2142497iof.12
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 12:02:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593025358; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/fp4SwSw3YGV6+/hyBJ48SgoIwmEKAUxHCjxAe9UOhUZ7WH6mMn8QnNstNm4iS999
         0Fenz6io4cN35E7fIxXz/BNy8eRv7ysGQipjbu35z6sXG3U9OFY4LbtT7J2Pkem0DK1U
         QT5Y/G97f+jr6Y8PhDUZRJfwYlCf8wQbUvTJI+aDRM53PyDl0sDBq9blkRYV83nqygyM
         +4TnL8M/iwoVsZNw/tGNgXVB96BtD7xLpjQIiISNuar/l5S7hVM7NNYLDfqU2h7eyLd3
         9g8UqJrcfgkwkBgBV9h0agRHo3Mpbt2pk6WomFAwhEQ3xFzH1HtCchRPQ4Lm4gaBm5ud
         dgag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=6jab0/VmCr04DUiJ2r1nbLJtCkAnf+5CZGT8wMrP9e0=;
        b=mT3DP922B018vImG8/EOpJtY4W/TrBcDqqbhk6mjlbUWjpSvtLiluJ+Uf8Ts1/cYjR
         eFBctDCf6Cb/llztD9EeW1+qsvueGcyuCnxMwxgJooEUAhtgArfBC44VqEnqFeIXT/ga
         /iweCIrnUeWJN8pUEODXzdk1P38YgSsHjTUnO8xzzTtjISP14xDb9+g13XbR8UUFwYj4
         IE8KzMlssyPTfXKVo1elHfAhV5U2/hbDS94/F4oPObo0E8xbAtO2oSLOd5Vr0tAKMCGk
         DKlGb2MWErX3+OXBo7UxCqxwZRATpjU7bqgLbERMTgFhf+lu/YChwH9IwHqF3/Eu8CYV
         i0BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KczMdtn4;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jab0/VmCr04DUiJ2r1nbLJtCkAnf+5CZGT8wMrP9e0=;
        b=ea+CbORiWZYkIuSDGnfDcLgRKB+6zssL9ntkKi6ci7mIhJWwOZA3i56E9hsMXDtAg1
         w33ozlZ9qwLa1ynr2PIs3A7X7PEhImHrcTdKkqw6peCb5oaumJBkrdLqjKR4xzBYuNpG
         JOxxclTVQxG3XJ3ClEMGxTfKgt2NOsWiQAczVouYvolQ2+tisF+IQ6ey+HAp6ZQIUbQY
         qC2F4R7jx48EvftdqWVokIPRBvA2x017ogUgvVGLdQJQbqyQFu8lZ/Gv1+ytiNjIwiiR
         C83atn7pQjigwRaEzUoDnq/bnXoRAyoMeK5ACIgV/xZUFq9LgQqDbmD4lBan49vPYNwP
         +72g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jab0/VmCr04DUiJ2r1nbLJtCkAnf+5CZGT8wMrP9e0=;
        b=L8xQSKf/Te5EKg7yoM8iaFJpNaUsXMhZgXp/7SADfwtxtdzt1+ZMm6LaOYpXMfX4Li
         So7sJiQ0yM3jrXFMpCHLieESWPeojmpv8n6H2sCK/n2Z6WqffbDIZywv6MSVebXYaxku
         CfX2vPRia51GKIaoZIX7Djdz95BZt6tgk5CSxRbVtFZ0Fz3uReyr76b92Y8wa6Y7TCto
         mcxapOGLD8N103IUPAXnhD+PjDO6jQ0S7G1YJfvqYDBA65yTQlZraQp0UbmQrQzCr5mZ
         xV63LptkDhvr/paygvEMyzqsotWpUFPel1OEMiRxlY2I8W2EOhXtTaS3ZjOIzcOx1hkB
         TIgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533qo5DFFmGwf0SnBMvk8o3x4aL0pmvCOaR4qEA3wIUSCqjuAIB+
	a9dqoPsHDTHkQ5F2hJfvz1E=
X-Google-Smtp-Source: ABdhPJzC1wRnhJR6PKgKlILZKMRHXFaboScNtJJAZEUosRCvxU3ThuNJd4J8UpEAyjZXBhrRdfcTtA==
X-Received: by 2002:a92:10a:: with SMTP id 10mr11343560ilb.172.1593025358121;
        Wed, 24 Jun 2020 12:02:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7f13:: with SMTP id r19ls123268jac.6.gmail; Wed, 24 Jun
 2020 12:02:37 -0700 (PDT)
X-Received: by 2002:a05:6638:a1a:: with SMTP id 26mr24594659jan.67.1593025357794;
        Wed, 24 Jun 2020 12:02:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593025357; cv=none;
        d=google.com; s=arc-20160816;
        b=PSX5BRkL7uMvQTUAkvCjIGKG4pa9No2IkV8gceAVucW6ZkX1yB0dHGAqPyaacS3UlH
         rcBLm0Lm4nerQgIsgm/urrXVH5VhRzaEAl+7/gCdhIPkQ8D3cOn87lP6xBkyGoDiCMnA
         QtXi8PzjMgzvftLvXsdS4KtqSCKeoU4ujKb7ktLs8xvHCc4Y9RRN7JG4KB3NiiHwttZD
         WoOGcIcw6HzrGKd0sZ5jfLeKIPMEZkLbfClviO2RFm0mh/BOQ8q0/jOvPXzVf0ZKeaRM
         8ufWa5ubctQLv8rJTdo7NJ4HXCuUTV3xRjheZJdXgH+Uup72t5v7Mi/cgjIhjnfX2oY9
         n3cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+qu3127tBFmVhMr8gXTwXyQA9QxtlJANdX5EyJVMX+4=;
        b=qPlffDkcU9RSEuFZPisFrAAfhWCs3W0EQRDoiyRiEfcJGv5uDYfzCTMxPJv9TZT/Rh
         svwaVW3tozWyzbtd26Eu3ibVYzlXKomNKrv2PuGcBv24ewbvLwtGCFlxVGWwP4YWJ03N
         YQqdQUAHzJxn10PL6vkBI7GJjIeSuGOvU/9bcbw070aL1h8JVB6yvzb390/y7zpvK5Qc
         KqFjSnn1lk4fN5vopnRN1RiddDv+zNWmKK05ELbGzZvdA2BZdmXsfo8NfLDmuGxYO0CR
         YNcEA87/YRmxbAaxLikClhaaVfuY68ofm/FnlXV9S3DdsFbv9ABx2gG2c5QsdYj/5VJQ
         V5qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KczMdtn4;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r8si714864ilg.1.2020.06.24.12.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 12:02:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id EA4F52082F;
	Wed, 24 Jun 2020 19:02:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id C04CF35228BC; Wed, 24 Jun 2020 12:02:36 -0700 (PDT)
Date: Wed, 24 Jun 2020 12:02:36 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
Message-ID: <20200624190236.GA6603@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200623004310.GA26995@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200623004310.GA26995@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=KczMdtn4;       spf=pass
 (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Jun 22, 2020 at 05:43:10PM -0700, Paul E. McKenney wrote:
> Hello!
> 
> This series provides KCSAN updates:

And three more, so that GCC can join Clang in the KCSAN fun.

> 1.	Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
> 
> 2.	x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
> 
> 3.	Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
> 
> 4.	Add test suite, courtesy of Marco Elver.
> 
> 5.	locking/osq_lock: Annotate a data race in osq_lock.
> 
> 6.	Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
> 
> 7.	Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
> 
> 8.	Rename test.c to selftest.c, courtesy of Marco Elver.
> 
> 9.	Remove existing special atomic rules, courtesy of Marco Elver.
> 
> 10.	Add jiffies test to test suite, courtesy of Marco Elver.

11.	Re-add GCC as a supported compiler.

12.	Simplify compiler flags.

13.	Disable branch tracing in core runtime.

Please note that using GCC for KCSAN requires building your own compiler
from recent mainline.

							Thanx, Paul

------------------------------------------------------------------------
The added three (#11-#13) only:
------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst |    3 ++-
 kernel/kcsan/Makefile             |    6 +++---
 lib/Kconfig.kcsan                 |    3 ++-
 scripts/Makefile.kcsan            |    2 +-
 4 files changed, 8 insertions(+), 6 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624190236.GA6603%40paulmck-ThinkPad-P72.
