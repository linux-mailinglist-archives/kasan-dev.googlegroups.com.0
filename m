Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGEATOCQMGQEYTBOO6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 47D4D38B7FA
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 22:01:30 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id g21-20020aa787550000b02902db9841d2a1sf8461537pfo.15
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 13:01:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621540889; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPlV+J6GNbSmQRRatblS9xC89QncqShU63SnbcfUcFfwESnCv7FmRRG5lJsTTc5JG4
         e75jdQPksk1q24TvZu+XzTgqztoCTkf6LQlXL/kjFqaep1B1+LxnmC+oU6G7B2o+JYt0
         sjjWTIwr3TjEpxuAcWwkO7GZLtDMzLN30PW1P1ewHLPThuDkTO/h1+xF4X3dwF86jDJt
         ua3dEVctBGFLS259pVuY6TCdXDoHNGiX8l3LZkyhHXRcEbKcVqEx3LT2afopc11broaS
         DHGARoIpSN9Yd1PLzwAI8d7oduwB8umnmOC3el2vykybAIarytrI0GdrqRkEoKLLznwf
         OdCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=9WisBKzI0akfs8wtZO0hvjAz6z+Tn2pCxuwUZlHDuok=;
        b=oQhuVRMqnShbIMmtZYDtfDf+O1wrBtR0zzCY2kpiGji50LaDVgrjlCBD8nHtqjLQf6
         7/wwXyP0CBaV+MWGkopXn+96Wq5gpeCGvMHTsA7VMiK/lCrQjAff9248rWKEMJxDLZ9y
         5/5adLdAbnaf3MjgNw1hT36X6oZQFhdsbHtQgW9yee4zsafpHwPhGxcur8GAgSfJ1Dg4
         ZZfJnne63MuG3OuECI8vU0hqc0jI4od2+YhRG4hDwwASP9nYRg67zXHJ0bUvQkytJd7x
         evtx/6SqY+UwCTnywYWb6cBLNeMPh9tpd6FH2yQ6/AkYJca0neOPHyYIQ/4qimchKhKX
         pVSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sJlqMCiv;
       spf=pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9WisBKzI0akfs8wtZO0hvjAz6z+Tn2pCxuwUZlHDuok=;
        b=ahmDQcs0dUSG7gMDMN9lSEFtlSlsAnpFmxTAC/7Ya00bR9kg1n1t7r30bMzYAtoMVD
         dcjnw7VuNTTJRBdYquNdndMG3OEf2OwoSVBL/ZGoCT8Ox99w6V1jII49ZAbLn4I5AWms
         sgL0aMsbOvk5JuykcrpIWtyJp17RUQWN1gec717oGXH7D3/4DOFCiR5TgUnzW9OVjXCN
         xIIzkNrKS6TgBLZxTlZbgwhjqodnGjiSA+6B1nbqA/dOvvMyrjICZCie1txeHFOdBz8p
         KAdCyPh11JiTWK8/DWaZDTKlKX7LfVaHVHI+ofcvyEaZNdzwUY6t/APNcGEthqqXX2SE
         KDTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9WisBKzI0akfs8wtZO0hvjAz6z+Tn2pCxuwUZlHDuok=;
        b=h7GHN1zceDdL5uiOAHiX9sfYIxTB3r3OytXVtg2O9+7XUv4mRtzs8xMjGaifBs2t62
         2x24SFdB5KFgdxFsAevqcfc+1zDteqrtWvUAsCJHr9XLqU+pQheTDAReah7mp/OaAbhI
         7m6R9WmXwZ1aG4SsA1BUgLBEyJXI6HNfzILKO21pTLEFmMqsm/oc/+3Po2F128QIghnQ
         dsVUues6iyS4/FQXXMMNKscfzgTF+Mtg3B4uXX6LOXegXjqhGkaNqEU115OBweG9dpUB
         nWLLU68/WMV9arvcO2aT51JuoJNGzD8p7Hd1Zrh0cA7MJk7hWRCkDB54+ymGxXMwqfxl
         y3ow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lhmSRqdLlxJiGVPgoRNo0M9qfmHITx5JORHGNhrjETg+wMo7S
	WVDS3VPHzzyejq6AiJsjPnY=
X-Google-Smtp-Source: ABdhPJxbnmJpQ1AmnEN7PUImbxg2JCnaCyWFfmB3CnpQraAKeDWA0hf+HW/OKDSesXw/vM9rlxMAMw==
X-Received: by 2002:a63:e952:: with SMTP id q18mr6127154pgj.430.1621540888956;
        Thu, 20 May 2021 13:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa8d:: with SMTP id d13ls2540717plr.5.gmail; Thu, 20
 May 2021 13:01:28 -0700 (PDT)
X-Received: by 2002:a17:90a:6c97:: with SMTP id y23mr6783459pjj.174.1621540888411;
        Thu, 20 May 2021 13:01:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621540888; cv=none;
        d=google.com; s=arc-20160816;
        b=na5TqIkYQkcPde06771WI02oKDQ289HjThYT6jydHDB5FDK8GwncjQCu+ZsqCvLr32
         tIaF+HweAjFzCt5yFDwO7oGK8jwuS5xl7H6ljK+ggy2NXOZHvQdCv8z+syqo/tBGB1Rx
         rWb9BtO06uAad8Cb5wkfyHB/ISlHaMMItnIfBDRQavX/2Rlsjr2Sn8j3hYuv8zH7ewQ0
         z238IxG2IRcwoT6o7xbl+m9iphbc5kVo/3GCRoYyCb2uQIXbFX+7dFlhtAggzg7wowbA
         6RgBWKhbI6EHp9FqNZrA9I9pqLzYTTl05FarPplld0CbVeFwG2kERebiiIF5x1CbYucd
         pbkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=74kEfEU0RWrz9pNXwPIZEzsW2p4mFxx4fjJsCNJM4gk=;
        b=OzO4OMJf+qrSAsPqKXMxABGFYlKzk+Bmcfb3YzuIlsNBzJ+yspUbwO/0610knkXu8F
         EIo9qmnUhwwbNg2y42htaqdEDGy8aebG5t3i0ovbtD27sO1BHnBTTAMqNbCYtIcTB15p
         DCyASSf1D/igAjk/HmVmtcLZlqSwNuA0s4dH8052USZpCwF4o+8t84JOazkWLhHr74Gm
         vZUcPrdWPudnqosDasyhZhxvxoZ5lQnLzjtLNWl6iIV+JEcsO16N6qkm/W2sNNK8qutC
         qAQKtY9BZ7HoSfK5mWZG7OUEot4rh1aCFS5dJdNOrOSzIysgi1GxEvNfqfa3J5mbKZ90
         SpnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sJlqMCiv;
       spf=pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si358082pfv.6.2021.05.20.13.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 May 2021 13:01:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 231E3611ED;
	Thu, 20 May 2021 20:01:28 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id DDF5C5C0343; Thu, 20 May 2021 13:01:27 -0700 (PDT)
Date: Thu, 20 May 2021 13:01:27 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, tglx@linutronix.de,
	elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com,
	gregkh@linuxfoundation.org, nathan@kernel.org, ojeda@kernel.org,
	arnd@arndb.de
Subject: [GIT PULL] kcsan: Fix debugfs initcall return type
Message-ID: <20210520200127.GA2227122@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sJlqMCiv;       spf=pass
 (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Linus,

This pull request provides a fix for a regression introduced in the v5.13
merge window by commit e36299efe7d7 ("kcsan, debugfs: Move debugfs file
creation out of early init").  The regression is not easy to trigger,
requiring a KCSAN build using clang with CONFIG_LTO_CLANG=y.  The fix
simply makes the kcsan_debugfs_init() function's type initcall-compatible.
This fix has been posted to the relevant mailing lists:

https://lore.kernel.org/lkml/20210514140015.2944744-1-arnd@kernel.org/

It has also been exposed to -next testing and has been subject to more
than the usual number of reviews.

The following changes since commit 6efb943b8616ec53a5e444193dccf1af9ad627b5:

  Linux 5.13-rc1 (2021-05-09 14:17:44 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git urgent.2021.05.20a

for you to fetch changes up to 976aac5f882989e4f6c1b3a7224819bf0e801c6a:

  kcsan: Fix debugfs initcall return type (2021-05-18 10:58:02 -0700)

----------------------------------------------------------------
Arnd Bergmann (1):
      kcsan: Fix debugfs initcall return type

 kernel/kcsan/debugfs.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210520200127.GA2227122%40paulmck-ThinkPad-P17-Gen-1.
