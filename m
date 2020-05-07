Return-Path: <kasan-dev+bncBAABBXNL2L2QKGQELNHGOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id DD8201C9EFA
	for <lists+kasan-dev@lfdr.de>; Fri,  8 May 2020 01:12:30 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d35sf8661143qtc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 16:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588893149; cv=pass;
        d=google.com; s=arc-20160816;
        b=xA+yb1v+54D1Ovy6ZVxoT5Ol9kp41ujy5efx4xQxiIdl5Ii2lMzADorf99MH+aie2m
         DWDTDVst8uJ3cqnnPUfwChMsip80YBTNyWY67uAchBaROwOu1exrMBEO3T1YOqkmT7d9
         dn61c85Xp8+k8HcyVusxdq6kEu30RhkEmVLJZNNPjDKCMeOeVNt2/94Ya0zpVFoFr3gB
         0uNZ1J3wrAgRMQDViDPjjTaRowmyJyVH18eD6FJBVqsVjaGVoxm5f8kU+w4fU1BWquiD
         NY5m4zBMv1yTcZiLxhf+rjEwhufpxAfD+eLbnnxlaWWlbtUWAzJrVcWVWWnxByQLHv9F
         R57Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BpObWi+7dmWVPRpwFzEk9q8SKInMokaCtAbYFRMpdvA=;
        b=JxWoERibodajYXn2IwaQ/CSiPvSu0Kx6yIYaePLWJXRElD8P0BNWNrPCJcPeW2I1p5
         jcrzuDM58SQp4Mwqq2utESB7YFGGXyonacV/MMKHGsQMmQzGU0CSkGT+rR+sDKwvA+1U
         7y6le7hw4pby4kb0LbC8rCkqe8H0hE6rWcRQ8NuNz0qO21Bc9hNEn0VV1wm/Ic9xkw6l
         wM/vUkDm9loGHVUdtndAZloTOXnfGf/ZcBR4NK0R8HGdO18Cg1L7xEJyiR8t7dZBLK9c
         a9uP7OHrIeq+LCQHjCpZeoenSwVGPKiMMwHK9Ak1D+3lrGLJJjfaYP7FDYnWP4YyRwZT
         AwyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TZs79MWz;
       spf=pass (google.com: domain of srs0=3tp+=6v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3Tp+=6V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BpObWi+7dmWVPRpwFzEk9q8SKInMokaCtAbYFRMpdvA=;
        b=Ba6U+cfQVNgZVBw+I3Mh+6cWu1Lyxul16YnKjR6TpWZCWWJWaiCLvJ/hpIsQB1Fxmc
         HkHuqmDacwoCOp/l5uGbnI/LnsAvNwdl8/xgUtZ5GF9+TjpistuNp482kep/g7U0CgYG
         srX4ifwsAIp9fmJVpLFaZr/KaUwNISjFsOinjX9YKhokwRvrC2/vjW9ResFkkc23gFsN
         1kNIdN1iYcdcqa0eEnf3FRkJeRNWMjRa+3NnxrX8Izq3V8TUqzEzqSVMffAZ6mjjXvYb
         4D/a4aue1tmmr9X++Y7I5z6tD1sBtMS59cZ/ITAUafncqTieTvX2BjbUkjAjbo36TrJG
         BrQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BpObWi+7dmWVPRpwFzEk9q8SKInMokaCtAbYFRMpdvA=;
        b=MVluFblAWOKw2Ec0mJlPVgXDC/+m8fvEff2Mu3aD6GNlcy81sDX8M5p05qLWnzqAIf
         WXU1H5/TO4K9LnYy2CwCrwvWjP/HM4OpQnXe48hG57YNfeoig5e4I6DRN/vRbDd1+1Hu
         TqSWseqBnCV9HUFpSVAejfwebhtWmU/f1NZhmAZl3AH4LvOK9w3r18P5zezmrSTZmkEW
         5LRCr6djbNDQ9dEsDmoA/HcB+AEYs/jRkD8l+gySORtfrNJ3ebHLR8SBmAdJWopJUZP+
         zpWbWoXUDe+BowjzGgMAo7SLVxilYOoUj9IIn7jEItowLmcqp7+66sb2/kPUlVg/djWD
         DXew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pubx/umswCHz8j3dhVJjUq+hyHxJ6ByR/eTDABlAMYI0y5Z4p8+o
	X4Wic/UVCoVFihPtsVrMy8s=
X-Google-Smtp-Source: APiQypJRtqMa7pmRofspKB1qf9nOHUurWk5j2nI8e7FxyArUcaNT0APEJcgrzD/3UDdUNzr6oB7mig==
X-Received: by 2002:a05:620a:692:: with SMTP id f18mr17397995qkh.130.1588893149206;
        Thu, 07 May 2020 16:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:609:: with SMTP id z9ls3579233qvw.5.gmail; Thu, 07
 May 2020 16:12:28 -0700 (PDT)
X-Received: by 2002:a0c:eb09:: with SMTP id j9mr16261532qvp.196.1588893148872;
        Thu, 07 May 2020 16:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588893148; cv=none;
        d=google.com; s=arc-20160816;
        b=zPPAnbLnPpM0ydpr55QpucunA91CjS9IA4XxY43qf+gWczMnOFUDwlOJCmsF/XkeL7
         uei903TgTBy1yEJS36qBujzKKo/ZrUoa+Zxc5OjcubEnbzRTcKSAuExVUuADyEWcbfrI
         z+2V95z4X27OGAFhw54R+FHKJBEwIQxzqKd8C1Md4RXJNFmq76kwM7aQ8jUOmNpqLj0n
         a6ZXgYqz2yK0zx5HmGH47cJtmXccduogz8Ss9l2DVstfm8KO3mjG2iS3xQ9gmyll1Mhi
         4RTKLQHXWw2Q9vH7IGLRmcn3JL+Kdc5Gdj3e77S8bxjCtmRKQq64oNy+h//EO7DPrgFk
         /sUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RZt5wVLNU5cdIPMlEjk+3/ha30jMgPyaf9V2hdafcSs=;
        b=dgvAz5ITu9Mc2BjIDe5bAz/A1eAuRuK7W260wQ5r6euCCKWnR7BUoIYCl2WoaCYts9
         ENl0oPewG5bYp3w9eU+vroFTA8fsnIG1Q4JxyHZz/cWsLvqcI0A1UsUVyq08qZrVFcoK
         cg5NsBdPjLqNfNi2rSBVhdK2ltXQvsHqBGKXPH6riM5Rb16+K72VFlv//CN/fganyCCq
         662kg5Vo4xdf7vyB5ujWExup4bj30JuTS1c8e2gOTh/zBq5vp7X2+2OfNOrgSib0iKD4
         zqIU3jp3KdFKm4QJFXoF9aokI8cMw4duKCudI9wGfSNOBzrCgQDkXneE9vhcXXqtYyg1
         DQuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TZs79MWz;
       spf=pass (google.com: domain of srs0=3tp+=6v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3Tp+=6V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u20si738858qka.2.2020.05.07.16.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 May 2020 16:12:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=3tp+=6v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B61BF208D6;
	Thu,  7 May 2020 23:12:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9B55E35233B2; Thu,  7 May 2020 16:12:27 -0700 (PDT)
Date: Thu, 7 May 2020 16:12:27 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org, tglx@linutronix.de
Cc: kasan-dev@googlegroups.com, elver@google.com,
	linux-kernel@vger.kernel.org, hqjagain@gmail.com,
	weiyongjun1@huawei.com
Subject: [GIT PULL kcsan] KCSAN commits for v5.8
Message-ID: <20200507231227.GA12010@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=TZs79MWz;       spf=pass
 (google.com: domain of srs0=3tp+=6v=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3Tp+=6V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Hello!

This pull request contains KCSAN updates for v5.8.  These have been
subject to LKML review:

https://lore.kernel.org/lkml/20200415183343.GA12265@paulmck-ThinkPad-P72
https://lore.kernel.org/lkml/20200417025837.49780-1-weiyongjun1@huawei.com
https://lore.kernel.org/lkml/20200401101714.44781-1-elver@google.com
https://lore.kernel.org/lkml/20200424154730.190041-1-elver@google.com
https://lore.kernel.org/lkml/20200424154730.190041-2-elver@google.com

All of these have also been subjected to the kbuild test robot and
-next testing.  The following changes since commit f5d2313bd3c5:

  kcsan, trace: Make KCSAN compatible with tracing (2020-03-21 09:44:41 +0100)

are available in the git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan-for-tip

for you to fetch changes up to 50a19ad4b1ec531eb550183cb5d4ab9f25a56bf8:

  objtool, kcsan: Add kcsan_disable_current() and kcsan_enable_current_nowarn() (2020-05-06 13:47:06 -0700)

----------------------------------------------------------------
Ingo Molnar (1):
      Improve KCSAN documentation a bit

Marco Elver (17):
      kcsan: Add option to allow watcher interruptions
      kcsan: Add option for verbose reporting
      kcsan: Add current->state to implicitly atomic accesses
      kcsan: Update Documentation/dev-tools/kcsan.rst
      kcsan: Update API documentation in kcsan-checks.h
      kcsan: Introduce report access_info and other_info
      kcsan: Avoid blocking producers in prepare_report()
      kcsan: Add support for scoped accesses
      objtool, kcsan: Add explicit check functions to uaccess whitelist
      kcsan: Introduce scoped ASSERT_EXCLUSIVE macros
      kcsan: Move kcsan_{disable,enable}_current() to kcsan-checks.h
      kcsan: Change data_race() to no longer require marking racing accesses
      kcsan: Fix function matching in report
      kcsan: Make reporting aware of KCSAN tests
      checkpatch: Warn about data_race() without comment
      kcsan: Add __kcsan_{enable,disable}_current() variants
      objtool, kcsan: Add kcsan_disable_current() and kcsan_enable_current_nowarn()

Qiujun Huang (1):
      kcsan: Fix a typo in a comment

Wei Yongjun (1):
      kcsan: Use GFP_ATOMIC under spin lock

 Documentation/dev-tools/kcsan.rst | 228 ++++++++++++-------
 include/linux/compiler.h          |   4 +-
 include/linux/kcsan-checks.h      | 261 ++++++++++++++++++----
 include/linux/kcsan.h             |  19 +-
 init/init_task.c                  |   1 +
 kernel/kcsan/atomic.h             |  21 +-
 kernel/kcsan/core.c               | 183 ++++++++++-----
 kernel/kcsan/debugfs.c            |  47 +++-
 kernel/kcsan/kcsan.h              |   8 +-
 kernel/kcsan/report.c             | 455 ++++++++++++++++++++++++--------------
 lib/Kconfig.kcsan                 |  39 +++-
 scripts/checkpatch.pl             |   8 +
 tools/objtool/check.c             |   4 +
 13 files changed, 880 insertions(+), 398 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507231227.GA12010%40paulmck-ThinkPad-P72.
