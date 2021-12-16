Return-Path: <kasan-dev+bncBCS4VDMYRUNBBWVE56GQMGQERFZEN7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D1CD478105
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 00:57:15 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id z16-20020a056830129000b0055c7b3ceaf5sf327860otp.8
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 15:57:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639699034; cv=pass;
        d=google.com; s=arc-20160816;
        b=VHeuQ4e7wuCRdoK4EMxmCRFcYQ9O25s0yS5VKNxu4TLWxNGGnXvn4epLCcMhoGTcfQ
         iXzQPJEkumzwTgorH3JLr9oDVXqaNGdM3W3JMm2q83uAN023kaR7yCVSkeUfnUZMx2pV
         2km2yJyMsSmuNwDEc+WAq9m3U3STz/GOZiyFcZrn5aqpfIcxtxXc07OH191gpnoiQ3xn
         /QDfjyxfPXIseMDxAjirFXho1caFESJ0cv/uPbMLB3Uf27kJ9oZAXnC6JUspxzeV7bN9
         J6D6+wL0k3X75G0tjHTOr+nPkFYZahoFsPO69qCaty19T+mx5tJ6laCjedDMAdxuJMXE
         cYiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=MhY0txoKFevZJFQn6PTB4TPI/kFKoxKpeQB39HmEMsM=;
        b=W0Y/KhP2kgBzLa4PDGAM4Uzmwx0IbeY+zqWrg0nuBRMtwd0pMAHMQqDBJfhmxhXcbg
         4ytf1psz1IjOWO1qxxUSm05gWdXlvZfbWBNA7OFwrUek1l9Nnig32NsJSESbpSNA+Ai/
         LvMF47X+2vueEW6ozhFP4f8gwqEA3gN0gk2/yHs4md8TZr0iwQ6tEwH3n/Q6GeUyeP4W
         QveQFRSDmcMoihQaWbXAE+rUaRMf8GjJIYwshFMSGOLDwMymFavisazInruUGIVe6pML
         RbnAxBSykygsawS8kpGI2+O6m7ZX8bjcGXZn1v7TKOxzMIjkFSuo9fzWrHuP4ZNrrWwo
         K8Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dei2kj6q;
       spf=pass (google.com: domain of srs0=zdho=rb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=ZDHo=RB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MhY0txoKFevZJFQn6PTB4TPI/kFKoxKpeQB39HmEMsM=;
        b=XyxOJfAefQYoZEfovFvd5ZNLJXRAguuPCBNl+Df9s029Tl8H+tHh3FtKxpACsIGAQa
         b47ZdkaNJQyco8zrljA8+dPexSCV+h+k1bXuG+DVrYS7ddS7Ng/JWLJPB2U2cbIg69Ja
         P/IOA1nJFlXGn0O1ievDzFiBpWiHkjmig8rMeIpp2GPX1JQx/X2V3+xZMaZVv/0GduRi
         +Yt6PYW7l2F1lsEbr4vI6vLDDsFn4Uje0p/s6cxWeE0SG74XCRH3+CjzmBv7WKeb7tH0
         VSeAUs3f9oj6HdQJDMElf2cgPo8CAZqBcL/8/M9CHDnnEMv4oG4hLCk73+rUcwnCK1oT
         sbTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MhY0txoKFevZJFQn6PTB4TPI/kFKoxKpeQB39HmEMsM=;
        b=t8eCnbhpVf/Zu8dr99YE7ECq+fIWhdWRiusKf/kup4UYgcKi2DDl1KaGQjwLoCP6Nt
         E9DH9+uAOfCuU2TYt/3NfkoNrROrrYMejgNMzEKDA8PViIE1Y5JVzwAqU8cXfraiFISO
         Z+wwTtTdapgqvhj5sW2m7O21oQjn2dHhfx4du/EPM+iAzh+8n2tmIUX+6LhkRCtATY2l
         miK95ZvmNI+l+ECNFZRhjz+xi+lgA7aXP7yu3A+mco2OJ6Yu/QN2p4XHmqyoWdExThQ0
         M6hD7hEwMhEQZrOZFh434tSVV9rSXvzRs2CtblRaUnWicdSS+DLDFEINj4/tEaxGYin6
         0fdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+NdlgnPCyxijJFndH//lmJi3XeLGhY1jUjcWYCEyvVSQeZEby
	ypTyfQJeWPJkecpohcwqBaU=
X-Google-Smtp-Source: ABdhPJxNs0v/DnjW+Lclxz3q9bx03+XLWyV28HrX8Im9vb4DqmOjWMpky2wtT3tK/Gi9Px2FA/pwnA==
X-Received: by 2002:aca:44c1:: with SMTP id r184mr5870740oia.15.1639699034295;
        Thu, 16 Dec 2021 15:57:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:90c:: with SMTP id v12ls1686519ott.2.gmail; Thu, 16
 Dec 2021 15:57:13 -0800 (PST)
X-Received: by 2002:a9d:5604:: with SMTP id e4mr376198oti.249.1639699033910;
        Thu, 16 Dec 2021 15:57:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639699033; cv=none;
        d=google.com; s=arc-20160816;
        b=AmFlWSmeJBNKyDL21vr80UPyDtQsn3Rg0k98KB58jlFAqgMRPzZIBmbWJxa0TBrexI
         wcQ8ht5KU4CRmCWDX2Y9xVBjRQwm1ydlXonO37BzyYW0rbJF6gZ9bCB11rX7GeC6Rqo9
         lxX0vmNP7ZRd3GB2b/MkMkdaLfTIZiocyP1baXE8tYZBihRs75qY5HdkRrcM+JTmJFHp
         v88WmWFuy8L+43RZ865JbMw2Cnh2CRXviu32YRjiL3fQ6qp0PAmLOUV0MaEiMq2nPxwH
         fd5BlRGwzpHzBPLqn0PozQ6eHutOeakn2h+AkRqDdopIKyl6/agLoz0wy9GIut4rU4I5
         MFXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=9rgTWgkKanrZHPv2JUoTzCaQMI1uO8dDC8haYlNBF94=;
        b=NhEdGLid3lElromQdKxdCY/tHLvOgD2xRlDDqbtLA+zUIo6XXXbg/juXS3e/xLseUB
         LHM1jzYBo56JN0rw8nUpVB0y1KFGqYD1GlXeKXtTJ9uOogCg/bu47PcqV21bWAHKg1MO
         3YVP3Fcah3xkWTHvwCpg/XWab875mS+zU9lAiTOMaAE8bNxSa5v4BtY95N+3+cw1NLA1
         jIKew+hqhZInB5gslelslablClVgWnXya3PcIdoxk3sUBurxTIhDnr76HB17TIBy+NqW
         xvMlXdZGYLU852cHkLgvOpyt76ozGfHD10JTJLRIignW/a6j40++eEGcDB2Z4KJm8YmJ
         B17w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dei2kj6q;
       spf=pass (google.com: domain of srs0=zdho=rb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=ZDHo=RB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s16si432127oiw.4.2021.12.16.15.57.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Dec 2021 15:57:13 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zdho=rb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9882061FBF;
	Thu, 16 Dec 2021 23:57:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 07FB5C36AE7;
	Thu, 16 Dec 2021 23:57:13 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B3B995C0556; Thu, 16 Dec 2021 15:57:12 -0800 (PST)
Date: Thu, 16 Dec 2021 15:57:12 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: peterz@infradead.org, tglx@linutronix.de, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-team@fb.com, elver@google.com,
	glider@google.com
Subject: [GIT PULL kcsan] KCSAN commits for v5.17
Message-ID: <20211216235712.GA2991567@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dei2kj6q;       spf=pass
 (google.com: domain of srs0=zdho=rb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=ZDHo=RB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Ingo,

This pull request contains updates for the Kernel concurrency sanitizer
(KCSAN).  Perhaps the most notable addition is added support for weak
memory ordering, as described here: https://lwn.net/Articles/877200/

These updats have been posted on LKML:

https://lore.kernel.org/all/20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1/

These changes are based on v5.16-rc1, have been exposed to -next and to
kbuild test robot, and are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan

for you to fetch changes up to b473a3891c46393e9c4ccb4e3197d7fb259c7100:

  kcsan: Only test clear_bit_unlock_is_negative_byte if arch defines it (2021-12-09 16:42:29 -0800)

If I don't hear from you by Friday of the week prior to the merge window
opening, I will assume that you would prefer that I push this directly
to Linus.

Have a great holiday season!

----------------------------------------------------------------
Alexander Potapenko (1):
      compiler_attributes.h: Add __disable_sanitizer_instrumentation

Marco Elver (28):
      kcsan: Refactor reading of instrumented memory
      kcsan: Remove redundant zero-initialization of globals
      kcsan: Avoid checking scoped accesses from nested contexts
      kcsan: Add core support for a subset of weak memory modeling
      kcsan: Add core memory barrier instrumentation functions
      kcsan, kbuild: Add option for barrier instrumentation only
      kcsan: Call scoped accesses reordered in reports
      kcsan: Show location access was reordered to
      kcsan: Document modeling of weak memory
      kcsan: test: Match reordered or normal accesses
      kcsan: test: Add test cases for memory barrier instrumentation
      kcsan: Ignore GCC 11+ warnings about TSan runtime support
      kcsan: selftest: Add test case to check memory barrier instrumentation
      locking/barriers, kcsan: Add instrumentation for barriers
      locking/barriers, kcsan: Support generic instrumentation
      locking/atomics, kcsan: Add instrumentation for barriers
      asm-generic/bitops, kcsan: Add instrumentation for barriers
      x86/barriers, kcsan: Use generic instrumentation for non-smp barriers
      x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
      mm, kcsan: Enable barrier instrumentation
      sched, kcsan: Enable memory barrier instrumentation
      objtool, kcsan: Add memory barrier instrumentation to whitelist
      objtool, kcsan: Remove memory barrier instrumentation from noinstr
      kcsan: Support WEAK_MEMORY with Clang where no objtool support exists
      kcsan: Make barrier tests compatible with lockdep
      kcsan: Turn barrier instrumentation into macros
      kcsan: Avoid nested contexts reading inconsistent reorder_access
      kcsan: Only test clear_bit_unlock_is_negative_byte if arch defines it

 Documentation/dev-tools/kcsan.rst                |  76 +++-
 arch/x86/include/asm/barrier.h                   |  10 +-
 arch/x86/include/asm/qspinlock.h                 |   1 +
 include/asm-generic/barrier.h                    |  54 ++-
 include/asm-generic/bitops/instrumented-atomic.h |   3 +
 include/asm-generic/bitops/instrumented-lock.h   |   3 +
 include/linux/atomic/atomic-instrumented.h       | 135 ++++++-
 include/linux/compiler_attributes.h              |  18 +
 include/linux/compiler_types.h                   |  13 +-
 include/linux/kcsan-checks.h                     |  83 ++++-
 include/linux/kcsan.h                            |  11 +-
 include/linux/sched.h                            |   3 +
 include/linux/spinlock.h                         |   2 +-
 init/init_task.c                                 |   5 -
 kernel/kcsan/Makefile                            |   2 +
 kernel/kcsan/core.c                              | 347 +++++++++++++++---
 kernel/kcsan/kcsan_test.c                        | 426 +++++++++++++++++++++--
 kernel/kcsan/report.c                            |  51 +--
 kernel/kcsan/selftest.c                          | 143 ++++++++
 kernel/sched/Makefile                            |   7 +-
 lib/Kconfig.kcsan                                |  20 ++
 mm/Makefile                                      |   2 +
 scripts/Makefile.kcsan                           |  15 +-
 scripts/Makefile.lib                             |   5 +
 scripts/atomic/gen-atomic-instrumented.sh        |  41 ++-
 tools/objtool/check.c                            |  41 ++-
 tools/objtool/include/objtool/elf.h              |   2 +-
 27 files changed, 1347 insertions(+), 172 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211216235712.GA2991567%40paulmck-ThinkPad-P17-Gen-1.
