Return-Path: <kasan-dev+bncBAABBCNH3X2AKGQE7MKSXCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 698B31AB0C2
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:33:46 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id p20sf20889240iob.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:33:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975625; cv=pass;
        d=google.com; s=arc-20160816;
        b=MtmgolZ4A1mqhJYnIxrnxJIogsZslqdHWTJjUJllp8U9aKWydZnCE43wmR5IodD+v/
         nVje8M596F5txsXHeNnkGvJ3yR2Om1pvw3RvVKmP9/WUQI66EJet1A/Ef+BWPk1uKD43
         2sPaGu7VBwb7ull9ZO6yE46dJYfeEadjOfjk5kTwyxG1zZ9DBRosZ5Vxa6UGxRKjpvEv
         jslI0fHFZKEQ5oo5y1R2GVRUsdZUDmjQV1ivcAh0ZVO8j6tby07xKZ3gS9tFNZmHMOg4
         N0/TYllCorJJvUSkIO2HzRNuSAmhnzvAkzGn4n+jFIekvXdE9oZEPnvDZukNU7euDWPw
         ECiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zq32Hx0TF5Rlin3pmcjpSH4YX5wJjjBbli2AEq59S+o=;
        b=Dd5fV4gKGNUyI0qFjrQ3/9yTZrI9twVXhQu9Vc8TcFm4LBIMjCVwtEzCwQIWjjQF4s
         p6XMGcbcR+4cQlUTNOsBjSowHxv1SWdbt9zo6J6CvFuDNomc+I1s54qLGJZD05Ilke0a
         yh8k/zpS0Nqcp3oWBtoRmEpLI6poSnL6g84Ia3myGbFczIqa2uqtkcgD7vml1f6UPrgp
         pjgKNZIM+eRNk7Q1pncxvBmsq8fMV9btuZQT4+5TcD42c8pwdqD47kjjVWvWdMnBOEA2
         ilfW8bShnyYrpR1IFfcBrxu++vKaLJW5RI/ab5/iy1HVGe5l31l+cspmej/E7v7kjxsA
         Wzew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2bKf75KC;
       spf=pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Xozv=57=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zq32Hx0TF5Rlin3pmcjpSH4YX5wJjjBbli2AEq59S+o=;
        b=CP1+w0uSoktkvrF0jdmN8RA89PalPP/9kKhr0kQTK5AWXv5LVONObjDDxFbYm8QwMn
         kJq8Z3lmlB3vMo8/Cgc+w2KF6xuSyN8W0MuEMxEaA/RBqapmNx2xVt3T1yUzW30pW+9W
         6GCyGlTpHoNj2RRmI5OVzNiSO2jUTj6L+5FDDIx586dbKciU3TD5RHFDzsrUn3X8KDU8
         JPIIZGqFP0YqoP8szKrt7vvbYVQIJHxtqI3z2W68LtqRa5DhPetDJZYQ7ntsJAvtmhkv
         oMyd1iGZOMk6CdyZfCGF0BSga123ePR2Pex1kqCQ3tVCdtF/LDMFkpF7qo7lm2KCE+E1
         ljIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zq32Hx0TF5Rlin3pmcjpSH4YX5wJjjBbli2AEq59S+o=;
        b=Co+i6mnmB1fTznyM3ZWq7wLFFQEPB3b6iPUnZrsEH23Hq9EhR10Bcdcn3e7r76Naf/
         mlB54RHlOAIYlRE7iZ5GOl5JojDkeLUT8k16PztXDQFwXYFfCHmlTX7dU8gzWpAStXer
         NFEOEk+zYjZbkniGsCjLA5wVajma7urbZvnDnX5MB1XQQXH82pF/qKfw+GKJmRXDLNgp
         JtD1IgQUtp4medcRV+pT779x4acdmLXlfuvRLWQIOjOabVwHTs3iI61BMpAortPlg+J0
         OC19G9jTQcHvL4MtklZTjCnxo7tnwweH++HABhkHlbKFQohPUICn2wwbfWS85OUjQOir
         zTwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub2LZC9BUcJIYH0lkMFefxA0tCmu8UAwnhhq8p66kXAVIgW622i
	Mj7XCx3q0nTCxivuxpJHeUU=
X-Google-Smtp-Source: APiQypKAQpPTeckhpzJ6vrWMiqsKCVwxjCdlFN1DWn461Cd2ofNPfFBOk5lXcwEX80nzxmECJ+cRQQ==
X-Received: by 2002:a6b:7314:: with SMTP id e20mr27901706ioh.165.1586975625325;
        Wed, 15 Apr 2020 11:33:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4a6:: with SMTP id e6ls3837958ils.11.gmail; Wed, 15
 Apr 2020 11:33:45 -0700 (PDT)
X-Received: by 2002:a92:798f:: with SMTP id u137mr7271731ilc.231.1586975624919;
        Wed, 15 Apr 2020 11:33:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975624; cv=none;
        d=google.com; s=arc-20160816;
        b=fXVM2bg0ZN8Us+EteKFKvJ5QVqybHp2yoKfj/Zx/zpX7wfi4INjCC0OFsWIo7YeTGq
         /KLhw9FL5FWD7WugnP6i5GLZeNQKlhL7De6lE6nWmrR+oH0E4pJVZ9gAAGnCPvAMd2l2
         erGk3BZ5f3C+A+F7PW8HaQQWmUQHT09HdOEhee+DHE6UTY0FOK7MHq213Bu3ZC62EsyS
         NjeJr3wmglP7kNmoRGuLKVE+oWTPdt/zM3Dkut5oqaPAFhefOLa4YBwe7TQfIRzDMFos
         CeHQ6BB9rEr7PnwOlscBg1OpDsmRZ4hMeMgwWDcrcvtx/bAXMHE5gsMgjzZd9RL5ORQA
         MC1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KTir11HGldmXYI/UeJAD4cYD54l0FOR9RK+vbF8dWJA=;
        b=mqbT/LTJz1VqZOidPvUTl691Uin9OYAbk+fHpHv0AXBOD7yYe/EH/dQKwz8GLmBZ/6
         mkFoEYZvtIAdSHP0ycgFKFLbm/9IYaLOfbF0GZ9vGpHPZ6zj1eJfN5IXHv6PCGReOGGH
         FlgEG6jHHiPClOOfy7XzeaUIa9gP37aVVFp62dEmNubXwyQBUbdMGPFFJ1+05V5XGXMk
         iZitkU8GJeCBdvpXEgCgIt09WZfGLjdX4ispvN3y1wWJCXl07iR0Q5daSKWP9rRjUA32
         Euqw4DicRh7g8kgm2Dn60gmRV6APkGVxocHiwBDVoC9kLLsThTaNCejZyTNxyqStIad6
         E90Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2bKf75KC;
       spf=pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Xozv=57=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z2si1322745ilm.4.2020.04.15.11.33.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:33:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xozv=57=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1A6DF20771;
	Wed, 15 Apr 2020 18:33:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id DE0FA3522AD1; Wed, 15 Apr 2020 11:33:43 -0700 (PDT)
Date: Wed, 15 Apr 2020 11:33:43 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/15] KCSAN updates for v5.8
Message-ID: <20200415183343.GA12265@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=2bKf75KC;       spf=pass
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

Hello!

This series contains KCSAN updates.  Unless otherwise noted, these are
all courtesy of Marco Elver.

1.	Add option to allow watcher interruptions.

2.	Add option for verbose reporting.

3.	Add current->state to implicitly atomic accesses.

4.	Fix a typo in a comment, courtesy of Qiujun Huang.

5.	Update Documentation/dev-tools/kcsan.rst.

6.	Update API documentation in kcsan-checks.h.

7.	Introduce report access_info and other_info.

8.	Avoid blocking producers in prepare_report().

9.	Add support for scoped accesses.

10.	objtool, kcsan: Add explicit check functions to uaccess whitelist.

11.	Introduce scoped ASSERT_EXCLUSIVE macros.

12.	Move kcsan_{disable,enable}_current() to kcsan-checks.h.

13.	Change data_race() to no longer require marking racing accesses.

14.	Fix function matching in report.

15.	Make reporting aware of KCSAN tests.

							Thanx, Paul

------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst |  230 ++++++++++------
 include/linux/compiler.h          |    4 
 include/linux/kcsan-checks.h      |  244 ++++++++++++++---
 include/linux/kcsan.h             |   19 -
 init/init_task.c                  |    1 
 kernel/kcsan/atomic.h             |   21 -
 kernel/kcsan/core.c               |  182 ++++++++----
 kernel/kcsan/debugfs.c            |   43 ++-
 kernel/kcsan/kcsan.h              |    8 
 kernel/kcsan/report.c             |  543 +++++++++++++++++++++++---------------
 lib/Kconfig.kcsan                 |   24 +
 tools/objtool/check.c             |    2 
 12 files changed, 887 insertions(+), 434 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183343.GA12265%40paulmck-ThinkPad-P72.
