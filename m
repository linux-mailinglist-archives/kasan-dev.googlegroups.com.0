Return-Path: <kasan-dev+bncBAABBUEVYTZQKGQECSGUKVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CB30188C40
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 18:37:22 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id r23sf5072722otp.4
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 10:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584466641; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlzuefC0jBcEx3PEwssgvBa8TMx5IfYPPuorjFkT01MYnA/GfyMOf4z4ta+nfke+Uz
         1m6H44/p0IFwZiUUz9hMXpB03p+nKS5JfLAm6Rpu/XeaWy0x2dG1ic9w5dtxWl1X3zFj
         wh/iWKvboNABx0EizHml9B0GML6cocK3dDi0+DMqdpC9UvmCJReS2ScWa8kEjeh6y0LB
         SwzHjmHrBckSS44kHRzkVRmnY/wgd//0fF2vmZFeDEgzgIS6HfG6P78gj2Fqj2nLb/jh
         P+TSm8oQRM0ESKcwHxLTFzsj4eUtm+9cZcXUFbU/OOcIOsK5E9NsRWm46hEd+dKwla7o
         eE5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8H4ilx3mVCOcNYbgfm/J+av1tG+9j5+LLsXfzcFQ3B0=;
        b=CyskuBnhRErh8NWjhaunI6iN9dnilDOk0AG486GObcO++6Zs8Dh1vI1s+bvSMNZo7Z
         3X80tBCMJ4GWmXPLdII0rjK4sAm2LUwHYhV4cuDLoa69WL57YS8pqtiERKVKAT476EME
         UHdvq5nrRlFrdvGJ5hJBAe13zEt8BL97x59rStqVpXk1aQe1kxYcAJAchZ8j7kVFv06S
         WIYHiAd1VYmyY706pqYIqL6KoCwV5+v1MoNb8mKc7cUeTHfPhVgrlpQef4X6wuAbM0HX
         HHRZyoagLXVhKFMm+BOl1VS9p6FSJgM5MR2GG/9uU+f6eSWjPc+mmTnpmGTnuNYi1Vtp
         5rgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=efsecl1d;
       spf=pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8H4ilx3mVCOcNYbgfm/J+av1tG+9j5+LLsXfzcFQ3B0=;
        b=nm/B7hYAnOYj598fTSVBFKxkTDHbVYBVP39gBr9Idg6FrzfX8ABRmp5a4JLXCPko47
         e5l+4AlY9klZMy2lwPZIyjTfPJV8fWTmS0/yxXLCaYVoDxI8C2bA0rh58PvLBHOS8ijZ
         o5xJzTF/9CyRODOvp14wODXiyzdtzpznx5b50x+E7CCgav7qb4R3PFKsUy0H3AI55oO/
         YUoSTQDW8ex2c74IMWTvOBRrem3cfJhTz6qDJXUUF264ZKKIUexWA6sNpUyYRuKvGHBn
         dH7de1QCjETEW1B6U2KLunKxoR3ZmVQadXQHhANwwbsHqz3/K3ju8i0oukc4BIZmR6eZ
         TsLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8H4ilx3mVCOcNYbgfm/J+av1tG+9j5+LLsXfzcFQ3B0=;
        b=GrmtqFxacpkasQ870o7hArIQs2HvuuwQtP8FFR4+HwfKlC7AshYjhtZokrBBjIKJjn
         4fC8N41r+uNT2q8A6sadVd1+5xg0HJ2fVfifAjxo6eKa/4C6Zq6NsHkS6DsUOozCVTDL
         npcQHdBin+3G/v/JESepD0AkW6pMIpb6GfmTmB9YSGpTk6PTxr0QTubx1HMA5dCf0ijQ
         fBtB2QZpB8fsZtZfjDCdb74BARfH2PJGRUR57TEyHj9JC8DofLShvGNrI4d1hjJ/RzkK
         R/ubbSaeu/VkPyaFwuKRQ+cD9h5R5pfrTf3FAgJM1V3Vl9km23fydH5Z4N/wXLoZnH6n
         CpWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1mHmGWQvTF02II6xHp7e8OEKOrLrG+1GAsVxyiPsTiBvDLK5UQ
	hbyY9Erc7/p5WaU2zdrj8m8=
X-Google-Smtp-Source: ADFU+vuzc/4rxY7hpn/UIZ5Im0nWpQbGe2mjFDdPkOFGpEimh0Nf+nMhehQVVRRM+i8pryeckenjCQ==
X-Received: by 2002:aca:be08:: with SMTP id o8mr335836oif.101.1584466640974;
        Tue, 17 Mar 2020 10:37:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6759:: with SMTP id w25ls7980068otm.10.gmail; Tue, 17
 Mar 2020 10:37:20 -0700 (PDT)
X-Received: by 2002:a9d:1921:: with SMTP id j33mr282231ota.309.1584466640612;
        Tue, 17 Mar 2020 10:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584466640; cv=none;
        d=google.com; s=arc-20160816;
        b=DOcEuiNqMtW7/WMT8XfyDq9/OtWPC+/nVqd3aRnbcz/nRtmiK6eS848G0lbcMbjq5J
         PyVCiES18mBNJ59LKJl0+NMCToVJIzPtLZkhIBYWaG7TRs571dnyh/4wJBRZQVp5+elo
         GGIjQc3W2v3Axv2Ml5MQ7fc7JM0JKXy3wUs6Dkn2/z6Y0iJ8zZRbA52W7tbiTZJ24fu+
         cRqtGDQwF5p4kOfZNLsv9bEsSbPy+chYRqfCjDM2F1noo6era3rvnCoZyURW+SVr1wPa
         adbb8onwbl47cpfxX0O0AqG/8c7BAISDTid2BNysgyp5J1KtlhleGwzZmmRlTXkucdhL
         Jk7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FqPdHhOkQx0Vp8C48XF6fcEQHXIYdgIcJt/CuB9+Bok=;
        b=zs5K5iJ+Q8xFiJuBD+6y7pQMqvYd7T4bRheJUK6cRGfPRuzwEVQv33hxEMT8GuzASE
         BPUXHVvz2yEgigGPBrYZ1SmP6Vp2fhyE79TkqCvxwLCpeY1ViIN9dv9qSQQ9nQ0X/Kic
         FD4n/rdvDzy3afvJVIZ8h4dMHLPRytLTZn2OT8bq44mG50fptBgL77vqJR/UI0U6QzAX
         6AhAkc5NU11Xx/d2Q6JcQGmT8jBwYUbdHySQAPqnDGVmxDdUYwQZMQsNXVLoDsp7wPBn
         hVjfvCLZAqxVbWmjrbdN1H5wM0s9pHpEj1T+EMgdoyfRZZmz4wARR3IE2lvzWaRGwfjg
         I+Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=efsecl1d;
       spf=pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t81si273761oie.5.2020.03.17.10.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Mar 2020 10:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C60B220735;
	Tue, 17 Mar 2020 17:37:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9C68935226E2; Tue, 17 Mar 2020 10:37:19 -0700 (PDT)
Date: Tue, 17 Mar 2020 10:37:19 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: kasan-dev@googlegroups.com, elver@google.com,
	linux-kernel@vger.kernel.org
Subject: [GIT PULL kcsan] KCSAN commits for v5.7
Message-ID: <20200317173719.GA8693@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=efsecl1d;       spf=pass
 (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

This pull request contains KCSAN updates for v5.7.

https://lore.kernel.org/lkml/20200309190359.GA5822@paulmck-ThinkPad-P72/

All of these have been subjected to the kbuild test robot and -next
testing, and are available in the git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan-for-mingo

for you to fetch changes up to 31bbbb841768f369301d6f65782dffd65d22aa5b:

  kcsan, trace: Make KCSAN compatible with tracing (2020-03-09 13:18:49 -0700)

----------------------------------------------------------------
Marco Elver (25):
      kcsan: Prefer __always_inline for fast-path
      kcsan: Show full access type in report
      kcsan: Rate-limit reporting per data races
      kcsan: Make KCSAN compatible with lockdep
      kcsan: Address missing case with KCSAN_REPORT_VALUE_CHANGE_ONLY
      include/linux: Add instrumented.h infrastructure
      asm-generic, atomic-instrumented: Use generic instrumented.h
      asm-generic, kcsan: Add KCSAN instrumentation for bitops
      iov_iter: Use generic instrumented.h
      copy_to_user, copy_from_user: Use generic instrumented.h
      kcsan: Add option to assume plain aligned writes up to word size are atomic
      kcsan: Clarify Kconfig option KCSAN_IGNORE_ATOMICS
      kcsan: Cleanup of main KCSAN Kconfig option
      kcsan: Fix 0-sized checks
      kcsan: Introduce KCSAN_ACCESS_ASSERT access type
      kcsan: Introduce ASSERT_EXCLUSIVE_* macros
      kcsan: Add test to generate conflicts via debugfs
      kcsan: Expose core configuration parameters as module params
      kcsan: Fix misreporting if concurrent races on same address
      kcsan: Move interfaces that affects checks to kcsan-checks.h
      compiler.h, seqlock.h: Remove unnecessary kcsan.h includes
      kcsan: Introduce kcsan_value_change type
      kcsan: Add kcsan_set_access_mask() support
      kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
      kcsan, trace: Make KCSAN compatible with tracing

Paul E. McKenney (1):
      kcsan: Add docbook header for data_race()

 arch/x86/lib/Makefile                              |   5 +
 include/asm-generic/atomic-instrumented.h          | 395 ++++++++++-----------
 include/asm-generic/bitops/instrumented-atomic.h   |  14 +-
 include/asm-generic/bitops/instrumented-lock.h     |  10 +-
 .../asm-generic/bitops/instrumented-non-atomic.h   |  16 +-
 include/linux/compiler.h                           |  16 +-
 include/linux/instrumented.h                       | 109 ++++++
 include/linux/kcsan-checks.h                       | 174 ++++++++-
 include/linux/kcsan.h                              |  46 +--
 include/linux/seqlock.h                            |   2 +-
 include/linux/uaccess.h                            |  14 +-
 init/init_task.c                                   |   1 +
 kernel/kcsan/Makefile                              |   2 +
 kernel/kcsan/atomic.h                              |   2 +-
 kernel/kcsan/core.c                                | 183 ++++++++--
 kernel/kcsan/debugfs.c                             |  65 +++-
 kernel/kcsan/encoding.h                            |  14 +-
 kernel/kcsan/kcsan.h                               |  33 +-
 kernel/kcsan/report.c                              | 255 +++++++++++--
 kernel/kcsan/test.c                                |  10 +
 kernel/locking/Makefile                            |   3 +
 kernel/trace/Makefile                              |   3 +
 lib/Kconfig.kcsan                                  |  70 +++-
 lib/iov_iter.c                                     |   7 +-
 lib/usercopy.c                                     |   7 +-
 scripts/atomic/gen-atomic-instrumented.sh          |  19 +-
 26 files changed, 1068 insertions(+), 407 deletions(-)
 create mode 100644 include/linux/instrumented.h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200317173719.GA8693%40paulmck-ThinkPad-P72.
