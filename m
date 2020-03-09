Return-Path: <kasan-dev+bncBAABBIVGTLZQKGQER7GJZGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 69F2617E7C2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:03 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id b82sf973748qkc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780642; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mu7Kd6OuNScF+/fqGL1GPQwTjveZbKjy8lRudSb/Hl8mhieb6LSTb3ejaY633eZpTG
         IHt2e4AtZHH23A80EdksrfxFlXkV3UVw6oreUJoEkl8MlJXVmswW06D+INhUSMqYO4qU
         dex9Itx1dvxgwjCEf9yvWfV5srj+BfNjlaTYbG2l0G3l5HCrGMtAqKaTvvXrMn9bMkes
         6YldayTthfhjtRrcxQwPE0/rK02KPRj8/TxZzVnD81di0CGLVz0c2XNTK6pMX0562yeO
         U6LQn+YOYxxaeE0ZDT32I2rOsPATT3pXGZZvvD5od5zFWGdQJuPin/FD/7LYkRK3tFup
         fxPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XMQgrIXwg2PS3xJ5K3UUw7KqZ+7bTyYaqAfYqa/88wQ=;
        b=ydm+3lOx0ex3hOlsDQyifqc7rfNxHfw0W3tvPS/fP/ojP9vYQOkur7EYHezKP1dccg
         sIzaS/0aZg2mKV+4BVskgnNekNH5hjegdMwXth486z3DQKaMYYFDGRvARxf6Aq86hHxp
         xkxuTEH9wGamieTr0prxaPeMzODTnTDxtfrsyBY9y2XM6kc7sfzS0Xiqij4LbGfjD1jC
         HVcvLzHHyaP9P6KhSCmfEosQSMM+AaZncr2Mne5UH8fBuEhViElji5Oteo1nyU+R9j3J
         xgkAvZhX3fgzoYyjI+ZdN38+R4Yh9gwGQdIKnBdWVUD/APW9eqN4Isd9w8qoLZ7uEp/I
         BM+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=l0sMWuxb;
       spf=pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XMQgrIXwg2PS3xJ5K3UUw7KqZ+7bTyYaqAfYqa/88wQ=;
        b=nFAGxTwhLx/wmqSAAxm3A1RmO5ihngnTASocC1tVYAI8TJuVpTyQjOsXeQ79PhfeqE
         3IQ7Jra0KLhS5a/plXcBIi/jVQomYWFnUG5QnAMbgmU0FVy2ADNpy5UOe8YPOpQVbfEt
         8ZOgXx5hTOpuftiUS8fZVfXlMZCe80phqpKuTW2lhb2J4NzygXMabKVwSMyBToLTmliZ
         yrakW25WH5lnktxHy8e7JfoQ7FCwPAIu5IWQFjUCR4aAv6INSmVwffqR4K57z73uRD8b
         JMfkvwrXVikxnnVyo/gu9fiKUwiZBW7jzlAp2Lh3n/z2VFPkyO19HrnsJTEiQr/4iZyV
         jNAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XMQgrIXwg2PS3xJ5K3UUw7KqZ+7bTyYaqAfYqa/88wQ=;
        b=Xi2WgSHtw/pfiItdRZDSbhtuBm4S5RpqzFZHQcDkZp7RuAqvM6vve0avE4m4PfzSTD
         IgTm0kMuEN796eO5pHTsz1hJ0mgsGCfXQFULRw4RTbMHAQ0Qd51MOmyv5AYf/CfhP2G1
         Rw7C7JNFLilBvRkQ7MDvxj4cldk6yf1oO6RapnjLoZmdeyxjfr1icTIRZASBuprHS69M
         cn0ySU90oN+0m5L+9qDsuv8KTQwxohd+e+zsX3YEriiVs0Zoc55iSfjJe/vmFuukpfmH
         Q15o+taQ4mkXOZrtD0u4qDY9U+WZjt9qiXqKpQESlezyY99l/NVZSKm4oz9fAtpaiMUp
         70Jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3XlmgJcXtnkarPRZg1b8MZJoFCVyl5BdqmB3Gf2Lgwv/UNTPGK
	X0thQSSn88E7W4RzyTgoXgs=
X-Google-Smtp-Source: ADFU+vv9ioBD6p+7GzomuQtI1AhtyAFqzGbAbSptI8/pDP5uWBvlHVSAwrFEYaTCTanBJcyjZfy2bw==
X-Received: by 2002:a0c:b757:: with SMTP id q23mr15911152qve.213.1583780642086;
        Mon, 09 Mar 2020 12:04:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2764:: with SMTP id n91ls4029258qtd.0.gmail; Mon, 09 Mar
 2020 12:04:01 -0700 (PDT)
X-Received: by 2002:aed:2591:: with SMTP id x17mr4118620qtc.380.1583780641261;
        Mon, 09 Mar 2020 12:04:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780641; cv=none;
        d=google.com; s=arc-20160816;
        b=nFX6+IcRN0G6LbnrXsb3nPIb/N4KtLdgbGYiCx0Y1ou9QyXHw72Qy6MV2fYDWNaiGP
         kiv7RX4Okk5PgmR4+G5RI8McpTPQWzdM5o/E8heOiYVji46eejc/aq2d0Bmyi134cArt
         QF0iXyfXzCMCZRkY/bhc4uX9J/wpUI3ISX6acZxwHSrA7L4GoryNQYjj0LNln17um7jO
         HyfKoWSecWVY5xXXzT+WCEnAV8IfBNhomxmQLyBzqWuK7Aqa3CA6GEo/D13TOgJ+Hb2L
         OT1Zrof8384T6I/tnDtrDA8ioAaOOS3NBUasBHE0BNqraSSjsARLc0CLS/1Pgq2klZIX
         rS6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UjsmxU7+ZhpPhdaNdpMuU1Y4mLXGcA5Ned/htl7Hu00=;
        b=RN1BYWXAwRWWEIvVc9jO1q5OLsBQQ6cvTgKf1lxKtmXU/aYLPdc7rYbMWSr93tOdHb
         znfd/4hTrwg406XgR/5r7Lyn2G7SOjN8w/TuKy/sv1gn1hp1IAkvDi07dOdF7orsfnFM
         8pV/hN2CrGSW26Y0CaNyeo4PmiYGSqQXOkcJfDd1pP4q3x2hWPN3SyOBtTgmK+T05Jeb
         tYCpFnk+hbPNaJm0e54+MWaKV+n1u01f7YW2Uzd4u6jgtIRUHSbaKwvQShuDOBExh/kv
         7ohr5Ctu0NDO92mLYAR456RVb96/hNUdr4jrRl8AkyYnC+deL3hyi8d3mXqutZkmpNwY
         DyWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=l0sMWuxb;
       spf=pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g23si571617qki.4.2020.03.09.12.04.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1417420873;
	Mon,  9 Mar 2020 19:04:00 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D78053522730; Mon,  9 Mar 2020 12:03:59 -0700 (PDT)
Date: Mon, 9 Mar 2020 12:03:59 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/32] KCSAN commits for v5.7
Message-ID: <20200309190359.GA5822@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=l0sMWuxb;       spf=pass
 (google.com: domain of srs0=rofd=42=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=RoFD=42=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

The patches in this series have already been posted, so this posting
is just to give a heads up as to  which of them are likely to be part
of next week's KCSAN pull request.  Unless otherwise noted, these are
courtesy of Marco Elver.

1.	kcsan: Prefer __always_inline for fast-path.
2.	kcsan: Show full access type in report.
3.	kcsan: Rate-limit reporting per data races.
4.	kcsan: Make KCSAN compatible with lockdep.
5.	kcsan: Address missing case with KCSAN_REPORT_VALUE_CHANGE_ONLY.
6.	include/linux: Add instrumented.h infrastructure.
7.	asm-generic, atomic-instrumented: Use generic instrumented.h.
8.	asm-generic, kcsan: Add KCSAN instrumentation for bitops.
9.	iov_iter: Use generic instrumented.h.
10.	copy_to_user, copy_from_user: Use generic instrumented.h.
11.	kcsan: Add docbook header for data_race(), courtesy of yours truly.
12.	kcsan: Add option to assume plain aligned writes up to word size
	are atomic.
13.	kcsan: Clarify Kconfig option.
14.	kcsan: Cleanup of main KCSAN Kconfig option.
15.	kcsan: Fix 0-sized checks.
16.	kcsan: Introduce KCSAN_ACCESS_ASSERT access type.
17.	kcsan: Introduce ASSERT_EXCLUSIVE_* macros.
18.	kcsan: Add test to generate conflicts via debugfs.
19.	kcsan: Expose core configuration parameters as module params.
20.	kcsan: Fix misreporting if concurrent races on same address.
21.	kcsan: Move interfaces that affects checks to kcsan-checks.h.
22.	compiler.h, seqlock.h: Remove unnecessary kcsan.h includes.
23.	kcsan: Introduce kcsan_value_change type.
24.	kcsan: Add kcsan_set_access_mask() support.
25.	kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask).
26.	kcsan, trace: Make KCSAN compatible with tracing.
27.	kcsan: Add option to allow watcher interruptions.
28.	kcsan: Add option for verbose reporting.
29.	kcsan: Add current->state to implicitly atomic.
30.	kcsan: Fix a typo in a comment, courtesy of Qiujun Huang.
31.	kcsan: Update Documentation/dev-tools/kcsan.rst.
32.	kcsan: Update API documentation in kcsan-checks.h.

							Thanx, Paul

------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst                    |  227 ++++++----
 arch/x86/lib/Makefile                                |    5 
 include/asm-generic/atomic-instrumented.h            |  395 ++++++++----------
 include/asm-generic/bitops/instrumented-atomic.h     |   14 
 include/asm-generic/bitops/instrumented-lock.h       |   10 
 include/asm-generic/bitops/instrumented-non-atomic.h |   16 
 include/linux/compiler.h                             |   16 
 include/linux/instrumented.h                         |  109 +++++
 include/linux/kcsan-checks.h                         |  284 ++++++++++---
 include/linux/kcsan.h                                |   46 --
 include/linux/seqlock.h                              |    2 
 include/linux/uaccess.h                              |   14 
 init/init_task.c                                     |    1 
 kernel/kcsan/Makefile                                |    2 
 kernel/kcsan/atomic.h                                |   23 -
 kernel/kcsan/core.c                                  |  279 ++++++++----
 kernel/kcsan/debugfs.c                               |   94 +++-
 kernel/kcsan/encoding.h                              |   14 
 kernel/kcsan/kcsan.h                                 |   36 +
 kernel/kcsan/report.c                                |  414 ++++++++++++++++---
 kernel/kcsan/test.c                                  |   10 
 kernel/locking/Makefile                              |    3 
 kernel/trace/Makefile                                |    3 
 lib/Kconfig.kcsan                                    |  114 ++++-
 lib/iov_iter.c                                       |    7 
 lib/usercopy.c                                       |    7 
 scripts/atomic/gen-atomic-instrumented.sh            |   19 
 27 files changed, 1517 insertions(+), 647 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190359.GA5822%40paulmck-ThinkPad-P72.
