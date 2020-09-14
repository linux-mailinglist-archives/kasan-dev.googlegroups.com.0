Return-Path: <kasan-dev+bncBAABBJ63735AKGQECGJ423Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id B8C55269421
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 19:51:36 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id n128sf249266vsd.5
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 10:51:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600105895; cv=pass;
        d=google.com; s=arc-20160816;
        b=tEKGZCnF/g1bHvndGxYD4v7/INFw5K2p1saadw2d1jIvVoWHNN0sJ10Di5kyQEb8o9
         54zURyAO2fMt21Bh58lM2kK1WtOJ80ywP+oR48hISc5IjUnY/QVB+LTHZOZxFWpuejRX
         L53zAT5rcGcZ29NBAUblkDfpbY+xUcYOPToN8ChS+k9MYClW77dg1eQOuZtE0FwXEAPh
         TE465IuU6CQlxKST9jozQp4FJwqRWaERZ8alBnuHaZ5SIluE9ItQbWMQuTCKvj8qwhMm
         lV68tFrVDQOp/S/YSjM/Lm0iGR1sWlNN9LM7HAvnnGxdnkxwWWIFA8+HDO3PhJlkk5iN
         Kbaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kjx2A7i6Etn3CqMP+WlXvzE2MMoVQWQ4uRI9+wFSHEA=;
        b=KJWYY+x3HLm8OU9WrrDVcP9DaVWfSAHKZ90JNof22wOCx85tc4lVhGZbwwWfvDt0UO
         kTw/o/syNF+i7gZfliA2yjfSmdvqXGmnzqkBP8VSs2nHxPSWGz3LowoflxWQ63hckTrU
         Exgy4S380saBrH5fipVGF6AYJN8evUu4/z33KcSdegsaQuKqaQ2fN9gatgKnII+6VpMU
         HP+4OsgiQFFASbWKq4Jcoi5GMm7ZL5TTcJ1WGZGh8Dtzmim1mjAOWV0L8jXbN4roPbAm
         YILZOmA8eKECPtVEPZAGgoUAIvC+kcRcZMCT8Q+UOGvdafYq6HEiOEbGXgia9I0S0FpF
         vM6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=1AE29D7G;
       spf=pass (google.com: domain of srs0=xikf=cx=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XikF=CX=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kjx2A7i6Etn3CqMP+WlXvzE2MMoVQWQ4uRI9+wFSHEA=;
        b=bzZzs3n8GYT2a69u660iMXb/gvpjIwmMViV5f6bCx3hut67MVWP+u0meD60A5t2N18
         4Vj6VXN5HGMyPP6x4GiZyysAxEjU0b8rifcK8xsTJSX++BoNEIEoY4r8DYiJKCAjcLv2
         ggk+1ecgqfcDlWeXXiBG/GzmNpaLqvGEFRtvPrE/++gVh6VT1iUwfzCMiaCEhfbdZezM
         EaqR44gjYrC9IJJN1xFm222VQFo0OY47dYn6iEZhOxz7pRmnKhDlPdLGz83+u0eQhR56
         w3ysPMEYVrvSaroeJ8N2DuVqf/FHwhd/x5YtGOUUCmpqilO9R1xCapJwsZ8HIU+t4oPV
         hZDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kjx2A7i6Etn3CqMP+WlXvzE2MMoVQWQ4uRI9+wFSHEA=;
        b=coG9uXMjLqD5uxpDzfgDmMiwcDcL1JL0HF7kJqN1v0FYojSmLh9bKm60TsKGNDzxhH
         PHa/FjKpyynsdYOP5bN7ieAi01E+pnIKTYqvdn6V+5sQBdFRT/lrmeaLDDwUFv0ElQh9
         3ovIwwpijbGuAsFLL8KXU0Pw3huaY0x+JwHo0worPG+uxfz+mcux8mcQByjnuwZ8FrTu
         JZU+JaebrAACpkPTFI0EfGX4GPeEoUSyGUNO4w5P38BZB2SZNflvbn37YWaYOkx8M2cO
         QcXebNUB9YlwDrz1fh3VlxBAJoSmN5G6OcTkPMJHYgEyizu9KHLhRFrIXjtMSczsarN8
         BV+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JV+Ikg4T4rP1YVxQncPZp1M8ECWrLnPDxEbPEyRqNXGOenrzd
	R2ocOvN7hqxOBmm633BDbn8=
X-Google-Smtp-Source: ABdhPJyhKtEb/E2sFeYOdB8jhYA7PJ7NOLMUF+VPGpnS8toZqibuFXV9hfxdxNZ7pAkSlzQPzZR2Pw==
X-Received: by 2002:a9f:3491:: with SMTP id r17mr7379591uab.113.1600105895474;
        Mon, 14 Sep 2020 10:51:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c899:: with SMTP id n25ls506643vkl.1.gmail; Mon, 14 Sep
 2020 10:51:35 -0700 (PDT)
X-Received: by 2002:a1f:b486:: with SMTP id d128mr7739001vkf.1.1600105894989;
        Mon, 14 Sep 2020 10:51:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600105894; cv=none;
        d=google.com; s=arc-20160816;
        b=sgAnlXjtI7GBJxrbW3mNHLM8eK/6gXyU3DkIMF9qDkXmXWYAzEg5J/zxpRCxukYPsi
         s3O9Kj1SFHWwISOPVrE1BUJLBynNTo91pSp51aaX58JzoncrfLFyBCBALF7L3jY/7/N3
         V37poi8u21ectEF447flOGbPfCFBmsCX1ok8c4re/JJY1aQbErr39hicE7N3Opid8114
         fhfgq7fFDO6OMFnlC+96c77ximPp3MNSHeiLEETXr7FB2tDEbMXV/MQjYlNH9sTBykgI
         xSqqrB0oWYtxJ6BP5Sofshx5b+CMwPyHg+UKDQAFHoOZNOQ7S6wEoxBZvyM+0YoOz6KF
         onLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QM8Sqvlx7cYWr4+NC/bHaZRZ8ixkpYgxAF7POnW2Yrs=;
        b=e12Azm8XJHJjhGAuRRWlNxIBhcF2W9zpwtWkf93oJPhm/Zwdm4QCi1UJ2XvzbNW3cf
         DAxsuOF4C13Q8fMXq0EnrfqpCbvYNeq+dCJjixJLwqHZG31W1nvx67HrozWU2obi7t83
         Lz10NcCvaOuVdL66ihPKPFx9itdITngfX4b0e7Rjaq2aoXxdAT7+Gb3GmzeRDZwmRePL
         eNCnlQSb29TeRL7EONklGCNwZOiU4quZxktJsmEHQ1fDkmareuXqYoZ9/czjtHLDgd7H
         Ipv+Vj1FORatd/S7rXqDkFc3dWzo+lwjeqgRuME3sq0AYVVtqlbrg8zot1TUIPyM9MFj
         XQBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=1AE29D7G;
       spf=pass (google.com: domain of srs0=xikf=cx=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XikF=CX=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y65si789415vkf.1.2020.09.14.10.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Sep 2020 10:51:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xikf=cx=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D412D20EDD;
	Mon, 14 Sep 2020 17:51:33 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9C58F3522BA0; Mon, 14 Sep 2020 10:51:33 -0700 (PDT)
Date: Mon, 14 Sep 2020 10:51:33 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: mingo@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, elver@google.com
Subject: [GIT PULL kcsan] KCSAN commits for v5.10
Message-ID: <20200914175133.GA14094@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=1AE29D7G;       spf=pass
 (google.com: domain of srs0=xikf=cx=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XikF=CX=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Hello, Ingo!

This pull request contains KCSAN updates for v5.10.  These have been
subjected to LKML review, most recently here:

	https://lore.kernel.org/lkml/20200831181715.GA1530@paulmck-ThinkPad-P72

All of these have also been subjected to the kbuild test robot and
-next testing.  The following changes since v5.9-rc1 are available in
the git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan

for you to fetch changes up to cd290ec24633f51029dab0d25505fae7da0e1eda:

  kcsan: Use tracing-safe version of prandom (2020-08-30 21:50:13 -0700)

----------------------------------------------------------------
Marco Elver (19):
      kcsan: Add support for atomic builtins
      objtool: Add atomic builtin TSAN instrumentation to uaccess whitelist
      kcsan: Add atomic builtin test case
      kcsan: Support compounded read-write instrumentation
      objtool, kcsan: Add __tsan_read_write to uaccess whitelist
      kcsan: Skew delay to be longer for certain access types
      kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
      kcsan: Test support for compound instrumentation
      instrumented.h: Introduce read-write instrumentation hooks
      asm-generic/bitops: Use instrument_read_write() where appropriate
      locking/atomics: Use read-write instrumentation for atomic RMWs
      kcsan: Simplify debugfs counter to name mapping
      kcsan: Simplify constant string handling
      kcsan: Remove debugfs test command
      kcsan: Show message if enabled early
      kcsan: Use pr_fmt for consistency
      kcsan: Optimize debugfs stats counters
      bitops, kcsan: Partially revert instrumentation for non-atomic bitops
      kcsan: Use tracing-safe version of prandom

 include/asm-generic/atomic-instrumented.h          | 330 ++++++++++-----------
 include/asm-generic/bitops/instrumented-atomic.h   |   6 +-
 include/asm-generic/bitops/instrumented-lock.h     |   2 +-
 .../asm-generic/bitops/instrumented-non-atomic.h   |  30 +-
 include/linux/instrumented.h                       |  30 ++
 include/linux/kcsan-checks.h                       |  45 ++-
 kernel/kcsan/core.c                                | 210 +++++++++++--
 kernel/kcsan/debugfs.c                             | 130 ++------
 kernel/kcsan/kcsan-test.c                          | 128 +++++++-
 kernel/kcsan/kcsan.h                               |  12 +-
 kernel/kcsan/report.c                              |  10 +-
 kernel/kcsan/selftest.c                            |   8 +-
 lib/Kconfig.kcsan                                  |   5 +
 scripts/Makefile.kcsan                             |   2 +-
 scripts/atomic/gen-atomic-instrumented.sh          |  21 +-
 tools/objtool/check.c                              |  55 ++++
 16 files changed, 677 insertions(+), 347 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200914175133.GA14094%40paulmck-ThinkPad-P72.
