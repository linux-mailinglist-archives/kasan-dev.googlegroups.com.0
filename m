Return-Path: <kasan-dev+bncBAABBLH5WT5AKGQEDT3SZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 022C1258097
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:17:18 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id k185sf3582795vke.10
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897837; cv=pass;
        d=google.com; s=arc-20160816;
        b=IJS7JCKrNyVdtBpBZaHzBMZeB0aaL4boDtgnofZ/Kbc+PhDjUsjbMEH7FPd+/xjnff
         CKS79d1LVYGXrJZ7qI1VSyM7ueplcH490yyHSxLyLC6so4A3B1N6SYiy6Xi15oKC+SKH
         Mj/5yMb/8gMy5ljFTT8H2G2noMSIMscC/rMfaYYUBZyHgV1weTUPKggorgH0kLFENmyA
         GR58UbVEmPINBXYBCpTORnmMdtoCP+EWG7L9suULojLHtkAdIAb7RXGTFeRMP00jte7n
         1cvoWmhUJLnbmAZESx93lC1MBb9aChiUZOH4NAXr50rud617LBb/0mu4meiMMFrrlfTq
         7QOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ey3ObQHSS96uI/9Ke3a4eW7VhW8QoMmZYvVt926H0QE=;
        b=mqK2M7FXcEeC48zDovMOOXmOT9V67zr/tLX4Gz4UCa07BkIZ73ERBohjlXnEzTLhXk
         xPqEw4HaDdNMAl7bguo6b9v+cCFLNNPxiv9eLAn5PJQZFPvQKORljjg4bbTQbFczs6qA
         sGLp2yC03Wb0ELL4NGNDJs3X0N4NmimlGny06R+yDD+188uDwwp102tbj+hQltXX5ERF
         o73Q9KMSMPE08dJs6GQVG/f+knOiXvY5QQxzj3u7eRs7NCJ3kzjnhb574/ZqWKT9EsX8
         Ut38SNZuqEADTzV6/hZkCZrh1vGyRz2SmkC4jHCMjQQkpefCB4xlrw5YB/di8NKL1BKI
         /icA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j1qdUDQm;
       spf=pass (google.com: domain of srs0=ouxs=cj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=OuxS=CJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ey3ObQHSS96uI/9Ke3a4eW7VhW8QoMmZYvVt926H0QE=;
        b=Zc0VQd0qKaK6j4zPoMiigmcAlTd6rdeC4r3jbUJwU+tdoueevDQMWLa7Zn81oROzXP
         F7CgnuYkafU90oxA9VY9eR33Z/rdQt6Q853xDDfXdsZc7pg/iNUZfHcC+TIaJ1mAtHRh
         qFVf2ppv+FsPOH18G5cX8/18Tos/Naco4QOUts/MrEqjVdlicBKsEThEsQAZAg9D7ieg
         Uq+8h0ds0e9p6idFTBTgdW9+/rHtP6yS5K2XiyiQ+Q2N54OMmenPgFWqnq0bCLzyVNVe
         0GGF+KWGTx0a8WAQscQ4NynmAg/qjod6IDQJJXTRvMzyUfNQIH8hSHkhKGnZA/Y/jxHj
         5BPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ey3ObQHSS96uI/9Ke3a4eW7VhW8QoMmZYvVt926H0QE=;
        b=n6OozAsVyrHUfxA9vvJTkioj+yc1aj7PdHSHRPa/50JGO0fxBL34aBpkw2Hj7kgGwd
         t3GNYhVv22RBSCihOf72UmV8T8rm/jPWpkGTPj+FQxHxvl+59WCCTADrrdTmONE9OXhf
         rks5d5mLcwWfDlx/o/jjS/DEiFLbVvfhEM1VdUzBpDjh1zngikqjvqQZwC49pWbeR0LA
         jKFQKyYkh/0bVZaE3kAC3334UU6OuI1/EiW1s0lPzbgHeVfoUDMzdBK2ra18CA+5Ug1i
         TpL9CYIv9ruP8gA2wnto3pnRQZbkCY2DcCpxTzYAai9NjiMJgrPfimJJLyLPITMU5gyD
         IygA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53022ByBN8F++eQ60z8ylgv1Lt/PhZIspKsPICyDMAV/TqVPD2nR
	55v5dl3m/SM/lz0BFo+ITnE=
X-Google-Smtp-Source: ABdhPJyqVPsBy4FUcB1a0RMGvLfwst8Se5e0vKBZyY2ChpvxNFCEs/qCDwKXXoDFjg8Iexhbl+9fnw==
X-Received: by 2002:a05:6122:149b:: with SMTP id z27mr2254355vkp.52.1598897836955;
        Mon, 31 Aug 2020 11:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:40a2:: with SMTP id i31ls250772uad.9.gmail; Mon, 31 Aug
 2020 11:17:16 -0700 (PDT)
X-Received: by 2002:ab0:5e43:: with SMTP id a3mr1974830uah.19.1598897836650;
        Mon, 31 Aug 2020 11:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897836; cv=none;
        d=google.com; s=arc-20160816;
        b=U4P1QQpNkrLyq6bKexcFUy1zvbObcqHXHMXwnca4tWcjtaQPffkapLGzac8geokk+S
         J5U3ARQl7DVLlGs/bIG0pNDUsb2cC0U1sgkpzhyXcUdzfHua2cUFDB37RbSFHI3CBMOL
         jdmIU0ENHKNS3am81H4O6HUoa1C7u7rIVM/sHBuCNWPeF6rUDIB50dZC29IJNtuWCkUh
         9HqmYsOQVEddzvdIXp1RoLM/vnxhUe/yhgO9k69oBTxwmmJ0g0wrM6nJBoLVDeQVSktf
         VirKBDabM9tFmRNHai6u5lg+6TM0giuJnPqwLiFyQcWf8Rc/h7ZNLIMElEsGdttfwpzi
         WVPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8NJuSzJvjWc52xwGXYUA4Bg+AK84uWxoHE6r6RwVGko=;
        b=WenousJHWu+o98ie6EkW4lOTk4O1ROQKgxlsJmUg7UIkTPGFdL8bm2LdpOUbblj3Ei
         tNHxYMQBjakyWz5RtovftcQy+gTgT7PnXzZ7N1JX/7e0SL9eHJlfA8lQbTptXXdL0hBC
         ulYc125DJN+lOyhLH1iFEvQggPmjqJF8wnbM0/dZHVrcQHRC7GelrY6jwDqUSZRPAMVh
         ttRCyhhBHcjki5TcPNsrKQX0zirowaF1VN9yz5nsSNhAD2kIr13N/UT+gwKCIScujPfB
         fsiBrfKrSgBJXaF3nRvzNbaMcukcLQTVG9lTxrWd8gPk4YYiHWdjZL/dkksC91wdJTrf
         0OPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j1qdUDQm;
       spf=pass (google.com: domain of srs0=ouxs=cj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=OuxS=CJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 134si443316vkx.0.2020.08.31.11.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:17:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ouxs=cj=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7AEA22071B;
	Mon, 31 Aug 2020 18:17:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 0902835230F1; Mon, 31 Aug 2020 11:17:15 -0700 (PDT)
Date: Mon, 31 Aug 2020 11:17:15 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/19] KCSAN updates for v5.10
Message-ID: <20200831181715.GA1530@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=j1qdUDQm;       spf=pass
 (google.com: domain of srs0=ouxs=cj=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=OuxS=CJ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

This series provides KCSAN updates:

1.	Add support for atomic builtins.

2.	Add atomic builtin TSAN instrumentation to uaccess whitelist.

3.	Add atomic builtin test case.

4.	Support compounded read-write instrumentation.

5.	objtool, kcsan: Add __tsan_read_write to uaccess whitelist.

6.	Skew delay to be longer for certain access types.

7.	Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks.

8.	Test support for compound instrumentation.

9.	instrumented.h: Introduce read-write instrumentation hooks.

10.	asm-generic/bitops: Use instrument_read_write() where appropriate.

11.	locking/atomics: Use read-write instrumentation for atomic RMWs.

12.	Simplify debugfs counter to name mapping.

13.	Simplify constant string handling.

14.	Remove debugfs test command.

15.	Show message if enabled early.

16.	Use pr_fmt for consistency.

17.	Optimize debugfs stats counters.

18.	bitops, kcsan: Partially revert instrumentation for non-atomic bitops.

19.	Use tracing-safe version of prandom.

						Thanx, Paul

------------------------------------------------------------------------

 include/asm-generic/atomic-instrumented.h            |  330 +++++++++----------
 include/asm-generic/bitops/instrumented-atomic.h     |    6 
 include/asm-generic/bitops/instrumented-lock.h       |    2 
 include/asm-generic/bitops/instrumented-non-atomic.h |   36 +-
 include/linux/instrumented.h                         |   30 +
 include/linux/kcsan-checks.h                         |   45 +-
 kernel/kcsan/core.c                                  |  238 +++++++++++--
 kernel/kcsan/debugfs.c                               |  136 +------
 kernel/kcsan/kcsan-test.c                            |  128 ++++++-
 kernel/kcsan/kcsan.h                                 |   12 
 kernel/kcsan/report.c                                |   10 
 kernel/kcsan/selftest.c                              |    8 
 lib/Kconfig.kcsan                                    |    5 
 scripts/Makefile.kcsan                               |    2 
 scripts/atomic/gen-atomic-instrumented.sh            |   21 -
 tools/objtool/check.c                                |   55 +++
 16 files changed, 697 insertions(+), 367 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181715.GA1530%40paulmck-ThinkPad-P72.
