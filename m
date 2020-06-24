Return-Path: <kasan-dev+bncBAABBK7FZ33QKGQER6VEI5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C1D37207CA3
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 22:08:12 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id e20sf3395250ybc.23
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 13:08:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593029291; cv=pass;
        d=google.com; s=arc-20160816;
        b=i65oPq9cS5TSEJchs7ArnLP12jdFTKAp4j7q9ZQoMAYtYFYfOYDNBCYQkyS4FYda1L
         tt+vUJgDU+21rONNn18NW9G3AzJ3ShKncGcwcA5QpzHgJjo8zjDkCACFrQagnywCR7Z4
         wr2I80RB1grTbosuYZgtLEK1yMj6gCwC12Ppac+l9AwGacv3/LJ3ZgO+jUE00DmXeaq1
         6OV9wTDjgh9wvdwEjOs1IQv4Vez5QuVBblQtJ11cBwoFwkgJE45MtJBVVwXsabGk4kkD
         Jxs3Qe6KJmlr5lvO36+X70Xu4JCumr1FOpR8ATsVe+f8g0d9+BJe2CJRrHXgWz8fryig
         AXew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=3igR2X3Mp+59+oSlfITFZ1mnEYcHN/NxrrRoFwsAhZY=;
        b=WeIxtTWaeWwEqQQd3Enfb9St4hGIaT/MINXHP1EZXwzfmEt3OjlRDp/qL2HuK7r1Xm
         e8wivg2yVYG12i6f4cIbl8Mii7B+GgSf6koeJ6bBLlbiameExC5UW1pr8XLdV2hDLrOq
         dY9m72oWEDH3qThFSyc1foHx9iIZFAk9j3D4XL1yWg4gCAASnGe1E+NX/2DKFXHey01l
         OUlI9gtioHjaNwOTBqDiMyg/udjU4+24/4cbUnnGrzIoTCAWKtC4d+TM+gwctoNUjYdh
         KSHSWwh9BTBBtecsCN6sT8iq0jTPgoBo2hkaiYfeoMrrlctH38BTeTfz/tCW1WXSWMQD
         iy+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UXDlpgRO;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3igR2X3Mp+59+oSlfITFZ1mnEYcHN/NxrrRoFwsAhZY=;
        b=mV1dA7kz60uaUg/1CwJb8P1Uh3+Y33Ry1yXhOgupnCiCpi/yW1O6ZKUpT9hq2NtcUE
         8VqJdfC16vO8YUzL/L9UbatRzllqKgzFD6G7Eb4T6IywGKEw3gHbjmmfquxG8qXIebl+
         xQqwGn0AqH4whHNI3Sfz3EZxKeJ5QkDTVaJ7V9+LvzhoOzGbGi2pS5Bt8rB4yf6hCT+M
         69yqriInu/R2Hsk18rI8U5I9SYmjm0sabk0YVLufpFQH3WhEXn5ZCkmoyUVSzV5GU342
         YvZA4UDnIpqmPNepZyfiWG+XI0KV24Na+Qq2rjuOcNtt70nEUoMr742WgyE5ii/3fQQt
         UPeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3igR2X3Mp+59+oSlfITFZ1mnEYcHN/NxrrRoFwsAhZY=;
        b=R6jrftQctxucbjNeguGjkZIG/QTFhU/ppNJGGVhHCnNEUxeykOvXlq8PLDnLs+ex9c
         8j00yqFgZdFKsE+HsluIUDiF/l0HwOP1ULJTel30T+LWPE8JvwznZPILuGvdzPbh0xdE
         5Btly7njHI1rbRDm+s4D4s3ttAe1nCyP9joVuVq9PadkqyfJxc/7j1xZLmIR+Y5Nm0Gl
         xpRuFy9ElNhqStYDeMsV+LiiSeckHfZM65hx+xesr6PdDNd/OyUB4zPnCE1DXWXexYxz
         SaoU+en7D9+2gmlq2+Lu3gaTsVLI84WnvelXZBVS9aqD6gjLcOhhUd9hmS8u1B9Xjajw
         f1Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313O9eNuOgsHsETxNYEyeVEowynP58NEAqkFQ5XWaVfBZ+/q1zG
	FJQcYmiOcX2u3moH0/vwmIQ=
X-Google-Smtp-Source: ABdhPJwe17KCbZB2/tg7WfoMAxBIaXqyjRNxtWDATicqwjhOJGNGVQzwgraHQwU1QO4b1AhW0ILiuQ==
X-Received: by 2002:a25:b8c:: with SMTP id 134mr50141015ybl.428.1593029291751;
        Wed, 24 Jun 2020 13:08:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3412:: with SMTP id b18ls1188739yba.8.gmail; Wed, 24 Jun
 2020 13:08:11 -0700 (PDT)
X-Received: by 2002:a05:6902:514:: with SMTP id x20mr30833586ybs.160.1593029291416;
        Wed, 24 Jun 2020 13:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593029291; cv=none;
        d=google.com; s=arc-20160816;
        b=CCxcRW3ZAmHgE+thDQ8VZvYSH/oNwL1y5gpMOaFJU/g9iRsTevdfY0Hz8i2CjudwfW
         Ui7KviTNYUNODnMc/YY6WMY6DMHyad5WpGytp1+GqvONVhmowR5yY0kxzq5gY00mzfIo
         oqSlpD4W+ypfk0xfk9qHgG0kPB/ptKz0+qsvApjVKMSHolARK4X6p0NTrk085j+9CWJZ
         If4inZt/ntmevWEZc2Z01XlHrtYTCCodS+YX0u3oZrdNniyoAT0WwFGf5EugbbqYQvHS
         uhXO/6r929qORDkkkoZrKcqpfLnvBoa76tUODRGTwaP5I8K8UDnBa2VliBezbFRo0TSi
         wQYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/ODOCQgQlqdRdNCDCPZAGKcmoWhH62MWrZonaAkC52A=;
        b=VgC/ydbuVTtZwMCPFtoUx2MIn3f3UQ91sObbhs5eADuf53v3FkPJ56eXXyB/fpPnfg
         77Nv1t419vjAXp7XfU/ab3QCLwpELtNPjSh6wF3z/ifh/DYQogcwxYJF1SFEBIUaA3qI
         wNicoKe0xJSFzEWGIcRdAG1fSL5YkKN7jVBd6aB8VpebsZvNyJerziobxicUlqbNvXFF
         NwX6iYVItlFp369lYHrvpAsnbNF8k3n7o57JAx+7JiWmXLH6vGALANb7VORWlM0AjfX6
         H/+/UoaTaNxGj7NXLOX/Nr/Jof+RtNAiMR6Bg+8YPI3zjPnyezx/kcSOHd6deptC6SXT
         uCPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UXDlpgRO;
       spf=pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KPUj=AF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v16si1755658ybe.2.2020.06.24.13.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 13:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kpuj=af=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 69AE92081A;
	Wed, 24 Jun 2020 20:08:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 4EEEC35228BC; Wed, 24 Jun 2020 13:08:10 -0700 (PDT)
Date: Wed, 24 Jun 2020 13:08:10 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
Message-ID: <20200624200810.GA20999@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200623004310.GA26995@paulmck-ThinkPad-P72>
 <20200624190236.GA6603@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200624190236.GA6603@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=UXDlpgRO;       spf=pass
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

On Wed, Jun 24, 2020 at 12:02:36PM -0700, Paul E. McKenney wrote:
> On Mon, Jun 22, 2020 at 05:43:10PM -0700, Paul E. McKenney wrote:
> > Hello!
> > 
> > This series provides KCSAN updates:
> 
> And three more, so that GCC can join Clang in the KCSAN fun.
> 
> > 1.	Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
> > 
> > 2.	x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
> > 
> > 3.	Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
> > 
> > 4.	Add test suite, courtesy of Marco Elver.
> > 
> > 5.	locking/osq_lock: Annotate a data race in osq_lock.
> > 
> > 6.	Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
> > 
> > 7.	Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
> > 
> > 8.	Rename test.c to selftest.c, courtesy of Marco Elver.
> > 
> > 9.	Remove existing special atomic rules, courtesy of Marco Elver.
> > 
> > 10.	Add jiffies test to test suite, courtesy of Marco Elver.
> 
> 11.	Re-add GCC as a supported compiler.
> 
> 12.	Simplify compiler flags.
> 
> 13.	Disable branch tracing in core runtime.

All three of which, I should hasten to add, are courtesy of Marco Elver.

> Please note that using GCC for KCSAN requires building your own compiler
> from recent mainline.

							Thanx, Paul

> ------------------------------------------------------------------------
> The added three (#11-#13) only:
> ------------------------------------------------------------------------
> 
>  Documentation/dev-tools/kcsan.rst |    3 ++-
>  kernel/kcsan/Makefile             |    6 +++---
>  lib/Kconfig.kcsan                 |    3 ++-
>  scripts/Makefile.kcsan            |    2 +-
>  4 files changed, 8 insertions(+), 6 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624200810.GA20999%40paulmck-ThinkPad-P72.
