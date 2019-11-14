Return-Path: <kasan-dev+bncBAABBIVEW7XAKGQEJV64OIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 57920FD0D0
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 23:16:04 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id m12sf6577571ilq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:16:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573769763; cv=pass;
        d=google.com; s=arc-20160816;
        b=NG9JtCzTgsvk9TwNxhsehnBh+jcziKL21PzO2Do1ddK2AqqjKtOIZF20LU5iIeXm55
         gmEB2dBTY1FHhko5UhDVtjX4/pxrdzp5l5i87DGDFbqV2F5uvTc4n9ZGI+0VIOv0tc7Y
         esbQ6t1mKo1uuvr9YLwRviKvAl7s0I5LPKfNT5JGmi+gaqK91ZXXC+lg3r4F23mNJf0+
         TwmEf//j5au5ONyfAcDG9FLW8wdtaofLDl6gqBLhNnxAxHH6Iyv/9QcMiid0JUaOfTJ6
         pJGCjRmKlNwwMMaQQWZozmB/k3J9mA35lk9a9FuR/QyEOoAvP4TGfvvbHPhh985BJv/7
         Sg5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=NM7daOzqTmPnghiK51yPHUaE+zXxrwuYgzCA09PYbHo=;
        b=dLM04OjvslCgS4l5zaQ0t9kSWF3DNqxe43zJ143hNlJiPpWomLLLMDU1hoWCxpGmfY
         fi1rODI2wkkePyDsleCK6uNf58BebkeomV/c30zfX83Aqh2re7ZmwA3DutIEs7Jelgrl
         TW5csaX5SnqYDCS8Rp4EL+vj/++e1hHsDysZKpw8CwFY0wONtPR8wxUlblAo2lr6h1ph
         NinAL1wXguA8CtvCOG8HPc0d/O00klTWFmBLIDIRvstzjDwNHlsdpL80ogPeDzdB0evh
         8bBbjI4gn3bqEjlSwYJAiELYMyqg9zO9mkEJygk2G3w+ZE3X8SvHq01wCs0oc1sDspdx
         Pn3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=evw1x+V8;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NM7daOzqTmPnghiK51yPHUaE+zXxrwuYgzCA09PYbHo=;
        b=QWgwMmA6BYSKGt8Rewn8ZpT+B3ghosjN/e5P3aG1Fg9C8KVRTcBz2/RCnJsge9UNqN
         ACM66kPX8F+dtdjI/82aL7YOOl0nyck3fpGNAHSd6D+6ED/4ImidIGiJ56ptsYelyAJL
         G9WEYZEd6PtDeuMliVlff+oRVXxSl+B7bfgioA9ehjRsBD4iH1M59WSl7MpJkJ9+kzP2
         7O8hKK3bUtRwYLk9YJgSdP8qBl9sxKVsbqBWJeUqpLk7+Wl70G63srs9hpUR2BfIya4m
         6DaGQg2GDGoSujckLq93deRQz+TOvYzwYH+tgpm0Ar5bgcocL6Jji4F8PX8HRBiKXKqj
         xIYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NM7daOzqTmPnghiK51yPHUaE+zXxrwuYgzCA09PYbHo=;
        b=amu4kjRSeo7pcE6u0D0WpwmOUueclxaCkOVnKITdY+QxFwMdAgnPmlc2joveQJ9aIo
         a4tnLXJ/N6DWzvHVvkzIHBrKtcfZ9vPoYzciZxP1MqPFjTaOEv7qG/iWj4x0UwZ5HwUz
         UHc16m+YGyqs5hqnzPaoexwLAZS04vzk32GqvtSaXv3ZuAsVv870z6V2x96LtyPRO4OH
         MdFycky6aclywUL4Fkktx+150AmSrjLbKUYcvQr2b8hk99vvXGibh8unaPRpSNSs5ph2
         i1LTX4BbFZLbDpPeDYdTBCTqhgHPPibwcA/02pBvnkaTvuG3VNDZCac9JewYg2twqSH9
         ejwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOaVN9BCWAAHonLyF1N0dFy844xoTzfXjc0EDj/c5C3Z8bqXpt
	WYlUlYzSeTP0/+yw183TgS4=
X-Google-Smtp-Source: APXvYqy513s7UqVyXpdVcCXPzCFJWuMH3HzFzrL4a0UG6LdQ1jiGWmKt2G23Y6jhIzpfjeUzFafv1Q==
X-Received: by 2002:a92:381c:: with SMTP id f28mr12489732ila.169.1573769763036;
        Thu, 14 Nov 2019 14:16:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d7ce:: with SMTP id g14ls1442359ilq.13.gmail; Thu, 14
 Nov 2019 14:16:02 -0800 (PST)
X-Received: by 2002:a92:7e18:: with SMTP id z24mr12312710ilc.276.1573769762675;
        Thu, 14 Nov 2019 14:16:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573769762; cv=none;
        d=google.com; s=arc-20160816;
        b=RRkDpFEdRu9pYhtNKoKCNb7B+aewQnFWFi7tGjBwOaqkpl3hYbnWMpxccNoenG9D+c
         /gPDq/AZIp7H/YMNIYM/PtgFm5KAKaN7a7nkl5UN8u2/7Hy91MGoxqHhxEr92W4ZfiQg
         nAX1/ld+t+uKz7X7/l9GjL7vmpGghXAM+bcQnH9g1diW0cUnHEg+8cxyv8I4ZgB7ENSd
         +qqfeAd5W/i1serSYtxfpQd1uGAwtfRhZOfzOFpB8ehPEtsbdTX12nkeX90hLQJJAyH1
         ZWgfDLiRPbyZV+D1sKf4K2k+UcAwpFgEReqL8EO89iUxUQbfK7fmhbpxMMmTGnKyAHUT
         ZgIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=kIhBDy7l5/6EzC0DbsJqQDsSguGXBOrvOQloopQTjik=;
        b=Exd5/ZzaDR7OjM2LqFf/rSHnkG4+ylJXCpwTlYqg1w85IzEXmALVkvf1odV4hNzlTX
         wZvkRKJbvwDhuMjxZaDDbxS2TfGVog16+mZWjutcKcIRZMTKydygSWr5XxekedZyK/28
         s4HXS4hNiYmW1ASYhatwudC3NCBXkE3Dw+a+10ZMF0zosem7sl7fgF9upXtOY9R6zrwL
         aq0eK+Z0mkts+DcpMdHhZXRdj4Lh0bdoc5uT+QdKGn+FfHTXWB2TFg0z4JpX8MSBpW1+
         HLOJwhR/GPLfS/dKsOwqlRcHWpWinLb/hT5AoWL5H5ucQUGmEg7zUoHP6RqErH/MjHzX
         YiJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=evw1x+V8;
       spf=pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x8si490185ior.1.2019.11.14.14.16.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 14:16:02 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B271420709;
	Thu, 14 Nov 2019 22:16:00 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 87E8835227FC; Thu, 14 Nov 2019 14:15:59 -0800 (PST)
Date: Thu, 14 Nov 2019 14:15:59 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, edumazet@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191114221559.GS2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191114180303.66955-1-elver@google.com>
 <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191114213303.GA237245@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=evw1x+V8;       spf=pass
 (google.com: domain of srs0=h8vx=zg=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=H8VX=ZG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> 
> > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > only enables KCSAN for x86, but we expect adding support for other
> > > architectures is relatively straightforward (we are aware of
> > > experimental ARM64 and POWER support).
> > > 
> > > To gather early feedback, we announced KCSAN back in September, and have
> > > integrated the feedback where possible:
> > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > 
> > > The current list of known upstream fixes for data races found by KCSAN
> > > can be found here:
> > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > 
> > > We want to point out and acknowledge the work surrounding the LKMM,
> > > including several articles that motivate why data races are dangerous
> > > [1, 2], justifying a data race detector such as KCSAN.
> > > 
> > > [1] https://lwn.net/Articles/793253/
> > > [2] https://lwn.net/Articles/799218/
> > 
> > I queued this and ran a quick rcutorture on it, which completed
> > successfully with quite a few reports.
> 
> Great. Many thanks for queuing this in -rcu. And regarding merge window
> you mentioned, we're fine with your assumption to targeting the next
> (v5.6) merge window.
> 
> I've just had a look at linux-next to check what a future rebase
> requires:
> 
> - There is a change in lib/Kconfig.debug and moving KCSAN to the
>   "Generic Kernel Debugging Instruments" section seems appropriate.
> - bitops-instrumented.h was removed and split into 3 files, and needs
>   re-inserting the instrumentation into the right places.
> 
> Otherwise there are no issues. Let me know what you recommend.

Sounds good!

I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
approach is to fix any conflicts during that rebasing operation.
Does that make sense, or would you prefer to send me a rebased stack at
that point?  Either way is fine for me.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114221559.GS2865%40paulmck-ThinkPad-P72.
