Return-Path: <kasan-dev+bncBAABBK7AWD3QKGQEOHTBHMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B49382000B8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 05:25:32 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id y4sf3593331oto.15
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 20:25:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592537131; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwFkoNSMYr3kceSNZdgW+4F3cuUMTR0IGsak5zPvSfxVsprXB8iIxH3YccRvhuqa4p
         RV79AxHInbvHTtSDdVIEbvBk708KFpsSHakyUUDjuGIHq41z6yVPPn/bgyNweWZJjddS
         zdlgDe4FLLdy9EQjmoEH6lndX91lbBrnrqRUhPZpeSNR2SLyeikZB0wzpF10aAPIsbzN
         4u6y+yzhs7LeSspL0yTKVWZNmSi8Xom6oY60jgWY9H5tfShrZq4YkrJYE3zhjc5IdezR
         sd7iRsznNn0Cm9xKS3fko7Hq+QOw+0kX5H+R8Opu/Syh4lbrjiM8Igf98iGgxeYp+0+d
         ajTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=vQsVXQaovfc9MgrA7v2LC0L/gXxZKqYE2UvfhSDO+WQ=;
        b=GbGZhNiYydVOLNinvBFFnMQEzwI/Gl6kcQ+Olvf3NNuCSDsdvU7aLj/MXiYrBKQrxQ
         0e04WxBgYf8cga2xRdd/e7ffPuwPwE4w5HSsgBD7gKuj6zH0n0whBhmINgGGFmEAIisw
         ahcRTDjbkFGN1n+ugtz4PZKcEpdk1LJb53WSNJW/vbEfj0B68Ti/+uANBXXAMyeJ+gdy
         jEaIRdm1Xus84aUgtWlVU2Eg6BrNUaoPeRbmzcTgcWrrnSmbGo/C13WIr6jtlv+Cg3ek
         TM9+ZvWImEP3KvAEzwkd7z0f0SByhEyJWWVIgY25BZYxn5cIruTkhXwKAu0EHOKRG4hK
         uA5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TwCCwEYA;
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vQsVXQaovfc9MgrA7v2LC0L/gXxZKqYE2UvfhSDO+WQ=;
        b=tWpChQ1k4Ux5A8NIPbDOiOC+tbrG38eDNmvQFpjtkOki5qT11dxZ6QdynDVPti2zgM
         ymXwFwmD9ELrHAf6ClX03oG/fdmi0s7+j8PD661yx0d0WiizR/4pMDEzZNz9ZWvwuPV+
         14yB3HwlVc42YNQm4l6bzyRBH3lsY5jK3lZceygrX4fXiIQ+oxqMkUwolw9KjHOF8p/g
         uTuUtIYM22E3+Zz3zxyog/mAsRiQfPeDED2fT7HoymuNoyDLbe6MLano5xc87pMxGRiP
         +reB4J78ohJrL8yYBZw4CAJy4oZB7H5IT3o/1HfOtvLWWpennaPdN6MKEvdbxcZhBXrk
         7ikA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vQsVXQaovfc9MgrA7v2LC0L/gXxZKqYE2UvfhSDO+WQ=;
        b=MwzUxawphq7pcxSf5qrMWa4td0YazoflPBz/ZhMIAwftW16Qn0+Oa2BiZRK/CWX83Y
         86mqLgON/PpVQJr18X+3olYBE3GCtA5rMlLfKPun4T/R5yC3S9iw/0a91gJpIDrOcYNt
         t8tVQTmd1CveFV9erAQOJXhTaf3Zdkuw8KAWRqzxNl60EudMt89+mvYImDaUPj687cOC
         vx3nSuHK+YQyVVMCBrzeS1Oyr7fufQI2X0kl4UQjgYPgTGu4Abh/KgfZBMmqbunqN02V
         W+8rfklqNT7Bw85RYxZHlZ/QJ3kte3QPXJjyLM4Bub892CEf1dH+Lj+8wJW3ucx2R9BX
         3Sfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hPnxTS67JD8USmlGsvjvTB09c1vZYLoHMV3CZuvNO6SumFxXH
	zqTuzq43n1iOPdXi5QdYOT4=
X-Google-Smtp-Source: ABdhPJwGazUqMsP/OuSdATGQbz+kaMHrP3QCfg54vWjIwMiHo2PoQ/OdrjN3ePq4YhGpDceyzGjTSw==
X-Received: by 2002:a05:6830:120f:: with SMTP id r15mr1372505otp.348.1592537131721;
        Thu, 18 Jun 2020 20:25:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:544a:: with SMTP id i71ls1619200oib.9.gmail; Thu, 18 Jun
 2020 20:25:31 -0700 (PDT)
X-Received: by 2002:aca:5dd5:: with SMTP id r204mr1723400oib.80.1592537131428;
        Thu, 18 Jun 2020 20:25:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592537131; cv=none;
        d=google.com; s=arc-20160816;
        b=xNIHXkvzteIij75IYIQAjtfAK5GDyKarx3YhgAoHpU8uD5O9WDv0IjhHUxzIwCV9pp
         FICvWuVkIhIQzb3G244815aiOnwN/4HQscauov2XlJzOFPRFtw5kHZNwW+c3G7UWCc8+
         oozgbfDX89qb/k3wBp6AZtoRKpih1RdcR3H82JRNMpNrEZTtDnhXEJvlAwSMRNpjdGqo
         dVO/zfaYfT/hQd5y6dLYX/ChedJl5AXNsNYbZFPj7XI0VNut2Tj8piYQgXMqQQG1CFm+
         LhFIzaptK9DGASFM0nwZ3AneVfGr3kH4FSJg2XFJ4jsOb+0CiyCV0STgFOTZkp8TPDON
         O7Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Qs1TtaP610pp+KdipDsoAPb1HZSWnGXfJphj9ixdBx8=;
        b=OQ8Vz/oA2l+voMjYVXsZmhJxPtrvf4/0P4FMDGmOvbKAHL1zAT4EXAsUDiHFkhO37p
         6m8ijigXsoFmxiC2TssuQjFDkTpUxGfceSghWvsKjirO19kG+Z00KD17cYsXMIGwqYcw
         zhVmTVmdP/rm6EtzpeBuXClrPed0p9sg8+n20Wq2+759PMiE8qgnkm1X+tA2O4EsktC0
         ByMoxVfzUNqYXvUXAseq41/bGvhkfRyOnKxt/TxbN1ItS0B7G/kciahGxInjvKjBrUPi
         FH24FpAM/0G6sW5ID+d99mvDOyk9Uyr+aDo7OFCnDkA48NeOYmSdznWmaGReT/gVcpPZ
         2w9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TwCCwEYA;
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c22si434481oto.3.2020.06.18.20.25.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jun 2020 20:25:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8E7312080D;
	Fri, 19 Jun 2020 03:25:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 73A58352264E; Thu, 18 Jun 2020 20:25:30 -0700 (PDT)
Date: Thu, 18 Jun 2020 20:25:30 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de,
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/3] kcsan: Re-add GCC support, and compiler flags
 improvements
Message-ID: <20200619032530.GI2723@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200618093118.247375-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200618093118.247375-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=TwCCwEYA;       spf=pass
 (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Jun 18, 2020 at 11:31:15AM +0200, Marco Elver wrote:
> Re-add GCC as a supported compiler and clean up compiler flags.
> 
> To use KCSAN with GCC before GCC 11 is released, the following will get
> a stable GCC 10 and cherry-pick the patches required for KCSAN support:
> 
> 	git clone git://gcc.gnu.org/git/gcc.git && cd gcc
> 	git checkout -b gcc-10-for-kcsan releases/gcc-10.1.0
> 	git cherry-pick \
> 	    4089df8ef4a63126b0774c39b6638845244c20d2 \
> 	    ab2789ec507a94f1a75a6534bca51c7b39037ce0 \
> 	    06712fc68dc9843d9af7c7ac10047f49d305ad76
> 	./configure --prefix <your-prefix> --enable-languages=c,c++
> 	make -j$(nproc) && make install

Unless there are objections, I will pull this in Friday (tomorrow)
afternoon, Pacific Time.

							Thanx, Paul

> Marco Elver (3):
>   kcsan: Re-add GCC as a supported compiler
>   kcsan: Simplify compiler flags
>   kcsan: Disable branch tracing in core runtime
> 
>  Documentation/dev-tools/kcsan.rst | 3 ++-
>  kernel/kcsan/Makefile             | 4 ++--
>  lib/Kconfig.kcsan                 | 3 ++-
>  scripts/Makefile.kcsan            | 2 +-
>  4 files changed, 7 insertions(+), 5 deletions(-)
> 
> -- 
> 2.27.0.290.gba653c62da-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200619032530.GI2723%40paulmck-ThinkPad-P72.
