Return-Path: <kasan-dev+bncBAABBTXFWT3QKGQE5642BYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B6DA201D48
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 23:49:04 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id d64sf1348141iof.12
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 14:49:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592603343; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDsorcnp+G+kaWFGVvwJuHWAThexmzD807m3VLZIGz4+ncPYIdSANU0y/kUBI+/qFv
         RzrL7gMB5ywSOmRnH5af4ddZ8u5K3DO5firnhLlyEZEHczQ6iRJPsxGP65g3EpdluK0T
         Mvbvt1o91B/4h5GlMmopQIqeAS9SaETGxfQe6BCvUh7ct1BTjMWABM775WBd+sFePZYb
         OxsxvTXr1eZM0GXwo7Ec2+P+bbGw6OW4+XPQYw7lHO51BS/WmpotL+6YeLpa/8pys43W
         2P1HWLXSOpr9rMsCcP4+wS2Yfg7NB5rYW4ghajIt/wyiXPu8RgfDlpo3cPVOIcf5l2ja
         T2/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=zTO8T+4diR2oJ6kEYOKfhZZESLRjajG0NXsQgLzk+Lg=;
        b=aXGeBmmxcHu+JNQhNRca53c544YHfmscaScmdJHPzu85kbI3kCbCibiOMccJ1kxkaB
         EDNuMq9mIuc6R94d7q1903refwfaoxsDGJBTYHqzMq+AmXsHJvVPrCqvNatr2ggHwfjE
         j9wqSta1UQ6ZE3MDjIL/6sErAGpkBDFZuRdJu0RnF9jGBp8v30xfa+Ohk4/1wz8mIyJj
         2unaTygR7mYt4tHWgxd+TEKA7vCplJv61AhNh4l0BivdXvQrypNlxy4CWKt4d/H6DRHw
         lNkFi4c9cPZ0pjoJ/RmGMh4CJgCqumzjM68415mcHHAy2nzducMeKS5sll5hjFUfLcNL
         ur/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="CDDEq/aB";
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zTO8T+4diR2oJ6kEYOKfhZZESLRjajG0NXsQgLzk+Lg=;
        b=NT84XDgmZpm5lOhWlJwt4b1TjecbjgD3yNCxcZeRv5C50zZUeHdu6/f5TNb9HF087M
         AS29SZORDtIuBjG2DYqSDjD4zMkJwK3vnUAmfU3XktwXXy7DbF+srsDU9N2AsBRr44F7
         ALnHDvmDGsHXqdali9dqMIX1WwP0S8Myx99ZRn+stz0Ha8Uz6MVCFFu5GnWWYd7H0Qdg
         Ae27xVNZxERUZEiK7CD2cZpq9zliG2yGXh1ccYRFfTIFoXtwWVcEmV1e7dUyv27ntX4t
         RgW5Zk69vBY/+GOB1GnK++uZLwr9XkS/8+saDSrRdHLNse3X52oyTwyQFdP/9k87a5Lm
         H7qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zTO8T+4diR2oJ6kEYOKfhZZESLRjajG0NXsQgLzk+Lg=;
        b=EqpVxhWzUrKPxaZTIC0EgM+RyI64d5Yjwar+5U4sDFHbhpin7yj18/r8kM2btHMfJp
         6BvT38Dx8LA4vQtRd5UnHpNxnCgK60+VWIoyaJjQ44ZZJTQTfyIk2k5JWRX1HM3TP3F+
         +ldAgkNiW2x/2J08zvcTxKn0c7Hb2IcSPSh1SMjPNBR+IK375UuZ3/cZ8bnwIxw+T8FY
         YOVAaDthlY4w8iHEShbV7WzDYP1Gmm13V4BAtOQpccEJrRg6EOK7fEyFE9wqv/aZ79Zf
         q+JzmNRS4sAUj5mr5XZThrRjyOkyuGYpsAlHFtpQBHfVBjgxZdFatecDEMS+xHWQ2rDx
         IsjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oAVtPKVoN4p002ivIGeOSad2TtiXIS+hREpc3RWrCTOet+H73
	yQ26kvSMK1+tKuV8gGtD1/Y=
X-Google-Smtp-Source: ABdhPJzGVHxozFQ2jCIpOGmHC+PEvuHfddPQqIxvjdfYau4k5BH6Y5c/Ry2FTY7PMUfbNBQCa1FigA==
X-Received: by 2002:a05:6e02:4d:: with SMTP id i13mr5899556ilr.227.1592603342903;
        Fri, 19 Jun 2020 14:49:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7207:: with SMTP id n7ls2181564ioc.3.gmail; Fri, 19 Jun
 2020 14:49:02 -0700 (PDT)
X-Received: by 2002:a6b:ba8b:: with SMTP id k133mr2691241iof.204.1592603342639;
        Fri, 19 Jun 2020 14:49:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592603342; cv=none;
        d=google.com; s=arc-20160816;
        b=tNamK93JwR0FmN8tU5uCmEhIhyXTXztUumeCL6v2JhLc4wPtXwc4WmiqW39Nh6iy/5
         bncygCM9YhCp8E4ZL13kXw4rhBBMO8B+fn+iYXJY5qJNtle4720jnM/9zgczLVTHbgdP
         0vi2qbq38qBC/stcypmTvTJDQxDqzgtGKXYhsF6FTiZjDouFqm2/21qNv8SG165hACJJ
         OK+Xpv4ExPWTjtaOCoMo6H9xBPPyrbPFhbjCyigvtKdSZ6+88dBIGtLwg7BykbFTvz8n
         upFMd8O0ZHJ81vq/yqcHCbgnpjC1/lJV2rHs1aKSmpBKTT09VTIpby2MWJgICAobc37A
         NjCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TSY6ayRawTnSVEtUI63+aatos+d3e+gryARyXiUey+0=;
        b=aLlbcVSpdXUtJnHVgFyuEsn9w4qJrRZyxRaBrym6+w14m0uUnIV/gMdhZIFEdn17Z8
         CI4OF7vGhLV/E+n3A72fIXk3B4U5FsLZvpzIUdopBTIuqXLBA0stQzCHxRxapBhXMxe0
         paxuPxjqBIGYFvuayRCn8Sc45MfzpveXTfOJEsoznLgcayQ4K2Pec/fxSpoDceYzG5MO
         RdV91dgGuAEq036iFQsX1rvlqAES60EcQ5p/sRBIubFQk2/O8IWM5lvFyxZO6tLl7i25
         1T33NHd/ODNQt1+nr1RnAEyZlXu7ETT4UhUetBmOmtxcn425fGGXHctHNTF4Nk8k9SJf
         8QhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="CDDEq/aB";
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z17si503528iod.1.2020.06.19.14.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jun 2020 14:49:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D4841221F2;
	Fri, 19 Jun 2020 21:49:01 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 74B913522B50; Fri, 19 Jun 2020 14:49:01 -0700 (PDT)
Date: Fri, 19 Jun 2020 14:49:01 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de,
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/3] kcsan: Re-add GCC support, and compiler flags
 improvements
Message-ID: <20200619214901.GA12084@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200618093118.247375-1-elver@google.com>
 <20200619032530.GI2723@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200619032530.GI2723@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="CDDEq/aB";       spf=pass
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

On Thu, Jun 18, 2020 at 08:25:30PM -0700, Paul E. McKenney wrote:
> On Thu, Jun 18, 2020 at 11:31:15AM +0200, Marco Elver wrote:
> > Re-add GCC as a supported compiler and clean up compiler flags.
> > 
> > To use KCSAN with GCC before GCC 11 is released, the following will get
> > a stable GCC 10 and cherry-pick the patches required for KCSAN support:
> > 
> > 	git clone git://gcc.gnu.org/git/gcc.git && cd gcc
> > 	git checkout -b gcc-10-for-kcsan releases/gcc-10.1.0
> > 	git cherry-pick \
> > 	    4089df8ef4a63126b0774c39b6638845244c20d2 \
> > 	    ab2789ec507a94f1a75a6534bca51c7b39037ce0 \
> > 	    06712fc68dc9843d9af7c7ac10047f49d305ad76
> > 	./configure --prefix <your-prefix> --enable-languages=c,c++
> > 	make -j$(nproc) && make install
> 
> Unless there are objections, I will pull this in Friday (tomorrow)
> afternoon, Pacific Time.

Hearing no objections, queued and pushd, thank you!

							Thanx, Paul

> > Marco Elver (3):
> >   kcsan: Re-add GCC as a supported compiler
> >   kcsan: Simplify compiler flags
> >   kcsan: Disable branch tracing in core runtime
> > 
> >  Documentation/dev-tools/kcsan.rst | 3 ++-
> >  kernel/kcsan/Makefile             | 4 ++--
> >  lib/Kconfig.kcsan                 | 3 ++-
> >  scripts/Makefile.kcsan            | 2 +-
> >  4 files changed, 7 insertions(+), 5 deletions(-)
> > 
> > -- 
> > 2.27.0.290.gba653c62da-goog
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200619214901.GA12084%40paulmck-ThinkPad-P72.
