Return-Path: <kasan-dev+bncBAABBQ7PZH3QKGQE77SQFYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 56EBA206554
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 23:44:36 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id h10sf5889103uao.4
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 14:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592948675; cv=pass;
        d=google.com; s=arc-20160816;
        b=tByX40fBNNi7yhtXVK0gy8+Ik3SoS8/2V/KkGb2NWSw0gYvDblE57pUgl3a6CErUFq
         ZHOY4L9IwVIearHM6fpiz1m8BU7Ftz+WWOiA1dF5zrb+rZWqdG0u+cypIMVbMoKTBECQ
         6K8H2+jsphP58Zro18jF3NXeoPVvZC20VaX6OxQX830lCUSPsyUnLUDGERMs+J9KqfpC
         9s6shzwi6mo8T1jIoS4zII+uXNbDysovmKFEnZ7E7zM2ixNi0vN95T22gcQ4hMRJLVct
         Pwisfo7WsezS38TxMuyBmovx/b1emgRNbenH6aRt/p/Ix5P9U7azQOBY8m8sIq/FY/p2
         clbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Ar0GaSOt5VOsXEMmYTvPiwx31tf3IbZiQI7IxIWPSA0=;
        b=BLc/05MSjfakbDvQLPGRbM7G084Mv2goGjg/+OFn8kvTGtGYmcuj63HC0SFQLjPwlf
         YVSfw88ME3gfDf4yHPsVLa0kOWzeThbn32Kr9xxELqhdb9ameA2Uw53/suKx3we5SbFO
         9QEnU10nS/6x9fyhw54D5PCOhntdMLfKvurvMRhHzewXy9kdw/UJ27sonW2Ampq/fg/+
         2JVjUuhopJuEnSkYFY7uK1mzie+bUwanhF9Qg/DTCDjZnMWfS+gU27/9G3XV9UAdMHIq
         PtYc4+jKBrUtd9sxTLwAmx0psU1YDBCv4w7l/+x6z5Satwk8VZCMqxkQUsmka6lEW2eE
         tNGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=M5bJeLzL;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ar0GaSOt5VOsXEMmYTvPiwx31tf3IbZiQI7IxIWPSA0=;
        b=qAgRCT//KEvF+kzqbexZi7wvBMecs7KBLtZRF6JNTkrknmE1IIWuyuuCcmMXCxLCx3
         WP1FwkKwBHxrDWCni3gRnoCsmbxgqfv6ulSPnpHxVweWtqkKuQDB59VPIWJ//a6Fec41
         jTXa2F2rmZEn88GL1yWKmbljgBgts6N3wiuP1HQoi+JyOQpenE0WTe77ULSSs9yrR9tw
         LbZfOLx7ydA+Qoi/L99o+dWT9xRfvzkYp4Gdu2CQJBWzlQK3OpeKrdW6J9a5WkHcFrEr
         rIoFo4EhV8pS0WAFtG6ICADvOFydwFcMar7XOuxQLxs1lmYHU3/mqDyKZgKar2+ftiGH
         xyYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ar0GaSOt5VOsXEMmYTvPiwx31tf3IbZiQI7IxIWPSA0=;
        b=Xyu2tMF5O0OA6GLwpz6EPoTZmgXEVHFAKB/GhYRhEHgFFPEaPcii2ptcIUVp6NUpU6
         fp37Q6MWUUxDy56uj4QzGDY97PAm9nlPIw+XH3baGGHLp9pH5l1EFlcF+cd5aZBPUlYy
         FUuGF3nicKQsXEozt7CY2ae58n5TWKy4V7wBZ/3CY/7zwdTZkDir/d2AG7jTB28h/dVq
         zVarrTTFjek2YmfHYz5m79/ordy2oUXKiBY3eLfewf71K92fMCwQnbPhdRJuliXnR8Kh
         TZeZle0L1+N5BBc7/cmxm1S9cfdl1MkSizTU7wiRhyfa7jBV4bTyX7AhqBiEHfMoY4yr
         1hkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300vf/NZKkYwXgD6uYmbvRItJdYEARKym4FmTBlvbkKfopJU4rL
	SFhtnEazOJ7zPyszArQIC9Y=
X-Google-Smtp-Source: ABdhPJxpETDnKa0+AkcCS0iqXoDn/La2h5EyFgoIT+5Mb8ldrZLlO1/R9SDScI2+/yU0cxTs7lOxYg==
X-Received: by 2002:a67:fb85:: with SMTP id n5mr21418081vsr.43.1592948675368;
        Tue, 23 Jun 2020 14:44:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5b4d:: with SMTP id v13ls1474028uae.7.gmail; Tue, 23 Jun
 2020 14:44:35 -0700 (PDT)
X-Received: by 2002:ab0:2eb5:: with SMTP id y21mr16273616uay.92.1592948674957;
        Tue, 23 Jun 2020 14:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592948674; cv=none;
        d=google.com; s=arc-20160816;
        b=xxO/bcpS5QwkBpG/i97wTCKJ6sVDknHVWywzxOcC7pxpQNnrPqifeWwq881mX/5ldo
         94c6/jAGCwXypd7hLD+3W1JItwtdcdGRAIyvdBi/FbXKUWQXYfcbMcm5+3PWJlFLB3p3
         3zRAIgHXwdjUTez2NGqYHc2jma21lLf4tpQO5bbWySLoRJZKsbYnwakP8mj8EuWyzTxG
         qc5uuw7HWh+Nj0L8uqu+WYQUVs/n8nVBjc2LWy9X5l17El1IzZExtxpSTNM24llED2Kh
         rX+IXOg2VkeJduKjuO+4pPAiN6KrsXd97SoWanR6N7cvVozQn5Lp+4fcuHBGdV9V0pCg
         ZOzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=LzBQRIccm/EF78osjeyHIeU0L3SqR6HwGUszFirrMyE=;
        b=I4ybUYDWD6y+tPEEdTufYUiGZQFpmlrD6yCzPxMvIZqHVeA4DOnD9UPSv4zjUzoEdt
         lwYMqFfmAbsrEo4pI0KFz/OIHmo54wj7+sfaNuN+Vc0k/xePlXLv7KdLifxbIb8IcjAr
         TxT/cca5Rxd4uaPZ3Qk2NeQGKNl45Z45is4J3TrQan4S1sJFSYv1Tf7I/bAzcikh2Z06
         NcUmqD9Xkf/50lr7NEutOv5EJE7WfTRYl0aZzvL2jVMPkfqS0Of/7W4MI9QWQAfymhA6
         7usIN7BqHLVskqMWBWEZZ60MwQKWA8Ju1BLJvOyZd28q9FEyzRs59IE+/KyPVYsEZF/R
         ezfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=M5bJeLzL;
       spf=pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v13si882246vsk.1.2020.06.23.14.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 14:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E58EC2078A;
	Tue, 23 Jun 2020 21:44:33 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D19AD3522657; Tue, 23 Jun 2020 14:44:33 -0700 (PDT)
Date: Tue, 23 Jun 2020 14:44:33 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200623214433.GX9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
 <20200619221555.GA12280@paulmck-ThinkPad-P72>
 <20200623204646.GF2483@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200623204646.GF2483@worktop.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=M5bJeLzL;       spf=pass
 (google.com: domain of srs0=ovfg=ae=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ovfG=AE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jun 23, 2020 at 10:46:46PM +0200, Peter Zijlstra wrote:
> On Fri, Jun 19, 2020 at 03:15:55PM -0700, Paul E. McKenney wrote:
> 
> > Just following up because I don't see this anywhere.  If I am supposed
> > to take this (which is more plausible now that v5.8-rc1 is out), please
> > let me know.
> 
> Sorry, I got distracted by that NULL ptr thing, but that seems sorted
> now. If you don't mind taking it through your rcu/urgent tree for -rc3
> or so that would be awesome.

Will do!

Just to double-check, this is the patch from you with Message-ID
20200603114051.896465666@infradead.org, correct?

Or, if you prefer, this commit now on -rcu?

	5fe289eccfe5 ("rcu: Fixup noinstr warnings")

If this is the correct commit, I will rebase it on top of v5.8-rc2,
and if it passes tests, send it along via rcu/urgent.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623214433.GX9247%40paulmck-ThinkPad-P72.
