Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFAUSDAMGQED6ZOVSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id C23123A8A40
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 22:39:53 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id n62-20020a4a53410000b0290246a4799849sf201884oob.8
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 13:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623789592; cv=pass;
        d=google.com; s=arc-20160816;
        b=AmugfNHA2vNessnK4QgApslKr8PSn+YyUiD0b/ES35ahM2EmfnboLvh7mjsfbeIUm1
         0WxYoDub/TPAQWL/nj8krhQdVqwx8ms6e7GYw1bELBWkQXPspJLR5TszDkpwkb8JvHpj
         7TN36OtaAlD9lYyKSh94aWMvan9Hd3oqnFN8bGKNbHDdUf547wpP+ulksMFmqcbQHA+H
         eJnod7bjwyJYdhNmoH4M57tSn9ThZpwc9WyV9MBXrZD3FyQh8kzzykdKVrmi+08cMQbf
         jUt5M12F6gLN7HKEqyuDj+/HwF4jllewQUomTy1fPPdc7CRe2gzi5KeEBZ6YkOxcYCAt
         0suw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=GuPvOeKR0nNjPUwYeWebqHDmapeZGqUQZwhnuD0tav8=;
        b=FodnxWLBHFq2jlHsz0K8mF358pZ+ik5tMNJblxqiQDID+v0QGpAPz71iENn/lTSVy7
         87wz/kBdPfKa4HMmIfbvDfHBpPZftjTMEKGG0W4pHo/w7Cbx9s2K4GN81KPznbOCsiWN
         MS1OK5fqV+y/N/Hbnwl1YdZfLOMUH7TxYxR+YT5dbvQ/jOAC60zbodtcEezCtXQMRlzN
         0zmOS/5adRa7TNpWi64OGFYHsHHgq4a6KLOiIa9fb0dz38Q8tve80qRVc3qiaQXVTxSt
         5z4J75IoqS4eAJcyK8siL0+wKIQzFpJD1iXvOTbBlq36swJ7rBZC8rJvhben/V+8E1SX
         nRog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dR8pjiWu;
       spf=pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GuPvOeKR0nNjPUwYeWebqHDmapeZGqUQZwhnuD0tav8=;
        b=Mav8LQ1Lq/nOGPXwksoHk/Io6CkhFXTcZFQwnR/v2w9E3Rs9b87EKooF/nl/TyYOgg
         jEVl+2f6p+dxyl2fccgCCuqCDqu61ez1ovKwgCOrgrJYRbxM+ij9hPaSlC0LjLulD4cX
         7/LEnBjKY07ty3GIDADKerpBD7AQTX+yB51XG+tKHJeobWXPpiTdwrsCt3wa7Kxan/5S
         /f89g39faMYNfbaGWHxkPKVJKgKcIzplu2CZS8c6L8enBbmwj5vsgDoXkcyVd3//up+P
         Bc6IxXEbQQGZhqkjKgiNnefiTIkrP0Ad4tRUvYoO4PmgwYPu3qAtjBltb6v7+jqJS2Tu
         8kFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GuPvOeKR0nNjPUwYeWebqHDmapeZGqUQZwhnuD0tav8=;
        b=Pb/JHUd3DPixKeHiBACBbfxEXLDafUijNxGeDNs0PVCoiHLXCls6mcyTWWjboVO0xA
         SdmTOTx6hI1oJ8r3aDjxT2ZaDcXYXyY9ylO9qCUDGrFU+niLpUqsopouuYOgxCo5aJMS
         Auc5YxkR4SBiZC3F6YYKnMk8NCNFseyfIMa6Z+LR42Sp0CLsec+xRlVbqTm3cI1x75nT
         V3CbAcaXO+gRhhWtzD1FKXOdcHZJbBYeUQNt+rWQiq9Q9nh6NgnLnLF1g6tAr9mQEYOx
         5QFY41IUSiWggXwrEDwdFtrcFX0OF9Y092WtY3BMJm2o/EjWUYVTp48TQuFxhy9cHgVh
         Yr2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xur8evJnuoTvlxql/W7k3wLiRLhhGB7xndw/J4fSMxzhutQwz
	bLlswqX0l0+Kd/Fzrm8VhUU=
X-Google-Smtp-Source: ABdhPJwjS0DVjkD2md+Cr2ptEaLrzUXB8WbyLwPtgrgO+rWq7Y3HbsjJzV9XJCaGHVI2hIgcsZ9hcA==
X-Received: by 2002:a9d:346:: with SMTP id 64mr874339otv.320.1623789592583;
        Tue, 15 Jun 2021 13:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:bd6:: with SMTP id o22ls47550oik.1.gmail; Tue, 15
 Jun 2021 13:39:52 -0700 (PDT)
X-Received: by 2002:a54:441a:: with SMTP id k26mr669054oiw.76.1623789592271;
        Tue, 15 Jun 2021 13:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623789592; cv=none;
        d=google.com; s=arc-20160816;
        b=qyMMn9cHXlt2Onr08G2AucrGCkj6HiFtnnNF2vHk9fvmURDi3PbEXjrkx6QUzSrkqx
         Lvg9eOxKTUgS3Ymxn63Ts02aRHW641fgni5/Cs+4cAsuAZGBplCycn1P7pIN78uNd8OJ
         2klhiuaWBd5ocLG3fYL+htLGx+6OUi+PkMSVu53Z3ZNjrKaOYD+/rcD84odRhp8bZkIf
         Y9XOtKqeBTFXaN88pq5U3gJQUOrcC2K4vd7atTMnKVE7ljxqy/91T90JoCAEre0kBrM+
         9sVbik3uEhEJgxRFDqRhlpcf3uhb163XF+cD34nShVp6xWLjYzbDTxJOSJUI7j83m9rJ
         l0cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=akPzNFg3+HtDpFicCJu6W96zPyCxrD6YiDmfcSEaIWk=;
        b=idd64PdLRgHuIq8q/aThPsI107y5/uCLClOqStok3Lq9c7thr6/NSodXwFdcJHcNH1
         uvYC+2kj5PuK1cVcvw/hLgO5fdck/B7c4E+hEmfuwcB7fByFmGFAOJnKrARtcCR2mxhi
         nEFdtCL3mdvy789fqPq8QYe3a72SdG/si2uuqKPzl7urG3x7cpBrdQJ2qSOxhNFME3L7
         LHqPQcgZIQt16228of+NM36FudCGXVPsVwGLgC2EothM3+B1+unwbikNfHZseZRYmX6b
         MQIABmhLcaN9mveawuq7/U0QtesfOMlCX28mB5xnr7TJWj1srUc6E2o3KeNM4gw2aD1D
         ZgEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dR8pjiWu;
       spf=pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k18si15630otj.1.2021.06.15.13.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Jun 2021 13:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2D9A7611C0;
	Tue, 15 Jun 2021 20:39:51 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 040C35C02A9; Tue, 15 Jun 2021 13:39:51 -0700 (PDT)
Date: Tue, 15 Jun 2021 13:39:51 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, boqun.feng@gmail.com,
	will@kernel.org, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
Message-ID: <20210615203951.GU4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210607125653.1388091-1-elver@google.com>
 <20210609123810.GA37375@C02TD0UTHF1T.local>
 <20210615181946.GA2727668@paulmck-ThinkPad-P17-Gen-1>
 <YMj2pj9Pbsta15pc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YMj2pj9Pbsta15pc@elver.google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dR8pjiWu;       spf=pass
 (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Jun 15, 2021 at 08:51:18PM +0200, Marco Elver wrote:
> On Tue, Jun 15, 2021 at 11:19AM -0700, Paul E. McKenney wrote:
> [...]
> > Queued and pushed for v5.15, thank you both!
> > 
> > I also queued the following patch making use of CONFIG_KCSAN_STRICT, and I
> > figured that I should run it past you guys to make check my understanding.
> > 
> > Thoughts?
> 
> You still need CONFIG_KCSAN_INTERRUPT_WATCHER=y, but otherwise looks
> good.

I knew I was missing something...  :-/

> I thought I'd leave that out for now, but now thinking about it, we
> might as well imply interruptible watchers. If you agree, feel free to
> queue the below patch ahead of yours.

That works for me!  I have queued the patch below and rebased it to
precede my change to the torture-test infrastructure.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> From: Marco Elver <elver@google.com>
> Date: Tue, 15 Jun 2021 20:39:38 +0200
> Subject: [PATCH] kcsan: Make strict mode imply interruptible watchers
> 
> If CONFIG_KCSAN_STRICT=y, select CONFIG_KCSAN_INTERRUPT_WATCHER as well.
> 
> With interruptible watchers, we'll also report same-CPU data races; if
> we requested strict mode, we might as well show these, too.
> 
> Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/Kconfig.kcsan | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 26f03c754d39..e0a93ffdef30 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -150,7 +150,8 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>  	  KCSAN_WATCH_SKIP.
>  
>  config KCSAN_INTERRUPT_WATCHER
> -	bool "Interruptible watchers"
> +	bool "Interruptible watchers" if !KCSAN_STRICT
> +	default KCSAN_STRICT
>  	help
>  	  If enabled, a task that set up a watchpoint may be interrupted while
>  	  delayed. This option will allow KCSAN to detect races between
> -- 
> 2.32.0.272.g935e593368-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615203951.GU4397%40paulmck-ThinkPad-P17-Gen-1.
