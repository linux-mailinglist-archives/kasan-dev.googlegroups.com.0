Return-Path: <kasan-dev+bncBAABBFXKQXZAKGQEN2PDHZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1815F157EA8
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 16:22:00 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id e37sf4611992qtk.7
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 07:22:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581348119; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTtCVuP7LfwkLaqoli6/JdMFCG8ivr6Hc7Asvqiba0lXpQ8RyJu93CNDFiPwfpJ2TS
         vkioKLWKu4dHTiWqAS9IjX67eYrAO19+QSZ2CBrtaVcwUxi0XaGmNwHAFuqQSlTufft8
         xoqJefzZhIvgETfkhK6OyFUGx3gY6pWne7KfOmo2rxAk623k1R+qZBRlBNDdBwFuRLNU
         84l8MKJOzfk0NNa7xNwy9/lzNqYj4N1LjZ+muKTao9q2Bcb+BdKCSl+k1ebhhfva8fgK
         2952A7m4Mb6f5VGyxc13V0oqzueiWOexeKoDQd76tgVEHhKn4h0TemMT/I4vFOrAhQta
         fJ7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QGTcte8F9j5yW9WPMgFxsFu6MXZGKGSOWHPNQAYeytY=;
        b=Df7OYFjQZW9NyMhYSRo7yB0jblBPoO3qXGe00+nQE834+vbvKeN9gbIH0LkXJ+ATjs
         TGVGmjpuxloHcL1XDNNmaxQXfDrBHR4ut9IN+5twEkcduLpM4T9tpZI77x9ZBDtju1P8
         ugcHovMBAIyI35oSB0tqQgdNHN0XJeXKGMQHuA0yP5Gb/WIKGCAejN7FK+Fv6p4fjEFn
         i8tgNlZUhZq9xJ/U6s5yOtq9+EHw5Mjh6dNt5KjCq/fqMjsDnmgcQTvONRa/NyLQ8mas
         baxSHLHULUMxXzHkJXsWi67ZG/0AO7ucLUYt2mKpArz+g5jFzFOZZN5KX2v+tUvJFGCC
         EFOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=p542MkWc;
       spf=pass (google.com: domain of srs0=mxv1=36=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MXv1=36=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QGTcte8F9j5yW9WPMgFxsFu6MXZGKGSOWHPNQAYeytY=;
        b=KPb16ebucDm7RL0IGrlnrPBgmu0pxYB70N/CS0REHjxiQC7CvGGeIQyZnOvBzQYYbx
         1A4X5FAJbrIQesJx4V7V5FCnSmAMzWDC29lTzF9s0+pHYCBBRYrG2XCLF03L2tWYixeo
         eULgYEQQSuYo8UDIAG31gFf3YRWSih9m6rE2qA75jvNk7x4UfUiMMFwitF3kK6yAz/E+
         dPUY2I7H9vaqBGoUFGGBhKGUw4mtPDiainLi8rvnbphIvnaqifVeT5br11APxgt865D5
         3DDAGeEXp3AtnsBdD2LFEoPGGdfRJd0UO9ap04vGEMPbIFp2T2iAlefi2Ihus6wjnppS
         O/Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QGTcte8F9j5yW9WPMgFxsFu6MXZGKGSOWHPNQAYeytY=;
        b=pombhYm/4LrV3ZORnghgh7FFgyANsWC4U1bgWEmRrZtJN/LPgQwaG+31WcH5Bg3j7B
         EkQmIWU2wPLpBM4GDDxjH8U3zSdNGzhga1d0fSI1rwFGAaCf/QiZhS1s31Csuq1bURrb
         Nn5eP9hMEtYKO4JE1dPA4fxrB+qLVzY7Kknk3BeQ0hCFDtI8YgnNd4khf3qrdrWGsmds
         I6rRZ09Ifs85cQ9Z8Be1Qt0W8lY6zjUkxIvrjsOLR/N7i2oHE3WwNkCZXQUHdTVGt1Mn
         atFuVxhDhuGka8AEu3uRPuparnNH3wSyv/ZCk+fRcFcooEYwsZoH0q4rGVcJmstsXLIU
         4Ssw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQHdzNcX4LgPKfEVF+o+Bv0KMmFxDqeVpu9M2aOBQpsYqUTYoi
	2aQ5QG4eSJYCFmhLxTcgSJQ=
X-Google-Smtp-Source: APXvYqwxWUOFE2/eK0bMmky6SdFkRaN0BLsaViN0RYQu3+tThOwqImIRtLruOKsn0olk1AKcyBxCeg==
X-Received: by 2002:a37:f60b:: with SMTP id y11mr1199586qkj.183.1581348118906;
        Mon, 10 Feb 2020 07:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5441:: with SMTP id h1ls1739261qvt.8.gmail; Mon, 10 Feb
 2020 07:21:58 -0800 (PST)
X-Received: by 2002:ad4:4434:: with SMTP id e20mr10463457qvt.157.1581348118635;
        Mon, 10 Feb 2020 07:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581348118; cv=none;
        d=google.com; s=arc-20160816;
        b=Xgyjpf1u6PI4XX7ybCBtnAHpoDFm6hPGpkGEn/qR4sDJWR1iyrEny40ApaxYEXVytr
         CCuJT5adsHywpcn0pYXLXy5azE/hrYk9NsF5iMDC/zngfMeZGw9+l+dTKMmUv6I4Xved
         HLhDDMZGnRwj5f8Sbr38jigLd4BrViO+KloA/lxlS9fABW8q4P593qd70BuYU/pHX8Db
         0V0sARxmDHYIMN/J/AzUCYDm2dx/yb536kdRxSNQmmPQ6LTDtLUES6CC6kPD9OsUCkSl
         dKWkR0AoBDDtIp/nG508bG35zJPlYYucaTd5Oprhttwx+2ZVeCArpAaNz4+j/OGMYYzA
         1BTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wL77na+4Tr8fLRCxWeTcL2vUCczRx43y4v3artlyPL4=;
        b=qcg1qQNdmHfnEo6r/FzzyA5AlU8At4fKy5cwfeNs82KY4ERM47O1crcUE4H9DjGZNj
         lgdrwt0zJGPeOHf6vZNmqZ7Hbm2HaecnRad4skSir0WarR1d3ynhciLa8OO/QqoeXu7i
         GfR9nUKFE210AdSuP3FRQQC5E2pA/KqlTEtVf3Seo9lSsqa52L4RlB/nIRUwaTd4ltlG
         IE+glNzPbnSEvINYk0oKR/mbGJxjE9aANyQeuMHxDbAS7G6qxmnclNyvQSksdoJkCoFv
         P5tUJc+ZEb5+e/+v4ER6r2Fnij+Q1R5LNxko/Y41sLPBFPOCHJqL5UcNFZqiHMeDsg1x
         vDZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=p542MkWc;
       spf=pass (google.com: domain of srs0=mxv1=36=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MXv1=36=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o21si37654qtb.3.2020.02.10.07.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 07:21:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=mxv1=36=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [193.85.242.128])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5DB872082F;
	Mon, 10 Feb 2020 15:21:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 11DD33522700; Mon, 10 Feb 2020 07:21:54 -0800 (PST)
Date: Mon, 10 Feb 2020 07:21:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Fix misreporting if concurrent races on same
 address
Message-ID: <20200210152154.GY2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200210145639.169712-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200210145639.169712-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=p542MkWc;       spf=pass
 (google.com: domain of srs0=mxv1=36=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MXv1=36=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Feb 10, 2020 at 03:56:39PM +0100, Marco Elver wrote:
> If there are more than 3 threads racing on the same address, it can
> happen that 'other_info' is populated not by the thread that consumed
> the calling thread's watchpoint but by one of the others.
> 
> To avoid deadlock, we have to consume 'other_info' regardless. In case
> we observe that we only have information about readers, we discard the
> 'other_info' and skip the report.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued for testing and review, thank you!!!

							Thanx, Paul

> ---
>  kernel/kcsan/report.c | 20 ++++++++++++++++++++
>  1 file changed, 20 insertions(+)
> 
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 3bc590e6be7e3..e046dd26a2459 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -422,6 +422,26 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  			return false;
>  		}
>  
> +		access_type |= other_info.access_type;
> +		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
> +			/*
> +			 * This is not the other_info from the thread that
> +			 * consumed our watchpoint.
> +			 *
> +			 * There are concurrent races between more than 3
> +			 * threads on the same address. The thread that set up
> +			 * the watchpoint here was a read, as well as the one
> +			 * that is currently in other_info.
> +			 *
> +			 * It's fine if we simply omit this report, since the
> +			 * chances of one of the other reports including the
> +			 * same info is high, as well as the chances that we
> +			 * simply re-report the race again.
> +			 */
> +			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
> +			return false;
> +		}
> +
>  		/*
>  		 * Matching & usable access in other_info: keep other_info_lock
>  		 * locked, as this thread consumes it to print the full report;
> -- 
> 2.25.0.341.g760bfbb309-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210152154.GY2935%40paulmck-ThinkPad-P72.
