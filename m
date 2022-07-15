Return-Path: <kasan-dev+bncBDZKHAFW3AGBBA7MYSLAMGQEDIJ45BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 48D6E575EBD
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 11:40:20 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id d12-20020a056512368c00b00489f92be8c4sf1613485lfs.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 02:40:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657878019; cv=pass;
        d=google.com; s=arc-20160816;
        b=vcF9Z4S6az1SogfZhVYStpWCzPVw94CSTek7UTIz12bRbwUeOu0LrJiX5EHHRnA30p
         jtzfSRRlWD93y3DRfxD6YBJ47vJXNy3P06vbJHeaLlp7msXcw9cWL0/65PfFdEl/1Nwx
         BS9kf4mRGO7cjK9591Gv+4Q/DpvbhvKKH2En65GXCIXtIlSzp6NUTfFllHOOG1fZQsOf
         GnsXrCZjxUG9kTu1znJYBzZmmceT/4Ks+CX+vfshtMGKLR7zpUmugkb0KmA8e5jO8mWi
         FstI9JDyXojuZV3ZdrqgtZFz36fO4UGkuFzE860AVlGDWP/aZ73YXJzZH9v8r9k6Tx/Z
         qBdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sn8sPse2xg/v/tUROJnYlughARMboI813tb0iqEvJeo=;
        b=s2bYGe3Hbhtu7T1K18Ab2FK0Xlw7IJwZni6XkC5MuQSvBRyw1vUOPeW02OdeY+/Uci
         5M5bizY8iRrINDHp10HxQCreQHv3yGjsBHyv5mcZs3XYpH0KcoRuLZLCFCRkei9Pilug
         LAHlsqwz1kRs2x8r0j4r4yVn/MslQwnkVyKSS+KehObIL8OUuR0Bwv4q2t2yXOvEYyUK
         5f16lmkKvelqw1nMpAAv64K4kBBIiVaxCvpISPpIS1ZpS1oZOAKwbHGjFvjlHaaPqCj9
         rYT1Y6VMfElua2p10UQ977cGWEqJfGEmce6+FxOqynOStyYhgiraFVxa75eqGxebFEYA
         9k1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=HGxDO4vV;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sn8sPse2xg/v/tUROJnYlughARMboI813tb0iqEvJeo=;
        b=VpUt65X2eIWjtvquernT9FtS6wf+VQMlAldFH9Dv4gmaNalofwrql7iibFgVroAXbz
         RKE5tFWE4maGJ0aYLyiDNse704eWBbtvKy5gyj2uYkVUV0SvZcBpApspFaKjmI3MrrX1
         V/5Iuxc4FLNaZJkkGuYPG0uBSjGksBFjznuE0OqldsZlazG6bugVMKl1gylGLXlwb4aJ
         p9dl6+Pzc5ie5m5RFOrxGvK1Pvfx0BvXXgNmQlkNch7vem4M6T8qCUIs7oCkJORSdvT6
         YEpYvopVnNuJox6ofLvTTnfM3Z0mZ+9VZrPvlQNkGnRyCQ6k5V9AJZTaY/u2OJAh5Jfg
         RH3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sn8sPse2xg/v/tUROJnYlughARMboI813tb0iqEvJeo=;
        b=cPlxQJmLu0Xu33IvPvvzjAzUqOvZtQsg3BsYRRwwuMFBmuORRJ6Bl4wT2PO/VvaklZ
         +HQnu8NEE/MzE47E9dW/kTExVaXRnzD+HOpvTvngq/GTgLKPDrMGvtVp9L92qPOjHy76
         iFz3O89flk/owNhJuaUogVFlzsLeUEB3zkS+o7FZ/HTMJ74gT/acSG9jAv/WNHKrw2nG
         P6IARoqyou41Pdi1cIBFcd8QQi6n14y37lux8F9NittKnxDS1knm47cTha9/yv2i7Kuq
         wAfoIOYvJTiZbxz7HcAcEkng1vV6J2bCrUwCig+p/QQxt7XXeI2ija/GtKtGeCNB1B3S
         S+bA==
X-Gm-Message-State: AJIora8XS8LfMrs4saJgleJVJ8vjOCoZfQQeZ7GHatJMKh+txc03MIaP
	30PtZdNYxcAYPb0I3anTCNE=
X-Google-Smtp-Source: AGRyM1uuyQOdYb90N131CqO40V3dDFitsLs4T71SgGhwGG6a5w19gAYMvRGNJr4x3BxDDaEi1eM7MA==
X-Received: by 2002:a2e:a26e:0:b0:25d:6704:626d with SMTP id k14-20020a2ea26e000000b0025d6704626dmr6745685ljm.128.1657878019634;
        Fri, 15 Jul 2022 02:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e14:b0:487:cd81:f0e6 with SMTP id
 i20-20020a0565123e1400b00487cd81f0e6ls734557lfv.0.gmail; Fri, 15 Jul 2022
 02:40:18 -0700 (PDT)
X-Received: by 2002:a05:6512:398c:b0:488:f524:b7e9 with SMTP id j12-20020a056512398c00b00488f524b7e9mr7152503lfu.259.1657878018458;
        Fri, 15 Jul 2022 02:40:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657878018; cv=none;
        d=google.com; s=arc-20160816;
        b=NeG6mpePFKMPOZtepCuWT2J22HKQcRbJNEnHVgHz3hB/1P8GWC65hzDiv57cokHvCt
         cuILbHQqPrr4MiBdPOZS0NNqN9hFqhxEkHVNS2TvtFRvd4guyyT1iFocFTPfhQMhzeRc
         dTYikXjgD+pYG4Ye1zVk2+pzCsgm6wVqin8jn+AnJT1zbW2YpulsmrT3rjMDdi7lxVE4
         a9ckh+hMLTn0aZ7Y6FUtrpmjEat/SHWHSmp6YmWv4gfms/Mg6mgat/z0uFGOKVl0/IrM
         C3rsOqyxeGsJFO/tq34xeltA8JVe//fBDMbVAh5XIKoPBmXYy6M7MqU1VFddSgXSLhYz
         c43g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FU/0z2tKXuzPGmO+fW2XES5P86OHa09862weLmCDL7o=;
        b=LrJz1DtZvqoLvqZlkbHNXBhhKiSGw6OenpB9dmx1YKmGP254BvcHFM+vjxQxcxdEdD
         RLBUWm7DoGMj+6SyMy07VgTRDxcQtUWkT5LJff9fk8tNILzlB2pZ2f4mFp/PwHjwdUmB
         ox0LaqdaZZWA9iefJyq2Bsev0yoLaOiHMLEvpCXIKdNSFKB7sbyPebIEKQlpMe98CQXY
         N0XOwEi1/W6Lfe+fTQ0aYA12c68sdURURZrAeEoaS61kBWoCVwMIK4zMNkl49w1Hycok
         aeq+QhqN1Dwmc06Rxget9xJmthUvSoZPbFQB9zVyr7FMskrbbBty3g97770iGoTxPM+N
         C6ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=HGxDO4vV;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id g7-20020a056512118700b00489d2421c05si136005lfr.4.2022.07.15.02.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jul 2022 02:40:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 8AE0F1FB57;
	Fri, 15 Jul 2022 09:40:17 +0000 (UTC)
Received: from suse.cz (pathway.suse.cz [10.100.12.24])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 628592C141;
	Fri, 15 Jul 2022 09:40:17 +0000 (UTC)
Date: Fri, 15 Jul 2022 11:40:16 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220715094016.GD24338@pathway.suse.cz>
References: <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
 <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220713112541.GB2737@pathway.suse.cz>
 <20220713140550.GK1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220714145324.GA24338@pathway.suse.cz>
 <20220714111749.0a802e7f@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220714111749.0a802e7f@gandalf.local.home>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=HGxDO4vV;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Thu 2022-07-14 11:17:49, Steven Rostedt wrote:
> Although printk is not really a fast path, you could do this and avoid the
> check when the trace event is not active:
> 
> (Not even compiled tested)
> 
> Tweaked the comment, and used raw_smp_processor_id() as I'm not sure we are
> in a preempt disabled context, and we don't care if we are not.

Makes sense.

> diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
> index 13d405b2fd8b..d0a5f63920bb 100644
> --- a/include/trace/events/printk.h
> +++ b/include/trace/events/printk.h
> @@ -7,11 +7,20 @@
>  
>  #include <linux/tracepoint.h>
>  
> -TRACE_EVENT(console,
> +TRACE_EVENT_CONDITION(console,
>  	TP_PROTO(const char *text, size_t len),
>  
>  	TP_ARGS(text, len),
>  
> +	/*
> +	 * trace_console_rcuidle() is not working in NMI. printk()
> +	 * is used more often in NMI than in rcuidle context.
> +	 * Choose the less evil solution here.
> +	 *
> +	 * raw_smp_processor_id() is reliable in rcuidle context.
> +	 */
> +	TP_CONDITION(!rcu_is_idle_cpu(raw_smp_processor_id())),
> +
>  	TP_STRUCT__entry(
>  		__dynamic_array(char, msg, len + 1)
>  	),

It looks better. I am going to test it and send as a proper patch
for review.

Thanks for help.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715094016.GD24338%40pathway.suse.cz.
