Return-Path: <kasan-dev+bncBDBK55H2UQKRB6VB4KMAMGQEXJQT4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D62AB5B0418
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 14:39:23 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id j14-20020a2e800e000000b0026aaa13fc92sf1192768ljg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 05:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662554363; cv=pass;
        d=google.com; s=arc-20160816;
        b=Io3pM+t7NX6Dn9tXwB4Oi4XS1ZxuWTzH0WzcHLVkTBTAuQnGEezmRJpfmqhi2i9AEf
         msBP6MUit9nhGtVbDH6beVwdGLJPmEE2HIibPKMpE1ZRHYmRpv6nCttDQH0e27pZuHqQ
         myLcN8prqmZASrz3eKr8O5MY5bGoFbZ2VyWnpWyK4f1hg5LYaY44IPhIe07cpvxCjs4w
         k5Y5eAnQbB4E31v5qV3T0SMnBvV7gfyyKFdBFX08lkF3CwN5PE7tXvMixSky/RPREJ+a
         WkNDEi/u7Nl8b+P39b4CaveuHCDo1207E+R1vGlBArhsTxgWFTnocpnT8+6p3VhRxBUm
         rc1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CyNVdFoTD13Ca43oY1bGUxwnmubYCkctiqNviwgHlW0=;
        b=RBvbnHDbi82oAPq7D7b2cgx8VZ2JGdHqQhmq5JJPXdq1jvwzoWM2dY1kJBW2crbpaX
         O2WrgvgoNafZm9mSCWeL+I614HtPp7uyl2kgHj7HEgwYU2yazpKw/jb9D8r1noQ75Wkv
         OOYoePnfTvdCYTOhDxjw3jXBA2DpCZT2TLAtYb7oIY5H/QMliRHXVfHcfiUZ/voIBOzy
         JQBSp5D82ZmokFpv3F6GduaL6i0tMMomtysc2YtmNz5FhC4Q0hiHkGQ020z0Dw8x3i09
         1xwOliMjTQhFPiZFFf8iQOcfysm6WsXavZMprAjX8QKRoRpI6K0J4m2HIzV5oglDkGQu
         Kpdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kvlGRcc+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=CyNVdFoTD13Ca43oY1bGUxwnmubYCkctiqNviwgHlW0=;
        b=eBZSybrnZ4sO+qwtGg8H0kH5in8t27eBDJWzXYu6iujsM8+wcUqvA4+DSPpGLuX/mZ
         Cn7+lsazhAb3RtVxgNHybDheDkHmB8fNB46b+eXQKsUXgRSd1uXHb/HdPyyig8MzMMTj
         pVrq2xsbyl2rht3h74czTSC74o6CwBNQzrc4HAgdVEvg14Dlaz9wYYxycg6u0M6ICTpm
         KDNGzWyy6+DfF33lHG1kc6m5BGwcWcxL7UmryzVkQf8eJu2on72uk0a8xqcxNPTLI0JC
         2Q+CtyPbYrp8BJqCbW3Cg/x/JaZsSy53mWo2CYjkwGGPNiZIrUAJHkEX+VRCayssFnYy
         jA8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=CyNVdFoTD13Ca43oY1bGUxwnmubYCkctiqNviwgHlW0=;
        b=fY41xVHajKtsFxd8jpQPBSkkT+tegjfKCdzqxSc7XmWKCAfxHyL+Hcj0o7zhx4yxj1
         dLlU5dr+VFCN8Ap+Y93HDcnnlWlfSYdeD/s/aFb3Y1oDAi3jiM7LrWJndE8wY+XAU21V
         XZtx7b85pRrHdKAkXZBma82bTsIrtb1Bu2WMi0W0KTyRGBlw5Pngbg2gFPlkTAhIj0F3
         EE8G2Tl+2rQztkQ584l1xf/C5Wgz/ggMGUMT/rjFVu23jhue+GpkitGLsrInbM6x59h5
         sDjemJi/thrghhanijC8GCmQcNyFk6xszNpMUv4d+AQnVi1NlCS5p/bVAAwV27pnF261
         gN1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo11gcXuDf1mhz9f+cJNfOlJa3+PSN0pKq1GwBu6qIdCABkdhJiJ
	oZkOMWQVPQtprpI1NzC/dlg=
X-Google-Smtp-Source: AA6agR7if7aG1vJjNFB0MtCzLmtS/8kutEPputMcmiuxAyUfjypmkfpRFqzV6qYka4k+E8aSFCqSYQ==
X-Received: by 2002:a05:6512:2293:b0:48c:f602:475d with SMTP id f19-20020a056512229300b0048cf602475dmr1219784lfu.232.1662554363114;
        Wed, 07 Sep 2022 05:39:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls2916386lfr.2.-pod-prod-gmail; Wed, 07
 Sep 2022 05:39:21 -0700 (PDT)
X-Received: by 2002:a05:6512:3d08:b0:48b:123e:fcf3 with SMTP id d8-20020a0565123d0800b0048b123efcf3mr1022304lfv.418.1662554361709;
        Wed, 07 Sep 2022 05:39:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662554361; cv=none;
        d=google.com; s=arc-20160816;
        b=hQXL2lWhTiJpoaRcNM9LeBh5WTf9In4vTvB/sOLw6ne+j1ur++HKjQtepeF1c4AAcT
         /EyP8NrUGKQER5jGezR4LgTZXYeULP4sW8Wk3f1hlN9uy1HTalC8FYS1IGP5MhGu/y4A
         obBr9v9Y8Wm/+Sa+hWMZkOA9LAQLVoN8kgkgsTs0S7cKcEW/JzWImpVZR86ofULyjq9o
         8Y7UB+spEvPaSTh1HZO8K6PL4p0GrJbBhYTBfI33cNur7sNTEbNgWymS4XOwSTsD0Ynk
         /cFIJyFytUyI1joTqGYFJDE2yAoae+t/d5fgYJZE+8f1DjgaNOyATelZnUqHQ7PIhQWp
         5Flg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WaLVUa/zzUyERr1LanHZCtjpzRsLTFPoqJHLp72GAJE=;
        b=Tk6GdVzOfYYLfSEdUI4LQGAiciO/aQmaj0dnB2xTLk3FkAyf04SccymMPOz1WFPRmA
         IiXj9woQFuuPsCnhCjnh9DqZmOwoYjaMcWCExxWyXPPoQN3r+KizBq3qsQ0LK/JMR9EH
         /UTeWhT9wJWURC4Yi5nPKnRlrN8malzO9csXe7e26Y5G9axfOdDQ6BBJkoGZzLLfc30f
         DjuhyWH5NkHSmOWp6Q8FJFprvzBfLUoLQdQ09jVdyMTORJ/CtEZJ+tBOuVTTHOyXHxxU
         /oWriFYZUdcUZnbp9QzRf2x6GutuC3HBo80axe0dAIIRvctklKi8idb9hEI2tEKHhXiP
         ljJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kvlGRcc+;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id w18-20020a05651234d200b00492d8e5069csi677863lfr.9.2022.09.07.05.39.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 05:39:21 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oVuKq-00ARLH-Uc; Wed, 07 Sep 2022 12:39:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 79FC83002A3;
	Wed,  7 Sep 2022 14:39:15 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 35009207AB808; Wed,  7 Sep 2022 14:39:15 +0200 (CEST)
Date: Wed, 7 Sep 2022 14:39:15 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH] perf: Allow restricted kernel breakpoints on user
 addresses
Message-ID: <YxiQ87X1eUB2rrtF@hirez.programming.kicks-ass.net>
References: <20220902100057.404817-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220902100057.404817-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=kvlGRcc+;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Sep 02, 2022 at 12:00:57PM +0200, Marco Elver wrote:

> +/*
> + * Check if unprivileged users are allowed to set up breakpoints on user
> + * addresses that also count when the kernel accesses them.
> + */
> +static bool perf_allow_kernel_breakpoint(struct perf_event_attr *attr)
> +{
> +	if (attr->type != PERF_TYPE_BREAKPOINT)
> +		return false;
> +
> +	/*
> +	 * The sample may contain IPs, registers, or other information that may
> +	 * disclose kernel addresses or timing information. Disallow any kind of
> +	 * additional sample information.
> +	 */
> +	if (attr->sample_type)
> +		return false;

This feels a bit weird; should that perhaps be is_sampling_event()?

> +
> +	/*
> +	 * Only allow kernel breakpoints on user addresses.
> +	 */
> +	return access_ok((void __user *)(unsigned long)attr->bp_addr, attr->bp_len);
> +}
> +
> +int perf_allow_kernel(struct perf_event_attr *attr)
> +{
> +	if (sysctl_perf_event_paranoid > 1 && !perfmon_capable() &&
> +	    !perf_allow_kernel_breakpoint(attr))

I'm on the fence about this; one the one hand it feels weird to have a
breakpoint exception here and not a pmu specific callback for instance;
OTOH, leaving security policy like that up to pmu drivers sounds like a
really bad idea too.

Keep it as is I suppose, just me thinking out loud or so.

> +		return -EACCES;
> +
> +	return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
> +}


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxiQ87X1eUB2rrtF%40hirez.programming.kicks-ass.net.
