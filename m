Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZFTT33QKGQEJT7HEIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 90A3C1F9C5C
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:55:17 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id p8sf11620351ios.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592236516; cv=pass;
        d=google.com; s=arc-20160816;
        b=o31nY+BeVw04PZrJVTT1zasOSvBEnFyFnocGff1isx9uxtd6UkwO0NaKzgpX0dEgwN
         1RlQ9BSjdlyNFhuIcrgWaD7EgcVp4hdH7UL/cnVyOcZlNu0BgK7+iC4wxd2vmoIPmlrT
         qmPqPTWHkcvT9eZq5GZb/R/yq2sKkZRuFJ/a3bLCYfm63DJV0StNwEMHADSqYx6trP0r
         cEcNhC9iA5U2vdJ279Pne/k7bpqh3SF5E3jlJ48pJTIQF1rK8zjSSKUyVRBn5zloNPXH
         7mHzI4LVjPivXRtx2vkDjyd7n2Fs0o3DWRr9ERbiQQQIFaLUyrDCdlhurGz4AOdcHqmI
         Chig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=h59/cTDT53a9olDQSV55+U4+rJIcipv1Ih4BjDsShpA=;
        b=BdngSGT9PEaE3NJerVJYiZV0Qf32fDIdYCPqrUY2zo0ATUuobP9jn12t6FUh/CL4aT
         hD68mnE6AMzm24ll8khWmvWhDRwZqFPsbT2gAfr2J8Xs59dBbq4bMnbSM7L57mcSOix9
         3cuq6NAxoIjwRmAKMU1L2DODz292aWPn4slvP4Ld+h8/wlWPK8FmCr2oyp5LoYWOG4PR
         dH976adx+qR//pUmZpDRAf6yUr8/Bh8Y6SGCgQ8hXebuFX9N4iGn+TrmbWRx/gDIocew
         NjCOxQCYrYGd+dqB6pJXGlwcnbfxbmoUll6dmRgNm49UbQVBy3YvhiAuCCICj0vBBrT9
         rY/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="m4FF/1Ke";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h59/cTDT53a9olDQSV55+U4+rJIcipv1Ih4BjDsShpA=;
        b=AuGMC0E0fb+z0mBodZe/NA/av5+fYQtdW7bYiT/a4V1xhGxdaS6TjDeHeooilcoE5E
         YgAwYyK1m/BnAF+Eg+7p8T5/lCl/ouoikMjwxj7ViPhGRWtRQI5RzBxo8lDZkLJ/X5pf
         Ax7PbF7ZP3BIsdhsDszcvwDGNfk+PeFvuDLv1Cftoqde72iRhqNn1qTMsYWuXGX78JOO
         LMtlvd2SakOhQMqk1gQB3raCeJplkg4hXqG0L3ZMMcZ+8BCYhLDIIOdo5UJDJB6UukBR
         wRf6a8XQCrbcnc/2GrqitlJwKWao9TFcsfL7Gv2wvWlHBOIlloiVp4ZQyCZ9ZGBFQWcM
         cGPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=h59/cTDT53a9olDQSV55+U4+rJIcipv1Ih4BjDsShpA=;
        b=pk8+FSBTblwRMOGkja93ZRIsHluZvppajk/1WyqIr5tm61IoYlfLVBalyJaopDlCjq
         dTV3qZHKk5yWEX5UyEC3Lf+70K9ISZm0argrHIw5cR6QO3IPBkRReC9EWMIkAm7UeH7g
         nrvZbEAz6xu4G94DlBnNpoRkFZHcYF14EBrAkR/7BVCnSBBvhjn17pVpbqx4nE2m2YeU
         EIUki7a/ogIcbmqd9nxMk0TQcMOhOotUdiz/cNNnk1jOcnrVtiyBIN56Ss5KSK44eWQV
         9yQnQaO6iDyS7rx2UK9llke0LHmJ7GLVOtL887yoJn8bYQE3iYyuPOxgHU77Fs6PTfOK
         +dOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JIL+4Aztiqdbr0hu7sjch1pA0s6ZKnQSjhB+SDkrsqI6LpD6c
	O1XtRprwYjiODSjokvlgf90=
X-Google-Smtp-Source: ABdhPJxGGAmK17A0Jx+kWi6T5dgdyvF7v/V29EDKl3wr6ZFNJw1pKmyDuc/YtmXNjtuBa6axlYw7sg==
X-Received: by 2002:a02:94e6:: with SMTP id x93mr22644891jah.116.1592236516490;
        Mon, 15 Jun 2020 08:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c9cd:: with SMTP id k13ls3767223ilq.2.gmail; Mon, 15 Jun
 2020 08:55:16 -0700 (PDT)
X-Received: by 2002:a92:9f12:: with SMTP id u18mr26994879ili.287.1592236516262;
        Mon, 15 Jun 2020 08:55:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592236516; cv=none;
        d=google.com; s=arc-20160816;
        b=qOZbOuiwXWgFLn+VqfdLPDaXoVelYPHT8gjOKy9l3hSNTl4cjF7r5w8QuORoCGLW1Q
         sw1aj8Qw6xE5FSx723Wvk1Qexas4kFexT/MaKxVrHwYab0Y6iGmxiryG5+Ui6mlauMjl
         fqLU9XR605RIZBNVOAo5O5oa2hxzYwiT0bOSjAE37KIvOyYvG1DUOMIlpDQh2GcA+ZWb
         FHSS8LSawXO8YwWy8eVwaM+PEvzAn46MuT/q4BgMj7Op++/8uPH5tmKv38o4VjF72APR
         jGCmEfOKkqCAzTls3yOMDgePp9+dwqfIA5Yz/wmQBDFIMPZBqZHnHRxjT6EU4axsUw9B
         C/VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8Xkq9S9SwcNKk+N4luSOtQt3D5uwFKdvMxktzgQmU5I=;
        b=Sx9tuhJYu2tDT04LlDgVYhebfrDkQ0hfaIYAO8FYb73YSrxj9UtOsqLGH7uXkD9wKe
         9DwG+R1AuQo8mHUONm8VU/NnCSSHmLD3inYBpfyS8sShdhJFOAsrjPE7ujNp8OOl6Guc
         ohe2jFJmh0JtTvORSqaq5JsdFgY97in3jy/6EVldRaexiLUXAXKgJ5zyXKwMzbjgo8Fh
         gUhnnF1StzEKx1+P/DLq9nfQi/Zl2PZcVJQ6eHyv5fj6iOY71GmYnxTh0j3I8SVZk8Vv
         pvoxaEtMqvyf+W/P9wOX0f8QyGeG8TslUGqBHWdAYohMNRVtliqkqov0x6j+QuFzSmZO
         ZNLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="m4FF/1Ke";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id x10si840005ila.3.2020.06.15.08.55.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:55:16 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkrS7-0003jl-HO; Mon, 15 Jun 2020 15:55:15 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D09DD30081A;
	Mon, 15 Jun 2020 17:55:13 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id BAE9620E05A91; Mon, 15 Jun 2020 17:55:13 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:55:13 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org, elver@google.com, paulmck@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615155513.GG2554@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="m4FF/1Ke";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 05:49:05PM +0200, Peter Zijlstra wrote:
> @@ -983,13 +993,17 @@ noinstr void rcu_nmi_enter(void)
>  		if (!in_nmi())
>  			rcu_cleanup_after_idle();
>  
> +		instrumentation_begin();
> +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> +
>  		incby = 1;
>  	} else if (!in_nmi()) {
>  		instrumentation_begin();
>  		rcu_irq_enter_check_tick();
> -		instrumentation_end();
>  	}
> -	instrumentation_begin();
>  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
>  			  rdp->dynticks_nmi_nesting,
>  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));

Oh, that's lost a possible instrumentation_begin() :/ But weirdly
objtool didn't complain about that... Let me poke at that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615155513.GG2554%40hirez.programming.kicks-ass.net.
