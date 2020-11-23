Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7V4576QKGQEPDZLSZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id F3D022C0FB9
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 17:08:31 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id 1sf9458847plb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 08:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606147710; cv=pass;
        d=google.com; s=arc-20160816;
        b=TF8VuylaW+7+1EdDPphiqyvn9vNUcsc/stA1VO4sZvcnvJAN0gpid6EVzrLRusbOkM
         ESdqhOxcwgB00ijZlKOqxF4FmPZbRGZ5VSZCkzyC/KI0ZXmQ+Ngtl5xRTJCV/F7uhlkN
         RlY3jPPUPO6mVSD1+tli5KGFmZZmiaU1KYaS6bNl5WGknvZ8k2mIMTlhUvLzdrY/IdWI
         ZNxxsF7Dj5H3ey3W/mmL7QZANZvQlGzdqTx3dFlRT7cp/WxVD9HjVROsJT1HgN/O5c8I
         xIw/JnMVZf8MIwDcJepWi3/jVozIKA6Pggdzo/Xw/t7RXI/RDsQZbiwUMKGsx1jnk5Ti
         Kwmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ByaEga57s78ND4NKvRxnYE0iHoS8vBE7OAF/nzbfNNg=;
        b=JdHP3ljA7lTZ0K/haddnViELzmjNkh5BaNzHWhfeMCwXvNgJZimGRnLbo6iRI1qz9f
         ltykWOlJnl2S/CdA1fYb3UjdzVDR6zHCC/IDgDFI2YYdlYHU4WI1n6XucytFhK1lZW8q
         M9zOBht7rA8cUq/zaGSpWFiPaN/nEkt8CflWh4N+GGFgLkJoAdVTGeBn1t1wjNWIXaaI
         h69YBxTSak8MN8+HZR/H4xTIfA8b6aBi/+f6RvR8Hcj3q/BOk/VIq+V68ms/SSoxWe7v
         raV9ijAc2aTpuf61lSQmStrvoowNOaICesuew2FxuC4Eyl/QTOxHOvbHkFLZdxTn6R41
         0UMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=R9Cz4Sm0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ByaEga57s78ND4NKvRxnYE0iHoS8vBE7OAF/nzbfNNg=;
        b=VH9xYWJCOGi4wIeV/7m7CRdlyKAtsVTpsH7UwQK9trpRKosug+OB0euMFUuRutWnEV
         amKeuGB+D3EKHGgWtztFoucrPgiSwsHwLlVRchaScypxD28PEu8tDjOWU22P6zMmIDFo
         4er51yamrJzhg4jO4mH5skmRb1u24MCKSmevNHUD6pez3AgCjNZRsUBiKYXaA2ORHRmn
         1Qyy+AHSg5KdSDFVuVw/m550t7xwgV3uwgcxZkBSH00kKtHuG+VuQz5hGKJxBpYyjZqy
         1k82fc6Um0pJwZTf7JDYhv8vjFtEhFXo0L48Wst/jvsqYd2jo1B5sSoCc8LdV8px3Pra
         8Ijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ByaEga57s78ND4NKvRxnYE0iHoS8vBE7OAF/nzbfNNg=;
        b=rtDsj7Y7PJq02W+A7ZboCI1rMcOp+ELCFBjvmbM2gBGs3ZE9saNT8xkisNZRrijgTl
         ixE59yFBnUIxdChPj4bX/ITmRHhPx+lMV4g3LgctgjVyBcSOK0OVPhQPbmAe0r7BRr5r
         TE0oZ+K+tupAU4pkl8j08ueW2jhjWxjyk12QbvLTC6YHT1yOI6OMI6caHfT9uFBGzAMt
         jUdRLnADLFtiQu9xJEBhGp8d9TcJbrkzYafJedf0JALtF1qpk4UWLZKrGUVLgDDAR7VP
         yTIvwqTAu9j569ZXX6GbLefydIAcMHC3RSVZR/SlJiz54olGKFJX2ErnFmWvx4faARg1
         ik1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y7HRDgSPbl3yJdvkUmfOtBWg+2xractmg6EDMmPqLLYrQlqeb
	L4Jz+z9jOSwax6ScCqJOmgg=
X-Google-Smtp-Source: ABdhPJyV1VxbUOr+/7CjHSyNCQ0fXbu03TgAz5g+MmcCNIcILjp5ycnRRy250iHmfvKStD6sy7L0uA==
X-Received: by 2002:a17:902:6803:b029:d6:cf9d:2cfb with SMTP id h3-20020a1709026803b02900d6cf9d2cfbmr154126plk.55.1606147710478;
        Mon, 23 Nov 2020 08:08:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:480b:: with SMTP id v11ls1279843pga.2.gmail; Mon, 23 Nov
 2020 08:08:30 -0800 (PST)
X-Received: by 2002:a62:25c7:0:b029:156:72a3:b0c0 with SMTP id l190-20020a6225c70000b029015672a3b0c0mr76451pfl.59.1606147709911;
        Mon, 23 Nov 2020 08:08:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606147709; cv=none;
        d=google.com; s=arc-20160816;
        b=HxSfUTByS1Z4FxI1ZzTiOFnnR+dYzanOl03x8TJnnYPdrDCG1LiY7s/ei+1TWju/5Q
         HekwKn6DbKD0bIfXMnHg3oCmV20ARI6gJlvXSPYSDd2CmvTzKgBnRVpFH0b48PGpwPGr
         Pzh6ZrysFAfj1p+09afKxydTbQhutujjFmvrjfkPH+JtqtilGwVqhsPtjohiLF9okvC4
         7nq6YUDqbYdI0RwwPe7y3PtTCWH2Ys1NMH0Y7FYgDD24IH0DUB3K4FAeZ2nA+uT1UQYq
         WMzG6OOySeFjxZ4OYXJD4Dfh9fdWAI/9N7y40WRhSP1+I9YA+0lBf71zjs13YOZ/m+Sa
         9dmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=id/l05lUXRZXVoeT5E2V5g7f5O6E+dlvltH8HKfDmtQ=;
        b=MqM0EgCcnj5WcNEEgP72BbrlcInoZXlPP/yhDjnTTVkQGWClNsQNL8dBgupLp2W89z
         qZN5GLXbMRQLZVDujI/cl5vQ8mAKhQ2jz4xHJoTfJTUE/DkiWQYx5HdrbvRnoT+TrPty
         gFAVxevZVVhMn+38Yp0gXbwCdonbwMgA1V7At3DQIO4QUtxv7I7x992l6Rfn6Ut2sYEi
         th65TiJpA53mvxuOl6kzdF8KvOlEQxMzqf0JmO5b6wGFQKAntbcRbJH9SPhimxGKukZz
         1I1yFEluWpDq9vrsgRaF4tC45Gr5hDFa7MRtBUdX/KSVK1dcmY9E33WU6vqpd4BfX0Pu
         AJLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=R9Cz4Sm0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id d12si821310pgq.2.2020.11.23.08.08.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Nov 2020 08:08:29 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1khEOA-0003Rv-8D; Mon, 23 Nov 2020 16:08:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9CCF53070F9;
	Mon, 23 Nov 2020 17:08:23 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 81ACC20222D93; Mon, 23 Nov 2020 17:08:23 +0100 (CET)
Date: Mon, 23 Nov 2020 17:08:23 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2] kcsan: Avoid scheduler recursion by using
 non-instrumented preempt_{disable,enable}()
Message-ID: <20201123160823.GC2414@hirez.programming.kicks-ass.net>
References: <20201123132300.1759342-1-elver@google.com>
 <20201123135512.GM3021@hirez.programming.kicks-ass.net>
 <CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw@mail.gmail.com>
 <20201123155746.GA2203226@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201123155746.GA2203226@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=R9Cz4Sm0;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 23, 2020 at 04:57:46PM +0100, Marco Elver wrote:
> Let me know what you prefer.
> 

> @@ -288,27 +288,19 @@ static u32 kcsan_prandom_u32_max(u32 ep_ro)
>  	u32 res;
>  
>  	/*
> +	 * Avoid recursion with scheduler by disabling KCSAN because
> +	 * preempt_enable_notrace() will still call into scheduler code.
>  	 */
> +	kcsan_disable_current();
>  	preempt_disable_notrace();
>  	state = raw_cpu_ptr(&kcsan_rand_state);
>  	res = prandom_u32_state(state);
> +	preempt_enable_notrace();
> +	kcsan_enable_current_nowarn();
>  
>  	return (u32)(((u64) res * ep_ro) >> 32);
>  }

This is much preferred over the other. The thing with _no_resched is that
you can miss a preemption for an unbounded amount of time, which is bad.

The _only_ valid use of _no_resched is when there's a call to schedule()
right after it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123160823.GC2414%40hirez.programming.kicks-ass.net.
