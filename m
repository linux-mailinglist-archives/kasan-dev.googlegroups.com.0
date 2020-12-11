Return-Path: <kasan-dev+bncBCBMVA7CUUHRBAHLZ77AKGQEKJJUL7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BB7D2D823D
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 23:41:06 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id m15sf5011178oig.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 14:41:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607726465; cv=pass;
        d=google.com; s=arc-20160816;
        b=eymf3EqCb/Ao+oOQv7oTlmj+TxeSrBLoVxLvp3bq9rGbPRJTy8FAgNngjKPBpwfCa0
         qofSM/WJ/512g7xcKw8UDS3bx7opOJMmW8kTA4DXC82A+vJHJ5MCtjJ46dOk/O6l68YT
         P65UddcpKJlkWG6qeRmXuCr6E2Em00S8lbBASBR1UG2LeH4jnRrlOR/Ag2xiLD3NqKpi
         Y0706hcf+ZHRzedl8yD4Ugmch+EmVszMSkEqFTNfXTUzuhagAScDwrUPeDoYjFZrQA1/
         BiFaAir66kQnqd+5L9KKtlVioPImeAevVKeK+4GFFr5ZS69hGVEwjeeokqe4bZQks7qw
         v2Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hSS2M4O68Oclz7FRo9ove4nxKIu0CBGmTJa4ZzHFjak=;
        b=YH9ikvlPNL24NelvNZJ+YgtyMXQnhIoi/e555Kpj3e521Z4Z6TxtedV8Af8KIYN3my
         Jky4aqDCDgML7L7oq2i1Q0cvg0OYOodiH+XfwUAAqQgx/0MnZKxuoPjMDo7YuErVh5Um
         1VNjWCZ648pSIJSlHiuDV53TtiqxU1K/tFWuncQ/+GvVCCYLzzRZ6ZY3GAI7y1jaNOw8
         pmSVWA3QvBGxbIijI2NTUl/N5dG4Y616AwdeYEc58bqlGSH+2Qvb8Wd9SaI98MCJ9BPH
         INVswBvxDFQzx/BXbMm+u7f9gujlsDK/S6mCgnhId4gU0VZKo+DvqawMxOzfFbO0X9Qr
         UTpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="P/xE9AdP";
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hSS2M4O68Oclz7FRo9ove4nxKIu0CBGmTJa4ZzHFjak=;
        b=mTAai/nH/OkQaXKTvoJJhC0s5HIcoiNa93x/ZAM8IIwigPWpAWZMOEoO5H8qCn7Rnk
         lRQmOY7yJSiHvKF9gjoowmQ19x2QibK85JV9Wru8krvYPRL4TaOhWPN+hvD9egHKgtDR
         CG+R7SwM7STw4sT7iF9PMAqXAAH4TyBZQjIZXIkFhJ1IWe1HbYpbDNvPN/QGyySURwta
         ETMk9rbI8PQ8gjPSGOo0iVbkrLZ/MGP6t5JpjWBARe73voFR76sCWA0LuJSc3SPY6PmT
         z8Wxwy+rtFjKmbADK5uXqBhk0Ol8uhdPNm1SfjDe0EO9Eg2UVMK8zWBV72nyQoRc1jOK
         SASw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hSS2M4O68Oclz7FRo9ove4nxKIu0CBGmTJa4ZzHFjak=;
        b=nyLM3Mfij4tqUTOZY+ToQoyz5Lg9GU3X544d7IQpZ0R279CA4tq5e9NSyvkqz4LHdV
         qq2tn+ALJiqkTPodwwv2kH+Xjc4wW5Rrs8zV/fjGcYqlH/qz3oXCsQ7QC/puVjkUyOCE
         eT0mUMd7cjYVTxznEcpczraaI00cTlO+7kN+WX25Xeo6E3OPDIDpsDF1pSxeoiAXzlVF
         g9bi+Nu02U3oduNDlilIyIioTZEAthABprv0/OcGdab1hoY6VXBvc0pRT+mWT2eP/TWt
         CqqsW+pQdhTiWO3mlztaeLbCrd9kGYLeKmMgp9w4x4TS9MNOAF6FZf2NAos1+embfSZ/
         DoiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tJiVt+hxEvkNqiOKXTXFHBLoIkAIIws13LhaTB28OgnshNPtm
	S/ydFYKMl9rfGnjjuRJdnls=
X-Google-Smtp-Source: ABdhPJyOF7t9emEQIh8dhQjoVGx57gr0zr7aYlTBie7QKXL2443djIWVXE+gKqkLLFs4MzdMQQVyRA==
X-Received: by 2002:a9d:6b10:: with SMTP id g16mr11289818otp.301.1607726465023;
        Fri, 11 Dec 2020 14:41:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4542:: with SMTP id s63ls2653539oia.4.gmail; Fri, 11 Dec
 2020 14:41:04 -0800 (PST)
X-Received: by 2002:aca:53ca:: with SMTP id h193mr11115681oib.122.1607726464704;
        Fri, 11 Dec 2020 14:41:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607726464; cv=none;
        d=google.com; s=arc-20160816;
        b=MyPtp7yafnZ+2StWfqp7bYXqiskTS1N6s+LeJEU0UVq8xZuXRdH/i5X/ruSGkpu/kd
         /Yu2BC9qtSkBEf8j4EOhh0bhEQqenirbGdCLyxEeDJRusJayDoprkLaBToekZp2lmWM0
         MuLumAA1V1FNdYQfxR9akDts0zNn3D842W8ncOP17SAXABLZVJB2qAK1kpyewe7MIN74
         YfLt3gRvu9RV8p0vMmxjt4XEVTxAADWXf7Wo12Y58lTQylKnm4A59yg0YJ4GDE77Bl0K
         95+vNg3aJU9mTVH4v812pYujg85bQLcjHluNXcKRmWA8e1csM9jWxAPlVVHLhF+y0Zub
         3ZGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=kRziVBg8lxW7XznDihZSexr48+5dmZZATas/+pUCCCU=;
        b=AgUU0MZqgl/D6B4OgUx26QVaLhkp6wy0v19i2QpnGsKQ87XxGLsyi6/iMD56MBR/Rm
         qzldIzWrwB95o6ijV3oQ+yYTKzkvun9yQtuoK1MZF5cUd8xveLO/UyhC4nB62Z3yHj5h
         imEnawtDJ8WVC7h+5DmhAxviQGKBSUIggyMoCfCgiVOpVe4TbruhIHQmB881IABPaeBq
         graPHF4gs2onZ8iRNVedwbHuj8qkzjd2hqHjldwCa9sFqHF60bsLJaKMRZiZLovv0xzh
         tiXgH4vLcS9pkOi2Va3IhZuCuRrE0GVYiwtdzY+C34oDKpIGtK8T/cG0m32a++oaqIo3
         KYJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="P/xE9AdP";
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u25si686884oic.0.2020.12.11.14.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Dec 2020 14:41:04 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Fri, 11 Dec 2020 23:41:01 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 2/3] tick/sched: Remove bogus boot "safety" check
Message-ID: <20201211224101.GD595642@lothringen>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.725238293@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201206212002.725238293@linutronix.de>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="P/xE9AdP";       spf=pass
 (google.com: domain of frederic@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, Dec 06, 2020 at 10:12:55PM +0100, Thomas Gleixner wrote:
> can_stop_idle_tick() checks whether the do_timer() duty has been taken over
> by a CPU on boot. That's silly because the boot CPU always takes over with
> the initial clockevent device.
> 
> But even if no CPU would have installed a clockevent and taken over the
> duty then the question whether the tick on the current CPU can be stopped
> or not is moot. In that case the current CPU would have no clockevent
> either, so there would be nothing to keep ticking.
> 
> Remove it.
> 
> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>

Acked-by: Frederic Weisbecker <frederic@kernel.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201211224101.GD595642%40lothringen.
