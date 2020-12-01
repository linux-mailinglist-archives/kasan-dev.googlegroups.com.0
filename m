Return-Path: <kasan-dev+bncBAABBRPMTH7AKGQE53G6YPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 24FED2CA913
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:58:47 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id z28sf1364148pfr.12
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:58:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841926; cv=pass;
        d=google.com; s=arc-20160816;
        b=sM4FIB6HNt7aFg0SgiT/MOnQjn55w/Enf5TNEN6fWOqfTKNIjTWitaN97FIlOg1oTG
         24gNdqXtxHz2QNtmvgmUTZuJLQ0SzKXAtJdjT0GCVCW7Za4Hxe1fg51jg8myEUsOKMNI
         IdxBhOa1jnYqfz5AQzCgATMfpPDaKWc7CWx5u2dJUf1djVS+PLnz7SFzm77cOxn4yI+c
         PnELVR12x4t0wpq8Uzez6z1TiGLrd/IDTf8j7/7es5PhrQOxExMIheboF7FxoOBNucJz
         Wl7+RhlSAUD1RSMZCSRRCEuyKK1OvkqF6jeeNYVjQBEevpM196hE8Px5kSbbcsiAxmtE
         2IZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=bTNLXpxmsZSjdpmC5pfioWT0GyEVQZlgKdUaXCWqDbA=;
        b=Fxet4r56BilFzhDOMfrqkMx5+MvSK4BJco8/N1xaF11JISo54GJ91E46Kk86K95W43
         Swp+GsLArEmgdN46J4AiuXDndcXY7g5KIAl598LibsjRXblFS43NMAri1k1aYlrSY6PT
         08XZ6hgoIQ0AqNNbFECJQeUu1OBiORlBIOYB+EIyAswh925k5A2TyWpDuT9yMZusmmt3
         E8TfxDfVP+AbiRXiG5K/TAcamRtLLs5Ovq1UqiAtci3cSNbZ8zMvJQQQbk0GKI04kCId
         KOEiprVHp8pkpz1eHsMvyIxmaFNSMT6nAHzddi8jdvxXyFq/3NkSoXoeamBFiSKRqtcB
         SKhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CoMFJYJW;
       spf=pass (google.com: domain of srs0=wfi7=ff=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wFi7=FF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bTNLXpxmsZSjdpmC5pfioWT0GyEVQZlgKdUaXCWqDbA=;
        b=LABpECqgY3j9GV/UV0CZ/SD9h/vzsCyEwhRCzKsaoKouO+H2C3IwVtttoiIdXjqHLq
         CwXLtGqAOjTylOwnt4YJ68TdyjINIJVMHAIvbclgXJ7T1VxUcxhSZLUmvYSFsYNAXNZ5
         JMsZlQeUSR+QflZ4ZWp9aHhVXdjqCDraDgaDVqLStvV/f+DjfD+S3aUQ0d2tTxpIuaS9
         NtHo1/xpfksENFeu7A27YufswW1x1o520XEXJP/NdNglB8KLKAHopDfIoKxgployCweS
         jkjHquNnRmKN0NQz4AB6VP4HbztbDHSsWMS2Tx1VZCtNXGndb5NmLCUMLOwATehy5ohZ
         6jGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bTNLXpxmsZSjdpmC5pfioWT0GyEVQZlgKdUaXCWqDbA=;
        b=TRIRp7rUL2B4C/qyCaexgmDEHfaWB25/KJfx2DBpQQ0vp9ehzke2L+RBYui+MESvTy
         GsLIFd+Q/+1T5rzKkXYXaU45siQ4/TruqfrbWL3UzfV6UQ8H0nEKCVzzc7AlZAeV1dv7
         JIHehtVsVWkWzpawuowGtU7rm5B7pdWpRXEF0liD1Ggo6XhwJo53hsh407phfiQe6g6S
         2XGIpDpM9aqiUBbE0KwykBnTz+fVScbmAawGvLCIh2ZuDLDQQqrOaFgMqegwKpE2OeeJ
         5Pd7zQTU7iW7sGLcG1BHQx7aetadjzn4KpfLWIZ2q//zf5YX31wmab3z0AzqiwujHb2S
         WUzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Uoct5vrEcMIOG45GpPoHkhk4D5BCVOOeZH3r0GcgAR+E5MbRG
	fV6J147IQ47C3vdaZlPuHds=
X-Google-Smtp-Source: ABdhPJxQiWu/aI0wrg3cFxlNBo+53woSeFYHEINPMCRnF1hP8419WzSJCye+RtKASK2VHQim/2gLcw==
X-Received: by 2002:a17:90b:a0d:: with SMTP id gg13mr3483016pjb.223.1606841925853;
        Tue, 01 Dec 2020 08:58:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls1556792pjx.2.canary-gmail;
 Tue, 01 Dec 2020 08:58:45 -0800 (PST)
X-Received: by 2002:a17:90a:c90f:: with SMTP id v15mr3641418pjt.8.1606841925489;
        Tue, 01 Dec 2020 08:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841925; cv=none;
        d=google.com; s=arc-20160816;
        b=e0Q/LGo873oRnk2hA0AMXDqzlTigpHq+mkOdkcRRfEbw77XSTYPooNXtXm4w+utioK
         GH/9XztZAslCwJTfHGrT5ktG0M/lAs+zdQaG4P71HP3KrfmUJHnOycsXYoM4hC8oRHAp
         vlGlqQQGsMXmpXTnMxgO6LH6rW+cs3REu6pEKqEkzVtyL09WLSqdFJeUm+BBc/+wQYoL
         g9eqZMd277NE+bfxqh9uXiE2xmAyJAGbFvoUrWkgvkVgZsj9VoVaRS18bYvyN8Nfff/k
         hoxv54GZBbcRPdu/pBQScqgfhHh2HOgwoPD8ChhuY0vHhNj6XuvJgm5byOn5MGWtrf/K
         gIQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KMkvv9NSGbtPIL0+8ClvlivmbPxRWm5S9xTYJZOYL5A=;
        b=vIsrZwiaiYcaY7cqie5XPQut+r8J6cphKFoPBvTqxr8wGzVC66Qu4k90voD/kjUG7c
         QAOp3qmR1QgdFjmZ+O1nwhFLWipNJgnILx8rIZuimxDzkFAXYsPYVjEmDjpn2AOb8oHa
         yqKEaMc77/4c3gqZnj6hVE8nz3Kk1s+ZSkTUf8crF1ib2v+h3Lm8XeAnaCATN6nfT1SV
         zbZ/5KassTJ3Iq+x/1ra4K3d6AbR0FUy2qF8PibHWnwhAvc+kz4OJ3BiZBRqeFH1Dvwe
         nIKLv0HbCkj/4+FBt81VZSBOPGUH7kBLwXP7IQuxKwbnBaIt5JFu0sS5brnLaJyhI/FM
         XO/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CoMFJYJW;
       spf=pass (google.com: domain of srs0=wfi7=ff=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wFi7=FF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w6si30546pjr.2.2020.12.01.08.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wfi7=ff=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F1943208C3;
	Tue,  1 Dec 2020 16:58:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 8F1E935225C2; Tue,  1 Dec 2020 08:58:44 -0800 (PST)
Date: Tue, 1 Dec 2020 08:58:44 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, tglx@linutronix.de,
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 2/2] random32: Re-enable KCSAN instrumentation
Message-ID: <20201201165844.GH1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201124110210.495616-1-elver@google.com>
 <20201124110210.495616-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201124110210.495616-2-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CoMFJYJW;       spf=pass
 (google.com: domain of srs0=wfi7=ff=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wFi7=FF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Nov 24, 2020 at 12:02:10PM +0100, Marco Elver wrote:
> Re-enable KCSAN instrumentation, now that KCSAN no longer relies on code
> in lib/random32.c.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued and pushed both, thank you!

							Thanx, Paul

> ---
> v3:
> * Add patch to series, since KCSAN no longer needs lib/random32.c.
> ---
>  lib/Makefile | 3 ---
>  1 file changed, 3 deletions(-)
> 
> diff --git a/lib/Makefile b/lib/Makefile
> index ce45af50983a..301020c49533 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -27,9 +27,6 @@ KASAN_SANITIZE_string.o := n
>  CFLAGS_string.o += -fno-stack-protector
>  endif
>  
> -# Used by KCSAN while enabled, avoid recursion.
> -KCSAN_SANITIZE_random32.o := n
> -
>  lib-y := ctype.o string.o vsprintf.o cmdline.o \
>  	 rbtree.o radix-tree.o timerqueue.o xarray.o \
>  	 idr.o extable.o sha1.o irq_regs.o argv_split.o \
> -- 
> 2.29.2.454.gaff20da3a2-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201165844.GH1437%40paulmck-ThinkPad-P72.
