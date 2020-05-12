Return-Path: <kasan-dev+bncBCV5TUXXRUIBBWPI5P2QKGQE2ORGNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF7A51CFDFC
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 21:09:14 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id m9sf5342733qtf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 12:09:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589310553; cv=pass;
        d=google.com; s=arc-20160816;
        b=v0+20Ou+aYqnXriLVNkCQOBpBKPlJCfYTRvP0yCJQed8DWAabVhISpD/fu0myO1Jj9
         6ksaGRYBx8J/jmtWq5lOEh0N78o1X1q2hRtBE23CHdeOnk5yfl+IjextxHJZja2kwXWI
         yDw19BP9xsq9BLqQEYa1RHXzoj5oRLE3qVSWDoesc3gRCdodZ7kscn/k27rHgUCtpDB2
         9zXuBrahfmZXpVVZzhmvrIw0SENE4rXttfTCGqRnFlq2ARI0WuQcz7P4gYr1HcYZqb0b
         9MWfJc/+sO1QC6FYE7vtPnpb5d50RiikE6ccx8LJxfAUN4gFPAzE/iR+neS1lq0dJltX
         w7Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PJkkas5LGG0MNSFdBQFJPwmSUKReSaeKyi2tmM1phfQ=;
        b=wJOR+5buVunknTlfy3rtOXQNA4ZmQZ9QUE99PTqiKTkQfuzq1e+lDt6y/F3Eb6ahM3
         bQIthycHANlrkeE0eX+aYIE5thX4pBL24KPacXx8xAiGt3SDLJylJMzS4Xh7qTwjjxhp
         R1Q/dlZuc0Id20Ayr9zPCkGuFmrHRGY9/vgqrcFas+DXFtwldjHEiB3099Im405Mn7pc
         YjuKgf1nrjXZ/OQzAzRWbWEJXK0QNw06snEapzqzAYPO+YXHgS+2sGwOzdbTNRfEFSMQ
         gFljNoI6xwB6ZzVgbq8m8hySq0r+9+sRxLYWo0D/gMbo/rWH4ezk91Kd6KbBPNaiipc6
         s1GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rx5iU2PY;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PJkkas5LGG0MNSFdBQFJPwmSUKReSaeKyi2tmM1phfQ=;
        b=cW0jaYsAQS2hNd+kwQt+jFQzxCQKsMd+VKhLzPRiKVlXC5oKOayPEpj/Rz1UvlJvGj
         Zl1MT7ka1n2qcRQz9Y8HDgWXfpfxTtLKr6RjBUKG9rqW3Qggt6u8+BafFtjJdCFUFs3C
         BrZWBUztxks7YO5aj37Np/8FaY25BxXjJ1eNtTGd6pTRofVqKzQVeWQIyD5bXCl36zhu
         RLb9DTXRy1TyArgPSt4PRlJSFy8IpLKAgtAjVDdD1fwXXI7BT5cAkj9Q/0JeFt+4/tVv
         CGzG5Hfney2KJ6mbQStN+piOtP+04YhLe+RqVHBdGsfHzYSoQNNMfpIozcQsxaqX5Fjz
         YX/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PJkkas5LGG0MNSFdBQFJPwmSUKReSaeKyi2tmM1phfQ=;
        b=lmIjc6iKz5F6zKJN13vHE203ajXBeSwxmD079uTROVAcPp71lHzB1VpTz8lL4+AR76
         x0BvuJk/9tFVGYETPfITKahTNi/16Zh4HSGd20/x9RfLSt74NzFuXz4ECcyg95iaT2gu
         owcE7gnDgNa3Kj7mN1maEOMEjsHwvqY8lp1jcMk69kwq00MJubXBhDpdqqugWmHqitDz
         LWZrxEcXERu+l9FqZQzvZ4OSMUyQKXLRLUnT65ngEMWLfPEhD3vc0Kl9JSUhGIpkD7iM
         PT/HO1IjsWK4NajJMo6eqw99QQCdNggMpHtQtmO5ZDQPskwV64ymXWpnYY42DliTnpFf
         ODgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubBjZ23dHZpJEmi3k9OcOyNVQjkalENFeH4MWrjx88yuNIxrBQ2
	lVMA5g/C9UWiotzw9NK6nbA=
X-Google-Smtp-Source: APiQypKN7ig47Svwj5rGRbT1mxzqwtbHJ1m1C8A+/EciLEllB0oqxwWm/jrwH/FVX1YyDr5z870csw==
X-Received: by 2002:ac8:66d8:: with SMTP id m24mr23452576qtp.175.1589310553526;
        Tue, 12 May 2020 12:09:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3fd5:: with SMTP id w21ls6390464qth.7.gmail; Tue, 12 May
 2020 12:09:13 -0700 (PDT)
X-Received: by 2002:ac8:7b81:: with SMTP id p1mr11255451qtu.305.1589310553168;
        Tue, 12 May 2020 12:09:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589310553; cv=none;
        d=google.com; s=arc-20160816;
        b=LmmZe5DIPwEiUvrl/Dvapfaegx/AnkSI71NI4fFfTV3rBMSMcO0+rmhlhIzWRxKRJM
         860MyoLq8ubnpYTup1xozJttI3exd8hUb71E0SFansUd768N1aL9yjQGyPMdmCLjtanx
         CBAX5lzGOw+0sBEm69g/IBpzhFoSY75cgGqanUw02YP+7vYtgK5sfkywiNstpMLb4d85
         TdA8hqGuBGx7qsDxScBpS3cpYn+JVV5AzA3P2ri80FLWJza6QRDwuP14utmoQkIDFRaF
         e5lqf6y3/uYR6aT0kUVwNUeRIA0V/ofsNFXjRWVaLInL4Q6diDoPrZ7f0dL7Rks4pHjY
         D57w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EkBz8hLKynQENtHUYkQjAAzLTeUzsxCnvhIcGmmRee4=;
        b=bZBV2SRUZNIHHRLf5Tw5yYarFrZYrFxipV3gKke8b7yh+JufGzoZjqUDBaF6wJZSAI
         jBO7tVRdtr+V+yyBFG1lyOXaRdWeyRS9cPjpJsgp16rHiwFB5txWgB5YsIjmit2Xqd9c
         /BOH2QR0YMQyywtHMnnFCQyS2zpTNFwZteZlNP7N9iOksk/imw8Vsv7GQ9wp+XHwcXbX
         GG+s+KcE6dJ5F97lhEImhv07T1tZSEWkp6ZDS/XI8CZkoufm1+w7McFg/zogrsOyY/7y
         96fIghAziCemRI/GLimn8lYn8lYlYG0/6ktIuiS5S6TX9loVv/ASLkzNk2rx1punS4TD
         AdHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rx5iU2PY;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id z18si489083qtz.0.2020.05.12.12.09.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 May 2020 12:09:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jYaHA-0001AY-4E; Tue, 12 May 2020 19:09:12 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8D121304DB2;
	Tue, 12 May 2020 21:09:10 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7E65528B27274; Tue, 12 May 2020 21:09:10 +0200 (CEST)
Date: Tue, 12 May 2020 21:09:10 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE
 variants
Message-ID: <20200512190910.GM2957@hirez.programming.kicks-ass.net>
References: <20200512183839.2373-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200512183839.2373-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=rx5iU2PY;
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

On Tue, May 12, 2020 at 08:38:39PM +0200, Marco Elver wrote:
> diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> index 741c93c62ecf..e902ca5de811 100644
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -224,13 +224,16 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
>   * atomicity or dependency ordering guarantees. Note that this may result
>   * in tears!
>   */
> -#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
> +#define __READ_ONCE(x)							\
> +({									\
> +	kcsan_check_atomic_read(&(x), sizeof(x));			\
> +	data_race((*(const volatile __unqual_scalar_typeof(x) *)&(x))); \
> +})

NAK

This will actively insert instrumentation into __READ_ONCE() and I need
it to not have any.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512190910.GM2957%40hirez.programming.kicks-ass.net.
