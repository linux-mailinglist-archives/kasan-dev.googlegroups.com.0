Return-Path: <kasan-dev+bncBCV5TUXXRUIBBFNXYX3AKGQEAUQD6BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 43F5C1E8711
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 20:59:34 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id u1sf125239lfu.10
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 11:59:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590778773; cv=pass;
        d=google.com; s=arc-20160816;
        b=kFZ7Xr1AiudZJlrV0xzAD7b1gNNvX8mFqHAeCXucADnfcd2OhGO08Ft3RaK0J+19nm
         pkhv67HMcZ4h2KseFQW23lmtGN4gzHO50cFmkHoVzWDvna9Aku0lSHBaTNIKsEBKyvSe
         Fe/CIXCgkvaztNng+MhJA9FJIzOHwqZxaIn3DkgHNtNDnQ8nDZPSUVyLoloaD8ZsSkqy
         fgHqrC4a24rEel9uEoOZYVAFEzGn9kPpczYqvJW6jetE3GjBr8xeGNRe8Nj7AnwOnKD7
         LntQViqGZFWpald6TAnzN6+ZaTv1dv/4ZclWvbSK2fnya2+RiLBWUWlD2ccOlN8TcGa5
         SqYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PUgL32FXFrmCVGlAv6EkxacxndQsNZw99QrHOJujHA4=;
        b=O3NOml3Z/uz768kLlvGCQL0k6adkDqitk/d1IYax0+KCtDz3cGQ8hw0WL7PCugHjFp
         uaCZvBQWoiLwsLjgObwySLaQ5nytbSz/gz8nOQQCDc7YjVetxBbp/AS45HsKrpUN+PnO
         JOvFR8pyDIYdRgPFXq65/gszo/cSd3xA9ARdnW7XjmTPt6p/Jp/+qKYx5Adf+7zSbBSH
         ZOA2Bqt7+UMqkNwzqOqo+QY1ZOFz2vevru7p13HwzQ6FCVpzVtlPFsKyOqbqHt5gjMd9
         hGeHQrZtaMRFM0pAl0vStN7wjfvrvJUfSOwTWpQiRCgVDEDcZPK3OBBAuhgONd3Lpd5e
         vX4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rYVhBf3F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PUgL32FXFrmCVGlAv6EkxacxndQsNZw99QrHOJujHA4=;
        b=Rw/qKGV4UF9Ll7kHj7GBR8YgZ1guW4hXQ27LG9On9h2cH1r0t4uJXujalTyRxTqvlW
         80WfcbQmvQ/2CGz31jHKLvPE5WeWANxmUfZLxeGyisJUnwUPyLBmVJisuFL69J0tJx+H
         oepE4TELd0AYWU10AsEXpL5znwGpM6mFKFiytx1PqMsoFjQJb2BBwvxYQLUS/OH5sJut
         HfnCdouqoQWzF4QofHxLVm730hH6JLs5codR01jw1u6eYfnd7p/RKXi0HNg50kR5TlPo
         EadPijqs/twZxTL10i3Rr5D02TOAk4AcHByAkYnuZlICyndcBDRN+EauboYrh5CghY4o
         soeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PUgL32FXFrmCVGlAv6EkxacxndQsNZw99QrHOJujHA4=;
        b=F1pO0IryFRV+U22cvzMsYaaewXSdQCj+tGTSs6ScJp2rxMbu3RezaJuIUNtavi2oAY
         0EiyQXUaN9a5aPnD0HdqIyez8izlEPAGpfAY0zo8Z41lg3l6+Ya/PBctoYzX/K/0AaVy
         B6omgN0Ow7anGPUkDd674GGbkb0NQFeYSqy1yi7PH5bP86m1WkAqmHveUyZRQ7hqxEbM
         g46nwRxdHYE3uOCSOf6wLLVcfkPqXVSs6qtYKdwZRPBRCqGBysoFexlluJOs1NMW0SbO
         qENToipJ3qrXRxWWV4aVFUmmfjkCHgZrMxqO5XgtDxK2dp/dLQHykOt7P87vHoDLjDuC
         0a8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jzVBpnj3Lw7i8/rJqiOvyrjkJCr4a2GrYvnqimuV7AjDnbrHk
	FXZGs0a0WUv+LNYHYWwTdOw=
X-Google-Smtp-Source: ABdhPJxuEH18cY4dmqlYeKkaXKBfHFU8m6JoTUdUTyxrtoN6HbXHR5LDRkw5izCUTpn3TPD8smTYpw==
X-Received: by 2002:a2e:9957:: with SMTP id r23mr5090415ljj.226.1590778773666;
        Fri, 29 May 2020 11:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9042:: with SMTP id n2ls393748ljg.4.gmail; Fri, 29 May
 2020 11:59:33 -0700 (PDT)
X-Received: by 2002:a05:651c:1187:: with SMTP id w7mr4805083ljo.438.1590778773114;
        Fri, 29 May 2020 11:59:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590778773; cv=none;
        d=google.com; s=arc-20160816;
        b=bpkQOsZCFhteOc8P6myvp89ncF4RbZrCsdhmMhzAa3rz0JeAbiOgj842wfFHz2QaNx
         ZJiTx0pYfhLgH8tD2vw6l7GSdh5dQSTDxX4hE/+VHmim3OHFyrZwXxuTxVEolMGzrhcN
         FxJMR9KWZkRTjP5OTpsd0JFwV9RBXAJprgJxn7u7RbxcNyQs4I04qB9Koxp6S9IZ4UlH
         2xr7hhLmWGeVdt8G0ynLrpVqx5i6o5VnbAj1CVTcUvt/qwCB3v/LVeYnzneCDqSQ+h4e
         zBBJ9os9yt23YmBfqRtWRPWJoxN0UxfMpfkF5ePpC6mXke899FfwXLO3YCfIDHhxV1iw
         Q9xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sY/tG9kiE2VS5p/SHx6PtXudEGBk05lKgFcJLmAGXLg=;
        b=sHEj7wcjV9c72YqWDs1IEyCDrTgt0ASrwt2TH/TpNkNoCP6yDvJPWFUxWodNOAJJPm
         2EO1g5mKYjW2CVnl6c3OVpMKc6iEi/7FBhdPMksf3rLiB2SnKflAkh8p5TLLfdpNkS1m
         IXMivMk1lydemmOamCFQYnAw9m/gmHyxUDcjDzTT4j82FPHCJJg1CyKqJlw1UE6ie/u/
         2pE5OIJtHEstIhJuVJewEPW5pYuiR2TQ0Q5ZKlSP3r15USgwpzTkeEHs3Qcq1UEhBnfm
         jClsVOcjzmBIcjGPZD6gm2QBjdIXRhZsfaKqVmNFLinRrArvxYTk9RJJ8UZT6kGTKPwG
         ZRPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=rYVhBf3F;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id b20si657466lji.6.2020.05.29.11.59.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 May 2020 11:59:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jekE2-0006zO-66; Fri, 29 May 2020 18:59:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A315830047A;
	Fri, 29 May 2020 20:59:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 983AB2021AF65; Fri, 29 May 2020 20:59:23 +0200 (CEST)
Date: Fri, 29 May 2020 20:59:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v3 05/11] kcsan: Remove 'noinline' from
 __no_kcsan_or_inline
Message-ID: <20200529185923.GO706495@hirez.programming.kicks-ass.net>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-6-elver@google.com>
 <20200529170755.GN706495@hirez.programming.kicks-ass.net>
 <CANpmjNPaL=HRvaJOC37_Cf4S4kskZezmgRiDSGn460rO2dM4+g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPaL=HRvaJOC37_Cf4S4kskZezmgRiDSGn460rO2dM4+g@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=rYVhBf3F;
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

On Fri, May 29, 2020 at 08:36:56PM +0200, Marco Elver wrote:

> > +/* Section for code which can't be instrumented at all */
> > +#define noinstr                                                                \
> > +       noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
> > +
> 
> Will this eventually need __no_sanitize_address?

Yes, and __no_sanitize_undefined and whatever else there is.

https://lkml.kernel.org/r/20200529171104.GD706518@hirez.programming.kicks-ass.net


> Acked -- if you send a patch, do split the test-related change, so
> that Paul can apply it to the test which is currently only in -rcu.

Ok, I'll try not forget over the weekend ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200529185923.GO706495%40hirez.programming.kicks-ass.net.
