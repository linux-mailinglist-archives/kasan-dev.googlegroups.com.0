Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJ6E7L2QKGQELEYPYXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05F7A1D5001
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 16:07:37 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id a14sf1004742qto.6
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 07:07:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589551656; cv=pass;
        d=google.com; s=arc-20160816;
        b=I17dZePmZGCqjNrCHS19WyIxXOFZ47ivnFlaNJW398RqiBUTyzrqnSMlGvn1aniZSr
         xlygBNYkOi7ZkDE+ozrBA+//BI5Iya+lwhQUrbLKno86tiLWwz1FOYiCNhmH2cpmV3KS
         2vOW4tq/7fepeIAgXI7dofq2DQEuB9fdVYUiU93Q6BJ1k0m/1E9H1bFS/VwZyKI12RSk
         ea2z/fPmMarRAQeeKNb7+Q7odLOuy1XvB+Ak8mY5PF8xto+nqaPeLsZaBpOxgc5xHhLu
         b0FAukAZ2+ZiEENiNzR3isUh+3mbkSa6SnHxC2ZHVVSdFaJV5B9n8ZStd5L9HtOR4S9h
         jbSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jVwNBqttjM2SfnnfxhwPyv+tbpucqLPf9JyqvLXmHeA=;
        b=YU3qR8cExKVdt9KkB63PcwYGURj3/mTNtI8W5M8i59Zczv1IlECLryxLsaghg0u/9B
         BkvbY/9GtkPylboJ+b3SneOk1Kth4gzNmbyO+ekQ9BCDN8lvUantVHunW6wNEdv/U/Az
         8fGlbbrTpn1qP93II85+im1W5huG+vfoeesdy6lQCSXlXEiOOJslH3RwPiJhu+Ya+mkO
         n8oyYiUZDW13JNhg1OkhKOfeewptJXh6YDjbDVqvLKHLGfiSzUUWH5uE8szJJsek+hLt
         H+RF2YvWbT7NePVQ4oG52Nd51W/vzxuHlsCI/BCa5eB4b6fbGr1NBizae2BnrvzheBGp
         1+kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zUHgBjH0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jVwNBqttjM2SfnnfxhwPyv+tbpucqLPf9JyqvLXmHeA=;
        b=AAGo2SkeD/03sT+EWepG1SBc2NQGAi2BhIr4fNh+UUm3dMFwmqsrTHdXKB5dn37oK5
         2NWmxeu/5RKnCYnforru5diqrO+vXBmbV1JGlPK5XjwiPS3xPvpqztecmM4qJnye4OLI
         HYMXA54Oam/++lF7o3UK/47bW53LMbjsU0y/6faY2pexNExAMk28w6Kh+8YC2eapF/CX
         6a1zPXifLlznfu3ri1coeo7S9a/a9/FYfL/mnDOe8qsf5yp0rks2SeXQL38Sz069JX7t
         eBVLa/jDvc8alLwA/sCHzejMtM0wmJVkZXC9BnpIW+br2sM7W1CZ6y6ehRRgq5Qu3AHP
         DaVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jVwNBqttjM2SfnnfxhwPyv+tbpucqLPf9JyqvLXmHeA=;
        b=GXlkDPhT2hl9EHRq019rPuF6Y12Oxdvs2Zc6gRO8GLPnUbm7tgDQEAktpHWH6wgwQy
         5pTQC8XWzZXBL3QTkoyOLtJtJn9n5edvaae+Uj/hbCvIg5BNxJAduhlcB56IUWpUl2Kd
         3uqqLpzoQiQUG1yF2fTI39HgAiVIHfvTfT/mFYI48i/7WEU5u0V5afqdv7yFiWi+Fikq
         FUSLU5Xw1p3exFJIu7zVvh1BSOmkpXjG+FW/xNY750Z9dBKHVOU+IMRoggxEqwgkqMZa
         BAz31XyFuRNSY9xlTgAd9sKe92SvolfW3tUjql5XgmfZ6hldcOAl5s2zslFKBjfZUelm
         Fweg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DY3jY9hr5HzyVMrvuih7gxvSccN+J0cL2peao70G2knGEUIjs
	DdXIT84GkqTkmk6ZPY8yqV0=
X-Google-Smtp-Source: ABdhPJx9w0NkK+wJI71H+ESA8l2pQ3dEyvrq4YMmTTM4XHTkLoinjPb22lcaluwosEILySVm6plmyQ==
X-Received: by 2002:ac8:4a06:: with SMTP id x6mr3531936qtq.214.1589551655800;
        Fri, 15 May 2020 07:07:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e53:: with SMTP id e19ls895294qtw.3.gmail; Fri, 15 May
 2020 07:07:35 -0700 (PDT)
X-Received: by 2002:aed:2542:: with SMTP id w2mr3734451qtc.43.1589551655375;
        Fri, 15 May 2020 07:07:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589551655; cv=none;
        d=google.com; s=arc-20160816;
        b=W5Y01wJpz43b8ud+9N+jvqwxlO+swftUTDOTbn4CkBML8O1HVb3bwjSxPR3rdvQixo
         Rc6m6yszaiCoFIuSJuiGt3dR5HlwncWutOb77Cj2FhL0mJLD4WQVdZ3Deuwbl6HERCod
         WwWpA76kAG1KSlZuP8xvFtAk+j8ldh3Mk5cwvVq5L/iPh5PIxbVfbx29T5H1aZB7Qrp1
         lSnTpJtyLMdo90AcylTrGWjkOm/L68KLNrZ7C7qjAVc++K5/3n31RNBUQREEDjG3BGXG
         EEZFpAw4+FHK/o8aTsYd9Xw7SZP4BtIwlxIDaz4CDbgM1h6Ugv/P4oAGaFTwAh1B6Fst
         Mcdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+dIiT/UOLZH4C4698DgVf1kBe7ueqiNo1hUe6DDcp2E=;
        b=lGiISjdADm6+ZaQHSm/5ibr3FGXbBbaa7R3IAdDexsB2p1/jpYmUMN+KM/9orEmAkC
         CUpEVXW8woNw4Ka/OYRZxLz54k91q8zpBUK3CbMGH+0qzqq9k3Z77rKFWW8NETrYp0JN
         55iecuRZbpnIjK25MTiT5SUrk35zuYUONb14AhOkOHXuWN0NiIuJzWBzacAWDFBCxry/
         ludssEi7BkUsgVoh0CXW1h2lhCrue/dcmmg8imjnOciOO3IkQPP8U8JVj3bTN7wV8fHk
         brJTklkR6vsqm4JBbUeaA41jCHz05/I4Hvx7FfYKIi47brYhhi5pbjgs6QB6IFrT+lIw
         isvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zUHgBjH0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id p187si139287qke.1.2020.05.15.07.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 May 2020 07:07:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jZazl-00027r-FC; Fri, 15 May 2020 14:07:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E1D11300261;
	Fri, 15 May 2020 16:07:20 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C8A8E202E0F9C; Fri, 15 May 2020 16:07:20 +0200 (CEST)
Date: Fri, 15 May 2020 16:07:20 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: David Laight <David.Laight@ACULAB.COM>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200515140720.GE2940@hirez.programming.kicks-ass.net>
References: <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
 <20200514142450.GC2978@hirez.programming.kicks-ass.net>
 <26283b5bccc8402cb8c243c569676dbd@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <26283b5bccc8402cb8c243c569676dbd@AcuMS.aculab.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=zUHgBjH0;
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

On Fri, May 15, 2020 at 01:55:43PM +0000, David Laight wrote:
> From: Peter Zijlstra
> > Sent: 14 May 2020 15:25
> ..
> > Exact same requirements, KASAN even has the data_race() problem through
> > READ_ONCE_NOCHECK(), UBSAN doesn't and might be simpler because of it.
> 
> What happens if you implement READ_ONCE_NOCHECK() with an
> asm() statement containing a memory load?
> 
> Is that enough to kill all the instrumentation?

You'll have to implement it for all archs, but yes, I think that ought
to work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515140720.GE2940%40hirez.programming.kicks-ass.net.
