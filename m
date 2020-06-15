Return-Path: <kasan-dev+bncBCV5TUXXRUIBBL5IT33QKGQEVM5MXSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id ED7DB1F9BFA
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:30:57 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id w20sf8421967oth.20
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:30:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592235057; cv=pass;
        d=google.com; s=arc-20160816;
        b=IHYmXFj3L7LsuZUReZJgEr+4dzAASSVFCNlI5e7zsJfm1sSjjWyW/TqV80JhhNngk3
         RTpBgjOgU67Xl+TJWCLWczAASf8k89wncMWmvTxf8I4eTHMyZm7IRw5wOWaVAct3bdkw
         TrVur189YvZ5s/vzFWHHWxqU1N6uFdPyuG3TSTTgPHQGjcVr/RowXKR9jvSpj7ru3ZSY
         X1PNh7UOLKa4OWxZs+AaNEL6BZGY7ePuyyqO4XASHogSF6k3Xa3Hw6yJtt0seDHKLFIz
         9C8tKEGXSL4+1it/F9Z9ik5c5cun2EyXDaJPG+gOCrLdx2G8mqbqF951AjiJXaJBW3vD
         4hwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0zvnf5IIJGYWKHYB/ONo+l+CGw+gQ7ZpWsTIeXRpqxk=;
        b=q0IPFyeKABXqZBwlhTjUFW5klo3FRMu7f6QCaGSHFSa6oqY00g4v8LipUxCyNoEWiA
         wImfRgBgI9tDOkY/BTnGci8bN1JMVMhyFH2iLSLfBb+I+2fJX+ETKdbLh7cud0EWq/8f
         ZW4QYOFnqUvquo3fwFN0GvfXXuXxpqisQiXO8Rct7aTIIG0HMfxbLxPeOKq7dlUqDXNJ
         nytCLeDbvh3GkCvH1vXWzkywOY+q5JFbxRAuD41IVdSTWzPEn8vwTsImkJeRLC8SX68k
         GzKHroEDWrhOJy0wNlyu6nvcr9ApuQPvDySMmZp/OoUmgfjfUqEyDsz/L8Kp+eG5mFKT
         UAQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=t79Kc9yP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0zvnf5IIJGYWKHYB/ONo+l+CGw+gQ7ZpWsTIeXRpqxk=;
        b=nAbgJg83P13YmDW94he/s2kUsuJCN6aH0ljCTPOp4z1rijgqhOZrv7zaHt/Rthf71t
         WjrQEM6T3IknLSI0PnanarJgg2pVfrcFoGKgEbKh+6Gn210q5lU1atsOfKKmDfGAGrWw
         ybH7FzUWJGMtI6BbegrUMA2yKdiE9+tAwVTHw19CopE7STlaPKSDYWzExc9ZQL8VSWas
         BnYWgBVnntnOaX9fXD6wsKV/wUxZxgYiKoCmbOYs5D+yFzc8WHWntSgtvPHgF4zG1v+p
         69VZ07jNUkGkemj/tWhiRyrMACJe29StNN60COnGEupjXH646J9+ieg7Yl4o9zKrv6o0
         dxcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0zvnf5IIJGYWKHYB/ONo+l+CGw+gQ7ZpWsTIeXRpqxk=;
        b=MdV4O/IL1knwu4jL35MMQ4H5+faUVCxawieMD8+/plJgy37nmq7A85+UXHbNe/q4/n
         E953d6S57Y5hNXOVLzdkGDYdWRVh9SNjZ0acT9gzemU6YB/FTpoknm4ydaNC6nT59cAd
         vFftSOdZq8bdlPyj7G7wtyE+zbVF/jZ10NIXCA30hI8wY74TMTxcWB1V9zy2PBF8/puJ
         XQiz+gU4yqiZzLmpZpfIzili4mwqzHDBkyxlinTXP3hFiLpj0LV5etCU4X2em74AzFky
         MOZESaLWzWtjI+FrWgEJAklSIUHHCF1W0MUcORA9LOIBrEImB7zLAFJwZHdlv9oYswtX
         /Uqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533v6iBuu582tDLLdFI5vEeebP2+qxHQ2KWNEa3QGhUFQ6NmEg/I
	7z+pys+XBbwJO66IjMOMeLI=
X-Google-Smtp-Source: ABdhPJxRjCx2Eb/kC7n9Ni+aXbX2IWckR5xZbvztIcmBGKAcjqlQnGMYRbGgeum2vJOoaRab7rDxvQ==
X-Received: by 2002:a54:4006:: with SMTP id x6mr9004466oie.148.1592235055899;
        Mon, 15 Jun 2020 08:30:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ed48:: with SMTP id l69ls782750oih.7.gmail; Mon, 15 Jun
 2020 08:30:55 -0700 (PDT)
X-Received: by 2002:aca:6004:: with SMTP id u4mr9515430oib.106.1592235055064;
        Mon, 15 Jun 2020 08:30:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592235055; cv=none;
        d=google.com; s=arc-20160816;
        b=e1Y6m2U6FTrQkUeCj4FlDve+VasAQtdyRXBOgnTTBUx98s5h4MxgaEVtE41Kd9Jtla
         WKl5srYZJy4VUzOLVwsIMiM+VeG9j0qm7Ag5ls3ao3ug4hJtqiZVezGFlrJXgRVY3pgo
         KjFmNYDG9dQBh93pmJ/GdPMUFa0581dnQyNfBo3Xk5Tu/HZyvs4Kgr6pR1STlN2luyO3
         n+NJadnkqr/+LGiLYTunu+et8SryYfsTaKlkNV33s1UrhJgCamvMMfMlT59Gv/FOEzDW
         M5Oe/BKETGwhcuaP0PxJpJ1sLJoUMNQVJ7+8ygryJuFV/dpXBLyB2kduaL6u9lTaoHpF
         QufQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=G5VsRueJ4myNT2iAEaTfoIaElgSbzxAH3MtfLJh9wMQ=;
        b=UNWs0BKxt1/t9B7kEhy26B2j0Sfl3JKV+Qijz0P3dKZjcKGVHtedc54+Na8o+ZXYlU
         vkMtTpbTMrTmQjZKSWTnW2G/84ak9eKHtBN6w8lCEuy0nzBPdebw70NtYhmWJbWIgjxw
         vLl35kR6RjPckkJrVJFgzxQXPlwM23bWt0wJireOutgBwwCGVkeGRRcopUboa7l9zzi/
         KE64+IUsGsFxkMk4PR3C8fFTk8ySYkibWcamskVD1C84ldI5d5N4lj/PLt0C3LUkXhva
         x8YzDFHHkFTX6MzvjMNqsDBR0YIt1EOHgaJtQ6Sp86rvAfFA9VCHtOPijhv9NqQXs8NH
         Z1lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=t79Kc9yP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id m26si69188otn.5.2020.06.15.08.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:30:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkr4Y-0003tB-4g; Mon, 15 Jun 2020 15:30:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8C6FF30081A;
	Mon, 15 Jun 2020 17:30:52 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 73096203C3762; Mon, 15 Jun 2020 17:30:52 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:30:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615153052.GY2531@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603164600.GQ29598@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=t79Kc9yP;
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

On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:

> >  	// RCU is now watching.  Better not be in an extended quiescent state!
> >  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> >  		     !(seq & RCU_DYNTICK_CTRL_CTR));
> >  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> > -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> 
> This one is gone in -rcu.

I'm still seeing that in mainline, was that removal scheduled for next
round?

> >  		smp_mb__after_atomic(); /* _exit after clearing mask. */
> >  	}
> >  }

What shall we do with this patch?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615153052.GY2531%40hirez.programming.kicks-ass.net.
