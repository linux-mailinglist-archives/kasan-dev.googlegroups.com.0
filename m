Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJE6TTYQKGQE772ENUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 051A9143FEC
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 15:48:06 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id s23sf1692581pgg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 06:48:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579618084; cv=pass;
        d=google.com; s=arc-20160816;
        b=RjQQCSxhnmcfrag8rdAqkk605S6F8segAIwUAZaS5tqLBfOQScUsFhWG3KFg4eAry0
         xSOahMQOZSpIGK+hF2PHJ7KlaWgZQzGGNrFoVWNnPqNor5fCKqZJVolU6RvM0RMB34VL
         X2tdg0w5CTarRrRB9OgFfOOki8dd+BmFsIjYiliQuMPwFTYPt/gP7BcnrGdnJ2JAOP5U
         IgLCjh+6Mfq7E+9vo2SEjiw4iRvK43lJRplHeRINozmjYfrd3oQBycYE+8PU6kj2Z34L
         IP+rMuur1BqN+V25tOENxKhjnhljaTU/eQoVDU2CGKClXcXdDoWxYiY5YOnbIg0wk79Q
         1KXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6ttdK2+h+QnQxrGyBYRbqH38zKJwyuPLaFJuGKUr8Zs=;
        b=XLcD/9n2G7h2LqNWB2yklqY0xlhT3Fyvo+c90cslmaSFhhsyFt1duKQwlDyolHrUok
         O+JwmmyNcgu8rw+OPC7ISMsB5sEDj91rJHAu9cehR3f6GO0vJrHfAS1bvpnBGHx/nSmI
         /pF+eSkWcqw1A53FOwgOpqIwg9Niisi75hTkhwY6uOLAmbDKXDXIfYyhCbmnrZq8u54J
         Ndm+rWClPSjCYClfOzFFi0cA4xezEtTyopg1Rn6qmmoXib99F0woTYl8V1BHmI4SPI3W
         iTQ7QBUPRqT9HTqb86A60c8ooBQrMpjsJWzRjP0BYMQxANlj4nfQpsC1zqnccVJJtJH8
         1bfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bwKVHF7s;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6ttdK2+h+QnQxrGyBYRbqH38zKJwyuPLaFJuGKUr8Zs=;
        b=eOCUWJVpRjvSKKKAOd5llkSWXdk9Mx1I5utDfnZFQSy0qxpQjoUI1PQFOe5jYqoNXY
         cQlggEOuMfj22hcmfjSjNKg4RJ3pNs49U6BzUvQfVLVBu0/fdGrwCMuHQlZs7mWqSfsd
         HXYwFKTaGs4LPZdm/p+HGpkWbggFJ4BT9vJ1YVA/++aCMtribizfetPiX4c4XJuOT3Qc
         C58E4wuNW0RRq2zYIdkcFWLElzWJ/WhspCKiYWVLnE94+OEiK6r1En8YYLLUBxH8ItJw
         mGre2QOD00DNMshlQwDl7genDTRoRUbAdCPsB3Sg0RDjdwFzAVsdc6uHO2I8cEdgydv6
         jXxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6ttdK2+h+QnQxrGyBYRbqH38zKJwyuPLaFJuGKUr8Zs=;
        b=MKdlP7L55WS/EgvZT3Jj6VpkfvnF0GflXmZSc19J7XsXhmzHSCWc8UXwn8k0MIEiWc
         eCHSEmhZCi8srsf5mAnj+Y03pjKlpDfVj/jH4kLChuu4RBPTswfUpmPtRmLYhk1M2JNn
         LEYklRtN9qhQw3I7bpvUAlHREzhSUnxB0Jh8vCGZrpg8IW/tlh1bB9l84l4k8jv22TQb
         sUl8DbMxQ+ynucozBrLzf6hVibLnijbu12H5uVu6oXuj44ZTL6felkXPKt+8KxzZAVYv
         mpBCNebuvRdjwtq2Sq0mcEhwiYcyBqkFpxhYp2CApEKYmkZlTWHBmjaeq1O57WdrAtFs
         SpAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWWuaepGuWnAQ2RG1zP7+7/3Gz4djRsd8dr9Xq2FiIRS0dq5J1s
	sz47+opQ8nFGYNFHVhufA+c=
X-Google-Smtp-Source: APXvYqwnh+wOrFx88iM+waTt9La4P6DfDLRY7fM9EwXrpT+d86CiSaHacd0tqmtV5uXRGfTkQvfuwQ==
X-Received: by 2002:a17:90a:8008:: with SMTP id b8mr5861336pjn.37.1579618084776;
        Tue, 21 Jan 2020 06:48:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:cc:: with SMTP id e12ls11673777pfj.6.gmail; Tue, 21
 Jan 2020 06:48:04 -0800 (PST)
X-Received: by 2002:a63:fc01:: with SMTP id j1mr6151958pgi.220.1579618084190;
        Tue, 21 Jan 2020 06:48:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579618084; cv=none;
        d=google.com; s=arc-20160816;
        b=eXPIYABAXMaClBPdHiJZdJKlaVspcMvTznwRCvXgOlqvt2dZfDhTF1HNoPwc3vmj67
         XrjFHTJ4r7dv8D7B+1SXuPtxuPCSeJMa9VUz9bFiuHhqqYpOpKGjmh3sk8ycAjbphiho
         HKcvCiMq2qXA+LStoJBPq+1GBoGPlTpmWd2Ei1RFTrtjMqn6mVIs7F4gTFPBmx91Iyd4
         6r/8NlWUMJo640AiHkpDKspcmZtb8cuUubzczdXNekvOxAoDz7GP8/0HkEIxtycowcDE
         wCHCk/BVslHRgpaGDCkk1yC8Pz1rdkgACReP0q/X004O54xddo8/u/BCELMlQ9k8kR4U
         bcSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uyryvzrOJVnY2Rp4qJ6rxjhfB8x1mJVRx6ecxsTZGfA=;
        b=u492DPaFRoAG7X+2cSoFffpi06SJVCTexlHQWb/oehcIZYG+mjgZCZC0yh2l2dCwAr
         1CCu4aXaU1cPcl7Y/5quY0qwmR/SCqKS98Ol3WJc5p7sd0yD3jrNP3pfT6UvXv942jTH
         ot7uUKuqMvWBXk/y3XuPncPscJjPajxvlB9k/VambfH5NAEEMScv/Szzn249R2M8vdOS
         Z2o4ww6GaXiKHALC6yRqJIQhpqDl9bHahWUDhephTWGvO3N8L6bVPigfNESXsWmMiZvC
         3MMA42M7cnOyek03ZP9UEVzHVGHfQ5b8V7fwphXXT1KtLEuw+9UZxj+mCOaZIwYwjNFh
         CZeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bwKVHF7s;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id y13si1132371plp.0.2020.01.21.06.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jan 2020 06:48:04 -0800 (PST)
Received-SPF: temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1ituoJ-0007N0-GP; Tue, 21 Jan 2020 14:47:19 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1CE8E30067C;
	Tue, 21 Jan 2020 15:45:37 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 35E7C20983E32; Tue, 21 Jan 2020 15:47:16 +0100 (CET)
Date: Tue, 21 Jan 2020 15:47:16 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200121144716.GQ14879@hirez.programming.kicks-ass.net>
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net>
 <20200120202359.GF2935@paulmck-ThinkPad-P72>
 <20200121091501.GF14914@hirez.programming.kicks-ass.net>
 <20200121142109.GQ2935@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200121142109.GQ2935@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=bwKVHF7s;
       spf=temperror (google.com: error in processing during lookup of
 peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jan 21, 2020 at 06:21:09AM -0800, Paul E. McKenney wrote:
> On Tue, Jan 21, 2020 at 10:15:01AM +0100, Peter Zijlstra wrote:
> > On Mon, Jan 20, 2020 at 12:23:59PM -0800, Paul E. McKenney wrote:
> > > We also don't have __atomic_read() and __atomic_set(), yet atomic_read()
> > > and atomic_set() are considered to be non-racy, right?
> > 
> > What is racy? :-) You can make data races with atomic_{read,set}() just
> > fine.
> 
> Like "fairness", lots of definitions of "racy".  ;-)
> 
> > Anyway, traditionally we call the read-modify-write stuff atomic, not
> > the trivial load-store stuff. The only reason we care about the
> > load-store stuff in the first place is because C compilers are shit.
> > 
> > atomic_read() / test_bit() are just a load, all we need is the C
> > compiler not to be an ass and split it. Yes, we've invented the term
> > single-copy atomicity for that, but that doesn't make it more or less of
> > a load.
> > 
> > And exactly because it is just a load, there is no __test_bit(), which
> > would be the exact same load.
> 
> Very good!  Shouldn't KCSAN then define test_bit() as non-racy just as
> for atomic_read()?

Sure it does; but my comment was aimed at the gripe that test_bit()
lives in the non-atomic bitops header. That is arguably entirely
correct.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121144716.GQ14879%40hirez.programming.kicks-ass.net.
