Return-Path: <kasan-dev+bncBCV5TUXXRUIBBV5JVHXQKGQE6RXEK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D53511150E6
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 14:17:12 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id l13sf803156vsp.22
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 05:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575638231; cv=pass;
        d=google.com; s=arc-20160816;
        b=xyTEdKMJ+3CmDjQv8ybFh+CIpOULNZsrvASMFI1R+Br9UfPWlDsjz2pks5OxUqFQDx
         +8qZLr+a0Zr9qTqSY3BPYt6xDrTAhnQWLGM7Y+wdVD0DWXKmAbJdNBYqsv518XxJWmxb
         ZbJ20mZbpjK1u3fYub1JPC0V8t42xWcuW+Ov5DJFHppX93kDFWcDVSSH2X2FVGeqMMnG
         qUOJgU/zYvEiklRGsTtuRC25CJghLlMQF95GPOekYVoZUunTPVBLUxEyJROjacLTT4xj
         oHOmYEsI2OgqHSMJO8OLJrCyRrK8H4BR+vGUMY5De25lD4dqpGswQCAa8Y8BDjjbNJIv
         4KGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lrf3ogtjdXUH2fDbR0/+yfY3GlfArQPh0cJ4/YByUBo=;
        b=GfcqHBmUmCQqzS2jI+EKwXSDNM6PGjFuWVHTYXxskQrETgrkX1rUrIewXRVjJBcGPw
         3lxdB/YumYwW+M2LIMIF5gVIyWuEPJd+Z4VSU4vRZjyd+0ADp/5IwPqxpiprjpzCm5ok
         BWd3cJQY0Y2CVYNQMeQw+HO+vUlAkH+bBXuDvZ3w+JtykjXVVWZhEClbW2sXg8XbY5MX
         GVNtuWC18XsRp4S7hMaMedkiKBy6/ggSzcf80ZhaVqL3eeOo6rxm98KrDiJinqgQkdWk
         jw0uzNrH+bDtALrkb0sAjFP7SWbgYPygBMXoKiBfuIzezsGS3it1PmXQYNJSIsvoHkSi
         /MIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Orv0ZhCR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lrf3ogtjdXUH2fDbR0/+yfY3GlfArQPh0cJ4/YByUBo=;
        b=nusRyWRFJ//Ozeim19w9yzwAFLMj8hIoBrDpGV7RPHd76LVBH6vBNOB+yjQA9v/458
         c7w6igzeN3d7gtydMWix9kmCGx6I9jd+tWxHXblfPv8vzwn0U65mSdMoTtuJA+aw1v6W
         L4SuzS9t4AYLfNaVyYSP3H9lPAfRHYmaknTQ8E837Rmgzhby4518VdqgzZhGdkY0pomP
         z7IXrV034WIaf2YxRyImwDmwES7PvvwbUmKDqVrMKyYXnUFor43ZCLTife2pQKAFxzgD
         FOSfo107EMO2o4PEckqrWd8HAs1Bg+ok5XVYW9XxllHwLWX14r0UxAVvFMzhPoZfRqxU
         C9iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lrf3ogtjdXUH2fDbR0/+yfY3GlfArQPh0cJ4/YByUBo=;
        b=e/U+ant8eY4oD3yV0Hotd2S2giUF4NtN9vad09OQCB2p1X6Q9+KYlsPrxyVjVOiRrk
         FbaV1pecB+CCkqXs5QcebxOMp25MrVOs59iNnhGLYO/HLsRnWi0Xn01VP/JO5goR+BfA
         6RY9Fm+N0kPVGRq9sf9NNEP4eXNws5xXdw/DPP/eIiVing36vGaHXmW224q36OR+abyL
         +Nstv6gOa8KCUpIY0KuLLn2WPF2lgqEyVIZu9lb5uI1GScQ2UB7qzDtDcGtqem/51dPV
         KwX08ezOE4bVykZVqJ89hEG/hGiFGQfE6+NH2Ph+BKoosz3Jqb8Gnz7waBZQC6ZbBPrt
         bSKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU2Gp+TkHchYwGQwAfAKf9Z8x93t3KpdajmvU5I3px99AzVJRIy
	1M6+zuADIAlHYA4iWq1IeOQ=
X-Google-Smtp-Source: APXvYqzaEWFUXpqwrENRrYDoP24Ydnr0k0I01ABOpdn/JEwvADbTpbvyy5qJLYFMFM8Ugo7FDRPHyw==
X-Received: by 2002:ab0:a9:: with SMTP id 38mr11931312uaj.12.1575638231458;
        Fri, 06 Dec 2019 05:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c5d7:: with SMTP id g23ls394791vkl.9.gmail; Fri, 06 Dec
 2019 05:17:11 -0800 (PST)
X-Received: by 2002:ac5:c844:: with SMTP id g4mr11948674vkm.25.1575638231023;
        Fri, 06 Dec 2019 05:17:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575638231; cv=none;
        d=google.com; s=arc-20160816;
        b=bzQ1c8zkqGtJ1A0acOFOz3sAoes5dHUCAnpKjCyFsyM/PRoYn8C+9lOd5nPzrDiUp9
         GBRCXfNQ1PjHWjPWTWX3lKPej6FSnsW5GHbTwK6no6gVbOV2npYOEv5Dl9dGidr+lUHS
         1q0m47eanigVVFbMp+VdLWVuSyTIrJtj9cvtD0Bk2eVgtoHC2G25Uy7E/+hh+Bb/b4qK
         1CstSaLArd8yKdmkWoph34IEYRa2zJb+x41M/pHDcfhtQdOuPRdZM/7p6LgBSjqhvBuP
         RqmufIpgPIGW18eDU0w8FytUvTeLQQ/ZHQex+/6RYBY+j9NpCql6zV4Obzoy8WKb0++h
         po5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=c/BS0k8X+8NG/g3S4NAeJDxb7dNaLWprIW3ucB/d7FI=;
        b=WpT5oUv3aRzkxRkJSpqACxlxJ888UAWirCeq/NNVlNmfuwHD24SfKjxOjvzln4JMNC
         pIU8h83APwwKx9jdSQIC/NL2u9XT9c+FZ4UNJEv59hjNNIhonNq06qOEWoR4ck3ieuYC
         lyuAey6d451EdGQ4pUA9jkLIEatflQJiy1YLqEj65A6Zxm3qpvJAqVgFyBN28C8tJJQ8
         W7x1TIMmlqouPR9lmBCF+Y3QOrwk5EdBxZt40cq2Q46wrjfEju1VdPzbqhjb6+Vkpf1o
         3CXmtRA96kzQ8Gjnk63cnMLo6N5TFuJmveZKf7VLND0UGyEhcl+Dtj4iPRCUd7d1lssx
         RzmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Orv0ZhCR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id n13si477771vsm.0.2019.12.06.05.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2019 05:17:10 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1idDTY-0007Xj-Ha; Fri, 06 Dec 2019 13:16:52 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0CC7930025A;
	Fri,  6 Dec 2019 14:15:33 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A750E2B275E62; Fri,  6 Dec 2019 14:16:50 +0100 (CET)
Date: Fri, 6 Dec 2019 14:16:50 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, dja@axtens.net,
	elver@google.com, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org, linux-arch@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag
 (topic/kasan-bitops)
Message-ID: <20191206131650.GM2827@hirez.programming.kicks-ass.net>
References: <87blslei5o.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87blslei5o.fsf@mpe.ellerman.id.au>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=Orv0ZhCR;
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

On Fri, Dec 06, 2019 at 11:46:11PM +1100, Michael Ellerman wrote:
> -----BEGIN PGP SIGNED MESSAGE-----
> Hash: SHA256
> 
> Hi Linus,
> 
> Please pull another powerpc update for 5.5.
> 
> As you'll see from the diffstat this is mostly not powerpc code. In order to do
> KASAN instrumentation of bitops we needed to juggle some of the generic bitops
> headers.
> 
> Because those changes potentially affect several architectures I wasn't
> confident putting them directly into my tree, so I've had them sitting in a
> topic branch. That branch (topic/kasan-bitops) has been in linux-next for a
> month, and I've not had any feedback that it's caused any problems.
> 
> So I think this is good to merge, but it's a standalone pull so if anyone does
> object it's not a problem.

No objections, but here:

  https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git/commit/?h=topic/kasan-bitops&id=81d2c6f81996e01fbcd2b5aeefbb519e21c806e9

you write:

  "Currently bitops-instrumented.h assumes that the architecture provides
atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
This is true on x86 and s390, but is not always true: there is a
generic bitops/non-atomic.h header that provides generic non-atomic
operations, and also a generic bitops/lock.h for locking operations."

Is there any actual benefit for PPC to using their own atomic bitops
over bitops/lock.h ? I'm thinking that the generic code is fairly
optimal for most LL/SC architectures.

I've been meaning to audit the various architectures and move them over,
but alas, it's something I've not yet had time for...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191206131650.GM2827%40hirez.programming.kicks-ass.net.
