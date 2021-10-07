Return-Path: <kasan-dev+bncBCJZRXGY5YJBBHGB7SFAMGQEVWURMUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id EDB8B4257F8
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 18:30:21 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id u2-20020a17090add4200b001a04c270354sf1036317pjv.6
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 09:30:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633624220; cv=pass;
        d=google.com; s=arc-20160816;
        b=OhETQrYy0hsZI4eypX3ti64dv8v1ozxYk0SWFFYu32stXKB3hxL5ikPR2ZguIB73mS
         ogiWG/SWkQq02M+pAuUNoWkuV7rSC0GTcTZD4+pGH+xL/PDjmh3inFcd60aK/Uctd6GL
         kmWTfx+vFunA22FWs+QXR4iADRC8zB91Z+CnPrNwBzhN2bC9iurWqgyBHsYoNcXOd3w7
         Wzir/s+6yr8g0LgaNnVMnfsnfM+t7B+T1ixCV1Gdux9qOVnRMy8S53tfRikWgfl5Rmj/
         qn6Db1GYZgK7TPgoi+HIac23W0AwabzToNbj8lwIBB+0z6k0UT6IbbXWFskg/h5i/MjQ
         QgAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=nv5VWe9gfwCicyy45qhb3h83rUOqpNedu1G3QxSDOCY=;
        b=yyjLvdY+2qklcNO7eB7cp0ein7HDpsISISnVj4TS8UQmdQzPXtn2jloayufnZAlqBS
         /nDZcSJqrYGbtQZ4PETR8j8hl+5sE9atjsrlaxn8uqgd52SpXQX8zQAGqQJO5xdJN1H4
         kJD85jbrGRMAGlDmJEo4flgh8BZjkfjW/qu2FmMveHJvISVTuik4xiPffyeGvo5UJmJo
         zihnaFT2gOXEyMbNaJX0et7gc+wDja2o1FoLMl3x8s/JUONjNG6llfC4CsqIhA0MspVt
         Q3SV/0lNKxwPjLIZ7CWAiqjdQ89ENqutXH8mv4UBr3mVzW8HzcZqFnihgxB3LRQxFhO+
         iGrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VhAvPSdN;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nv5VWe9gfwCicyy45qhb3h83rUOqpNedu1G3QxSDOCY=;
        b=s/9iWtvLvffPiNhEQy4SoP0Rtkrzq2G4ARCZfMBxbwfB9eYMi34A3y17l0Kjpgz/i+
         ZxLBWv6HumJz5do+nDQvcnP00euO5nBcFp12y4OFnNl1B8NW9lxAZjxPEYr+RpcrAzE2
         dpNS/5duHQnx5yL60EO5SE3t2DRXVDkSUTIIh2IS+RIVx13lYVcy7IIN4nkkAa0roY/R
         ixfygD3L/k/O3mHMO2E9JVzy/ejsgh6rhZ+JX20QHk3J5vU8foGjcxz+kqDz1RinpwKL
         6A3sjo0p7KSSKHmXbRDI/MXtfvhOwMC9Bmqa/N6BVgXbfGx6rXllQ8PMBn+oacx1N4aa
         xZnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nv5VWe9gfwCicyy45qhb3h83rUOqpNedu1G3QxSDOCY=;
        b=dqDEnfTKWyHbnjLJAlnkDZdjI3Q/QX0fmapPgm6msW/l/iSdKX7T2LEGiM7YFQercE
         oCJxJQVBARiwzphf5x4AfAaDAIQdS7NrlVdoor+H3eJQCbNP75gpp2VSRTKL1DqaY6SN
         RL9FBZS1LcFaIcOWRUmSxw2hLAw2szCghXhtL4Y6A0NKvvOaybpDLHE4DEANfMnmwLQp
         CsoAQ1groAW8EGEYk3lWR/DsyorFxUuVvJihIQaq0d1Ek/tkQaQdHNy/AhEfZ8+m0PwN
         HtEjkNEaS6aLfg9N1LlEGt5c80brqIpOQ+RrlzBAEUyLINd+IZTYiwOETpvwshU2DKAn
         TJ4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cho+pYWC9ejORiM1fpLatEk/K6PIDBsexZt90K1IJlt+vCxaE
	A2EtvZHA64DLSPa5eXJ2Qi0=
X-Google-Smtp-Source: ABdhPJytQU4OSrN3do5H/GmGBSoUvdSelwNF7TcOPZGjS8rqZP07BGGYoT8mAtokGX74BT7Og2r7tg==
X-Received: by 2002:a17:90b:1e4b:: with SMTP id pi11mr6018543pjb.179.1633624220407;
        Thu, 07 Oct 2021 09:30:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d206:: with SMTP id o6ls5105957pju.2.canary-gmail;
 Thu, 07 Oct 2021 09:30:19 -0700 (PDT)
X-Received: by 2002:a17:90a:4fc5:: with SMTP id q63mr2119936pjh.148.1633624219803;
        Thu, 07 Oct 2021 09:30:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633624219; cv=none;
        d=google.com; s=arc-20160816;
        b=mOVbdflZxPhDHp1g7nNcFzI+GByTzBquWcqYKf9hYw3t0F/UlWQITaPeiebPBoVgx7
         NfK1tZbK8VbMRKuMhyzhHwQGgpjpDTfHybkuocQz+6BrofNKmgkZ+Q0jR2mxfV7P+LCo
         rLflHRLlcYF1mNFsHRv6IIOFKkSmRyJcxhkeWILYbPUdTPY45ADGFicBvd5r3SULn1rk
         rVo1xsGtzlU1AhzmP6zIBQ53noPnvubq2hetF3dDYIQWAWOFUrx7QnzyuLGOtS2lW3b1
         41/4DAG2DwWJbLLo/qHPSJ9Y8gNO/zZMDnfrYst3427cS2aAUNWANeRNS1Nr5JXgB0N7
         tpeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HlzQGOQ+T/cMNUQSex04E0f1oD857GAUtTeDMeRhCqA=;
        b=wq1SOCNv4WweHJCIamFT39TsUl32wVqsovb4/Gaae1yXcjErgwHDP0s3NjEKOOTlXU
         W7PuOVVh65J0DwDt7l0VcZBZVUhVlZYOEN2Xhbc/pD7EPp6IPFT1BpXAJQk16gcw7vZ0
         USNagZRD9fSz442t7apeigwvRaN8bYdoqo04oUFYcTcHvFlcv055e0v7idJPSHDUi3ww
         wgVGSNFMksRrWjV5dZKUe4nO0Dv5unQzXieddgoFSBB2sT7TIuCz0D2fmXW22Rr27W5u
         eN8cehHAkXe/n7iSnT0W5JVAP8J1H/eWcNnHaje5bT5q09u04ySlK60rBBAQRYdynlv/
         TKdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VhAvPSdN;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w16si9842pll.0.2021.10.07.09.30.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 09:30:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 869E961245;
	Thu,  7 Oct 2021 16:30:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 4E5C35C0802; Thu,  7 Oct 2021 09:30:19 -0700 (PDT)
Date: Thu, 7 Oct 2021 09:30:19 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Boqun Feng <boqun.feng@gmail.com>, rust-for-linux@vger.kernel.org
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211007163019.GI880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VhAvPSdN;       spf=pass
 (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Oct 07, 2021 at 03:01:07PM +0200, Marco Elver wrote:
> Hi Paul,
> 
> Thanks for writing up https://paulmck.livejournal.com/64970.html --
> these were also my thoughts. Similarly for KASAN.
> 
> Sanitizer integration will also, over time, provide quantitative data
> on the rate of bugs in C code, unsafe-Rust, and of course safe-Rust
> code as well as any number of interactions between them once the
> fuzzers are let loose on Rust code.
> 
> Re integrating KCSAN with Rust, this should be doable since rustc does
> support ThreadSanitizer instrumentation:
> https://rustc-dev-guide.rust-lang.org/sanitizers.html
> 
> Just need to pass all the rest of the -mllvm options to rustc as well,
> and ensure it's not attempting to link against compiler-rt. I haven't
> tried, so wouldn't know how it currently behaves.
> 
> Also of importance will be the __tsan_atomic*() instrumentation, which
> KCSAN already provides: my guess is that whatever subset of the LKMM
> Rust initially provides (looking at the current version it certainly
> is the case), the backend will lower them to LLVM atomic intrinsics
> [1], which ThreadSanitizer instrumentation turns into __tsan_atomic*()
> calls.
> [1] https://llvm.org/docs/Atomics.html

May I add this information to the article with attribution?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007163019.GI880162%40paulmck-ThinkPad-P17-Gen-1.
