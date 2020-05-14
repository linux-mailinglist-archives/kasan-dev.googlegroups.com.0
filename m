Return-Path: <kasan-dev+bncBCV5TUXXRUIBB2EX6X2QKGQE3BUPXWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D7EA71D31BB
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 15:47:24 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id q4sf3466679qve.19
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 06:47:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589464042; cv=pass;
        d=google.com; s=arc-20160816;
        b=bY3rovkv9eAGTQhCl+DFKbbF/cTnoZ+EUcZf3axi4yJPf8AJU9I3aYYiLXaK997NQn
         u6ku/jeOWOT8nHHaXJQmnirIIjKyb/4JXQfDjE5hbeQBDFhRimH0VBogmuSclQWRZqar
         lNXDkfWLiu9ZN9Np7fzBuFI0tidU6ohbcL0dtUCBQeTrseyLisPXTBdi4lDgJxpGK/Ey
         PyM667O+ajMXGmU2EgO8lKG7cGtLVpEIWKJ9qjhIZFRpCZBSm1i5OEkrM+pQwjR1ivvs
         NKmwyNurJyYPebnN/Zdwhim6yBbP0GW7UUDg+Bq0pcLqdF3uNjSYV56NYtMFfAch63YV
         hRqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qCIsFmgpU7AodYnUiZWedC7pwBsSE2XyZjFOJbYJhj4=;
        b=e7vU64a67kFBzIb0VEu9AcZEKju5qzKb4ZtcHSId8RyInwQhtTvzLYYNsFjusdkbbP
         nP/7X8TKL9hlt6RxOapxJFRAqwHmQvnfVFsoQx0lD2C44ObAoWmOeI81uHMJD2E9ANPN
         fHvgaVDA839MNJR9UXjBNNL8BstNe1IRCsGam1zHOOs/PXd8a09rpgFxrCFrOBxjmpfy
         GQEAa0LEDwE6xNW4Iw48EHtg7KadIzcdIKzgpIGFb9YPh6fad1pzKNxgScYC7xxn6Oye
         iozViOcAto9+EWYPL53mSZ0gYObhFhhZLxOmqry0ziaAlMFnHsKTHmfXWpJj6mT6VJne
         Tdog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=wLziFQot;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qCIsFmgpU7AodYnUiZWedC7pwBsSE2XyZjFOJbYJhj4=;
        b=ofE/o5Lk4Dt888rhBHzamfUll7qMAkCGAoy+x30FgAptV5plnUsUsz+pIeCLyhF/6s
         nTERCT12Em+VMxgBKq+xOENDtxgQILEh/rhYuZMnRtfXOamYuzhfZ5GgpSgrh2JmTA0v
         21/bxOgqOna709qrMYhUoYYcJjE9GbspdLa4YMj7cQN0R0eG/Hz/VxzYcPdFqPxGbfjk
         F0Bjo4sy5d0jjOynyRM4dBvwbsyhCiQ0hbvLq0DSu1Ly6shqQFxJqU/if31kOuRE1kJX
         WDE0Ufu1T2ynohLt1LydrsDDpO3SQ1rKHgyIA3DMFUNbwylOlwReiQf83wOKTQFybdvZ
         jQgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qCIsFmgpU7AodYnUiZWedC7pwBsSE2XyZjFOJbYJhj4=;
        b=K9/Mlb8EC4P5w2tfrtygZgOGbmjWXjp8ino4td9TAYXlRlBherla21Myn85RMoU8jF
         rjNifkFdU+DvymXTebKOLhau7x1tNSphUAM2fQun7QsJTzPVJiXyePoLxhB9tRihEJep
         pYxi7DuU6QAOm53lsfwz1KiDDSjnQeszUS4d9cd1odnBe/wUw2hoymokxuPfo3XfS6Kg
         cJeDiIHJ6NGJG1A3nPtc1/sfUwnHfa6KfldQve/Nmn1bhjbjS0Y+hOar/YWgixBiK1y6
         T51o1Xkd+N+5exf5rkvsI7hLnYZfC9W/LWRCGfI8Ga9Lz8RoTNx6RLHsgMjmTHTI3o86
         HTAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530axocmacVONO5+X6LNpi9eoAYtEhbHaJKOBYxRPWG5xdm/CgWJ
	0jW6/uH4jRMdEIcHiSgQ+6c=
X-Google-Smtp-Source: ABdhPJwp7qD6jXAdnAtjHdeIuVwagReqUwo4PaoS0gUn//w7k1INUUCYeo2PyyKo8qdOzPIlG328mQ==
X-Received: by 2002:a37:78c1:: with SMTP id t184mr4868811qkc.213.1589464040545;
        Thu, 14 May 2020 06:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6c2c:: with SMTP id k12ls1563870qtu.2.gmail; Thu, 14 May
 2020 06:47:20 -0700 (PDT)
X-Received: by 2002:ac8:4e1c:: with SMTP id c28mr4629167qtw.378.1589464040163;
        Thu, 14 May 2020 06:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589464040; cv=none;
        d=google.com; s=arc-20160816;
        b=RHAq/lzPZKcWeze06CAQdUAwOUQSVrcw4kgMaMOR+Ar4VKfYLYpkvh4grgqdzTThS+
         F+qdhn6ms5QCURO7zoOd6VPupoRpAKxf7baTW7XD0n30Hmmaq4ITp1fMkUSNe3tffCRe
         9C6o63JaSC9Xf3ga5+p+p30fzzmHW3yLs2hTW8Po68hgyOD5NbQfECzddjZtZG46LxIr
         H9XM61PMKWd/XdqmgfRZ6Z8zaB8E3ajHAFSqaB+rUsB4KItUL9iu8mqy7cLdj6kNtXwb
         5p12nYHPvKHXIUDI9Sej31ss+upnS1+vnt1HZ2YD310rk1j9fAUIV8f84ZxPakNsIyOC
         pHSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+y+OkMlzMktu9KK047UqVkffx7tV9CVsxhVOVttko3E=;
        b=j9h9vKeB6w87tEsYutobBB4LDA1q2sUcgsWiBXTPXCqHTOxHIicFy66QwuskYjuhcZ
         yaB2ah6Iwp7jVyOKeNmQ16p5yU7ONUBxKXjl1R3B/6qVSraka8C2uh/cXndi0Qx29pjW
         8LN1d3lMrYr476siIPjl/ThqeuwFLwaoQQY40yMSG67z9GdaUxuSDRk9/Y68qhbKrTiY
         rkp0dwW62elJu8QrTGy4CUCPMx9siQh6WtJ1c3ENQRr+NVcHAgS32+1u/vUWsn2xqtu6
         zeoHzrYiA6La70k8qIrp1xX8oy+70uKK8w0Y2b6kkDHOsHVJQy7PNRx15RuYGbs1EMKn
         UyfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=wLziFQot;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id w66si230466qka.6.2020.05.14.06.47.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 May 2020 06:47:14 -0700 (PDT)
Received-SPF: temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jZECb-00007I-LW; Thu, 14 May 2020 13:47:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 353F4301DFD;
	Thu, 14 May 2020 15:47:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1CD942B852D66; Thu, 14 May 2020 15:47:07 +0200 (CEST)
Date: Thu, 14 May 2020 15:47:07 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200514134707.GY2978@hirez.programming.kicks-ass.net>
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=wLziFQot;
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

On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
>   2. __always_inline functions inlined into __no_sanitize function is
> not instrumented. [Has always been satisfied by GCC and Clang.]

GCC <= 7 fails to compile in this case.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514134707.GY2978%40hirez.programming.kicks-ass.net.
