Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJVDY7YQKGQEQ5X2EJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EAFFE14D09A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 19:40:39 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id 63sf123277pfw.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 10:40:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580323238; cv=pass;
        d=google.com; s=arc-20160816;
        b=sPPXb2WPWjsGJeOVImHjL+blGeHhWhgICdfmvzJMONSRkqOQHAjFu5tQi5wbtW7dHJ
         l7OtFJWHpPP0xG8yrsCd2Wvfrjdi+zhdDliQX9g0mib50VkXbGRvsVydEqidMoT0St6J
         mjMMPRzeUQUsLDGNAZAb47fblSgmhaE2OSxS5t7rP5IM7FLoo/UeYWMweWQ7xR14ISkD
         uBjaZOM6hIGrwu1OVTuqhC6dXSWFPFwWDjwRAAHg9TVL+nh4qjdtk7oDrMknZZBDXqEG
         XQiw3Z+NaBR6qhtU8UK/bKIzHU+5MnKVkaUGfHwldSNRECG01H5MLlyx704YH+kDWm49
         sNzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=0tbf7x+f3NieaUhxRILlNm0zgthHJXEXsPA5zErbmq4=;
        b=GquqvS2c3tnso+X+CS1G5yX96Xo5YITlawc04B/avGWcr5M84b2KH2M1Tjn7D5Ap2z
         v1sb70WFiRoRmpQeMi8M5KDjKTuspL0lZYGWCE5zLnnlDxNKDdKXossP5Ye1a3P7PrOD
         CoPyBbbNrpr3uVvlGXjdfYYqSUQKAylbnSyy647cJ7TXp3YDdEbi5lHjVvTKMY2kVgmV
         0gF6CMknmwMAyQ2I8BiF3DLAkDXwonrj5LDKcgUNRQUbCIB10xHrjjREyu6dR/IO+pVe
         xfoZJiJU0D7g2GSEk/ZpMUubqAeMNHmrW2i2nTO5QU1Zgmb3fNaJYI3hWGdyRFPTGXKX
         APtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=PuB4FG0m;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0tbf7x+f3NieaUhxRILlNm0zgthHJXEXsPA5zErbmq4=;
        b=P+ZT+EfXZi0k0tb+PdZnyQxMW2fLQXWcC5qEFcqzcWcyLPiafOc8AVnU+cohIkdyJh
         OxUtAaVkZb8r4S2I9hs8XKlMiB3EpybofxdCddHKWlcu1V7xlT52ZTp1ZqDrzxFmAmzA
         P12Ow9EhkbIecd4yOjnJxHnJ/uKLCRallaWB/ZDowIcoHUs5DWr5wYsSp0XzD1k3cIgr
         uK4jUHBKjACGbDQ7QIY7I5No8N3FHUO6MNe0Ea1xhmiWRYGVxPV9u8xyf5KC1lVfB1IU
         ryg7JMgord24wRvTCvawmmPNTjfYBQ8OTZvSJx/A3IFIWp6VpkSzSWdYNvMYrMpR+qhB
         QMFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0tbf7x+f3NieaUhxRILlNm0zgthHJXEXsPA5zErbmq4=;
        b=O4KCK8WwTKYxywSQYskpQmP6pjkZFxy6PKFtCPebE3s5dyx4t6wCLDoDkKiM8lUDWm
         L2u+uIhI5gcKM1LpTypfqE+P+iXHS456EAut+PgSFlR2kl8UDNCuJQgoIHsYDmJTK1Xo
         nqRYvkNqkjoTz4pOPFLBd1tljLohi6xP2sVRYei0N2P8mUMnttcGZP6t2x913wFFx374
         BaY1DI4cwxPlbiJizkOCI5zfcaaxLzhD/H2Z/IVZP2Dcs+zTukWOmw8fu/TkEfq/WFdx
         cOSqEtx2qOHr81y3DmTDnMXspXGWhDwv7Mt0xLSuE0b0wR5ncilBvwz2h9Lmjmv0SBBP
         aMyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWlQBD+VJFsl8uICiU+qnxzX0PJGj5Br16nKiYzjiNWnaxfqU1j
	nbW+WKR40a7TEDanVlpywf4=
X-Google-Smtp-Source: APXvYqwjDKYx/oNZROZSR8kJx5bgoEq/Jasm4eyUnfuJBaPBG8XVdrMSnV3P/KKAHy3GVu8A+fsjlg==
X-Received: by 2002:aa7:848c:: with SMTP id u12mr931411pfn.12.1580323238234;
        Wed, 29 Jan 2020 10:40:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4608:: with SMTP id v8ls88365pgq.8.gmail; Wed, 29 Jan
 2020 10:40:37 -0800 (PST)
X-Received: by 2002:a63:d54f:: with SMTP id v15mr503395pgi.64.1580323237822;
        Wed, 29 Jan 2020 10:40:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580323237; cv=none;
        d=google.com; s=arc-20160816;
        b=ElZ798YTM3VDPm2c16InuEvo8v/+72Rb0rREc3ftdfoReC7+FHBsfeTp3CvWTZoim9
         dVj2lYOzvba9OouR9XuBOrJKZ44S0uck1FesfZR6yJPBq/4wVHn7WlLR957HZwkVm6dq
         gEK0RSSbOuAkC2rOqZkuMla7BdHYaNOxU41fD1X1S/QSkt4KRsUEXmt8amtoOte643NL
         hzBY73Za/FQevS/Dnz0DZbO8SN0vujrnwFxhyQiRkbCdlLEp256HjmrJ0PDOyxuZMUBl
         OvS9mOlZx8wpaQ5gZpPJIyHOyyyPc/upK0iSXEfv6Sodj6dJ9DknZZxNI2zx7knWpysY
         Esqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GQmHDll3iwjJrh7vaYQic2Eyspa/xass3sVAm/tVDXo=;
        b=dorPMqag0JIN/ACDQXfOm0kb9Y3DSBpWZ5y4VZVTlWdctXAyACWQ7URFej6vJm3S9u
         IeEbWeAo8dJzQv3Kuzhppj4h9pNjIFTJz3wULx7w+WYzHqit7fiQ7Se6Tdfcf5fFm/aQ
         1CSli4gChSq7xpgYHu4RVSAMAmFHsA9uVlcqmphpRfv3kuhosi7n8xgr2qQKuIIcvQdj
         G38n/l+DueVS+oMCrWVeNFa6Bt9eRJbzj1bbgPheSUv65ov7mUoBtykrVdwTiZ4UKxNa
         qPkMMuo7r6M11xQfVIDIPEdmKa3Ax9FWQ47R3umlBmrdNvvU4+DAHUKPnbankf0y2bMj
         IqPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=PuB4FG0m;
       spf=temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id y13si141319plp.0.2020.01.29.10.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Jan 2020 10:40:35 -0800 (PST)
Received-SPF: temperror (google.com: error in processing during lookup of peterz@infradead.org: DNS error) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iwsGJ-00064A-0j; Wed, 29 Jan 2020 18:40:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3626F300DD5;
	Wed, 29 Jan 2020 19:38:41 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 245202B7334F2; Wed, 29 Jan 2020 19:40:24 +0100 (CET)
Date: Wed, 29 Jan 2020 19:40:24 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Qian Cai <cai@lca.pw>,
	Will Deacon <will@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200129184024.GT14879@hirez.programming.kicks-ass.net>
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
 <20200129002253.GT2935@paulmck-ThinkPad-P72>
 <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=PuB4FG0m;
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

On Wed, Jan 29, 2020 at 04:29:43PM +0100, Marco Elver wrote:

> On Tue, 28 Jan 2020 at 17:52, Peter Zijlstra <peterz@infradead.org> wrote:
> > I'm claiming that in the first case, the only thing that's ever done
> > with a racy load is comparing against 0, there is no possible bad
> > outcome ever. While obviously if you let the load escape, or do anything
> > other than compare against 0, there is.
> 
> It might sound like a simple rule, but implementing this is anything
> but simple: This would require changing the compiler,

Right.

> which we said we'd like to avoid as it introduces new problems.

Ah, I missed that brief.

> This particular rule relies on semantic analysis that is beyond what
> the TSAN instrumentation currently supports. Right now we support GCC
> and Clang; changing the compiler probably means we'd end up with only
> one (probably Clang), and many more years before the change has
> propagated to the majority of used compiler versions. It'd be good if
> we can do this purely as a change in the kernel's codebase.

*sigh*, I didn't know there was such a resistance to change the tooling.
That seems very unfortunate :-/

> Keeping the bigger picture in mind, how frequent is this case, and
> what are we really trying to accomplish?

It's trying to avoid the RmW pulling the line in exclusive/modified
state in a loop. The basic C-CAS pattern if you will.

> Is it only to avoid a READ_ONCE? Why is the READ_ONCE bad here? If
> there is a racing access, why not be explicit about it?

It's probably not terrible to put a READ_ONCE() there; we just need to
make sure the compiler doesn't do something stupid (it is known to do
stupid when 'volatile' is present).

But the fact remains that it is entirely superfluous, there is no
possible way the compiler can wreck this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129184024.GT14879%40hirez.programming.kicks-ass.net.
