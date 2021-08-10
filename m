Return-Path: <kasan-dev+bncBCU73AEHRQBBBHFAZOEAMGQEJFHEL4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 191963E8373
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 21:14:38 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id m4-20020a170902db04b029012d5b1d78d5sf934470plx.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 12:14:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628622876; cv=pass;
        d=google.com; s=arc-20160816;
        b=tttWHRA7WBfLoYz/s2mlo1PxtOp3N1PPoebucOR932uwX9rpkDPFC1cB3Du7H9nqPI
         tMyurdM9CcRPR6jYae4fwt/HNwN7HNcF2phlREtnOrQEHRytiIkowoEt9drrd0Fm2BwR
         5vjH23OvtMr+TBYZSxBaTUv0lTbKezMKd2q/EF0rqE8ILA8waoYuSwlE6fioShE6zHfz
         Zrfl7/h+5kMGD614mxg698YoSFeqHIn6wWmIGGJF7EdIHIJJK7HOpsLSy6yZ3J7KHOk0
         CGtqVuimSZ+1+hO3Bkq2/IXa2R19RYdE//UbQbu+5I9qb7GuFQUbQdUxHSg7uneibi4w
         6hww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EsshshGJGDdoTEzyBKyIZiRqWRryJizBjTMpyKthoew=;
        b=R6qbaFYz/ZF20bz6s30c7IM3Yqbz6ObNb7UbF5VYDysEDixVphjerJsFF2uxqPbb+t
         tRrZ1+Tp24uz8fZOq5pLDfjU9KcuPpGZ0oPoeXkuFpYds/ROO9P7NVI9X96JCEjTi77U
         XU3VRC7AOb+2SG4chV32m7F/55AMz44r/t2s3y6vsCVgmxAK/FHdn5WjVQ2liGL0wC0K
         kmfURp9NPot7OwapT5qH8J8Jph6cXGxSv4NzjWH7aK7A6DItjen0sNnX3Z63n0BBDaBQ
         YSKZ1qkzckqeXblafmonLNIJIhKvAbPCcNSSTnUTeY06DUE1YMmEzyqQE2uFmSinAQof
         5dkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=5vfy=nb=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=5vFy=NB=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EsshshGJGDdoTEzyBKyIZiRqWRryJizBjTMpyKthoew=;
        b=TLr5uC+DDYeUX5WXpngc4RN5v8t6TIFGM/fJMrGf6s7e6JLDq2KV5tQsB3oPFb31AB
         6Wr6zZbJYGyldPhxJyzWZK03IQRpLlz/uNXRUOQP6NGFsKTXzqWfMYmq2MsYqqICca72
         HY4+RxFWoVYHKCFN9ILMX6EJCe1DfzCwUKvgL6/iUU0eGSziZVPSLgJ83yGsyselJ3wo
         MHMZ4aKyw78MmL5r3DwG6Hw030zYzakdWb3T9XWIwQMX3E/9iZhoTArd0aKS5tHagqeQ
         5uHd/l2tzJS5vi0vWtUXIhp8yFDYB49Dcl5wiAZFkC9rPjFtb780L2OfPmLyOfowzea1
         bp2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EsshshGJGDdoTEzyBKyIZiRqWRryJizBjTMpyKthoew=;
        b=VIGd1qkh2qBNtIxfv2bLiuq+e5xln41/014DKVX6pkWnzbqQ4FU8hU21IKY2020K/c
         kxOGOaAatJi3eHRfWnb+hyTqBdJavbv5SyGInthD0KfRB2dhHvy0mXuKQhg7GNk2lR+w
         fEzKsro57uwmsManvIr27d0Qh4MIcqWQD9/EUBvvq2ha7dv9a+E+V4sPsSeN52ZFoJmy
         Sz2k5a9lN75Vrmvw/JCs8DQdzJWowsbO7ziH6mTl/VtwocACrA2ys7JgRpFJYiimuths
         hPQ/OvAO1dK7iVYKSA0huVCtqsavrMBg+tWb/SYvFpsZmF/uX0ElfbLUE1hNNdD7vkb0
         tfCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nBJ6v38MNivJTBSwytFjiZPyWByd9iUN14TXt1Fu4M2UxfZVt
	eG+XzxqF15BzKlbb5cwoCCE=
X-Google-Smtp-Source: ABdhPJw/tzkRcphe+syQyQUlcqc08Ft3fJ2JVwZv4oAJCHd/yVkjHgRm46sR755nd/N9bOJRVvXJ8g==
X-Received: by 2002:a62:824a:0:b029:3be:dcd5:b012 with SMTP id w71-20020a62824a0000b02903bedcd5b012mr30186609pfd.61.1628622876704;
        Tue, 10 Aug 2021 12:14:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e23:: with SMTP id d35ls9017992pgl.5.gmail; Tue, 10 Aug
 2021 12:14:36 -0700 (PDT)
X-Received: by 2002:a63:c22:: with SMTP id b34mr782083pgl.422.1628622876118;
        Tue, 10 Aug 2021 12:14:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628622876; cv=none;
        d=google.com; s=arc-20160816;
        b=pW4/KKOOuLIEjRVjDp6TaZS3KkVkmDIHKhrsf5f22Swv0lFU1YA6HKi4EafKlifeEl
         t6Ru8/UfFM55WMOGmYKM6kO31v7HxRmRNMsZdECqN9w8mPyxW3/GV3z+WUNW6rE3VmtL
         CCJNh0mVoLgDhyMt8yXxaeBckczLvAwCi8f0XjAF5bQixuyKD/x9Y/RNBBYCV5k92Nwx
         d2w7Kw9dTytHI1cFn8kEjwMHoko5DmTyq+k3TQ/EiNf+r0R5DvW9GAHvko5Nch4Wxsgc
         6JrvUMMBoKippgrcxsv2FXqLVGW4XSTBIghZABqoKvgKhFHbfNbLLMlIQYNZubHGgDHp
         VT4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=TosBKhoA5EcxFdJC0qHTVwkj4KRuIaukeWiUmZs1Fr8=;
        b=GEBjDg83lHH6d2lumW731SIQwc7Um1SVi1kK2F3zWJUP+G5IqcZEUbH9BYL1oUxgpt
         mNEV/ftMvmxSawL0ci38iyra/xKXzLWYugltY5UI8F2Yke4vo7g3Qo/NStwan3c0H2VM
         gA0toBkffOhIR5L3KIqxaJXdEndGT4edKQcXNv5WeY03cUbfN4dTkfdz23KA/OfR8uoA
         M07AohMBoMTpM3rixC2HFWbNh6G8zi8XCt9HB+qg/Yx3ILhhg3UFc9f8i/TjMRH0OfiP
         5nDaRcA6VOKC0T6qidmhRxyCbwsyJbEk2z/AP5J0v/4p5Z9vJp3qmN4uqfT1P3vXDRtE
         LfXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=5vfy=nb=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=5vFy=NB=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e1si181707pjs.3.2021.08.10.12.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Aug 2021 12:14:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=5vfy=nb=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from oasis.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2468561019;
	Tue, 10 Aug 2021 19:14:35 +0000 (UTC)
Date: Tue, 10 Aug 2021 15:14:28 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Clark Williams <williams@redhat.com>, Thomas Gleixner
 <tglx@linutronix.de>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
Message-ID: <20210810151428.3e02d386@oasis.local.home>
In-Reply-To: <20210810095032.epdhivjifjlmbhp5@linutronix.de>
References: <20210809155909.333073de@theseus.lan>
	<20210810095032.epdhivjifjlmbhp5@linutronix.de>
X-Mailer: Claws Mail 3.18.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=5vfy=nb=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=5vFy=NB=goodmis.org=rostedt@kernel.org"
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

On Tue, 10 Aug 2021 11:50:32 +0200
Sebastian Andrzej Siewior <bigeasy@linutronix.de> wrote:

> - With lock kcov_remote_lock acquired there is a possible
>   hash_for_each_safe() and list_for_each() iteration. I don't know what
>   the limits are here but with a raw_spinlock_t it will contribute to
>   the maximal latency. 

Note, anyone having a kernel with KCOV compiled in, probably doesn't
care about latency ;-) It's like worrying about latency when lockdep is
complied in.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210810151428.3e02d386%40oasis.local.home.
