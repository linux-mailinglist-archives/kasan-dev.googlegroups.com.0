Return-Path: <kasan-dev+bncBCV5TUXXRUIBBSF5ZPYQKGQE7746DAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4CDC14DC48
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 14:48:57 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id z26sf1852712pfr.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 05:48:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580392136; cv=pass;
        d=google.com; s=arc-20160816;
        b=A9xmj+E38X2WFJLOjwz8ht3VEtZr0jiN2vxgn1FCOGfmdozWoJ8AONvhl5OATZdSI1
         tcsTz9a4BwtV95HVCKRghTuntT2ojlvU4nCZAEEbg5nxXVlVrZSoIo/BmPC6wf6Icg/P
         BkAfNNRgSWymZTX/D2SXs6ohTcu9GBm9p4+tkQg+lXY1rXFWUdsh8kYhDXFBkffPYuFb
         vwAOAToAE9fqJiODf0IggHi9iQgNKAugVjvSRa1IvjM3oVnEZ9ZPbynFPlXPig0GVGe5
         zS+3MjXCmc6h36A01l1wDMkC88A3Qpp7MV3fFJ7/B4NqGAkvzjLOWfRzvAUPGzJN7RsI
         OBag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GBLz4BZVYxfkhWnfeZlznWkM0Dlx27n6hXpKj9VzT54=;
        b=g/3YjCdHdWCoKzWjf451DTC/Iyl+tSGyh2W7cS2pjoGVYy8dNRo8AOzIaFawPpttze
         Q/nLaijYvaMH0uoU8xwD4frPH4cpoouYUv779s26B+rrRmbSEJttvd1Ng1V96CyJasVF
         at7Ybj/XS9QcEkytuJBbv7Vd3MZzoiKXGgu6bbYC6b/57Z51qpUq+oMj+ZGhu2az/Ywg
         WcVlB3m8W3+1FUnrj9VBCUuiF7Fx6FyPJBcz3/Hqs6C5cbgvPi5tsSK1Xne3mClqGpjI
         xY2wdYUvrio/dOeClLOoea+l4Eg7Fqgr4EBJTF3qhvSV9HarATYM6wvbnl5kQWJ0dBwQ
         khaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QQ+WNZuW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GBLz4BZVYxfkhWnfeZlznWkM0Dlx27n6hXpKj9VzT54=;
        b=Re6B1XA7LQD8G+/o32FcheaCpMT/o1DdJAUaRS151FRrb1XWjvLYWLxpYtVgtU/9wM
         al/I/jagTYR8uPObh71Vc2U73GwKNOPVYybhaOGaLbaxzxJogHa+mRG7t454Raky/2/T
         NdJXjDmm9VlgqYWM5Y1wMYe4ez/e9dAVxNeRIsDIf+YOJjzAh/WpjkESzIz+8IKCWpWy
         4neutZo5lcJ+KISg6KxJ02cl4AeiiHR7hvYMmlLNWbi8Y1KkmU0M4IQImkbtX6k684gt
         kZ8QmRZpJlSvcMWCJwcIkqPfKQyxF7R9gt4lGHvfuXhubM6KgaQ1RPFJHlUV/wXdQaqK
         GYZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GBLz4BZVYxfkhWnfeZlznWkM0Dlx27n6hXpKj9VzT54=;
        b=oSf2ehSl5c+DAX/3KYRmvQoTsyVnPSAir5A+11hWLQIdLYvLqe/EhZzslbOtjOwBbp
         fi7nKKRP/wgrFOCofHHhXZ/BVHxdQWCJhCGiot+KSO18Mv0mgjKbDurXyio+mersldfy
         5O5Y6sU5hIn9qIZAddsKeXYYk9V+rem4NKiBT3xRg2uLyM7+JkA0bfbAZ3lMEsVxNMOC
         SgQ6nWjTORBL6ni/PYgNsuWBOtx46mHyIe9T3BxaA1FsNCT3OCq3g4EEosCBAvxlobPg
         n+eHa5HxljCVeXAwq1BOhUkolRteC+QvMJlOKPOwEdJB/JW3p3gPkeM9Oh82tsm36n6R
         tBDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVn9rBSO8PZ8ENdTYCB6uhK8p8hvzxSwz9HRMv8hLCFlcGRHa3y
	TyKsvsjWVlADrKCowA+ETTQ=
X-Google-Smtp-Source: APXvYqwRlXMAz9e9bIxKFgHyYKenc7ypR/AfmUZAax98kNmAD57TP496s7LcYjUuEyLHY/kWi1o2BA==
X-Received: by 2002:a62:19d1:: with SMTP id 200mr4958182pfz.26.1580392136340;
        Thu, 30 Jan 2020 05:48:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4608:: with SMTP id v8ls1539544pgq.8.gmail; Thu, 30 Jan
 2020 05:48:55 -0800 (PST)
X-Received: by 2002:a63:c511:: with SMTP id f17mr4725388pgd.198.1580392135892;
        Thu, 30 Jan 2020 05:48:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580392135; cv=none;
        d=google.com; s=arc-20160816;
        b=HFQGQGPdNXSky9d0AVFvfmDf74tBj4TjigLkYJasspJVu87fo6ed/nf9Vpv3gXyCoO
         pNzWu9fddbia6iepUtUzEHoxXesGcweUDvpoYLVwL80avcHg2xLeJSjKeI1CQ+jF5SN9
         LbJ6KO2fKE5KzyPszYUzPrZLvtPD+9xuLN/BBPWzioyOZt5j0Du4coUwQqGHwy/+L2UW
         0n3eywe9HxOYSZ0DTm50XWG42QxSOaWnGAzNo+hrPcxRfHmSDjZCTGw5u2G8VbmX8cCn
         srt/qpsYiIdkkTEFkgUpU6lwrZ8mXSCEjM8Exl0k7Ee6cktB7r2MiuNdXxLIDQa2yGir
         qAPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KWeJ60yy7ZEEaAUYkcnvwcBr+M2J16KKlBnyHKEQ2N0=;
        b=TuYlz0Ldn3iL9QMt4HP0ZypnMGHtn4PZatDYQdRSfLSrKOGmPuVwIq3HFXwPMwui3d
         AyDBTsOK7UufgTgFLu3hFIiGpLJflDShwvXjRVUu8xY5/D3aEj2Fh3P+ueZ2MWkM6CFJ
         YVPNmlz4UzyHS6HbQ5eLrdAsrpjVpHDr6Ito8wKJTXsoSw2xNwbrGFP6l6ZYbuGRQV+A
         2ifOHJE2lPmB7XKE3fa4Y8v5g0tv4g0VF3oDXdr+OkAIGCzYRWoljYNt0/fSEocxEvxM
         fxmB9kmou0w4ef9083J5IkmtCgOxVdCDofZ1PR4SStmOtxYgHF0DTEJ/ozmqWyYXt1jV
         cv+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=QQ+WNZuW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id i16si321083pju.1.2020.01.30.05.48.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Jan 2020 05:48:55 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1ixABh-0001R1-T0; Thu, 30 Jan 2020 13:48:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 6EA86304BDF;
	Thu, 30 Jan 2020 14:47:08 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AE96120147130; Thu, 30 Jan 2020 14:48:51 +0100 (CET)
Date: Thu, 30 Jan 2020 14:48:51 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Qian Cai <cai@lca.pw>,
	Will Deacon <will@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200130134851.GY14914@hirez.programming.kicks-ass.net>
References: <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
 <20200129002253.GT2935@paulmck-ThinkPad-P72>
 <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com>
 <20200129184024.GT14879@hirez.programming.kicks-ass.net>
 <CANpmjNNZQsatHexXHm4dXvA0na6r9xMgVD5R+-8d7VXEBRi32w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNZQsatHexXHm4dXvA0na6r9xMgVD5R+-8d7VXEBRi32w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=QQ+WNZuW;
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

On Thu, Jan 30, 2020 at 02:39:38PM +0100, Marco Elver wrote:
> On Wed, 29 Jan 2020 at 19:40, Peter Zijlstra <peterz@infradead.org> wrote:

> > It's probably not terrible to put a READ_ONCE() there; we just need to
> > make sure the compiler doesn't do something stupid (it is known to do
> > stupid when 'volatile' is present).
> 
> Maybe we need to optimize READ_ONCE().

I think recent compilers have gotten better at volatile. In part because
of our complaints.

> 'if (data_race(..))' would also work here and has no cost.

Right, that might be the best option.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200130134851.GY14914%40hirez.programming.kicks-ass.net.
