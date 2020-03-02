Return-Path: <kasan-dev+bncBAABBE5I6XZAKGQE2KRSXJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id C10DF1762FB
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 19:44:36 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id z5sf167779pjq.9
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 10:44:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583174675; cv=pass;
        d=google.com; s=arc-20160816;
        b=MFQlQI0VGXoBd+v6TS3e3psGO4/9fSrTntySoJxHDRE+pXdGSlPnieMpG3eoRd+Nq1
         riCTfh9ir0TJvtkFJg8BytBbrt3Mvn1u7aL1KbnJPnfAXITvwB628iTr1DDl/d/20xMD
         l/WqZWdha2WuUpUccsG30iu9uzXtrR+MqmKC0JDxeZpv99fa/7csEidlG5tLx90grUI+
         JLzs7xi6UT5xsqife521Jsw+25Bo5iaXSPnRGTfv9f9K28wZcohCs/R7n/I23iph3TTQ
         Vej3bdiuqJGHNcytFwP2TF7KQhotHA8hDIS1fioT5XkVMgLBAQy9wsVebI7kd4rvCEez
         V4Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=UgDxWnglVcJKIz242YOXfdKigflZMPtvwef9JBAideU=;
        b=lTksD0Vj6l2EkW+VlrJtjU4dWIiojYK/tfoAEqrpb2dXpEUeSF+1KuY63bt5lHkz56
         Mc75KDI8lRgtoEGie9k8p4nOMI1UT0u+dTkfJx/FAmq3mXDcm9MoKd+zL1vUxSbKf0y6
         rcttmzQJYe+ixowC5jD2fspNoGW69vGnOY3pjTjGZHYNelkHXWg6qBJuUuDaIrMM1Con
         dr55+sSnC3bBsZH0Ob4l1QWvHePujyjGpRGur+epogYifYm/A7rLQIEn+LaGRpAlF217
         8g211OhoEGqk8u13QUsMxPcb5VQoGeuyr0orKOz6OhNUdbGKu57FwXYGcWeu+85M/C3N
         /45g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RRLY9a1v;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgDxWnglVcJKIz242YOXfdKigflZMPtvwef9JBAideU=;
        b=NC2VM5shcIUCz4EbqAA3BNLrJZvgueQTKrGmQP3/8s8jP0DGwwCJ1XfOAohK43Pbda
         1uHKpHpGn9TxNFTnvbJomiKVqmG+n/+v8nlbFdYtCRyCe3YYB6b/q6HhXH2LYpl3m4H0
         Qr7/9PNNOJmvKzi6TE80h09uaiL0xD4R8n0Emomf+QB15drwmIRjYgHxMQLhj4nTIPzU
         3evPLEud64n4uQ6L/Jg+7mme7p4Lcg/IC066AieLW9yq1wQrW3UlS11WKB5rDk/AmatF
         fwcxPwcX+0+Vhzg2XBQrIw6gX2fdkE54PMnY1SS4slFKQ+CHdH9rti3WGjSnPB6tEe3K
         1onQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UgDxWnglVcJKIz242YOXfdKigflZMPtvwef9JBAideU=;
        b=eXfzH/tkDZhbxUtVqLMAtUA1HGU3Ri5Mjj5pm8jVcuo5wHvMcmUj0BUPznhZBBRCqC
         oEB3m6qR8t3OIfF8r3HSEgQUH3GuPY8CzumkHAJk6ioI4tn4GcIyQZ5rGssykEgmefK+
         iSI0/BGZNscjUI0EAJwwLL1xOX2XcTsO3grIKKJgbCcA2wsnqPwdB8daGKL77Jw8Xc9t
         HVCOR6Lji6x4rhvxK7dboRjsFfi7HgnAZpJAReWiddKCyoufQshlpD9QEzrCR9pKN1yy
         PMCbulAG+yJU5rpso5jJz92AXileRoAKx2QEtAkcDYG0wls1mjb0gaYzWU6qlagKbK3A
         7V7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3u6WJVv88Ebr+PrvaRzuh1ylMxTUE4dRfb92hBdTN3pwY/MjA+
	iFVZUpr4tDXKc2ANt3xVTAI=
X-Google-Smtp-Source: ADFU+vtDGMCLvu3tnI3SK6GwQPc+BGTTNCHLAJ67UWrwZr9Yfd2xZZRZ8p4wBd7SNG11cS65NCMoOw==
X-Received: by 2002:a17:90a:77c3:: with SMTP id e3mr258729pjs.143.1583174675408;
        Mon, 02 Mar 2020 10:44:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2a1:: with SMTP id q1ls63610pfs.9.gmail; Mon, 02
 Mar 2020 10:44:35 -0800 (PST)
X-Received: by 2002:a63:be48:: with SMTP id g8mr265352pgo.23.1583174675073;
        Mon, 02 Mar 2020 10:44:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583174675; cv=none;
        d=google.com; s=arc-20160816;
        b=OHT5IWMRBoJSzpZjeLSqqjg+B+5fr0aGpGkRNyzIeGxRvo8C2vfGRbkpaMkEAviD4G
         RkhWOYpdxPlZpVkFKRFPpi1IOU9yS2xxR+npxLzXBvWaDJyARa+aAKph7Z9juOlbUgi8
         EOaW/FYX+9CYghuZpB/ZQbyMvjtLe1S3JS2M4x/C2lSHWaVBNOVo7TV2IpkOwPYQn6gd
         hWQwVx59JlryV9aHgxrASo5It22yw1xE6T3wmv7q1YZr/YkUvctz4XHXcZey3B3vAWTC
         Vyh6B5GkLWhOPY4P2hiXk0yOzVlpr+FstGGl4Q/0Umxs9Rbaq570dv0G5OTd/pBI+i5q
         WqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xC3luU9luWif9zkpHX91xYMSIF3QvIoKNlbMxUDrpC8=;
        b=TmaED+/M7LAm4vYjlDwfal5Jc6B1kwcBudqafhCQesBx9l3LESO1qL3ZoRB0F5Uo0L
         LwM0QlGnvnvIzjmTgTjwyPMUxPJNPREgANZ42zgyJTDFDIBV8YwzokL7M7ZnsqfdVlXN
         OG2t3YToxZnmihrNQIbJ8+tzDqy+N8wTAeskrmPa54aBPqZkYtH/8VxJheJHqtWLFg5n
         R18Tc7R/Ocb3Y1CnhzXZk/Uxyd4ulmEEvHxpiq3SpFbdi5vT6AULdXvU28Kkk2fMF8CM
         FyukXnMmWZsJSuE2WXxnPMnQVtIOq2zc7THhnx1FMH+KC+XpRsfVwU4oO9pQc1D+x/DF
         vmew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RRLY9a1v;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mp21si7647pjb.2.2020.03.02.10.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Mar 2020 10:44:34 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B59DE2072A;
	Mon,  2 Mar 2020 18:44:33 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 91C0B35226C8; Mon,  2 Mar 2020 10:44:33 -0800 (PST)
Date: Mon, 2 Mar 2020 10:44:33 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Alan Stern <stern@rowland.harvard.edu>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, parri.andrea@gmail.com, will@kernel.org,
	peterz@infradead.org, boqun.feng@gmail.com, npiggin@gmail.com,
	dhowells@redhat.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr,
	akiyks@gmail.com, dlustig@nvidia.com, joel@joelfernandes.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH v3] tools/memory-model/Documentation: Fix "conflict"
 definition
Message-ID: <20200302184433.GL2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200302172101.157917-1-elver@google.com>
 <Pine.LNX.4.44L0.2003021256130.1555-100000@iolanthe.rowland.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Pine.LNX.4.44L0.2003021256130.1555-100000@iolanthe.rowland.org>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=RRLY9a1v;       spf=pass
 (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 02, 2020 at 12:56:59PM -0500, Alan Stern wrote:
> On Mon, 2 Mar 2020, Marco Elver wrote:
> 
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses.
> > The definition of "data race" remains unchanged.
> > 
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
> > 
> > The LKMM as well as the C11 memory model are adaptations of
> > data-race-free, which are based on the work in [2]. Necessarily, we need
> > both conflicting data operations (plain) and synchronization operations
> > (marked). For example, C11's definition is based on [3], which defines a
> > "data race" as: "Two memory operations conflict if they access the same
> > memory location, and at least one of them is a store, atomic store, or
> > atomic read-modify-write operation. In a sequentially consistent
> > execution, two memory operations from different threads form a type 1
> > data race if they conflict, at least one of them is a data operation,
> > and they are adjacent in <T (i.e., they may be executed concurrently)."
> > 
> > [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
> >     Programs that Share Memory", 1988.
> > 	URL: http://snir.cs.illinois.edu/listed/J21.pdf
> > 
> > [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
> >     Multiprocessors", 1993.
> > 	URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> > 
> > [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
> >     Model", 2008.
> > 	URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
> > Signed-off-by: Alan Stern <stern@rowland.harvard.edu>
> > ---
> > v3:
> > * Apply Alan's suggestion.
> > * s/two race candidates/race candidates/
> 
> Looks good!

Applied, thank you both!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302184433.GL2935%40paulmck-ThinkPad-P72.
