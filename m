Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPF66GFAMGQEMY2XXXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DA809422AE6
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 16:20:44 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id s10-20020a1cf20a000000b0030d66991388sf1371561wmc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 07:20:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633443644; cv=pass;
        d=google.com; s=arc-20160816;
        b=sb+gDmrd4e35qr6X8V3GWaoPqhWCz9InnauEd4vBrxNR9jeFGCVvrBWYhhoP7BYNZD
         QeUbFWy9Yr6B/LedmBCm45eX+hDnEX+imDK12ouyw4h291gPpo6uWAT0su0uwmSwIuNe
         oRDlw6HE/ROgWz39ldA5tWR9gALGVVxFJePXZ2HSAZ5Z2lRXt2FH+BcLWltL5OLH3mhi
         e2bu3ZSeyTHUxegov2zhyP8lbCUx2Vpbj9YtFduwsdRuzfS6xg9Qyuc2ilIkZtUHjBxY
         r/EoeE9zQTs/SbMnmGCYAN6mV0MOyNJrpd88vz+MvJ9tzN137eha9WDV+baF4WzetaxO
         AMMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zhD1u7H9UFt6cjDEizeHkMcqQJiSIYQaocj8vxVeMEI=;
        b=orPhEWSWnX/EBs1wkBdGi/YKm6UC7epQbvGo3X29m1Tw/kqZWFLjGaHs3sr8Ay/uHr
         s4VogzdaH7PMLQut8OYPaxUpAu1eL5UW+T33FAx59K9YRtlB9gG1/g+6u9yJPKvAg5Go
         FTxZWYa5D15ihX2vOiCkWJhzkkFKtpotp3R5u+q58l8usVuguaNgBW+vCz+0QAOAB/jQ
         9oYsvqWSmj9TN+/iIINYSAI2qWjc/ZqW4dxGtgAVxWN2cdtphZQmdLQpKKk1qcFjbqH4
         rUIicxlzJtDuWbQ/ShuVURlhzplkyv3zo7ob9uAktEM6Oi7UwBbfQjOZdLeOCkm61QOH
         YG5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OnNnDZAK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zhD1u7H9UFt6cjDEizeHkMcqQJiSIYQaocj8vxVeMEI=;
        b=iKv/lpz6fkecZa6eX9S8cSANxid2+XnLp9gEQLOZTd8akZKeONFrUuhhwwJA+LWQvn
         EYxEMMGW9enGVehP+wq1LQob51YhrNRvA7+up8tw01UCbqnpAdq5Y31SPvWn9ux14+m+
         QAodK2xd52F9Ym23lEPn7ZkdNfB9keFMi2TZmJeyoQIbRJr/Pq9TshpprIH157K1qER3
         D/QGh/8CWQd45YsjHlJzD2k/3jQhUk5rZCHo1s7z21bYeS16TV1NHuLrEHYw1om+aehO
         4QeAzOEXjYfXgWnsTENbH3cw3p5Ylx7oig7X/VDnNJAIuRQ3gxZR+KO8sf3KRy9mJ6HN
         a0gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zhD1u7H9UFt6cjDEizeHkMcqQJiSIYQaocj8vxVeMEI=;
        b=eik8VAjmTZwR1Fx6qBmHm0R/qmZhNwxqFHw+C79zrFIljrx1qq53J1nMwvIzmZRGt+
         8dyAyAi05lMf7NvM6CFSrL+d68iVb23UoTOCTmKk8xzvJr6DiUXuG/zgc2ZVWnbNh/eB
         o+a8HUY2tyRyzW0Haq2UtJKVYocS75M2kddhZrNnP7BkYGGEE78gjKRTm34f16S8XkOI
         13NiwvV0JB71/2aC4MwlSz8A3H16Cu8TTv2NNlZ4mMjJgC/GlbN2XDELGaVlZT2xddxa
         9oERPo0lb6mEf/YjKff5ZWbJVok3IY/eZFIr7uXhd1/TY0jHczyIMX42CG1KQJOftzKS
         3vjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gtFPeY2PdFz+0ru3MJ3RQKExAl1ZB7ArdZDIge58cPPDrBR7Z
	/bGMceEKgTeKwhg4Ts5Cd4o=
X-Google-Smtp-Source: ABdhPJy3W1EQqPibi8kGNSafpa5LGGRp+33aULoOrywbmW3FRrjjTLE9TStBjfO/PoeR12W/d/Hz1Q==
X-Received: by 2002:a1c:f216:: with SMTP id s22mr3825421wmc.27.1633443644621;
        Tue, 05 Oct 2021 07:20:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c782:: with SMTP id l2ls2807806wrg.2.gmail; Tue, 05 Oct
 2021 07:20:43 -0700 (PDT)
X-Received: by 2002:adf:a30b:: with SMTP id c11mr21837204wrb.289.1633443643791;
        Tue, 05 Oct 2021 07:20:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633443643; cv=none;
        d=google.com; s=arc-20160816;
        b=wPJ6MLkrCL1wCL8iY3UQFB9ImQexnEWvtBXTUumN8nZmRFMkBqo5CzdCam4jOBwU5X
         z+rP+9HqNHuq82chLGSsFFqLYfXEs3qLU0Ql1YOCB5wMiTjm57hbq13eta2A2NiLaZb2
         Bouloh69TicuSmMT2GeQvhthrQBTJ/JuElJnOLBwlfLwNBvgGo6o1QsutH16YvzgdBK0
         5OBPF6K/HSO3/Ju1C92SXvdj34LbEkd8/LuWj5Gcq9Z3z5KSnSnuZSkBxvSHtyEq8XR2
         7wovHsIkY+9QeaK4KkoztirHMvf5tMgiuv4VYbs9LU3/ziPsWzFNhk9mbeEJGzV9m6Yc
         RwTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9cd4fflbhPi+WS75BLlYH8Lxr29xEplX+5DiCepdM6M=;
        b=tXJRsZPKbMwdz3183IUTuBexjisoqSe+V8ZToEg24P1tAkkA0PZwWptRnZ6ar4uPUd
         BbMreAlIx9E4t2kK5kxKSguRlBZSA/mSKzY6kdYK976wK1MNQEvXnJoeFq34EThwp/fm
         hgDZUNipGKVYC9W69KWi3f4Kbyn2Tq63F6dCwNn00fb5qsP9/1wHwI4jl2/HtM7u5ky2
         Es7t13LVZfTngPwUQ8UNPbfnjh0PMLOPo9dmF37v+2HC7+OkN0TxyMJ+9AhPwtYgiX0e
         yQ8hza8FfMcMT2x73BSxyIQ1fWcsc7QEA7yGT3UQHnpRRRQsF3RqN+/v5oui4MaKg1Ss
         6rsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=OnNnDZAK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id l3si120320wml.2.2021.10.05.07.20.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 07:20:43 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXlJ8-0083tX-1Y; Tue, 05 Oct 2021 14:20:38 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 28D5230003C;
	Tue,  5 Oct 2021 16:20:37 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 100B321339B6B; Tue,  5 Oct 2021 16:20:37 +0200 (CEST)
Date: Tue, 5 Oct 2021 16:20:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 04/23] kcsan: Add core support for a subset of
 weak memory modeling
Message-ID: <YVxfNbTgT7GN21I1@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-5-elver@google.com>
 <YVxKplLAMJJUlg/w@hirez.programming.kicks-ass.net>
 <CANpmjNMk0ubjYEVjdx=gg-S=zy7h=PSjZDXZRVfj_BsNzd6zkg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMk0ubjYEVjdx=gg-S=zy7h=PSjZDXZRVfj_BsNzd6zkg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=OnNnDZAK;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 05, 2021 at 03:13:25PM +0200, Marco Elver wrote:
> On Tue, 5 Oct 2021 at 14:53, Peter Zijlstra <peterz@infradead.org> wrote:

> > And since you want to mark these functions as uaccess_safe, there must
> > not be any tracing on, hence notrace.
> 
> In the Makefile we've relied on:
> 
>   CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> 
> just to disable it for all code here. That should be enough, right?

I find these implicit notrace thingies terribly confusing :/ I've
reported fail to rostedt a number of times only to be (re)told about
these Makefile level thingies.

Ideally we'd script notrace on every implicit symbol or something.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVxfNbTgT7GN21I1%40hirez.programming.kicks-ass.net.
