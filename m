Return-Path: <kasan-dev+bncBCV5TUXXRUIBBYFVS7YQKGQERTHIRDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D6E9414304B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 17:52:49 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id 4sf158452otd.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 08:52:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579539168; cv=pass;
        d=google.com; s=arc-20160816;
        b=ddwYC1uw0MHbB4PvRfKrCLWGCzjgdAJ5fYDu5YZ96ca/IZSji/5WIS1ES7bRtTRszt
         mpusBL1Dc1UE41NPYP0kQZ76K7FGMlNAn4o2yWYvK1DPO0umz3ducjr96ZUMdJAvnUgU
         hNVk/llG8gT8uB96jXx3nRqapbDuSk1KogiDitZlTdPPuWWIkrnHvtMXx0+iBgCeglSB
         WJ17as8tMzzkUkGTIwoBNPdU8pMEFsnbL7uh45TpP1YKOSVKS6XFpWEabDe30iD8MW7W
         uI234/fLbACJsYifq/Zt8E80HNQU+SDPj/oO7YSRtH7YHbj49AZ0MAqnhQJh+O9jK2KN
         MlHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=hMWGG6mjNcRP33DpgURrvghna511hr8oFO6Q2SdEAUs=;
        b=Dg75zJK2KKfByL9xMCKNlCEhotbZQCcPdidmnPLu7dz57BNyre7ZmSGFVROX30BiQA
         Hod5CKh1VRehRMiSb5BP5NL8V2WDF+zoG8CBfkNyEQnHughbr71RlZdjCV4X7v7tijZj
         j1TJpTvMFGocK1P26ldp4ruGC7CVWHDDR0Uvi4UZgoSmQFoYv6y3zVbxKmjLkvhEdeyd
         3wcAQadwoNN6kyd/rH6nNzpeA1aqjES84yhRcRMdp3jWbrmVurLLLnB69BIvbBFCbTAW
         Uw5gw+G7Z+bsH0A57YuqlvBJDKytE6QldqWHCXp8Qy15pOed0VOBNRAwOc5v9gx9XI1h
         rzmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Md6XQet8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hMWGG6mjNcRP33DpgURrvghna511hr8oFO6Q2SdEAUs=;
        b=g/t9MPPhi+bDjLFhKo83ZIt0GwyEsTTe4o7N7U4wxSFKP2P5FD1CXCWI1u44u73yic
         Z8+XvgxlIPWzFFs5K3lxJ6LdRNHH9g6I3yRrZMRHYm+WDJSTQ8KvJAjntV+dgnkJmvsg
         ocYTGoXFfyQp61hCTY0LeNMGkQHOI3VthRfSAKkDQlkp9g25y5L62wCxhi6DMlu7gc+2
         V7BMwOxRsleltKtPpvtKfB1Dpsd8p2eETn8ugGdCntkoof+gNULVqinnq8gkX6j5XA7X
         1yTg1MxgTyjryzWHNlaBubykD9B+M4GmSIlbS+NOqZHJMIHZJshxobjpCily6IolhcGG
         0C9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hMWGG6mjNcRP33DpgURrvghna511hr8oFO6Q2SdEAUs=;
        b=iIMHgStl6gQnS+ngZVaaJd5LCDTmELPmk+yL8eWdJ7H0tCYLTbxOVcAFJ7Ft+1Pex+
         GqVaupjyedBRPPyzkAB5sZLH6cwPaS2g6xdpymu/OwHKfa5yy7xsOcYnO7sSTxxgqiJ/
         +MJroH8Gv45UnDimRSeU8SoBYqilsbLEzQMRhohoW8lttkhLH9RhmQQFDEyWl+P+ieA1
         IIaTBT1MgYbTWMY5FYW96s0nj2maecpqAXxacnLTeATVy7W2w2etAfwBQ/JsvsM95Rel
         g6fmEmNlsWG+8p+MSH1r6N7Y5SZpCFFh8os7UhecO4I5PvLcuJx0fCmci7exog1q0jRi
         IBRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUaCVL3yI8EU3DeNpS33HOwkiEodpJ+NpxoI40NzPtsfVn6GK6D
	PDQNLZrD9BoDTgv+R6agCf0=
X-Google-Smtp-Source: APXvYqykoC0kQty9eKiEyoNoowGc9Z60v64Dci+zv1fD3kfXFOtlGQV/HsduL3TlLLcd6H1lijrkAg==
X-Received: by 2002:a05:6830:1f19:: with SMTP id u25mr294632otg.170.1579539168491;
        Mon, 20 Jan 2020 08:52:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:895:: with SMTP id 143ls5874891oii.1.gmail; Mon, 20 Jan
 2020 08:52:48 -0800 (PST)
X-Received: by 2002:aca:d544:: with SMTP id m65mr123959oig.177.1579539168026;
        Mon, 20 Jan 2020 08:52:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579539168; cv=none;
        d=google.com; s=arc-20160816;
        b=kbvZin3naMeiNtvCV4Im1l7NF3ijkvMKanmgnMPfFA2+mBsHOCWe244UNVyvjax3K4
         JaOyYjqPIeLaIrlIUU5sQe83MVAOWHQIyk7fHsI05GxgW91x/duMQaUsXw3xv1TsQJ49
         KC9Apk1FWwblURsc8GArxI913DfgXltyiW4Q9+GIAQmDSmSX4mrnYCF8x8y42TcMJQXi
         AT3zasVGETkqd2UUR1Pi8F4isptwaMHTHSOlZrS7J2hAvDEbnpxynPlmIlsWXFQzYeiY
         o8Ph1yxuMWEsnCHz+ciHLNRfR59AUev2z15ySWWIdCxE16uneHktQ8rMnSdxwD2vLa/J
         EjUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VDW7FtXo4BtzloxC2r6H0DCb1zORddn+6B6Y6JeqHl4=;
        b=X5thn8ACWpRVPU7KjXs15qYliHYN751nZlud/eHWcAB+hya5qMFTcTS6c0u3tVBas5
         jXbKwFjeUqdQHktn4o3sU7tZLLLeomPvrPDJMKHBMkuj09FZcLU4YmYLFPJiww79RdQP
         K0YRx8r1yZ7d7s2Lg6GlpRewsA9abmNI5IZ7383WKll0HivArhwxM2hub8W154FICvHx
         lJS2irNErh6y5WERTbG8blACCnKq/oT7883dqFI319RcmvqD4P1T38BayxdhVm9lpCaq
         K5ECUH8F7CykYeIkICTo02KE5sPiQfl4/m2CrEft/aP+1/3eFwE7WOH9K0OeflrNDi3r
         /11w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Md6XQet8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id 14si506700oty.3.2020.01.20.08.52.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jan 2020 08:52:47 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1itaHq-00022B-Mr; Mon, 20 Jan 2020 16:52:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 89C353008A9;
	Mon, 20 Jan 2020 17:50:44 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2574820146B63; Mon, 20 Jan 2020 17:52:23 +0100 (CET)
Date: Mon, 20 Jan 2020 17:52:23 +0100
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
Message-ID: <20200120165223.GC14914@hirez.programming.kicks-ass.net>
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200120162725.GE2935@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Md6XQet8;
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

On Mon, Jan 20, 2020 at 08:27:25AM -0800, Paul E. McKenney wrote:
> On Mon, Jan 20, 2020 at 03:40:48PM +0100, Peter Zijlstra wrote:
> > On Mon, Jan 20, 2020 at 03:19:25PM +0100, Marco Elver wrote:
> > > Add explicit KCSAN checks for bitops.
> > > 
> > > Note that test_bit() is an atomic bitop, and we instrument it as such,
> > 
> > Well, it is 'atomic' in the same way that atomic_read() is. Both are
> > very much not atomic ops, but are part of an interface that facilitates
> > atomic operations.
> 
> True, but they all are either inline assembly or have either an
> implicit or explicit cast to volatile, so they could be treated
> the same as atomic_read(), correct?  If not, what am I missing?

Sure, but that is due to instrumentation requirements, not anything
else.

Also note the distinct lack of __test_bit(), to mirror the non-atomic
__set_bit() and __clear_bit().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120165223.GC14914%40hirez.programming.kicks-ass.net.
