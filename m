Return-Path: <kasan-dev+bncBDBK55H2UQKRBQGQU64QMGQE7PV32FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C5119BC975
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:41:22 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-37d603515cfsf2618004f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:41:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730799682; cv=pass;
        d=google.com; s=arc-20240605;
        b=h6TX8Te3J9BLM2pNn8770Emch9YL3LrXg2KW13SQdFCjAxd6Jz2rnrGXJojkz28qLR
         C4F24h01BUkU8MV4ykbGrI7CVlWnCui/KRA3GkYR3cXZbXooI9Ae+trCZ/lityBPGzr4
         tEAFCTDzWUt8zF2XOYTQ7dcEeG20FlwPeJ2JwA+eLE3EPArHsN/5qgvn0aHP8ufkJg0p
         FIHSGNB3a2qDCb+DkNaR3Lw+CEGxFMUnLiPF1rMBZGnkX309xh50PeTBkU/C2aFz/fPa
         3X0QQKuvrkZPCLN9L9uxelTDADqN7PuCSo4o0lRY2gZOrXD0OZJVLGvtDu8CJGvFEpyc
         FK5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s4yhXWJud5A8y6QGFfLyDgDvhdOuOkUp5LbPfRHgmzY=;
        fh=7vi9frT0mWZKOwjf1CF7VStNvkLbhRDB7SmR6J8FFjs=;
        b=fAxwqF9GhKihHfuSsODlAMFEcFy5kAkpjgW4WGSROTw00E56cJDcAmMXQXtey2A5tU
         sG4Cy4sKmoGeH/trUQjJ+MTKeEBFHdd7ob8QGCQsUsxxcfyJdFnOjDWql1kAyz2awuKS
         FenCQaSNjEbeDIg9BZ+h9zWATZD9wqbVCLu/XibyCdzdbMPHjn83H+AnhxR+gNlwbqox
         pjuama2+mZVnixXmxeZZnSGEprwg3ncaxyd94/N/8M0MKXQTjDipY+Wv9QjBqRYcOadZ
         l6JLPh+A8FQracMErVqRU2WZt01cLH//WS0FKyJ2PrtHynncY+1gWur2m6wdQlJaVeBW
         UP9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YTvdVs3m;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730799682; x=1731404482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s4yhXWJud5A8y6QGFfLyDgDvhdOuOkUp5LbPfRHgmzY=;
        b=bjAYQj3aA1IUHcZ7eqjzHoz2zVx0prDhV61nH07eKaaGYaJaixyB4dmN2sGCjGX61X
         GbttP3BMs+QHHtWMRSGm43JyVCHpjbph58v8U2ELNRx/u3Aq1DyLpQb99LgKtwqmlFIz
         oY+oyq07vMWZHYzO5HeyCZjdzR48QgrUtjUJ35+hJg0Ukx3I5eWFhxPzO2CpExl/saYE
         +0dxyf7ihbrRGqvib4ZXTj3uawh+Nq5hlExqsH9m4iIq6t8vzwrs9w3Ymu9pCv6VhCmd
         WAKHKdwG6PKxuQSEa7xcz5Q3Y5pmrxXGV8uhT/C1JlS5DQ6Bc0+LJa1fXgEyPu7Io1mj
         zW2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730799682; x=1731404482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s4yhXWJud5A8y6QGFfLyDgDvhdOuOkUp5LbPfRHgmzY=;
        b=vQgGOXAXMQrQxL0NcVw+Uwah3PF5NyPSg5NkH1xRkN5Ykho5u5PMdS+65bwokfgY2X
         9dQ2Cl6BToOYZJX9RBi7546ZxI2pTu18i+zy9EQ6PpeLHe0NQyzI6miwB1rk1VUtriZT
         s/KA1jzNGtrLwBM1VsNxUuhgiK1f8cwrLfr7zRUB5v6Mg8Dw0T+JWwJRb7QfFR9L/Uip
         wDTfmKsL7OUM+CYzSBROhpz08S7j9eg5vlXTCHr2qMA5ShzYHi/GwROZAPnH4J/+PHTP
         B8jgBJ7s6KdH+k/Q08/zizv6xqZYD5c2dfuR7KILvWGwBiDifMZuCSCHDXxUwR/c5EPU
         SBUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlkkGHC+m8dLB+M6/tzZCJOQHywXtmWtLfLWtym65nWwoJ93PRddc01XKj/3MzL/t4EePOpw==@lfdr.de
X-Gm-Message-State: AOJu0YxU6nm4Ge5mSmpJzEocE2n31o37Nv/BZ+RAF8jZ1TJQH65yrcBm
	7FtOSUKzshLZlmcUA/Ci5WLGHGMKY8m4YMYBiZlN7A7+Vrq3zshx
X-Google-Smtp-Source: AGHT+IExAyAHZ/VorkKzcd0GZqRJPJacURLShQki544k7eGPb3fNXxerKY94qUX+SPeFgL1U/i7LYQ==
X-Received: by 2002:a5d:6c68:0:b0:374:af19:7992 with SMTP id ffacd0b85a97d-381c7a47487mr10226629f8f.7.1730799681033;
        Tue, 05 Nov 2024 01:41:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b86:b0:431:1413:6f32 with SMTP id
 5b1f17b1804b1-4327b80c431ls1012475e9.1.-pod-prod-04-eu; Tue, 05 Nov 2024
 01:41:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFvrUhrOqFykThmb3TajaLuri0j9MuCBKVunv1gMmDplCj58I2PpJVZm3OZOYBD5u+WAHi8pbIV2c=@googlegroups.com
X-Received: by 2002:a05:600c:511c:b0:431:5533:8f0b with SMTP id 5b1f17b1804b1-432832972bbmr120716445e9.32.1730799678459;
        Tue, 05 Nov 2024 01:41:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730799678; cv=none;
        d=google.com; s=arc-20240605;
        b=IJz3Dge9gcJllerK/66fdsX+3TJ27JIoHrO12XKHZm93MQdCavGf+W7KyzgAg+wjKS
         qYQ+yAREJPisFMywE/YK2gbxYbFnqOaWYYbf1dE+VaFov6ioPYxOUFD2NhdFIzM9s9Y1
         5Ochi3Any8mFLqsAqvOFVkUPO8xWd6ljQ/a9B+AjAcJd3zM3NdUGw0RsPXGGUt6fzUcq
         4Cq1AN4ystezgxlikr5+6/QLTEn2r7EZ3klNTI6WXzWBlBGbCPqsiqJwiuBZkWYxsoo6
         CCKA8rrAOJyuYcVcH6JguJ4IFrLIEdcdS8DSfJKs/YLnCkNW3EGP7VuEEXZ5QC0Mvm58
         IXJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z8kH650L1UR0Vg33/2iiIpMIQ3EUCdNJGgzftwXxcEI=;
        fh=HKTbcizfr8o6QpmRNM/kCBMgTgM8xHS3xBQP4RvcwvY=;
        b=IKO5wt8ZmMekxkOzI3SGoCTxfdUtO0H4CD81QksDDneGNC++aPYeZaUgUsUAozTbA9
         XbfbfKiw3MEpQAEJVhc1yK15NjJEjrxgsKzqkdrlUeQ8lhswpYlhW5utmJ3XtFr9Q/HC
         8O4X6/Xd2pwZIuAkpEZLnK3ARjy0l+YL/Z0OlSGUyjLn9WmLDMbB6t2urV5xShVFCf9P
         UzAQ37SdyFyolZd6bdN6QvzeFBhV+kiLG/sVID2AqsgbNum4QVQ7FwPTpGXSTPV5yzXw
         vlBUeOB4Pqy2lejOKvTFoLDiBINloUkzBEB9hO+bhEq/dySme0U0fbP3Ai5ndcaKI86a
         2xFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YTvdVs3m;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a368745esi468855e9.1.2024.11.05.01.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 01:41:18 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t8G3o-0000000BiOG-2CUo;
	Tue, 05 Nov 2024 09:41:16 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id BAF8330083E; Tue,  5 Nov 2024 10:41:15 +0100 (CET)
Date: Tue, 5 Nov 2024 10:41:15 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in
 read_seqbegin()
Message-ID: <20241105094115.GX33184@noisy.programming.kicks-ass.net>
References: <20241104161910.780003-1-elver@google.com>
 <20241104161910.780003-6-elver@google.com>
 <20241105093400.GA10375@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241105093400.GA10375@noisy.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=YTvdVs3m;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Nov 05, 2024 at 10:34:00AM +0100, Peter Zijlstra wrote:
> On Mon, Nov 04, 2024 at 04:43:09PM +0100, Marco Elver wrote:
> > During testing of the preceding changes, I noticed that in some cases,
> > current->kcsan_ctx.in_flat_atomic remained true until task exit. This is
> > obviously wrong, because _all_ accesses for the given task will be
> > treated as atomic, resulting in false negatives i.e. missed data races.
> > 
> > Debugging led to fs/dcache.c, where we can see this usage of seqlock:
> > 
> > 	struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
> > 	{
> > 		struct dentry *dentry;
> > 		unsigned seq;
> > 
> > 		do {
> > 			seq = read_seqbegin(&rename_lock);
> > 			dentry = __d_lookup(parent, name);
> > 			if (dentry)
> > 				break;
> > 		} while (read_seqretry(&rename_lock, seq));
> > 	[...]
> 
> 
> How's something like this completely untested hack?
> 
> 
> 	struct dentry *dentry;
> 
> 	read_seqcount_scope (&rename_lock) {
> 		dentry = __d_lookup(parent, name);
> 		if (dentry)
> 			break;
> 	}
> 
> 
> But perhaps naming isn't right, s/_scope/_loop/ ?

It is also confused between seqcount and seqlock. So perhaps it should
read:

	read_seqcount_loop (&rename_lock.seqcount) {
	   ...
	}

instead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105094115.GX33184%40noisy.programming.kicks-ass.net.
