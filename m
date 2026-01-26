Return-Path: <kasan-dev+bncBDBK55H2UQKRBTF437FQMGQEOO2JU5Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6DHyB0/ed2n1mAEAu9opvQ
	(envelope-from <kasan-dev+bncBDBK55H2UQKRBTF437FQMGQEOO2JU5Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:36:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B44B78DA49
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:36:14 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-383005da622sf16403811fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:36:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769463374; cv=pass;
        d=google.com; s=arc-20240605;
        b=YErV+g12iMoHvCJcgTGUcqhgFyIYFoCXcLYm4xCsH1NeeC3vKDBBqsTGBmFJWu0Yja
         18K3ih+nGP6rPpmo6J/1w3IPS+ppdcnYa1Kdzt947fN24qx/LD9Zl1Kf6OwDlPAcUDw7
         oTmA2hcOmFbc3rteo2J5dWXph8B0Z9qtlLXPBuoxNMQV9LYZhVr7R1EFIljySATBIUEy
         5F4Yvf5MAJ5aY/vpJzOpo/2grFvhdFBMYAhychPumqOlj31VQFyYF/wY/XEu5uL/FLn1
         TjhW86UOJ2goSJdamnp6HsOcFmsobCPZamPIFSdmMW35SgK5EGokHIjNJZc3K4hq0qJl
         GQ9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gW6QnoVn/Ks3kSa/sx1uxOQP8UOGeWIM3OKumTzrT78=;
        fh=W04Lb6/CIkxwqS3V9bs6mwY5KS5XihWn7wdF/lVoZBs=;
        b=cZG9S+wJxxJos+jDcMNvG/ii0v/Lzx8AoUNxp+/2XRRc4Xc23dzqvVnbpmEs2jGWwH
         J22TWjfjSVe5N0RjMQcjKL4mmO7bY9j2psp0Xi9hrMH9CGIhnQ/QOMSXaPCXAc0XaQ8a
         WDIOb0TskxXUgeMWR10lpA8ROKkyzMfAnUKqiCQaLVV8szu8lmVvOfKHQ2XaQb3eByIH
         x3oPQX8JnHhOoMm2PUpSEJpqg4UjGLD7CwWvQ4B5euot9CQQJJgZLbzHPg5vnmtNow1m
         Jp6I1v/uTcgTCjgFGNW57rZdhMEcDai2a8YLoYPS0haEbETDp1k9FNd3d/BtUyTSFbw8
         veEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=J6iAAvmt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769463374; x=1770068174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gW6QnoVn/Ks3kSa/sx1uxOQP8UOGeWIM3OKumTzrT78=;
        b=rfvH1kyRrmB8Q3PVrJa6nleE/7LhX5Gr5nPMu0i6YkUDjCovaQQw6QyY5QwCxISChj
         H9JAgNL2lUZH086Eq6iGaqk0mJgI2yRDhkeh0r8Ug4cFcY2BQ1D4hWmqjmUx1Fsk27Vo
         LNCDtBunNnVCIVBpMBX/lcCDQryNaXy11/qCQqTJCUiRMco9V6x+oA3rJwRLVHWtF2F5
         aM//kdMAjhsXHinr9/b1J5TsZ4atLH6vL5lcMUF2yS4uGVb0a52KLxBo0xawPiw1vbxo
         7KBbGUi9TsRZ4bhu57vYSqLdcaAR6ugjXv8WIo8xAvhNMOMOOcJVa+ubmXsmdx+fCGRz
         j88g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769463374; x=1770068174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gW6QnoVn/Ks3kSa/sx1uxOQP8UOGeWIM3OKumTzrT78=;
        b=dZiGcBX1U2QocrSqK3JrMe9FJ5WqhHyKKDBygmdosH7aGhAYyqBXOMmtNNzcrx+Zzn
         A1FdKf0RojYu8qjDEnfystL7HW1pH5yItj7ELnbNDO+ZQenKTuBfB4BqQWLClH3H2QKb
         a3nfzcTi9P2AbGaUf9lq+ESuMlFNqdxBOo178q7a7YzhXOEBDo/1h5lG+5nHvUspM8AR
         6wwMxaf66aZVbJf/Zrl8CczxDUxu6aMP6l3OwheUZf6e6xaUZt6ZUcpdrFWzvCzLz+sa
         xxWQOEBHxUvuWDDGHe2OXaJRkphzuf2c2Lps+kSDlYSIVcoNcmmqs5UuU/eDIcUKYQkH
         KLsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzAjQ0n17LqUohtfkpnHw1xZI9ko7hAQkMfF5HmWRGg45gPPzqA1dq4JlDjVj0YttS9I+Aqw==@lfdr.de
X-Gm-Message-State: AOJu0YxUsrKn3OcfcnO+UNRGMBDqXDYOJ7wpg4ReaUzVQbmzIYtDtK9d
	8PFP2/PtyHyO+rrjoz8FpKHyEt4XWgWzyryq10Y+F/aGuqhycLCWym0y
X-Received: by 2002:a05:6512:2311:b0:595:9d6b:1178 with SMTP id 2adb3069b0e04-59df3a0d810mr1522382e87.40.1769463373515;
        Mon, 26 Jan 2026 13:36:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FIOFTGNFvrARMToyYDfd1zINv+lkxM2NdwW37dddKXQw=="
Received: by 2002:a05:6512:138d:b0:59b:7bbc:799e with SMTP id
 2adb3069b0e04-59dd797ab6als1705776e87.1.-pod-prod-04-eu; Mon, 26 Jan 2026
 13:36:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWTCnVswRoyduZ7ATNY7Yo10/nphfDjPQeQXCnp4+HWboxjSasGjhxuY1/QgmWDnRTglqOVlWXc4YQ=@googlegroups.com
X-Received: by 2002:a05:651c:1113:b0:383:1ec5:9641 with SMTP id 38308e7fff4ca-385fa17a64dmr17196001fa.37.1769463370567;
        Mon, 26 Jan 2026 13:36:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769463370; cv=none;
        d=google.com; s=arc-20240605;
        b=himKOSb8X14jOF+y3xOSRdUgqWuVgQQljN23eb73T/mUDvV3VILbmnJjpo3V8lV4GD
         DbYTew+ITDuFwfs8ZFWHl08Mq5dxrR4O8qWn08KKzPikbjHPNGmxQUgLVp7OOzvDeAFq
         /qXiaIyNswY6f1jvzTMGndvI2AVcBBN160XxOozCxs3SAp4s85Yuk+Bj7siC7AKerEU4
         ZUSs9dIE1CgHtO7Mi4GRnt+bIx1LfWETYVFbWvPHtEebI9od2f6ioKQAufFwEfKqD3Al
         JGxSN57jeSCVyXDL0IBc6Lwyx5sFsw03Z7zmTU+iP1Qeo5QLmS3bUhzd0P3s1j/5GlIB
         Tqww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IDX9AjD0dwjrQefXov9k2MtCld60dtQxGUUAV2j1WjI=;
        fh=dMnbXmMHW0WlROHqWVurkunvR1FS0hKijZfUULZ96Oc=;
        b=SzrI0KLKqY00w88u2IDA2l/5EOHdqq245VTZQVjPF7cPsoVUt+03fAvCZd3R2NuqgH
         WWtF37Otw5CUIGNQkbLrgECG2noFXV3RhmoSf8pAxcrofowlVmZdl8TubNUJmrtKQUpf
         24yUFguj3/HFvqUBAYNJwhMAtaBgIY3IAb5az5KP9vYblab5IUIf5IdUWXkM/4/jb3WF
         pMPps05fxsnzHbWS5/wmgQUn48pxFQq8+IBvR/sFJ+RCDayMsnpCf3deOcMDT02/eYr6
         6MPz+nRVc4uM+0+26C2+7UjAQrHMRdfW6onEA55uhds4h6499mijPSDQ0ZD7RHAZO7No
         H7FQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=J6iAAvmt;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da0ea73fsi2449101fa.4.2026.01.26.13.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:36:10 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vkUFZ-00000005tyU-07kL;
	Mon, 26 Jan 2026 21:35:57 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 41718300756; Mon, 26 Jan 2026 22:35:56 +0100 (CET)
Date: Mon, 26 Jan 2026 22:35:56 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v5 15/36] srcu: Support Clang's context analysis
Message-ID: <20260126213556.GQ171111@noisy.programming.kicks-ass.net>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-16-elver@google.com>
 <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org>
 <aXez9fSxdfu5-Boo@elver.google.com>
 <8c1bbab4-4615-4518-b773-a006d1402b8b@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8c1bbab4-4615-4518-b773-a006d1402b8b@acm.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=J6iAAvmt;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[infradead.org : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDBK55H2UQKRBTF437FQMGQEOO2JU5Q];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,gmail.com,kernel.org,davemloft.net,chrisli.org,arndb.de,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,i-love.sakura.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	MISSING_XM_UA(0.00)[];
	RCPT_COUNT_GT_50(0.00)[50];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[peterz@infradead.org,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lj1-x240.google.com:helo,mail-lj1-x240.google.com:rdns,noisy.programming.kicks-ass.net:mid]
X-Rspamd-Queue-Id: B44B78DA49
X-Rspamd-Action: no action

On Mon, Jan 26, 2026 at 10:54:56AM -0800, Bart Van Assche wrote:

> Has it ever been considered to add support in the clang compiler for a
> variant of __must_hold() that expresses that one of two capabilities
> must be held by the caller? I think that would remove the need to
> annotate SRCU update-side code with __acquire_shared(ssp) and
> __release_shared(ssp).

Right, I think I've asked for logical operators like that. Although I
think it was in the __guarded_by() clause rather than the __must_hold().
Both || and && would be nice to have ;-)

Specifically, I think I asked for something like:

        cpumask_t       cpus_allowed __guarded_by(pi_lock && rq->__lock)
                                     __guarded_shared_by(pi_lock || rq->__lock);


I think Marco's suggestion was to use 'fake' locks to mimic those
semantics.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126213556.GQ171111%40noisy.programming.kicks-ass.net.
