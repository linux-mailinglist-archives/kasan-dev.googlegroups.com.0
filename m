Return-Path: <kasan-dev+bncBCV5TUXXRUIBBUOM3L3AKGQE4J5REPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FCAD1EC29B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:19:47 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id y16sf9076717pfe.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591125586; cv=pass;
        d=google.com; s=arc-20160816;
        b=O9PnkK3KvnWkEZ9z7533w3QJ90LWfq4omNBsk9eFtO1bWEDS8WL/gn3zoB5fD1m6px
         xGJytHSs7/Zpx07IfO5PQSQEaAPPqp2FS+/vFUydABP73nc/bauDRxcDYWwGbuo9gVO4
         D65KIEmKl7aBYpIjiBuJtjfEx+2qnl3W5qw+0V6unHKnFpfXLzKFTTJhpIOVQzcuoFwt
         VmUULCpTLGJGF+2pdRl/+ZKFJF6yZeVfmfchnE5dLLfn8bsRqZxjl0OZGf7uSk0Ex/vD
         FZmXGA5FUwpJC9jEamWLmch5hger5rScLCoti8XASYehvavaA4mAGHTTvLVcC+pGrzOM
         qexw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cKUGmxw4k/Yziov9biJNtRAPA1n7r0+6qXHYlAw4Pq4=;
        b=g2WaS9pXRh52cfUkehLdiSZ1pKv7hbjUo4H0OCT1nxRLvBnu1ZFU6LXiTReNvkgcDe
         1heT1EFZihPqTa7XDbB6CrHHzXR3hJjTSLkYwl1oPbzi84NVWCmqzJ4zgQw0va2y16at
         4B7xQtcwP4RABgLjWrRXrPMVcjVC3i0leY8H1ehNnVZ+8t9ywL3qrJwl4X/QQjMue61T
         MzcWzxvV8QxrZ6MPcX6WqUEhEMQdc5DQc7yWJwGAuvpCQed5LkikywAoSy33y9I0sAQL
         8pliWQE2FzDSZUgI6hGC2kJ8Mp3cCWGrCPl324uVXagmFVpwyaWVzTsGc3VDlMdh0pRN
         sz7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=A7zYw3qK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cKUGmxw4k/Yziov9biJNtRAPA1n7r0+6qXHYlAw4Pq4=;
        b=VehNKo+uqAYRUspbVBPnGpzImle2/1IZj/auuFASxkHGs/EDhqLOTejSqdz5FnjoUW
         55K/XYfsIqZ0N0jt8NoKy0qHYzwdLsNwNtIyywIQLXFyN6YbLzuVoslMIwV45HpkyY4C
         +BTpX5ehTqwzeSp3sp3pNnktYe11krhXKmh5UGEPDtb/VTrTw/1NsBLu/1MQq57C23E7
         5jIfWVePolWEWnJ+YfZ3Ob2f2f1x2I0yix/0X6o6ivjYxx2JPN4iy/ggVw6gDtthKVTK
         7Y8NaE1JMRYMVYWtO5LXP9td9+5PdJ/b2w7UEHDgfC5NbF8gM8nf0sMrp9TNzLPFdS+S
         PxaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cKUGmxw4k/Yziov9biJNtRAPA1n7r0+6qXHYlAw4Pq4=;
        b=nV19n5c+WyiseICPRsAq26bsJ2mGNG+/ZEdRtbT15fsZgQAZmijgxLQNhZ8SVQztaO
         wU5fWV/QftlV3Wht7IZ/CkaRmYwRc6I66rvRHfHkHMM7qDgC6i23BEPWff+5PP2GuhhT
         POa0lhElp0P7zRL91ef0HXlrNIQ0+zRnX4mmxnNNaUHkD0MFUITQI/2P49fDRJ6XOK+Z
         L9rNbZ8me+pIM6gsdyv2Y/asomwDgvb8LxS5nKMLwpIRKKlPrjM/X/KJvjHrmfdilZYf
         wtb01VOcxYaNcVOdgBFODBACrFzqNnVVzksimdcOQDbBDiHpshrRma62gy80Q4vzToWz
         qZMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D0+8uK/DwiO0jDyRhyCf9hpSt9FuknRHtGOCoE4HmusYAUxxO
	ofXc4zi0Df4qb8Y8WsyQV/w=
X-Google-Smtp-Source: ABdhPJyAqlxAmN8jllL00mSvUoiB9qYRIYClEsVL09kWq0K3eTwQKOjck05BdltYz+va+GHl0I+5ww==
X-Received: by 2002:a63:be02:: with SMTP id l2mr7869988pgf.347.1591125585776;
        Tue, 02 Jun 2020 12:19:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls2044666pjx.2.gmail; Tue, 02
 Jun 2020 12:19:45 -0700 (PDT)
X-Received: by 2002:a17:90a:734b:: with SMTP id j11mr731288pjs.114.1591125585441;
        Tue, 02 Jun 2020 12:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591125585; cv=none;
        d=google.com; s=arc-20160816;
        b=YxsHlSAlcGP2KPrwHnpLgkmpxqAANNzCMfeQwdIDNWD8ac4FJvGoLBmPTksYpKFjoj
         cBuka3gYLI3DXjxHSkh9mb4gB4Y1i7vYZ89fhQtgImcolGSjPkturbTa6ztrGZswAgOf
         ktcVDft6O+ZBs/RySHJWK21ow2aWsxPaq15R6uR7M3fa4jpeLYAofIqKmZPdy26uXJkL
         T6nl1wEvb5bi7Q5F5SMs0r1uwYbjtU6kJI1vRm+VSJPGtv5Ln8r02LlK/BP3EQ35qrr+
         ciOVl5bfJKv5XTxpCfpN8c2ny+lzEJpgORseyb13xxxo5D2K0kU8jATIqZ9n+hMHMe7z
         eVEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mG+CJQG33NKFFc3Wsgq89KyUGRH2llxotrBKMYPSKBw=;
        b=TilbFhyH6K6MLRAwgxOE81WI9ppxXc+qyZ9nTqrDQHev01oVCJyo69Wh+ItCEbm4Au
         bUYCBqC6/H4IiM6gEWzEQEv+pv8hLfCcIKUWx5458qdXFsu/GHdfr5EDbHEx34osDj0Z
         YMvnEI+jVmbJD+XfQz54NFkZlcrpQ1ye0hW/XUh2gsDFXsxIpuagQFpCtSgASASErOLp
         Hnia8LZ8CQo0XQSg/dJAwus8T+XXxgemZhXz06cDzB5wvgBTg/qlyZtVx8oml6eKv7Mf
         3Q9pw3QhzpyA9AKbr1vR08kdbxHU/olE9pi70q4SJCQOoABt0hFUkH46bE8NCwrwswQD
         wM2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=A7zYw3qK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id ds21si178319pjb.3.2020.06.02.12.19.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 12:19:45 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgCRn-0002rw-If; Tue, 02 Jun 2020 19:19:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 40F5930047A;
	Tue,  2 Jun 2020 21:19:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 323CF202436F2; Tue,  2 Jun 2020 21:19:36 +0200 (CEST)
Date: Tue, 2 Jun 2020 21:19:36 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of
 KASAN and UBSAN
Message-ID: <20200602191936.GE2604@hirez.programming.kicks-ass.net>
References: <20200602184409.22142-1-elver@google.com>
 <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=A7zYw3qK;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jun 02, 2020 at 11:57:15AM -0700, Nick Desaulniers wrote:
> On Tue, Jun 2, 2020 at 11:44 AM 'Marco Elver' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
> >
> > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > have a compiler that does not fail builds due to no_sanitize functions.
> > This does not yet mean they work as intended, but for automated
> > build-tests, this is the minimum requirement.
> >
> > For example, we require that __always_inline functions used from
> > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > fails to build entirely, therefore we make the minimum version GCC 8.
> >
> > For KCSAN this is a non-functional change, however, we should add it in
> > case this variable changes in future.
> >
> > Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> > Suggested-by: Peter Zijlstra <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Is this a problem only for x86?  If so, that's quite a jump in minimal
> compiler versions for a feature that I don't think is currently
> problematic for other architectures?  (Based on
> https://lore.kernel.org/lkml/20200529171104.GD706518@hirez.programming.kicks-ass.net/
> )

Currently x86 only, but I know other arch maintainers are planning to
have a hard look at their code based on our findings.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602191936.GE2604%40hirez.programming.kicks-ass.net.
