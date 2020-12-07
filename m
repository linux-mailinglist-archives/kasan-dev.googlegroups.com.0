Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDVXXD7AKGQEZO7H63Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D3C9A2D101B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:09:50 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id o197sf2677114lfa.12
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:09:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607342990; cv=pass;
        d=google.com; s=arc-20160816;
        b=pph9zmvGUxSIo6PiROD8T35RSbiFup+5pSnHqBlpCsVbr+bSuWAWVtCB+k/vTkA7QA
         avd96w2Q0yS23nUBM5+gbD0dtaShTA1wrXmawhkgEbstUBmBKwZmvIkMdXdVcdsZ6bhy
         YyGwTgEMPg2RHjkhrE10+2Uou7Be84zS7NjL2kCICsV3SfP2Bxhz4e+zycDSZlxOKbQU
         MM26D3o0F5zBA6/jFsLsSbQOTVmbNWlk9/7XuM6ABYrtZf06aatNNacmx12t9tzYGxNz
         AVmeClO/hv7CioxF+wM3QLpvDB9jZl4hxbygma1Ag0cVjUbkGDe/rZjrVaEhkVTMlNM/
         7CgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3bMo/qLkvVIKsFGbeXwLqnKLYHrYeZCo5kZxOPav4m8=;
        b=O7VtsIVIdGdkiTohHEr5P15EkvEGsu4EmIFsf00b7hVe/X2siG4vRAtmplwzvFYFo7
         8QiTn6NKgtKjsOw1p1E8iT+eJRAGl2FlfMpoqW8+3dE0QfEn/OFVve/f1XB1As7JvTuv
         sCxuhLmfBJLYOwxvsHp3wkXj1ZSCCJ4j4s1NSsoq/PGSjQqtJJV/NkspD6QiqrEPIjbe
         w44rrKQ87Nvjeo54jRh2sjqKJmQdik0Mt7eiPNg9JUE7BMoX7nOVrnQBD8hwNxWLhyEk
         57aKJ/j4d+ri9Vz9ssDVY6kLRL1JO9WM+wb+1qJZV4KBaYL9Ue6D962YlM/23N5+kMbl
         QF6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Ob9akebT;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3bMo/qLkvVIKsFGbeXwLqnKLYHrYeZCo5kZxOPav4m8=;
        b=OS196pSLcXnNhdqtGcNBADA/gOEoDSksQ+MKbPmLGSwEMceppZY5GwbOM4515z012m
         YlzWBrJdIlHogij4hXGKyhEFWMUl1SSACCWgG9WZYEnfTaUhvLEC5r8C36OvnAXQGUIL
         ncObj9yVu06j08B1JEXKMyusFuP0MEONb35BHOoHV/vgBlGZOBbhG8ew59m82yR6irVZ
         A6bLcQtOdpyDyRTaXzy+G4bmyAPpaVD4SNfwtKYhkkHCehqwzNp7ho0NFVezSu0K6aMW
         4C64HVVbl43lc+lcSBFlMFLRG2h7ZtBm7tMpjO6uPTmzA3wV2dT5oUKYU0We9tiaOhWy
         aDOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3bMo/qLkvVIKsFGbeXwLqnKLYHrYeZCo5kZxOPav4m8=;
        b=FkUhPEWuk6shyC/BpWz+eQelMQC70pKj5vFiiJFDD6FpTStPRkSjkgc/EAvMv8JUl4
         usBEzsaojxTwcggiJAuwe4QVY7U4vbp+ajU+NfylvHrw6Pngm/zVThwnCH4YpNKd39HJ
         ooSUCJTd/dYyt9OB46PUOI4JLb6e6pgTd/6dviby6jc3ySCd1f0UDvatRd6mh1DiKJee
         dnjHzEyQmlJEsw1XGIUxXpa4vTunFAoHdGcHgtIPF0ewH3FPuRZ5xWPhbU/A4uqsh6tK
         9M52pEz3tYMZ9ygeCIUqnoAg/OHppgACwRrgnABF16XELSFzTGrXZRAxefX1ahQLB6pa
         u7Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339wKWvE+tL/RkBSNcRVRMwn6UduCLHnGBiC+QEkb4l/9i+DTdn
	/lrpl8EFv2euNw2yUR2ziVA=
X-Google-Smtp-Source: ABdhPJx6ieESL9WPQxOT2dLRwo5RbfRiqQCO5G1rmuPAK2A/hOa0kTZQr7uEuzY4YuxV65MVnp2/Yg==
X-Received: by 2002:a05:6512:78d:: with SMTP id x13mr6113624lfr.366.1607342990359;
        Mon, 07 Dec 2020 04:09:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3614:: with SMTP id d20ls651539lja.6.gmail; Mon, 07 Dec
 2020 04:09:49 -0800 (PST)
X-Received: by 2002:a2e:9acf:: with SMTP id p15mr27647ljj.192.1607342989499;
        Mon, 07 Dec 2020 04:09:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607342989; cv=none;
        d=google.com; s=arc-20160816;
        b=oD6zggoKQfxiuJE0hHa716b2+5wd2Zv+xtxsGciwk4CCEo1ZMmbw7skdggj0pZPSnL
         FwrvXio9rkA88tMfHCfebcrjd+DE9wi9T3HmejxHcsViRjPJr24YWu0u+LJlCTXZjuOY
         Ooz2rW2VSiaiWajF1Rl2G1Mk0cootG/bxWaLfEvUaAYuQv7bUGMBS0Svxi/paaRyiDW2
         bjp6HJHyqk797SP3BwOa66rhCJrS23uz1CXI1h4H4gB6JlEngBPb9VExqJ8HuQRgg+A2
         4BA6zv2KeNWLhJLhHjybdAhCNrvN6u1uHbJp+uw75ELvLmJvnaIoBC2OsFMvOOojrs0S
         FCYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BbTSzr0ekrkrwUMtMIVfByGKajgzqxX+9tYinOrH+wI=;
        b=NPpCSeEonft7dXmppdadXmJH8H4yKx3LrLf1bhpZ/xlLv1TdJWaxiTpzeep0Y7gOV1
         1C0qXRyNQOndFG0gJryVHiahG1VaYfJBFJ8rWfEWwAqbZB99N/hHXRz5Szix+t5nrG6i
         zYkEPuw2HctpUyw9tsg5YpIBeZmcEF6plKEvsBIXA/6L/9rJKMkGkOWqv/SjAa2wAy3l
         rQO8FMJxFvWIRffsfS41Txbvijx5o1Bm4nAlEQ6loe9jOf9io4y4Y5F5cr3r5npGbcfH
         9E4IBlmRGt8IBics1tl85y0R3bo1cXGmfvlkA/zaOOkFY4fw5dinv+Rpl6iZUwol+SHn
         6PfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Ob9akebT;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id h19si572385ljh.7.2020.12.07.04.09.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 04:09:49 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmFKs-0001ZN-8N; Mon, 07 Dec 2020 12:09:46 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D4703304D28;
	Mon,  7 Dec 2020 13:09:43 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B8A1020812B4B; Mon,  7 Dec 2020 13:09:43 +0100 (CET)
Date: Mon, 7 Dec 2020 13:09:43 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201207120943.GS3021@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201206212002.876987748@linutronix.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Ob9akebT;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sun, Dec 06, 2020 at 10:12:56PM +0100, Thomas Gleixner wrote:
> +		if (data_race(tick_do_timer_cpu) == TICK_DO_TIMER_BOOT) {

I prefer the form:

	if (data_race(tick_do_timer_cpu == TICK_DO_TIMER_BOOT)) {

But there doesn't yet seem to be sufficient data_race() usage in the
kernel to see which of the forms is preferred. Do we want to bike-shed
this now and document the outcome somewhere?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207120943.GS3021%40hirez.programming.kicks-ass.net.
