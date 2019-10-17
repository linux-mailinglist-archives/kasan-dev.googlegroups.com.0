Return-Path: <kasan-dev+bncBCV5TUXXRUIBBIFZUDWQKGQEGIHVBOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EF65DA6A7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 09:47:46 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id f15sf1458229qth.6
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 00:47:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571298465; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQ2zbh4vUbwEnSuoCSfCz/VQhUojO3v43lI3xXoaB0rndFr1NIe3oMC9bUhQSPnAGh
         4YJ/xycoPth1+Sn6K8hJvxttiPmUNt/LDK2U3LETTbMFv0yBYrwk4RHT/aIBE9Y6oFee
         FSEWG1tk+9O4ogPCVCfLWnQhElMM6HkDwqpXpI/EcTDFo4ZufDxUQAVvHZu3EsbrEuzU
         WgwV2/+jBM5XVdsRZdLgUK+V54Xib5wbLR621n7xTucEz5pExKHD69fcOWgHZh0nKgYl
         b7/Ijp9eY8z+rcOrHd1gs4EGd8d9seMTY4e2rm434u+gHFu/lptLWAYfB35BbCADseYg
         iKYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=j1/JaUwez64VQGGBVxUJtn5PLWyDf2FsHhFj1ULChPI=;
        b=Vgdgo7eyt3jMRxtuRDzRWBLZgNdto7LdFkTYwaYmAtBkEFXJhUL0n6sNSNtCenbRoT
         sBEvLUnyuqZl8n4SZPAfGk5eYmY/xJITZ8oaCJejNVXBZI3YGT9zAlym1YrZMUcdbkh8
         YTetdDMFLO4h8cyrkIP1is7ggWCm1Np+n9CJnsdUtaWPBbvRDORr3QIeckAjcW+JTPfk
         HD8L/A/Y86X5QSabtPlzPG9H8YBV6pjhyQlMLXZmviB/sJVhYB77P8dVbCm74fMWFuN2
         EDTzot3Vu+4KevejjEaU90Hdmm8yNA8ObhHFYgk8bJfcPGTUm8HDGVOdR5uesKLuWZJc
         Jv+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ROM9pgBt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j1/JaUwez64VQGGBVxUJtn5PLWyDf2FsHhFj1ULChPI=;
        b=A7Hu+iKV3fMQl17wkfQGWXEilfXl7MSNo9dRrv59kgVbH5AtPpGUwaavlRcp3s0z2x
         J3Rodj2GEe5nVztRiaef923NOwG0sIhV6RHxWtbdH2yxAFnsPYSIbnX1YWakS1QEW8Ch
         h3SncqIHQ3Yt3N6LfORQMOeU6gmMVhXS07fs3yNvxfVLcMWEHp8wYVH+5nPvJtRxidjL
         dmx3jUWiGuji8EKVdlfFqkhcNlbFGwwzfYtD2D5r+wmMHVuU/cX9rwmDizq/Jt1Z6xpD
         x03O1I3JWyIjtnHpz0jjZx3Gl7WrQ+KddjHw4SjDo9lX6YYkXtbG9AKmy5eBN5sieUxz
         KpaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j1/JaUwez64VQGGBVxUJtn5PLWyDf2FsHhFj1ULChPI=;
        b=on1PPAF8AC4aggSbAz72z6bgnglTClu9pwH0HopXzDTS+CixKFleiOVKlNnsOaso4B
         FGbus8r1sJWGxAF3rf61Wq380txCX9aT/q/zucLsQxjPsVEY/LWAtSeA/0WjE8f0Uskq
         igoZy1wQCUvlBUMzyjmnmofca9YPkDW5ZGCHR990riObQkgbXynRQ1AGznGmwjp0PCm2
         vfVMDJNXYyBRHyAK4iwh46qxHN+Dg+bvuCgOKQyTp0FHfNkRCXj+Fh54I1B3RB4sU+Dc
         O5fsJxefXNU07yv1f5UUtInDOmN1LOv5cefdaX6LLMZwgg/zmQZNBAVWOfLh6Cjlv86O
         LZTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW3YH9b5vm69u1q5FPb1nsYbgbrG/LZi7SjG5VIQ7kLzvdIQzfE
	qFCB571Rqi7KUbWBm7P7nXk=
X-Google-Smtp-Source: APXvYqzlmOFaadUFn3afG7Kr2t0SOA4YNroO/wHDho6cErV7Oc3rDvqodTPcG1B0XYbYxnNohdbldA==
X-Received: by 2002:ad4:53c8:: with SMTP id k8mr2482964qvv.240.1571298465078;
        Thu, 17 Oct 2019 00:47:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:34fd:: with SMTP id x58ls477842qtb.8.gmail; Thu, 17 Oct
 2019 00:47:44 -0700 (PDT)
X-Received: by 2002:ac8:6c4:: with SMTP id j4mr2440274qth.235.1571298464817;
        Thu, 17 Oct 2019 00:47:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571298464; cv=none;
        d=google.com; s=arc-20160816;
        b=r9BleJeR3k2Pht1EKUWZDYnvW68Y2CzHnCVVWxZ3K5Sym/TZSQFHkB9SHkwWsV/TkO
         1NsuVQnGoV8kJP3ZJHF3m7F3eFqB8tov+EQSuEY9W9HGgjzUCsuy5m9vjQ9eEApJ2VHg
         pm67rmp4EPZ4lywWEAPIqBKDM7KQwtdzxDT9HuJQ7YhTr30dUnomocRrAGBNsnuK1gX7
         Sdo2p5FAMVa2SFY6shefS6o0fXqLy04a7OeDWxRCk/wVbj2XXZ+mhjT5WSZRkS/HkrA7
         2iArDFZSJiB0O4SilM+gizo+b0how0di1z9axbqmxgcV3WhpJR4BwUWWN0yjAFz71C0M
         brQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CB9qLsgKsb2C8+4Pa5xdxWx+A9UkvlFXKVU3Kno+WKQ=;
        b=GzyKUGVkOKLpAqTwMnFnWsABC1Zlj4yCyDnzA67puajACldZaf5LXLaHwRxlm7DWik
         aYHRieH5wYkN6DNzAaYBO9LpBFP51VlOlTyCsRqhW4Si5qpBEbpg8K23qflgqXhiOfiU
         QfOYlHgpojqdEUR1Ho3LSZsuuXh/76oP3U7XYVnbz0EEAKC8DvEv1GE9OJze9DAqPpry
         581nfC/OpOMHQoDNNQsDjo2LwATrw0VgBWdo36smcNWsO0AeBaRn9zdl1Fn9Z78iwqdr
         cmtj18i0CwcOm3OUn2fItmtv3cVEQU2K3dwDiROOTbeFrGt05jnIllWqCcinW+ieBR+6
         FcOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ROM9pgBt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id o8si72872qtk.0.2019.10.17.00.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2019 00:47:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iL0VR-0008Vj-Jw; Thu, 17 Oct 2019 07:47:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CFD2530018A;
	Thu, 17 Oct 2019 09:46:34 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1CA14203BFA9E; Thu, 17 Oct 2019 09:47:30 +0200 (CEST)
Date: Thu, 17 Oct 2019 09:47:30 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191017074730.GW2328@hirez.programming.kicks-ass.net>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-2-elver@google.com>
 <20191016184346.GT2328@hirez.programming.kicks-ass.net>
 <CANpmjNP4b9Eo3ZKE6maBs4ANS7K7sLiVB2CbebQnCH09TB+hZQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP4b9Eo3ZKE6maBs4ANS7K7sLiVB2CbebQnCH09TB+hZQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=ROM9pgBt;
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

On Wed, Oct 16, 2019 at 09:34:05PM +0200, Marco Elver wrote:
> On Wed, 16 Oct 2019 at 20:44, Peter Zijlstra <peterz@infradead.org> wrote:
> > > +     /*
> > > +      * Disable interrupts & preemptions, to ignore races due to accesses in
> > > +      * threads running on the same CPU.
> > > +      */
> > > +     local_irq_save(irq_flags);
> > > +     preempt_disable();
> >
> > Is there a point to that preempt_disable() here?
> 
> We want to avoid being preempted while the watchpoint is set up;
> otherwise, we would report data-races for CPU-local data, which is
> incorrect.

Disabling IRQs already very much disables preemption. There is
absolutely no point in doing preempt_disable() when the whole section
already runs with IRQs disabled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017074730.GW2328%40hirez.programming.kicks-ass.net.
