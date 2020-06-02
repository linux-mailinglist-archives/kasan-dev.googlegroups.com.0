Return-Path: <kasan-dev+bncBCV5TUXXRUIBBXF53D3AKGQERUWOTIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB0F81EB8AE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 11:41:49 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id c5sf122084ioh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 02:41:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591090908; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3WCVf+3xNOjdE0M4bsWxLeRMljmsqiM2gmaZ1OJ+3pbt9tcsHIryH4oORlSU0UETI
         h/8bCZLtmN8gj2MOSarYEO0rFQ3iCsriHpwemzDTxBbOWGVg+Vni1wqbJwoDxQ4or1UK
         IB5dvM24rawuNdeAUOBvGv1xYpP5QGl4mp4SGjOh0AJt6+CLU3Rt7fPSxQNcX6XQ5YIx
         nI1BlXuumsDnsWzo0LIeEcPlhkBZncBPSdHK70RnKPIQ8b/9AAM/kczHw56TXLxcBqdc
         oKtsLkPPosKIzZCj6GZLLDc307ylXd90M/f1NnHS9r45nLieZfv5BL4ZLTGH0FUbc6OX
         zSGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5eP/66B5JoH8jSDCsIdSeYxdwTZCu9ZlLFzFVrzX0ow=;
        b=fGd8vww9qt+Hu3pds9pjRL/m/atLjNP6NVbdqB6EBWvKRwG4Hpu1wugdE3vEcb51oA
         IqsxQ/g49uzmBYphgX8coRNKFZGt1Nj8UV6FihtmAkZar25Ql9zUY31vlG8FFegUULq2
         MzF2xY/04qsQ8dKrWNKEHYJygE22SRFljTfS+Vbpwc3GnvhNveNQ5GuC/y4JxVF+1eJW
         +2VQSiybro5BfPjuCP9eIuJtxeaOg+pkMTcZuVAS9r7cIjRowc4VHyWTtI2JXAkjuYJa
         wFYuDxYcAV5t/TaNU7MtB7tx1T27nLUOH4qp65DixYdvGtYQA8bNATkr3EX2tn9BOT2P
         pbSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n9ailRcx;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5eP/66B5JoH8jSDCsIdSeYxdwTZCu9ZlLFzFVrzX0ow=;
        b=MxvQrQlALCOUtT7IVqt2OZgpGy2m9jVUo36iTglPQ3qqjUxp28ElGvZU8bC6P6Hu0i
         zQQ7ac/2t/qeSY17lpKrNtKDhpYG0TSUhELaMvmWKaCorLROySxl7vyjDLQj1mWyLMxS
         RbHJ/pq105FFni8NCMk9epemPIdlUUdyOuN2+/O0Lbjyf5O+DEoOZ8pgmWOCqCeklCWi
         mPNYK74FtRkYErJNQPZ3nohzQ8lXQxU0WV1ebLMdYwjweGPMEBXMriT4KmcbE8C9CV8j
         EdbO3zvWLGADw0CGJ7KJ9AVdctDDa/Pq1XfqaFLS9fGZhT4xgBN9vPJ7uU2ejZNDniDO
         RbNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5eP/66B5JoH8jSDCsIdSeYxdwTZCu9ZlLFzFVrzX0ow=;
        b=sJPFGe9D6zfroc9Rn7fXLtaLTswJRwZWjKVez3bLwsKCHb5WPyVLuieDxB+pAsMQqN
         XzZMYgJHkmKnKNHYN410ffzwFM9BUAJctX/roG4WTDvNAEgWUlF7kJOgqHlyaLwb6h4Y
         SxzzcCn1yMD7E3PerOa7SKotNkQz7N0x9q26LE2BDoT5jxjcZrz28ZeLAze7pfZzh66G
         l0mi7ERYefAIdaSsklCmqTEiwfZYSzTDRwf1k/E+tFUvAmGx5GgSPuymMkcM8QJj5i2p
         g8kZiAi34ihxya2EmeeJgdHOTXqSZSqP2sD/BcDyYd1PYxf6hayKs0seM//IPXW5fQhS
         0HPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wx/xrtm2lhS5VZDSrz4+jXSPIC5uVF3cHdvhdhShjxvptS2R4
	1q9JFpIW42B85kzshQO2Mco=
X-Google-Smtp-Source: ABdhPJy5PVseQCjbE4BMlR37/F1PDq6SMsZFCgflmRVxaHTDPjyaJMtFQBrJxEn4T0xBXW3A1PGIJw==
X-Received: by 2002:a02:a91a:: with SMTP id n26mr25147719jam.104.1591090908762;
        Tue, 02 Jun 2020 02:41:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2e8f:: with SMTP id m15ls148219iow.9.gmail; Tue, 02
 Jun 2020 02:41:48 -0700 (PDT)
X-Received: by 2002:a6b:4413:: with SMTP id r19mr22215715ioa.162.1591090908377;
        Tue, 02 Jun 2020 02:41:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591090908; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQkpyCiu4YBL7/SGL20mc8jYFVEjzBs9ACIa3Cot2c7mg6+nzsBg97kJHEmbjyep0F
         kuR3ULyaHUfZQNidIK2Af0VdhswvDFAJT6HAN6wiLgtaCP7klo9siRH/fSPKtFo9+KQC
         joMeavs5IIwt0ZrPSCWR3L4ZgkGcmkYahmD5zOA4cJg+1g1QrGomfJaP/P6aWeSi891H
         2xzL1JDWHIs6c8TEPIQ+uQJotQJZJ4FNjIAphM9S/rTgkCx44flGpOf8kMZdSjJ4O27E
         Yg5GssjoDMLrBSJogFdO9RYCdZnWy/YG5z3WAqDDPjB9uKZCOng/QuMa0eyG24xlals1
         oOCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f/FIn/xczaJeGePujbt0xf56oNTzmB6hv0F5AGXANOY=;
        b=PMAEl38qAvkcP3FINODuJJaIgNcKthveuUET0yTge40e3lHbqf4X4izqmCphN16OHp
         VD6443JrhOYK0Y196KD/ibM8mkUUnLcNfzpB+l+IAmblmxiZ1nSIArSTKE+hZ1asiSJc
         4+660PDra2VxB+kq3rAJiNUUB96K1OjCHfKo7DwjTSEffojVIhQ6YSB8fvSLbahLX/Hj
         UaN/eW67pHPj4p0kZ7jvEwc8yq40kK/gPCNqM2/7L90QUKmKrbZ5QyYo9uYBLOyBtzAr
         xygxVcdOpTtUHAWHbLsFmdxtLLjCQjyX5azhZE6NdLwnpaJB+adcNS0bAPYq+oOtC39m
         +SYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n9ailRcx;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id k16si39318iov.2.2020.06.02.02.41.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 02:41:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jg3QW-0000NT-IR; Tue, 02 Jun 2020 09:41:44 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 52F053011B2;
	Tue,  2 Jun 2020 11:41:41 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 34B1A2B9905AB; Tue,  2 Jun 2020 11:41:41 +0200 (CEST)
Date: Tue, 2 Jun 2020 11:41:41 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>,
	LKML <linux-kernel@vger.kernel.org>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	Oleg Nesterov <oleg@redhat.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: PANIC: double fault in fixup_bad_iret
Message-ID: <20200602094141.GR706495@hirez.programming.kicks-ass.net>
References: <000000000000d2474c05a6c938fe@google.com>
 <CACT4Y+ajjB8RmG3_H_9r-kaRAZ05ejW02-Py47o7wkkBjwup3Q@mail.gmail.com>
 <87o8q6n38p.fsf@nanos.tec.linutronix.de>
 <20200529160711.GC706460@hirez.programming.kicks-ass.net>
 <20200529171104.GD706518@hirez.programming.kicks-ass.net>
 <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
 <CANpmjNP7mKDaXE1=5k+uPK15TDAX+PsV03F=iOR77Pnczkueyg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP7mKDaXE1=5k+uPK15TDAX+PsV03F=iOR77Pnczkueyg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=n9ailRcx;
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

On Mon, Jun 01, 2020 at 02:40:31PM +0200, Marco Elver wrote:
> I think Peter wanted to send a patch to add __no_kcsan to noinstr:
> https://lkml.kernel.org/r/20200529170755.GN706495@hirez.programming.kicks-ass.net
> 
> In the same patch we can add __no_sanitize_address to noinstr. But:
> 
> - We're missing a definition for __no_sanitize_undefined and
> __no_sanitize_coverage.

Do those function attributes actually work? Because the last time I
played with some of that I didn't.

Specifically: unmarked __always_inline functions must not generate
instrumentation when they're inlined into a __no_*san function.

(and that fails to build on some GCC versions, and I think fails to
actually work on the rest of them, but I'd have to double check)

> - We still need the above blanket no-instrument for x86 because of
> GCC. We could guard it with "ifdef CONFIG_CC_IS_GCC".

Right; so all of GCC is broken vs that function attribute stuff? Any
plans of getting that fixed? Do we have GCC that care?

Does the GCC plugin approach sound like a viable alternative
implementation of all this?

Anyway, we can make it:

KASAN := SANITIZER_HAS_FUNCTION_ATTRIBUTES

or something, and only make that 'y' when the compiler is sane.

> Not sure what the best strategy is to minimize patch conflicts. For
> now I could send just the patches to add missing definitions. If you'd
> like me to send all patches (including modifying 'noinstr'), let me
> know.

If you're going to do patches anyway, might as well do that :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602094141.GR706495%40hirez.programming.kicks-ass.net.
