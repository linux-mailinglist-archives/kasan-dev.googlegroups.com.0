Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7VIYX4QKGQELIBR3UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 32471240732
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:06:56 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id q18sf7102494qkq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597068415; cv=pass;
        d=google.com; s=arc-20160816;
        b=mytam6Kuo8M1IpXO/0CAaqwD6+3wWdWtX22xmDCH+H4Lxg6wzxtEEIQhsY2DDf7eM9
         1tyO1FCx64eQ8X2kI1F6qJN3v7SI8KLWm/ZnEX1CWy3EWDgzdTyyoEmOWIRvsJiK/Y6q
         Wiv8CpfhGUtDn5Tm5be3VTP3ZMCECniDju1JU3VJsIQcO/cmM5QLZ/aQ1CWIizUad1+k
         BhIWQH842B1qikHX+IBMJWpxnuCyHZuW3EvzDhgNM9dGGAT1F7q+wljm9YC3O2FSxMax
         TxF34NiUo6xJClkm46CqZpcBt5XTdd8DhEsVazL+dAxx8K9gm2j58GJULqfMBxycieZ8
         KbbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zy2AGE4pmT4cAQD53leuPRVgXH/6hrTyhujO03Z4IU8=;
        b=mMwSFm4lw8n2SGDQENUF2HT8TCY2ucsCHIIkQDJuNJbM6LlSRMSSpMgW8vhGCOrMUL
         2o5LpQLYHt72JtE/LDcc8RajkJYon5ptiS9MT2Cw9pGjseeYbiHECNcCW9L+L6WcrqAH
         bLDXYjcyfIojU6+qKIOYpKPnkjqdpzE2Mqc/x0qk6OgLmArJErOpRjcjFSI4bSui6DDQ
         CGKHc097SixE4CcH/+rCPjT+4LcPR1I0NTF0wn05Qjz7kDrGGaGxQoJt7OOshYKe1m80
         emto9rC5ol9m53gQINZ1MCDZNC2slyJfzfNJ1h0KR5DpA5MzDDNj1R/ssXlbODk2qalA
         pKHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="UamQ/jqM";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zy2AGE4pmT4cAQD53leuPRVgXH/6hrTyhujO03Z4IU8=;
        b=CSwG1uwJKJzX+lIwrIWfUcxHvJtzlcrqNcMJlqvw+Cu9hPtUB3qqY6pKkxO1HJNYPX
         TKXEom4N5NjQ8BP7GBMQlbdK48mBvE4jylpNxJAL54hftSBluSRafd7j3Q8XZRQds/pD
         nAyAbjcjL/ZBF3kTFsnGIVJmYEXZotd9Om4NvsI7zzDl1Tx2kayJYlS8cDO45vHDgUho
         HBzffFcuOJ9eJRmBl1OmczVIpHTuU6akza/ZD69aB3gU8IQU8Z3IbhWArWjKtewLF6dx
         uhZY4diIVv3NioQJOFp9SFTqtxE4Iq2gBBvwuQPCza5T9yJX/72RaNBmBFHftDcsiKTc
         IdHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zy2AGE4pmT4cAQD53leuPRVgXH/6hrTyhujO03Z4IU8=;
        b=dUCXAter9a1dASB/Jcy1SNxQWbk4OY4kK7ch7pf3qQ6I6y4saRjfRuNd8Irt43cc2G
         QbaQnzhy2ZeLUIM0HGzla7O6qAeh7XFqXqFXHHS4DAoyVzz8uksAVqY0e32XTlRyHOsH
         2OSPdv2beGaF2DZN6DrN00diKKNCy2v5TAlQco5eCGS1fsgIQMxx6Zxfh04WK4OXrvqs
         CFzjV2Kx7Ae48kgFzHY/VHUyAUkBlfrpSeDLbmufZ7OG+Ph8HOgPD08DFmPUt59w3HX6
         hIK3schWjqEYn1CjvpKG3EG7g8nFg39JwO7QL4MQ53Q8u7GpkpDZYTBmapDy6QsRJBA3
         wroA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oIcW01+dXDpHeYuad/WNe2vYwxlnBITApznrSq67WSjpzK9Tn
	u34n4jY1Ii/EbJ3A9ptMFjs=
X-Google-Smtp-Source: ABdhPJwSun10hMzg0qbW28C1ZeWFjvKCN3dfhM6aEwkg2k1d9XKlk/j+9d3EhUMJvkPFz5w+Jiql0g==
X-Received: by 2002:a05:6214:184a:: with SMTP id d10mr6718089qvy.190.1597068415151;
        Mon, 10 Aug 2020 07:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5482:: with SMTP id q2ls4319545qvy.8.gmail; Mon, 10 Aug
 2020 07:06:54 -0700 (PDT)
X-Received: by 2002:a05:6214:11a8:: with SMTP id u8mr27042882qvv.88.1597068414454;
        Mon, 10 Aug 2020 07:06:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597068414; cv=none;
        d=google.com; s=arc-20160816;
        b=MYvcGi1hHaQEMh3HpUrbyweCCW96USOwhbQztnC5c/ed1qZ0y0fT9CgO7FBt4jNWyI
         YA0X9GzMpcut9c5JaRaTl10lJFNkcjVOYaGBEe/bahgW/syX19y6p+mXAWEIGKSskEit
         vU3nOyHQq0maFnOhcfeUvTF2nRW8zKHtjKqF9YbhdTp2PjgIFNVBZWKOOqCUFD6k+QRZ
         yNTxxY/AhoFJPFSrkobK0Al8yfQ9kdQP39UcYb2O65UhhlLz4AXATQaIwDbDBoZuuAqx
         c5py9VJhQXeuYQVEfQBmORytaeT4XpaDf13q7mpXlsLaVCwvUFEc0GnA0y2xPrR+HYZv
         Qxew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0NkcUhh2BgxISPZreSijRxme2NhNix1+tFt4ONKujyE=;
        b=RNvP3DsoNUDKuLLhQ7QhN7lEBCoVYRi9pyjYjABHjMPnbVDRKRlNd0c9Sd5zlq7QST
         LgyFlaHF1+UNoMf5mwa2xNnPQQWnDWKM6IOiod6gowXNeJfc6VUoqm1WtoQtghjGqFfe
         BWEOGsUvMUfJjHmPPgHhZLgKHw63yq9FkqhQU7BJSOu1DOP6OyrW4u0l08PUFAkUi+ZX
         J/ESo9T0nj2MsqfG6sx2FtSRyowha74t7tpPQ38JNfJN3L4Uq/ZdKL1u3OR0MXIZZbGB
         FulruKBFlhC48ob7oxn3wkKcUPyVstglXl09MSb0UbeQax7xF4o71qMDZ5sQk6GQrX5V
         mNOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="UamQ/jqM";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id w5si8039qki.1.2020.08.10.07.06.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Aug 2020 07:06:54 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k58Rt-0005F0-Sm; Mon, 10 Aug 2020 14:06:50 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7618430015A;
	Mon, 10 Aug 2020 16:06:48 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 618082B2C802B; Mon, 10 Aug 2020 16:06:48 +0200 (CEST)
Date: Mon, 10 Aug 2020 16:06:48 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
Message-ID: <20200810140648.GZ2674@hirez.programming.kicks-ass.net>
References: <20200807090031.3506555-1-elver@google.com>
 <20200807170618.GW4295@paulmck-ThinkPad-P72>
 <CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG+YTV6ytj6wsc+5BPQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG+YTV6ytj6wsc+5BPQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="UamQ/jqM";
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

On Mon, Aug 10, 2020 at 10:07:44AM +0200, Marco Elver wrote:
> On Fri, 7 Aug 2020 at 19:06, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Fri, Aug 07, 2020 at 11:00:31AM +0200, Marco Elver wrote:
> > > Since KCSAN instrumentation is everywhere, we need to treat the hooks
> > > NMI-like for interrupt tracing. In order to present an as 'normal' as
> > > possible context to the code called by KCSAN when reporting errors, we
> > > need to update the IRQ-tracing state.
> > >
> > > Tested: Several runs through kcsan-test with different configuration
> > > (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> > > original config that caught the problem (without CONFIG_PARAVIRT=y,
> > > which appears to cause IRQ state tracking inconsistencies even when
> > > KCSAN remains off, see Link).
> > >
> > > Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> > > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > > Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> > > Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> 
> Peter, if you're fine with it, I think we'll require your
> Signed-off-by (since Co-developed-by).

Sure:

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810140648.GZ2674%40hirez.programming.kicks-ass.net.
