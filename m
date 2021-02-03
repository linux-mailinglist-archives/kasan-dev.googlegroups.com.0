Return-Path: <kasan-dev+bncBCV5TUXXRUIBBB5H5OAAMGQESASUTHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7256930DFF8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 17:47:04 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id u15sf19433wmj.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 08:47:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612370824; cv=pass;
        d=google.com; s=arc-20160816;
        b=hEaQW1y/p0QUUi+ax9AVvHRHimb9vF77p8vRww0kRoLeiKq7rSyDaVjYxXxgRmuIKN
         armCDZ2R2ttXFOT1VCi7l0H66fdDCw+oDidF6mjUDbGuv1HUs6FliKv7llA9qTMlZaVn
         y6WDUIcgqQHQSyMz0WGOJvN2Yx6cMJHccXfN5RbTNC8kVhCKO3xWb14DFmo4AfQG9KT/
         B/MJTTCGQ6zfXBWtMF/ufSMRGgH4hjdEl2ED0g2LJHp/z8OBROMSrwfX1ezQwQFr2hUh
         dyb52BHng+SZMNk99QYpT/SzxuVHj21Cebx68KW65UBJjRn15qr2bzcAKgCZEAeOevWp
         uSbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=k8ABIBW6pTmNE1263+nyg9QC1mNC3M2tUU4tpmj6Kmw=;
        b=SDITta+bAjeDUHS0EKpaQzHxdc5kwgf1Yer308bTFPZx/JKvmsClx3RDNszbnDj8ds
         hYMPWOTtzE/2ZYryIb8ZwwIh+dEBOV7mbt3Zn1f+dO17nUPnKi3kkE8o8gM04roziZbC
         8xDhZcWCyjWa55JpIwjmg6GaYFX+sazfpDUEUQMtWIIQhra8T7c3NTePmijzhkvM9u4G
         GM+grRH6QWZN1HDSsjZM7cgdfqyHo9lISTTAUF59Bants4KHlyM7hz3X9g+rYVDRMEBt
         w4tJiGXxaZOSDLF8L8qGZb+j6rdbk+Lh5Sv5kHWqHQICHCyKeubfsfSvJAQc1QL/Ju7+
         86xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="c/OoSJg1";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k8ABIBW6pTmNE1263+nyg9QC1mNC3M2tUU4tpmj6Kmw=;
        b=K7F8H75vwT2Rw8CImKXuYYYzdfnv8rnqESUV7VbAiCRZ8Xp2Uadaj2yxzdS8C9adzD
         kZNGH20W6/8DL3JpvMqkcIU6ehv4leoUp1ZumQA+AdRTWCweiqfoSGRgR8BQQor+SI7X
         F7nWyYEDG5+IcrwoCdG30EHLFZZaocwY+exYiwuNR010zD4xwJ61Ww55irsmcvaS5wtE
         F67IVUSQ0tqpzisHwdhgNDUwz5As1gwziYZsKx4eMpmUf+j/ok82OzDexEhf2YCemI3k
         7hWGYsH2E8D1yOvCruXW+n73TkQb4B/b5HckiNNX1M4IDe7BWdRjMMu0d0cZ9vCKQWND
         LcnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k8ABIBW6pTmNE1263+nyg9QC1mNC3M2tUU4tpmj6Kmw=;
        b=jnpiVcH3Dc6NAjxu6XhYZIGMmcqvSGVdbBLTa5jWTtW8E58of0NuScn/vomQnxCskx
         yRh2sevR6YoIkOy6A43EgH9IIW1Fb8VEnqtT5qINhFzi5K+s5d9b8Frxq9IigFgeA3cq
         gFYlhtnZmgpHhmJvn+1pOMU9SrpP7dNhERORf0+uJAA8ZpE2efS+ZGRSYxLh3MT7CICs
         Fd/5HhKMK6NGqCx2fy1+xWAp9ZlHX5vC05sNhsmy7YvOFH2NBn549keRd/nk9hSgUEGf
         lgsjenxAQ6EZuqqI+BsccPTo+iFETUXu1r/FJUaN2Xrta6Nr6c8v+7tZWccMykqC5tH2
         CRDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XCsDu9YKR87EvxiBIeMuV7XaxeRnpD6TRmPYxHWO9lN6c2IsE
	gmLfrjGJVGUKT4MtPdgUiJk=
X-Google-Smtp-Source: ABdhPJz/X+W2fvhKakWMGF6F6GWSDiqU977zOJQO2+5yAdCLexViVENJjD0THGVNSRTDRu7S/n0BUQ==
X-Received: by 2002:a5d:44ce:: with SMTP id z14mr4577329wrr.330.1612370824071;
        Wed, 03 Feb 2021 08:47:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fd09:: with SMTP id e9ls3454177wrr.0.gmail; Wed, 03 Feb
 2021 08:47:03 -0800 (PST)
X-Received: by 2002:a5d:452f:: with SMTP id j15mr4589465wra.298.1612370823300;
        Wed, 03 Feb 2021 08:47:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612370823; cv=none;
        d=google.com; s=arc-20160816;
        b=PfjP9dGgKX5EMPaEbCK0eY/plZF+CLo76QAErMw6RKJxH4f1g5fko9Zl3oOxPZ46Gt
         P7zDT38wlPqllETdnR50bUad5gp4ArWnpIM/LrIy0kwM+gISGbEeA5WBwOMUIuropjLq
         28uZeWVSxoGOCSa2t0Ck0Zg+VMLXFST20A4GZuhXFfF79SAt+bFyu0wn39ZOmZhHVuhS
         VKRiCupW217VS/fnu5QHVMbKsqCy+0NbvHXDky7dr2vrHYA5URar2goj/gx517L4Vein
         ostyAq5IoL0GtxZEdECdjsC3E97IZGIEKrD54goFw1bcuwmmIDy4PxDu0/6Fo78UwrAc
         Y2Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FXQrxdNgWCg9t/vLa4D9ZuZRDMCP+8XGxw4US1HhTog=;
        b=Y7Az+zyfUZAj6u2vxLm2hFUKkBtOSzkt91+Y2W0SE3HHBRDp6kVA+SW01120LtXpb5
         2T/VHDZrQR6QiLz9T1UjYULr8DqZTWarFmjvbm2DYINPKbouQrhEWxbwVVx5qKuDWZ+K
         KaDzxiL3KjeX6U083lWMUECBmavyGF0kqqOpyPhQ5gOha/pbx3l3cftdktkLXn/7KNIy
         myvPsi+3AlvTZ9wh8CAr4H/o11N+nO1jbB6VXip0+cywqATZocI1beKSH+d9Cazpw1Do
         /ZwgY2JQl+Cs5RUzW0g+P8qO/hInTuETaYuGpSgyI8QfAX8SaB3FVQ5H2e+y+LZxXjib
         iMRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="c/OoSJg1";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s74si119672wme.0.2021.02.03.08.47.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 08:47:03 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1l7LIa-00HCKb-H6; Wed, 03 Feb 2021 16:46:38 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A8E0F301A66;
	Wed,  3 Feb 2021 17:46:33 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 97C5520B4DFEB; Wed,  3 Feb 2021 17:46:33 +0100 (CET)
Date: Wed, 3 Feb 2021 17:46:33 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="c/OoSJg1";
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

On Tue, Feb 02, 2021 at 07:09:44PM -0800, Ivan Babrou wrote:
> On Thu, Jan 28, 2021 at 7:35 PM Ivan Babrou <ivan@cloudflare.com> wrote:

> > ==================================================================
> > [  128.368523][    C0] BUG: KASAN: stack-out-of-bounds in
> > unwind_next_frame (arch/x86/kernel/unwind_orc.c:371
> > arch/x86/kernel/unwind_orc.c:544)
> > [  128.369744][    C0] Read of size 8 at addr ffff88802fceede0 by task
> > kworker/u2:2/591

Can you pretty please not line-wrap console output? It's unreadable.

> edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0

Not sure what tree you're on, but that's not the upstream commit.

> Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> Date:   Tue Aug 18 15:57:52 2020 +0200
> 
>     tracepoint: Optimize using static_call()
> 

There's a known issue with that patch, can you try:

  http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBrTaVVfWu2R0Hgw%40hirez.programming.kicks-ass.net.
