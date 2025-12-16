Return-Path: <kasan-dev+bncBDBK55H2UQKRB3M6QXFAMGQE7SYRQ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7439CC2AD5
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 13:24:14 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-477cabba65dsf30099375e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 04:24:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765887854; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z5iO8SDArR8FzGJ/s+g9g3iFvrsTcn+c4iSVELuYreLrQaLkERQCiiOHU2yYl7HE7a
         1or8UYSmn6dw4qi2hyR6tKjlUris276EJFfGMQdEFKy9+HZO1/Exzn2CQPUykU4NdQX0
         8TvNdPQO9Oau+TUfW2LUC2KTUOjBws+5Z7V59lBLjnNT0f5pBnYT4v+hDcX5ISuLjaDA
         f6J5z5zRQrCKGqmoh95E910xMsOeYapzFhYDMpjOPAtO7roEIICKKfjseecIZETkqD3r
         CE3YD394lccF/wcGNC2gkOJ4SFD22o7Zngc0ncFJnSx7tnxHA0tdGr1tIbNEJ3gGW3s8
         kEhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JvzNlrcD2BSgRUsK3E4AA1HSOjBHaVyOpIxu02ZHVSc=;
        fh=grQrRTahNfEBqFSZJKfTkdZMol3iBG2EQHA+LaelWGg=;
        b=htCykrso1m1D+rPY0uK1p5Sx8ywj5Si2ITuEqkX1OQDZ2V9P3+AebDdfULH7FYLVLr
         MRlayKSsYBMnmf6yEhv9AIFKoyOgDwWybVQpOZwCMNYVUxlVQnfckdA/leJg+6MDNkJk
         ePeXK1JLS1YOVRr6qiTCC6zvz3Ni3mryq4yWMovEuJrtHW/iuXs9dWaKygBNiz8wx8hl
         D6aBS0Q21luj4KHjSt3lNVdZlZkp3/h5xij3sBNsxALuewojg84s6lWMbnIrdBvVwbcN
         okDq4irYgyl8M729Q3Rjp/UMKLhRZ/BkkiZeKn49qderwe8HcWbu6H4uDpEcyJ9ktHKY
         /7wg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=g637eP12;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765887854; x=1766492654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JvzNlrcD2BSgRUsK3E4AA1HSOjBHaVyOpIxu02ZHVSc=;
        b=ALbk6p02QTsMgWghlHTuwCHQUU2oybir+ZbhhF3Q3JKr8rOzh76PpsrjWq1bxpzsWz
         qGLes6fcgdqk5bOm9jkNCUZSky/CoyAQil+hPx070T3k72q3B6xbTXBb5qp8OHZ/UB/p
         A1PjdpTnTuoz4mRo3Q4XGIrSDTKx9KgjrJUWqw7QANG35Ojinh+0Xp2qlOCT8U34TNli
         GLL56hIfvIM2xnlupBQZiBziKGYiu1SjYnBK1A75t31uotnTON29e5FFV5vDygR2gthb
         yvvudl+3PfMrgFeWu11b3ynmf7vlg+ogHcMHXaIBE58vXPkExBN5nUy/6+kXtuR7ntfV
         bHBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765887854; x=1766492654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JvzNlrcD2BSgRUsK3E4AA1HSOjBHaVyOpIxu02ZHVSc=;
        b=AjBSBJHkHirqBXkP7XhGCpxkrg8XLiq0RQUajjz+EAYOSFtIgwoYkFT3Ebkwhwwn2y
         01jMl+2P3mLcZMP8N7YWBYewUSdQCe8Q4dT0BNBnOU6SV6ov5381Si4f+2jrLdiGseCQ
         g11kr6D2VBrZX6IFBihk0Njqb7ZCAtjNV10EmT633XxHZEu4I6ZLjAZM/xbA/6V7AXio
         1JCn+RXWiO7K4dQ+AB2nE46TUpEn8jNa3Wt+KtK1mzpbHwhtfBUyWbnkhotAoyDjcz0d
         ZF1hsTDToLUEg3RxO0vkhWiV5lMIS0yEW7W3nHrTOJy8JWY8PXEhEDNPFoS2cLqFfo9n
         o8jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOHdusi/L9E40Mf55YiqLOGkmWGJKZdZvNIigALIXsI/isnBRtsfA9fqG37qTfZU6VlmdY4w==@lfdr.de
X-Gm-Message-State: AOJu0YysdL12MDHA8XtejMzGVTXaMDaHu9532OyF2YP2bTjBp9hTLmql
	PIRLhxgK4yL5bC4SQ2BUfqQbeQLVqnorIG427Ros00KuL0Brp92blpGe
X-Google-Smtp-Source: AGHT+IFW0hWwu/1cPCE7xUWhe8rlXrOcgkjBdHKIPlCiw+LnbPloIZObk4Jb5X0hawvuQQSpsq3G+Q==
X-Received: by 2002:a05:600c:c081:b0:477:94e3:8a96 with SMTP id 5b1f17b1804b1-47a90806ademr99054535e9.20.1765887854074;
        Tue, 16 Dec 2025 04:24:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZJufBbwdJsQRIG/kVqycA3xnHAPdmU8frpKzBOYBIcLg=="
Received: by 2002:a05:600c:3596:b0:475:c559:4e89 with SMTP id
 5b1f17b1804b1-47a8ec6a769ls39972985e9.2.-pod-prod-03-eu; Tue, 16 Dec 2025
 04:24:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVenImf3XyRk4ihLQVBgidUBHDdAt7KzQJJji1bJmUBCpEsuf4P3usVJOr/wY8NHJundImhDAlC6Lo=@googlegroups.com
X-Received: by 2002:a05:600c:8288:b0:477:a1a2:d829 with SMTP id 5b1f17b1804b1-47a8f8c0caamr137374285e9.13.1765887851019;
        Tue, 16 Dec 2025 04:24:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765887851; cv=none;
        d=google.com; s=arc-20240605;
        b=avgEfYW3OMubSXndjk3a6k6yE/i59fuKIs/fTPUkC3ODMSfgUMdgxm6449dvy6hpPg
         QhMcXKV4/EdR4By5DMHBCdUO2udF7+mr2FlcxphFt7JIvrH6mT0cCOiAJkxsZW2exs5k
         2HgdjnNQktqsInqZ63fMBboWOkUz9WTpGg1K+xf9FUgQVufqq3Gjw99Kl4lm7s8ExiUW
         nYZPn9+2uTgw66MHBjjOo98jq8kVEVF+lDDb/2jKtHsiDtonWLnAaPOYWr5bZQ7Dqyvc
         tYtb9OkfHAenT3kNBEVnLpbqTuVGGZmFrr5YfU08Huc5B6HE32Om9A+YPa9m6f8ujJvm
         5FdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lLRQaT+PfrlE09N+ydMoSz7Mn4llxrI8kjoKOroo6L4=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=JBakvvH9G4V3KYbTCGtZqJXRDbiSV/56JuiSSoYgqhESn/hRx4DmSWIx6rWBSpe0UJ
         TCeWCPc2KKQfhtZgdpCenv/VmzdCl2J9kFn323oI7AnGWQBuAzmpwj2ExaCOt5rW7phs
         WOi0/CyVBM6TwmmurS8R8o+DbCgAaqK0TM9eqjQawzOfCyyqKNJvvjFc1V7BBrmZkaO3
         JQliIrM6Z5rFkqnSx98fyAfipjulg2rEc3Ec2IIvXeQoFuziBKgUiuC9ndUiSiz4IcWW
         LgydUHKzLWw4N5tORi8HkQbxl6Hz2GkzhlBc2e6vM4P7WsXUVHF7GJkSS4U7vVWv/8dQ
         2iyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=g637eP12;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a8f6f93e3si278425e9.1.2025.12.16.04.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 04:24:10 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vVTES-00000004hkA-3IWl;
	Tue, 16 Dec 2025 11:28:44 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 60ABA300220; Tue, 16 Dec 2025 13:23:59 +0100 (CET)
Date: Tue, 16 Dec 2025 13:23:59 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
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
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
Message-ID: <20251216122359.GS3707837@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=g637eP12;
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

On Mon, Dec 15, 2025 at 04:53:18PM +0100, Marco Elver wrote:
> One observation from the rebase: Generally synchronization primitives
> do not change much and the annotations are relatively stable, but e.g.
> RCU & sched (latter is optional and depends on the sched-enablement
> patch) receive disproportionally more changes, and while new
> annotations required for v6.19-rc1 were trivial, it does require
> compiling with a Clang version that does produce the warnings to
> notice.

I have:

Debian clang version 22.0.0 (++20251023025710+3f47a7be1ae6-1~exp5)

I've not tried if that is new enough.

> While Clang 22-dev is being tested on CI, I doubt maintainers already
> use it, so it's possible we'll see some late warnings due to missing
> annotations when things hit -next. This might be an acceptable churn
> cost, if we think the outcome is worthwhile. Things should get better
> when Clang 22 is released properly, but until then things might be a
> little bumpy if there are large changes across the core
> synchronization primitives.

Yeah, we'll see how bad it gets, we can always disable it for
COMPILE_TEST or so for a while.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216122359.GS3707837%40noisy.programming.kicks-ass.net.
