Return-Path: <kasan-dev+bncBDBK55H2UQKRBFWC57EQMGQEPH3OXIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9034CB879A
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 10:32:07 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47918084ac1sf12388935e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 01:32:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765531927; cv=pass;
        d=google.com; s=arc-20240605;
        b=cR7FGeI/FCsHynysmN8IrPmpdqRI6CZqKvtyiqvLc4LeuELuMCJrYVL+ZcVj0SRnx3
         RQaI5Y93981eD1XW97b53tkSSoy/JjCwyBiFnRuBTr4JP7bEvFkimQbFg2SJ7WOuS/L0
         uRXL11wVtIPIfFRjWt1VVl9f+Yis81us5cgEKQ1OUyktDoF01Q+1h0DIhla3j8BwFPpC
         7WojGjCXwrDlEdqSeeezDt/WtUzpF+E1IKQ73MkK0nQi2lS3PohxdD4FYySiaHZ6ti+e
         iyU+a7DjnT8+ItvElCSzqhF8AIDX8iX5QxB3EDrJLM9GCD+9XcBDsGikcpxYOLMz6DNB
         Fuxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LKXvjT2IWP4ijAIYgAIuI+4miiPJrEvB/6nLuLkiOpY=;
        fh=PZxcL+yY3yuwoZW3UiSKQqP97pnCPl7C/nGfWQ4JV0w=;
        b=C1vjnvQDcSnib3+OuJtlt2DiQMrOlB0/rca+Hy2Iwh0SXf6Z4Ek6fsE60NqRkqgf/v
         g6mZAAlnl5rUKpjob2SYd2SGoVxdJ++FaFtfgBvaFM53beWFi6bMsLU9GxhwFPOvXGrS
         qMg19ouvLXr3MDAftao8r+Z2i6oNr3J2Y9ogqaJfbuf8nVqYWI5N+kUpiUki7VafbZ1b
         /dKq1yR1SF5Lrm1XqUiy/YpPx4ESdZ9QMhZY0od1DHQl7RNEHH+w4BO1EBZT+ng06clm
         9KsU5qoUz/I8yjBDdOcInwyJG6HXVwZcvPILoTTrMeUs+TfvBZx2I1Quj8gWENj2OApv
         sVBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=DMpgfaqC;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765531927; x=1766136727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LKXvjT2IWP4ijAIYgAIuI+4miiPJrEvB/6nLuLkiOpY=;
        b=I9CCzuzCkUAl3GbDCwQD6BX6q1SosGM7+3W63KMfxEL+neV06qqm1SUc/XRWETHp2s
         QeEO3yuyX3KD9kBN1PQmsCSVXghO0lVJLb5sKf2E/OeUPXXdgOSxI/c+86vS/sn+i+tx
         yQGiGl8xAtRYJAJmO5eg3P3hi8EMR3Ucz93AHScT7H4io2m6ZwUtG7YlgeylF/c6h98k
         oZlRyrThWtnBvYEjL9cC2CbtGd5d9eN86t2G9vmULtFAOQd4/M9RnD7/XQKg8E4spA15
         Lr/Hqeq7SQjUcXCLW2Lm7KCl1gYuk3xP8D2p3NefXLiJYbM6Iaxdn1ozcIJGWjFe+qEc
         gLjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765531927; x=1766136727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LKXvjT2IWP4ijAIYgAIuI+4miiPJrEvB/6nLuLkiOpY=;
        b=V7Ylnd4ulzCGukyw/oVRY6AL5wnPXXMA60z+NhjAUvc3EABonEKLetXS3ffmHX5gzQ
         2vOk0sjb1oPw9TTRzvWLmskVfo1romVECl4mRWAgb3sGi7kljzIrctGOOwNhTGPdNA94
         o1tbXYNiRa8uBiIW+ohNatDBk+HyYWCXAlDp2XaesU2mUws+WrDryr/eA2j8to6wJdGZ
         SeygbVA8bcJvvWSLoxEdkD3dDu9W4EsSqO149f9+cEb3n3Evj6bpiOsWP9KXh2k8N2u8
         G6gBlVu5e2Bx7uY7NfjyZbF7/NgtU+RSbLi+wRLuV/bcXmtI0gu7hF3yMdY+R+BKcMm1
         81wA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUau3RzWYY3GMvFj4kam9ktV9d+GcEYTyKp4mWu79gvA+domYnlIBdme3jdvUyDKXJsOvN5aQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjZxgLNanTlaiqaxFwk2Qem84tUuRr3Se9+8oSvWZig7AQJ/Ou
	6f7E6ztGWnsP+B/mX/wXHtjBbAfsVzb2lD8gRRerTggRQxlCt9hpBRIK
X-Google-Smtp-Source: AGHT+IEfsX3hE13snGxkTt7jj0FNieB3wDm6NJall4Oj/Beuia4NiqhtXHXc7vM4q8A7J9AB2wmOsA==
X-Received: by 2002:a05:600c:83cd:b0:477:7af8:c8ad with SMTP id 5b1f17b1804b1-47a8f90eed3mr14533775e9.31.1765531926870;
        Fri, 12 Dec 2025 01:32:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaDvkESKijZev6EP1VelRh424Mq7x4ZX4gZJltV9QMZdQ=="
Received: by 2002:a05:600c:35d2:b0:477:a293:e143 with SMTP id
 5b1f17b1804b1-47a8ea603c2ls3791435e9.1.-pod-prod-06-eu; Fri, 12 Dec 2025
 01:32:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV35qC3IQ+yMTGZrLRDmeUmQs/lpWX8ITnSBFaza/m5zKdcg0alJzLeJgg0SXlP8K6EZBu8d+TbLG0=@googlegroups.com
X-Received: by 2002:a05:600c:1ca4:b0:46e:4a13:e6c6 with SMTP id 5b1f17b1804b1-47a8f9064f9mr15683235e9.19.1765531923820;
        Fri, 12 Dec 2025 01:32:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765531923; cv=none;
        d=google.com; s=arc-20240605;
        b=TSMpc3XUCL2WbbAaUG85AFBHL1iqGDLwKbIBSeSFqX5DqBPrsTgIty0VDdlru+134b
         w9VFFr8Z4A5rLb3P4ZfDUqJDiPUz1MbfVD8nDN65lohCjSfa2aq7oiMOBGIySCzeWB9N
         TTnJ/hiUbij+88VyU/2MTd1bMKMnOjpO9JehPs0Yi1KkrBAptjkD7NkdjC0wgY2AqWof
         FG2lzhy8f561WpxeAkZ/cI3q6JC37LoddfVGdENconTJ2jTczUkc9MOZ1mUgHUn71tTj
         YBjsSs16XXhdnvKlwbaLRzK8MQAgehF0cYy9bTBswdsihF4Bl6GRcxzERCkOIKG1Hax0
         pjXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7N1yRupjJwsCEjdeUujuXdzSn7k5Mwr4a3y236fW66U=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=VWs7Zv5NJ+C9nltTjbkszFofRfOPmxO5sl56PBrerLqRkfVil7PwXoPHDxI2hjAOjx
         pVAFqBE2q9bsVxkpvEHfLgEJW8l4UMhit8th8NXlmrb6zWksbqXXOM6ibYUGdCLve/32
         Kh8aEa5vBb6p4BLl8tLsJtJaQI9CJBMHsSoHn1HYPjfVARkh7ZanYiYBXRzA7wSX9ED5
         t9xpmFFUgT2pEqWLba3W+M94/V64VLSpwlWMaJE9oRfvg+IknwSR3MnopOsflOIYzrbd
         QnI/5ktXJ6WkYQS4V57H4Mof5FT1bPuOKD0hrpdQojKuPpLU4wXj6iXwvwtf3PgHiNXm
         tWjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=DMpgfaqC;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a8f3a22bcsi59775e9.1.2025.12.12.01.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 01:32:03 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTyde-0000000GP06-2F8E;
	Fri, 12 Dec 2025 08:36:34 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8C24F30041D; Fri, 12 Dec 2025 10:31:49 +0100 (CET)
Date: Fri, 12 Dec 2025 10:31:49 +0100
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
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
Message-ID: <20251212093149.GJ3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120145835.3833031-4-elver@google.com>
 <20251211120441.GG3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOyDW7-G5Op5nw722ecPEv=Ys5TPbJnVBB1_WGiM2LeWQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOyDW7-G5Op5nw722ecPEv=Ys5TPbJnVBB1_WGiM2LeWQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=DMpgfaqC;
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

On Thu, Dec 11, 2025 at 02:12:19PM +0100, Marco Elver wrote:

> What's a better name?

That must be the hardest question in programming; screw this P-vs-NP
debate :-)

> context_lock_struct -> and call it "context lock" rather than "context
> guard"; it might work also for things like RCU, PREEMPT, BH, etc. that
> aren't normal "locks", but could claim they are "context locks".
> 
> context_handle_struct -> "context handle" ...

Both work for me I suppose, although I think I have a slight preference
to the former: 'context_lock_struct'.

One other possibility is wrapping things like so:

#define define_context_struct(name) ... // the big thing

#define define_lock_struct(name) define_context_struct(name)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251212093149.GJ3911114%40noisy.programming.kicks-ass.net.
