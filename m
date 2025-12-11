Return-Path: <kasan-dev+bncBDBK55H2UQKRBJ655LEQMGQEAPUXNRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E51CB5AF2
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 12:44:41 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b70bca184ccsf81730266b.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 03:44:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765453481; cv=pass;
        d=google.com; s=arc-20240605;
        b=f4EPR60ewoMc4tIWmLT9M6gTJiq4jvmzp/6j5qDhlDXrTPLHWd9DINDLZGLb5Cqg1A
         3aZkebR2q/tpgu4+d58AdqFLkzJ9K0xtTmfLaC6oM6+En5QUw0WePxrf9teiwWCJ3BJO
         G6RsXYQEAdMWKZT/z22n/dD8aTeDQDAYi0IoJmoWH+znwcZ4B5YCP65ttQlmk/dr0F2V
         on/mftXu2DKsXge5Hi0w6MFtIgFeXolU/782WF6arrR2YEZFBNrYyeie9WfKZeBpFDBA
         kBqfRFi5rUM/m/q/fbHW0w4b4X3cmDnKZCZHU1ePH24eZIO6LJm/bCThB5uIN7Aom3K8
         LuPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GzXBL0FtKQsIDCnQYsO6L+I4Cg+OacB0k2XBHTrsXjA=;
        fh=mcJV8Rix+TWl4kofNglGlW+TrrQk27whpIy74YySXG8=;
        b=Aogo6kBjdMcAx0UexpbV25eH/k6vzfqfN4U5dkCx9fmJ12zpiLsB5WKPJA2rPBrN8e
         a8Kczs7F9r8wWL1iIspDOR0CylTxQpfxvgKc2S4FUsNnJZmSRaSYGGxUMLPRp5j7OlBd
         sNlJWDY2btUErqNl2a2gNDt3Mq1ArV74gYhCJGKjPxObAj/khp8wnChxneffauCSqvu+
         wnKZCKz+dtonL/CDwa6U0cLTHgmT3DMVx3+MmTqc3X1rBL2MdRFDpUhsvRmcypxPwoB6
         TtNHWFTj/TKC3vSGTbOi5lfmzqzkblMTWyvnh9iVtaNP9xcWNU7JGhBxvqR61mwzmR05
         zw/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uIJmfimn;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765453480; x=1766058280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GzXBL0FtKQsIDCnQYsO6L+I4Cg+OacB0k2XBHTrsXjA=;
        b=e0kGxrr1kWe4HyB8WV3ZkQrt3W8AFV4eVgjqKm13/hQPpotKSIPFomGSi/eU7p9jIu
         MeW5IyfH+9/rY+JyLACdNPBUWOaDnUccnTQTOLDYBtz9QvohIBCMzTX2pC7M2DIhfFEE
         wCJIEjASfoXnFSsOxJ9wQ4rarQ8wMYL2e8I6gxk5bbuPA6rY+OSA4/YTELr3SQL3ovWL
         W00IEfRe0KeLQs3NH/TV4O/9aGpMVrDVbaAExtHLniTqpCDErLQX9XLh60nCJsCLIZim
         VYZaFQrSQ5+w6CPAmP5CapEsYTZntFfpHseJmH1V8ItEElL9SZljlTh/sxX/97nSBXNA
         7aEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765453480; x=1766058280;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GzXBL0FtKQsIDCnQYsO6L+I4Cg+OacB0k2XBHTrsXjA=;
        b=gtD7QzHWTni/guD/JG75GZWATh8qZieJfDmRqp39+G10MNK/xkDh0LGc50u6yfOxP6
         Z8XbtYCbTpPohUuvjtIyfhMVkXzHW6SaMGD7c71wiMwpdk1wpqodRND/RXBlf2N+cq4p
         0WdzWNQa9Oj4F6YL7eORoW5s8ZlPLs7QPeQmkXAyUJ5uDcRRqZqzsuE1v1pPrO1XujI0
         PCKnqSnu3r8BZcCv7DwzL/lfmu3c2lvfFi0VbtogCUFPL00/iKXSXfvBZFfWllKZiRUU
         xVAmOhO26QEg9QUBihUMZjYwITEHQzh2qG/wCy+9Dfi3CI+nU3OLgl/ERMab8ataw9lg
         eFuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnPPv8vsXHIqn8FHB2MCE8aVclVAPngWGs4Cq5hMyNixlSqb2HV7D+cKxR0ENcouNvfHmSlg==@lfdr.de
X-Gm-Message-State: AOJu0YwtUc6y5XsiXZvTcPx0l48jEMnp8QOfYsdnQPq+6OsXFYcSvBg0
	6z6zfudwv2Za7v1o3BTPa56dKC3u5tRlNn8aHg9DGxT1tkf5EEuKDJhL
X-Google-Smtp-Source: AGHT+IHd1s1sCvUFzI/F0whKHNCiqz8ydltHtdNzNQlybkK2m7scE0A64EPU+fJflQPFbSHVuhu8BQ==
X-Received: by 2002:a17:907:3d92:b0:b73:7974:94d1 with SMTP id a640c23a62f3a-b7ce8414a71mr642892166b.36.1765453480509;
        Thu, 11 Dec 2025 03:44:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaEZtv5J6j7BkVKiuxtT5clk0/NpNLHgep89SKE/1BWsg=="
Received: by 2002:aa7:d38f:0:b0:647:a4b1:7993 with SMTP id 4fb4d7f45d1cf-64983bcc6cbls653280a12.1.-pod-prod-03-eu;
 Thu, 11 Dec 2025 03:44:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJBcqm/U/4xAd5j2Jjz0eJzALyp83sw3O4OFRw2Lj5kZDwN9+53HlBM12SqkipRYEe38eS+ZnL+zQ=@googlegroups.com
X-Received: by 2002:a17:907:d8b:b0:b7a:368:8776 with SMTP id a640c23a62f3a-b7ce82ddc5cmr593173966b.25.1765453477309;
        Thu, 11 Dec 2025 03:44:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765453477; cv=none;
        d=google.com; s=arc-20240605;
        b=Qycz7uW7glNZqfpsk6NiEfHEpLHPNTw7PzEDpgdQt7+2EnzdyQgYKLi69IFMLAxRor
         DuPBcUETBsqxpCuyOF3uGNI0FVDbvU2Acm41GDXZ5ZtYFBHoV18gVE7nsgDK8HHTMhU2
         OF2PBF0twBgoM8HZwzUho6Cfxja9WIOMLCxfvgV1NPv56As7GGG3fox9f0ChqvDEvWjz
         /GHZDQVEq3sI/tFqjDt5jRw1VTMNA8M2W5WpzleRIByZz6uCHpysMNu5RWoYMYZoK9FJ
         bf8E6p9INdILC4Ccu03JzEk3TaaKzx5v9fwaYW3xHbTdsx763CwPx2WwLxs+wv/d812M
         QWFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1Xyvz2EmetVTqNxA3ooND6KrVryVhRTmeDWJ7L8+Veo=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=FVf340YBhT0gFCnDkjzcLhxvPFgjpwwISiqqsACA/riLrNcSXx/nyxMI1eqh84e9PC
         FMyFXC57Jz3ZtAVqs+lylG5fqHbpmVRCeBicPct82Cz3FmqhBeKw6yoE9qbxKpTOZ1DE
         oPNz3/0f5rTvtyXY/afNSwcM0Bu9U8BDbzTQiKyz+F/WudLKytD195pJdjhjYMNsQBCE
         F2CBIhr4pYwbpS2bKSg2SksuQKuFU0T5KD5NRh78xktLx08rFNcl2ANyuYxji4LNw2O3
         l2OOzkX01JpZvQKPiMwBP1KserCEoxS8gBDKNI0A3FRff6ncEv2hNsl6tG0LyK09tLG9
         Owiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uIJmfimn;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b7cfa284bfdsi3376566b.1.2025.12.11.03.44.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 03:44:37 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTf60-0000000EBKA-0bcG;
	Thu, 11 Dec 2025 11:44:32 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id AF7D630301A; Thu, 11 Dec 2025 12:44:31 +0100 (CET)
Date: Thu, 11 Dec 2025 12:44:31 +0100
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
Message-ID: <20251211114431.GD3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120145835.3833031-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120145835.3833031-4-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=uIJmfimn;
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

On Thu, Nov 20, 2025 at 03:49:04PM +0100, Marco Elver wrote:
> +/**
> + * __guarded_by - struct member and globals attribute, declares variable
> + *                only accessible within active context
> + *
> + * Declares that the struct member or global variable is only accessible within
> + * the context entered by the given context guard. Read operations on the data
> + * require shared access, while write operations require exclusive access.
> + *
> + * .. code-block:: c
> + *
> + *	struct some_state {
> + *		spinlock_t lock;
> + *		long counter __guarded_by(&lock);
> + *	};
> + */
> +# define __guarded_by(...)		__attribute__((guarded_by(__VA_ARGS__)))

I must express pure hatred for this '.. code-block:: c' thing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211114431.GD3911114%40noisy.programming.kicks-ass.net.
