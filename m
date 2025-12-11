Return-Path: <kasan-dev+bncBDBK55H2UQKRBR7M5LEQMGQEM3N5JHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 776ABCB5C4F
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 13:17:35 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37a492a537dsf92231fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 04:17:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765455432; cv=pass;
        d=google.com; s=arc-20240605;
        b=WXeJaX9hCx/lmOzSdHwQXwMRBrNmh+XTaMe7BnKgaN/cYn+8tEw9kxZwmLhp0lN/lc
         FsIZkIM1/CCirzZ/v2YZegE2c3syvuwjzW4D388UHWxRnHm9i24nIeZwiQaxowfZT7gZ
         0XMkIoqoX+CtONZ56IPTXHHnsNRASvpL99cPrC0cNVe1yEdwAarrb3Eg1llIjw9G2cxQ
         wFv5k4WLQHCPNMCKrDCUhhCh9djNWY1OP5hpvOYnZN7mxediOXWgFfnwBAcmgTni2ng1
         FpS9B4rP+Cl55xE2VYdKttiH1+jdy/qA6Ha0tZshGk9rXWPcmsmdMdjPlCpFWD676f9l
         avfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8HnnGklhxswM6vZedKel+dB3qJxpCUnoI3jHRXgbVuc=;
        fh=bFz2oNipw9OQoIZQMJVu+lxAWAqj26Yp6qS9VBzoB5o=;
        b=YdwbEVi4O6bGpoqZ68omPbYI0K7JM5WmougZ9ZQpv2HID3jEgQCC1hJMx6xRLHRaqa
         yd3KKogQH8nCagAOCP5/vXV3n9Pnq5qXW3CjYjGze2Err0MHVa/7iIqbLA6J1a9Ptvds
         mGH1veH2SaHwM0WniJg4OSHhp7brp9u5k+d9RKJSMAXRMmOeQjWJ4pCKxfI94h+scsLc
         U+1YeU+3DTLJZVCc/gDU6ISfr0md4tAiH7kOmhpSCUq7M/zQD1zIgDUMRlFcVjzYyP5z
         2ftnhB7IIjjmT8ZKTwVaQxgd9Wti7Z8e43aLD/eainZzyT0YbtQxM3uCHq+xB/wPNHpX
         IGYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JQUFeVK9;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765455432; x=1766060232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8HnnGklhxswM6vZedKel+dB3qJxpCUnoI3jHRXgbVuc=;
        b=wQ+v2xC5d6LdvhtC4PrZl5MahpQOdS4RhMvPUbG2MJsVh+/Q7v07WK9zvQ9dsuMMeU
         ANxAa3/poynxePQ9OsS4DI+36jFZNlfRDZH714KRIJUElSBbz3LU874yCb7sdfbM8LvW
         YnkyUcmpXqYgQ+4vybV5EbhF8j+jOqWC/VW7E39fm9NNpNCV5wlAti4zLDYNVN30XQyN
         qPXMB85oUX4j2GaC1HF+Y/fEnzHyp1C3lBvFUypfWjs0Prx6V8i6JKUcY+oK4K902cmW
         MpIApZY1vcjL87jj6JOAYepX+z7G9k6RajzF9W/gXJtsAcBHm+zcRHguwsIosTNL5Mdr
         9tcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765455432; x=1766060232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8HnnGklhxswM6vZedKel+dB3qJxpCUnoI3jHRXgbVuc=;
        b=fCJtBFMJuCIV7NkwtihnVrkKglBMHh9hUq+31jTRNDRtIw1dRXwY0kb2RVnUoWuu/l
         FovASmuw+KxWi3EtvvAMcbrPHo25gklUpMPB252bFNLLfFZh4GYnniLOW51zQ2oqenCP
         l0E3BvkFMRcrs2ladOSKILII5hQrqkkaTbcZVlBn1Lyb6XbOVZ3hwGAFQhaCw47pygcL
         n9XvW04gsS+ABDUoIXqXnmMsvAfaUOK/Z9Du6cOHkbpVm9Vmz9Lzm8cMMZsXjeujKYlB
         SAhbYYh5IU9vH8a3gAWJBUnytmLF6ejr2Kqr221eRkPSKM27eXuNz+/7GWGgswoE4kpx
         91gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcQczPbVPTrVIbc9q8YqTsRm8liXR29uYeaMFaPHBsxMaIeJsy+Gq3d8coxfvUNKsymS40Hw==@lfdr.de
X-Gm-Message-State: AOJu0YzJt+B+daIppfhw3SFoA04K7LkCMcCgjuGsnLQjrh/BIOMuIi5X
	zaDVojowecrE16WPO2fICHI4N9jBgJEmHeidCsBQI8q0ClY6OUymIG1h
X-Google-Smtp-Source: AGHT+IE/TQhnL0LYzB64/sHyH3iMmogfVh0BS0M6VeJqqW1PpntaygLsgq5fC6Rvrz4n5GSbIdFuvQ==
X-Received: by 2002:a05:651c:31cf:b0:356:7e6f:c66b with SMTP id 38308e7fff4ca-37fb208bdf2mr17523091fa.38.1765455432535;
        Thu, 11 Dec 2025 04:17:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZZ0EVs5FWUNL82YdEnAH8nyQGXaYRsFD4O+JufnyZd6Q=="
Received: by 2002:a2e:96c6:0:b0:37f:b4e0:a50c with SMTP id 38308e7fff4ca-37fbc8168b0ls1377061fa.0.-pod-prod-03-eu;
 Thu, 11 Dec 2025 04:17:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWo+ah99KAvdrVoCHe+/oVeXLj2TpDAwkYnXK0KyuV2lFgR6qzgGG6LWFWK/ia/mV2UkxmtTgvy/m0=@googlegroups.com
X-Received: by 2002:a05:6512:3050:b0:593:1383:7945 with SMTP id 2adb3069b0e04-598ee46eddamr2255362e87.20.1765455429072;
        Thu, 11 Dec 2025 04:17:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765455429; cv=none;
        d=google.com; s=arc-20240605;
        b=jd8ww7siL1izH/2uuw5uyOsgv8+MOWn027Yikkfqtg8BEpCPpRQftFH+6t8hdxOkSl
         eos1uav6khY1eg5KU1+oFt2fmFrr0anfz3Nj7ddza/SeOFuB26a5eW5mgqDCAt4ZlvBF
         vJzpKVqpPmZTCMJFjXoEGHgxtYdiGuGAvWkHcALSGunGLrmZgQm78rUD3D0LxGwXLuIW
         q9PUJpwawPEDrlIk1BRueOWAQzIxJq4bYsHPwpiiwS9ztOpxQ9PcAxNsYF+XCL46FiJ+
         TIDAL9JDMZb4Q/v5EyaQqpqunrmisHWmtN+w8donOGPAbLDVLautX+rZMk3mK9Nr+bHF
         Faqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=39KoR5/fOj3fCtjlvg+DfDvWOhyBBWrm+m1GgO5bCLU=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=Zq5f8mAdvxPQHCvY9+jr5LgXu41OY9lwZgZnni0lEUEiAJUv+0fUVet0xkc78wd1/p
         Ie24MZ1c3Y8m+2Ob/UuQI5+dsm6a2HnLYjAbijtQcsaTfce8ybKZYObq3qZIV2f5LqXN
         zHNLr4Me0PTPPO1hYqgU7D0eyoc0pSpvSYbLxvjXRhGAFLoNoKUrbEjGTyrjcxhQFLVc
         dR4/xWKIiDAgiCD2H3L3TqGZVXrMC3kLVe+doJ7x1SKdPZ98vPsPCo4+SeTRPyiHr7mH
         9Lm6l7s6bxnXlNNp8t5T21GIrddkEbC2hFl1UjG6kcUGfz09mhizuldFAfb6ZDSa4Cqc
         6bNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JQUFeVK9;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2f736c4si55820e87.5.2025.12.11.04.17.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 04:17:09 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTeju-0000000Et79-48aq;
	Thu, 11 Dec 2025 11:21:43 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 87A0730301A; Thu, 11 Dec 2025 13:16:59 +0100 (CET)
Date: Thu, 11 Dec 2025 13:16:59 +0100
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
Message-ID: <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=JQUFeVK9;
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

On Thu, Nov 20, 2025 at 04:09:31PM +0100, Marco Elver wrote:
> Introduce basic compatibility with cleanup.h infrastructure: introduce
> DECLARE_LOCK_GUARD_*_ATTRS() helpers to add attributes to constructors
> and destructors respectively.
> 
> Note: Due to the scoped cleanup helpers used for lock guards wrapping
> acquire and release around their own constructors/destructors that store
> pointers to the passed locks in a separate struct, we currently cannot
> accurately annotate *destructors* which lock was released. While it's
> possible to annotate the constructor to say which lock was acquired,
> that alone would result in false positives claiming the lock was not
> released on function return.
> 
> Instead, to avoid false positives, we can claim that the constructor
> "assumes" that the taken lock is held via __assumes_ctx_guard().

What is the scope of this __assumes_ctx stuff? The way it is used in the
lock initializes seems to suggest it escapes scope. But then something
like:

	scoped_guard (mutex, &foo) {
		...
	}
	// context analysis would still assume foo held

is somewhat sub-optimal, no?

> Better support for Linux's scoped guard design could be added in
> future if deemed critical.

I would think so, per the above I don't think this is 'right'.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211121659.GH3911114%40noisy.programming.kicks-ass.net.
