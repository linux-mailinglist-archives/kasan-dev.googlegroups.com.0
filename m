Return-Path: <kasan-dev+bncBDBK55H2UQKRBF45TS7AMGQE3BDJXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 82D3BA4E0EA
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 15:30:48 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3910034500esf1328652f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 06:30:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741098648; cv=pass;
        d=google.com; s=arc-20240605;
        b=J3UHgl/0SvsQnbuffsWb1r8rdsSCmCLoKjqvOL8IJO2CtHNFe1CVQCzeyHREMv6tua
         XriT8iIQ4ga49bwmN6KTgtOI7WHnzA3ygxiqTZcJ2Z+T+W6fMuP/zNW3E5qPHVkd0v8M
         lr2VrM75DpWjuCLRFkJztAKrl2pd0mhRPuJqS9z62/ijeq504nw5/FjDw4Aff9GScCQU
         PBmsM7IU4GmlwnOGClPMNvgbZJa1/muYm/iSbzYXueBsIao8aVfqaYWUX7X5RwfPPEGC
         T606gIKw9Qhz4t9K3PNaZfUZzQgINaNiBPXsp2ay75QeZZipvggQFuZ1vUDwFIRAY3Qo
         oIJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zLkcJDWdOzm+lHOJ3zlX3BAK9yfe/UoMC3Ueo/uQv7Y=;
        fh=GfjLf9yskV94T3o9Lrlb9K58jDEdTF2Ylw4KIpNmPsk=;
        b=PWLsr+VpHafrLOz8Ozd+XKtPICi7OTKPDkZjE4eSSafABE+r7qZWkzWpX8yhRxv0v1
         loq0AvfjeelSGK04h8dGORU8Cz2qDFdWxHn3X58UbUBy5UsXkdVur72Etm+a6J1b6frZ
         AJZuRzPe4/cfaPIEOe59BZVmKvxMbvN1SM5s9r9CgQnC408Kp5zbZ8AjFfmKhW7b+ZMs
         VgZoJgPKj6161IZvJFsjV/BHfS5r+VoxaijHTV9pDmKy3Gaw52nlfPA5eg3PdvWYGn9b
         N6LPYanK43/em9hmJ2bUsaMFRw9TV4gnGWn2qUVPcxi1rX8ig0OUByFLVYNkT/jE2vxL
         zfzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=O6A3Q3iA;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741098648; x=1741703448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLkcJDWdOzm+lHOJ3zlX3BAK9yfe/UoMC3Ueo/uQv7Y=;
        b=mvPAQ/O/TYeez1+n4WmT48TjQxZJG3RWlbl2cr0ICu4TrFYZfc10HY4k63UZn8lqVu
         C+u9mr0KegtXW7gaGEGicY2BR1xr5dgy8tTZgQEdHzPf6hjSsz1AQuIl23vPeYiIiIaK
         wbcxHhX2gX5yNvS/iIuvlERa2j7PdiOC3My6pn8KrlnP4cyo/wsl3ztqnrO2rOhGhMBI
         CqCkgtwjVWE0Pz8Ku5tkp9Temmnx3X8qh8EdA664rKQF5wSSxy4DuMdUnUIbXx1PgLkM
         7oWryhQ2F005knMNxN0XB9pS4xKav4TiDlMLvux2vMOlNItHF6AQRCFGvenCTapvECi4
         AGMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741098648; x=1741703448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLkcJDWdOzm+lHOJ3zlX3BAK9yfe/UoMC3Ueo/uQv7Y=;
        b=dZxbgQSc9bvQRzM32zi7AvHVlQHtG/VTWfFs4nFw6FAQ6PpJinkEEiXUKsKakGYjW7
         m1aiPRiCI99/YcEVfqj5KjU9uImAqFX4RZGfcKBL2l3dK9zpj+Hk/Knh3RU8ep39nhWe
         X5gte3PmWgKQNsW1C+R7QC8XQ9173EuEcHXZzPOEZTnTdSMAdgMabDcMD+LA0A2D4hBe
         qdufY/vKXq9rm++wHRc7K/PbGpel8SiTByGqDxUgpoWyzryZFEdHoorgk5aNsLSBLIjx
         8YCuDC5PzuGrCIl5zc2c3xpVrvDhNgc95aX2Td4oNVhweKCkpCucWmZt+b5+Byv87MZK
         wzrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwHV6NHBVb/HRR+xEIjjsguOTTM58CQxG93sdOGh8QvAFRGrSCXmqB6dSnIO7ItU+8BJxPfQ==@lfdr.de
X-Gm-Message-State: AOJu0YwZ30TMSlLxuywSYvivacGjGu/VdMs3I3viWQ9l6nuNyHxVMtF+
	OlRCTAlNpLDgkVc8kKdzaqM7tfBpkd4wVyjmeBEoD3hfmwtVXUBE
X-Google-Smtp-Source: AGHT+IGW5yISOmpuP6K9CgZzIV2RpiMNOCzwok1GS1kkhMZ/Ma+Etdrc7ITakkhFe3zNLTH1jhr97w==
X-Received: by 2002:a5d:47c3:0:b0:38f:48ee:ddc2 with SMTP id ffacd0b85a97d-390eca47db0mr14804589f8f.37.1741098647431;
        Tue, 04 Mar 2025 06:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEskVNt7/Ye4WAQWVke3cf3afJWfOPQf4COSBzJsQSTXA==
Received: by 2002:a05:600c:2e08:b0:43b:cad1:8b54 with SMTP id
 5b1f17b1804b1-43bcad18c33ls4012135e9.0.-pod-prod-08-eu; Tue, 04 Mar 2025
 06:30:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5kGuHeFZjoogFc+R6LrJtEiI855R5xkHgd4Y1H+Km5gf1LRbg44xSWHgtRlZYWvJANnfo44+WsIU=@googlegroups.com
X-Received: by 2002:a05:600c:358a:b0:43b:c0fa:f9e4 with SMTP id 5b1f17b1804b1-43bc0faff90mr68285925e9.13.1741098644992;
        Tue, 04 Mar 2025 06:30:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741098644; cv=none;
        d=google.com; s=arc-20240605;
        b=dibqAZjdcJnevZtiKvMluJMxKtR0I8GAAj1IH6qK951+F8BTAoaYbwsAhT2/7+dCsh
         k2W8WgvCsTGuZZQINSvWm+CoSaie5OPLlCrV8cgvZDOj8ufRUrk3tD3aYR+JWVmIDUM5
         NUJ89zuv311ewjEzx75gRZrOYyCofbDvxYZRDkGy4IOBH2uNRcnhkdLxzZxGddVTT3+R
         AN9RMDxCjuAWyplH/nWkNu4D0htWipAq/l5Nv+at+zOVRlbrz30PNvXPjdRdjJAxslcO
         70T5ODY0oOUEO7iuWdOkc8H4yv+G4WP9OyzjZSwXvkkaC3A4650EFQa91p4jhNhoULXQ
         3QoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9VvfiKn9vnthqkbug7Ck5fZJaYFPZHMHw0rvMhQVYiM=;
        fh=7TaygT2PzvUByhK1cv83Q8e6MDKw7N3itZdt4LeniwY=;
        b=Mb74GKSGJw5EELOcwgpzy54HBJ7KVUC6vJSzTYmqKQKDtY69M5ZmV/dvFHMOBuau1n
         pm4u2DDRHNSUBQyBeP8m4P0ha+07S+sF4rarRKYxLXPowkLfgDWN5IrlIHC/B9RUwvzJ
         wjx/M0J/tcJ4R0FxtxVfLbp6cKpN2ikerKBHz196+kP2gkxPwPIT2RquoAwpMRpPxsqr
         rhk2aFhRp7K+DvJ5qBE07mFydi7doyHFYZSjnO5KFYx9PC5ChfxsT3ndiF87J/XP5lnN
         WGL9SRlknWQuRnHRYbwKNntv4oDFvW173Mofj3RJHi/EbLV9PX5WzkDZD1RKTfntRw+t
         WqJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=O6A3Q3iA;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcce9536bsi410545e9.2.2025.03.04.06.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Mar 2025 06:30:44 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tpTHx-0000000037U-3a7E;
	Tue, 04 Mar 2025 14:30:30 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5D27A30049D; Tue,  4 Mar 2025 15:30:29 +0100 (CET)
Date: Tue, 4 Mar 2025 15:30:29 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 08/34] locking/rwlock, spinlock: Support Clang's
 capability analysis
Message-ID: <20250304143029.GG11590@noisy.programming.kicks-ass.net>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250304092417.2873893-9-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=O6A3Q3iA;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Mar 04, 2025 at 10:21:07AM +0100, Marco Elver wrote:

> To avoid warnings in constructors, the initialization functions mark a
> capability as acquired when initialized before guarded variables.

Right, took me a bit, but OMG that's a horrific hack :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304143029.GG11590%40noisy.programming.kicks-ass.net.
