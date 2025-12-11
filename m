Return-Path: <kasan-dev+bncBDBK55H2UQKRBVXA5LEQMGQEKARUCFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF1D3CB5B38
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 12:51:51 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-477b8a667bcsf10739765e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 03:51:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765453911; cv=pass;
        d=google.com; s=arc-20240605;
        b=KaV4Y6ByxQY2Ra3xK2dodDJQoTmixfM1zTOeE4R40LAoXwxUX4HI+ukdEMQdZmzVMD
         71IPZW+6U+zFojEJ4Tbwlj+/frm0poO2uXtJJ1XMtJUrzIIZzdawkFIT+fwBp59ecEYa
         RX7k0aO0us1Qd4Mo7B1eFiC90turOIPfXfvcru6gmr6nN5JNVk6LFJbyoqUDMzIz3TyN
         XEXr7wmjZhgJ8Nd54g0wwQowcxKchocefTZFKme138qjMuwuIl06v47o8WOf7BC5ilOy
         W+sd973FOyaOmgS8geD9Cl8KiZiy7DH+E8j8P/NtFl1GfwdbKytOXAjQ98uKQkQRUAKy
         zOOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9Gob4DuhXdkEGSZG9S9cSPPO9LcaIVU6dSmFwz4Pg7w=;
        fh=JQqSk7P2FF/1A0Cbb7NMkuz4CrBdyxSURNOj016AMgo=;
        b=UGtvQcxPbZuX5FhJwoWrDo10tcAkAwwDhvDJ4cTdzRZtKykM/yMXp0Z2wekbHzCgbn
         E5BH+WPpR+v8n8GzW85OnNBVXAjRVLEP+FG1E8xPiS8MBtskNAcN0W64WWc0W/jf8oFX
         48vN3zj0zblVq1uUEwuPyOjlCRmAp+K/l3HRsSzw2XMHfHLIlAfMQzDcuXcE1AJXx75h
         Xi3sVPsdQA+F6UmdWpaV0TY7kKn02u+RuxiJEXlvZ09oTA/Iw2/Rv5icU2Cn9VXI3caU
         Ldnmiu1JleXnTc63q7/Kj/b3PgSRoUTJM6jd7fLUgOOj5Ob+YQhfuGoVui5DaZaQmsM3
         eidA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YCtHfTx7;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765453911; x=1766058711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Gob4DuhXdkEGSZG9S9cSPPO9LcaIVU6dSmFwz4Pg7w=;
        b=mtzcqGRX2EafyiKLC2m2LoeVqhFrCILhA4OrzG5SUpLmQQwLCR7b4ZF/Va4jwjAHDA
         cf/rgVWwi3BX+G9XuakrvrpPtkX+YdVHRfQ5OTt9MXySHQHq9yzs+RrcIBTBxnRTb0nv
         Fa2/CpX7rdQci6WdFMFkkg7kZn4Bire1676RyAEdqUhO0PUOK5xX5PMmZIwULSozvs/w
         a2uJPlXsv89NZ2rvL5Yr5RXNEE7Na3Qwq99fgT6Taev9I6kJMTJqCv7hr3s73EYxX2Gz
         3pRmGyiCLwFse92knnODgOKn1W5+gUh7kKP6KBwGia5lMS5UBCa0eO8+vRhYajXPDPTA
         PxnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765453911; x=1766058711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Gob4DuhXdkEGSZG9S9cSPPO9LcaIVU6dSmFwz4Pg7w=;
        b=g2emWQQTch/335ytXEoQ9cReDG6jp8FQ3IypVpzkZk5xoQXOuzybTcH5WgA38UR89A
         9kgJM2h3EeYRXEbUEyUmO6jwPanoO3qC/VB79C5MqdLtTk5ShMWL4xBlD55IpNCud/Qw
         lOTYBCXRZuP/Axu8VMoPiAKthkp5w68m2LU0AZdcvYcYIsv8DPzs6DJ45fW+X8uoMivT
         GY7DyagPTn4Kdyg+PvjFE/NOb6lomHlIQqkhLdaPs4HAT7jvTAP76I+GOrLr3nzC3/lM
         Ko59xx+D8gPXQ8lJnyu0zdb82nBvkMhEPaPrQXvmeGPUJO9ocNGt8yZXA3HU1LMFQ3O1
         m7hw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLjojxuW+QOQYL4OPtftxdEPHe8aZbIQ3UxqwXtE6KRLDpKZZ1YWR9FYl18t4Yf4G5syIGDg==@lfdr.de
X-Gm-Message-State: AOJu0YxnEF7saU30CsPZT1/twpv+T/Z+Z7rFjMk+LCLI1rVd8c/qILIq
	Qw7ztbpMV0GSVwmLp7CFm3h0KlbL8yjaZDnCVA5UYNESiaSNr8PQIlsK
X-Google-Smtp-Source: AGHT+IHi7kVherJsKg1eiqubJf2PspbD93zKMm4E0n4triahnDyAXRlXpmtq2JASyJkEkwp07HyJWw==
X-Received: by 2002:a05:600c:558e:b0:477:af8d:203a with SMTP id 5b1f17b1804b1-47a84b6f628mr37189445e9.27.1765453910958;
        Thu, 11 Dec 2025 03:51:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaWabaa5ttRo6Bv+XWsAzVFi3AZHaH3dXbYWSdRM3Sb/A=="
Received: by 2002:a05:600c:310b:b0:477:a036:8e80 with SMTP id
 5b1f17b1804b1-47a88922dbbls4858525e9.0.-pod-prod-07-eu; Thu, 11 Dec 2025
 03:51:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUw+aghhP67YCLqJ6fpFee2Vwj3tRrp00L+X2PTcKSPFH0cH2kN9f/weyNnhzOUNURaOmBTlVCtCbs=@googlegroups.com
X-Received: by 2002:a05:600c:310a:b0:477:9fcf:3fe3 with SMTP id 5b1f17b1804b1-47a835ca1ccmr53040715e9.0.1765453907644;
        Thu, 11 Dec 2025 03:51:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765453907; cv=none;
        d=google.com; s=arc-20240605;
        b=YyR2NeNBigGDVWHAMLf0Pl11mfUv/kbvpSG2OPpZOlE3tTTuQ6EUyg0O64IheR07Qs
         vjcVA6k/KkyRyWLXAju6+a4qJMzzleDcNeWUq2LHn37kTNv+AFS2xl7yUTuh8hfyC0GP
         kWvFHoSIs4FPsFHIQQrNjSSXH6sCNXKcERtFgTCvqLdkikXo4EVoCKGjP0WTidzeLQg5
         9PMDY13LxOL8Lm9PFGwSUDDOWAWrINcZlusQfALPEB5LaMDe8qfGnbfaXspyvJV3hdgn
         GC9t5ZmzCOe7uG999UufalYPNZ71+K8RMOD8stm/CG8DGS6LCK0vEy8OUeKQsfcAFMZo
         PIcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+ruouxJOUh2d+f+e8HHYpqnGoZEuPo3luh7bn7bAHeI=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=L3oyu5mXYie5F8E7cvc2Mf3EOzor3/I3RjLJwdG3FvMxWYm6e1I0lGXjav6PnrIH8a
         GUEAAv4/fI2OBl0f9z/ar90u+Cksjsz7czSvfon8piW6Ovb46RfYtEYgg9yzAitcqKkp
         ekPGowbm9UxorEqLuQQiNSu65XqzbebjaoDnYkJ5jUjDcq9WMPxVgt2T9Y2GsjdOx4nZ
         GFv1x5dAWyZIsh9oqb1Xo1UeULJnutrK0FSGD9aGUyH7BwCFPQM/yVHQe9fYIuW9C3+X
         YUm4fCwCpuopcBuZ9C/0rVCA3Y4T19N98f5rl1lkIlXs4At9uhSMRHPuVNBrB7OCQtWN
         6hcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YCtHfTx7;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a89d8fd8asi247155e9.2.2025.12.11.03.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 03:51:47 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTeLL-0000000ErCa-0UbQ;
	Thu, 11 Dec 2025 10:56:19 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3748730301A; Thu, 11 Dec 2025 12:51:35 +0100 (CET)
Date: Thu, 11 Dec 2025 12:51:35 +0100
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
Message-ID: <20251211115135.GF3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=YCtHfTx7;
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
> +#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)		\
> +static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
> +static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;
> +
> +#define DECLARE_LOCK_GUARD_1_ATTRS(_name, _lock, _unlock)		\
> +static inline class_##_name##_t class_##_name##_constructor(lock_##_name##_t *_T) _lock;\
> +static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock;

When you rebase this series; you'll find cleanup.h moved to
__always_inline (because compilers are weird) and these should probably
also switch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211115135.GF3911114%40noisy.programming.kicks-ass.net.
