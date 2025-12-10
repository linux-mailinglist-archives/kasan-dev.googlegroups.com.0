Return-Path: <kasan-dev+bncBDBK55H2UQKRBO6D43EQMGQEVURAV6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82B1FCB37D8
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 17:37:17 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-42b2ce6edc9sf666831f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 08:37:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765384637; cv=pass;
        d=google.com; s=arc-20240605;
        b=JwjELc+EaXupnMD9/JGGJCicleZbVJ+Jq0I/a1mh2LXcoDGNfNcRqFs4qT/VoVGKyt
         zBt7njX2vxcCieKTFevUjIlgmzO7dcRgmdcr5FI8bKwwOxVayeS72RSIV4ubot1/Ov71
         sRKt/bO8pwN/vZgj5WZsUCOxEnfw9MSlxuE+k4gJ5NVdB27wRurAPE3/S1izwGPLH6Nt
         9Z0kf2E6R+I2n3STlPY2WAs8pMMyFjG6qaAwmsDA9pRxX12JUuep82O9SjeiWTotSYbu
         uxCqRY7ikrNgY7sP8FuO0Iw/iOqfGVoWLw9hd0gPvlwcorUFHwwRBWxwVdGiKVJ3dav9
         TcXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WpXldMp3EkISdUx3gg0Ce0NwmNg2234JB3CVrBZBf88=;
        fh=lsg+oR5ZWRCOplVeDbggOcnCw21tinEYiZgnWOZ8GSE=;
        b=Nh2a85Kzl8E85Ot0VHPZvubD3eEafKQzFZJomSiZ+tHlCF9tLhUW5CPqw5RLemJKCt
         Z8BYmS4yRbMHgoocZgkkoul27TwaSTY5ny/yP82BoLqWwOGOW+2dFDLZ9jY5OygdnpoO
         m3sS0YFlhDKiAcupA3f8pbTk7PTA57PYYGSkaX0SrOp2+XfKrBvkut7ihcdMwfXz/28u
         nXkpqIOfsDWcMj/+G5uHdop+vzKbC23dY66jENL0ZlBWf5AZwPL37NYnwoUm5dVcoR0K
         OsmZbMoRpv8rrwjKHDbr5ENi0ct9V4zMR2slTHSur1cbcKZlaUcjqdlRxL2SHwrODsbV
         BmTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BYu/J6AO";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765384637; x=1765989437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WpXldMp3EkISdUx3gg0Ce0NwmNg2234JB3CVrBZBf88=;
        b=eA2Y9b8kfT8ydAAOWD19zyxHNyk6XIYUJ81KSXOl0x3PGl2aRS5FQsgSrmH/F8FpOj
         2U5ZU/LKpb48gRQT0aatFLPam7CPQYJyCThn66o7QXTonYPeK40c9EBx3Uben3g7jU+b
         j/OcdjBCXenTJianQLUpsHJKpczy/AiwkO58oI8YPLa7VKICrjgXu6j03W+v3Nt5tAia
         /1ZX2CX8bblyC/QY5m+geB2bPzU3b7gsUfOv3QkasCVmOo+S4/8n9SwWUGKeOggw7wfC
         iXZPiunfwkYkHeKncg7djucOIaDcOBi1RfA1D67rWHCG4COEZ1jIynkE++0x/Z7GFDDT
         rg+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765384637; x=1765989437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WpXldMp3EkISdUx3gg0Ce0NwmNg2234JB3CVrBZBf88=;
        b=c1uiHEkQATQyAFSp0ebhZ2zOUIP3BrsUup9QHC3wNvX91/tXKJAUphCQI171P39dbZ
         5so5Q4c28O0sVKlY308xanWxz9WEktgYqizggIS62dMuVGOWHbnTgqTGS+ywtDB4vQS9
         V++AE3wcqotyr8MoffjBZTXu5KaAjbYZ9E/7XSQmTdlK7LHpcOpfKDyBc1WEmHxRK/in
         uDA8ofEJ9TwfNiolMeYbvs8+9wxrrSt+yMofRDTZkaqZB++WNLh0AQ4GLzPsjXrxLDjI
         gSMeEjK5WnJ5ZG2j5A4tK5PhwqXTAcOpCPVf5h/ofS/RFp4ot+1rejn6z2Ane9DWxEiX
         r4aA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmFXpLot1V+ug4unWfYif4iimyKKA6lRzGHQRU744Sq8uXK6U9jEaPh4HhfpUgSdKZ8uHsng==@lfdr.de
X-Gm-Message-State: AOJu0YwqF7aWUEzSO94xRg+uGOMfPvgPZ+cbnidg++klZCvEDmukHrU7
	4Yj0QfUljfp/ZYiLkp96FChMWCkabzJEm9BoJT0Gi3qjtXnUX8TJs/NW
X-Google-Smtp-Source: AGHT+IFojhRa2zQObe/orOocqsQok+mkUM1iD8LDMsS7o/SYTr2ljO4oFSfRbs4tGTNgXTsTJUdZRQ==
X-Received: by 2002:a05:6000:25c3:b0:429:d084:d210 with SMTP id ffacd0b85a97d-42fa397bd66mr1951038f8f.0.1765384636540;
        Wed, 10 Dec 2025 08:37:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZDfJEBGaBbA6ZNrZM+/YBdRaiHsdWA2Mze04Fh9G7xIg=="
Received: by 2002:a05:6000:43cc:10b0:42b:52c4:664f with SMTP id
 ffacd0b85a97d-42f7b032457ls2586178f8f.0.-pod-prod-08-eu; Wed, 10 Dec 2025
 08:37:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRcbekKoil0TbdLTOIXQ7GCJ9Zj18gvkeGeKv0PQsvkcx81fBOj2mfIuC9Pk1nnbdYwp7ubrAqJLY=@googlegroups.com
X-Received: by 2002:a05:6000:401e:b0:42f:9e56:cfa8 with SMTP id ffacd0b85a97d-42fa3b0eb44mr3259427f8f.60.1765384633162;
        Wed, 10 Dec 2025 08:37:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765384633; cv=none;
        d=google.com; s=arc-20240605;
        b=lugXbbV/G6jvVpse8rAz292iqS/5ytJiBzteUMFuiAvPqgQjUrlnBVycTa1WPTrGv1
         qV2ZBDptzW54QP8VoBkbbdgFxT8t6myOF/n5/bFFBaeA/sUXgrK/ap5RfPgjrPeRGRCH
         QuOZQdQVQS07HsyWGd+Q00K9Vm8l+nvxlEhyasvoWDeJmAUPWdbX1uisj6QiaNAbISZY
         yQD31u7SmrVkQ8Z6hvdawskp2O3lKQCIz1VLF1r/iBwDb/CPrPw+9OBTsayw2wWBd+Jc
         0m7kUJJ601O2HQSS6XyYk/v6iYcwwGKb1Hb8EcGZMgmC6Isxw7bCM7La+rkf3oeT1+xc
         aRpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kgo0gn00i5ezpmur+oazSYFqerNtpx0n/NmNjZb+ZMg=;
        fh=aKVCN2GaAXB6pv2lcQx5Iq98JVHFUd8CIiAswtYA7Os=;
        b=TRd8qXGYnAWUgGoIHRqyEoWY4QnfSpcYieWwYbTaY4QxrHBHUrgER62Fn+2rT2Qb3q
         /Vx0MhE6O5BADD4kTYTDdIAzI8HG5Gl24/zmIDuT8SdE2wbcwxoYR4eK/nYHqcmBXojq
         fZGhhwy/dai4PAKd11nAo8r1znwrRlYI0YFq8GrpWDhkpTja4LCBqn6bLPDU7RJtpbFY
         hdkYnk9bQzeEeDq26TP9dM11loJaqaC1OCKDIG1awX74xEBO8wiX1710KCgnRWKRsmoi
         6siOxZYb2spzWa6i6LR7UythgNb++VglZyoNASjngOgF8Adi78SGQvUapbpEXFyjEqCU
         6xgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BYu/J6AO";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7cbeacb7si313686f8f.3.2025.12.10.08.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 08:37:13 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTMJz-0000000DbAQ-3Ck2;
	Wed, 10 Dec 2025 15:41:44 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id A3513300566; Wed, 10 Dec 2025 17:37:00 +0100 (CET)
Date: Wed, 10 Dec 2025 17:37:00 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
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
Subject: Re: [PATCH v4 00/35] Compiler-Based Context- and Locking-Analysis
Message-ID: <20251210163700.GN3707837@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <aTmdSMuP0LUAdfO_@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aTmdSMuP0LUAdfO_@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="BYu/J6AO";
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

On Wed, Dec 10, 2025 at 05:18:16PM +0100, Marco Elver wrote:
> All,
> 
> On Thu, Nov 20, 2025 at 03:49PM +0100, Marco Elver wrote:
> > Context Analysis is a language extension, which enables statically
> > checking that required contexts are active (or inactive) by acquiring
> > and releasing user-definable "context guards". An obvious application is
> > lock-safety checking for the kernel's various synchronization primitives
> > (each of which represents a "context guard"), and checking that locking
> > rules are not violated.
> [...] 
> > A Clang version that supports `-Wthread-safety-pointer` and the new
> > alias-analysis of context-guard pointers is required (from this version
> > onwards):
> > 
> > 	https://github.com/llvm/llvm-project/commit/7ccb5c08f0685d4787f12c3224a72f0650c5865e
> > 
> > The minimum required release version will be Clang 22.
> > 
> > This series is also available at this Git tree:
> > 
> > 	https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=ctx-analysis/dev
> [...] 
> 
> I realize that I sent this series at the end of the last release cycle,
> and now we're in the merge window, along with LPC going on -- so it
> wasn't the best timing (however, it might be something to discuss at
> LPC, too :-) .. I'm attending virtually, however :-/).
> 
> How to proceed?

Ah, I knew I was forgetting something :/ I'll try and have a peek at
this series this week.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251210163700.GN3707837%40noisy.programming.kicks-ass.net.
