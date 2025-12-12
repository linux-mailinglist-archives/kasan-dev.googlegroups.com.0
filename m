Return-Path: <kasan-dev+bncBDBK55H2UQKRBAWD57EQMGQEIIWHXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A64BCB87A9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 10:33:56 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-429d7d12182sf140805f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 01:33:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765532035; cv=pass;
        d=google.com; s=arc-20240605;
        b=NzqSs9cykcr7XgbNnEjyQK/zWEcmuZlUzMgUKC7ThXpjVapIl7lZVR9rOtfOmLkj+y
         yl4GZDm/Q/YrXe06iMnAwX0rTj5m7Erkf4aRBIbTCena2fvaIfy9DZcz2RZ4ARt/vbpC
         GxsFe4mvFQt6MhzSK95JX/nVTPG0o4Kf1hTegJYKJdHmhr8R5TpzFpjrBuzd1ftHRTF6
         JQE2S5CKb/KaRcTjCM5HKySEHCYRp8VOGgDkFEKUIBGHY489kXlfotYHzWLukaGiyzkJ
         q5M3f79qreVujNtA+8z0EDNyEoBHQ51hokn4hVGC0J6ETgTz/UyXcveLhk7f8cMt6fcB
         41gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H8ZBkMkPSR+VNA+jcam3dgoocKAQyDhPL5uEUNIkkvQ=;
        fh=4wBRTbCibMaqEB4dVbHUPqd4mQJBhWEVWOz/sDAVccs=;
        b=RrBg4aVPGcoIDjFUefx3QxVTxDdGiN3BGv33pz/3EOUtA2HIwVNWPJsK0wfIseMtEm
         lQ7zEAB76ugzp+8bPZ2wWVDNM3n0OOc9iuerm0breOQW09aCzL7GOeRjDGKKRQMeWt69
         ZdgSdGwyQfH1ry/W9uYe9dOCDhFuARbk5eD8X4Jj4jZkcwT7QrYk7Kyl9yTBVCfFx6Pl
         /U0Wx6Ol6YoCajLvMUlALnBTClWGyfRfmRCIRIvhF9q+6PICU8+OP1wOnVv/vlTWlHUD
         aKKPUvbUCcNRMvsV/vJ1vTBdlgyH05ZXFDQiU4mPHuvi1lTfOdKJ2Ec1LvBC5PgQ9p6n
         vf6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gP5FiKEc;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765532035; x=1766136835; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=H8ZBkMkPSR+VNA+jcam3dgoocKAQyDhPL5uEUNIkkvQ=;
        b=nCbLKGNHe4ptbpMf7VIf5zpHk25dJll8ViXXOOY1Wt6RKeTPbvzdBwLbsciP/E+meY
         8xkzNnx1JqAD/0DxwTq6qJO9yrvdWpOSnek/c23fzbTZkbdJA2l7b3+DwiiVelXRb5sH
         NHR4EMB8tzSUhGJXPqGy7JlF9IDpodsIzgB0LnYFAW2gQdeK3erhHtABflQVlkheTlIv
         oFMHg7+EReXAtJO14zaW0L3jWJzbaROI0EUo4Y+oxRJVJtwGIobwGHNLcoZy1RUie9e6
         xOj9GJ+5mXjZ1FSz/YBOhWdpOpXru+We245uTer7a59rK/8UjGc0inpeOU4+2FjszgDZ
         03/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765532035; x=1766136835;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=H8ZBkMkPSR+VNA+jcam3dgoocKAQyDhPL5uEUNIkkvQ=;
        b=C+ET3S8yhF2MWhTntj2CqLtPsLN12AuaiJRB0hTNjY/a0uDlGH6qC8nRg06WdBI7ry
         cdTkTRHsDNjjKQN1Lh0l1gQLwaBLVmGWFa49XM2YIfjIb2SHxF9kpjTkels2joPmXVdh
         d8ucSwgY4yqo6NLMsO1TLkUi2+eOUjywqdeSIOO5DvwNvod1UTfa1nKDQ7M7QDrTG/ty
         E1grTZ8g0beI63V5kJUYM64Nv1o4p8J+H+7/XG5i7+wSkVBPPklV7AjlEBMdhxAKiKAI
         bsFGD3fNXaytwAeJXEd7KoJCNvR7Okl9v6Q7nQiGfw4/bTjP3QOSJ8RrcPXfoeOzbX6+
         luVw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWevlRp0nUGrQaUIbUUDFPipF+Qzxkxo/gpj5Gsl+IDcOkBp82NYbjMP3RvIzIQVyDng8o84w==@lfdr.de
X-Gm-Message-State: AOJu0Yy/6y5rwzUosVojf0wK5BhegdSV76Rl4gUnLANmLUjHdrg2HsBt
	eDBxh9D3v9tt3GkWPxtwkIbTJl2+b4V1WB/0DV+fylB/PCqyPEZfYIcy
X-Google-Smtp-Source: AGHT+IGAPpuoJptsLg1KJEgeSDgMIx3yxwbqYozkjDz37wB7cqWe/IRNrSBJ7Y8DMsueb+tYqyIgPg==
X-Received: by 2002:a05:600c:444b:b0:477:a203:66dd with SMTP id 5b1f17b1804b1-47a8f8a8a12mr7894315e9.2.1765532035117;
        Fri, 12 Dec 2025 01:33:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZModCokIDYk5Tp6q4a87iOOOQoKSFkSbrBSjAGJa1IyQ=="
Received: by 2002:a05:600c:19ca:b0:46b:f67b:3bc with SMTP id
 5b1f17b1804b1-47a8ea160f4ls4288865e9.0.-pod-prod-06-eu; Fri, 12 Dec 2025
 01:33:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXU57zzulod5Xo6i/P8AINCVARLHRHdliMxoCEl1/E1adx2TxwNWgmfxFgdNE53lrF5v0JAsJL5gJ0=@googlegroups.com
X-Received: by 2002:a05:600c:83cd:b0:477:7af8:c8ad with SMTP id 5b1f17b1804b1-47a8f90eed3mr14607615e9.31.1765532032293;
        Fri, 12 Dec 2025 01:33:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765532032; cv=none;
        d=google.com; s=arc-20240605;
        b=JGuO3+a8bxL92qnUV7uFsgL5ZhqV88uPSCzvlxK0ZCKUgnG0QP44W7xZZFtM5cgtbL
         Z14fvjRMYl6GVvRJsyTqmj7Ar7tIO4E4JUwMlb2DuHRB2f7VCEFKvCCaI3slAmPgLYQU
         Grt/GwITl5isDnfv8YggIQ4KIB3Y/SE787d44zxQUKrB2TzAfTRLH+CEEf/nc/nN9fbM
         g/Ucej7fQtaZeAWMQN7G8kw5bONsDyyf6amWEf5bwgcu+G/MMT+UqCrJwboT1Jic6mG6
         OAqc121eLYRA9osR4NkCOZeQC1ME3kaMWOVCcIkNtKo9VCACtceOFnmHtvw/6QRS9/6c
         A0Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pQbWCtHdrI7qQ4N4sW7tS14xKqY+Ou7bmuq3drTQLtI=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=VlvaU6EszgpuUBbz6Rv8nWnlwMDggaeR6CvAxJtFrVt92jWN51Robziv+P0HNBR6Z7
         jw2kSPJyN3eNkHdlT3lHNIUZWvXjJ6VmH7EV49XH/0DQU921O7VM8WRuoHop+lnApNT9
         Miwq6bNwH3mYrnPlIL0DXntUOfDOp1MFRKg59JYee0m8MHqcar9WP5m9HNoXxxzAf2bZ
         +JE8mvAEc4zqjBOha1WN4FkWXlKMqBezIA3/8NDNMPfw7FKh1V2bH7MsfzlotV1Z8JRn
         swxAFGoyCnXO4s56mbsk91Z8+0vOJEUrx4ek8RCG8nHWv3UwM32cd1rJPAUmQQLn6fvE
         b2WA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gP5FiKEc;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a8f49c17asi166145e9.1.2025.12.12.01.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 01:33:52 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTzWw-0000000FU4K-0MV6;
	Fri, 12 Dec 2025 09:33:42 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 08ED630041D; Fri, 12 Dec 2025 10:33:40 +0100 (CET)
Date: Fri, 12 Dec 2025 10:33:39 +0100
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
Subject: Re: [PATCH v4 16/35] kref: Add context-analysis annotations
Message-ID: <20251212093339.GK3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-17-elver@google.com>
 <20251211122636.GI3911114@noisy.programming.kicks-ass.net>
 <CANpmjNN+zafzhvUBBmjyy+TL1ecqJUHQNRX3bo9fBJi2nFUt=A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN+zafzhvUBBmjyy+TL1ecqJUHQNRX3bo9fBJi2nFUt=A@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gP5FiKEc;
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

On Thu, Dec 11, 2025 at 02:54:06PM +0100, Marco Elver wrote:

> Wrappers will need their own annotations; for this kind of static
> analysis (built-in warning diagnostic), inferring things like
> __cond_acquires(true, lock) is far too complex (requires
> intra-procedural control-flow analysis), and would likely be
> incomplete too.
> 
> It might also be reasonable to argue that the explicit annotation is
> good for documentation.
> 
> Aside: There's other static analysis tooling, like clang-analyzer that
> can afford to do more complex flow-sensitive intra-procedural
> analysis. But that has its own limitations, requires separate
> invocation, and is pretty slow in comparison.

I was sorta hoping that (perhaps only for __always_inline) the thing
would indeed do an early inline pass on the AST such that these cases
would not in fact require inter-procedural analysis.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251212093339.GK3911114%40noisy.programming.kicks-ass.net.
