Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZHMXHZAKGQEEXYPKFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 796F3165D3B
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 13:07:01 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 4sf2008269otd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 04:07:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582200420; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAJeAqGvQJPeYqrVXD+CU/CqIRo4vwv8pqvmVQHNQ0+hiNUkR8y4IBePFECfGIPIyk
         HB7SqRvbGPgzTnxnRB6wEYxb7FWNmb50XwYaQm+RMY5Oxb/gHG7NgP7bpNlmqLiXbgVy
         qagb0e1zBBBu4+V+w4h2RDqmzC4Zxm91UrdWlIvLt4mHcYAumNljCEN7ndtmIsYvGEy+
         ykZ4GBRqZkjfffOC7mgImDRC9xCwrJ0hcGHYYARzFMaITM1x0pz/2L7Ti6TdYHGc9F3k
         291DNi837vnnVUBUtACGykiNUwJDKI3IneyAV13Nnf2WuwyWPGNYQOXnIyFW5iHuYr17
         0Ndg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cIyw6sxep6xWvXGKg1JFEBKeHdejlKUa6ct2vPAlDfw=;
        b=yoUT5saPnHkw1xBv1beuhY+hxgBUhsc9X+j2RocJs6xcrACifwWqVfu9qD6vJWRd0w
         Pd58D+2EXAilKX2ciKyAaT7wOmYnq8Q2A0p85OiC/h43IrmRbNXqvnhvh8jmC34R4pEE
         YW9aDCLLTn0mCGMlj0vqSSLMQ9UKoArRaYUMfx4tzJ3QRXYpxYdFU781WMjUZ1Ww1ryV
         HwaVPHYhRa7FzgyqM0px1Yaka91m5jtXL6oKcoI3MBusJTKl3NCVNMHT0qQ9niSzgN1n
         eCDBG84F7OOVMEnWNWUsSELWr3gPJpWzfiYn0IHblq/TWlV1S6xnueCluLo01aVPBgvq
         hkQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=K1EYLRC3;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cIyw6sxep6xWvXGKg1JFEBKeHdejlKUa6ct2vPAlDfw=;
        b=RptVSxb59GyKxpwspkkgp7ieRuG2Tc0FFSVthyMGnWkifC8UYM6SwawqsVq6abz6RM
         GAC9TAjpIIvQYBy5B/QzVhS2z4T3gt3LVvTNJG5wXoP8XhuiGrJLA//9eAafrxioD1TL
         e0r++gczvGflyt2y0ZPiYIz1lyI4QCHI+ok6KEn/czJD7XFuBhW+tvOs8S6ZtBJ7+jIy
         S8OGeNLvepQpuBvI4xlFYKUcPQwK1H/u5to2JGqlsOm2EoSh2lguiVP9neyNeUf5+UV4
         11OoL5l+q4hfdyCKkyJRvW4FvhBH91w9ORYkentvYy422BFvVnaWv1LZ0HcHT5OKdfcI
         yCMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cIyw6sxep6xWvXGKg1JFEBKeHdejlKUa6ct2vPAlDfw=;
        b=MIGar/nFkZTladhldcX4TqqR1oXySfh/eiT3GDpKtNo52KF1Rl7cuhWgnt+egc2+Ux
         NEWfHCrmyCvRouk9Cw+xiAC8PqYIxgFemHifhBMvI4m6XffSXoMUoYMKhcRLO8bO1vVI
         F6KewaYyG58fCXwfylzs3TjX5EhxONgh2W9InBFvUoUlVX/7dHxr9OwigYjLI4IBe8sT
         7qmoNPzyFmpl/Ek08Jvsf7elwsCJGU3AS2qW+LfOjm+61eFkZWG/pN7k9yuNangXhmoq
         P7jYsUmOc/sJoiyhPf3WnAXkr02Zu/4fnskzkaQNUbprDeDvD+a+INBJh1jVRlZXw0Mv
         EYHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVXbhiMNNpsiv9oa4Q1Dd4cZcXGeCSy7vKEPbEE7rp6evS1oxc
	AoyxT3ciHGIC17lAcoZ8/MM=
X-Google-Smtp-Source: APXvYqzmfu52SSgcXBN7Ubm5ADe2siW/9eiZegSeK/5j9lYf0vPMV25Wf3kJpcX7PsJgwozct8sLFg==
X-Received: by 2002:a05:6830:144f:: with SMTP id w15mr8688116otp.46.1582200420230;
        Thu, 20 Feb 2020 04:07:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd6:: with SMTP id k22ls155288otn.5.gmail; Thu, 20 Feb
 2020 04:06:59 -0800 (PST)
X-Received: by 2002:a9d:68c8:: with SMTP id i8mr23907455oto.34.1582200419860;
        Thu, 20 Feb 2020 04:06:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582200419; cv=none;
        d=google.com; s=arc-20160816;
        b=nPahNlZQBXjNfGUudDTaRgzh9LuSlB/E3LYUqfzrVP/fxqD1dgOco75P9Uwy4QS88y
         9oedoh6eYEHDTwZERSzWMnhQ7iA0Mcet+1tkBhFSYYuRqwmBx57LCPrE/26SzrKD6y9d
         TmUL8uN5tKh3yW4lWPIeYFZG0vxkJco4B/VPvDQDEyB4wX4nFsonkKrUCJ/jrC/6UhIX
         3yGQzXre3Y6hW+ouGmol2CjqF/vazrr6yTwgZBjI6JJZHpeHHfS8/UZmg9QTfl4yTRSw
         mt86+9dbicKu9GG5Bfno0UzD0f39jZSiIgcKbnCd0dAghzrIczhE1z5QqSd3rJX42Dez
         HM1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Cv6/HWnnJ/eE0Z4xVRlKKP4A5MEBltFbBUkFytPysi8=;
        b=PdiUchJ6B2aVn9BpaMOk0aOxGwYbwj/3tLNGYyf0Plcqz8kLsRRLBmLFp2Ux1DCugC
         I6rm8Vtj2Q85Kewxe+L9PL/BN+hnyo6835dZDgbl+jACRQhNM/qce+nYU95aBYkFCPv1
         4FpaFlAI7GUF0PK/XP8b2J59RmSmy/xuASaZF89tnwkCrqbpjKWZ0R3MYbcRCPiE+tpk
         tB++s7m4vf7Xr8fsqAgOIY4ZqaDEZyUPwv9ItvU0QQO9nWpsXsHsV4/sWh/czGYm7Eh0
         ZyZxTOv/a4Lfr2nruea7QSBrgb346yEI0fV3SjG6rZPt1pACwINqhfY15Xg1uR1sQggV
         nn1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=K1EYLRC3;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id 14si217293oty.3.2020.02.20.04.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2020 04:06:55 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j4kbD-0002o7-7q; Thu, 20 Feb 2020 12:06:35 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1124130008D;
	Thu, 20 Feb 2020 13:04:38 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B5E6C2B4D9BDA; Thu, 20 Feb 2020 13:06:31 +0100 (CET)
Date: Thu, 20 Feb 2020 13:06:31 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ingo Molnar <mingo@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, tony.luck@intel.com,
	Frederic Weisbecker <frederic@kernel.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3 22/22] x86/int3: Ensure that poke_int3_handler() is
 not sanitized
Message-ID: <20200220120631.GX18400@hirez.programming.kicks-ass.net>
References: <20200219144724.800607165@infradead.org>
 <20200219150745.651901321@infradead.org>
 <CACT4Y+Y+nPcnbb8nXGQA1=9p8BQYrnzab_4SvuPwbAJkTGgKOQ@mail.gmail.com>
 <20200219163025.GH18400@hirez.programming.kicks-ass.net>
 <20200219172014.GI14946@hirez.programming.kicks-ass.net>
 <CACT4Y+ZfxqMuiL_UF+rCku628hirJwp3t3vW5WGM8DWG6OaCeg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZfxqMuiL_UF+rCku628hirJwp3t3vW5WGM8DWG6OaCeg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=K1EYLRC3;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Feb 20, 2020 at 11:37:32AM +0100, Dmitry Vyukov wrote:
> On Wed, Feb 19, 2020 at 6:20 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, Feb 19, 2020 at 05:30:25PM +0100, Peter Zijlstra wrote:
> >
> > > By inlining everything in poke_int3_handler() (except bsearch :/) we can
> > > mark the whole function off limits to everything and call it a day. That
> > > simplicity has been the guiding principle so far.
> > >
> > > Alternatively we can provide an __always_inline variant of bsearch().
> >
> > This reduces the __no_sanitize usage to just the exception entry
> > (do_int3) and the critical function: poke_int3_handler().
> >
> > Is this more acceptible?
> 
> Let's say it's more acceptable.
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>

Thanks, I'll go make it happen.

> I guess there is no ideal solution here.
> 
> Just a straw man proposal: expected number of elements is large enough
> to make bsearch profitable, right? I see 1 is a common case, but the
> other case has multiple entries.

Latency was the consideration; the linear search would dramatically
increase the runtime of the exception.

The current limit is 256 entries and we're hitting that quite often.

(we can trivially increase, but nobody has been able to show significant
benefits for that -- as of yet)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200220120631.GX18400%40hirez.programming.kicks-ass.net.
