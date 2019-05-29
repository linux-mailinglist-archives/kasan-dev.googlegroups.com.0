Return-Path: <kasan-dev+bncBCV5TUXXRUIBBSF6XHTQKGQEIYB7UDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CAECF2DAC4
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 12:30:33 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id z1sf900260oth.8
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 03:30:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559125832; cv=pass;
        d=google.com; s=arc-20160816;
        b=p6/3vqi4PX4/Pt9tL6ugFI1J0AlaVAJ1v/9J2l2WBnYXc3utdwudGQNlF9lzW9gic9
         jzDTHdSHUkPjpqb2tgWgJ9ZAn6Y920AbZtGnP4NROT/+esQfQjhRqyWMbiCTkP5xqbnb
         iu18CA6wAva69Dx7DZ4rhCV2wIbClgJP/PyEIVNKb+fhYqmmvUPLITUOGy+xr38VyUIn
         2/AbLlf0zr5bGVcKEJXgcoxSj62b4AkOHMr24yta66pnsNe4qJdzS3KAH4BKwQ+RXJwk
         g1aJGfiVkTXfyNQMcHQf+DQvJRi+BmHLIYPuffjLEHVDTppDQbEUMy9brxQcq+JEuS27
         +WhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=899nWmRdK/Hpq/VMfbRfRqDlYxtxO75HiT3ONV3EID0=;
        b=SKtLwe67lNtAWcPKiR9m0WBWvb+zA1krosaABPKGjSrTcbfwdC0CFGtVqaQWLzC4Jl
         UOU5klK/UUQk+fpsfgQtrmtcGpqG+tfLe3Tdy/c4emXSQA16eB43Ybi94IubQRnaISLD
         uv3GutgJKgKHp4Uk7Ur7p6dNfzEnK+zeLfxtnlVL7+awYhFjW2G/YeEPhG8w7QWrF+Sy
         GpjulsmjecezexoQHIaiGVMJvNIM8CY80WCi0kbqq7w/UnPeUbVulpnQ/bIkDfX7NCGh
         2pXoUTSwsGzdf4G9DiSUQxh62Sm9jlod5XZ9qbUNIIjUwIpUqDVHGLQUk1SxhLm5frrP
         mACA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=XQxR27+W;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=899nWmRdK/Hpq/VMfbRfRqDlYxtxO75HiT3ONV3EID0=;
        b=YGacpjovDEJFVPOmqrALXn/RMUgQEYJLxiWZBllO0us4dRr0iEI8cEhm/oAACLa5mD
         50UV5OPDG5OTREnRW+z4JsH/6hsZ+T30s9u7LCheNXaQabkLbsGMOsk86hcD6tOSk8pK
         Uv1n6NjZo44/vJ09MJI5GbpGJOb/Wg3e5imrWj8EvXrLnChDJmaU+G4VUkeVc0nV2JgU
         C2lhjuv0+y1VqKina/ZGylzZTpGLyIhcYZJZ37GZMXh0Wg4zSjLSl75piv6nS4iScd7U
         0nQwJer2NNfaoP5xzAvXu/zHOm2Ol8LnHV/Yu+n0TjeQiHIusC3XHyQYU69c4MyLJLAV
         R8Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=899nWmRdK/Hpq/VMfbRfRqDlYxtxO75HiT3ONV3EID0=;
        b=L5oJFJYf6p4Rk75blH5CzxmqfDTRR8AmnSGkwdq/WL2YO6rbkFUuZ4uTLxc6teWBgB
         2cfci3pWVdnLLpQ6g7s0rrLiSszjDmky3pUM9hzVZZWJBZggYDz7/Rx9vEZqcclq1o4T
         XBJvo0TSiCmAN5JiDEsIcxkrYBnf/j9ZbcKFmIihqQ9WFFCXNGFmfMzrcofUDPSRSvhR
         dj+IE7KuB9I+e5IPw5s6S7bNc8n9NcEiB0CDXsjtYTfTMxQTY1Sm2XXeuvUIgz6WSfyq
         qHHhVp5OVTuKSpP/e1QbdirV4eaONBResdnh/4/33rA472uq03KwzrZ6OCCFt2WuWBuj
         sA7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU05QHyaXZ13cb7VXvAvR0fUaeAJWQNhwce/HLaBH3NHUe/MKrF
	KZ0I9irbRk3Q8jYYvrkx/ZQ=
X-Google-Smtp-Source: APXvYqx3NPEd33lYQqMKcL3EWr1iFOHte5ZVtdVSuMD1TEvL4KNpiYqa8fJmoE2XBfqWo06MM5wjrg==
X-Received: by 2002:aca:300d:: with SMTP id w13mr1378020oiw.26.1559125832738;
        Wed, 29 May 2019 03:30:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:774d:: with SMTP id t13ls332007otl.6.gmail; Wed, 29 May
 2019 03:30:32 -0700 (PDT)
X-Received: by 2002:a9d:7d07:: with SMTP id v7mr25433709otn.18.1559125832392;
        Wed, 29 May 2019 03:30:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559125832; cv=none;
        d=google.com; s=arc-20160816;
        b=xFbc3rjLyqpVfRm40MjmSbwxE4MARogABj7Ms6eqhtA36gLCHsb8fbdAcdR2Qt8DX9
         fValqijMQjcc6nzwreHJARW4dvaHGLjt966FOe34KNa9RmOcAQZaAu+7g4WsReXTGaTb
         /98NEblHx3C+9RLeKaeDc9hrBu0EZ64ATDuuufh4l6LWhF4bcgDg6d+Bx2T3D0BTL3xo
         37AA+AX4PvpvjX3YgSWxEcQxC6ysKttpMvQx2PQMEbEo8/Q0jlQVt8doSTkEnGsWpQj8
         q+U7W7N+OvxuCQHBYKmuP8+Pe+gvXH/RkTSpvT3cK4I0IO1JAO5G7VfYfH+Zm9WGLZY7
         PSxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1dAPKEgrdA77wQkAtd5gC6oh+a8AzS+LHB60Y9C2ymk=;
        b=Y8Uj6As5im7GfTM0iq0fUGIuGuQvrWnPZyrQtu8MFNm8bLpQkZLuHWsSW/3Mkxk5cT
         rt0ASqRMRJwTn46se/L3LlkcHr0tWR88kykCevYn3lLSw+20EhwGlk/htJXwUAGRbwOS
         VmOstaS0ksiWPBtR/QjGg0dcsneQjrechg5QxrR9oNXla6gVG+wW0xZuL0CC3fLqOU2E
         pAlnp7t7cgry/nyn2qy1KSnM58mYfVHfcZimxeXYrBUV3O7fbKOEGY3JHIC6Sn90FQB8
         43dFRjrb5gG4dYmtFVKpag8S7LDDx0qS/x3FHkGukyiU7nJHSiBN9253d2zMEChsOkuS
         70xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=XQxR27+W;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id a79si732222oib.2.2019.05.29.03.30.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 03:30:27 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVvqV-0003TW-Mw; Wed, 29 May 2019 10:30:12 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 45FBD201A7E6D; Wed, 29 May 2019 12:30:10 +0200 (CEST)
Date: Wed, 29 May 2019 12:30:10 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190529103010.GP2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=XQxR27+W;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, May 29, 2019 at 12:16:31PM +0200, Marco Elver wrote:
> On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> > > For the default, we decided to err on the conservative side for now,
> > > since it seems that e.g. x86 operates only on the byte the bit is on.
> >
> > This is not correct, see for instance set_bit():
> >
> > static __always_inline void
> > set_bit(long nr, volatile unsigned long *addr)
> > {
> >         if (IS_IMMEDIATE(nr)) {
> >                 asm volatile(LOCK_PREFIX "orb %1,%0"
> >                         : CONST_MASK_ADDR(nr, addr)
> >                         : "iq" ((u8)CONST_MASK(nr))
> >                         : "memory");
> >         } else {
> >                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
> >                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
> >         }
> > }
> >
> > That results in:
> >
> >         LOCK BTSQ nr, (addr)
> >
> > when @nr is not an immediate.
> 
> Thanks for the clarification. Given that arm64 already instruments
> bitops access to whole words, and x86 may also do so for some bitops,
> it seems fine to instrument word-sized accesses by default. Is that
> reasonable?

Eminently -- the API is defined such; for bonus points KASAN should also
do alignment checks on atomic ops. Future hardware will #AC on unaligned
[*] LOCK prefix instructions.

(*) not entirely accurate, it will only trap when crossing a line.
    https://lkml.kernel.org/r/1556134382-58814-1-git-send-email-fenghua.yu@intel.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529103010.GP2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
