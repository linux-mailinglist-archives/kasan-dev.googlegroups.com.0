Return-Path: <kasan-dev+bncBCV5TUXXRUIBB5FQXHTQKGQEYQ654LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 295662D9E4
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 12:01:26 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id w110sf864720otb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 03:01:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559124085; cv=pass;
        d=google.com; s=arc-20160816;
        b=odoTACYcEbOG0VcFCsWjOiA0sZUgYdbj7rhNRnqVkJtbdIIP2t74HfYWvKd19TgSpw
         W7Ta5AeKmjWPiE0psINH8X5k0E4QRdbnPk/x+qMlJAop4N8fklsKQITGcaMIX0PT6meR
         HiJWKXhDiFNRuGGcA4BVKtJhV1oRXo236YWaelDrsuhIxcZhK0qh79l6g6sEFdmHwo8U
         jfVhvd9UWBCWmzEBuO/+D5WxS7WwwZmEPqAEu07xUQGoDyXwkVm4ESgPpUZzw33dUtKC
         bGzS8qvU2vwAbJ9qMtVC+5Twsb77VDzhbWAAwln8139gU25+NOuwRFFOVXuMs55xzp/p
         v1FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XB//bNCsf19h2ChJOBZeF0DA1mE20IP801Qq9hOaX9U=;
        b=eDHdElj6owR1OxOz8VR7TaDwBkUU4DcZuo54UkcjsULWOokfnYLGhUpJVH/tVg7Opp
         rRUQXeV5SsshUFJg3oyD4OQgYXwNYwvhvy3gH1KB0ci8N56Tmyn8cfKuPz87yPZIy0sT
         oAU+DgZu7xQFwZ+vkNx/MEAgnMSpbYtSq0CI6kGUGHG2rY+N/o5ickk5B0PkpYer8OJh
         +TE7PA95+s6HgqkNXrZylXi/QwcX7c+Y9aLKd86ntrYvki2HlPwcFXR0vsFmaVMUoBOv
         I3KW9wqTDLyoYkvTPVzpeEZRx1mMYSdIMKglRHjWGmAzeT4UlH8kLEKdrkw3fSV2UlPJ
         b1eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Yzc20FEH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XB//bNCsf19h2ChJOBZeF0DA1mE20IP801Qq9hOaX9U=;
        b=fwnv1Rp6Yv1t5r+9ocuCgCSNK6BfHnum23ne7Y66QgZ+sz8doZOJPlJVjU1wkUd7A7
         AhH+bnKHsry8JhzGRkIYW5DmAxBD22/nj2PcrQSI9RSgEbEOo2Re7k4wtpvp5w2490DO
         7YPCplcdglDZqGa1VeQ1zH6FxndLU/a7On4JYjTBYL31k4wboFNJEZW1mE1pQ++jEQkL
         5yoCbAKlt8U1/oeEQzLsgenswIN8VDwJO8II32PbzRl9n/e1VSAzFfRgA7y4zEaLXhfe
         c/P4NNc4ekx4IRoaD7RVMrsnTTD6KVbZg0I2AEfFcYdXcMUv90wCg+XOqHSYDTBDAcQc
         B65w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XB//bNCsf19h2ChJOBZeF0DA1mE20IP801Qq9hOaX9U=;
        b=S0Y0/clSb1GAb04UpEmg4UIPyOu0bKMDDJxy3JIdyVFp1TlgUwTiAaVx8GLei84dP7
         7WdpaOyqhQZq+WEe3ZfxV7jpjj8V37HNSnlSgbFEFiPonYzFy9nHdnmO0XGzbiMLuP5U
         eiO0/2Pqcm1bBj+7mlVlWsNUX2/6q+a/memrGRV/Z4Y9b4jw6GZpf14IYC52eqwREwNE
         Wl6LrjPD4Cn8pIfx27Ylv7pJIu6REgn8KCJpd2iAacZKZtW2KzK32CZDyKNYHDCkA5oH
         0cnMVA20v3wADpsWoZeTtbulN2W2O+KUXaTBYu85tjPHvMy1j/exgAtexX6gzlPZZiVA
         /ExA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWg9XkmBvb8FEolynYsSpMU6C84crRcalyBQaDilT8MX07C2VAp
	zhWwI4BKAj7aoffMwh3bxO4=
X-Google-Smtp-Source: APXvYqzK8j0XdRDcWldtRq8wysGMvmoNJU76AbC1BfQaIXRBiyGNxbFt1PcQFi28nwq2zISegGOtuw==
X-Received: by 2002:a9d:7dd5:: with SMTP id k21mr51658496otn.167.1559124084883;
        Wed, 29 May 2019 03:01:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bad7:: with SMTP id k206ls260087oif.11.gmail; Wed, 29
 May 2019 03:01:24 -0700 (PDT)
X-Received: by 2002:a05:6808:642:: with SMTP id z2mr5728097oih.83.1559124084561;
        Wed, 29 May 2019 03:01:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559124084; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5uUUtk0erxjCTgcKYVbKF/bdsUy948Djktf0bKwohY0ijI4sylEzQZn8lM4B9oqgF
         G6Xm/Kk4bt7tMuCMnxJUw1tSXWfYlneUdjuyliiD40ziJj1y6AeEtrf646HIAFrKXjTI
         VZQEJUnXJIOMlqQay+siOpI3wCFUOk+toBRKA6kkgNjRt+30Ig8UKMEfuL33r2sAtdGg
         iHWOgubGzZHA1L7YXWLs9nHc1otsUxWeziwFJdSb5QlzFH/TrW0kxlH9l2i0m0zyYRJn
         6AAX8JmRPyez18cRo25yC1yqE4HI5sxzDCzL0QgaE7+djXpzs9HKMzrQaKZY5zUWEkvT
         /pJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kIMbddNkHXghmps6hNcFGND377pg1jMOBcSZ29+JswM=;
        b=J8LaoZp5w/fWAldmPOU5hSXZoYaZsqLHdz70HvAguIrrv3ODrMRO8VED0Z0n/1FVKK
         84awYZMfE8p8eDpqLd35dUvfQAPVEGQL8pmXDRNaL4oP8QAUYBNPM63bHMTL2iIWeQ3z
         dIT1rkH9fLV27btWskCBkORS4mPO8PLgTyyaTGnyKA8NTKw8su15U8iX2qfUzr0jG+wS
         l11QdRQmPuZYc/ORYcfaBQ2N0appDhX4t4Xy55wTpJ6bQDLvMEMviP0dkcahNDID8/Di
         TEe3qE9rKGa/V/YNwyXC3co5fpOCU1QLMTIRpjxEI+GOsxLmLktFLqnE9dkq6FBYavDI
         Ji0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Yzc20FEH;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id e25si1247893otf.3.2019.05.29.03.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 03:01:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVvOY-0003zL-7S; Wed, 29 May 2019 10:01:18 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AB46C20729088; Wed, 29 May 2019 12:01:16 +0200 (CEST)
Date: Wed, 29 May 2019 12:01:16 +0200
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
Message-ID: <20190529100116.GM2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Yzc20FEH;
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

On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> For the default, we decided to err on the conservative side for now,
> since it seems that e.g. x86 operates only on the byte the bit is on.

This is not correct, see for instance set_bit():

static __always_inline void
set_bit(long nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		asm volatile(LOCK_PREFIX "orb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)CONST_MASK(nr))
			: "memory");
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}

That results in:

	LOCK BTSQ nr, (addr)

when @nr is not an immediate.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529100116.GM2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
