Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5YXHTQKGQEIZMDOCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E4CD2DA34
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 12:16:45 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d22sf1270053plr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 03:16:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559125004; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0+c7Y1uSn/YfPTI64c+BidJxNYuKeZ7ssEImDPF2Fq+wwtoPr0qL6jU9xvyumi5iJ
         ds8j3NxClQMvMJzjyoF5PiYKlZcYkXZ4bdeDapNlsVHUFgQcmdqrrCSiJMQUYR4GrG3K
         FZi08+EcrT49PJF2vMEmDJcsVijdCOckdTtuUUWyVKKy7Zd83nuUElGRQGTXj9vTH5WY
         bgEmRsES/M2NSixkTcNjkEvisk7uvCSf/gbpRigM688eGtGgfXyuEt16EjiYp7QdEd5i
         xPLfWtBcJBqYD8+y/uLGAFHYUtZcAQWwN2h4Ewc3cwuBELjq9/61BwCFDucDzz+fGMuH
         uCXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lapQAMEQNXEOpVbZCPlDxc3P9tMaiY/6iGxCvBcOuiM=;
        b=aCA8W1JXJ631H5TLJ7pkFdNdjA4ouJy2XWYiaDxiHepj5NOGLPavnAvUo2B4S2zziX
         AIRHi2h1HZ4KtOtsxI6G7qtGGJ715CK/GK0rMJ73Nt+VP62VIPF8I3t+IYgRTNTBuOQD
         g31NOmvjIgzHse8g2ndhM/LI/dsDsgRaYJSzWpNSwCFpJo+/rPyy1EJWd8rtuXPlddW3
         nINV7O1qb8FuvoUmbam9qrefyq/7fqFlh7XmlhZk0C1tLQHhtZDcHFm9bkCJwlkZV53/
         tQufiw3wK2Xtu/p6BIz8pj5dbQTBvzSyLCH9Zslv1pWzlpO9DEXiCYD44MA3gpu3ZDqb
         mu9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uPCsWh9f;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lapQAMEQNXEOpVbZCPlDxc3P9tMaiY/6iGxCvBcOuiM=;
        b=QNJJjxax5rO5A+yUjoLEwU5dTfLUhcQwABlEJZh+pRqYOrtL3/6qBlLfsFreIpWRCo
         inhp7KRFTpbpIDZIu6DkXH1MkcJl2w32xpAwHsHqB2UzqnnHgoCeKaxbULu+bXTpsYtO
         OulG6d5tDM1Lv9qlS6UBi92kDawZOw/oy0JxsyxWYkXw+14e+onPxCKcpbcN+hsJiPwZ
         3TKGfn/i7CtH5Icg9WSceMQdG9rFQZVyId1k+gOCSQ01wBQ7rwnOpCFfPuFBJCeUurN6
         0Rj0LaLh82T5IjJNaAkF5jqoqqYJ8A8cGNC+ei4vHCvTcAgTLozUUZGV2NpGLSY9YG4d
         p+JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lapQAMEQNXEOpVbZCPlDxc3P9tMaiY/6iGxCvBcOuiM=;
        b=bnMkqV9K3gzUccdMuJf/0mY3mL15+mfiRoYpzAvrOALpdUitq6TzJPvRqIyWHG8vkh
         JI1Ukh0HVIrUfvQzSG9TkMFPsOs4fabeN79RqRv0//PBaDbfjZ6dRPYgP5v1i5FESTDS
         04P0R2YIghcq8BO/NSRiGS6WXErIoj/0mhPAHApGlL2V8lmgf/pBNA49tiZnhQPTtvXu
         nA+R/XTRUFufOpmn86tawIr7B5aAM/px9Mz5F2sIGJtJSUjjlYRNVrXZmyMkD/cJ+MYh
         RYcVSU93Gpj1ZcY2kRAMMtIOPNcDDczAJYK91kEJXO1qIiCRo2uVMAvIbVHAILbLdb8h
         UjYg==
X-Gm-Message-State: APjAAAXRrKX3XvpqWqcdjJ8yH+WUF85k74f7huOdAui0HBM8IvjGpsFf
	y++53iSN+c3sq1lIt7m4b+8=
X-Google-Smtp-Source: APXvYqyIPwyN5v/YB12pwQ18sl4ZaIhLbsO/Nc6SySbxYffp6thfB1GAMO9/0AHQkcxlU/Xki1DOmA==
X-Received: by 2002:aa7:9a8c:: with SMTP id w12mr63388205pfi.187.1559125003770;
        Wed, 29 May 2019 03:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b685:: with SMTP id c5ls458724pls.16.gmail; Wed, 29
 May 2019 03:16:43 -0700 (PDT)
X-Received: by 2002:a17:902:8ec3:: with SMTP id x3mr83551182plo.340.1559125003376;
        Wed, 29 May 2019 03:16:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559125003; cv=none;
        d=google.com; s=arc-20160816;
        b=JZM7aeQYzyWF4d134MiWKD3b17VCnpeNmTFBxEVPs7YiRSiG6rKuM70oWncnShLuCR
         5xx3lb4xuWTFFbYZ3hv4D0Ar1wEgkAOiUAvElpD79IYwXtXsVvdmO4mx9GPuBc6vbgPV
         Z4qovqIVfhYztR+dwBSS2TrIerKnNOLNpc8fJHSTLKP5B+/FInfJ8XAitAJY1KQqUaP1
         QtswsM/fVRakSq7XS+hfUHszbE0I2ltqBc2UAMxHIueZVpBzHzwwbgKni2fWFf9kF0cR
         nnLLLekCzBDbQn7E+Y2LJ0WA8cVDkupu5aFgw8zlzJwsd6FQvDt8+dXUdByMts2nRJ3H
         Ct8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Abxu/H1sImqXuhwWhYSOk5xvOYnoBkkpjqInhihBcCI=;
        b=mGe0kNyqjhJ+m6i/ACuw2jDhTnGVnRag4zVP/5rNYq32v5+GJ40BHWCcZSpcFaiM8J
         B5KeUOXBzOFpg0A3ncbniBleWbdiQrRIK4DMal0w8HGZg53F+Qq1wX7NX7EgUwVxdm6q
         JlvAyyQwKX5O1SrFel0P385fVkZ0UhNcuFxGggroCCZwWc/k5ztIPft6wPG3SHV2Irc7
         G0vWNJrpdVmcxGn4C3y4xcUCDTStOrReiToenu0eXPigA0PzulAQLSk/Q8wD0D8n79T/
         x7QmxcGnVyk6w4mQQYLVx7IZDbaWNWWn+25vCsv1IrxGgcveccbhqYK07H5JCA+6/QBI
         ZGQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uPCsWh9f;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id o91si149615pje.0.2019.05.29.03.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 03:16:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id i2so479731otr.9
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 03:16:43 -0700 (PDT)
X-Received: by 2002:a9d:362:: with SMTP id 89mr37406316otv.17.1559125002323;
 Wed, 29 May 2019 03:16:42 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com> <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com> <20190529100116.GM2623@hirez.programming.kicks-ass.net>
In-Reply-To: <20190529100116.GM2623@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 12:16:31 +0200
Message-ID: <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Peter Zijlstra <peterz@infradead.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uPCsWh9f;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> > For the default, we decided to err on the conservative side for now,
> > since it seems that e.g. x86 operates only on the byte the bit is on.
>
> This is not correct, see for instance set_bit():
>
> static __always_inline void
> set_bit(long nr, volatile unsigned long *addr)
> {
>         if (IS_IMMEDIATE(nr)) {
>                 asm volatile(LOCK_PREFIX "orb %1,%0"
>                         : CONST_MASK_ADDR(nr, addr)
>                         : "iq" ((u8)CONST_MASK(nr))
>                         : "memory");
>         } else {
>                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
>                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
>         }
> }
>
> That results in:
>
>         LOCK BTSQ nr, (addr)
>
> when @nr is not an immediate.

Thanks for the clarification. Given that arm64 already instruments
bitops access to whole words, and x86 may also do so for some bitops,
it seems fine to instrument word-sized accesses by default. Is that
reasonable?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvwAny54udYCHfBw1%2BaphrQmiiTJxqDq7q%3Dh%2B6fvpO4w%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
