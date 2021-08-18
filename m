Return-Path: <kasan-dev+bncBD7LZ45K3ECBBKGW6KEAMGQEX4GSYAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C3FE3EFCF5
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 08:39:37 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id q11-20020a5d61cb0000b02901550c3fccb5sf246869wrv.14
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 23:39:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629268776; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXQKnwhC1F1NskVP4rHM9Zb3Bc1qJR56S3MBgpgyynYJX+xgyKIduaCSiVdkncNT5p
         KEhMr+vplIfbSlGfjCDWtioaeGg3gvluFAuM/kOLgg3Dpc8leTzTBEjopRW2Muv7+2jT
         /kbXALP779E2f97PHT4GZWcpEJb//R4FXONujR5iZbSbGDWR3pogOsIG7FlThYzmHSDM
         t11zP7b7tNpMBTm/01XLWCV+TSBXxFxB1cAmNapTASNG70TpWS0IUc+e+fD2TaUbAqpB
         vg1VZWtTiDa2vH007FWvEC/WupuPTcNTqBonk4VAsks+SrdXQm+4vcRxROvUUJUJ+CNG
         9VlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Atop18YE4U7Fdq+rx8Jf1tPVKysGWsZQoZuDi8kqWc4=;
        b=X5RsX55MQwTp89LoGRiwgQiI1hEkhGfJGyvUsNG1tkfaoiykpjhBCk9Z548OV3QbVw
         WF5NfKNdyeOwp22Kw0HUtSrz1Yt0qpA5Hkruu6hnQbrg9ukJG8SINW3FlMNhz8xaIgsU
         Fd6d5Vgc6YvVh98CduBqM5EnG/nxPWZmEed3uPg6O6IuKyHHDXylUekkeWO4lSwwengb
         PHUsicbXK59VgZHs80UER/ixa9LuuZWoXRNCu1cRELa+Gl8+ISW/ZV4uH/GC+iBlh1Jd
         CtNAb8pZx00+D7UQKLzMbHH75+NaJ4F5BwhwmUrW8z19YCfL7QWObZ6UO70R5J1YPWKs
         xK+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="RMWvSP/C";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Atop18YE4U7Fdq+rx8Jf1tPVKysGWsZQoZuDi8kqWc4=;
        b=QDSceoGn4HR7o2BdxqqEd/gpqowHaKIbdICI2hgrORyPT+evT8/DquY9JeDmghfLj5
         W1vIGx4Yt9cAtRX5LTIG4BnISghb3D1NHt+kJ9RwDPLlMgnqS4O3OHDgdcYgcn44z1pe
         cB7ZcgJwuFg0wOCJPzfPGdAOIBw/asaVuUcCBbscjFGyKnCnbB3w+jmK9Om6JWW/U39/
         GCzFJubVLCBhLErGNalv5sfOnxgY2gZIJ924EvRS3OG8TxpGuRzvZAcCC7BRJHk7Jok9
         /FkwynfawChvxM7hKmWwHdhrSmoKEK42LVwoVA3oUo8m8MjFJH7tEH9x7qvM/OM6Jk7f
         zwZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Atop18YE4U7Fdq+rx8Jf1tPVKysGWsZQoZuDi8kqWc4=;
        b=rQ5BnjubVZHMyrjpD+8qcWHGS1TUyC9HYKKQItImL0Re0LPqnyLOG5xpIu69EQWFOp
         z2LqkrJrDDIYxgTh5fCaDbLFEaWEwRPg4IKr1TwMBg5LqegZ9qNICY9N0+0bvvD+gsqh
         2gki9JHxhk7cFpppNOcZv92yE5OmCqm8AIqj9aMpwZ9AnW2n+m2ohzJ/t+cfNdKytNuU
         ADru/DRvEVjI/BaPet94zwp6WPxKw0DkVjyJ+Kvx48UHP7VoX7jOXKyoofBvxhrQX3cw
         5agc7S7MtmP4dXqz30MGzw6GejUnPypRdszQKD1eBmRmrAn7pQTeWco3s70ew3Co8mmL
         04fA==
X-Gm-Message-State: AOAM531AkcmQB1nmJea6y6V1yQRXHNXmR2F2F8Wym96/RLTQSgN48Isk
	Ah7LLvkc8d4ma/2OwEOih5Y=
X-Google-Smtp-Source: ABdhPJxjYdXQBck8M+j7MIk0Wf7ymDp65Cyua/3cB4V+bGgby4JZnGZIOeuyKZ+5Jmgld0CU8r1seg==
X-Received: by 2002:a05:600c:198e:: with SMTP id t14mr6635112wmq.167.1629268776803;
        Tue, 17 Aug 2021 23:39:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cd8a:: with SMTP id y10ls2064202wmj.1.canary-gmail; Tue,
 17 Aug 2021 23:39:35 -0700 (PDT)
X-Received: by 2002:a1c:f206:: with SMTP id s6mr6843722wmc.15.1629268775708;
        Tue, 17 Aug 2021 23:39:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629268775; cv=none;
        d=google.com; s=arc-20160816;
        b=g0aoVlDiSPfuVSg+oC07aizmwLA/HBJ97tbH60vMV1ccJ14UTCqRqv0fZ0MHOwFYrE
         bESl2k0tm+sIq6aFSeceClWTAJzR/XCgUT946r4LDLpX6cptjWLTFHobzeqnWK7GRhyX
         I4ALrK/uTOQZ9Puo03y06kA6/d+yQNPQdJRs2LZD3XQoRwruttkd0kx3KmAGB+yVCT8j
         YfND6U2iUQkjbqtA1Q+MsLTvXS6/wppmjfI4/n4PuaOuzFyoKdZz3nXP9VyeQ8TaBsvk
         6vZfm1ZKtzRjvkgkIayS7Omiap/xUaoLI8Dg0eOCGcb+nVdiYc0uHqmhgjospiyg/iQ+
         sRBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=hVrGSTnE7k8RtP/gKm1lkEWkTXogfMVkN4IhNiukPaY=;
        b=U7NZKR9JFpAtmuhhbHlxANsmFoQW1uBlR7Cs4RAze+LJVWLwsTlkVKhASYS1bugaW8
         HcH+m36FkbHvLlLNBjJcitPft+RvodVPPU16jzfpXvHwxZ/5iAyQMaJFmp3FiPGRkYcg
         F2e6nIO0rg02sQhG/FCtgjGSZ3jW5pVOrXvUBlnHqQG4bwYzzh0BqowpaPbRHiYK10Zu
         2ZUi9LCUl+6PgN+7Q8Cbfezb/jiFUAM0jT9A+4HLSk1dYVLnZzae5GQsv/WhAAgVsQkX
         jAtmwPf5aR30ZaFWof8qIniWOToJ7V650ZPZl9ZM1kB1613puJ1j/ODEHgnoTm4jWX+n
         LxGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="RMWvSP/C";
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 15si243255wma.1.2021.08.17.23.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Aug 2021 23:39:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id l7-20020a1c2507000000b002e6be5d86b3so1061878wml.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Aug 2021 23:39:35 -0700 (PDT)
X-Received: by 2002:a1c:2702:: with SMTP id n2mr6857397wmn.78.1629268757259;
        Tue, 17 Aug 2021 23:39:17 -0700 (PDT)
Received: from gmail.com (77-234-64-129.pool.digikabel.hu. [77.234.64.129])
        by smtp.gmail.com with ESMTPSA id d9sm4677050wrw.26.2021.08.17.23.39.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Aug 2021 23:39:15 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 18 Aug 2021 08:39:13 +0200
From: Ingo Molnar <mingo@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: elver@google.com, mark.rutland@arm.com, tglx@linutronix.de,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, Peter Zijlstra <peterz@infradead.org>
Subject: Re: [GIT PULL kcsan] KCSAN commits for v5.15
Message-ID: <YRyrEQt52d0kaxQI@gmail.com>
References: <20210812001359.GA404252@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210812001359.GA404252@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="RMWvSP/C";       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Paul E. McKenney <paulmck@kernel.org> wrote:

> Hello, Ingo,
> 
> This pull request contains updates for the Kernel concurrency sanitizer
> (KCSAN).
> 
> These updates improve comments, introduce CONFIG_KCSAN_STRICT (which RCU
> uses), optimize use of get_ctx() by kcsan_found_watchpoint(), rework
> atomic.h into permissive.h, and add the ability to ignore writes that
> change only one bit of a given data-racy variable.
> 
> These updates have been posted on LKML:
> 
> https://lore.kernel.org/lkml/20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1/
> 
> These changes are based on v5.14-rc2, have been exposed to -next and to
> kbuild test robot, and are available in the Git repository at:
> 
>   git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git kcsan
> 
> for you to fetch changes up to e04938042d77addc7f41d983aebea125cddbed33:
> 
>   kcsan: Make strict mode imply interruptible watchers (2021-07-20 13:49:44 -0700)
> 
> ----------------------------------------------------------------
> Marco Elver (8):
>       kcsan: Improve some Kconfig comments
>       kcsan: Remove CONFIG_KCSAN_DEBUG
>       kcsan: Introduce CONFIG_KCSAN_STRICT
>       kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
>       kcsan: Rework atomic.h into permissive.h
>       kcsan: Print if strict or non-strict during init
>       kcsan: permissive: Ignore data-racy 1-bit value changes
>       kcsan: Make strict mode imply interruptible watchers
> 
>  Documentation/dev-tools/kcsan.rst | 12 +++++
>  kernel/kcsan/atomic.h             | 23 ----------
>  kernel/kcsan/core.c               | 77 ++++++++++++++++++++------------
>  kernel/kcsan/kcsan_test.c         | 32 +++++++++++++
>  kernel/kcsan/permissive.h         | 94 +++++++++++++++++++++++++++++++++++++++
>  lib/Kconfig.kcsan                 | 42 ++++++++++++-----
>  6 files changed, 217 insertions(+), 63 deletions(-)
>  delete mode 100644 kernel/kcsan/atomic.h
>  create mode 100644 kernel/kcsan/permissive.h

Pulled into tip:locking/debug, thanks a lot Paul!

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YRyrEQt52d0kaxQI%40gmail.com.
