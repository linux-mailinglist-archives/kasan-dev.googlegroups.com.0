Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLMISS6QMGQEDU33UXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 748EFA2B19A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:49:19 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d0615ad135sf4583235ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:49:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738867757; cv=pass;
        d=google.com; s=arc-20240605;
        b=i6xuB2opUeTczU1RSQDQ5zrN/vTvC0CxanOjm4a9VkUI9xsltpbYVqkQu/O+LVhazu
         xCjMjipokI9BxnXmEdLRiAN1zOgH0c4LcGH1lglkGQ8P62WBjTlwk6HboTWSYYzPhMKw
         13U7YxVUcXT8caSNcOhtIm+/z7cHu/v4l0ZRfo9NxnUS9B2wK5a9SRiQf935F/zYGqop
         YYf4UYqBhV+JF/ZIFgVvEJStUZO5ZUBsphfRjihu6L1Be3VVloR8mGfSVGHy5tga2Xfa
         zmqu5ak0C673Yl5oiEWqVctiUYqy3XXHh8tqDqeVTrHzLgu3AxsvkS47BZp1t0q8ndIi
         9MaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6zi/GmcQ3hSUiGm4gF4nHTr1h11jzSwf9zT8V41j2PY=;
        fh=WYmhCOczj5m5UEeXAYivSHqjlFVMHTPQ557eF8cQrCI=;
        b=JNvcMq69cCpx5VuiDtlYfv4dLmjjkYQHW3uOOC5tnAlbrR4QDDecdKKxcwo/fiQRnI
         e8YAmFUB4y/ogLGK8lmezOnqQEEOICPWfuJH08yKFzOJOaRa7jP7OmyKplcwYCAy0ir9
         toQuZYhky6pD0kEP2K2TQrWysCDQYaek43Zso/tZCUtos5cJ1sLrYBpoLBq5By4uCwgt
         ZI0JZSv/CYF7Y7DYSCJ/THgsgHLtRd5l5/Wc8Cps8YP1qZSXcJxAdQylRoH3uVN2ehG8
         ZtM1cC2tcHYrp7y8KRWpTnhiQbqGsp9+TJiQl6VpvgbMKp60RAxobIORGGvUvvSxap0L
         7dfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U3v+hcsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738867757; x=1739472557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6zi/GmcQ3hSUiGm4gF4nHTr1h11jzSwf9zT8V41j2PY=;
        b=kiudg682mrBXuEPkb3rnnjEOsAhEowIa+bFZqy1tCSrY/93+PYWxvgnJG+bOM2VplB
         E9Q5j8tNIHxD1tyUs7lQTQAMfa6uvIxPnTB+Uwhi+b7LSK7VAz0PYP22uxSr3+EvK7+T
         5RXrZY53JZyb8gWuW4TqiSUiNR3axC629SdGs/zgW1xdfJdh/6tr7LBdarkmedSBJ9EY
         hjiaa+QSkkenZvTvtkic8MGYAjfZpsyk68ioiYUQuiKXmgZgVISlVMKfBVFRvSBUibyK
         x2rRrgCdSgbboduWnpUDRYjW6rd7S6U0uaA1DLz93SbwBNUZHrp+qOeRUZJ9Q1uoFVEj
         YeCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738867757; x=1739472557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6zi/GmcQ3hSUiGm4gF4nHTr1h11jzSwf9zT8V41j2PY=;
        b=DKvYqsjzjzme0ePkN71G8ZWlMRpQ5szKKxYEGoZOhoOjLRA9S5D4tCHM283sAMHdPX
         fWt3A4agPe2v7PNljOBop/owPOATjzcoaVSSVaDnl+yyH4jb9aGCRy5KEn7ywIY3Z+dh
         QHJxYZJZri4lifRDaiWxkWKD9a/w7X856NJZZx9hAE0UXymi1GA55P+toZuyf5gLZpIV
         XnwYNbMCHwsVUiSS4SQXBE5p4eCwibI1KDanFobtIWYWgyBbTS0o2+R+giLoKULEjLBB
         j+qq12o9d9PhFVagl2bT9//Mv7UlRmya/oHTUNqwKyLDMnLtSPvUZT3envEE7KzC3EtQ
         KL1w==
X-Forwarded-Encrypted: i=2; AJvYcCVgmaSrKKH9i35h/kN3IAYPyJoipqzr6Pp8oNBWfisYXKvV9iZjUC0DaU95L28rLQcm/snKpQ==@lfdr.de
X-Gm-Message-State: AOJu0YzG+qLfifqwYP6kRnIpTgvHBJyHDLJvxwopZ6t0h4l3SrPQ88ah
	HvRDAQxUQlGgnnUAigy0azfQVrBYfjudGTTl0Um+8ZKsCLwi6LxH
X-Google-Smtp-Source: AGHT+IE16BsrbvC7cXT6ZD2uXv/fEL03zYlN/rrZN7KLbq2WOMbgYYFyyesIbAOftS+NY4esDkddJg==
X-Received: by 2002:a05:6e02:1a0b:b0:3d0:353a:c97e with SMTP id e9e14a558f8ab-3d05a658ea1mr42256305ab.10.1738867757445;
        Thu, 06 Feb 2025 10:49:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17c9:b0:3cf:cf0f:7dab with SMTP id
 e9e14a558f8ab-3d05a4bec6fls4715125ab.2.-pod-prod-00-us; Thu, 06 Feb 2025
 10:49:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVnbEDH5F7x7b3eQTu7JK1rbuZ02O9YCSHzV4doxxV7ZhhN01Niuxyg99c/P7SBul2y6CpkBC/LFBw=@googlegroups.com
X-Received: by 2002:a05:6e02:20e8:b0:3ce:7a41:d885 with SMTP id e9e14a558f8ab-3d05a540706mr38698695ab.1.1738867755978;
        Thu, 06 Feb 2025 10:49:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738867755; cv=none;
        d=google.com; s=arc-20240605;
        b=L6AuUFGy4BF4zY2llJCj63CJJ64fuH08ygbKiL9TG+c/jIrwIDdgfkkDjLBFf2Np9D
         pKTSS0vtF0IjkRBqJ9qXExqOdb+h2oBsKxzYP2WzgLF0xZA5h6PxDaMnM+jTL+xJ3Ong
         962nK4c+jq8Ihyhmx7XafpJda7x85p22vTXiA8cDhC50ioDmpT57iSSdi8qq18VjSX/F
         ++LTI4yxygZbIXL72+Skx99BblDVFyl6B/4UVs0LzCnddsxmSy8POmIaNd3Ksj3mPdkR
         Yut/J5qvM11MX3WbChBqn4xXF8KLfdrHDafGjOSb3Aue6P2Y0LNidxISDHmmyluqdWix
         gBDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nlRt5j/kIPL45Og0/CWS7P0L4BsTBNK9TmluKrchWAg=;
        fh=LeHSCVo/5KfYieGioTbHX4r91Mxqi3WIUA3Dl4IduFo=;
        b=YhPsbIXPXzrO5ZTYYgpbBK6ddhYgoqfhgHjzmb209xSvTPfXerpuObenNuJ1Papke1
         r/LL+gXtBvWDRbP4oQMC1yS5yoGURi4Ctzr0gA4Wd/b8kRM5CZVWGntXFVz6A2S2exgE
         y5kR/35zkhGLhyHv3rQgJtRRUAXXKjdr5mF018gsBJDXStqcnAW3Y/iNf56T+Mv6nZfZ
         bSwn4LstVhVdfGDwyDmP5IpEzckGNzdYj97vRZ0MeY9cEHUg2V42DFlA5IbboaNn2bzu
         uLx/sTqKA6+okm6akWk3ZQN+VqM7Zsm6r5rAuK8E31fDfV1yHWAWPa8cGn9aPP9QwEOz
         KUPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=U3v+hcsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d05e9af0f0si870565ab.4.2025.02.06.10.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:49:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-6f972c031efso20835687b3.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:49:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXQr3Epm6BN5Cwuu3r+ZQHiV5IRS5gFKK0w4mDXc2bcPjB0Ut3t1MKjo/1LeiIpkTLWqhxfgNrDeic=@googlegroups.com
X-Gm-Gg: ASbGncvj4YiFlzDIZ38ShlV5dOOzKynIkVJJwpS3HvTyYOPEqjjfqnH3hvDc3iz27fn
	H+IkZ5PZoChSq7qjP/LlWY1EK5cdez/vKr3hYgWAobflfecKBUkEJF3u3+BV3lC6CmA8Fuciyt7
	04rKxFLK5l6asEgwP1vz1BYt80Zcw=
X-Received: by 2002:a05:690c:7089:b0:6f9:492e:94db with SMTP id
 00721157ae682-6f9b381fca2mr191027b3.2.1738867755278; Thu, 06 Feb 2025
 10:49:15 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-2-elver@google.com>
 <552e940f-df40-4776-916e-78decdaafb49@acm.org>
In-Reply-To: <552e940f-df40-4776-916e-78decdaafb49@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2025 19:48:38 +0100
X-Gm-Features: AWEUYZnk9rIG8ZqxXrgEaM8RCQ6m2IyEZ2vODfXrtzceps44fJ5AzWTWAEX80U4
Message-ID: <CANpmjNP6by9Kp0rf=ihwj_3j6AW+5aSm6L3LZ4NEW7uvBAV02Q@mail.gmail.com>
Subject: Re: [PATCH RFC 01/24] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
To: Bart Van Assche <bvanassche@acm.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=U3v+hcsu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 6 Feb 2025 at 19:40, Bart Van Assche <bvanassche@acm.org> wrote:
>
> On 2/6/25 10:09 AM, Marco Elver wrote:
> > +/* Sparse context/lock checking support. */
> > +# define __must_hold(x)              __attribute__((context(x,1,1)))
> > +# define __acquires(x)               __attribute__((context(x,0,1)))
> > +# define __cond_acquires(x)  __attribute__((context(x,0,-1)))
> > +# define __releases(x)               __attribute__((context(x,1,0)))
> > +# define __acquire(x)                __context__(x,1)
> > +# define __release(x)                __context__(x,-1)
> > +# define __cond_lock(x, c)   ((c) ? ({ __acquire(x); 1; }) : 0)
>
> If support for Clang thread-safety attributes is added, an important
> question is what to do with the sparse context attribute. I think that
> more developers are working on improving and maintaining Clang than
> sparse. How about reducing the workload of kernel maintainers by
> only supporting the Clang thread-safety approach and by dropping support
> for the sparse context attribute?

My 2c: I think Sparse's context tracking is a subset, and generally
less complete, favoring false negatives over false positives (also
does not support guarded_by).
So in theory they can co-exist.
In practice, I agree, there will be issues with maintaining both,
because there will always be some odd corner-case which doesn't quite
work with one or the other (specifically Sparse is happy to auto-infer
acquired and released capabilities/contexts of functions and doesn't
warn you if you still hold a lock when returning from a function).

I'd be in favor of deprecating Sparse's context tracking support,
should there be consensus on that.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6by9Kp0rf%3Dihwj_3j6AW%2B5aSm6L3LZ4NEW7uvBAV02Q%40mail.gmail.com.
