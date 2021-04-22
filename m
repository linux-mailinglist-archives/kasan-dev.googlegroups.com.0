Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBM2Q6CAMGQE6GR3NTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 62B7236871C
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 21:22:46 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id l61-20020a0c84430000b02901a9a7e363edsf8279630qva.16
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:22:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619119365; cv=pass;
        d=google.com; s=arc-20160816;
        b=zHDiWuBu4WiG2xW2nLFhT9IEm4jPdnesHp/61W48FKAR5jOTC+DvgmZh7yjFzO995L
         FB2IdBR3VqHeQ4cj3VdX3I4HooqG71sGOJD/x6HwpLdunbd+UvBYAgdQB5BqzTbtHWpU
         c+WaazXqpFIG/rfdpxXEvQ8nO5eLJjIhPIP+Jj1b4OsQmmlipVp6OYqMrosVD+A/D2SZ
         xB+x7Qll0TQ2H/V6cJDxseQvn6n6584iM7vrHM6oOOjqgQ0XKeXHl+N/9y9rx9qPKDR7
         Hjv3oT3IbFDHsKhGLFfWa/W7VHJEPpa7TvSmi+wB8a8uBP4mnMDwEmQEnaLWrFdohKA3
         8jxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tee+attYuxJ+VBToVqtBMl8jyZv7Q4t1YzR9RuOKBI0=;
        b=qgLphcGgrRZNy9I/1ot0osDsHvoE3dl+iPJHC75V/oP6zPAZr/eU77m1rt2oB/eVt4
         QWVEuJsQeRBwKfwWc3SJ4JlDhyaaW93FBKgyY1RhKZMANyYVfShui4JYHYlvLRKlZ17k
         0XF6bV5ZIIdnKuMDzFu+z+NOW7dJj1hJY2zgGGdWegOJyUkhEwXDhALheLm0HeqSzk1k
         ssdnAbXOkUArobW6A8R9KQvylwdsYRO7YOwy9nHMoqKtIAsudhKsrl8UOckX6xV+AqO5
         xbTkVdmTgyhdbsaap24kmexOkH4zlX3HJrLQSL5m4OqFLfMwsZRs5nKKp4+UfV0KxH2z
         MgIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IuMg6mQe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tee+attYuxJ+VBToVqtBMl8jyZv7Q4t1YzR9RuOKBI0=;
        b=lNAYlRJYQ7kKMLa/VkTndqnjB8Bfo12t4vrib1mqrvhaJ5hGjld4PLeExito0/ajJU
         uc2dUcnnG2HCpPUFdPrZDrENka1PgBJ4dYKkFEuG9DL1e4cvOgyal5DjjGXcEn+XIkHX
         ULx3gm0iOFhD/oDU6KoQYefNdn3VujqyAbvjqwEpgenv2AoqiLECE4c2LD6n71exZ5gp
         7nf+a4BVW7dx4CNYDVhQVFp6vpSiuxjAqy5uzMUr4sOXdOShrRUWysqoeH0aajN/OhW0
         xgZTVEzMNGMAdd/uTK0zjqU7VwqnyHAlQhY24dtzDv7guiQCqa+6pP2ussvVHjs24nnP
         a/HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tee+attYuxJ+VBToVqtBMl8jyZv7Q4t1YzR9RuOKBI0=;
        b=Sjz3GhTLM0ymWy8mhbkKCJH6jLr6IYzit+i/uAi9spFF6IAowvJFUYALshR5d3xZM7
         +kCyjTM7LywBtDzfn18k3m01UfFnAnT0C1DidAiKMwcPNZYXGDw/kBAIz/Mn4kC7OfX+
         kAJJWPdscLQ73Tog2tLmUbdC0pnk9/GbZlaUR481Sz59hl5PhLE0RN7xIO8iH7n8XG3P
         B8d2DHopr0p4UYQ2JM0edC8j2TsXzZv4HOl2iql0cKZbk07mMH1yxDdJaNzduIoKIFqx
         9xSbcf8XcKjL70U9qkGQ5nw75DhZ0ygZmHmTckX1GA+ZzOV4ZDzKL/I0KVWhxtYGc+wp
         eaFg==
X-Gm-Message-State: AOAM531skkaDUVssf3F5OWrGCwCs2eeOfIoPrFdqVnct6A8pSh8AIJo/
	0E2COjSoQD1X93VSXBX1ie4=
X-Google-Smtp-Source: ABdhPJwnYg7wbIHMy6XVaUufVSyXG0Y+CYW5uOgLj7MAE4ujDY03Bs+BKSZWySbjGDP4/VZNLRyprg==
X-Received: by 2002:ac8:7c56:: with SMTP id o22mr19171qtv.133.1619119365152;
        Thu, 22 Apr 2021 12:22:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d91:: with SMTP id 139ls3674042qkn.11.gmail; Thu, 22 Apr
 2021 12:22:44 -0700 (PDT)
X-Received: by 2002:a05:620a:e1a:: with SMTP id y26mr338438qkm.280.1619119364708;
        Thu, 22 Apr 2021 12:22:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619119364; cv=none;
        d=google.com; s=arc-20160816;
        b=Ns+HY92YNQTze8pXJZdGu1jlfKk0yrKyPEZKihzrVGqvvb2Po9VTuhyuLewB9g9Cbf
         PEg0Yp+1Q6zLs/9/T9nW95gMU4Q1ir48XaGwbrJIgYRYWj6wJskVL702h+XwLhVU/ZU8
         vj4PbG3mq1BQ0eUojbhnDyYK3EQ0BmhL3J+lvi2Fy8fnYrEwmyxxTXxWWOzFVh1+Eqx4
         wUiCuS/msL4x09YZZThptj6SRJqZ+YuTJby9Dwzf416k4zsQcsMu4ZPZQu/R93dGI7wC
         7Y6XEBy8TA8L59WX+P27ZV4QbWztCmMzWIKXPtD7Zg/DzHPVB+5A1y8Eadxy2QhUGIyp
         IumQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=66cEbil9eINHpcRrkzmgQxcSDhUEl5mJfXPxp3tOEXI=;
        b=JMsZnWip7jkMDCmRqf4lZpNRh33JF2LNeN9MeSChqpjDczt7Pv6UEFb94RET/ws68d
         5iXs3LGgNBP7WBWlZjTA6GyFgHCY+v2Va2a9p1gfp9TKVYIXS17ZbIw/Wdpzjs3Bq32N
         DkCvTeTseQ99cJLBMMThA8xCYm2VLZjE1tzfaoXGWYZfXoPRbW7Fa3nTsZAW0YM46dtO
         D85MB1dK5bt+HbwaLdpLyfcj8PmDvaBOvHoakpbxIcsKYO7Mg3T9j645WL4GDq90/BKb
         FPt+nbEHDaE74G2QszENisyJwbmx9jn0dg5cx3gNyHz3sbU6qOlZ8uqP4B1RhIDh1WuA
         2wxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IuMg6mQe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id s65si683313qkc.2.2021.04.22.12.22.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 12:22:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id e89-20020a9d01e20000b0290294134181aeso17416201ote.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 12:22:44 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr83098otn.233.1619119364007;
 Thu, 22 Apr 2021 12:22:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210422064437.3577327-1-elver@google.com> <d480a4f56d544fb98eb1cdd62f44ae91@AcuMS.aculab.com>
 <CANpmjNNjkQdziFZDkPy5EnwCF+VyBWKXEwCDgNpxHGZd+BLQag@mail.gmail.com>
In-Reply-To: <CANpmjNNjkQdziFZDkPy5EnwCF+VyBWKXEwCDgNpxHGZd+BLQag@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 21:22:31 +0200
Message-ID: <CANpmjNNHRmaxawVKNe8Oe=pnEgoJG6iqevHNJRa4EoeFtS5fYQ@mail.gmail.com>
Subject: Re: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
To: David Laight <David.Laight@aculab.com>
Cc: "peterz@infradead.org" <peterz@infradead.org>, "mingo@redhat.com" <mingo@redhat.com>, 
	"tglx@linutronix.de" <tglx@linutronix.de>, "m.szyprowski@samsung.com" <m.szyprowski@samsung.com>, 
	"jonathanh@nvidia.com" <jonathanh@nvidia.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"glider@google.com" <glider@google.com>, "arnd@arndb.de" <arnd@arndb.de>, 
	"christian@brauner.io" <christian@brauner.io>, "axboe@kernel.dk" <axboe@kernel.dk>, 
	"pcc@google.com" <pcc@google.com>, "oleg@redhat.com" <oleg@redhat.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IuMg6mQe;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Thu, 22 Apr 2021 at 12:17, Marco Elver <elver@google.com> wrote:
> On Thu, 22 Apr 2021 at 11:48, David Laight <David.Laight@aculab.com> wrote:
> >
> > From: Marco Elver
> > > Sent: 22 April 2021 07:45
> > >
> > > On some architectures, like Arm, the alignment of a structure is that of
> > > its largest member.
> >
> > That is true everywhere.
> > (Apart from obscure ABI where structure have at least 4 byte alignment!)
>
> For instance, x86 didn't complain, nor did m68k. Both of them have
> compile-time checks for the layout (I'm adding those for Arm
> elsewhere).
[...]
> > Much as I hate __packed, you could add __packed to the
> > definition of the structure member _perf.
> > The compiler will remove the padding before it and will
> > assume it has the alignment of the previous item.
> >
> > So it will never use byte accesses.
>
> Sure __packed works for Arm. But I think there's no precedent using
> this on siginfo_t, possibly for good reasons? I simply can't find
> evidence that this is portable on *all* architectures and for *all*
> possible definitions of siginfo_t, including those that live in things
> like glibc.
>
> Can we confirm that __packed is fine to add to siginfo_t on *all*
> architectures for *all* possible definitions of siginfo_t? I currently
> can't. And given it's outside the scope of the C standard (as of C11
> we got _Alignas, but that doesn't help I think), I'd vote to not
> venture too far for code that should be portable especially things as
> important as siginfo_t, and has definitions *outside* the kernel (I
> know we do lots of non-standard things, but others might not).

After thinking about this all afternoon, you convinced me that the
commit message wasn't great, and this should be in the commit message,
too: https://lkml.kernel.org/r/20210422191823.79012-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNHRmaxawVKNe8Oe%3DpnEgoJG6iqevHNJRa4EoeFtS5fYQ%40mail.gmail.com.
