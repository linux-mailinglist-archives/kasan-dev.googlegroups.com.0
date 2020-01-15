Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHW7XYAKGQEZ2C325A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1778C13CE41
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 21:50:22 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id e128sf20683758ywc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 12:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579121420; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdUjbzo3i3PV+oqWqfIq2impI0/rnnalC3Kf+lBY1vTByUpfepbFJR9047dazNakLu
         riMEN0/XoecV07piiqv9mWGKCRTPKtvdwfXM3gpC6+WsKRZJw0nx3kx+ayNjmLdY0PlY
         PXFA4ZswQNy/o+yPDn5sFlAI/wQRvUe+huX+iAhSrmTCb/WoJDsUd8ziTtrlcFqGWAlH
         COPf+G7UrTGf1YU2Arwr0VJHCJEpr+3k29SA8wf6oZT2XeOHn3GVEpGStdCqVSfCZfkU
         8GjFTPyMtkL1cyhAPAvzB/0Vpx9G7jDPIp0KPGwYBDnDfmLn1QuA7mFV4SYt35DQu8Zh
         7V8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gF2BjQvjghwmvgnJlR+aqwJTJy5WX5J+gk0XnFIJUI4=;
        b=VA6Cn2wAnuRDTd9PG0qtCTRCDgZy3VlLLtJycNryxP/Y5e5ZC++qxrmz/CYI108W2c
         RMnL+I6xVr14utGGCt8mqQxZVW4pH4vSmWx52zVpZlkO8HlXyvCt/toW2L7EWxsUHLog
         ZxyYOOYxLAjiQcbudWZGYM+tEOX4JXw3IfSYOTGidR1eqM3EY1fw6Fu1yQs1Tf3dtU72
         U96kGcmG8diukRs5c0F2eOjmJWrC9yg6pO+wcPKfrgPlpDwp/cUA0+wxFijWL5vcaPGq
         8ZitJEeXCZk4tI9XhxF/N0jnT+XxqXM0PywYqKZ3ncZRZ2AzeALvgCHC+CoBeb3kmtXV
         xcHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RME5cH1b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF2BjQvjghwmvgnJlR+aqwJTJy5WX5J+gk0XnFIJUI4=;
        b=e5Iif9MYF18+zB0ogjL1+H0r1ggmuJRtgIKqiXBzCU9tC8cROgksqLF5D66pdTsLL/
         A3WoZhzB6Yes9BHv0VrDXJqHz16XfYCZL2YURlQ+u/6KSpSqkwb6Ipij+WhiYjgtoDX7
         cvxnEX+e601iFmvkRQHWg07ADUv+17BPD3rK9rQx+Jp5ms8gF2fY3I+uVIoIxlER3GlA
         4Rcs3v1EWIRvj3P1TUflk/oF4En+usMxs5jL44M+4b86w0NNy+cr9Pg/008OBgO15d6A
         NSDamfakMkpfePyoD5q288q3PrSr21tYZN5NgDG9qu7RB9Eoueazna7HZUyvHKXyS3AL
         trJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF2BjQvjghwmvgnJlR+aqwJTJy5WX5J+gk0XnFIJUI4=;
        b=TkbdExR1L8gsJyeNETYwrKM/vHvpG2Gstm93X/mVKq36imuu/4r8rq8z0XVgQRxMTT
         VkQ3hKTROzqH3Bb07/zzr/f/CHhmjO69N5PGmwdVvo1B1cG/48AEiNsvJg4kOD/Mhfp4
         sb5XijxZi5hKHc+RxbhtYjT3f+7HNTPELgQPD2xuAMdmVmRAFDVbfHSptMxOaydr69UR
         6fFns6Ug2lPFTn2Hap8Hss3tSGNJ0vzm2SvNjXJFBzV488zXt3qwxfakpGxSvnUc2iLk
         nlT6Pk93d317VDDohsOaWTxiEcYYqe1PREjIDBCq0ShPLoJWf9qlDWN8hUiv2uqJYMLi
         qWsw==
X-Gm-Message-State: APjAAAXOxc4JrBnagBBco0BPGqxs5Hul4up0aBZ9SIb2j4feztkhYrcv
	KLW6SEyj92+FYjdijj4g9tM=
X-Google-Smtp-Source: APXvYqxeQJZbO2nFjruqEtAksfVXaCllWcpDZPvKx0txpN2lvqfh8nKkmO9X6OHtRytWTypBbwu4QQ==
X-Received: by 2002:a25:cf81:: with SMTP id f123mr22034297ybg.444.1579121420681;
        Wed, 15 Jan 2020 12:50:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d08f:: with SMTP id h137ls3208452ybg.10.gmail; Wed, 15
 Jan 2020 12:50:20 -0800 (PST)
X-Received: by 2002:a25:6a83:: with SMTP id f125mr347161ybc.212.1579121420277;
        Wed, 15 Jan 2020 12:50:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579121420; cv=none;
        d=google.com; s=arc-20160816;
        b=A1+KcKLHt4vBQS6kZYIPP6WbwA7dJgTOdpQtcprNjx9dATOqVRAKooF6598JVfhoI8
         rcsyn1fOe17V4ecMJ8FL5kbhBKoVC0LiDbtE3UEMACEgFApfXF+0y1k6pkewaD2fcT79
         DZt6g7r4b6r5XuviATJxWPHMCmjz6TZIt+xBDDe9G4O6UK61ExgbVHjSlVp/5f/Xdtff
         i99OnqQQTq2cFhYebHH3CL6kwP5tmjuXch+eY00KrS5Jm6K63rnQPm0dtCYuZJiJu0/6
         3PpvL8EZkFgSaiahsux0cwn7Mgae07zxsKcyuZ0+mGq/yAzmBrev5qoi3Hn3mMcSe3m1
         481w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/0hOUZCXUZrxkCJ9AqKR7AVN+IgQDsfD1fDkF1X5WSk=;
        b=XNH/GL2jR4Rhe1U7QmK7Kwmh0Ejh8d6wdbzFv7U9+Imor+abNO0x9+DOwZj/gVqMlL
         obL3PGiyktoc9nHGssJ2DJNtsrfyRtWfqQbNZR8x46DgXv9xroPjPJJIvuHMBg0lJosw
         qRIWX2butU61Hx4TNlC8S3pwwP2lQDjsl6TQrR4GRWS/Sx/ntOgHVEyyMQQnEiE4O3sa
         jWtA6RItQWYHOXeRYjTrsYzkA0LKTpdXTpOTUy/OayADD3oVC5Gwx00/KorqhGdxwBvu
         f1LkADCElJAHU3ifuzmM0aWekip1No5m8bT31hnvvWDDp53TPAdWIbzzJN5Rmn61sUi9
         F1HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RME5cH1b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y3si918024ybg.3.2020.01.15.12.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 12:50:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id i15so17367360oto.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 12:50:20 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr4203681otk.23.1579121419529;
 Wed, 15 Jan 2020 12:50:19 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com> <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
In-Reply-To: <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 21:50:08 +0100
Message-ID: <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RME5cH1b;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 15 Jan 2020 at 20:55, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, Jan 15, 2020 at 8:51 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
> > >
> > > On Wed, Jan 15, 2020 at 5:58 PM Marco Elver <elver@google.com> wrote:
> > > >   * set_bit - Atomically set a bit in memory
> > > > @@ -26,6 +27,7 @@
> > > >  static inline void set_bit(long nr, volatile unsigned long *addr)
> > > >  {
> > > >         kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> > > > +       kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
> > > >         arch_set_bit(nr, addr);
> > > >  }
> > >
> > > It looks like you add a kcsan_check_atomic_write or kcsan_check_write directly
> > > next to almost any instance of kasan_check_write().
> > >
> > > Are there any cases where we actually just need one of the two but not the
> > > other? If not, maybe it's better to rename the macro and have it do both things
> > > as needed?
> >
> > Do you mean adding an inline helper at the top of each bitops header
> > here, similar to what we did for atomic-instrumented?  Happy to do
> > that if it improves readability.
>
> I was thinking of treewide wrappers, given that there are only a couple of files
> calling kasan_check_write():
>
> $ git grep -wl kasan_check_write
> arch/arm64/include/asm/barrier.h
> arch/arm64/include/asm/uaccess.h
> arch/x86/include/asm/uaccess_64.h
> include/asm-generic/atomic-instrumented.h
> include/asm-generic/bitops/instrumented-atomic.h
> include/asm-generic/bitops/instrumented-lock.h
> include/asm-generic/bitops/instrumented-non-atomic.h
> include/linux/kasan-checks.h
> include/linux/uaccess.h
> lib/iov_iter.c
> lib/strncpy_from_user.c
> lib/usercopy.c
> scripts/atomic/gen-atomic-instrumented.sh
>
> Are there any that really just want kasan_check_write() but not one
> of the kcsan checks?

If I understood correctly, this suggestion would amount to introducing
a new header, e.g. 'ksan-checks.h', that provides unified generic
checks. For completeness, we will also need to consider reads. Since
KCSAN provides 4 check variants ({read,write} x {plain,atomic}), we
will need 4 generic check variants.

I certainly do not feel comfortable blindly introducing kcsan_checks
in all places where we have kasan_checks, but it may be worthwhile
adding this infrastructure and starting with atomic-instrumented and
bitops-instrumented wrappers. The other locations you list above would
need to be evaluated on a case-by-case basis to check if we want to
report data races for those accesses.

As a minor data point, {READ,WRITE}_ONCE in compiler.h currently only
has kcsan_checks and not kasan_checks.

My personal preference would be to keep the various checks explicit,
clearly opting into either KCSAN and/or KASAN. Since I do not think
it's obvious if we want both for the existing and potentially new
locations (in future), the potential for error by blindly using a
generic 'ksan_check' appears worse than potentially adding a dozen
lines or so.

Let me know if you'd like to proceed with 'ksan-checks.h'.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMk2HbuvmN1RaZ%3D8OV%2Btx9qZwKyRySONDRQar6RCGM1SA%40mail.gmail.com.
