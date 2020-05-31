Return-Path: <kasan-dev+bncBCMIZB7QWENRBHXTZX3AKGQELBT2SSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A90B31E9693
	for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 11:32:15 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id d23sf1301846ilg.10
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 02:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590917534; cv=pass;
        d=google.com; s=arc-20160816;
        b=TiQXDdtkgM72QDTd0wD9AhHrTTHeMrSE2IzhitlDIw3hPRQ2XrvNBwXMlqdspg5tmT
         kQ6qbdJgDJuL9qPnKCtAyEmlIl5GWrIs3ZcGbxBiy1BeIczOJyU1lvu7ZL+ITyJ6ttRM
         a6EYfqVt3f0nbMeSw8kxktTx7l5gh5VWlzKN98ieuTDPTraP69C0vUcbA5BP+KEPK5oQ
         7u2oAMQsK+JjuXFYOynXe9574yqgAUAyCf1H+RY63rGPnXcZX/a1DwdReaOCJB+16kVY
         M5PiqaBGTgO3iJMRNILQ5QbZfXapTPmxJuXLYf9siLwWYRokROZSGptGwr4ax+YzzOGv
         Z8Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j4ZzK/yWSMXBfJj6p+xN6IRyLdhd/v2vuMaCuCvX2T4=;
        b=wWbWrt/2T88KITG0LfnJnto0jV9inTDErQKlCaex8X2aIX92/LDeVz2JWNemAUGuCc
         67MMWQTE5gdEU2ZNJZ4Ciy2bJqVS+AezRSt5pP/Kfp4UQolK0zfJQartDjGU+mpg84LM
         DgL45nGE4LBKHRzRci/khVS714EWSKJCY9GRyE9hmDnB8GeB/5AoHVpbzqC0bwznUIZT
         GnYrbq6OPwjt0cpQ0zJxiGrSOFWyaDPIU55WzKdtBbJtgtD1rmiizwbC/JaUC6X5H11N
         ihEYswLopB47nR9lOqsSkTdQyAnLzODCzKfR+/BLdm4nhzuZ7qUtPaQU9KNvl++G5lc9
         XBWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xw7LhJ3V;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4ZzK/yWSMXBfJj6p+xN6IRyLdhd/v2vuMaCuCvX2T4=;
        b=EJZNAjPAtgBGTOYz6WxAqlC/DkfSD5GVCmF584fC8LwVq1Dzg/fuhRtgGeKThjh5TK
         1r/dtdwFPjS/FZQllUxCBWgK37vakgzneY8gs370mY3EzWw7ZzZui2mvqHgvLAsNHlu7
         i9gUmg+5laW6N/M6gOlqOM8hPs1kvf1+rENToCOHns1ldck3+JQTLQAhJAZqMubRCe2N
         nzoEDcdOnIA3qSEEf+yCuolCy0iceS/lIqCdRp1wSZyw5kO6WpxmtVYym2CP915P/m03
         +1PeluMDYpmctvDE+VLCMyuslTw2/c3YJcxVf3vkuGrmQNt+smxt7x6gKV1WRRqiaGtF
         FANA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4ZzK/yWSMXBfJj6p+xN6IRyLdhd/v2vuMaCuCvX2T4=;
        b=GIIe8NduUUQRGnkNpHdKGLEYhEWezz96sUQN5fKAat36ms5YUSO0LZLSU+f8HUVn1y
         34IbQm2EIa0rGBckLuO7Zlcw+tDuo2Vxivvv3/v3yQ09A8hQFx7xJz9t2U8QgKfy87jk
         bdhAkujHsB4vBnpXhFDC7lkQI7/A03mq64dEgODFuGtbDjOhI5FQuSXM81E/erRawwiG
         nlsVc8n1N3uIiSn8MRBwxk1UaJW82Dxk+uIMggJEYiali7jyKZ/SKmdtX0JCbwHoVK/E
         /msaU/TbYG6iSh3b2Cew9aL92TyQrH5HQ09O6yxVyNQaZCijDm+E5dHMbwAJUyWcdswS
         htRA==
X-Gm-Message-State: AOAM533NphKIY+iH0lQkziBz92vc5ytNaMRD5tZyio1SenhUgTVzWE63
	NM9K6YXY9lbZVoAUc+h9Uoc=
X-Google-Smtp-Source: ABdhPJzp2aIx/LG2m5kTgiF7ZH62RQKyDdutL8UAjMPE35gboCmUKgEGiJdOinmiZIFiutblP0JiZw==
X-Received: by 2002:a05:6e02:11a5:: with SMTP id 5mr16267994ilj.108.1590917534636;
        Sun, 31 May 2020 02:32:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9108:: with SMTP id t8ls2794786ild.3.gmail; Sun, 31 May
 2020 02:32:14 -0700 (PDT)
X-Received: by 2002:a92:894e:: with SMTP id n75mr15898189ild.271.1590917534358;
        Sun, 31 May 2020 02:32:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590917534; cv=none;
        d=google.com; s=arc-20160816;
        b=yVUttu5GP+H0tmsDNed2Qu2lEmJNVsq4IcLF6Q9EN+bTuo5SQ81aT+zviPwwVY3e3O
         mNQhOV7o+Qfpno/FQvQPbfSgrCe18f1pGKDO+9lKAsKNwrxQNiAKajgKI4bod3tbbIWP
         kD4fQEUGf9LX6R0DLZFKFyHOv5M+RGr1ICQ+588E0j2bhqpLbDZA81yiFJS2CtmytZzI
         nfBZ0KktVhZ1Qr9uoBedOAsObEEwHOmOlCR7iWdFvdM2KkvnBHxSiaPV/zqNyOKH53gX
         j9Gyf+1g4TMLFUDcpTc8yLji+dPAHXdnWBx234DpZIdWiISI6ltTr5zHXRm4N5ly7AGy
         acEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BZ0Nb+D2BlnH8V9KcsWA38LcbQH/W/Hv8FyeJMQSm4E=;
        b=RndayUusl94D29Xf3CZwyt6kDwgtGZMcQmMfz1cHKI55VLm+2vJpDQ+6nDMVkmVIEU
         TpD7hYNyJm1gvDHQwLzZwdvnlhDjNMx1QOPT1cMvunfBIUGfoT6gA46smeKAXOgUS/WZ
         /5OxxhKI2Su1OHI0j+7icKZZ0JMoRdrtL4xfiOWrmiQQVGvvPIqV1K0dxgLyIustotrG
         LUbCBkBe8pnlRJOq0vrQYMfoeLcbkfdwsLPl4TN350cU9ZSXoFmkOC80F4ir7p3iC+c0
         wDSb+6doUwgfbESFdg1ycA/1dvU5fH4Pt1d3SuGSYvPNjcYenaqF5VQCHCmokvhc+OJi
         wzRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xw7LhJ3V;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id k1si631298ilr.0.2020.05.31.02.32.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 31 May 2020 02:32:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id dp10so3126082qvb.10
        for <kasan-dev@googlegroups.com>; Sun, 31 May 2020 02:32:14 -0700 (PDT)
X-Received: by 2002:a05:6214:bc5:: with SMTP id ff5mr16199847qvb.34.1590917533617;
 Sun, 31 May 2020 02:32:13 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d2474c05a6c938fe@google.com> <CACT4Y+ajjB8RmG3_H_9r-kaRAZ05ejW02-Py47o7wkkBjwup3Q@mail.gmail.com>
 <87o8q6n38p.fsf@nanos.tec.linutronix.de> <20200529160711.GC706460@hirez.programming.kicks-ass.net>
 <20200529171104.GD706518@hirez.programming.kicks-ass.net>
In-Reply-To: <20200529171104.GD706518@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 31 May 2020 11:32:02 +0200
Message-ID: <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
Subject: Re: PANIC: double fault in fixup_bad_iret
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xw7LhJ3V;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, May 29, 2020 at 7:11 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > Like with KCSAN, we should blanket kill KASAN/UBSAN and friends (at the
> > very least in arch/x86/) until they get that function attribute stuff
> > sorted.
>
> Something like so.
>
> ---
> diff --git a/arch/x86/Makefile b/arch/x86/Makefile
> index 00e378de8bc0..a90d32b87d7e 100644
> --- a/arch/x86/Makefile
> +++ b/arch/x86/Makefile
> @@ -1,6 +1,14 @@
>  # SPDX-License-Identifier: GPL-2.0
>  # Unified Makefile for i386 and x86_64
>
> +#
> +# Until such a time that __no_kasan and __no_ubsan work as expected (and are
> +# made part of noinstr), don't sanitize anything.
> +#
> +KASAN_SANITIZE := n
> +UBSAN_SANITIZE := n
> +KCOV_INSTRUMENT := n
> +
>  # select defconfig based on actual architecture
>  ifeq ($(ARCH),x86)
>    ifeq ($(shell uname -m),x86_64)

+kasan-dev
+Marco, please send a fix for this

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYB%3DJ0%2Bw7%2BSHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ%40mail.gmail.com.
