Return-Path: <kasan-dev+bncBCMIZB7QWENRBZUQQTUAKGQEPA7QM6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D1D4287D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2019 16:12:56 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id b10sf7179954pgb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2019 07:12:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560348774; cv=pass;
        d=google.com; s=arc-20160816;
        b=NM5LfLU9KddHtS/pilxoOiaxhnqp+aixO/Rdspa1naaDl6xorvWrSxJKFQzW2vinXG
         rPikG4diWdbfrC72ocow7S4PfD4moeafDcr3HrqshXbV9ZZ0OXWQBEGr0n+/h6KKLheX
         fxrL9afn0uHtdpDZ0WLX+tpn6Lh33xaYPJq1uhkbNlM4i1q3jVz63K5X05CdP1s5TSNz
         bZX/eo8vn9HJIChDG/UT8DoST5/AKlJ6G8KB7U+3PuXyL3u8TQNVScybBsHVFMpVw8kq
         U6cWUm9vAMCd8VamQpgrhJiiztx4d9YTbK22tu7w+ENHKpjU6I8R/Hdt+FmzQ/CAxS/q
         /Tjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HfWGqV+V41CACK0maUkh26XTYE23M3WgFnlgxtdsuD8=;
        b=cnosUXzHZRtt1qjydKbzg2CqE4OWM9/ynF9zvo/G2tNCDY62nG6l9U4jEsHeQ23wDE
         RylOVawE29cyFOcs975LzkKhAxFacX1eSpuVE1OdzsXG+37aoPB63aW1BL//TI82K16V
         11KH3fk4f4a4DEM/0TaORaDlxrF9ACMbo+33l1fLhL4JxFD7UPxz/C0XOGRT5AXW1YyH
         PeuCalVyj92aspwFt8tjD8GVRwuwZHztjjp1CfyTvfWXCeOFpJyy/IzThrLF+1kDSK1f
         80Q1lOdFMFhf82SHfcmXHgxDw0Qp38603K2ROZhXNMD/nV+pOMUr/S5kG5sj7az7DlKv
         9HlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RqyGGNem;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfWGqV+V41CACK0maUkh26XTYE23M3WgFnlgxtdsuD8=;
        b=TR6U3HdUj3TkHZ4tIvhzC1MQ0nnmboIGj07E8hF17fKSs6tK1QDVo7COXWUbG1mubo
         61gLSIwJulT+xmsLN1aYTVXkSBTPUn1mTs2jIr82d/nFEiJjpqkMdNu6MR6pNPq8kKlj
         ISv9uLxnHDgRZlFpapxikgYPATZkhKR9joAqGyfZNumg/HEwQRSptejv4AnRolekP0h+
         4RZuQ4a5lMxabOI+tk+spR7rwyIWbpVxTGj1zdqMBpv3bcCyOSw87WF/FkrGKN3lByPe
         TDposB83EOuJeTbpHm+sw67t+0iLdjtgZofvhe1afBB5+yuZYwCfihGdwjVfqI5cpXrE
         3m4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfWGqV+V41CACK0maUkh26XTYE23M3WgFnlgxtdsuD8=;
        b=ZpaGZY2K8WIIgfm6vSR45WK5D0wTve0FtJFzf6MeCW1yhp305R/CnoUBKdbL/vxZPO
         tAkdopsnxixLFH8j5G5dpL7Jm4HjMPx85djuePszKrslDdIigRZWeVMM+lRMZD63q5X9
         KPHfh/dLs7R4Bv9rc6b1JJleLXkwsBOPwvCZh7+DpOBKILfxNVFCie4cXAtdOdnUdJAx
         LJIBHSJwhF2vjd5+r/+eGg69LK8RD67H1ZnTByYfgcipxDgog6ulJTCyTqj7pmeuz9NN
         PeYrAg5MbrD/SUH69xSCz+FqCa2r8AbCBGBQzQZNa486Guj1FOeX5N1rEHbdoSnZVs0u
         eXbA==
X-Gm-Message-State: APjAAAX1InpCLTG0FP3r1CeRxPmifyt7+aWBDalIDHT+ToLQXJ0wQId7
	DxM0FuwQMlsPRuka66iQebw=
X-Google-Smtp-Source: APXvYqwsItUMOmVFPETznI8KM9mkyZ875ReI6vRbcFL0EdN0mRuOCvUwPMKfsdzm3eWl3eFtxkOxhw==
X-Received: by 2002:a17:90a:26ef:: with SMTP id m102mr32306846pje.50.1560348774745;
        Wed, 12 Jun 2019 07:12:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b8a:: with SMTP id b132ls558685pfb.9.gmail; Wed, 12 Jun
 2019 07:12:54 -0700 (PDT)
X-Received: by 2002:a63:3710:: with SMTP id e16mr24999766pga.391.1560348774329;
        Wed, 12 Jun 2019 07:12:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560348774; cv=none;
        d=google.com; s=arc-20160816;
        b=CUF/6Ejk0BfM/VVUVsT60+ris9EEZcfYVQQK+PjSDesr7XNUF6pQobUJyJ0WVNradV
         avyk+h8pp+3DuYSBuU7mVz1F0WY2+ZopSBmNN2iv6sXMU6/9X6gsAyi9QqGIaOJ+PPlf
         iptK+x6O0ydk9SSvlW1pRjZwak+UEC90VZmdeFH0d2rOiXwFsz2FTtIZSUwa2sBXdcpd
         vHNhWNWVD71NMS//dtOMJrwRixYqKufo58lzPZohqyoYlxP65HLGCMX+fgTIrAGBYxwK
         cn8RVbRScpUhSETUMflFOgsaq9RA094KFTiuYfTsp4APSAVpZqGgqw4SXs/c2U9utqnZ
         0OvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/fXeSKZUU3yYcblyjjUr+PT/LFbKmVa2WZrUUbFVZZ0=;
        b=D48uKMOCcfnoTvAjxyl2f8ETYLGbCTG18auNUlbi330XrwO10b/6CkX1m/TwQ1XqNE
         6LuE/qyHL2KcfahKyuMxsyNhHjCgIKYo5Z3pU2yNNoav0dr5dQccREMAIkJqMF4fE8P7
         GQWb6wKTXpM5D3tM1pFoUGpOwSzMWWj1VeAIWeyTbJd+GsKapKEOeCdwYm8Ytm3LIRbi
         vZ9LTstU9MXGi3P5UvVsTVK5xFB1O/WAadeX1Uz0RlY2WjXByy920v1lR8sgBEbAYIWd
         1KeAP8VEL7mB4R5hdeg4EPP3kWDIlSTrS3tSU7sj9I5y6DPhQV4ItctTMQi+GOsKfkIx
         4F5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RqyGGNem;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id o91si2491pje.0.2019.06.12.07.12.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Jun 2019 07:12:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id e5so13063907iok.4
        for <kasan-dev@googlegroups.com>; Wed, 12 Jun 2019 07:12:54 -0700 (PDT)
X-Received: by 2002:a6b:641a:: with SMTP id t26mr7794304iog.3.1560348773474;
 Wed, 12 Jun 2019 07:12:53 -0700 (PDT)
MIME-Version: 1.0
References: <20190531150828.157832-1-elver@google.com> <20190531150828.157832-3-elver@google.com>
 <CANpmjNP_-J5dZVtDeHUeDk2TBBkOgoPvGKq42Qd7rezbnFWNGg@mail.gmail.com>
In-Reply-To: <CANpmjNP_-J5dZVtDeHUeDk2TBBkOgoPvGKq42Qd7rezbnFWNGg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Jun 2019 16:12:29 +0200
Message-ID: <CACT4Y+a0H0NiMmydmw1qOA=zUXDmBZXHmh6-fp9nU0UtAPZvxQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] x86: Use static_cpu_has in uaccess region to avoid instrumentation
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RqyGGNem;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44
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

On Fri, Jun 7, 2019 at 11:44 AM Marco Elver <elver@google.com> wrote:
>
> Gentle ping.  I would appreciate quick feedback if this approach is reasonable.
>
> Peter: since you suggested that we should not change objtool, did you
> have a particular approach in mind that is maybe different from v2 and
> v3? Or is this what you were thinking of?
>
> Many thanks!
>
> On Fri, 31 May 2019 at 17:11, Marco Elver <elver@google.com> wrote:
> >
> > This patch is a pre-requisite for enabling KASAN bitops instrumentation;
> > using static_cpu_has instead of boot_cpu_has avoids instrumentation of
> > test_bit inside the uaccess region. With instrumentation, the KASAN
> > check would otherwise be flagged by objtool.
> >
> > For consistency, kernel/signal.c was changed to mirror this change,
> > however, is never instrumented with KASAN (currently unsupported under
> > x86 32bit).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: H. Peter Anvin <hpa@zytor.com>
> > ---
> > Changes in v3:
> > * Use static_cpu_has instead of moving boot_cpu_has outside uaccess
> >   region.
> >
> > Changes in v2:
> > * Replaces patch: 'tools/objtool: add kasan_check_* to uaccess
> >   whitelist'
> > ---
> >  arch/x86/ia32/ia32_signal.c | 2 +-
> >  arch/x86/kernel/signal.c    | 2 +-
> >  2 files changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
> > index 629d1ee05599..1cee10091b9f 100644
> > --- a/arch/x86/ia32/ia32_signal.c
> > +++ b/arch/x86/ia32/ia32_signal.c
> > @@ -358,7 +358,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
> >                 put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
> >
> >                 /* Create the ucontext.  */
> > -               if (boot_cpu_has(X86_FEATURE_XSAVE))
> > +               if (static_cpu_has(X86_FEATURE_XSAVE))


Peter Z or A, does it look good to you? Could you please Ack this?


> >                         put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
> >                 else
> >                         put_user_ex(0, &frame->uc.uc_flags);
> > diff --git a/arch/x86/kernel/signal.c b/arch/x86/kernel/signal.c
> > index 364813cea647..52eb1d551aed 100644
> > --- a/arch/x86/kernel/signal.c
> > +++ b/arch/x86/kernel/signal.c
> > @@ -391,7 +391,7 @@ static int __setup_rt_frame(int sig, struct ksignal *ksig,
> >                 put_user_ex(&frame->uc, &frame->puc);
> >
> >                 /* Create the ucontext.  */
> > -               if (boot_cpu_has(X86_FEATURE_XSAVE))
> > +               if (static_cpu_has(X86_FEATURE_XSAVE))
> >                         put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
> >                 else
> >                         put_user_ex(0, &frame->uc.uc_flags);
> > --
> > 2.22.0.rc1.257.g3120a18244-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba0H0NiMmydmw1qOA%3DzUXDmBZXHmh6-fp9nU0UtAPZvxQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
