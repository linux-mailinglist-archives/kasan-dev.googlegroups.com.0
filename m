Return-Path: <kasan-dev+bncBCF5XGNWYQBRBA6KRDYQKGQEFFSOHJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 084001412B9
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 22:20:05 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id m18sf13902615otp.20
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:20:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579296004; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPFWSLQkxkYsyjXsXpM4WAms5do85syRgZhBdpRti7lA/nsxbJaFJ0xznwRNOEU27M
         hQ9ZCc9X8BOmS2HuvP4bVxW1AtSilO12iFf4dYswfmiqSo916g3YFD0FvP5i2tbOan1T
         qrEIxKS9RQ5vQO0CHic0M0ruj0XTRGqLT3IwaMAVEB603uZRm4DFGQZcTRx2V0Ef9vfQ
         5c/GMELKdc4+icovJ+arU1sCdR4LFk/qs1bXHsEchRhxKvz1WGypkyqEP10+DX1jQf+e
         mHE3Aq9DdUBzvjr+fP41dZqpG+bvNtR+TzZFa4NMu971B6gwAovlsgUsAet1vWCXewOx
         PBxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Q77sAA/dnbzwJWT8VDi/CbwSgBKKUl/J8npYQRpXlwg=;
        b=WYbdehXbQ75c5ShM93OpJ783RUtJYE5gy4m4vt2WMnm0V1k2vBueNLQRxeOY80yj6y
         E4Nu1Y6eZkwSMVyw5LPB3Z89AdAfcje8QJLBrirVzVDTPCY7x+HrCU0bI9h21tY+V0TL
         0h6+U/R1QFxTJF4uL1sUtuMhvtLs6JGEwLsyNob7oDNKEKNkrLJQhx1VG9VVslQCwpKn
         UYFx4jw04IylfJqDneTlTApCiSi7NjLEXGT77v1PFFyaNLLHDqRfelYgXJpThbVRFzmh
         67Ov4lrL5ABuciPKnYbgpU8FvUSRbpCWODC4OQdxqvU/PNMGLdGDG7eZ/342bPE2Shjl
         d3xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IjpQ6Aru;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q77sAA/dnbzwJWT8VDi/CbwSgBKKUl/J8npYQRpXlwg=;
        b=WjlYs1xNnV+6wUeSMvSPAbe+q4YTQlA+ldi1u4LTBJohWQKwOL2ripR2gGPy9MyZXv
         qg0iutJMPFo2TC2CaM6aCPN5q55+7Jfe3/eAMN4TJNyfUuOQwYiK8bgCyVN1H0ULMIhN
         AdU87M6xrWlayKoiW4YxipNxrEjY3qxwS/TMemKJdPlBDcSyFsOmt0ot1fe1lIInDaU7
         XhExnJ7Q/Vs/O4qMuz6n2SxQhxYvQZKDewcRa7eXpCpeFhSlPJqehEqcwoqLbzX5qlGL
         B4lp5iLK4JNn21JGsCJS9K3joE5oIJMr8JXeMXvY5mqgWKGcy/lwOlF+as3rDwcww5SH
         Vl+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q77sAA/dnbzwJWT8VDi/CbwSgBKKUl/J8npYQRpXlwg=;
        b=XByPrYMHUomjkvDx0GImyb6lS5MyZShmgg4E5JzvD8x9hkeIvklA07ZCzpZfEIGV7S
         rzUcT+7Y++4M3UhpkjnVClpUX3GFIficCPh9M1iZp0waFah/VVILMOQ0MFm1cPIVCg2W
         wxd2dxMm9344q1vZ5G2LeMGfNmBgdjiXYzlwrJluvO/xTSvOv8qmp9BvE/diDUVuU1KB
         65JrRPFiHJG6qfYuHhQ2x4rOBlUCnLnYZGZZusJ0XmkUpuxEwAnyD08AIHY1CgdYrne8
         hG4DamHOA/M10YCa38XlFQGXEYf596YpmMpnc29MaM9UxMk//tJosiHXUuPk62cD0qmg
         BuVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtcWfTwA9EmoKGpc6+thVNhoBLA6zU7kKaH1l31+GLkJvwpMmA
	fTU9zSn6qGIhqhxLxLtGZO0=
X-Google-Smtp-Source: APXvYqw3MCM5nMstPrK2uSZWXofdbI5TWoHWcFCw34liihYwwle5NFgw0Re3W9+N68z9U71rKIivww==
X-Received: by 2002:a05:6830:c2:: with SMTP id x2mr7788019oto.8.1579296003883;
        Fri, 17 Jan 2020 13:20:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c694:: with SMTP id w142ls4871881oif.6.gmail; Fri, 17
 Jan 2020 13:20:03 -0800 (PST)
X-Received: by 2002:aca:ec50:: with SMTP id k77mr5051614oih.114.1579296003490;
        Fri, 17 Jan 2020 13:20:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579296003; cv=none;
        d=google.com; s=arc-20160816;
        b=0Jts8ZEuevZ19Z/DL6LQpy1sd348Ctu0YshlIQE/EvNOi3oN9w4MdMnRt4hhT/4bw3
         /bMrQjJFn/oHNfg8AxFeOVcpFzVvImim8w5exEn3IifKlhpijtvtUBwY1WTBeL3g/fxb
         D26qrHWQ1hx0ngo//cXM1YNrAFGJDmLf1eLeU7UdBGI5kliJQrznig5q/hiOwxwJVqhU
         FjDeom6go2hdBMVwqv/nF/bk3ZveLZuq2eJAXU6FsgAiR14J7d6FKnLmURnkNtgvdDsB
         B7JU0tL7MXt+DStIaZyooYo94Q71c4x9ujWv2fgCT5SWl1OBjhRwkKzzsgxKvioQ/eEu
         PGnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0ov/MSAN6f4SPopx5kOpmENhTI+79DbFyHl+2GkJMEA=;
        b=zpb+Tgb8sCOp6Us/RH4XfaJcAR6wjxnQeb+JbEaHFAqB9J5pa98s7MwF3WKwCp/cG/
         Ddd7bvOCXLWs6EWxXzbCMjmYCvpmIOVBnIG2mIh9eGhObE5BZDMPqkDVILJaPo7VBhVj
         VnoxrhvU3XvRuKJHtc1W66DKFQQ1vc6te15m5fI0LmUWLEesib56G2NabHlRueugQfeJ
         zevIc7wBKhibLxwPvA4Ns0DJ5X7gfXEducI52SC+u0KxZbmRnUD52XHnDOlJHMN9zpGD
         oKggUAbZuztV464rGeT+5OfwweyxMTzJ7BY6nbQ0VUI/I/fqpOwzS7b0ig2zzXQcxtha
         DWwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IjpQ6Aru;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id d16si1222079oij.1.2020.01.17.13.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 13:20:03 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id d15so3694097pjw.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 13:20:03 -0800 (PST)
X-Received: by 2002:a17:902:b401:: with SMTP id x1mr1280965plr.326.1579296002758;
        Fri, 17 Jan 2020 13:20:02 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id w11sm29039174pfn.4.2020.01.17.13.20.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 13:20:01 -0800 (PST)
Date: Fri, 17 Jan 2020 13:20:00 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>,
	kernel-hardening@lists.openwall.com,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: [PATCH v3 5/6] kasan: Unset panic_on_warn before calling panic()
Message-ID: <202001171317.5E3C106F@keescook>
References: <20200116012321.26254-1-keescook@chromium.org>
 <20200116012321.26254-6-keescook@chromium.org>
 <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com>
 <202001161548.9E126B774F@keescook>
 <CACT4Y+Z9o4B37-sNU2582FBv_2+evgyKVbVo-OAufLrsney=wA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z9o4B37-sNU2582FBv_2+evgyKVbVo-OAufLrsney=wA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=IjpQ6Aru;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Jan 17, 2020 at 10:54:36AM +0100, Dmitry Vyukov wrote:
> On Fri, Jan 17, 2020 at 12:49 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > On Thu, Jan 16, 2020 at 06:23:01AM +0100, Dmitry Vyukov wrote:
> > > On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
> > > >
> > > > As done in the full WARN() handler, panic_on_warn needs to be cleared
> > > > before calling panic() to avoid recursive panics.
> > > >
> > > > Signed-off-by: Kees Cook <keescook@chromium.org>
> > > > ---
> > > >  mm/kasan/report.c | 10 +++++++++-
> > > >  1 file changed, 9 insertions(+), 1 deletion(-)
> > > >
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 621782100eaa..844554e78893 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
> > > >         pr_err("==================================================================\n");
> > > >         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> > > >         spin_unlock_irqrestore(&report_lock, *flags);
> > > > -       if (panic_on_warn)
> > > > +       if (panic_on_warn) {
> > > > +               /*
> > > > +                * This thread may hit another WARN() in the panic path.
> > > > +                * Resetting this prevents additional WARN() from panicking the
> > > > +                * system on this thread.  Other threads are blocked by the
> > > > +                * panic_mutex in panic().
> > >
> > > I don't understand part about other threads.
> > > Other threads are not necessary inside of panic(). And in fact since
> > > we reset panic_on_warn, they will not get there even if they should.
> > > If I am reading this correctly, once one thread prints a warning and
> > > is going to panic, other threads may now print infinite amounts of
> > > warning and proceed past them freely. Why is this the behavior we
> > > want?
> >
> > AIUI, the issue is the current thread hitting another WARN and blocking
> > on trying to call panic again. WARNs encountered during the execution of
> > panic() need to not attempt to call panic() again.
> 
> Yes, but the variable is global and affects other threads and the
> comment talks about other threads, and that's the part I am confused
> about (for both comment wording and the actual behavior). For the
> "same thread hitting another warning" case we need a per-task flag or
> something.

This is duplicating the common panic-on-warn logic (see the generic bug
code), so I'd like to just have the same behavior between the three
implementations of panic-on-warn (generic bug, kasan, ubsan), and then
work to merge them into a common handler, and then perhaps fix the
details of the behavior. I think it's more correct to allow the panicing
thread to complete than to care about what the other threads are doing.
Right now, a WARN within the panic code will either a) hang the machine,
or b) not panic, allowing the rest of the threads to continue, maybe
then hitting other WARNs and hanging. The generic bug code does not
suffer from this.

-Kees

> 
> > -Kees
> >
> > >
> > > > +                */
> > > > +               panic_on_warn = 0;
> > > >                 panic("panic_on_warn set ...\n");
> > > > +       }
> > > >         kasan_enable_current();
> > > >  }
> >
> > --
> > Kees Cook

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202001171317.5E3C106F%40keescook.
