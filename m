Return-Path: <kasan-dev+bncBCMIZB7QWENRBANJ5GPAMGQEXZZ764I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B7A156865A3
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 13:01:06 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id o24-20020a5d58d8000000b002bfe173775asf1875540wrf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 04:01:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675252866; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0G1Ducn7fbYe9C1SYjH7g0hVfHKjxi3utjos+HaPULGa95Z+LCJ51q1Hqyuj7JNjI
         rZkmvE2aLQJutJFCPB4ZzBqcCMDEV0tVRZ9v5Lq1jhIUcqi6GtKtMsMlMU6SWUtFp5+C
         /rSeEGyR95pLabIH6zJkyBaDi19B39LzyodGkuq4gJKcjsey78mvYNYmRDfqkXhQoc/v
         mYRKLpWG5cC32G8a/7shLFzNeOb2khv8o01nrmCKfaeR1sWnEberLblKE2Yp37xZjvAf
         a4aUA2ymvtxGr99J5p6pJg8uGemCUmbzOtIiO+XMJkAJQF0NPFnXCl+qGPptykH1xyJ9
         KF7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lmhPPnz5QYfUFxLL5p2I8qQZ/1hsVoJPHuO1DHOi1aw=;
        b=t34mHDPax7a0gwIGQ+5XuC2SeF4xiAhHc+NX72FPMUeDUOihEmAPTYGkiW+9Vjj2rY
         tSwDGOLEe2sOAIvRNrzbs8QfwmrTN2P8LAGntZLf9JUZwlopzA3jZGD1iVWC9hJpwJ8A
         XEZSRCQsYUxJU20e0mpTBNKD6Z84sFIiFNwF/8iGAS/Tzf3yMZ/FwwrWYcd4Z9cfNJAy
         OGHuKA2kYv31AYZMVDdy9SN+/fURkiJqrBhePptlXaZkSU2IbiSghZaUWX5y5hcdYzWD
         aUFxDFDuhypybqD4nm7Cwx7nYUCT+vRLCkA4zZPVBUzPKCYRXNgA5fDtpj74xibZDY/e
         1NNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fYBQpmj9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lmhPPnz5QYfUFxLL5p2I8qQZ/1hsVoJPHuO1DHOi1aw=;
        b=dyjYcy/jILcs5mwOGPM5r/JpSc0PXrk9yOxMPtMdWFvQBhrqU6CKPTRfeASI73EyV9
         lRpyRBJSTl4whV/w3A4t2iUTOEsgiGHHHwCvgm02e0porMwBkiQ1jtEBHNVG9IEjgK0i
         bYZmXG+b5xfVGx6r18Oy/eBS253outXjGbm6VjRAStROvn+J4zVmZbBSNilIUw7Re5TV
         Ul+mYmts1tzYfuuOWgpkH9p/RI39ZpBZN90PgMvdM5OcY5Nw7zuK38y3xnR//FfOR38C
         /5PJZFZ7DU2xPyOjAjd91/iy8zrl7yJuamyiJHdTgpVXnGDKMNGZonCs6vrrf2e5kUS6
         ZDHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lmhPPnz5QYfUFxLL5p2I8qQZ/1hsVoJPHuO1DHOi1aw=;
        b=4bMDEAcNXm8C+U0bimeVnN6lOaqMe7VFunvovL0WoMzSdoLMeLLWIoNuG45jqlLouj
         15KgSGIZJOWBTVXFsW8AWhwsSHcC+cpp3hLYlGQZFP0RAWyXkfwTpuX98N36/ob0e/Fy
         clmZ71uhw238Z8ng6/3csfSsgUyDQznMNII00aLBsO0X/vsoGFmektxDb/wvbaquSrFP
         /Y9sI3lWZb/0HAixQcAD0uKRF1ez+o2nY4SC6PV0Zmn5n/QjQ/70dlMsDBlzpRT5iSxK
         /rN6LnaQHJiQfQdsrjP77FGhwoTY2g6FuGmHWBIzSZuKHfsyAHfX1DFPpKI+nL/14NQy
         4RTg==
X-Gm-Message-State: AO0yUKXK047alwxdaoF9liOv4M3OWp0ziwDSjk1otsYFRamgDzBx3oDE
	kXq5ucEF8w4EzP7AST4FmtM=
X-Google-Smtp-Source: AK7set+zQx5kbMi1fF2372sCsBAPtJ2zZF7sYjhCwjVNdJDF2RjxFEJMe9PJphjBwXnEkvGaXhalEQ==
X-Received: by 2002:a05:600c:524e:b0:3d0:50c4:432c with SMTP id fc14-20020a05600c524e00b003d050c4432cmr117345wmb.67.1675252866091;
        Wed, 01 Feb 2023 04:01:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b06:b0:3d9:bb72:6814 with SMTP id
 m6-20020a05600c3b0600b003d9bb726814ls902072wms.3.-pod-control-gmail; Wed, 01
 Feb 2023 04:01:04 -0800 (PST)
X-Received: by 2002:a05:600c:491c:b0:3dc:53da:328b with SMTP id f28-20020a05600c491c00b003dc53da328bmr2007309wmp.14.1675252864825;
        Wed, 01 Feb 2023 04:01:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675252864; cv=none;
        d=google.com; s=arc-20160816;
        b=VvaL1L3xl4fW6T+lugQytpBcpqarW7WKXhEpO2SfMmbPyrhjMCQJsSscQErn5Tg/rn
         Ve7Ds8BUgW5hYpEpqJNY3b/Bv7pQqzvU68AiylpnhYC8M+i6yj55gPyLcLVq4wUore21
         BBLzPN0oMevmUO6Cf9wwKe9H7K+m+fh/A93gSQPzdObE268vn1/fYQrCDHWmmgMqj4bE
         TP9SN//0YuHdi5W6BfVnH02M2UtaOp01cgPtPKWcfFO+8rIftUrpPbuTiSi8rk9gtJhR
         at8AHDvTc+JO9zbuH7PqgI2bY3bf3qHISM6FsLj7X2qPwYEUgzoxJS9QOLtxI/zj6zXY
         MPZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XkDaAs7NEt8L2ex9bykzKZqXj4em5dtmEAnn6lTD46I=;
        b=kLNXD5cpdtYgs+vBLm1zZow+y34g8hqI6QzzcfZCn9WrnvLShz8puGe2CDB/LD53JT
         ABjjRvcA8BSPMW7/ATn3tEg0D8yewk5IME2hyMWuvTtV2lwbPXJJHMSDr7NY93WLvxdt
         A77hDQo3Do/0r/CWswOTTDdQc80ga1OsSNydvNHCgI030d5xqDJXHxj4UCFJcgmSnExo
         tG1gWuYq+4mSVstaxLhsIiQKmjj1Kbg27VRYPof/coln6iBdnz6i2PoMG2SUP5bG6T2W
         V7L4j4frm2fahFMq9O9Zwusngwjq2YGpxwfek5xV9CWFk+32H2ylM0b4AHaECDUb7vOW
         JzBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fYBQpmj9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id c8-20020a5d4f08000000b002c08af7815fsi298816wru.5.2023.02.01.04.01.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Feb 2023 04:01:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id a37so19155834ljq.0
        for <kasan-dev@googlegroups.com>; Wed, 01 Feb 2023 04:01:04 -0800 (PST)
X-Received: by 2002:a05:651c:200a:b0:290:7c00:8cee with SMTP id
 s10-20020a05651c200a00b002907c008ceemr241094ljo.144.1675252864135; Wed, 01
 Feb 2023 04:01:04 -0800 (PST)
MIME-Version: 1.0
References: <20230127162409.2505312-1-elver@google.com> <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
 <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N> <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
 <CACT4Y+Yriv_JYXm9N1YAMh+YuiT57irnF-vyCqxnTTux-2Ffwg@mail.gmail.com> <Y9pS4MNnFWOEO2Fr@FVFF77S0Q05N>
In-Reply-To: <Y9pS4MNnFWOEO2Fr@FVFF77S0Q05N>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Feb 2023 13:00:51 +0100
Message-ID: <CACT4Y+Y3E7nu7PGj3m6+83Hs_D=3dVZe4rBh5-Pn=Gsm07r-=g@mail.gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user addresses
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fYBQpmj9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232
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

On Wed, 1 Feb 2023 at 12:54, Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Dmitry,
>
> We raced to reply here, so there's more detail in my reply to Marco. I'm
> providing minimal detail here, sorry for being terse! :)
>
> On Wed, Feb 01, 2023 at 10:53:44AM +0100, Dmitry Vyukov wrote:
> > On Wed, 1 Feb 2023 at 10:34, Marco Elver <elver@google.com> wrote:
> > >
> > > On Mon, 30 Jan 2023 at 11:46, Mark Rutland <mark.rutland@arm.com> wrote:
> > > [...]
> > > > > This again feels like a deficiency with access_ok(). Is there a better
> > > > > primitive than access_ok(), or can we have something that gives us the
> > > > > guarantee that whatever it says is "ok" is a userspace address?
> > > >
> > > > I don't think so, since this is contextual and temporal -- a helper can't give
> > > > a single correct answert in all cases because it could change.
> > >
> > > That's fair, but unfortunate. Just curious: would
> > > copy_from_user_nofault() reliably fail if it tries to access one of
> > > those mappings but where access_ok() said "ok"?
> >
> > I also wonder if these special mappings are ever accessible in a user
> > task context?
>
> No. The special mappings are actually distinct page tables from the user page
> tables, so whenever userspace is executing and can issue a syscall, the user
> page tables are installed.
>
> The special mappings are only installed for transient periods within the
> context of a user task. There *might* be some latent issues with work happening
> in IPI context (e.g. perf user backtrace) on some architectures.
>
> > If yes, can a racing process_vm_readv/writev mess with these special mappings?
>
> No; those happen in task context, and cannot be invoked within the critical
> section where the page tables with the special mappings are installed.
>
> > We could use copy_from_user() to probe that the watchpoint address is
> > legit. But I think the memory can be potentially PROT_NONE but still
> > legit, so copy_from_user() won't work for these corner cases.
>
> Please see my other reply; ahead-of-time checks cannot help here. An address
> might be a legitimate user address and *also* transiently be a special mapping
> (since the two aare in entirely separate page tables).

This brings more clarity. Thanks for the explanations.

If addresses overlap, then it seems that the kernel must disable all
watchpoints while the mapping is installed. This patch tries to relax
checks, but CAP_ADMIN can install such watchpoints today. And they can
unintentionally break kernel, or produce false watchpoint triggers.
And if all watchpoints are disabled while the mapping is installed,
then this patch should be OK, right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY3E7nu7PGj3m6%2B83Hs_D%3D3dVZe4rBh5-Pn%3DGsm07r-%3Dg%40mail.gmail.com.
