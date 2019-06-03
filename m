Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3WE2PTQKGQEC3RDWDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0856B32B57
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2019 11:03:44 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id v2sf14185617qkd.11
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2019 02:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559552623; cv=pass;
        d=google.com; s=arc-20160816;
        b=OwR7IcQuJg/M5gBeXLo0F0GejtpiL4M8Mnm/ywAeCG234iYC4mgqnGYastNR0Yx90q
         7dzRd+xMWAupySA1A5jUuG1r3bqySTceeJwfwus11jGHPWn8M6blIGMvWze9/VS6H0lT
         XCRpLU+W9Ajvm/dLXmj12MrKPMbpAVnYqdLxRGrpQiq6MtGPYbDO6d0a1UbvqlfGpQdo
         Wfe0/HLVZ9PIzqmSeDIArrowlpkoguUSxY0Sx+xlD+Kqt21XHExo3oatEWNShBa+zsbP
         T0yBZwiycCaC7Psh2DlgZegHeySoX9S3zQZ3x9sJlytvCj3AAt0CyoZg/EJGj8wFoQgB
         ZKDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zmC5+PjmYig7C/tzclsAUYhXg7F7l2KJkeBJiuxj5+M=;
        b=Y9/66Se9VoGuU3BC2LUucBEDbhtWlSWDQsDGOl0IS5WkdOa7/LG20HOjpT1FqDCBiK
         9hc9uqZDVexN7EUXTl/nj0iywX1wViwb2AZgrEjv0+gMfC9EUnO4hV/qHGJri6MQj7cv
         revjjlzrgJMhl1n5PtYs8iQAilCCiJeLdz6TRu65DUeYX8V5Bq/3zdCwP08H1e7WJDu9
         7c9n1yIZget1LiLTrmgakrIyzoUyMBx9AohUVawehEXPnbGeVywDMbrNnXQkqZAMfx3f
         dSKZIUfgWH3U99gTdhMELSRh9+pXw38dAxWyYI4/uazfi/q2lHIXJhNeCNovhtMi9uw4
         EOvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="H/dToC9r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zmC5+PjmYig7C/tzclsAUYhXg7F7l2KJkeBJiuxj5+M=;
        b=p2nXRdOgEIIEd7nZ+DUd0K3ZF/riUCH10F39pr4EY+UClaROx0s5ITvgs72Uhd1vwk
         /j8WfpodW7IUV4kAbAxfuGeATnuHZDGkgCly2laImI8esYLr0bAQBEiNF23UEsXvDwf+
         iAp3lsiST6dK3mldF8vuH6ysnhoVu78HBJK9t3NQdvWyvxN8DupLjFI9RPX8pekLEk3Q
         LKmhLg941QFuTKM86sBtKzLDUh+I92sVTaUWIND3oC+Hu06+E2wB1V+QZwYrrwGmDXj1
         Z+WYzPyWWO7WrG39m8jJx7JaXVHJFPWeOeXAvEnMEgnFRWOrobUBpM3tREMC4HUS9LM2
         CJug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zmC5+PjmYig7C/tzclsAUYhXg7F7l2KJkeBJiuxj5+M=;
        b=F+g7FIdAWVe6HSDPQ7Af73/54wTd4Ivkf6v3E37Bz4oOd6vN8UEwMnVLBv257dEJfY
         Arp7i7ZCToUdWGwmSiyu7ALKAI2fGKULuxgV8ABWe298OBf5+UiFxKidb5FoZ0HaO7Iz
         kq9pqMPsb0zb/2Exh48x/7EiW2+Njy4i0rqrNZPDDoXYvmZpeC+jG9xbdAweXf+NCtFG
         DdH8kXgSq+dr9r6OscClZN4c5DFaFEt76rhpWCJD0kuZRRZJm2NrUzArtokCoP0F5JVm
         Ox8UQs7FYs08ANqIE58gGobVlneINq7WK1UQpxoELyKRtuuC4j/8/jqIJcdh4itrriMq
         jghg==
X-Gm-Message-State: APjAAAV6yE8WGUN+K44ODzxCOJR4GLef5DGK5VBNmYejNrBIKIbjX1x6
	0AnNbY4j5uFk9/CQZtxPUJA=
X-Google-Smtp-Source: APXvYqx8gxULxDsLFHn0AQhmQ0Cp/BdH0SczVp9HiY7BHePNEqdnejW90nMqeXr7zeJo7AK2Bc46+Q==
X-Received: by 2002:a05:620a:1443:: with SMTP id i3mr1799414qkl.11.1559552623021;
        Mon, 03 Jun 2019 02:03:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:258e:: with SMTP id e14ls5034167qte.7.gmail; Mon, 03 Jun
 2019 02:03:42 -0700 (PDT)
X-Received: by 2002:ac8:6c59:: with SMTP id z25mr22777781qtu.43.1559552622788;
        Mon, 03 Jun 2019 02:03:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559552622; cv=none;
        d=google.com; s=arc-20160816;
        b=rMqR5NJ37ZeCIebkycDa271qmMLAR6lc3RnC81/oUMnN2l15wLxgC6oirV29hBr0GO
         fvXMMoR4e/WavJg9CSOM8sSKCMyqUIc5XXZSyYu7InflfFdcUHotI36NT29KASUwz1NX
         BEZAoGkMXJoYFg6PcsDLDZcc46Y2rvZvLJt3rNa7i/WUtFl0uhdMH5oqQgnMSczImXLO
         s7WgILycgLDFYU2lXIXrh5DmY/iznp+WB9wT9wMKw6Oy53U6nvaCk00LqOwRBqPdCbWz
         g9So5OeWSvjonLHP1z4Vrexv5SZxYkkmU0SY/9QteuNh85bmO0YKhrCwCIGh6snY8oTy
         JauQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/VCvRg4+mMJ/yKzCQebn8clHJnLDYyzYIHqLnBJ4zrI=;
        b=fmvogiQ5HUXlFtyv9qo77KO4J+d5kTFKa+A9pwm37bAsZVUPWSs4XgndH+bBIMKUF0
         7SS4HFrVOVXfI5c5oPvq7YVY295N1KZbA8UxmQiczfDU6oqODadTOGtHWzQB0o2YruMK
         EPO96pFi0hxbVogMgdhRtf8I8LetiVc638TrAnZAm+0eB/2hLM0WAnpzzV0nVZKl2iV/
         bvupLTrM2cGTBcCB/aSgaGMGFp7s8WUTflyjJnKVrACnxYpJA063/3fzeIfpF5PYpYdC
         ddJN90jwhFeCTJrOsyOD332GSK35H/yMcV67piIlbRqwXpXhClf/Xt2i+v9j3iu+Z5KQ
         WY1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="H/dToC9r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id a79si531628qkb.1.2019.06.03.02.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Jun 2019 02:03:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id r21so2872615otq.6
        for <kasan-dev@googlegroups.com>; Mon, 03 Jun 2019 02:03:42 -0700 (PDT)
X-Received: by 2002:a05:6830:1688:: with SMTP id k8mr378583otr.233.1559552622037;
 Mon, 03 Jun 2019 02:03:42 -0700 (PDT)
MIME-Version: 1.0
References: <20190529141500.193390-1-elver@google.com> <20190529141500.193390-3-elver@google.com>
 <EE911EC6-344B-4EB2-90A4-B11E8D96BEDC@zytor.com> <CANpmjNOsPnVd50cTzUW8UYXPGqpSnRLcjj=JbZraTYVq1n18Fw@mail.gmail.com>
 <3B49EF08-147F-451C-AA5B-FC4E1B8568EE@zytor.com>
In-Reply-To: <3B49EF08-147F-451C-AA5B-FC4E1B8568EE@zytor.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Jun 2019 11:03:30 +0200
Message-ID: <CANpmjNMt8QK+j6yo8ut1UNe0wS3_B4iqG5N_eTmJcWj4TpZaDQ@mail.gmail.com>
Subject: Re: [PATCH 2/3] x86: Move CPU feature test out of uaccess region
To: "H. Peter Anvin" <hpa@zytor.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="H/dToC9r";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

Thanks for the clarification.

I found that static_cpu_has was replaced by static_cpu_has_safe:
https://lkml.org/lkml/2016/1/24/29 -- so is it fair to assume that
both are equally safe at this point?

I have sent a follow-up patch which uses static_cpu_has:
http://lkml.kernel.org/r/20190531150828.157832-3-elver@google.com

Many thanks!
-- Marco

On Sat, 1 Jun 2019 at 03:13, <hpa@zytor.com> wrote:
>
> On May 31, 2019 2:57:36 AM PDT, Marco Elver <elver@google.com> wrote:
> >On Wed, 29 May 2019 at 16:29, <hpa@zytor.com> wrote:
> >>
> >> On May 29, 2019 7:15:00 AM PDT, Marco Elver <elver@google.com> wrote:
> >> >This patch is a pre-requisite for enabling KASAN bitops
> >> >instrumentation:
> >> >moves boot_cpu_has feature test out of the uaccess region, as
> >> >boot_cpu_has uses test_bit. With instrumentation, the KASAN check
> >would
> >> >otherwise be flagged by objtool.
> >> >
> >> >This approach is preferred over adding the explicit kasan_check_*
> >> >functions to the uaccess whitelist of objtool, as the case here
> >appears
> >> >to be the only one.
> >> >
> >> >Signed-off-by: Marco Elver <elver@google.com>
> >> >---
> >> >v1:
> >> >* This patch replaces patch: 'tools/objtool: add kasan_check_* to
> >> >  uaccess whitelist'
> >> >---
> >> > arch/x86/ia32/ia32_signal.c | 9 ++++++++-
> >> > 1 file changed, 8 insertions(+), 1 deletion(-)
> >> >
> >> >diff --git a/arch/x86/ia32/ia32_signal.c
> >b/arch/x86/ia32/ia32_signal.c
> >> >index 629d1ee05599..12264e3c9c43 100644
> >> >--- a/arch/x86/ia32/ia32_signal.c
> >> >+++ b/arch/x86/ia32/ia32_signal.c
> >> >@@ -333,6 +333,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal
> >> >*ksig,
> >> >       void __user *restorer;
> >> >       int err = 0;
> >> >       void __user *fpstate = NULL;
> >> >+      bool has_xsave;
> >> >
> >> >       /* __copy_to_user optimizes that into a single 8 byte store
> >*/
> >> >       static const struct {
> >> >@@ -352,13 +353,19 @@ int ia32_setup_rt_frame(int sig, struct
> >ksignal
> >> >*ksig,
> >> >       if (!access_ok(frame, sizeof(*frame)))
> >> >               return -EFAULT;
> >> >
> >> >+      /*
> >> >+       * Move non-uaccess accesses out of uaccess region if not
> >strictly
> >> >+       * required; this also helps avoid objtool flagging these
> >accesses
> >> >with
> >> >+       * instrumentation enabled.
> >> >+       */
> >> >+      has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
> >> >       put_user_try {
> >> >               put_user_ex(sig, &frame->sig);
> >> >               put_user_ex(ptr_to_compat(&frame->info),
> >&frame->pinfo);
> >> >               put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
> >> >
> >> >               /* Create the ucontext.  */
> >> >-              if (boot_cpu_has(X86_FEATURE_XSAVE))
> >> >+              if (has_xsave)
> >> >                       put_user_ex(UC_FP_XSTATE,
> >&frame->uc.uc_flags);
> >> >               else
> >> >                       put_user_ex(0, &frame->uc.uc_flags);
> >>
> >> This was meant to use static_cpu_has(). Why did that get dropped?
> >
> >I couldn't find any mailing list thread referring to why this doesn't
> >use static_cpu_has, do you have any background?
> >
> >static_cpu_has also solves the UACCESS warning.
> >
> >If you confirm it is safe to change to static_cpu_has(), I will change
> >this patch. Note that I should then also change
> >arch/x86/kernel/signal.c to mirror the change for 32bit  (although
> >KASAN is not supported for 32bit x86).
> >
> >Thanks,
> >-- Marco
>
> I believe at some point the intent was that boot_cpu_has() was safer and could be used everywhere.
> --
> Sent from my Android device with K-9 Mail. Please excuse my brevity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMt8QK%2Bj6yo8ut1UNe0wS3_B4iqG5N_eTmJcWj4TpZaDQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
