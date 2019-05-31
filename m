Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHHVYPTQKGQEUJHDYEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id A6E5730C31
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 11:57:49 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id z1sf3261880oic.11
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 02:57:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559296668; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZYkVhJA0ZMtbv6Gy5qSPl9u3MasfgQTj2frv6Y80ZKT/2NFeSBaZIqB+pAlKEyzJv0
         4uaBmM5H+NYGUaC+i/lOo9a12sLBPohkihg5t3PLpZZdO5ABJJYRg7mXCIsxPwnUDXr8
         6UGPyMzxSu32pAqPq44sVCIrGv4j/Yxa3uE/bELivTKkxtipUfFJHnZmzkXww7wLYMmj
         eB2lWN5Pv/Pz2abeidOTYf7Oj29xf4ZHifVwrX35fH85YJz5C8Y7xbf6sDeKGpzlUy2f
         6gMJ0jtUlNp3/SKTJadWPlCH++2Ta81gB+wTLHzISPIavjZVrpihpKE0sOrKpqTrzGVS
         W/ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gV54FOfVaMzlZlrY793Cwc1HIOLHGoBoFxj/0N9yw2A=;
        b=jgBtFVlCfpHiVUOB3/OPM3/kn/sl4S6Eq3zVcGvrak2Say4Ww7Oyb3f8Jyizzls1sZ
         W/UdQO8jOhrKuvcJ3hEOa8OFe55M0QWyWFOC5LVobex4cilip3Eye3WcrbSIJTbr/5s0
         2lSkeYNHnNpys+UOPrYsb5QHi440r0aqoF56wnzQwjtQP6xb3TVHtHbTAJDjMy0cuBZE
         f0+YlXL9jEnK2ou9VGn/hR7RUVZX8CoJTkA7xwwf/iIlj91FaPZWnZA9sJbvguSgsMoR
         W51EKM0vDCUUxU0zX9H4gwuyAxwgVCvEr7fq1VAH7BpACvx3WkXdVZzaEy58U8VUYI2Y
         Yysw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e32JUU3P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gV54FOfVaMzlZlrY793Cwc1HIOLHGoBoFxj/0N9yw2A=;
        b=n/jaSY9Y1gfM8bhmegvkt/IaeluBJon2iwTdmv9xbkb9ZMLHkhAtlalAPBlbB+L6Gd
         RuK0kHIk1u/KFovUgctfKZ0/nR/UzxX1nroWsN3YgLMca2rDeY84WtPqqHU92DgteIaG
         +tTMlDV4UuNIzvMRVZVQKPkCBP8xWI9Ag3BGMbGg2iLwpeyFo//PWQD6M9RVNeaGU5AX
         RnkOppMN7L9H+WOzrjIU07dvgXkDIFKna9v7K3OBbgh9gEJcEY8tXeSSl/++IU8l0y9i
         HDIouqhkHxnkIirRMiE2V0IOW7+fY6Has8gXGqbh2akI7orkUbTU+112cxtqoDMDSLd7
         1i/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gV54FOfVaMzlZlrY793Cwc1HIOLHGoBoFxj/0N9yw2A=;
        b=KC5/HrpKe8lJo2+X7rU1rw1FP2GuMSPPe7YYWNk5wwNbj0CDALDjkq4gQbU5jgDkLZ
         JdlYKfCkihBuIfPFD5X7lshGxkh3vid5ItECu2E19lmIddiToOsyc5gJtn4cjLZv37bT
         u47IB8qQ9Ojr5+1G47aHwziOr5IZY5flpquFQz/+uz8gO/YDlp/PvQ+wK+9R9lXfH60H
         NAGZWgSCYCcfqBIAIJ2+abb5ORrTiKUbqzNRyH3+AkFaHglLaO7vd3z2sPubg7nvi2ns
         eHkZrMcc4WSt2ihJtVXymgUuvH8w+EIOnySUEYQzyNvoROXxCvtMG66zrQIF4BxgXCY4
         L/ew==
X-Gm-Message-State: APjAAAUl217oWVEvMWpHqVGdm8A2Mn34H3jV9qX++0AObq4wwaVBRFYA
	PXmccLuf3+MawAPrTq8VLzE=
X-Google-Smtp-Source: APXvYqyJBWHF4Tn43ijf/qvp/WWN94CjoO91XMitdGTmZqB0XPrcoDPYrf1yega4fvEUeJP1n1zzHg==
X-Received: by 2002:aca:e44b:: with SMTP id b72mr82144oih.108.1559296668134;
        Fri, 31 May 2019 02:57:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:ec8:: with SMTP id 66ls901950otj.16.gmail; Fri, 31 May
 2019 02:57:47 -0700 (PDT)
X-Received: by 2002:a05:6830:1042:: with SMTP id b2mr1086968otp.345.1559296667866;
        Fri, 31 May 2019 02:57:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559296667; cv=none;
        d=google.com; s=arc-20160816;
        b=aNsWL9vqkKpXYIWBZWtXceDMgtG+/sfajTIHtOsOXS8f2wW7c5fhtYw4PrXiC0Neer
         cQ2VL7e+Ele2eZabQCH2vcIKsM+0dEhJG+FDHvavtINvxi0aH1ypZu9+tnBqvCjI/jjv
         HbgGfFgZLyIzcQLkkdAuNFMCIUPSmBtsNN7oz8SUumwjtX0vzlaBlB7MixnAgSvC3jOG
         mklmVpUeSUAfgiHh7Ct0uGU1ylTXUcEtzn1Zf+4Sh7GeBDw+Odp3M5LPn3A2aaMCPZkt
         ApUelVJkMTvqteOQO+3bSoIOY71gyI6CqXbtkJKPGCE1itKC26bNFWv91MihgDQtUXxH
         FoXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t/dabiI1+zXohN0XPJPWZWWtcKfqB2v/nUShweQXWc0=;
        b=E2su40Zf0W1zTGxHMrkbIb7g1tuoQgZ91gtfXv5ImwBHWYVYVZJMz1udrDtWuUJJZN
         4YLYzQ70NFemaG2PUCIhrOm7cy3AzSUHxx27sHq1pBjlDlzMCdD4rSTgr9uVvBq6QRJB
         93WZt6rU9vy3q7SaWKbRJM79YugxOk2uQNb7YusV6LLLICWMADanWXsdDgNIOFlGdHK0
         RyPmEAf5KZDib1MgIH2/W5fDQ4QLtXY9W0ew4CJa/l8GnFf1OrU4MsRKMxnUAOPwVLLZ
         qi0wOApZgdiP1/LBjVAdtwCL1vdP3e+ETVv8gV6DBizkxJ7XvuwnOh5HgU6j3BvQQKVt
         olYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e32JUU3P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id 9si257740oti.2.2019.05.31.02.57.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 02:57:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id b20so3678003oie.12
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 02:57:47 -0700 (PDT)
X-Received: by 2002:aca:bfc6:: with SMTP id p189mr5781082oif.121.1559296667221;
 Fri, 31 May 2019 02:57:47 -0700 (PDT)
MIME-Version: 1.0
References: <20190529141500.193390-1-elver@google.com> <20190529141500.193390-3-elver@google.com>
 <EE911EC6-344B-4EB2-90A4-B11E8D96BEDC@zytor.com>
In-Reply-To: <EE911EC6-344B-4EB2-90A4-B11E8D96BEDC@zytor.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 31 May 2019 11:57:36 +0200
Message-ID: <CANpmjNOsPnVd50cTzUW8UYXPGqpSnRLcjj=JbZraTYVq1n18Fw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=e32JUU3P;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Wed, 29 May 2019 at 16:29, <hpa@zytor.com> wrote:
>
> On May 29, 2019 7:15:00 AM PDT, Marco Elver <elver@google.com> wrote:
> >This patch is a pre-requisite for enabling KASAN bitops
> >instrumentation:
> >moves boot_cpu_has feature test out of the uaccess region, as
> >boot_cpu_has uses test_bit. With instrumentation, the KASAN check would
> >otherwise be flagged by objtool.
> >
> >This approach is preferred over adding the explicit kasan_check_*
> >functions to the uaccess whitelist of objtool, as the case here appears
> >to be the only one.
> >
> >Signed-off-by: Marco Elver <elver@google.com>
> >---
> >v1:
> >* This patch replaces patch: 'tools/objtool: add kasan_check_* to
> >  uaccess whitelist'
> >---
> > arch/x86/ia32/ia32_signal.c | 9 ++++++++-
> > 1 file changed, 8 insertions(+), 1 deletion(-)
> >
> >diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
> >index 629d1ee05599..12264e3c9c43 100644
> >--- a/arch/x86/ia32/ia32_signal.c
> >+++ b/arch/x86/ia32/ia32_signal.c
> >@@ -333,6 +333,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal
> >*ksig,
> >       void __user *restorer;
> >       int err = 0;
> >       void __user *fpstate = NULL;
> >+      bool has_xsave;
> >
> >       /* __copy_to_user optimizes that into a single 8 byte store */
> >       static const struct {
> >@@ -352,13 +353,19 @@ int ia32_setup_rt_frame(int sig, struct ksignal
> >*ksig,
> >       if (!access_ok(frame, sizeof(*frame)))
> >               return -EFAULT;
> >
> >+      /*
> >+       * Move non-uaccess accesses out of uaccess region if not strictly
> >+       * required; this also helps avoid objtool flagging these accesses
> >with
> >+       * instrumentation enabled.
> >+       */
> >+      has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
> >       put_user_try {
> >               put_user_ex(sig, &frame->sig);
> >               put_user_ex(ptr_to_compat(&frame->info), &frame->pinfo);
> >               put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
> >
> >               /* Create the ucontext.  */
> >-              if (boot_cpu_has(X86_FEATURE_XSAVE))
> >+              if (has_xsave)
> >                       put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
> >               else
> >                       put_user_ex(0, &frame->uc.uc_flags);
>
> This was meant to use static_cpu_has(). Why did that get dropped?

I couldn't find any mailing list thread referring to why this doesn't
use static_cpu_has, do you have any background?

static_cpu_has also solves the UACCESS warning.

If you confirm it is safe to change to static_cpu_has(), I will change
this patch. Note that I should then also change
arch/x86/kernel/signal.c to mirror the change for 32bit  (although
KASAN is not supported for 32bit x86).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOsPnVd50cTzUW8UYXPGqpSnRLcjj%3DJbZraTYVq1n18Fw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
