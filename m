Return-Path: <kasan-dev+bncBCMIZB7QWENRBUHEYOKAMGQEOC4PNDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 512B15364DD
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 17:46:25 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id v22-20020a056402185600b0042d5f95eb4asf742860edy.13
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 08:46:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653666385; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uk8X3nnBgInVWDt2VtxdfUnMez17OlT4mjv1KPQFjEP9gGWUlMC5Rn5qcWO9Mlela0
         4y+a606O+pDKyPwZAOKffDb65dwfb3EKbpnmy3qPGUZPMhJXTIpXSui10nmytwAON2We
         AyIaBIN+nPEe/olJ9t7ltggTbiHILQ6CiakQrsiSEHCkB5iP6b0d+mz8yWWjDme3HASZ
         mYNNz3TuKJbqCBo8NCkrpv6O/ZtZnySPFvr8JnI04CbavAETxF49ZLtaKPdXI0r0DOX5
         Q/HtwW8s2fdd+9dFDbhy950uaAdp3cROy3IKTygsihQRYECQqWmF6wmX2X94QOFjW5Uk
         fqYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IQrJrP/Kl6nobKcVqTqEre+JzaUGinyGBrwt1uVIOs4=;
        b=nOmEf2OXHDKu9AbvezZxVKZ5NGjKkHVcrfHRDEzgsRcIb0ZaHkU5DZaWiLBWRIuGvi
         78Ozomusp51t47o9vdpYQOX3Myh9wSDjLGaiPSWybdxS4/1+InPwbuva5rfzrpEJtTyO
         M2/rcLR2JhBEq6y/AMl70EwZOtJ/O3OTOQgPU9MJ41vLMg+ebrwtYQSkytn5q6Hsqi2i
         OxBOKp/Q5c5ss5TP8s3UF50FbC3idn831jz0P5p9VmsuxZxfNFPXCAp9Mmk71XtKgfEy
         3YZ9qMPqmb3QMX/3XUo322cvCY66GLPEATMfPSDBNdv9Q3VXqCGPHIlkPDu71xgCyflX
         OugA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J5itKyxM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IQrJrP/Kl6nobKcVqTqEre+JzaUGinyGBrwt1uVIOs4=;
        b=QbJAw/KbDXIqR893g33SqlPpfcNQCDaAVJJxI0ET5NBEgm9pvNQJL/JaBFpdbPJX22
         eh9rXE2JyPlGVYjcdEqFJbuFokbRE4k+lNiDXhHhnXZ3JHUyQ5suW0Qw4rKlb/+Z6H9G
         KWGDebXddllKzXR1LYqdtc0+xUFUaJXkMm9xfkaZ0ey+KIbab7etZoXilSQkr4nmwLf+
         yQ92+x/bdcEWLeZg3RylY9aAnBm2ilIwgdlOUPbiAuZCXEJFE3HK4o0SmbqbPfCfL+gp
         hJpWk8jeHrfD9wuHn649qTFCkQVpBz6KP63ZLEbQ0sBWvSoR+ejkrW6aPnwS1Xcs/Ocg
         zWSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IQrJrP/Kl6nobKcVqTqEre+JzaUGinyGBrwt1uVIOs4=;
        b=j4aVrBWzhL2HHPBWZLw1zDWccFDnp8j2d4rMqGqqUQWyRAEGIFX/fhISOcCGYLQtJ9
         KIyVv/940f8Gej7IsDspj9P1lxjymxVL/fSEj/4uJc2gax+GGVYlVSoHQwuRJumvmaqZ
         Vi8cnGhgNWqKxngrpXM2clrhGJhLDKMSxlFWuKibXa8L+9PFMtze9rv+e1rTdoilVrtf
         ZG+L3ja4IlAikkUGQZ9qnKsoKYYWgLzORnughzpO7oz7JYrEbqbO9Bzgn+WN1iaJYQ8B
         GVKSh4QHS3cFRSiaW/4HAKegHrLzVKKp/TM2AJfIKFnWhkmbqKBSDJpmuGUk64HsZyJQ
         2JLg==
X-Gm-Message-State: AOAM5332eZKtKR5M+CuHXv9OZmZAloOiOhmV8r9QGFD81/1wiVT+rS9z
	zF9T10EPNXSIV2y11XmpJGU=
X-Google-Smtp-Source: ABdhPJzNg08aJj5IIlokqGd+FS3MQfPHk/xonD+HhNKGoE9q0nAS3PqoLOXAtiEQYOH+uWxI7nGyiQ==
X-Received: by 2002:a17:907:2cc4:b0:6fe:1c72:7888 with SMTP id hg4-20020a1709072cc400b006fe1c727888mr39275052ejc.373.1653666384944;
        Fri, 27 May 2022 08:46:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5205:b0:42a:c2bb:3d7f with SMTP id
 s5-20020a056402520500b0042ac2bb3d7fls435084edd.1.gmail; Fri, 27 May 2022
 08:46:24 -0700 (PDT)
X-Received: by 2002:a05:6402:90c:b0:415:d340:4ae2 with SMTP id g12-20020a056402090c00b00415d3404ae2mr45399733edz.331.1653666383957;
        Fri, 27 May 2022 08:46:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653666383; cv=none;
        d=google.com; s=arc-20160816;
        b=tImBkrh4W3/hgFYdroohgjNV0zMgqO0ccPygWJjhsoROR1ifFR7sAtwCRkiJx1Ihly
         9MXAUHYdtqPvszLTkxRH7k3Vlb3ZXvFPtvjVxc4PUNWjlzkblZeS9lTeiQCsHRhE5koy
         0fGsCmsgmpzX3OxrO7/3/NOo4QF5LGv0cDI8fgKbCUzH3RTfyA6bkqtUs9rRICS8K0MD
         G20i5PHmjcvdPT/5HLj8XCXE1yCNih8dRvL+133sP2NwfH8UeXMOd5Musy9LzGGRsQJQ
         6g2aucmipPb9TnRzLxLvTI3tH0ldaNK1GvoNdt6qGMmsg/lytpTeHPn6G5mUnHCUEBQi
         pFSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QpYyaIFQsHQ1SQPPWz8FXNjk5sSNyuKP3F6ff73fwcs=;
        b=JzymcTcWppmhFaxQ194AaIIYPoK9JjtrNzlBLl/uEUNTcPTWP73M1aF6/ctVDpofuY
         oO95zpqYAZgl+uYei4ZK+cqiTLmeCJ9hrqh9QDg4eZOucgSoKooSJgYSxxXmXoVJWnmJ
         kjQ4M0o01uWEZG7ulURJWWk7mFIae/iB0/r/FpA1IVRODQeWjlB9X9LFfIHeoC0/ndEu
         EsiPvkJ1mmKXopww9CzYSXsRsmEuo273XlzpIo+r+5oTsPK1P59wSQfN78MZ7ZFY6UHv
         HTLCsazvxAnYFWpXbx9a5sgmBLLtlXlTkhunJiuAs/00Siv+tcfEmP73ZkNU19/r735j
         vkPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J5itKyxM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id hc39-20020a17090716a700b006f47118d7bbsi304956ejc.0.2022.05.27.08.46.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 08:46:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id br17so7515940lfb.2
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 08:46:23 -0700 (PDT)
X-Received: by 2002:a19:7106:0:b0:478:68b5:86d9 with SMTP id
 m6-20020a197106000000b0047868b586d9mr20020202lfc.417.1653666383196; Fri, 27
 May 2022 08:46:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220525111756.GA15955@axis.com> <20220526010111.755166-1-davidgow@google.com>
 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
 <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
 <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com>
 <134957369d2e0abf51f03817f1e4de7cbf21f76e.camel@sipsolutions.net>
 <CACT4Y+aH7LqDUqAyQ7+hkyeZTtkYnMHia73M7=EeAzMYzJ8pQg@mail.gmail.com> <5eef2f1b43c25447ccca2f50f4964fd77a719b08.camel@sipsolutions.net>
In-Reply-To: <5eef2f1b43c25447ccca2f50f4964fd77a719b08.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 17:46:11 +0200
Message-ID: <CACT4Y+Yv2AGRCLZ=cpxQtkrxz9YKxPGLBcriyFo7FVGoDiyaSQ@mail.gmail.com>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch <vincent.whitchurch@axis.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=J5itKyxM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
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

On Fri, 27 May 2022 at 16:28, Johannes Berg <johannes@sipsolutions.net> wrote:
> > > > > On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > > > > > > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > > > > > > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > > > > > > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > > > > > > rather than just showing the RCU callback used for that.
> [...]
> > Humm... I don't have any explanation based only on this info.
> > Generally call_rcu stacks are memorized and I see the call is still there:
> > https://elixir.bootlin.com/linux/v5.18/source/kernel/rcu/tree.c#L3595
>
> Oh, that's simple then, UML is !SMP && !PREEMPT so it gets TINY_RCU
> instead of TREE_RCU.

Nice!

> Unfortunately, it's not entirely trivial to fix, something like this,
> mostly because of header maze (cannot include kasan.h in rcutiny.h):
>
> diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
> index 5fed476f977f..d84e13f2c384 100644
> --- a/include/linux/rcutiny.h
> +++ b/include/linux/rcutiny.h
> @@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
>   */
>  extern void kvfree(const void *addr);
>
> -static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>  {
>         if (head) {
>                 call_rcu(head, func);
> @@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>         kvfree((void *) func);
>  }
>
> +#ifdef CONFIG_KASAN_GENERIC
> +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
> +#else
> +static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +{
> +       __kvfree_call_rcu(head, func);
> +}
> +#endif
> +
>  void rcu_qs(void);
>
>  static inline void rcu_softirq_qs(void)
> diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> index 340b3f8b090d..aa235f0332ba 100644
> --- a/kernel/rcu/tiny.c
> +++ b/kernel/rcu/tiny.c
> @@ -217,6 +217,18 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
>  }
>  EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
>
> +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +{
> +       if (head) {
> +               void *ptr = (void *) head - (unsigned long) func;
> +
> +               kasan_record_aux_stack_noalloc(ptr);
> +       }
> +
> +       __kvfree_call_rcu(head, func);
> +}
> +EXPORT_SYMBOL_GPL(kvfree_call_rcu);
> +
>  void __init rcu_init(void)
>  {
>         open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
>
>
>
>
> Or I guess I could copy/paste
>
> #ifdef CONFIG_KASAN_GENERIC
> void kasan_record_aux_stack_noalloc(void *ptr);
> #else /* CONFIG_KASAN_GENERIC */
> static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
> #endif /* CONFIG_KASAN_GENERIC */
>
>
> into rcutiny.h, that'd be smaller, and export the symbol ...
>
> johannes
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5eef2f1b43c25447ccca2f50f4964fd77a719b08.camel%40sipsolutions.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYv2AGRCLZ%3DcpxQtkrxz9YKxPGLBcriyFo7FVGoDiyaSQ%40mail.gmail.com.
