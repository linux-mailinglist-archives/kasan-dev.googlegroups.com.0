Return-Path: <kasan-dev+bncBDW2JDUY5AORBLXYXGGQMGQEUTLYHMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 00C6546A929
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:10:08 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id n19-20020ac5c253000000b003030c0efe45sf4732143vkk.20
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:10:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825007; cv=pass;
        d=google.com; s=arc-20160816;
        b=erhLRE0OgAZeLYsfQ1h1xEXgkfvhiYkzxTlf8nJMlyJdgdnqYtd1iXRqPDPQii2ziB
         dHKqw3Gw/mXHgE7wowJdJaR5XXkLER8IFFBStoHYd9YFDetb8u0UMifM2QAKf5VYHhX7
         qjm1Hugq41/r00GSMeU+bIyzEDV+UEgeEZEG5GZcMvz56Ms+9QKs9j3XrqG7VhGDHibF
         1vF1ycKekg9tF5oO+E9KQClfoX0tVRMmvZRxItfCXFcZcxAkbhN7JsRa6Gd4Qyb1Cmzb
         TJ2NQLKpybM3x2SBFymb633EYsj1mU4PlyhYta+Sp9BFGSDpxCvhsDOW5Jy4r1+uLJOV
         dydQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=DFkwyiy+HchKqt6fMsjEQhgWWcCrHlKqCr75+5u3hqQ=;
        b=wasl362MtMwNAkk/eBvEuoTpC4igVfXMuXkkQpy7awk5VShrqXojhkRhisUT8UJbkq
         wqFLwYTXXSJFrQD5TLMq2VC/Q6T1UiiZAuHnl1deiPeM8788oMZrJHqbx1iZY0Buo5SA
         KBYNRDr3NOjbE4h9R+635ZN1SnYudHHSPbYCNp/aAhUmY025a4jC2leLLcD5+iFI/jpy
         awAGaSI5ZYXPXIcOQl71NHUIhVgfU/HUWEH81/d6TEpQL+F7jzrO3BFPUbSn7x3Lk3rh
         9CB2gl8tXl4B4p5bsU/ovvgnahAhnsMWwt0INWg2w+93vvO0rgHeyQOVW4mpXAdb4aYu
         PSLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gxZcfGvI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DFkwyiy+HchKqt6fMsjEQhgWWcCrHlKqCr75+5u3hqQ=;
        b=XeLtUvdrtC+EZaZL7RAUNr80M2h0r/XBi0OLXqLcNcwbJNUfkAy+7bZz1Jnq6Glrgb
         OhVhAT//IT60CXEMAcpNprMIRQKjYCxTuwJhxNAEv+bZt91j6WYIA/NK3Yl0UQ5VjAxP
         W+YrUrOc9D7hAwAhTmTUb10iTWOIe7Kl2H6ZX07X0at0bSedE5rfnYu3xvP3Fxnnzn+2
         g3a5s7amQ/MaIkf9x39Ndigsha9SbCd5WkDL3wGRxvuykbue/jBi564ouS2Eo6v3kavM
         EKu2XPSJay7p4QtLHALLRpF2eHwFWEr/8eyYbLXvuiUZcmasTyKb2BM0bpJiSx6VnUQ6
         vGaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DFkwyiy+HchKqt6fMsjEQhgWWcCrHlKqCr75+5u3hqQ=;
        b=iCq6d/apgmRmWaBQHeJdt+zSmohSzjk6NL8uS5T72/1rO/eWwFRlbxPz/e7cvgZqQU
         1RK+4on4Z/LLPLN8WcFONmKXnSr3JagYitHbe0m32TsxGjfAbt+r3wTg2GWrBX+tRyx3
         s17GeYlhO/mw4JFgc16xR6rHH3x5lekuHSji061sxpvikasJw8Pfn3FMI4mXlpOn1gWl
         ATdwquNDcUq7Gc7kDCqCNuNO61tg/TZG9/c9ROmfehXtVeYykZOSCWpsaQproUX4Utge
         dU7wLR9P2wyu1/i8ynnLjRNxcTu87XlBkuVfCQ6cgAjw6aQGSvAFrPZFbT6+mX4jLwq7
         eSiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DFkwyiy+HchKqt6fMsjEQhgWWcCrHlKqCr75+5u3hqQ=;
        b=KQTGMYcIFUFbwGSSAfI63+Sh8mua2YG//VUPnpvcA2nHQrzxmxyV21A1WLbur22qgt
         iz/lRC/Pxt1vfWHWVRBkj8sqIi3Edq+cUwnzmdAULFURcam/Km0Ln8FheAWRGt/Snerc
         lWbfJom4C0fkI7s6Y3vqrJo2YW7Yph3a+bBZH5+bK43DIp+wNMk/cFhAaPaylovc0rAU
         U2ii+PU1jzwEcSldZgkyhK+xdP6dOZ9zRg5h/QeFotTRI+3Y0HBrpYIISNAJ4khLQmSP
         YgTcAxb/mk5DqOBXthvjZEUiPwGphmnivUyOGdelIyvf5aVIzUZCOh5eaYujk6bgPinP
         N1DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319Q1rQHA7c51TSTkCTNMKtKGpGeG8ibikTlKGpc43SoFh3mNig
	ZUc1E3pA6dtuN2KopZJOUIk=
X-Google-Smtp-Source: ABdhPJzLMwhyEBfujCA8Rka4hbWU+iKvyoewYNkGVQpMlqGU6ZjcKdNdhvXKooS3VhNlK9iRhQkWqQ==
X-Received: by 2002:ab0:2b96:: with SMTP id q22mr43556738uar.87.1638825006925;
        Mon, 06 Dec 2021 13:10:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2454:: with SMTP id g20ls5446503vss.4.gmail; Mon,
 06 Dec 2021 13:10:06 -0800 (PST)
X-Received: by 2002:a67:ce0f:: with SMTP id s15mr38781197vsl.33.1638825006351;
        Mon, 06 Dec 2021 13:10:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825006; cv=none;
        d=google.com; s=arc-20160816;
        b=AEtcBML7F+l7aN87iZHmloGAwMbUxv3lgYW9yKE8t6ZheQZLv45D9iRhC8GNaGMDZM
         XOw3CSU6Thv0SenuxfJ/Jf/r24ogSffWKQnDi9r2fz8/nkwI+pMzG4ckct+rtM9cFwdj
         b5UsadmjM2fZeryWJgFEn9vBBYpc4yHOO5bsm0AomPfpUruY2scWK6hhXO40KcJNeJfS
         1xxXNSQbtD3wco4WUpPO2HwGsJNREZOTcl/kobuYmP7l0bb0KsCca+BiKDisW471Qa6d
         bttPH0p2gOdkZrDdu9HrBB7gfA5U/3vYgip5YQoY9WW2obieRN4aOrC8cnpzJgLLwFyu
         9HMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vPzV3+wkeUfRoOQi+Ln3ww49AQZvsG1boIOkNO2vCs4=;
        b=0bvKHM04QLU4C+ytMJm4t1u4UCX6nwbTPs5T0JbxA6d2suKmmnURuYOTOrEnuZc91Y
         pNK06ndAwpcmywFpg9V0ftpErGjVTD5XmjUkFfPJxjVqNsY2ri1m7scRF35JxxIQJs6J
         HHyTcAW4XMspmfiOoYmNNX72g/HR31jROLdQ81z5jT0WIyjcezuCvtcWZITAZyaQA7pA
         58ubFJqiUEOnAWchjBkaNSQuaYOHRK3VHX4NY9oJGuS1Fg2KzrCRFfyjwvMbxEE23ycl
         ++Gzb7LFUGQiTuJ14CNU2euPJkrhs75cOQmITFQ5fsAP4R4QcoYc78dDSnBHxykO7jqX
         JdoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gxZcfGvI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 140si636250vky.3.2021.12.06.13.10.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:10:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id m9so14666621iop.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:10:06 -0800 (PST)
X-Received: by 2002:a05:6602:45d:: with SMTP id e29mr37042616iov.202.1638825006153;
 Mon, 06 Dec 2021 13:10:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <b82fe56af4aa45a0895eb31f8e611f24512cf85b.1638308023.git.andreyknvl@google.com>
 <YaoI6qgQEmzNU/In@elver.google.com>
In-Reply-To: <YaoI6qgQEmzNU/In@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:09:55 +0100
Message-ID: <CA+fCnZfE-6zwuPySgMH6r4A=j151uBZvFP3wzOKvAD6JNLgLkQ@mail.gmail.com>
Subject: Re: [PATCH 28/31] kasan: add kasan.vmalloc command line flag
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gxZcfGvI;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 3, 2021 at 1:09 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> [...]
> >  enum kasan_arg_stacktrace {
> >       KASAN_ARG_STACKTRACE_DEFAULT,
> >       KASAN_ARG_STACKTRACE_OFF,
> > @@ -40,6 +46,7 @@ enum kasan_arg_stacktrace {
> >
> >  static enum kasan_arg kasan_arg __ro_after_init;
> >  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> > +static enum kasan_arg_vmalloc kasan_arg_vmalloc __ro_after_init;
> >  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>
> It just occurred to me that all of these (except kasan_arg_mode) are
> only used by __init functions, so they could actually be marked
> __initdata instead of __ro_after_init to free up some bytes after init.

*Except kasan_arg_mode and kasan_arg. Both are accessed by
kasan_init_hw_tags_cpu(), which is not __init to support hot-plugged
CPUs.

However, kasan_arg_stacktrace and kasan_arg_vmalloc can indeed be
marked as __initdata, will do in v2.

> [...]
> > +     switch (kasan_arg_vmalloc) {
> > +     case KASAN_ARG_VMALLOC_DEFAULT:
> > +             /* Default to enabling vmalloc tagging. */
> > +             static_branch_enable(&kasan_flag_vmalloc);
> > +             break;
> > +     case KASAN_ARG_VMALLOC_OFF:
> > +             /* Do nothing, kasan_flag_vmalloc keeps its default value. */
> > +             break;
> > +     case KASAN_ARG_VMALLOC_ON:
> > +             static_branch_enable(&kasan_flag_vmalloc);
> > +             break;
> > +     }
>
> The KASAN_ARG_STACKTRACE_DEFAULT and KASAN_ARG_VMALLOC_ON cases can be
> combined.

Will do in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfE-6zwuPySgMH6r4A%3Dj151uBZvFP3wzOKvAD6JNLgLkQ%40mail.gmail.com.
