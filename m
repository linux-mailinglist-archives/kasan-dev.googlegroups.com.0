Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIUW2GHQMGQERPZOUGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D8CD4A0145
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 20:59:32 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id m3-20020a056e02158300b002b6e3d1f97csf5306303ilu.19
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 11:59:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643399971; cv=pass;
        d=google.com; s=arc-20160816;
        b=VyBzieCMEeO9SbUHcxuKM4PpPWqD8pmsXS/snVqFAUaXkvIj5qfl2QFpVkP4N6BmYJ
         5q1a36iZnaGsFc342BMPdAQRHxn1hSZKpKIdFp6owRYVotFcJHNlDt/IlgvdSP6gM81+
         wcdEF1ctGN8WPr+okjHO+E97W4qttb/xlXqZrWWWa/Z0fqQXWJMqvCp/FFHaS2fgFR68
         h8S5RyZ83gWisyhFHg4UQBGy4toQzJ/FWuYNckQFoUTzDpS/cMNTMLqhXgQFMTQNduru
         p4XlyyU1v6kf+cVOziprKAP9RxGcJBfQ6FMLWmCYWMzAE5WodBpA9NAkFHYRjp5KvCS9
         vNPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uOOCnqv/eBO+27Rx2NewbKqLxGy7Crmihxk6u2onVlY=;
        b=tIoL0AV0hOdcneH6XyNvrC+U2rS3K7Uku63uJIF/QC0KKhzIcTlEx38X9GFKI60PN+
         4f7irp2X32u9FqbX5Yg+PPZ0zxGBFmqjOXjysFr7BWR5aZSECptyFBWEK1e6VHvSfRw0
         R8HuU5Izu2+8oX7LCKU8jStXc5+uL8/1ok+q4hicC3tkmWOgk34ZQ1AD9mcZh/4BiTGK
         xeza+MDVUfFqo3jPdQbidH+IUbI/xcknPvwR0S0A166To1RCePmfYXmOYCVabUAjp11v
         HsAADJw0wAnNuMH+T1AJ6VOSTcGrNLHesuH4ugINQ3No7oWV2PpipoNOgrOcHvaW4bKj
         SBqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QzY57hp7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uOOCnqv/eBO+27Rx2NewbKqLxGy7Crmihxk6u2onVlY=;
        b=oL9ZE2pdbAG8LosDd8TG7h9yIWuPo3rkdROWTTxiOoIVHvawMlnRPs4IZntAdEhAp/
         v59SyD7HxzGZyabedrJi2OFsLt+EktW+VdFfgD2QN9rypGMNfU5aDf5kJAQ/l2qvgUAg
         WlG+zXq85XwTC1TxPIMf6chO9N2+QIRVKOMRI5ddIR5cQn/SbozfL6Ztn4508noTaxFY
         LHnbd8JUYBh4J28DpSxQhw4FXdjuPBwbfI+Gax984+V9FkeBo+pND303bo8MLhtpwHdo
         Wz0iexw4gdJniQMFZqA59dZ4vbispPKBQNYTgxmTLg18OpnzZBzk0yV6A+Xt+8JQRDy0
         ll1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uOOCnqv/eBO+27Rx2NewbKqLxGy7Crmihxk6u2onVlY=;
        b=rSFU/DFA/odIhjl3Bwi8DuUUDlQh62q/8JTBMIc0F0lfXIl2X9amPv+/rS4R2F6lQW
         62Nx/6F1aarrPcw1iCkJCPHlm/OedELIrXdwd9aL1J/1Dh3Hx+9V0fYM0SBfp0XJhcSl
         XF+JxiNZqLUYxDfV35e87U74ZhHsvyJneFd8PFFrxkEJ/13voCtGgAu8BbKjo6ExW0jN
         AMP2Gpkw/BzPqtZPBUsCBjFYyGqnB3xVP3PwBLXIK6Iwuzji5Gepp0Nwuzp78fj6gWEn
         L8BsGy2AR/n2JcQO43u9iE5jbQNc7LVkUYPEL9C72DkOA3OmeTqob+zHaf0jPtCdC6ww
         ARMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wMIcy0aHH/XJTpGf6D8GkCyW7aWKxy+NkJkTdTmxBP4fYvuIG
	lzipvHWYxCWsK64jXDQfM9U=
X-Google-Smtp-Source: ABdhPJwjfNy9xlNpDL1abf55VqxK67YGsUXM8lJZnvFcYbbJs/rErFYjfaHIibthgWbKuNM+DG+ylw==
X-Received: by 2002:a05:6638:22b1:: with SMTP id z17mr5549660jas.194.1643399970543;
        Fri, 28 Jan 2022 11:59:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8d:: with SMTP id w13ls2290818ill.4.gmail; Fri,
 28 Jan 2022 11:59:30 -0800 (PST)
X-Received: by 2002:a92:c264:: with SMTP id h4mr6888269ild.320.1643399970188;
        Fri, 28 Jan 2022 11:59:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643399970; cv=none;
        d=google.com; s=arc-20160816;
        b=YkPj/hstUSyAIWCCiKDHMCr1wl+JhzSnf7LywFhSdGqF9hQbmNPgfHhL3pwBq0ThPV
         OUg2R74AfKRSj058ozOWpfuOzUv7IEDpaMslUV/JhcCso2A0DmLoTGxLjyn+eFnCaRq1
         d9TxFnVtrNfyGZyOnOGhxcQe//U1ikZxvbTlF/iF9Jhlz8jJ7ACR4XJ2y0x7moPhiTfq
         i/WASuIhujrYpQjieJI2KURsovNP3bhbw21+9PFeInBJoqsOJcSSf+BIPLjwt3HEx4Q5
         VdHmFxOV7e+OaxrulvbTAWE8CpR93bbJd8qkADWL+PdwlKgIEvKxhIFglX40A/suZ9iU
         QtLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=k+KRxXOu730X8LGDY8ibWFrqzfk6XaCWgUlQ/FJX/1g=;
        b=DWyu9GIus+xD+asZ83G/ASSuohUmV/aAKL/ZBEVEp66LWSSmKDUVgErgjq6UBVZPli
         +rdd0jep/NDRAJ00AEcYUIrCcpT7hx2C3wYaYTTZRAPf50Uga+jfaGqPzt71kDQpytfr
         oJJLdO9olrnhb8tJOzs+pZfaecuq4TXA4+G6s2qv4HSWPZuFHnYePuUtNmax19ySPFhG
         pceEQHxYxU8weuMvUs+hC8mE1FI87R4Rs8P0NxIS0J1U5NgDih/PAs6Cjm+83lqK3pN0
         Vers0EgcI9SqTjU0sKkGefDw9GT/gvqLQR8HcOpbrqYLbOsJTLRrV6McnOiBrNIEmG2I
         9UVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QzY57hp7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id x10si423294jap.3.2022.01.28.11.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 11:59:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id b1-20020a17090a990100b001b14bd47532so7372779pjp.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 11:59:30 -0800 (PST)
X-Received: by 2002:a17:90b:1c8d:: with SMTP id oo13mr11600468pjb.59.1643399969749;
        Fri, 28 Jan 2022 11:59:29 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o11sm22920833pgj.33.2022.01.28.11.59.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jan 2022 11:59:29 -0800 (PST)
Date: Fri, 28 Jan 2022 11:59:28 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] stack: Constrain stack offset randomization with
 Clang builds
Message-ID: <202201281141.2491039E@keescook>
References: <20220128114446.740575-1-elver@google.com>
 <20220128114446.740575-2-elver@google.com>
 <202201281058.83EC9565@keescook>
 <CANpmjNNaQ=06PfmPudBsLG7r9RsFXYo-NQR4CSM=iO11LFSHKw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNaQ=06PfmPudBsLG7r9RsFXYo-NQR4CSM=iO11LFSHKw@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QzY57hp7;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102e
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

On Fri, Jan 28, 2022 at 08:23:02PM +0100, Marco Elver wrote:
> On Fri, 28 Jan 2022 at 20:10, Kees Cook <keescook@chromium.org> wrote:
> [...]
> > >       2. Architectures adding add_random_kstack_offset() to syscall
> > >          entry implemented in C require them to be 'noinstr' (e.g. see
> > >          x86 and s390). The potential problem here is that a call to
> > >          memset may occur, which is not noinstr.
> [...]
> > > --- a/arch/Kconfig
> > > +++ b/arch/Kconfig
> > > @@ -1163,6 +1163,7 @@ config RANDOMIZE_KSTACK_OFFSET
> > >       bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
> > >       default y
> > >       depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
> > > +     depends on INIT_STACK_NONE || !CC_IS_CLANG || CLANG_VERSION >= 140000
> >
> > This makes it _unavailable_ for folks with Clang < 14, which seems
> > too strong, especially since it's run-time off by default. I'd prefer
> > dropping this hunk and adding some language to the _DEFAULT help noting
> > the specific performance impact on Clang < 14.
> 
> You're right, if it was only about performance. But there's the
> correctness issue with ARCH_WANTS_NOINSTR architectures, where we
> really shouldn't emit a call. In those cases, even if compiled in,
> enabling the feature may cause trouble.

Hrm. While I suspect instrumentation of memset() from a C function that is
about to turn on instrumentation is likely quite safe, I guess the size
of the venn diagram overlap of folks wanting to use kstack randomization
and an older Clang quickly approaches zero. But everyone building with
an older Clang gets warnings spewed, so I agree: let's opt for complete
correctness here, and make this >= 14 as you have done.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201281141.2491039E%40keescook.
