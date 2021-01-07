Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAN53X7QKGQEOSUKHGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F0862ED75A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 20:18:26 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id r29sf5468293pga.20
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 11:18:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610047105; cv=pass;
        d=google.com; s=arc-20160816;
        b=PrYAxwn5L8Y/fyQN/nlV2jd4MNjZ3LUsW7WJMBjSkkgVY/XP/PpVusHBhnD0joYOnf
         d7uLRkh8roRt0jJ6Y6nvGZtScukTyIVJa5qTQBN6OhdMa6XeWmgpxcS04t9kE2zRYL2G
         F+qPhWFmQgn6Ji8MZm9P5aX4DbpRb4rmdwZdfBgumfis1+wXHh0k/mUi/LGY9zPAWgrk
         uZ9vvfQXaOUlxFQHi5KLXyiZPom5+B09xtRAU7zQtOK9k7cbHvVO9fJrb0jthqZfQJi+
         8B7nx6PPwBSboHvNYWD5I+5CnFVpDXXI/RzHMXbSq6jCl0HlmzljfpVVMyEUDGfo2gr9
         iHfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YiAtHNDdLSWQwVa6u/rTIs9SF1vwafefqOP9tcL+m58=;
        b=KpPkriZ22nu317TDx2vYPGOIwASWiVO5CWX8YBI+5VTfh/2juE91wFQGRQbIXWW+5A
         CAo1GUEbilcD+NFOqUMrjMTFv2Kn/9VDdBipWVlASjbCrNZ/T9V2MXg1FmTNvhGk38Yg
         2/kcnIer9Mxuo2+ah4vlDvYUCU3d3UFMG7eHoyIjfkTHxp8wBQaqyL9wZAL9COUgmZYk
         hNcNyb2Xo9rRWmAGKJfKweXRqfg/N/buz89Yt2JyHqWi582Q5XQrajoiyArU44n1vRL6
         A6NUBpGP4E77BX/5cvG2Y1NNJ4aVPDzvNpkI2vjHInrpvSZSydHT2GlHcLWufY9B8z7n
         F/pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SRNzU1EE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YiAtHNDdLSWQwVa6u/rTIs9SF1vwafefqOP9tcL+m58=;
        b=bSe6ImON+1DoseSTIeb97L0pw2WAHAwe2QXrBf1V/pJlq17Vg2oeKPGPbcJ6nDknxm
         1gngdsir5T5mIshVjyW1o6rte5H2VDcTzD6rHPFIzChF7Qmsfxj1q6gP0/I7Fb08CyWO
         BsMaHFenApkaio0EDddR3LBh6n/BRkzG/5LaLMN+BhNtlvTxMli+OYXxiHXIUnk/HDtk
         gOYxti3QeI/wzDTRymwYel1glgty+pBzyK1Tn8CJLwKJ28e7/lzM4hLqzB1LVxsAKG9u
         6f3tuy1xClWLaw4lYyyyvLp5UOheojZX6R8FRKYpSjTwALHnXlfvNY50hC/p82ZEatZ5
         sLww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YiAtHNDdLSWQwVa6u/rTIs9SF1vwafefqOP9tcL+m58=;
        b=I00QviMIbjBDx3bzzA0s1E25qY53KPtaweDS9LYx9nKwEKFSZaJ4jGPkbkctn39jv9
         sJfxYjd7sbSz51oK312FvnHTREZEA/EkZpaiAaDyOp0s8AV4Br93gxRUYpBiP8lwPeRU
         rdyd6LqRmqKtUeYlI21eFYjJD/0sPV+pcPku2HpA0yXBfVJynCL8gkFHK0k8pmVSkHFb
         vvA3Tn55ui/wwv/vaEnsPdDfR2FPOMNwtD1v059M0tUd7I1bXOR/EazjsP6ii2diea0Z
         eDcikEMWsVXWqbJA/eDofd2zG7jUCrI8vz6fSkIZZUOQbi9i2AX2Z8K5w4TEprpdyfwz
         q8cw==
X-Gm-Message-State: AOAM532DrCyZLNP2davf2xyVUOHqvpjrlc6Eev5utVulTbAQjZ8rLBs4
	v3hERpaCBUIF2rK3G/OoDbI=
X-Google-Smtp-Source: ABdhPJz4E+yxL6YzhgVFM6ZCReBW2k/By89zg762aGfhzmACiBHpmbG4P6FG5tMUvQ/t0qez0OMN3g==
X-Received: by 2002:a17:902:8541:b029:da:fcd1:7bf with SMTP id d1-20020a1709028541b02900dafcd107bfmr3491881plo.56.1610047105347;
        Thu, 07 Jan 2021 11:18:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb95:: with SMTP id v21ls3706974pjr.0.canary-gmail;
 Thu, 07 Jan 2021 11:18:24 -0800 (PST)
X-Received: by 2002:a17:902:d894:b029:db:e0c6:49a4 with SMTP id b20-20020a170902d894b02900dbe0c649a4mr3495572plz.1.1610047104759;
        Thu, 07 Jan 2021 11:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610047104; cv=none;
        d=google.com; s=arc-20160816;
        b=dbjWXy5YWe0mZeXLR/JybiGN4AwbziZh1tpyGgURgMEJUElXrUCwt+7uMUTTZBloYQ
         nnvLvLwVHE6/zS3GmtUl7QfeX9mD7OsZi3pUX67nHOmvTK7AeAdjn69c0GjLdqcUO96+
         7iZRdr6mGKatxO7HjYySNfDX0SbhuZPVCYTGSTU1i5YOzzNFtXdjhPjUvT6dkpO3d9B1
         bsLej0c9OkrHkouLSWuNkq2XRutUnUuEdKviqODrqvELqGmXuzPFxZosvn7rS31yg0iY
         Zf8BmjdwCwGTy89GnfARGCMqK/HdUvfdLqSlFqM3J7r7qk6c+zh4M5ZC15QklWnVZbrS
         w06A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M9UAwRqMYaSLZr+L6zDMPRW6RQbwfEgXAtxlUxRXH2c=;
        b=PBGLqgV/w4c2wWG156xfX5U73GpwM3T9QDhwhXB8iv2lrMsga3k5lrgOJz6Fvjre/A
         VX8jjewBpO1pB7guuvztGQKy7gw5Zx4uEnUZuecC6kjk4AARoPdaDBvUnhcQjLpCfcFI
         IUv1Wyxne8NmLDqz1vratg60xQXDtqzjgXYV8ro9Ahp7O5n99x2z3DMu7wCGqF4GU6XD
         enNqWdVBktVBR8MD/vH/bigW3jomFJhM34LjRERkAsbHcG5XpKJUICWQE9rRTauCbymA
         f67/NyAYwzoEKiLghj1Kwk9Q9s2LSPKhJmfc2A+Hg09mIsPpAllhH7GvHl1l59dBzZk4
         zUiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SRNzU1EE;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id j11si550320pgm.4.2021.01.07.11.18.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Jan 2021 11:18:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id t22so4464797pfl.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Jan 2021 11:18:24 -0800 (PST)
X-Received: by 2002:a62:2585:0:b029:1ab:7fb7:b965 with SMTP id
 l127-20020a6225850000b02901ab7fb7b965mr278226pfl.2.1610047104294; Thu, 07 Jan
 2021 11:18:24 -0800 (PST)
MIME-Version: 1.0
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <20210106115519.32222-3-vincenzo.frascino@arm.com> <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
 <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com>
In-Reply-To: <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Jan 2021 20:18:13 +0100
Message-ID: <CAAeHK+xBrCX1Ly0RU-=ySEU8SsyyRkMdOYrN52ONc4DeRJA5eg@mail.gmail.com>
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SRNzU1EE;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Jan 7, 2021 at 6:25 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/7/21 4:29 PM, Andrey Konovalov wrote:
> > On Wed, Jan 6, 2021 at 12:56 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> >>
> >> MTE provides an asynchronous mode for detecting tag exceptions. In
> >> particular instead of triggering a fault the arm64 core updates a
> >> register which is checked by the kernel at the first entry after the tag
> >> exception has occurred.
> >>
> >> Add support for MTE asynchronous mode.
> >>
> >> The exception handling mechanism will be added with a future patch.
> >>
> >> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
> >> The default mode is set to synchronous.
> >>
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will.deacon@arm.com>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >> ---
> >>  arch/arm64/kernel/mte.c | 31 +++++++++++++++++++++++++++++--
> >>  1 file changed, 29 insertions(+), 2 deletions(-)
> >>
> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 24a273d47df1..5d992e16b420 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
> >>
> >>  void mte_enable_kernel(enum kasan_arg_mode mode)
> >>  {
> >> -       /* Enable MTE Sync Mode for EL1. */
> >> -       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> >> +       const char *m;
> >> +
> >> +       /* Preset parameter values based on the mode. */
> >> +       switch (mode) {
> >> +       case KASAN_ARG_MODE_OFF:
> >> +               return;
> >> +       case KASAN_ARG_MODE_LIGHT:
> >> +               /* Enable MTE Async Mode for EL1. */
> >> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
> >> +               m = "asynchronous";
> >> +               break;
> >> +       case KASAN_ARG_MODE_DEFAULT:
> >> +       case KASAN_ARG_MODE_PROD:
> >> +       case KASAN_ARG_MODE_FULL:
> >> +               /* Enable MTE Sync Mode for EL1. */
> >> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> >> +               m = "synchronous";
> >> +               break;
> >> +       default:
> >> +               /*
> >> +                * kasan mode should be always set hence we should
> >> +                * not reach this condition.
> >> +                */
> >> +               WARN_ON_ONCE(1);
> >> +               return;
> >> +       }
> >> +
> >> +       pr_info_once("MTE: enabled in %s mode at EL1\n", m);
> >> +
> >>         isb();
> >>  }
> >>
> >> --
> >> 2.29.2
> >>
> >
> > Hi Vincenzo,
> >
> > It would be cleaner to pass a bool to mte_enable_kernel() and have it
> > indicate sync/async mode. This way you don't have to pull all these
> > KASAN constants into the arm64 code.
> >
>
> Boolean arguments are generally bad for legibility, hence I tend to avoid them.
> In this case exposing the constants does not seem a big issue especially because
> the only user of this code is "KASAN_HW_TAGS" and definitely improves its
> legibility hence I would prefer to keep it as is.

I don't like that this spills KASAN internals to the arm64 code. Let's
add another enum with two values and pass it as an argument then.
Something like:

enum mte_mode {
  ARM_MTE_SYNC,
  ARM_MTE_ASYNC
}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxBrCX1Ly0RU-%3DySEU8SsyyRkMdOYrN52ONc4DeRJA5eg%40mail.gmail.com.
