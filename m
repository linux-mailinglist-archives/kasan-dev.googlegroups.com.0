Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZFN4WAAMGQEVAKWC3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 968CE30BFC0
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 14:43:02 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id y186sf8482866oia.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 05:43:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612273381; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBOyQyAbVMng9UHWQsY8uc5KUecMgz/vblwg6LmBNV2DwU/arZrDWqLx5XE0iSa78h
         pghLTUige3Wo/6KAL1mSRgrQPRruvdTLQqLTrr1PwnPVEao+7zPE11f5NAb8i1WVMxyG
         bjiNcwTVfzs+Ok9s/7VOEQwNsg/AYKgfnxIza4Fd4+v2A2MnoFsN/4OxH6/q8S58fgeL
         CT68w1UR20k34tqR3MaIeNprdpJs6bYkzXYGZ9Ll6F/IeSbh87swVGjv1aWgjCxgqmmf
         jevnLLAOSloBgBOorZHgfA8+wLGSKels/4SKNIjPrUAYBe5CCw8ZEgKn0RGuuaaIYjkx
         uJTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bRbtzMnuRgFx9VCi4GXIRKGH4LdAL+j7KizOcLiGtow=;
        b=Z3404jTmmHlWVGfWZxGLyw/9I2I5uq1r4L/vWI8Nu3psttW/Zb4hGYC+FdOcbJaKM2
         Eoza9CceWfAJwyIgPur3qbQPQAXOjMsy5ADT9UFRz9pCybYuP8wTcVE4oRWUEJi5XPbK
         /DPsiEBXS0U7BxDW9yhzilYP12oGiox110jDsFHcvTQZVPtdX/YhFIQHuWXunK52C4+p
         VQqmbFCzebFl+PBpcnm8mjZo9X15ExvR8h/E4dYVX+SLV5BHZHucmQJ+cQ1/L1z719XU
         yxPxrd0gX8Hm+t7phSMiVRDsz/Uqfha9VQLN80sX7YKZgxhe8nP5CW7VcNp0GQiLU2TI
         iD+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJMp7HyS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bRbtzMnuRgFx9VCi4GXIRKGH4LdAL+j7KizOcLiGtow=;
        b=m4oAyk6uTWGQxAf46tjwtkTr+oOHmYl/CF3JUNFkpXd8VsVFOERgKkO4goD7br22JG
         u2JmyrzIaeS0Vfs77GfKbDF9uV1qJH4xkkWIYR9ll3KLA/SzVGlQMWiNsrHUcZJBo4bo
         TiaJ+dYWwBASY2rkFs3OMcYM1cW75/uVwmXscvvJBtjZ+iOJCdTeUGY84QGHSVKuaS9u
         GPr6td529M/Y0CD/3gv9k4Ew6gWr8KSv4YTwxJzqO/8btjo7rVlfsknzsPZn+7zuq74N
         3Yjv7/ULHsTz1i72Mm32LTygg660VZzeCCZf9IRnswRjsezxEQaYMkLPtmZilzscoFzv
         J8/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bRbtzMnuRgFx9VCi4GXIRKGH4LdAL+j7KizOcLiGtow=;
        b=baA93vXLSiOj/cEJRgH7ltcs5GCufaFNc1k1jXCOO34l5pTlcOvu+j9Wl06uHdwFEd
         IqxqG2YLWY9X8lbLjO8UDlUh0aEsxHmvaIIZ/8jY9GqfBiKMxbRaOmdKGuffLb0GWjjc
         AtkeqjwmJzXHksGqhq3rcT6Ox/gj7Or/8BKAlCepLf+y7wQFJm+f38CYaEPqvpCrZgXm
         5Gz9Z9cuTr+t3H2vdjAt+Y/qjlnEPZFuOzSISSWJ5xGga5dA+b7QTgKSkScVffDu/6kI
         WVjH1w7mwUWOUIE7GkkE8XCnCCY/rthEqa6diLjUmD5aEFnRtE0tYj6I+NsaTnvmUHZ6
         jUnw==
X-Gm-Message-State: AOAM5306mO7GZ0CDaxwvzwc0tR0UKzzC53Wm3odIoWRzSfMeFe89ryCQ
	akg/TcumkzGKHoHWrisaGxI=
X-Google-Smtp-Source: ABdhPJz2YkxZb1tF2aItdZuCSvOdIz/EzWi5TOc7pm2LEly5ObvVnfwlkt2Q52C2qk15UfScQSdHOQ==
X-Received: by 2002:aca:4702:: with SMTP id u2mr2841274oia.80.1612273380331;
        Tue, 02 Feb 2021 05:43:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1391:: with SMTP id d17ls4847085otq.2.gmail; Tue,
 02 Feb 2021 05:43:00 -0800 (PST)
X-Received: by 2002:a9d:664d:: with SMTP id q13mr15125146otm.156.1612273379956;
        Tue, 02 Feb 2021 05:42:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612273379; cv=none;
        d=google.com; s=arc-20160816;
        b=O7ZJHws70C39zRsBf3RJvQDH4rDtOzBj7TmWAEyE3SIDUdYpIwDAIZQNHREByrIbba
         Qclp8wUda6ghdLv9DK3XY1djBha5SXAF9viB551IPWdCutGwuWr5wihv86rL+YYePfoH
         uIXlnBiq2Ibp2ubpLMDvJWhBHM6Icah8WK0eciVJIrV7thI+C8Zo3IT9JkrIa7rusYQ9
         z9tfwozY2VKx4KvlYXazlAOdRtNFWwpRmj1f5KUeEyFs0DV9JdMHaFzNGHCjeSNhtEnI
         uKVYDOpiCMVJIiddCfZYfYd+1ZsmWfwfXdpImpm1slcQeG0HRKK249/sGwrvfXzRB/4o
         ZH9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ULfru5VoR6la+blRMAgVbCUtmZDEDwFPNm2BTtvrXik=;
        b=ADJiNdUlrMBTNTMhODFdW5d+9/VGZFRnROwBBsNothv++nqKK3izCqsgI42PyNh3vM
         mjd0aaEAN7A/eR8HksOo5+PGzFyGwxXIKOa0sSckunbhapff6TcYBWhHco9asianTBGL
         i+JM9WnFoNLpFGw3XC1+AKB+Ama9n/cqh1kr5+UDTrTq3EIi/Y+YWTuV3lpuX9d282fy
         2NyccR2YlLD5Mpm/UxCg7ZBwCXeL/KkEYNwINP5VGpmlB5KKYKq/P7U6k1wzJ0S8WRFS
         0vDewW71dkADc+q5EuyQKIgs73fhiSeZw8s3UBC4Ur3j5wxzu62ldRL5V4c/Fhd2d0OE
         2gSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJMp7HyS;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id e184si1733242oif.0.2021.02.02.05.42.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 05:42:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id o63so14901243pgo.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 05:42:59 -0800 (PST)
X-Received: by 2002:a62:18d6:0:b029:1bf:1c5f:bfa4 with SMTP id
 205-20020a6218d60000b02901bf1c5fbfa4mr21354404pfy.24.1612273379132; Tue, 02
 Feb 2021 05:42:59 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
 <20210202104618.GA16723@willie-the-truck>
In-Reply-To: <20210202104618.GA16723@willie-the-truck>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 14:42:48 +0100
Message-ID: <CAAeHK+yACsAfZqx2gbgoTMZHym5eMNr8e9XSh2+OL_UuK3CiQQ@mail.gmail.com>
Subject: Re: [PATCH 12/12] arm64: kasan: export MTE symbols for KASAN tests
To: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wJMp7HyS;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536
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

On Tue, Feb 2, 2021 at 11:46 AM Will Deacon <will@kernel.org> wrote:
>
> On Mon, Feb 01, 2021 at 08:43:36PM +0100, Andrey Konovalov wrote:
> > Export mte_enable_kernel() and mte_set_report_once() to fix:
> >
> > ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
> > ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  arch/arm64/kernel/mte.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index 8b27b70e1aac..2c91bd288ea4 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -120,6 +120,7 @@ void mte_enable_kernel_sync(void)
> >  {
> >       __mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
> >  }
> > +EXPORT_SYMBOL(mte_enable_kernel_sync);
> >
> >  void mte_enable_kernel_async(void)
> >  {
> > @@ -130,6 +131,7 @@ void mte_set_report_once(bool state)
> >  {
> >       WRITE_ONCE(report_fault_once, state);
> >  }
> > +EXPORT_SYMBOL(mte_set_report_once);
>
> EXPORT_SYMBOL_GPL ?

SGTM, will do in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByACsAfZqx2gbgoTMZHym5eMNr8e9XSh2%2BOL_UuK3CiQQ%40mail.gmail.com.
