Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFVJQ2AAMGQEGOFJF3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 292D62F7C30
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:11:51 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id c69sf4011322vke.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:11:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716310; cv=pass;
        d=google.com; s=arc-20160816;
        b=rnPY1k4rkPc2cmDkycCSfkwmOZX7VM35juOMVexcivRhOs4Aok+TiyeFf1NjPkeWax
         v+ip0KJgkd2FvUsBHMBuRjVLCeg7D9yxeVMq6cShzGairo5qOMcRNbG1jovD/mKrhMy3
         ULk8Dov9hAXdEwaU1DZ1Jy8CVIldg32O3PN5nhwaMZeOUaWWU1ORvpQqpaRqxLtieHmM
         DRr+kNzppWHFybO4FhAgyV4Q94QAaWR20cZWp19SoT1VWa4Slr+9XtfiGhi2XJ06hQKK
         z4nu+Vjk40S5OxAIu2pc6hILNfgvlM7NG6lvrPrLf2eXNwon6A88AM2qHqdJVqQYVF/L
         ydCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lJVrbRzy8mNZAQ4LZmGRDvNubkz2D5nwzKDHFm21pIQ=;
        b=bpGJ5EvHka7BfD6K9W7o+4gyRIHuAuhLKaLBaYqfBxmnl1R6sG84yBZ2XBV3grrvqK
         DTLnHhN4O6CmkfE7gyKc7QhqsnbclDzU/2h0cKBBYLcHoE09yKhIh3yaR7y0b7DA11Dw
         oRhShV1nleON3ziNp60XoTr0Szt49RGYj1ztuNRlu/UAhBDyw/SGxYIFCI2MBhwLKyeA
         HrX/jNaAPrPw+QCO1ncKDkOS7ggWGBZy5jywiQgpbZfnlDWXSTU3iaQCmzzzO/L5f6hl
         4L6w7D/eIN3CwySAYOQ8sZYRv+hxN990FYdJY/AeT582jaDh/Etxyil5kZGiVaf4vlnW
         SF9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnDXl4aR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJVrbRzy8mNZAQ4LZmGRDvNubkz2D5nwzKDHFm21pIQ=;
        b=fftLkgM5Ql5t8QykiBnofgPq29PGVlXe4BrIKMvqrtj3cb7mr6eDK2fO4zYdUeHure
         e5hV90n34G5rZbf2SzPeAPownuZxXwZFeZx00GuKv1Qf9Z7f0VrhbMDOdW8uwoW/hZh9
         tMvoXjKW0XvlYUG09My+UEheNO7ekt0dS37cIm5KNNQieaZ4yEO6tKidqaazHelJBv9r
         oRwFdaPM8ETw/f09n6DmUhgZbpgNkWQAhdJYJowYqDiBqpmpeUw11JUvzjcJ2Jf48bZr
         UT/Bldea5zZ9bDL7+HA0jOiGH4z/uyyTAbeHQ3J1WPdBG+R+IWzT4J36erMgcH2oFdn4
         /aEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJVrbRzy8mNZAQ4LZmGRDvNubkz2D5nwzKDHFm21pIQ=;
        b=AekjEofoBna2QqYZEyCFLgGR+EIpDCFKqZQ78NWSPTriCVOtQG2xdJfrEwf1CrJ3dx
         hXQYiH8FHhzjq8+enM4tgU0xgj9E8WDh7cY3J3m6OyyxBKFOPJ9bgU380xqTW4JXKEG5
         Is/Gwuk0wQhYL9Hni9ObBzadwcE8g/qiVbYExqF+TWDywZuYQWsSTKpVtn30i+S+GX16
         GPNBZRf+KLA+58qtab+Sp7yo5dDQOgRH5nikOUg2LmAJrH7TDoZ9gBaMDx/pZSeKaNPu
         h8AU6ra2thmEwDf61NZjL/WpHkT0NGLNgDhJRQjoqcibZBP3p6LeCe9dL2/KZQZd15cM
         FhGg==
X-Gm-Message-State: AOAM533pmR5sAZIoDGDgqMM5s2CqVrUWyTSvB0ZiwnIosgYlFb+8LWvd
	yCUtpEjwLQmDGRovLlLvqKU=
X-Google-Smtp-Source: ABdhPJw3ga9Dp8ksprmfESwOb4x+SQgaLqA3U0KqsLHn08Jh2ZZCEvVVzhbSPJHWCmSyZzX+lYIQMg==
X-Received: by 2002:a67:c282:: with SMTP id k2mr9699314vsj.1.1610716310282;
        Fri, 15 Jan 2021 05:11:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:11aa:: with SMTP id y10ls492966vkn.1.gmail; Fri, 15
 Jan 2021 05:11:49 -0800 (PST)
X-Received: by 2002:a1f:9ed4:: with SMTP id h203mr9953401vke.1.1610716309724;
        Fri, 15 Jan 2021 05:11:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716309; cv=none;
        d=google.com; s=arc-20160816;
        b=Wk9LmOWokrBhcksMgZJ1nollXvZVvcDH59B4JzgkfKy68SwCmQynW7VQXmn3GVQJt1
         RwovSsb4Q06DuONcl9m8PDpsToNuntdmt9kXoEXmbRlOUHsPaN0bZHxriGqgXg9dOmzm
         3+yDTggqT3W7oLie+WYRTIUnYCcyjM3I3vlbclIRceeU1E4u+Q7JKXmQ+zFQet4Ea8LV
         lbZveec+Qgwi2qe3tIk5kK398jPaU47cwnYW9sLC9niwQGKShJJ8EGlZh4/hC4oLGzmx
         be3bcouQOKqbvcDhWE41ow1J8aNtDRNYD4X7pvXWgmX6oksmDGjWgAA1G6XZaVGd9G2v
         PfHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6umvCsAyn8LNlLKR4Gh0cZmveVk8fGwHsSK6SRMZEbU=;
        b=imHEMIUCyNrvYeeKGhzaaHGSew5HqkNG4lAQlLe2MokQowwLnQ5xgPB1Cy16pQtQGN
         yQqiETFA8+Tr6PS+bIgKrj1CbUrgbN5Iqa5AC4uIcsMAlOfFkdyuOd33e6z865n5DpZ9
         dFGUWmC6hbVeRalK6roRJk0y3+vLjoeZ14MXgExjaKJDoIbgiW/nXcbIFqeda7evz+Ky
         k7pC1U3Wz6kDbC+uNzVfN1TWuu6SgsNnel1nioZOpjlqySlEj0doSXCfmPQ0bxDrr4eB
         yR7x9GfICPjS7yWagwydOLdS+Ack078gZG17caqkkWjMhdRjB4Ta+HjgKxPAptzxjKbF
         qhPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnDXl4aR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id q22si528618vsn.2.2021.01.15.05.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:11:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id w2so5438298pfc.13
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:11:49 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr12292780pfh.24.1610716308705; Fri, 15
 Jan 2021 05:11:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <dd061dfca76dbf86af13393edacd37e0c75b6f4a.1609871239.git.andreyknvl@google.com>
 <X/3yDGfTJ+ng+GJt@Catalins-MacBook-Air.local>
In-Reply-To: <X/3yDGfTJ+ng+GJt@Catalins-MacBook-Air.local>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:11:37 +0100
Message-ID: <CAAeHK+ztACu-tU65a7iFfX+TaQixCUzi2fngypOYuaRhOcUcdg@mail.gmail.com>
Subject: Re: [PATCH 05/11] kasan, arm64: allow using KUnit tests with HW_TAGS mode
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SnDXl4aR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42f
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

On Tue, Jan 12, 2021 at 8:01 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Jan 05, 2021 at 07:27:49PM +0100, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 3c40da479899..57d3f165d907 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -302,12 +302,20 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> >  static void report_tag_fault(unsigned long addr, unsigned int esr,
> >                            struct pt_regs *regs)
> >  {
> > -     bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > +     static bool reported;
> > +     bool is_write;
> > +
> > +     if (READ_ONCE(reported))
> > +             return;
> > +
> > +     if (mte_report_once())
> > +             WRITE_ONCE(reported, true);
>
> I guess the assumption here is that you don't get any report before the
> tests start and temporarily set report_once to false. It's probably
> fine, if we get a tag check failure we'd notice in the logs anyway.

Good point. I'll add a note in a comment in v4.

> >       /*
> >        * SAS bits aren't set for all faults reported in EL1, so we can't
> >        * find out access size.
> >        */
> > +     is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>
> I now noticed, you could write this in a shorter way:
>
>         is_write = !!(esr & ESR_ELx_WNR);
>
> >       kasan_report(addr, 0, is_write, regs->pc);
> >  }

Will do in v4.

> The patch looks fine to me.
>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BztACu-tU65a7iFfX%2BTaQixCUzi2fngypOYuaRhOcUcdg%40mail.gmail.com.
