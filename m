Return-Path: <kasan-dev+bncBDDL3KWR4EBRB7WHW75QKGQE6X6T7DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E8013278752
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 14:35:11 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id i23sf1780427pju.7
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 05:35:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601037310; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5JQ/4ZNR5Lz9rCCTj34SlyJKqj8FJE26auNmxFrRvmNsCBbGMzNxqUa51vR+tmBu0
         HZ5JkIcd4nTGvhoZXiIMVdNi0nbLye+LppDpTYGWndGjzOESsD3ewIdehOk0mZYfjrpd
         iAfuKCBig3JGI+2Zgm4LMsYlOE5bzKxQnkxRGipdkUvhizUNUVdQ72t4WgMpKFr0O6kl
         iVGld8MOeCKC18ajzgCoOhe/yhln5VXZFCQtm9WbdEXkWU46uzHFXkzqxKzZAeTS/6ZW
         wqv+i/gO7/4VK3pNWTY/jxsiupcipKLCBFfC/2nO8a9N/PpYEVhHlGbiRf0saYamGw8G
         2HEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=S1hY1SbBqViRUuqQTYpZqfF002iCCGVKZ4IV/5DHtew=;
        b=PHEfuy3hiA9U28ZBKhLRr0HbS23sFsU6wRmrtR3oU/f0AkM48eRemsrDL1T1B0g1qm
         FGfobUjBaf/xjVFS83bTpZyGGY61m+rQh6xpfAVE0PK1if6PBVW85wfVE0nmJFbSd2la
         VifgFoK1ZiKQ7Yad3GKu0EW3ClOvpoU6TvbzEdFy69p3ETXh4NGtrW9vNetY/XoHn2Nj
         lHh2sHA/lVVYZoVBM6rxrX7Rb/7THtDu5ZDAEx96n6OFTFTeOq6oQD2+AEk/xNVEExq1
         enOtLkiOESbY5Z4ecLy0BQXhyr/OL/hTDLpvwo5I9+J9JPdqkuu1GpDf8aj9cHdu1kBk
         AyPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S1hY1SbBqViRUuqQTYpZqfF002iCCGVKZ4IV/5DHtew=;
        b=lCxX4ELCJ9K3eTpM9q2llREKD9nu6DhpP7vySBrMCuGe+vCmitG4e9Wpam4eYlGEMY
         I/pweon7PkgYoCRRnAbhX0JNTTutSTiONeezvzTEOyQu3zPreOvZeZxf2gF2zgQA2GEp
         pbzve6CxDYb55Mbx8Ingi2KhsHjO2nd3L2YSYPX0RISi0Sv9AAY9WON3GwkXzz97amEj
         GCyW4oYbz8U3fCztscayGUS4cmSYymFQt3IcOh8vaSWi7uHJ0l7ULmhI6sV4WZEr/VcK
         /cE7YDb7GR9YjT3PLxfpDuIPi0XFU3gtbfCw1+XBhzlv8FUqiJ87Dv/RnWE/CkrrLiOr
         wELA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S1hY1SbBqViRUuqQTYpZqfF002iCCGVKZ4IV/5DHtew=;
        b=N26me2jBEkmPVA1MJIM7JXaIbvpM//1JKrjMl0OiAED4qxqOaCTve+G5ayXER4OtJh
         oqvpoR7FRv9wtn6woJb5ypcJgj2sUyhgnuBuZ7PIi4PsTeHM9232gV5YqA/jYW2TLLsL
         gtHczCB638euLZqeQx0kzb//YMVP+E9YL3YNLuR6wjfYCllBba2Vagosi4KVK+SZSu6X
         woBrlaHstiRI3so72NNrPB9w8F4g02/pmO35o0ELDUbNGgjGKFf++kpcZCz4dhm3u6KD
         2Yv2JHAKekS6kRL+gbZn1TMvop5M19JsHH6vrX26K6D448BW/IDvDfE7HLUPyWIKBuUU
         9EzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KDzrxnTTosT+Rfc0duQPD9Y/B+LHMTCqpb8UiCcjjGjjSO/ln
	faaOHrT/KVQCefYOWGm4kwE=
X-Google-Smtp-Source: ABdhPJxThvLY353S/UbjfgP5Rqt3fvwDgmuVUs/+xqF28nFELeNk/pTNP+46ARKel2EH9h/PPa+YFw==
X-Received: by 2002:aa7:908b:0:b029:142:2501:34ee with SMTP id i11-20020aa7908b0000b0290142250134eemr3786401pfa.71.1601037310638;
        Fri, 25 Sep 2020 05:35:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7449:: with SMTP id e9ls1508000plt.0.gmail; Fri, 25
 Sep 2020 05:35:10 -0700 (PDT)
X-Received: by 2002:a17:902:a50b:b029:d1:e5e7:bdd2 with SMTP id s11-20020a170902a50bb02900d1e5e7bdd2mr4201433plq.50.1601037310024;
        Fri, 25 Sep 2020 05:35:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601037310; cv=none;
        d=google.com; s=arc-20160816;
        b=HIlrNTzhSf3KFzvqFS5h4WmutAwVYCRgRuQDrjvgvyzlRsa8+kpxrEg0bl7QwFVvww
         t+rQyAoQall7rh9R65UPZ5IRLUlF1Mxb3wz98vtOtV+R3YEslrufmaCsBTz8ngNwRi9t
         MkYV0qDlBHZ5rgvQ7UqG+uyQljqkSdrVLNivgZGtJThXmKmFlVP+v12u4cws0TBiCQtr
         HTrkD4hNupzL6gIgf9HRjRMKAwDnBkfIrDZ4YfL3UHwEGtpgvb13H3TT4y+DDc253RpL
         UhXGEPzSfrnKR8VwojRMjrK15AWrZQsostedreNMHzRWnTzo0NCN+xfFr0k7zkkTHdLF
         NyAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pkezcW52/JMjswPt3mf5JA0kEQ7yGBao8tcWOxGLQjY=;
        b=Z7r/XeUXLuXaLhxVLwz/BStoQU9zYBHnl79JW0lacpQwDliAq4eq+Bkz+ZpE9H1Gc5
         Feq2b9cG5XUPqzOpPGppfq+NvrCBLhXcFTf2St55gH3zX9rYd5ghEsFNwA8gAw5Y4YCt
         Xdpdh3t+V4c8zG7e21AiANnqYqMI6fDILYq3F8uQwQzDQhmFU0yIn0TAHUT1biFJfgEo
         rqOQiVz9k/rrlhVxlwBP9KghigsH1GEoHPS5PahjzcxsRqIzw0UA1CEbdIUgovHygKWN
         5Kn1YOR1UDFXUSMcsvAR/InrpuRTolRpaqMxF0NHF+/HWktgTi+GR/tJq9vVh5P4oe2F
         a9dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h1si172744pfh.5.2020.09.25.05.35.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 05:35:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02FF021D7A;
	Fri, 25 Sep 2020 12:35:06 +0000 (UTC)
Date: Fri, 25 Sep 2020 13:35:04 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200925123503.GJ4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
 <20200925104933.GD4846@gaia>
 <CAAeHK+zLFRgR9eiLNyn7-iqbXJe6HGYpHYbBXXOVqOk4MyrhAA@mail.gmail.com>
 <20200925114703.GI4846@gaia>
 <CAAeHK+x=bchXN4DDui2Gfr_yNW4+9idc_3nQAyjRTwMN6UuvHg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+x=bchXN4DDui2Gfr_yNW4+9idc_3nQAyjRTwMN6UuvHg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 01:52:56PM +0200, Andrey Konovalov wrote:
> On Fri, Sep 25, 2020 at 1:47 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Fri, Sep 25, 2020 at 01:26:02PM +0200, Andrey Konovalov wrote:
> > > On Fri, Sep 25, 2020 at 12:49 PM Catalin Marinas
> > > <catalin.marinas@arm.com> wrote:
> > > > > +
> > > > >  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> > > > >                             struct pt_regs *regs)
> > > > >  {
> > > > > @@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
> > > > >       return 0;
> > > > >  }
> > > > >
> > > > > +static void do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > > +                        struct pt_regs *regs)
> > > > > +{
> > > > > +     static bool reported = false;
> > > > > +
> > > > > +     if (!READ_ONCE(reported)) {
> > > > > +             report_tag_fault(addr, esr, regs);
> > > > > +             WRITE_ONCE(reported, true);
> > > > > +     }
> > > >
> > > > I don't mind the READ_ONCE/WRITE_ONCE here but not sure what they help
> > > > with.
> > >
> > > The fault can happen on multiple cores at the same time, right? In
> > > that case without READ/WRITE_ONCE() we'll have a data-race here.
> >
> > READ/WRITE_ONCE won't magically solve such races. If two CPUs enter
> > simultaneously in do_tag_recovery(), they'd both read 'reported' as
> > false and both print the fault info.
> 
> They won't solve the race condition, but they will solve the data
> race. I guess here we don't really care about the race condition, as
> printing a tag fault twice is OK. But having a data race here will
> lead to KCSAN reports, although won't probably break anything in
> practice.

I agree, in practice it should be fine. Anyway, it doesn't hurt leaving
them in place.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925123503.GJ4846%40gaia.
