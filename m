Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZVEW36QKGQEGWSYXRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 691942B0E7E
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:52:07 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id y5sf4234440qtb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:52:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605210726; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bvb6RGKFAFlpkQpBFj8Bavjx5VblA+i2CyHhXv6hl6KoY7T0hlqCqYSLzFVaLVKbYv
         f7Abpv6AcW8TUql0d1cYK3xOVVvsupA4EqqRFfra8L8MfO5sWGrvB6vl17RLfb0ZZDai
         FDKjidakxUZipi8+vgqkDLGMydaN+IejDyBSR09UtKGMp2Dm5+7dvjmFDIBSPCTn7Wgh
         j8bvT3y2V45Jy3bGm8U1qXjeVaah9m/Klahd9U+C1SufiHYUtZ9Gk+my9vdY2ALxtT0M
         HyJOZV08q17Fvq2dY/v2mPrBrzZ3hF7dUZI0nmpM0YTPFtLStXBnjfPXcm4od3BzopO1
         aK4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fek1KHIinRGfXxZrsqSGHlcYVbA1u5a23IVvlaMxB9o=;
        b=EZ8ZbDjVGvqE2ueREZHMrm9FRoZDhHOj7Kf8QFlEaIw3aFUPzgXo7mageJQy4XtBMY
         JJgGwcDMiVTSVqrbyRvuNV38yTTAPU3/bAOSyxpUR0UFssnOUD//3Eul3MjwlR4OUXuv
         obrYi3gCLJJaOg8enBj5G16Hi5PeLWqnkLaojglE77wCWpJf0IKu8JmWoc7wBXJlbtMf
         WTSOKsjpS19pTxEyV7qi0mub4KpnMpsqsTqFJhN438wHbUSK3zgiq69vTx3DCfLXdYfF
         GekqwpJ0WaCpY0ck6EvgqNgNE0cuvv2AyvreajpbTEiVtg8RNcQckPQK1/XHAip5DXbE
         ezfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=euZJ1KFs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fek1KHIinRGfXxZrsqSGHlcYVbA1u5a23IVvlaMxB9o=;
        b=FKjPUwo0qwJpVtFeGu0b3uyx+lCennnaN0Sdo9hNd/etp0GHLjxarvDPL/agkWYvXU
         xZrTohitUDNR3qQ5BFf/7pkwJEbvQC6btG03V9dLGbXICasBdAhBugSLQ2paBUOChED7
         1sdv9kfCERyFZ+6TvtlFek7qD99+DZECbUoInwmJPbZKdIDIOrb7tfcLTLVdr++4j7nM
         V8Up1THKYz6nAW2cqRrfbJFOdlWWAoEP9A+h6TumWNgjTY9KwPehAKrO+67NVxmO0XWM
         TW9nRrlUGrWJShjHnKQeFC7lr1DBq0ARxc/eyw02xMnaGScFdmUWDX6k66hNmiANkUYz
         b4bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fek1KHIinRGfXxZrsqSGHlcYVbA1u5a23IVvlaMxB9o=;
        b=kLsujNt9/RvNZwGX2ZUM7lqln7CA3pdz1zFqtKtViG54lhyIq1xkE3BomrpAohvWct
         HJTvv9iMc9QALpcUNZIi7qGDSRrw6vP7modINi2kilq8ngTAFQNElICQ5g70wINGc/OZ
         9nw5x2gsFGFWL+OBXLLpy+12EptWCF4rrMHtG/tqgwhMvyOOfBctnQ4yZULC6z/4gpMq
         5+8kA0BPbSkt3g+8pXyQ//zT4iQx0in41Y5EOxR5TXDpYO2QYqxxs/dC+ngutBdGgJpZ
         rxQs6f1tMOWm3K2ba5LOg5uBG+J1N4cCsEJN8F1ootuO3wDXK5zdK8wQasf62iu+JSdW
         hMng==
X-Gm-Message-State: AOAM530lDCQuXpgWB2LQEYzGbGRgtPnPakLwEf580ksfQznffvz24gr7
	brP4zWboB/pFwwl1k3FGlNc=
X-Google-Smtp-Source: ABdhPJyx4JjfgwXa9Lot9r88L4nem7mWxLBNu7OlD3+eAIqsJah0mZLedeSz6MrNcWxlTSh4m91dJQ==
X-Received: by 2002:ac8:e41:: with SMTP id j1mr862995qti.43.1605210726538;
        Thu, 12 Nov 2020 11:52:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:26c2:: with SMTP id q60ls1377179qtd.1.gmail; Thu, 12 Nov
 2020 11:52:06 -0800 (PST)
X-Received: by 2002:aed:2be3:: with SMTP id e90mr844003qtd.127.1605210726097;
        Thu, 12 Nov 2020 11:52:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605210726; cv=none;
        d=google.com; s=arc-20160816;
        b=BDNKPd2rlT+EDta5V0iEBa/bAf4SnKkf1SEH7/hd1qoOTR6e7Nll5m+CQTWnkiNjAa
         HX1EmDjPpeas36T3pjqjVjJgDStwdHHleeonbp8s6xz9Ysd4O98IwUOn9rotBbopU8Be
         6DYHyLrOkGrNxxMjm4h194Qcwd+kiJuUVhAibc/wCyaHD9Qs/Q3BFSAqQ3EoEH/AfmHa
         aPIjHlrF+0mPhgdi+qVxlue5pQdzJVUsba90LBFiQiCkjB2lDzI4f9HJ6zOrT2xLHyFQ
         5/su4q5ozgfki65ERgtWPq3SzGxjIRP3gTHqwBnvu3itNzy6QsjOYqUomjxhDxkEJjx7
         OdyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6grGTHRg8rsQq1ytOmJKPPc/a47JtcnHiEDyRqBbLFo=;
        b=GgylahAhJJL8olhpq4SLnCvinS9r+CJHrKoiDqP5hCP+px3vYeXQPMyFj1PiitnNUw
         W5lcUwhRUkfPabCq++eesLsK1aSeQYakOtX+ekUiHbnYUNg9evz6MmhY8CRkzog3sec7
         E+NN33WDPQUZTTZEHJ7hnZbbubl+jwKc66LTu1dm4aKZ9CSRpmHP6wAiM2Kx1lRLcDsc
         6JNIW4daX9bPWjVebvY9i+3/EaGMdSXDVGuBqX2QTg6Rflrh32a/laouHvKrGIT0svG8
         bzqFyqaatIgGhJBokYYDTrfrIIcOaR3ssYN+eYylTPxTZucmYzpLtjp+vFL/cVVs1OtP
         e9+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=euZJ1KFs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id r3si433123qtn.0.2020.11.12.11.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:52:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id 62so5079814pgg.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:52:06 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr842940pjz.136.1605210725310;
 Thu, 12 Nov 2020 11:52:05 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
 <20201111182931.GM517454@elver.google.com>
In-Reply-To: <20201111182931.GM517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:51:52 +0100
Message-ID: <CAAeHK+wJz6qnX1Tsb9BTsbd4zjDXr61DLRmmNwDZ2+F6CwpQ1A@mail.gmail.com>
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=euZJ1KFs;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Wed, Nov 11, 2020 at 7:29 PM Marco Elver <elver@google.com> wrote:
>
> > +#include <linux/init.h>
> > +#include <linux/jump_label.h>
>
> This should include <linux/static_key.h> -- although the rest of the
> kernel seems to also inconsistently use on or the other. Since the name,
> as referred to also by macros are "static keys", perhaps the
> static_key.h header is more appropriate...

Will fix.

> > +enum kasan_arg_stacktrace {
> > +     KASAN_ARG_STACKTRACE_DEFAULT,
>
> It seems KASAN_ARG_STACKTRACE_DEFAULT is never used explicitly. Could
> the switch statements just be changed to not have a 'default' but
> instead refer to *DEFAULT where appropriate?

We need to either cover all cases explicitly, or use default in each
switch, otherwise there's a warning. I guess covering everything
explicitly is a better approach, in case more values are added in the
future, as we'll get warnings for those if they aren't covered in
switches. Will do.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwJz6qnX1Tsb9BTsbd4zjDXr61DLRmmNwDZ2%2BF6CwpQ1A%40mail.gmail.com.
