Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXU34L3AKGQEYCZ7JSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 90F751EDCD9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 07:59:59 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id k10sf1171456pjj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 22:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591250398; cv=pass;
        d=google.com; s=arc-20160816;
        b=NcDGqHVvHf62lHsAszOsC83UgGc3bbx0TtVbs59xmuW+MtoJb/jgN00t3IHDu/21c/
         gdkwcfVL0Tb7JCjlY0UH3C/H1XzN5Y50f7cUza6n0PbzlnGIL0LdrxVQx1iDXpOpGEeT
         QK9GvfK9dKa3WUCE9CX7x9uEu+eSazRVoGFhCs8RW7lDaMbU8s3Xl+d8yMMVSiNK8veh
         82gAy+ptOwaLrhBjWToWhhuVhCr7uGGgDdT+jAMPNSerF/jCEdtmIY7jwepuDtfeUqeF
         GM/1mDyhZAIV4INHwISYybp4N8gY5i3oUDT162ASccVtSxEXKiAM8msPiNKNlJeqcpDr
         5AJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pChmkISOdG/2aEyGpKnJQDgL84Lr9tPCmORFQdcWTQA=;
        b=DXzTwDlcjU9yQ/bOJDGmwaozS47FZ9xJvb1tW1JJ7zcn7mMDMFdqnEp5gN0E3ZMLHW
         Zf1oEkGD8u+T9oy9D43W3ObvELp9h9G75/dLMvB9Qc9FLadZ/m1Rb7PT+LpbF8UwzA8T
         mkt9Hor+XIlt5I5aVuD7bLbUfoYvKsdNaJUBzGhRZaWSq2yt7K1QGlr7HdXlnPxFzJLB
         g00olc1dwzf20Ee9aKHJW5+um9hR1k5WK0fQlSYe90z7lH2b9Oy0dQiJlw48JsochxPT
         BfF8P+bqRoIu4cx4ZyPt7JN3sIThk/NEJf4Q8UHUWAfprx/td6Q0g6Pg2yn5greQpj3+
         G5Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OHcY6D7S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pChmkISOdG/2aEyGpKnJQDgL84Lr9tPCmORFQdcWTQA=;
        b=E4x4KP6wjdj430PLvaJdD2uN79GDB7r/C2NEMJEH6FBKKzXt9fRyvem9eUZMQqwT5Q
         7SA9T4qSbKaWCs+sCaT+8zSbiWLiv467UZcMlFcCs8bWvGSQDFepSxdbirNJvOY7DSyr
         Dt58zn1f2dWuLE49lnhuml6ZXEBMblMnkCKOGK6Jmgcrqc2e4LPav172V9pAsw0R7kyV
         0TBC8hMQrwShQo7TenWVbIDJhZjz6XGL/vBkylOcxMePTig8ieCCyhEM2BR1Pr2FnjPV
         Lgf8T6cTz7Dl8XsBTdBc+xkbI/ZG97gkl1VahKWlUokN+dXqPMI/OvFCOjADjl33Re39
         tZkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pChmkISOdG/2aEyGpKnJQDgL84Lr9tPCmORFQdcWTQA=;
        b=t/ReJGaQg0OyFS4WeBtJmM588WGfgnmVGYRtpHVxzEqxXRMSznSQtFxNmDraWiqduv
         2xF5LBFfiWalUhcjQErQaWgIQMEYedQHIJfyEz3VxQx+JpupqWKt3JNTXOl76Ne1t1LZ
         3UHR4H3FD2OV/mwB3/3dDVYoM8zi9hocG/y1pUNhd13g03QwqNZnx7Mw3O3y/bu3Ji/C
         BAuedZpp9TLFFzWgRUIlmDOlVtuiJypsKdnJWInN4GRRonqXLu+z6WfsK+qwAjAdMSuY
         o0gupnTj/lCy0F+Fl3BKmE5OAJhZ+O4XA9Fd2bLca36xocGxSbz7vGBg7Ggp3orXFf/I
         4sqA==
X-Gm-Message-State: AOAM530T5/MRqHyzN50dkI59dKAGJkAfKbKOBeRIuSWDSeU+oWOC8dVb
	kY5W++bnRmoGzDvSj4puAX0=
X-Google-Smtp-Source: ABdhPJx0iAyXKSPsbwhTPURSXEjgtxHTisF9TytdJA7lJAa0CLj4HHy1QHbo5fraBYbzgNkADPco1Q==
X-Received: by 2002:a17:90b:ec4:: with SMTP id gz4mr4268938pjb.36.1591250398287;
        Wed, 03 Jun 2020 22:59:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d0:: with SMTP id n16ls1327103pgv.6.gmail; Wed, 03 Jun
 2020 22:59:57 -0700 (PDT)
X-Received: by 2002:a65:40c3:: with SMTP id u3mr3007048pgp.305.1591250397843;
        Wed, 03 Jun 2020 22:59:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591250397; cv=none;
        d=google.com; s=arc-20160816;
        b=fLccrtH5NEkjI01G+64GIeLf4PE9waoAu62taLcJC/pztY+aW2vsp0zJoHZOJoibHi
         a5Nys0yrb5W4KMGzLbKhhUyiUsiR0/vUJupHCboytTe1HsgSJzNpbFpxBvT2EPBgRAM5
         04y4jx2dftfmvsk98jrfeeyn1Y05RuEuIdvuVAP56xKoCzmQiUBt1OXvnrwDun1nj9nC
         ulR+9qSLeZmW5LoUJ4C/yNSRkbVVkx2/AvztB210RinrQhxLN/dSWx8vo+Npn9EYxCGH
         CGJXLjFIoq/f9TkFXaC6i4Zgcb2bxsjlXD2vdfUspv3A6jJX86UQ/E2IDqlNHJcsg7iM
         lF7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0+kU4eqI2FNaJfdh4S9BVeiYnuZgar4HG9ySm5E8SrI=;
        b=e6KziooD1SKCXdpDX+gtQ/mL0Wr45r7AYcMiGsfn67sBGz/lzKDg+QoMcNa89R0WNN
         7MVAm7gl53//E+K9qFu3GP0PN8F7Tx9vt5QjbuvKsZAZ5M9vslWsLIQzzKC3d/hz+g1Q
         PvS9AX6vR/gmzLWMxsUUFCsPOJvYA7Km3psTdgHDYv+FI3WiTvbd8wy2H9N0wYwXHQoT
         QQwYosjnbDpgEci4i0Fwo+q+S8gFbJbe8kkcxjR1htg9ze3WOvfxy4WkVo9R3u7SRNbW
         wx/INZTQKKGa05r3Gd/DV4eBp7KkdhanKv9GbzASq1Qz3L34kr0j0kEmgW0gTERcAmH+
         GRTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OHcY6D7S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc42.google.com (mail-oo1-xc42.google.com. [2607:f8b0:4864:20::c42])
        by gmr-mx.google.com with ESMTPS id l22si258279pgt.3.2020.06.03.22.59.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 22:59:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as permitted sender) client-ip=2607:f8b0:4864:20::c42;
Received: by mail-oo1-xc42.google.com with SMTP id q188so1018722ooq.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 22:59:57 -0700 (PDT)
X-Received: by 2002:a4a:e836:: with SMTP id d22mr2646851ood.54.1591250396888;
 Wed, 03 Jun 2020 22:59:56 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAAeHK+yNmGB6mEQoogGhUh_F1fXFF_baA14G3=4NyYv=oz8Fdw@mail.gmail.com>
In-Reply-To: <CAAeHK+yNmGB6mEQoogGhUh_F1fXFF_baA14G3=4NyYv=oz8Fdw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 07:59:42 +0200
Message-ID: <CANpmjNMoOOr1irxkGHz9S+dP4M4h+mpGu_Ve6tmaGDb0zN-bMw@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OHcY6D7S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c42 as
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

On Wed, 3 Jun 2020 at 15:35, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
> >
> > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > have a compiler that does not fail builds due to no_sanitize functions.
> > This does not yet mean they work as intended, but for automated
> > build-tests, this is the minimum requirement.
> >
> > For example, we require that __always_inline functions used from
> > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > fails to build entirely, therefore we make the minimum version GCC 8.
> >
> > For KCSAN this is a non-functional change, however, we should add it in
> > case this variable changes in future.
> >
> > Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> > Suggested-by: Peter Zijlstra <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Acked-by:  Andrey Konovalov <andreyknvl@google.com>

I've sent a v2 of this, which limits the compiler-bump to KASAN only.
It appears no_sanitize_undefined (for UBSAN) is not broken GCC <= 7,
and in general the no_sanitize attributes seem to behave differently
from sanitizer to sanitizer as we discovered for UBSAN.

https://lkml.kernel.org/r/20200604055811.247298-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMoOOr1irxkGHz9S%2BdP4M4h%2BmpGu_Ve6tmaGDb0zN-bMw%40mail.gmail.com.
