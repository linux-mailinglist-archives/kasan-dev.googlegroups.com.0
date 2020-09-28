Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX45Y75QKGQECR25LWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A53E27AD48
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Sep 2020 13:54:09 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id h96sf2224376oth.20
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Sep 2020 04:54:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601294048; cv=pass;
        d=google.com; s=arc-20160816;
        b=irnaKKvhFo8nIFsIjPhnQCCANyY9WyZTCuNKXcC3sSCZ3czAU1Z56/6mQBY/xbP7pp
         FixXPq4TSact7KiZOTjKQ8hKXzYbmA3XDdS7vNuw+z44sM138IcOG+sJFtUiNdEaMXb+
         Efh2dow+OKsv9HpiXYA7V7cDQEfnFM26CKTN6nac96pe3FsdwuWk1aTksaOCT5Mp4JH4
         OP6BnQlsvluRAcAm2Wzc1jfk7pJ4NaDPkBioLYU2vuCNwP3I7YUA3kKFO/TkHsl2nsw7
         R/SD0N2+r79zUtgwa/XsZdVOh25l3kSz/7uK6wRPuFmSaze1txGXey6jV00inAi73BCb
         oL8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vFJKv/mlpn+lxyzaUr97Eyw+j76nsx47aChFaK8I6vA=;
        b=EcDRFzuA2q5dUu1x/Df3vtvUtE0uvE47pmW72sqZOoDub6orpyQVfMVP+FTLZFSRpk
         mUt7iWgTUqDe9SRRrfAgM+R/pJ1JXSB971gwYdgCYlDz1cSQT2+6wvXoo6EB0C5530sl
         PC2bp9kb0ohWzjNZADPTv3fzkuKqr4coDrWEJIPWBBymZHQhSTRM59k3zTGfcpNjA8CJ
         rdyehkU50pL4F0CqL2BY1nUYhGVMFEit1FuipoM0py8w13khyzGzAJ+nzZETM4/U2KtR
         tANGQ0H3qHxjsTpo1k6nzcEkJJsAS8SDh2MEaVAbEnSHegSHRaoeLEqH49TCG/cDAFzE
         vJ8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FrUJQhU8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFJKv/mlpn+lxyzaUr97Eyw+j76nsx47aChFaK8I6vA=;
        b=ZS1U9AT+0vS4mGiWRr4tA8fLXBliGRtGxLo275N39Okdn8BzY+8D4wbP4+RG+S9X1z
         AUNF0Ji0rzOn0EkFeeR1b1lm57RYVn2eKVndxOFgd8MK5zD+ZxXe2r4SkutO4s3KdXhJ
         cNfqOYCGhaFIbm+6Sf77uoCXwoxNtg6V4ZuqXlhCy2QtGf/WV0yVSj5ooNGPaf4UGW3v
         lTq9dxCqB7nllo8yECL0a07el26AKg5JPpzIAAFncZ6mpXbUgslkWm9DPE6Qyv2OEgIt
         TNijyTN9V3sGFVYM9ZywF8GSEGIsvE4hAelZUaj4XW3OtZeAKtc+611tw7A8qp6xDkpw
         vSMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFJKv/mlpn+lxyzaUr97Eyw+j76nsx47aChFaK8I6vA=;
        b=kCZgmzvWk+UMP7wSZTKf0L3rTUf0dbNq+iHWnr60ljfVoXLocVOJ4pSbfW/eLj7hJ7
         6jWpNffhocz+qlw/An2gOcv4sw7x0lfVQclHqo0piO+6x1gJS9/B7jw8EWtNLzwXZ4f3
         J+rIhMok9pvzS46sGwF5ksCL/mFXNKG+a1Wx/94Zoc4hvMA+2FdqoOeIVw09tiXCbGpC
         2pg8KxUOGwnY91FxlkHtqSR9TQX0GbWOxNfrQggru1nqEAR3tZo6Yk7jxjEFB17ArAqK
         fKWNEt09ZeFwu7Y8wKn7KsnIs0yPG8uAyEkhlxfzv2NOVuyEnIYeZkx+zejnpaSImAU+
         KK4A==
X-Gm-Message-State: AOAM532uYus04rmUevTM0eu4M6GXKzSEZ54AvXb0iFz0vRL3WqZ1pHyP
	EO1v0z4LA/8pPdP/W5i7vLg=
X-Google-Smtp-Source: ABdhPJwbQ5vSrL3ABm8lEEvOmIUaF0ONe1eANV86cPdc6xwIeM1G+VWV0Y+0mIn9LD1AXzYhclYYAw==
X-Received: by 2002:aca:2208:: with SMTP id b8mr609687oic.113.1601294047908;
        Mon, 28 Sep 2020 04:54:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd0b:: with SMTP id u11ls146010oig.6.gmail; Mon, 28 Sep
 2020 04:54:07 -0700 (PDT)
X-Received: by 2002:aca:f593:: with SMTP id t141mr645698oih.166.1601294047546;
        Mon, 28 Sep 2020 04:54:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601294047; cv=none;
        d=google.com; s=arc-20160816;
        b=oCeZWMOKEijOjGtUmOyB+ZJrnu+XkSXUQnURsofjIRK/XW7LIvOaRJXY1zxcyYpixg
         eKNKDGJditsBcVojHRIlu25C+WSJEuArFBCnC7bVlyC1rn9aMSzObbLvFrnag7g3fjW7
         hzvQtWqJVVGhDSnnawLUMdRQkwxcbHaQzobJMmmk1CvN84BWNgvQuyJiIwmoxo609jRg
         IICPZwx57pLU8cQR8vMDKUSdZbbrjMyw5laLe++11/Lik8RGb46llUEMVu38K9PCTm7q
         0vF/ojA6Q6mWLgQ4kG39hp9rSn7g4uM4Y0T1vVK/0CKe74+g7EZ3nCairOoVcEQLdpzk
         Ue3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qVxE17p4zsLCszLlrp2+yy6w1PaUWdFxLyFkrOjdfgU=;
        b=Gpag9+eP2Qr61EAfgTNtMbS27ACYZU8aAHUQtgUBeGTXlxajfSF2InbqYO08WCnm1p
         2Qt8d7mf0YitsG+CWlC65RRI3gPdN+CytNoo15VA7PUTOv+diIdXI34lqiD/Tt6I8Om3
         REoo6BXRVBDjC0KZuB4MI1t1TRjtVLPg+hIM/jpBaU6N8BaX2W+rzYSRq1nfPxuSY50/
         P7vkQPZYe/FiqtGB9TzW+jhWb9PSua0xAfjvzVkgQr8ix6BOy9nQNl5eLdHXB+xoBeiK
         Ynf0KnOnSrA9y7tHW4kq7Od9Yavh5P9o+KjCt+wgI9vojXxsqXKewbkzc7eBMSJdpes8
         4+Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FrUJQhU8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc44.google.com (mail-oo1-xc44.google.com. [2607:f8b0:4864:20::c44])
        by gmr-mx.google.com with ESMTPS id k7si49542oif.3.2020.09.28.04.54.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Sep 2020 04:54:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) client-ip=2607:f8b0:4864:20::c44;
Received: by mail-oo1-xc44.google.com with SMTP id c4so225397oou.6
        for <kasan-dev@googlegroups.com>; Mon, 28 Sep 2020 04:54:07 -0700 (PDT)
X-Received: by 2002:a4a:a58f:: with SMTP id d15mr554121oom.36.1601294046985;
 Mon, 28 Sep 2020 04:54:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
In-Reply-To: <20200921143059.GO2139@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Sep 2020 13:53:55 +0200
Message-ID: <CANpmjNMS-6mfDF6o31yiejP0wmgpEeuoh0PP9QJa-qt0OpiRBg@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Cc: "H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FrUJQhU8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as
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

On Mon, 21 Sep 2020 at 16:31, Will Deacon <will@kernel.org> wrote:
> On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > not yet use a statically allocated memory pool, at the cost of a pointer
> > load for each is_kfence_address().
[...]
> > For ARM64, we would like to solicit feedback on what the best option is
> > to obtain a constant address for __kfence_pool. One option is to declare
> > a memory range in the memory layout to be dedicated to KFENCE (like is
> > done for KASAN), however, it is unclear if this is the best available
> > option. We would like to avoid touching the memory layout.

> Given that the pool is relatively small (i.e. when compared with our virtual
> address space), dedicating an area of virtual space sounds like it makes
> the most sense here. How early do you need it to be available?

Note: we're going to send a v4 this or next week with a few other
minor fixes in it. But I think we just don't want to block the entire
series on figuring out what the static-pool arm64 version should do,
especially if we'll have a few iterations with only this patch here
changing.

So the plan will be:

1. Send v4, which could from our point-of-view be picked up for
merging. Unless of course there are more comments.

2. Work out the details for the static-pool arm64 version, since it
doesn't seem trivial to do the same thing as we do for x86. In
preparation for that, v4 will allow the __kfence_pool's attributes to
be defined entirely by <asm/kfence.h>, so that we can fiddle with
sections etc.

3. Send patch switching out the simpler arm64 version here for one
that places __kfence_pool at a static location.

Hopefully that plan is reasonable.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMS-6mfDF6o31yiejP0wmgpEeuoh0PP9QJa-qt0OpiRBg%40mail.gmail.com.
