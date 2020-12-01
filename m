Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVOHTL7AKGQEBDRS2UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F9202CAD0F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 21:13:11 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id n12sf1512257oor.23
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 12:13:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606853590; cv=pass;
        d=google.com; s=arc-20160816;
        b=ejI4b9L0TM9+LD21twC7UwbDyIWAkTizIj7tUpLsdWae2kvTmBdT2U9iLDXHKTmIqT
         gJ9GfLF/xb3CwADxxt3i40pWnGusD1h4eafIpSBbI8wDIyt+ul36LpEWDEBn6zJGmMuS
         w6OIMx6bt4VJDT17yKKlJh+VOFpIVmlYMKbJhEP1GyGO3Am2t+F1PhEZrwa/m+IWeYBp
         zJSsoiy9yVK9vJZcCv7nWrg7UR3XH/fAlpIXNhDhxHAZOdHZdnWLN551+itLw05WJ/2a
         mbgVd6bQ1emhq1zuI54T4B9RhYXoGVCLGApH0w8YbYOthzF+mMYj83Lad5HROB+UOe1z
         iDMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dHQAI9PSohQO6ZV/HFL7vwVUDkMvVbAnsvG4bmkmUEk=;
        b=XSv+ikptANf/rLaZ7FMj0oczHxBqYiY+FRg0HD7xUI7ZmWJdZb+RIvB8ysBXWAvtNx
         zh3fsA2diGqXl0QN/DIrkyQpcJHrsq4xBkagwKZmrGueCd+EJdihPOGZ6w/yFPN66geM
         MMSHD560ehwEMrl8rHtzFCXtfdEza9Ow2l/k1AsdRBTNc5NU03/H4wXVa1jJKhTIRqS9
         cfdKM4tOOdKrNvMKT4ptgRwS1s4EIX/Rmnv4PKGMm8bfPGe8IyrqNeuOmYTy4waowb1l
         t0d3BC3p/SHATrTDLHK4POh5lD7gmpiTZhnxWy6LZaQ/C4/V8cYb+88ZLqICr3i8O1f1
         osZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YpEbgJo0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dHQAI9PSohQO6ZV/HFL7vwVUDkMvVbAnsvG4bmkmUEk=;
        b=RQXpWwc+kdOul1AP2QvAU2o/KEt3r2D6FRD78yA0DkPyeApAk7VRmjUzdYmBmO/CtG
         lfpeq6hMlxu6rOsFwx7m8zWPlVGF68rR/govGse39wU0Z3Wu8lCfkJ6nqFpn1sq0LbGv
         Ol7rqyH6diWGeqLHrfOj4fujraQhfTFyP+YdI0q8P8RvkWW6kPtTXdAuN+OzZxtKNDNY
         tws/fPv19u1A5ia/J6YO8Kg/6+1RSylFvRX3wMkaSp8mohv1lr/QIwHa3tbwgxd5O/eF
         XmcRCOIYM1m7JnsbK8RBaBZdQL8PjtpYy9y/i5uiRadBB+Kj7/PfALFWFPQdlfrTVCum
         +ngQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dHQAI9PSohQO6ZV/HFL7vwVUDkMvVbAnsvG4bmkmUEk=;
        b=kLBtWHtgZIBdGW6ed2ycvbi4SRqDeCSH0RMjAvxLJ4AnR9RCsiF7mZydqQKougOZcV
         YjPW+DXY5OM63XUjwhko8LAzsIuEsfSIS6qOEPK0fWD+u3G31xh1CFz7w1oGvxvUIsZF
         /CadHCXl3nmvzOnQdxYLBHPjhKnLJ43/TS8AjU9cmOIeg0JvuIGas6WsRcge1TFNXneI
         IPw5iurnCwEvsdPpRd0QOo10mkIJzURwIgFzqJ+YISHxYJJSNv7P+mpzNU7csBSlTXuw
         mPokTYe8WcRhyVCXO+CsQf3RVVVMVGVJceeVbdR+EGAlU8nrUnFo7oj7TLxA7q7vIBcJ
         bRWQ==
X-Gm-Message-State: AOAM530gte8MxnpKkhyCPDGks6opa9xq/jbnbOh0cQDuw2rainxruihs
	ouQ1WloVYFZCZeWvOjQquTs=
X-Google-Smtp-Source: ABdhPJxaPFayEi0ArC8F4BY3OXezRjlrDiuEFHQu5i6qyZ6q+qFvx7W7IRaH9wN55DWz18wrGN11Bw==
X-Received: by 2002:a05:6808:9b7:: with SMTP id e23mr2827234oig.167.1606853590036;
        Tue, 01 Dec 2020 12:13:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:8cb:: with SMTP id 194ls648372oii.3.gmail; Tue, 01 Dec
 2020 12:13:09 -0800 (PST)
X-Received: by 2002:aca:4257:: with SMTP id p84mr2813610oia.68.1606853589613;
        Tue, 01 Dec 2020 12:13:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606853589; cv=none;
        d=google.com; s=arc-20160816;
        b=0uSGHNhdiY9PkzFD4hzdQE0q48Xtvtry4mx7EIbHov0qbCM2D8qBMGnAStRLHbgAVp
         Y8u1dB/JxOtxLLUzTyOydm1Op3viKfIUsAINfRs9IrEpi5gu1cg924GfSSA6NMrb0SxX
         P7A6z210/T4cY1+y7X2nYVvKzpSsN4AJ/KqddudWvjpqNRquEwUFVJ9VXhbOu2EBqgSF
         3B11xj1RueS8+UzT+PKRYdZofu7wkczrgJXKF4CSJL6CXicSruz70NMjpF42IIiWKNv2
         hhOOvLDwBKZ0e46yAvOmVfm1tzKo8Uk0R0rJByDSww7VSgkOyhgoOKpxW6unFtqo+YFC
         kmTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jypGaIji9YGM02Yw6XQ65mzgVpIH31CChrgBYlzyuis=;
        b=zXeM/riKur5QRV/OTSvicffEjBO14av+ouLJ9jWtZPCSwIVZkrMCwd3Fv+DlEzzMba
         6cI6ZS6pwIGrfHGKWaAqzqvvWVB+HmwWnqg9lUa2nA6Lfgw3BgaBME7vv4lZY63RRHh+
         Re8dry88vLKKzDFptnQEGzNSexAm8pUO+/6xfrYZi8WsQu8UTxmUgaCc5xq4gzG3Xtkg
         kso6CoKZ99IHDPUn0F4T4KHAu/uxCIhfirNIlH63Z8UYq7ZIirXCkRDV118RwGI1fcZC
         KBbc0PyscEylkP3HXw0QLXv1AaObiOnSaI1n2qyh++SoepTNcqiKYze57j+ndG7Shxih
         jNnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YpEbgJo0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id j15si99314oig.0.2020.12.01.12.13.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 12:13:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id o25so3158988oie.5
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 12:13:09 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr2977504oie.172.1606853589041;
 Tue, 01 Dec 2020 12:13:09 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
In-Reply-To: <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 21:12:57 +0100
Message-ID: <CANpmjNOfs8Of0Kvp3v7miw5x0Neg5i4egc43bevLV3_rGCNqtA@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Joe Perches <joe@perches.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YpEbgJo0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Tue, 1 Dec 2020 at 21:00, Nick Desaulniers <ndesaulniers@google.com> wrote:
>
> On Tue, Dec 1, 2020 at 7:21 AM Marco Elver <elver@google.com> wrote:
> >
> > The C11 _Static_assert() keyword may be used at module scope, and we
> > need to teach genksyms about it to not abort with an error. We currently
> > have a growing number of static_assert() (but also direct usage of
> > _Static_assert()) users at module scope:
> >
> >         git grep -E '^_Static_assert\(|^static_assert\(' | grep -v '^tools' | wc -l
> >         135
> >
> > More recently, when enabling CONFIG_MODVERSIONS with CONFIG_KCSAN, we
> > observe a number of warnings:
> >
> >         WARNING: modpost: EXPORT symbol "<..all kcsan symbols..>" [vmlinux] [...]
> >
> > When running a preprocessed source through 'genksyms -w' a number of
> > syntax errors point at usage of static_assert()s. In the case of
> > kernel/kcsan/encoding.h, new static_assert()s had been introduced which
> > used expressions that appear to cause genksyms to not even be able to
> > recover from the syntax error gracefully (as it appears was the case
> > previously).
> >
> > Therefore, make genksyms ignore all _Static_assert() and the contained
> > expression. With the fix, usage of _Static_assert() no longer cause
> > "syntax error" all over the kernel, and the above modpost warnings for
> > KCSAN are gone, too.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Ah, genksyms...if only there were a library that we could use to parse
> C code...:P

Hehe -- another usecase for using that library ;-)  If only we could
require LLVM be present even when building the rest of the kernel with
GCC.

I guess this works, for now. Until the next new keyword that is used
at module scope...

> Acked-by: Nick Desaulniers <ndesaulniers@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOfs8Of0Kvp3v7miw5x0Neg5i4egc43bevLV3_rGCNqtA%40mail.gmail.com.
