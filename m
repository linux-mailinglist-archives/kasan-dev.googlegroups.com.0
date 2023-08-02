Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWGLVKTAMGQEN7IV45Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 555DA76D732
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 20:52:09 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3fe2a5ced6dsf1018935e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 11:52:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691002329; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ldi3nLpD/rU0xkq5ZOHwNGsGeAyISofYQOKaeZApyn/PPFH+PU5SZwaOnHzhSG7oEQ
         I+YGBvNOJeO6RZKrAdiQUITpFg/tZ4PkBw6bQO1uDHORnKeqxS8IlrqqB0kRuq8CEdfY
         oBgEk9ka2/J1WHTWxOVv6yHCBJ3GU1OuM9D7gem2u7RVuM3ldO5+N9zPqbRJxcxOqlpF
         hRFH81j3/M24cYtHoUNiDPvtFnTPsUVrDJhXiLg6faDcO/MOhw1FO6QXH0Yppn51K/UP
         AGPgJVMBbhnQUeRSGTOl6lBW5UP4K40BwwZib9lY5+vjyc90dfCUIbtwIdYwtA0c526+
         YaMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bwuITljtZNHhbpJXlNTjbzyfm4Pyrmk73ciq/IVL1YY=;
        fh=5UhT6Kq/KxI250G6CQJFQF2AZt+06QQA5+jvAFONf64=;
        b=jyyNgS5SN3K7sDTl/okoFatyA3jFbJmqh21wNBnI46ZOWfqd86JqwqH0+jIbc0/HPq
         rhPt+NslPIH+ui0LXQsL69ppCAL9j0cFk12FORHmn2h8lm24vShOqqIbVoF+RhHKRIxX
         RAEXH/91B7H8T0NcNcxBNm9LyEmsCSDlmvRzEKd2Wb/EwLSQGxc5AbaEBkmCKQEvUQMJ
         eGvt6xXZLxAuzXFSnle4yDR2PzYs5+Cfe1wPJxGj/BGDORkzqYBP3uh29P3sqOLHk9dt
         26T/WncGju79p3rL3tdhYZ+UU9zdQMG4xdyl5wIzt2Ql/eVfXrF2WPnUvHUisoWSTp5G
         zMKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WfVLnk4F;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691002329; x=1691607129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bwuITljtZNHhbpJXlNTjbzyfm4Pyrmk73ciq/IVL1YY=;
        b=Bul0en52kdz8IeSPA3qnrWXREcjiOMdMsl33lWzpZUFyAODKMo0ILMHoJN6mK3bS2p
         bHZ2xwyl2xeRnz6DKtOLzzMPWABaHFuiWlRLW6N+KVu9BODG0Kxv+mshouUEbya2VvAz
         w2/+nk+WA6egQepYUGvYi0TTWF4A02azUh1S5ov2kVJg2LsWbD4VCU+KmiLj5J7iC+K9
         QLaUhDNaIzYGpIotDeW7k1DeFT3cJYarV6pmrpGpqviJYk61eny6AjEqKtfgZtZwm4Aa
         i0M3KQ7P0ummGZ42D4cIOla8HB2B1a8U9RV6m+cuo7PyDu9sfbXXiKi45/bGHRlpLX4Y
         FxUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691002329; x=1691607129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bwuITljtZNHhbpJXlNTjbzyfm4Pyrmk73ciq/IVL1YY=;
        b=VcDe5YThEpUorAum9INQ8guwfJMExXVx9OteCvwlBQhgOFchQhd+rjFMq6kOhRmKuy
         Krep3yXCqW1Z8kMAfYhbqim5it6M8qGQWSk+VcFSnU7paW312PqxLxkM26OUT8WCSGWY
         mw3ekz5PirM8bROn7U7cYR6pLpfa2eSQwAFLbFmN6X5RMywHseYeH+fQHOgg7Antt4dr
         lHiX4sochSIMWM39STyp01X6sgkZ34gQHhY6WSXlVe+Ph+2X2LYGJwftNL65YZyoNNvA
         b6bd9HhlrHIHcL86potzt7ps/EchN5NaKciPhSP+NVWnz3vPAZPdkGsY39aPt5fq0xcB
         Tjcw==
X-Gm-Message-State: ABy/qLaj2wYyQWMlkjQNlRHtviENjM5b2IivXZudU1rotWny9cIV7MnZ
	pXa0c99IqLhY1cppLDC/gBo=
X-Google-Smtp-Source: APBJJlEyMM2BpE+3pBwWPaLlR+e1oUPIod1IdVBVIPuPREtWaeO1EJnF62GS0EuEbrMMlXkiOpYCWA==
X-Received: by 2002:a7b:c8c2:0:b0:3fe:2a98:a24c with SMTP id f2-20020a7bc8c2000000b003fe2a98a24cmr4169834wml.26.1691002328273;
        Wed, 02 Aug 2023 11:52:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f182:0:b0:313:f4ee:a4cc with SMTP id h2-20020adff182000000b00313f4eea4ccls1820381wro.1.-pod-prod-01-eu;
 Wed, 02 Aug 2023 11:52:06 -0700 (PDT)
X-Received: by 2002:a5d:67c5:0:b0:317:64f4:5536 with SMTP id n5-20020a5d67c5000000b0031764f45536mr5196993wrw.44.1691002326561;
        Wed, 02 Aug 2023 11:52:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691002326; cv=none;
        d=google.com; s=arc-20160816;
        b=LSN6ocQ9J/uyqxeOwgu1kIxjrsPGYvgX4wU+QladAxdnMNvBVbQ53xpf8oiQy81hK5
         dbG9/WULtH5MLQlkk2F9as7QZfdTCwtEUCXjHxxoBHdSce7lUw9Pxx61QSp2UrUVrPa+
         NIXdhBRO9u/zhr1hHc+OK7iE0D1W3y53dSzkQh8ZSPHYVirFSi7f72C2UCknVTmaisg8
         4PDZ08/gQa/vm6N4KrfryzortW5rT3xBC+1dFQYnJ5sBr/88oWBQUDmAmhrapLQxTchD
         Z70hwTH/zXCgFORJMNIY4aYNO44Guhz6HEEqcNVqkPl28avqMdhMo01nc+h9D7kjCRHR
         AQBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e52Aik7+FekPE4EeT0gUdOPtk6uJBw/P3h7TeG+ZQTM=;
        fh=H9QYNvW1lCje/pj7es7nler/VHpMk4DN+oBH/fqQ9/Y=;
        b=cQw4bKX7PF8cBnDGlkazTMSwUsmOrjj4kU0Ysa1FdBygCZZ752aeyfNcIXMlUc80tb
         lUN7BJPDfU7trPYo9JOVhr1EM8/nmj3PiCcdTzCfDklvr+q6+r86yWuvUanZoNmlzK/I
         tZyXXwrHMGExX3zOf7XOI0FpglL/ZHCE3MJHRZ+e6U3lTdT8yBSi1/BeaVnbDRAecTBC
         SG2wclEFSVB+pIDuFOysJMuPXnIAX7X0loBv/0Jy5l2FaRxGwgGjipecfNMk/PVHKZXB
         +yqNIwxH43sKwJwBnUgH/JnYDre51eu+3Pwsg/rayAN65jw4H71sNOJHrr5gHUCHo2lv
         wPpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WfVLnk4F;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id p32-20020a056402502000b0051fe8b74bddsi1250031eda.0.2023.08.02.11.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 11:52:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-3fe1d462762so2000205e9.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 11:52:06 -0700 (PDT)
X-Received: by 2002:a7b:c3d5:0:b0:3fb:b34f:6cd6 with SMTP id
 t21-20020a7bc3d5000000b003fbb34f6cd6mr5624229wmj.41.1691002326042; Wed, 02
 Aug 2023 11:52:06 -0700 (PDT)
MIME-Version: 1.0
References: <20230802150712.3583252-1-elver@google.com> <20230802110303.1e3ceeba5a96076f723d1d08@linux-foundation.org>
In-Reply-To: <20230802110303.1e3ceeba5a96076f723d1d08@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Aug 2023 20:51:29 +0200
Message-ID: <CANpmjNNZ7sRLxCFF0jTZvOK6s-=Z=DOAy8uz=B-i22GEnhNjbA@mail.gmail.com>
Subject: Re: [PATCH 1/3] Compiler attributes: Introduce the __preserve_most
 function attribute
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>, Guenter Roeck <linux@roeck-us.net>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Miguel Ojeda <ojeda@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=WfVLnk4F;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as
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

On Wed, 2 Aug 2023 at 20:03, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Wed,  2 Aug 2023 17:06:37 +0200 Marco Elver <elver@google.com> wrote:
>
> > [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> > convention of a function. The preserve_most calling convention attempts
> > to make the code in the caller as unintrusive as possible. This
> > convention behaves identically to the C calling convention on how
> > arguments and return values are passed, but it uses a different set of
> > caller/callee-saved registers. This alleviates the burden of saving and
> > recovering a large register set before and after the call in the
> > caller."
> >
> > [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> >
> > Use of this attribute results in better code generation for calls to
> > very rarely called functions, such as error-reporting functions, or
> > rarely executed slow paths.
> >
> > Introduce the attribute to compiler_attributes.h.
>
> That sounds fairly radical.  And no changes are needed for assembly
> code or asm statements?

The callee in this case is supposed to save the registers and restore
them. If the caller (such as in asm) redundantly saves the registers
as well, this would be safe although redundant. That being said, there
are no plans to call functions marked with the attribute from asm.
Only issue would be if someone implements such a function in asm with
a C decl with the attribute - but also, there are no plans to do this.

I'll need to spin a v2 to always add notrace: one way this can go
wrong if something inserts itself between the callers and callee, such
as tracing would.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZ7sRLxCFF0jTZvOK6s-%3DZ%3DDOAy8uz%3DB-i22GEnhNjbA%40mail.gmail.com.
