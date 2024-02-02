Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQF26OWQMGQEZH2OBHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5F7846FFA
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 13:17:06 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7c0257e507csf192618039f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 04:17:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706876225; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewiUYrrE46zSV76lJ1x4pIYckjjcVaU4ell71kBlCmWH4oYLc92mpnn+CKrmLeip8T
         JtnwtIeulwSn1WodPVdtGAjWJKpX/168moStcJLI7YuTYSezB0NvMj/6p+g4kyCrWK8Z
         r87Z0iT+UQBDFaPPtKCgV7pRhJRkpxKd9jypCLJP8Hxir1Pxc1O6Qb21h1KcHEwzmpVe
         OJkFw5o22blAhn2ijuT7Zs9Myu0c82RdJ9J+MHFptFV65kXGvl6QFW0IUXOs3UqewTGN
         DwPJ6qknmmZhOitIDnrlJzELOZgdKCIvpN/suQr7iXbOsrqjgCxFOy/jbS072BUGkkXy
         1mXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iAYnBAPe39C5gxM2fBMiLMr4gqCR9wvek+7b2zpkPlo=;
        fh=zKQayMdCixtLHJeg8bPv9yYSRyhQElKNXmrUhd9iMaQ=;
        b=D5Sl5BinxiI3K8ZYcFSoqkdhssdHDOlAIEe7x28BCRXjmFdou/QSJLoET7P/cxsZUS
         JoECRL96E7rolai1zFD8FJEhVyizyVJXC30D8EHpMNS3LDb+bUDbuQsys2zZ+C80x6U9
         LncP/UXJ/tS9RPg+JQwTDzF7D69/SpBmIn+anrzkD1cEM5va+WHeRWObla/zVbM8nBq/
         Nv5+k4H3cOazAEzNQzhlbDAdhOm01CXFoWNtWjPNsbcPUxeFLTCtzEOUJJ4z1keEwzyi
         IyNtK9/gNhZigkX9+qMxN5RWQ+36IXFRXbuNrIsZAcbqF1h9R1n87u6TTckRIaj2k5We
         DaRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JyUu3OkG;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706876225; x=1707481025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iAYnBAPe39C5gxM2fBMiLMr4gqCR9wvek+7b2zpkPlo=;
        b=T/JNl+9Nw0G7mro+LbN2p1liASkZphLNaHMuwscaSFrNHXKMIlfFlM3ZgB5xpS/txe
         sIpMDKQz7OGasMfbyTvzG8Gs6vhS8emm/p7s47BsM1Wi8+3oDgIwf9eTavZxInSnuxQr
         3UpE4aah3IL7KDeuYSKAlNpXdAA8Hk5V71pI3xxececClLgpjVKqS+wObA3Wf9OqfuID
         MrCzbrK2BdrNu+ycBN8xgMnPLwDhf3f6XjeLhl1zaFh1SU0Mk/wIdVhBVvRBnkvAx414
         SV3892/AGsOqh124NwJCzUiL5e09hignGcVeH6nu5sGE1ZdZFKLtGn/uuveMOB7a3s87
         cn3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706876225; x=1707481025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iAYnBAPe39C5gxM2fBMiLMr4gqCR9wvek+7b2zpkPlo=;
        b=GDlGvOVK714cuoDuZjeCelSfaT3LP9Zyz3mo6FX5Of8yTjT5nuazQ5/VrPITCFGoB+
         Xu4yjiiSXfzMFdZKXKMUIPfnIRVwdPNDayhQ46h7YH5TUEtZDPA4UiYy9c0iamh6ry9Z
         GIczb4Miqv1Ad84SjM/ye1bkqFIuYUwiqU7aI94eZsSidUuUmm2fpyXdYPUHRGxFuxHE
         O2wE/JXJCLZ/5xg0xbLDAmK0NW4Yvn2tUoTvWAIudlt649PXFZaTKuzO4tdF0x6eo8EG
         YpIsWUTzM5fd5lQ7o9vPmvOa+zz97tB6/gnPuWlyuWMrztD4GNVkiA9QpaWhZ9udhUkC
         06fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhxLR96sOLsgwsaa5wJgAKX70n0tNduWbkA66Kazn2+SHfuH/8
	fy2D+APudapj/b7nDbl3wcC/WEjGb4vWdlSBxanGGG7y5QA0/Itx
X-Google-Smtp-Source: AGHT+IGrQEL2omWoUBGf7cua14YtgpzGEZ/sMUKPdN2HpqpF/9Gxu7fKNjoDY6U8gh9LefTj3zG/Jg==
X-Received: by 2002:a92:c213:0:b0:363:7e0a:644f with SMTP id j19-20020a92c213000000b003637e0a644fmr1862595ilo.32.1706876225091;
        Fri, 02 Feb 2024 04:17:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2411:b0:363:93da:bf4c with SMTP id
 bs17-20020a056e02241100b0036393dabf4cls427714ilb.0.-pod-prod-05-us; Fri, 02
 Feb 2024 04:17:04 -0800 (PST)
X-Received: by 2002:a6b:ea01:0:b0:7bf:ffad:8e3a with SMTP id m1-20020a6bea01000000b007bfffad8e3amr1869278ioc.17.1706876224393;
        Fri, 02 Feb 2024 04:17:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706876224; cv=none;
        d=google.com; s=arc-20160816;
        b=VrPHG/dKNyTNYn6PclexEu8IqQn3mOLoRk6ZCZhlrGit6vviAGz0IFALqBtwr7pHar
         zJC4KRglLTwOPZm41pCmZaizMipXyseV+/5FID5MCM7qi1iXXMdATfPRpPGuUJIHGl4n
         gXZG2G9ZyHN/IaiEpabesi9E/QtHwN/GD+OHjKKFKn+SudXBfyDJNLT//diixe96SGnv
         AQe0hctohvNWoDC4NCMKtF0Skqct0WGBiQVeylYUdhKYiaia+yNu8Yu6pWDI8mxamJAB
         jyhS9Jd8P222r2dnDRZiVZrI1Oa2APeS0SY4QLyH/qC02lhMIWzpQpauR5B0IINH6CAL
         FD3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UQ0esveh//cg9XCkiI/7xWePudzmiIjItwxrOruHVwk=;
        fh=zKQayMdCixtLHJeg8bPv9yYSRyhQElKNXmrUhd9iMaQ=;
        b=KACoXCg1V1WbtgRjsit+mJFfGc8mFFV6mOl9Cx6cs25W6NVvIhn3G7h4wDq9s54XPx
         ghKArXfng4bQ5vZ6Lr7wbl33Kpuh1gqaGKkyXrlR1G2o8O4aen3I7If+Wizlwe8Oy2Gj
         zLpZMMw/Z6mSv2+NDCH9rNWGiIsJ2NZ5VBysCfjZcBSK6eMfTEM8CowxjsDB0ZvhA/5y
         F8kkWZT3Qdfx2o7DDAz6VQFI1LiethWtAkKTIiUAEjIKZR3lSeZhUKMUKa8E58BMTXkf
         zX+9uxNJIoEZWT848oyoFKGDEyZXTujalMn7U+bSCRXzHEXl+zo5pxLRhDlNyh37SOig
         uGgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JyUu3OkG;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCXsiVyUQ04h7x2zxwmLrtCRxZdA52VXsjoePtWiHxGulvKgvM5ekjizjvdIjy0NlriRhVklJWypHTQn8p5JtkDpMMZrxBpgIC7o+Q==
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id z195-20020a6bc9cc000000b007c03a9138a2si181215iof.1.2024.02.02.04.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 04:17:04 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-295d22bd625so1500919a91.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 04:17:04 -0800 (PST)
X-Received: by 2002:a17:90b:1298:b0:296:1dcf:c296 with SMTP id fw24-20020a17090b129800b002961dcfc296mr1876188pjb.18.1706876223734;
        Fri, 02 Feb 2024 04:17:03 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCUGVn+0c2h4HxapCQwK+CBO5gK3KOvlzIatkL3Eg+0hshg2pC4xRmXdAPGwrPO866Nj9YF+U6s6nJkm+zEO0B/JBsHbpfqLIrHUgGxhmDm7PR7dJOIlSKekZQeCfpS4kk6gdUCRy8AKy1koQcYXJUoBqPtoXthgUI8I+/eaEfrPbo4kflZwbchOOzcwU5swL0S6WdMTIJa+mw55to+6uV3nDPQwGmi8fzDIZ1/ceDsJxByCfPOeO0l/S81b9BgnbLDHSPgD7FlGPHvtp8Z/FomG1NkHrVilLrlukHP1pAw9wYKJnI22iJxJmSjYHmQniMGlZYsc/cdM58fBdkhFMawZoGvAvkTYiXvNll9VJlnJ8j/FX+IAuDXHo43itnq+OGQQdsBiGyQPYcczK3z4vcpWYVXqya3O7moVN8gWmQjkhvZgr8SZOqWDhbrhJgPiVmYM7CkU25sPa9I0PqKXD5aa7cvoHKmNkLXZ4/epetFyeC0sd5jBRU3IEcz8/3lo1E3SteGrn+6+Y/KEkJjGEjE/TlV+t7ZzrhslvL+T17oohFYN0g54YBk1TJzsBIkJwnqakFKkOfMS15bofbWnqaCKkx+rJlTObTtkF5AePTEEUWmqLLwa3jLiNLz4lnivpuzOGcGhWnPJl5a421rYycnirgqxJHh/cGTKPA8EmcYWycgZa67VxpoBN5oGlmkdby+KZtTF2BuWlV1VWF5HfxIzOVdG8qZz4Q257WM=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id su13-20020a17090b534d00b002927a36b7a0sm1671429pjb.23.2024.02.02.04.17.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 04:17:03 -0800 (PST)
Date: Fri, 2 Feb 2024 04:17:02 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: linux-hardening@vger.kernel.org, Justin Stitt <justinstitt@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	Fangrui Song <maskray@google.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Bill Wendling <morbo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>, x86@kernel.org,
	linux-kernel@vger.kernel.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, linux-doc@vger.kernel.org,
	netdev@vger.kernel.org, linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-acpi@vger.kernel.org
Subject: Re: [PATCH v2 2/6] ubsan: Reintroduce signed and unsigned overflow
 sanitizers
Message-ID: <202402020405.7E0B5B3784@keescook>
References: <20240202101311.it.893-kees@kernel.org>
 <20240202101642.156588-2-keescook@chromium.org>
 <CANpmjNPPbTNPJfM5MNE6tW-jCse+u_RB8bqGLT3cTxgCsL+x-A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPPbTNPJfM5MNE6tW-jCse+u_RB8bqGLT3cTxgCsL+x-A@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JyUu3OkG;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1035
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

On Fri, Feb 02, 2024 at 12:01:55PM +0100, Marco Elver wrote:
> On Fri, 2 Feb 2024 at 11:16, Kees Cook <keescook@chromium.org> wrote:
> > [...]
> > +config UBSAN_UNSIGNED_WRAP
> > +       bool "Perform checking for unsigned arithmetic wrap-around"
> > +       depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
> > +       depends on !X86_32 # avoid excessive stack usage on x86-32/clang
> > +       depends on !COMPILE_TEST
> > +       help
> > +         This option enables -fsanitize=unsigned-integer-overflow which checks
> > +         for wrap-around of any arithmetic operations with unsigned integers. This
> > +         currently causes x86 to fail to boot.
> 
> My hypothesis is that these options will quickly be enabled by various
> test and fuzzing setups, to the detriment of kernel developers. While
> the commit message states that these are for experimentation, I do not
> think it is at all clear from the Kconfig options.

I can certainly rephrase it more strongly. I would hope that anyone
enabling the unsigned sanitizer would quickly realize how extremely
noisy it is.

> Unsigned integer wrap-around is relatively common (it is _not_ UB
> after all). While I can appreciate that in some cases wrap around is a
> genuine semantic bug, and that's what we want to find with these
> changes, ultimately marking all semantically valid wrap arounds to
> catch the unmarked ones. Given these patterns are so common, and C
> programmers are used to them, it will take a lot of effort to mark all
> the intentional cases. But I fear that even if we get to that place,
> _unmarked_  but semantically valid unsigned wrap around will keep
> popping up again and again.

I agree -- it's going to be quite a challenge. My short-term goal is to
see how far the sanitizer itself can get with identifying intentional
uses. For example, I found two more extremely common code patterns that
trip it now:

	unsigned int i = ...;
	...
	while (i--) { ... }

This trips the sanitizer at loop exit. :P It seems like churn to
refactor all of these into "for (; i; i--)". The compiler should be able
to identify this by looking for later uses of "i", etc.

The other is negative constants: -1UL, -3ULL, etc. These are all over
the place and very very obviously intentional and should be ignored by
the compiler.

> What is the long-term vision to minimize the additional churn this may
> introduce?

My hope is that we can evolve the coverage over time. Solving it all at
once won't be possible, but I think we can get pretty far with the
signed overflow sanitizer, which runs relatively cleanly already.

If we can't make meaningful progress in unsigned annotations, I think
we'll have to work on gaining type-based operator overloading so we can
grow type-aware arithmetic. That will serve as a much cleaner
annotation. E.g. introduce jiffie_t, which wraps.

> I think the problem reminds me a little of the data race problem,
> although I suspect unsigned integer wraparound is much more common
> than data races (which unlike unsigned wrap around is actually UB) -
> so chasing all intentional unsigned integer wrap arounds and marking
> will take even more effort than marking all intentional data races
> (which we're still slowly, but steadily, making progress towards).
> 
> At the very least, these options should 'depends on EXPERT' or even
> 'depends on BROKEN' while the story is still being worked out.

Perhaps I should hold off on bringing the unsigned sanitizer back? I was
hoping to work in parallel with the signed sanitizer, but maybe this
isn't the right approach?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402020405.7E0B5B3784%40keescook.
