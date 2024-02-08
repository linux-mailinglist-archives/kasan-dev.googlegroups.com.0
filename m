Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQEOSKXAMGQEBGBZSVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5677E84DAE0
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 08:48:18 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-219461cbbf5sf1514642fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 23:48:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707378497; cv=pass;
        d=google.com; s=arc-20160816;
        b=HIfMbSuaxcO7xZb/ZQIxlQ4q0Uf/6ZCjrCjzWl7Oan55CaXMkR1mAHKcNw4QNW1nE/
         fHaBGadhI7EnPm3voK+cxcqXoRkHj17CyoldjQNvGzNLNZLXpuLPmQmY8ATJuyAvcdBl
         RsYW4w3jy5VeBsqQ9e9u7n88Xh8wLFVialynMo0Xvy7vgTr16RqOcc7NKkPRjlGFY/EQ
         +iwTkQOOaZqi5zAgpc78jzfKkNXklBY5DXpYpkeOVE/mYaeZd70QC1EE5lSZDM9pBo9O
         qfkI6h1F29I2wxpM6l2kjq/AhrbhQ1HgpuaR4N3xQUk909ikRmpTtn6h9M1Z3My5cg9T
         YaZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OyeWn3RzrSZzV1UDzyjgHH8PMBcOqTeS7WQsIYP7hAg=;
        fh=M4h6foU8MPGuDwIbHKEWO/3vZu9XNpBuhutXBMEwHiM=;
        b=TziEJWI7T0pm01Up5VMzZOgFS2tEVV/M7Yn+5cbUfbFQDDHEVaWTjedqIyvBcS+1F9
         9TYuiYqpBuenV68LquOckWlcT7NLGKua6rnZvz5RSLCnhiQbkimidfqNg2fOGz0hm07X
         KD0Cr6wtYyViQlpLHyoPy2A6KE8sf7OYvixB4zikHLW2u777euTBOthZ/O/oLG+Dykol
         Bhj6EnJb2tb1X3HGIZ5T2S0docYM2ncAgNO/+BxbY+t/38EfzkB88tufWdQevfrlDAMd
         QaKCe+255p+sw5ao7e3ImQN3l9/fqovUdSk32splukm3WRr3l6z1b+m6Nu4edDoV2S61
         G7tA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IDJpX8IJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707378497; x=1707983297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OyeWn3RzrSZzV1UDzyjgHH8PMBcOqTeS7WQsIYP7hAg=;
        b=ZgOtiXENUsYLjloEshUEnhImP+6GLD8gwgMzFG1rMY5jQagEoV8ggAnk1t43h85jU3
         Rz0HdJ9FdEMeooY14+q4E3XUXXFfDXHWWFoHYKoRPvT8AyaJ40NpQb8LnKWed/cMMial
         NZVDDfoL4UvDNXmUWeu3WdvqC+feO4ODxYz6mg7kT9KHANRbjA4H94J7ngeSUMOueC2V
         Ee+nr9xU+XzX2B9bXKK9LNuQl6zjM3TJdmuCRsI1//tET5kjvxiLV91qFCNW9VO+8w/N
         b47/YeohreVnesQOcaNQAqyxvA/MZYwE8abFNiMg7Z0sJwGq4boXYRhmeBjoPyCNVBbi
         28XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707378497; x=1707983297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OyeWn3RzrSZzV1UDzyjgHH8PMBcOqTeS7WQsIYP7hAg=;
        b=lgCZWZO9HdqmcXqlsC5W/kPgyR+IGnUmRDRqvriSwL0uYyA0Psnmqab7bpeyrpY6zh
         6UPk3tu/Y6u0oz0kVmADyWkkhbzJWRv2q95caySCum+OaNzsJ82ZuKTXo6/jTq7lfXov
         Q1Vn/lUEDpEEv5+yygy3kt4CrObLi2KIHB3AD6j0yIp+b1OfafU8eJys28M+2JCmW6jh
         /4o2gNMKO8/0QJ1JBWxVdefB1guqWLJnvEfbYkZqe6r9cRj18dW+BA1kScYVh3wpvLaC
         NM8OHHqVhUy+Wr7mhojCAh2HtVO/zG/sVj+J92z7PxFoCL1YWu8Kb+9mTMqEdZudRH5A
         d0tQ==
X-Forwarded-Encrypted: i=2; AJvYcCX7lGqn8GcWghiz0KeScFTURNYNv7QqzlIF+UsX8rbqcxKt68zN2e0nJLrZ23gPxdLHvaiDSCM5LM2GEj2nzIIzCqcEnkVaQQ==
X-Gm-Message-State: AOJu0YxODOhcM6RqUatdLwKMB2HNxJsQqqGrD/XUkzQgwjyRuBRA9dJB
	OygSUNUA+ZG4H7xwuIj4B7auEseA0P91/JOwpvFJlrf3ycGepVWI
X-Google-Smtp-Source: AGHT+IF785R3qpNVSlw25moqAHfTtkYrcobqdSJ0HNcPn7AlmkErdDYwAp4NxoA9TtBn+az6Wy5zFQ==
X-Received: by 2002:a05:6871:b0c:b0:214:b202:7941 with SMTP id fq12-20020a0568710b0c00b00214b2027941mr8824424oab.43.1707378496689;
        Wed, 07 Feb 2024 23:48:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5223:b0:219:e219:474e with SMTP id
 ht35-20020a056871522300b00219e219474els995643oac.0.-pod-prod-07-us; Wed, 07
 Feb 2024 23:48:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUN0htHrs8TYrE17VWkJSNP1JMsTWWiNusStKlnLO00Y+YJhFOhW1dSBH878f81Pi1ZMUDtimB+D9KQTmfHr94vt8D4rNzTWvAlBA==
X-Received: by 2002:a05:6870:350f:b0:219:6c31:7b4d with SMTP id k15-20020a056870350f00b002196c317b4dmr9094312oah.40.1707378495697;
        Wed, 07 Feb 2024 23:48:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707378495; cv=none;
        d=google.com; s=arc-20160816;
        b=G+Q0W61VQxPJGUMooEjILIlvaITJPqjULOpxgK6MOYRWaKb1FndC4U+7eiOF/cV8VM
         N1I916rhs9bwxgpf1aHSEbDYBh16g9/aQAsl2MuWgE3qtyhtjoohnez86v/bl+iDIcrk
         F/lmJ8FkN9rJ/bcINMfMLxpdt5CUkBg1NwaVTn71W1WYZlUUqb9MIDeoQjqwVVutcKzP
         yX4OJA6Pv9Ln5rXyJsw2fFZSmuvkL6b1KZfQNcE9rRYHtvSkgUJcVZSLhCBD4NSkjreZ
         nUUjdef0rp2IHjvsKnKRL7Vjzm53uf1st48nz6c+rR+XpAaNMxUlb6TtF17cf/qFUDu6
         Nv/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=385hCUDagPRLXBeOIkuJcZqA/c6Z79mqmXF47UMwoI8=;
        fh=kWl/NdmKdaZPfICB0DVI7EkQ922LaLy7e4OKfGvK1HM=;
        b=mLc08WopQ+zfRsTywhyjM5C89/bwY0hzqXd0Ktfph+MuKSgKZT/zo/Vv3dEHA/4IrV
         pf/Fn3Lh4ePNPqaK3UJa1D+jsx+6WikqQT7AtOMZBMKa5Pzr080oskJ1fvg1Y8RTMNwu
         JP5XAcR9j/C8g6WPdsnID0CdNuakPGdzxFjt8OM7bcftnufIE1L3kMQkfAy1ZwqBgmOV
         zWkKjA6hUIskc02TUl1zyNrEPSN/oZi399abv3qXvh99vK0avue96XqfIVr3GSblK/d/
         3ftGJjz7asFaHrIgLJxIedAlrn3iNKzQchRa8SuYQ6XrpzPefJIhIcKemlv4gja+eWbg
         oFSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IDJpX8IJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVkgQmpY5OU7rqeVLboJjTgLfx/5qh9Tb+PKlv5sGbw3mGCbTFA2FHVQWxoSMCAx0aS4w6qwhnzmwJj1k79zyUjaBcEALsgzmcHpg==
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id ov8-20020a056870cb8800b00219d441c1bbsi397979oab.5.2024.02.07.23.48.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Feb 2024 23:48:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id 71dfb90a1353d-4c021a73febso549558e0c.2
        for <kasan-dev@googlegroups.com>; Wed, 07 Feb 2024 23:48:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXoaZpokbEEf0+UlC9ZYpeS7t9yFdbuIM4KzMu5n+ryz+1D5cF3v6Vu3EIzN+cFtBWb533sTy8UWrgNmLNl14PuZtShCHokhSNXIw==
X-Received: by 2002:a05:6122:a0b:b0:4c0:1a89:e641 with SMTP id
 11-20020a0561220a0b00b004c01a89e641mr5647392vkn.12.1707378495118; Wed, 07 Feb
 2024 23:48:15 -0800 (PST)
MIME-Version: 1.0
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local> <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local> <20240207153327.22b5c848@kernel.org>
In-Reply-To: <20240207153327.22b5c848@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Feb 2024 08:47:37 +0100
Message-ID: <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com>
Subject: Re: KFENCE: included in x86 defconfig?
To: Jakub Kicinski <kuba@kernel.org>
Cc: Borislav Petkov <bp@alien8.de>, Matthieu Baerts <matttbe@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Netdev <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org, 
	Kees Cook <keescook@chromium.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IDJpX8IJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as
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

On Thu, 8 Feb 2024 at 00:33, Jakub Kicinski <kuba@kernel.org> wrote:
>
> On Wed, 7 Feb 2024 20:04:44 +0100 Borislav Petkov wrote:
> > On Wed, Feb 07, 2024 at 07:35:53PM +0100, Matthieu Baerts wrote:
> > > Sorry, I'm sure I understand your suggestion: do you mean not including
> > > KFENCE in hardening.config either, but in another one?
> > >
> > > For the networking tests, we are already merging .config files, e.g. the
> > > debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
> > > can be elsewhere, and we don't mind merging other .config files if they
> > > are maintained.
> >
> > Well, depends on where should KFENCE be enabled? Do you want people to
> > run their tests with it too, or only the networking tests? If so, then
> > hardening.config probably makes sense.
> >
> > Judging by what Documentation/dev-tools/kfence.rst says:
> >
> > "KFENCE is designed to be enabled in production kernels, and has near zero
> > performance overhead."
> >
> > this reads like it should be enabled *everywhere* - not only in some
> > hardening config.
>
> Right, a lot of distros enable it and so do hyperscalers (Fedora, Meta
> and Google at least, AFAIK). Linus is pretty clear on the policy that
> "feature" type Kconfig options should default to disabled. But for
> something like KFENCE we were wondering what the cut-over point is
> for making it enabled by default.

That's a good question, and I don't have the answer to that - maybe we
need to ask Linus then.

We could argue that to improve memory safety of the Linux kernel more
rapidly, enablement of KFENCE by default (on the "big" architectures
like x86) might actually be a net benefit at ~zero performance
overhead and the cost of 2 MiB of RAM (default config). One big
assumption is that CI systems or whoever will look at their kernel
logs and report the warnings (a quick web search does confirm that
KFENCE reports are reported by random users as well and not just devs
or CI systems).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A%40mail.gmail.com.
