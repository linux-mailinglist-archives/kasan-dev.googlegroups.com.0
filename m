Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRMKW36AKGQEBAMTM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B912F292724
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 14:23:34 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 189sf9916973ybp.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 05:23:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603110213; cv=pass;
        d=google.com; s=arc-20160816;
        b=FTua7pDTVvEjE/DtgLZqNIICVl/Y4ofBgyJpSixq2mUrYSXHIrnVW/hZoYotNfNdKD
         Klc6LSeTOnapriVIZVdEdvcV2JZBm9F0P1vz+Tv1kWLFry1AyIIAUEk1Uz3sw/v2nABd
         37mk5/D02lnfylujcfkByXBnk6q3eHaW+HX5U50Dh4zkx9As6Xd3swq0vjoE6Gx1Xw/Z
         FVCkbI8X4wHCfKl8kcPAGYWfEd+x7e/xk1a2WGid7eAALH8Gf9ukNfyJqhVIm4CiKPqS
         lbDbY6+OWBmFPHIEXmvDSKPxb8//F4gFcwfEPwLLdthqllKd/dmqQOok7GoS7rESwf1b
         /chQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hF0Fu/XL9ETeeCu40v6HtfVOO0hchfmJLcCT69LRaNs=;
        b=Vv6KNOWOD0OX8U5uJIt1siZmjobUctkSIEtbBjyH1CpwSoMZQZt+Yq5bue7DOo8Ovh
         YeRON5AdtMhVAH0m+v3RqoPPFscbknm63bGmDJcN01E8LsQXLcx+0xS4uuKRDpnSlOyH
         mm0U2j6Y2K2f+LDU3koJSQo1XhTfYJZqv+auXIXLXQnj4LxItD9HyH1gIq3MO6awKW4M
         nCZMYg6wwUKimAynrz6GStiRJf82T7oZ2iyxyfR2hIR3kuuHzG3W9jyfb4nmRFSGtaXG
         NpXDCA3PJDn43yQBLkylxCLumPlUtv9jTUmXA4u5Fb12yaXqIemmKa8HAhOxyRJmY0Cx
         0vmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNNb2quR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hF0Fu/XL9ETeeCu40v6HtfVOO0hchfmJLcCT69LRaNs=;
        b=EU3olCQcZqHJNIRRUY30peXtmyNLQ3EsaZySNUsCPQaP1s1iMpwjiPf8f2KGQBYPCA
         5Y2rESE7GcPnkPFHzElunguZuC/+o4GfffX4dV3FXLmR9OwAfBqSGXtF+o/KqxQnXcg/
         N88EcArK9a1HmyS05JDFnVfK17KPspf470HFXMbiLxRpBBVGngwIrf0Hr1CZuC4yYkrr
         9Iu5S+UG6LWrvKGrobXn0lyDBWcwZlovcpJCYteCSFhxn3mAOSt71UqnnGaXmr74taFs
         WBDAx17kBh712KcQrxtTzf75qNTmzT9Ovr0/fztTz9gqAoJaqg5QkurzlqlUUXNBSWIb
         T3Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hF0Fu/XL9ETeeCu40v6HtfVOO0hchfmJLcCT69LRaNs=;
        b=t0+Waw34/fXsB7kaBBYKaD37OAh4BgCDV+OAUEKyTYYta4p4xrsb7m6le+AwOgxzr9
         QuMFv+hdGgJWM4hh26CL4byLbMEC/Y5eigDqvNLK89Aw1BCOaBI8ccxgUwrzwD01/h/l
         XsA9cGd1FNaTefeOWqtlolGT7k0df0LA+Eez94eWO6QVtHvMj0aWhXdCNuBnKZwFufMb
         7AfDbWgPNRMR6GdeW/VIqLKYJ23mQkn9i0wt8OUlol/VVHiNJ5dFVW0KpS+i6BEuBB3X
         MpNGKw/6bE3L2uKhdO979e6DppMJ4RfSFCSnpftm30Cyqli3sEkQDvWv4W/Krjxmu3xT
         wA8A==
X-Gm-Message-State: AOAM531kCyqGEOxHYjG7GYIGfDAjAJ7ChdfrvoBjZyXVqxDjLVIsplVC
	j0mn24Nev+RIiMsXBBBo4u4=
X-Google-Smtp-Source: ABdhPJwPLxtFCJ3yTJzSYDDrwtGjbPsaPR9rvaSlY6nwykAPisB/aB9VcWVFEgtJ/8vDZMbMAEjerg==
X-Received: by 2002:a25:a2c4:: with SMTP id c4mr22265577ybn.515.1603110213812;
        Mon, 19 Oct 2020 05:23:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:20c6:: with SMTP id g189ls5047358ybg.1.gmail; Mon, 19
 Oct 2020 05:23:33 -0700 (PDT)
X-Received: by 2002:a25:d794:: with SMTP id o142mr21153159ybg.59.1603110213158;
        Mon, 19 Oct 2020 05:23:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603110213; cv=none;
        d=google.com; s=arc-20160816;
        b=yOEaIyBhidyHTQj3rt65XGTrlSsUAuskfl+usgMj8z1b6Jgp1h8AEsC/UHBlkmQRas
         5LaFgENFRr5cZcyWnb6TPT5/cRqL6prpETkYvsBMaiklsqnDFjNKNOK9OEdvocDYkhJn
         xRtGsTw67ECNlWZI/ygpwI+RUXTW2XPYHe7SuIbqXqA0hDSJruu49/5qPM6sUqFg8SPg
         YVAbHYZ0FzMJ3JO2647wOYLmNn6pxYFz1E7tO2w74bjOLynjd0C/Q9bKQTPx2Sg6PIat
         9SpG1/oBb/4yI9YKOLkBk1UVpsATTd2LResBcKFxBdUBqJ0FKhvEFzmD/7DnUn1IR1bv
         qxDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dQ/xkg0nub+4PWvL+CKk+B6D0YwCVYzzs73TSH8kNVQ=;
        b=kxFuIKEkMF9Cw/1Zb66pyuYlmlWEaUUYeBjQj7GwIeRRsKNlEYHp/I+b74EnhEPJsX
         mqZkcmZNwBIaTdwNuXSwfjNfUv9Hxu8nIH6suAtDmISXvLitjgeEIw/AObHHFN9oFz9Q
         1Lt2AskSQ2xaWyx35hg/aeC7loNPel/q1mQeyeMs3WI4VsEtI29n1vyLm96331DR0Kv3
         Q9NEtdqcZCB0L6TVom+2ZkfUyE38abfwVFaqSvAWKzFWrDEVoYMkM8Lu7jZ4X+Gsitzk
         GgoO7aoHV//y46AY0TRshjudX1ReKS/RTvg8Lpu//T3XARn9+6I/SU0T9TSGes9FAfv1
         4rRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNNb2quR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id f128si717644ybg.5.2020.10.19.05.23.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 05:23:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id f1so983401oov.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 05:23:33 -0700 (PDT)
X-Received: by 2002:a4a:b28b:: with SMTP id k11mr11874415ooo.54.1603110212494;
 Mon, 19 Oct 2020 05:23:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Oct 2020 14:23:20 +0200
Message-ID: <CANpmjNN3Ax2_CfxXixh8-NipXOx7s8vprg23ua-M_tvUKZGq0Q@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Serban Constantinescu <serbanc@google.com>, Kostya Serebryany <kcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KNNb2quR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
[...]
> A question to KASAN maintainers: what would be the best way to support the
> "off" mode? I see two potential approaches: add a check into each kasan
> callback (easier to implement, but we still call kasan callbacks, even
> though they immediately return), or add inline header wrappers that do the
> same.

This is tricky, because we don't know how bad the performance will be
if we keep them as calls. We'd have to understand the performance
impact of keeping them as calls, and if the performance impact is
acceptable or not.

Without understanding the performance impact, the only viable option I
see is to add __always_inline kasan_foo() wrappers, which use the
static branch to guard calls to __kasan_foo().

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN3Ax2_CfxXixh8-NipXOx7s8vprg23ua-M_tvUKZGq0Q%40mail.gmail.com.
