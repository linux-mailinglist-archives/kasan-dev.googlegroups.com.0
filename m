Return-Path: <kasan-dev+bncBDRZHGH43YJRBV6FZD7AKGQELZKEI5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 788202D5BBF
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 14:30:00 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id f194sf2369267vka.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 05:30:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607606999; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rq50z4/zROyafLB9CZtom7ETLEaB4NEm1xHr6roHpAjFUs+u9CF0ROtyHfUYNQgE7k
         3CmzE5E6OkZdc3kLtz99z3oz2MUBlMrYztPJeL2dm0gq1bzP0VifC/sMcnRjE82ssh+Y
         wprqw4ogXATaLQdkRG9Cg0mxEBxBSnFFiIuU/4H8lGhMp1bIIPRiA6VO9jIZrTRzhEiq
         AQC7tA2GL6bplN1uVcy84hUfZgyj9zvw/n0SgYGZv+ID7tYsyf0WjyAxH/ggY+SMNxOa
         Ky1EP7r/re1jS+dXKf+hu1anGrFYwys+wFzEGcV5i0lm3aJKTaBl8SK2lnE10uzxttFM
         /8yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=O33sxiqLNYPWuYrfmrpI6xUI3huHvraVxB5DYvu6N2k=;
        b=Ju/0WpMzk8i2g35kaIHnLLtH1flbVRIsW2r+51LZFBMsbl5kkSxwI7kTMKrKE8BQwX
         4dViVVQhSqfcCJfGFZMGVabXqzkJLOP5Pa/olF2Pb/vJhLv44khK6dBvO/dZVDplolB1
         leqt5EQxAvEEccYUIC0ChgYebxcThA68fpUv+Csf1L/XT5tbwlRwAhisZU4kERKXGSr/
         DtrJIA0Fat/kOtPdNQLsfSaTLryoYVmpRupf/w8jOk8DCDMetp/BDGWpp7KsWha1voPS
         lvwSjnF68HvJPn/k2G/1JmJocswi/q/8cEglA+1Ns7BlQPLEwjQvU7+IkNzV9AsFdnT5
         z+GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pbROG8ec;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O33sxiqLNYPWuYrfmrpI6xUI3huHvraVxB5DYvu6N2k=;
        b=iKYp62WMliuPSe1QagGbtw4TeiOgDV0AJgmJVKjW7Pvkt/488b2gq7rObUlVEiVFEi
         IxmqEG21cGAat4MUIVyX/baoDiv/6olswvxr9mA/tCmThLX2o4jBJVi0gILhkhfdFlsk
         FK3NzVfydFC7WYpkIWvHSqClS97ngEMeamPvdS7kfJCWesTKbA6XV/uLSfT9vwWzNk94
         jgkrzUfYwRQMKZsBspYLvTDOic7p/Q5+aQmg1O+mM+b9gjpL7bo4dI40oAbW0eLiVU/9
         p1axFRuNs7nKFJTEgJCkT/tg0k6xe3jFcQUgzyflTG22epKJ9CRtwBf/deSTLgVn3aTL
         chLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O33sxiqLNYPWuYrfmrpI6xUI3huHvraVxB5DYvu6N2k=;
        b=GleBhqdabt6WzWIrHSixpIyhD+fKZ8B9nZ1ASIsfk69Hqd3CzK0IWndo79erDZ9lfv
         4jkPWVpY+FOBDqA+r0SWz91BpI1GTFKZebJwLI3sGW2kT6TyyYGSmyFck9jRHPC/I7jL
         nhUJh/4ZRHL+X4QxaQ1kZQEf4u0bcvwSZ8xDS1J43tSom7BO8EbILoaF5W0DnjB78DfU
         xr/KFSG4kXTFj7BKKwIXxpaCL2UyZw94+kb/zg4LaxzbfsIzDfsXR5REoRT+D13EDoDA
         hHPePhxNFCgA7aHt+LAo45f3L8J2K4fPzoHsnrQfsrOFQGewkOaKkOQq+QohfG6IiuSw
         Z98A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O33sxiqLNYPWuYrfmrpI6xUI3huHvraVxB5DYvu6N2k=;
        b=CkUWy5FOKqfvDjF0fXNNwtA8aNmTMhqiWYtAKAG9KA1+X3Fl6SpVWvR8WoRgn7/2jC
         W07mDqYIBokkAlcK9NBzRuyyEap/SeB/kD5Rr4RyRPvB/lCM59pXGVLKYin8pR6iJJg3
         zYmnChjlpMr/TKdPZdVn+ZYyaTMv+0AhfaB24rqlIMXJyY0h4yO9VdY5rhkJstADHUUn
         bRUsowLDoFS/nmFXSsk8rd6omMFaD0lEbKDUHyGYi+yB29T698Yg3Lwkmg13MWne/IEK
         AH7LXHd6vjw8ZPxLyI9Oo5sMEgTEAeXp3gVxBm14Q88AiR7krwhOljplbjubOcXYl5K8
         Z2RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rASmaBsW0YwkYBtB9aPuaJ9F+Onlw+KaD1MB4f45fq1eiF09U
	TbVouIMifUFVECdo9FZWOO0=
X-Google-Smtp-Source: ABdhPJwuf5YiUANrHfxAkZXj3fLj3onFmsbPpKTe2OIXC9N+SR/xsuvWoVeSAZPbNOHnqOiyHdPdcQ==
X-Received: by 2002:ab0:6b:: with SMTP id 98mr7738507uai.86.1607606999360;
        Thu, 10 Dec 2020 05:29:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:5c83:: with SMTP id q125ls289473vkb.9.gmail; Thu, 10 Dec
 2020 05:29:58 -0800 (PST)
X-Received: by 2002:a1f:78cf:: with SMTP id t198mr8483910vkc.15.1607606998769;
        Thu, 10 Dec 2020 05:29:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607606998; cv=none;
        d=google.com; s=arc-20160816;
        b=QJb5g64stmj32dTuw8M0xqv1ssC5x9AzZJdJP/s5exBpiJ6ZkF+kE15bFunQHEZsJX
         n66xhKT7w5/nDICCQHB23P/YSDP8leJBxxVRkuVIlRePMJH4NJHcFEjdgRYuvo9MEKFh
         ZcS76XJNu9JDXCtR/zN7Z6GUuHrIuLlmJKmS+HLsCEUR6VjMTuMkj1EeR0VA4XTOfseS
         mMpw+1cIPtM9VXA5RlkKC919NGUaXplxlAyw+18AQyEZH81vlBhPbeO/IBixMfcDS48F
         K3A/nKU4nTD2732mmf5rqMZ9HBLt56k8WDzYWPyBtbZWchtdReC+CDji8ItvAvMe0vrZ
         +ogQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jhMaY0KKzxuLDDtui36uofcO1lLljOXKYW78L9cWppI=;
        b=F6qfSmMZq/wPypOgAC67EPyycyKaU7EIIF++SbFyCp5+a5lW2b9xNl11U4tn2OMWSR
         5XVUiH7km9VZ22RLAEHtq/YdygXXwR8xD+gQ7ONByUa4MJB9OlbHc4w6Oq55+inGi6bD
         wrn1Hx8U1lQa4DGu4CGrn/Xa9sCUECZCwmMfS/sDrGLY3QTmbG7rb29mMHDIW+lEQ2gf
         7kv/w1V3IdXA4Vp/vzQoULgOOq7NvoETepJ3ytw2q75IsTvQ7pN9hz3ABEDIcYUHKU7e
         YuDrFS3i/usR2nbWZTmPDIYsvPdjBeMGPL3qLjdFjF3Fn62y5Lv5Yrq2+2ITqwJHIpnJ
         VNSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pbROG8ec;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb41.google.com (mail-yb1-xb41.google.com. [2607:f8b0:4864:20::b41])
        by gmr-mx.google.com with ESMTPS id a16si397584uas.1.2020.12.10.05.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 05:29:58 -0800 (PST)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b41 as permitted sender) client-ip=2607:f8b0:4864:20::b41;
Received: by mail-yb1-xb41.google.com with SMTP id x2so4674777ybt.11
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 05:29:58 -0800 (PST)
X-Received: by 2002:a25:2506:: with SMTP id l6mr7829176ybl.115.1607606998553;
 Thu, 10 Dec 2020 05:29:58 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
 <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com> <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
In-Reply-To: <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Thu, 10 Dec 2020 14:29:47 +0100
Message-ID: <CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Marco Elver <elver@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Joe Perches <joe@perches.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	richard.henderson@linaro.org, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=pbROG8ec;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 10, 2020 at 11:35 AM Marco Elver <elver@google.com> wrote:
>
> It looks like there's no clear MAINTAINER for this. :-/
> It'd still be good to fix this for 5.11.

Richard seems to be the author, not sure if he picks patches (CC'd).

I guess Masahiro or akpm (Cc'd) would be two options; otherwise, I
could pick it up through compiler attributes (stretching the
definition...).

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg%40mail.gmail.com.
