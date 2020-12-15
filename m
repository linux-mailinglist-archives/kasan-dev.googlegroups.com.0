Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSMU4X7AKGQE5ROAP6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 51B452DB72B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 00:44:10 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id 93sf4836019uax.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 15:44:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608075849; cv=pass;
        d=google.com; s=arc-20160816;
        b=B7Vbz+UaRGxzIUK509m8CtgsmAZbTab8O5eVstkdJ6uP2HOlLAaKIsydKmEa/IudNZ
         EwU7TJbkKoTPnqxR7SE80D9ntxME0d95AqUfvHRikdGA/Q9cDx8xlm2BZDfot9EjV/uT
         7RVpjrH+bl2HkJZTJQdYaIF8+ld/SXtPydbko9E2e+v9qb04qJc03rquO0jSo9rfbKsf
         WTF69M0PIX7EScyjCAE2FZk0xvWgKpjpngHW7WZMgZl+RLWUTCGYlmahF9DXtl0WcPPJ
         YLvW1FTZJxPTpaCS88rUWhXLNO0DTyi7qgGQVXFpepq16/nSLiuNYjxGOos8Ud5qol+D
         39Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9N01qKHCVfJCtXJStrItSrjX+rkLdozVEuANh6gcMyI=;
        b=hr5x8SU4Dj7nI8IK2AeFdc4YIPlDDhwzc6K/bdnelRc6yI24+wBikM/gH5/+onkOHW
         wyH4ABpMeJzv3YU3j2DPhlWaJM6UpV01r4zzmQe7TmSGDkspfHOluFFPJdikEITNbUXy
         pFGZNWOhrJ++UbAVJ/yJAp/XBlmQM9ByZvkn3S+AM+B2HX6w6eL8dKRo5+QDcB3sJWe+
         WUenZ+ugGAW9HBU5cwzWc/a+35GBN5li4pR9RU0RfUUpEqeCGrommsq0Al0fdqQgGppK
         8w0jFAGBTBVkQppXDLYI8tO+lIdUAV0exX9gxEL2a1yvq2XCZZWJ4dlHFuvcHdBhAGmz
         hpAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JTpekMpA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9N01qKHCVfJCtXJStrItSrjX+rkLdozVEuANh6gcMyI=;
        b=X+o2Yk3Fo3JphdXRD3piHdpTFluvF9S9P80WhyfZy6HbENLWHuJpv8KyjaSrpVM3C7
         yOtPsztZyxRUMbeZxlRs6fDykA2CQpjCaYtybCtjUhC4xesLfzOOiI6Kr1tn/bkjRPDx
         uxL5+1ascsiat7U05boqG50zXA9VG4Jy0vtC2l36vE4FJZxEAsL7d+RKFjv3jLixs3M4
         dMFdDdL/uPDe7mqP1G3Dor2EwSVxGXdZ8o1b5z5mMKjjMpTELjea4u+dN+qOIywCp57c
         nJuqJuhvfl2hrjkUK/CExMzjQovbYe6Wn5xt09v+PEDMXjImHS7h0bvWUNGdfPJrRvqu
         +//A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9N01qKHCVfJCtXJStrItSrjX+rkLdozVEuANh6gcMyI=;
        b=hq7cozvXrg94LDJ7zBr7H9UlFjDND5xOE+5tuIGTf9Ewlsuwr+6ye5qU+6zcVR1gaZ
         vI02z2O5NmK1zcIrc8Jm8IGvFBBeugY6L5bSNpNnoRqqyfB4uuhK4Vj+zV1UAF/z4sqa
         U8tnwGtZaSCt14M7m8mtiveM72mEHRBSRtnonxnAxHfJatwsF9lebbal2sggD+FDvG4N
         zMKmsEfkIToCq3F1Bq8A7mBKcZwouI1Tg/lA4aEHEsoYnsDACzLnf2C88DYipx8Vjey2
         zbm69ABzHAPVXgYeD36yhrJn5Yof0aOD+dybXXoPJ4V83nqCe4otkUZnIAtrSioOey4I
         /c0w==
X-Gm-Message-State: AOAM531ZRWrr3SK4yhzpZvxM+mzzIeighotnfSNvbe6pcy2s2KlMSnWZ
	C+SE13hTzWJjVogUECmzyBI=
X-Google-Smtp-Source: ABdhPJzgypTkDrgXmbgKploI/NUeCZLLUd4oOYyd4i3POTtCgivGaMbVR+n9m5ul7Nb4vuTUVHSV2Q==
X-Received: by 2002:a67:8a8a:: with SMTP id m132mr18543937vsd.31.1608075849353;
        Tue, 15 Dec 2020 15:44:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7843:: with SMTP id y3ls1197757uaq.5.gmail; Tue, 15 Dec
 2020 15:44:08 -0800 (PST)
X-Received: by 2002:a9f:2604:: with SMTP id 4mr12125408uag.41.1608075848888;
        Tue, 15 Dec 2020 15:44:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608075848; cv=none;
        d=google.com; s=arc-20160816;
        b=pYik3qRd4/B4vIC54B/240IwOvfP9zay4wfahNBryvOnJCQvRELUXeUexCCVTJMhSL
         UnJsCN0ayQ1RMD+m7oKZBmywditrzcmFHBEJlvZilj+490H+9H+pxO2eP6AQG6h1aTDU
         8w6DxJ4QQSMTHLQ+xzjlXyERZ8JW+bOsLiuuSIYHW2UQ115OvsvIiM1YX02gmofHelmN
         wce180CSwTHL6Nmg9HE+0Q4SzmkF+w5aIDjAFIjDJNNuZ/6YvaJ6gfXgF0QPzUl7P5pE
         sMZEWlskjBtQUOQP6ZAPGt5/N63NejhRtdMG4UxjMCGI6i+ul/u8dvOiEhDORiyznLDL
         H//g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VMk7SZpHhf+ZRi/9XRqaSvGITvxxA084fMeyBbrwPkI=;
        b=kCN9avq4dVBjDOWh/h8I6SZ1GHq5kIt9Au3YcSoC0tjUe8rNZLgNu855xUSy85oyIe
         A0eC9pDjLvZtPubhWjIUR7MxvXdd8erPDKdgiKX3xz7piYfhTOapiJOtzmeCMjnFEzMJ
         ZdQYnGzFiqRjh6rUvBxGp6sQNHIIGzpCf/nwuvOLInI7geqtG1CRqM8UppIvKoafA53/
         avwE25+CgRWWDoJNvUT5bNaO2SYe+CWIZR3EoLZQR3k6jfc4dkxLYpz7pY4VMC3aRS3d
         0dIeqeC2VECvgNEdoAeVLgpKVBNyeOALO42Gjco+t5wrr6WAWFSG8uXtBJK9GvoVWi+/
         MegQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JTpekMpA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id g3si12953vkl.1.2020.12.15.15.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 15:44:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id 9so18207856oiq.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 15:44:08 -0800 (PST)
X-Received: by 2002:aca:3192:: with SMTP id x140mr670980oix.172.1608075848207;
 Tue, 15 Dec 2020 15:44:08 -0800 (PST)
MIME-Version: 1.0
References: <X9lHQExmHGvETxY4@elver.google.com>
In-Reply-To: <X9lHQExmHGvETxY4@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Dec 2020 00:43:56 +0100
Message-ID: <CANpmjNO5ykmE5kWJ0x08-dTDOLe+Wu=2yQ0OmfdQEbQfHByeWg@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix typo in test
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org, Linux Memory Management List <linux-mm@kvack.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	kernel test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JTpekMpA;       spf=pass
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

On Wed, 16 Dec 2020 at 00:31, Marco Elver <elver@google.com> wrote:
> Fix a typo/accidental copy-paste that resulted in the obviously
> incorrect 'GFP_KERNEL * 2' expression.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/kfence_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 1433a35a1644..f57c61c833e6 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -665,7 +665,7 @@ static void test_krealloc(struct kunit *test)
>         for (; i < size * 3; i++) /* Fill to extra bytes. */
>                 buf[i] = i + 1;
>
> -       buf = krealloc(buf, size * 2, GFP_KERNEL * 2); /* Shrink. */
> +       buf = krealloc(buf, size * 2, GFP_KERNEL); /* Shrink. */
>         KUNIT_EXPECT_GE(test, ksize(buf), size * 2);
>         for (i = 0; i < size * 2; i++)
>                 KUNIT_EXPECT_EQ(test, buf[i], (char)(i + 1));
> --
> 2.29.2.684.gfbc64c5ab5-goog
>

This patch could, if appropriate, be squashed into "kfence: add test suite".

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO5ykmE5kWJ0x08-dTDOLe%2BWu%3D2yQ0OmfdQEbQfHByeWg%40mail.gmail.com.
