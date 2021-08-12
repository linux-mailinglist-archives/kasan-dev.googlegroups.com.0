Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAWF2OEAMGQETF5P6CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id BBA903EA11E
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:57:39 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id s8-20020a17090a0748b0290177ecd83711sf4590906pje.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:57:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758658; cv=pass;
        d=google.com; s=arc-20160816;
        b=r+Ch4phJSozDzhs5GMzElfkZqjAVRohJRtiM+TGAXXkEuIb5H+ZPb5jhKbcIF9nFXZ
         JOxt+Rh3V2XXITOKUzamHA683/Nc2dQWb/i3vH6y6mfRbCpDjLvImWni8MwxN8niT04J
         tPr6Omi5kNS6XT2n1cIfXWnWoi/eKOAgiMu5qw1jAUVPYAh4URC47jdlvSeYq1DJe7zx
         hY9iKc7bZpWljD7O3/7/kxyPDVcv9ts8Jqn/ZcYNdzOD5lEcoh0lyW8PlEoZ/r+CZ/4G
         HtMg/BUIf+wNG5iYYs2Onk3NkSYzggAEi3V4oRSbut4sruJ0ZMNbXIIDSPwYgKbmpXx+
         BdUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k/4hIAiw/D0rQ896SGFBuT24+6INf6xpeMtGbINIKrs=;
        b=IFnq7/eF3wZzycMbmG/yzDqEwwnbpcG+KvNFGnhQyVXzwkQLfdqSEQmEU7beqlr54I
         5t1JGoTW3pquy7+CLDot9fvGHZT4hh5h80ixbuXTe/R9UnYRv8PVVLTqZw0wMZOF8yza
         PU22wjuYZx4B/515qs3WvlUBSeAycB0IrKY1459lszBTheeij/ZrsrTtk/AnT5V2WF1O
         RxhF7JVS1BCew8zLLk7IJBby6p3kjb5EPYOxLc59OnHfPKEhRNZrIWmfNy2yM8+GD9sv
         JI7fAVQb+eC3vI9nxIos3BVODttSyrHIPrkl5dl2+vYrk/YIOPXUBueu9ZaGzp69fcOL
         R7oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u1i8Cx7r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k/4hIAiw/D0rQ896SGFBuT24+6INf6xpeMtGbINIKrs=;
        b=aUyiy5rg2Xk5bSx0CZ3B4/cPKot9zCko/SYYE23SBTOBkY5sKut/ZS1AbIm5yAEEsR
         pDwTu2WEfASZbqBFJJjTUf76TXvc6SxSfu2I/t9dUPl/WAdf8v+nLd1uyWle8Go5ex9u
         R69Jy+C1d3PWRqdQNSbxn4/3g8ZbAAJy6sSQwJia3xfbsCP+qsfUTVUmS2llCRBHzhyc
         vU87zkTpIqNOCwTKN8nwyqetV9QacTR/iawwkUtnhB8Ys8BEZfxAFo75rZNIIACLDgPc
         1Z+/j+qgiHlcXx9OvfRqyOvJ7uXNaxj0l2EOOB46ua0lrgXVNPubSp/NOzIxZJvxmmhP
         Krug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k/4hIAiw/D0rQ896SGFBuT24+6INf6xpeMtGbINIKrs=;
        b=PpNB5eWBdehLoN0TEa0FS1N78rN14bpf5YE71d97gck2MBgv7t89jcDsK2VEKczfmg
         FYaTmUOmQNqdTUImK3lYYqN6rMA+trtI5uMUJSNgaOG1NGKCbBtrjKHdY319piN00CWn
         qlS6LKs4v3jC77jmWMVATsNMuhui64hPsZcQFBujEhDO+F9OqvZ9rR+uNrSi9lfv+Jaz
         ocKV2ghrc0aCH0R5VbxDX5rzxouAaKAbO8hkh5f8Bz53Ef/Q/oWPrCUBDz8ZDyH5oEAm
         J8T8Do479NcUjQK3YRyoE3tOb04ouMh54H/RI5Ql7I6/DaADqWGR4ZBjjB/bmM/N4GLT
         ugLw==
X-Gm-Message-State: AOAM533lslbjhWjIWo50uvzKLgq4V7Ai8bnVrB4/niadHmI/Gvz24nJm
	I7lT1kzRcPk8yFBvChj4XDE=
X-Google-Smtp-Source: ABdhPJwkNq1hB7Xtl3BzLj4Ice0ABLzaCVt4LU4OinhiPY++ypEaeE9DTMBzM7Kketxnt+voV2WsKw==
X-Received: by 2002:a17:90a:3d0d:: with SMTP id h13mr3413807pjc.20.1628758658541;
        Thu, 12 Aug 2021 01:57:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:360b:: with SMTP id ml11ls4739115pjb.1.canary-gmail;
 Thu, 12 Aug 2021 01:57:38 -0700 (PDT)
X-Received: by 2002:a17:902:e54e:b029:12d:76cd:6744 with SMTP id n14-20020a170902e54eb029012d76cd6744mr2725291plf.0.1628758657997;
        Thu, 12 Aug 2021 01:57:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758657; cv=none;
        d=google.com; s=arc-20160816;
        b=UDmhrEr7DWBXROslRspkdLOYqbS+lVw4HX5y0EdTXhiSiiJc5e3aAEWRCHOpazL/1J
         t1Ga8/Sp6jlA74HxCF/oKc7yUw8UqHgNrIyq/AWwRtd6GflPwXWXomtRUlgNcH/7K+Vn
         +RV4sFYC21eOU4acikV6sJE6n/gvPCOgNfMbYaYc+SM0YL8usITmTMKQOxeuKspW8++n
         pC8IPBB7E3kztkBQ1izxS9blS85UBzHv8pwN8D+pQz1N6o7U6NDoFZiDH6ePJqX2YNl1
         xiSPexVXEOCOElQdPQZvLCwn1L9FL9Ay6Fm7JspYpnFfFbxT91DTDR6SVCfzcHmNcgP0
         T/ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Az2ike7xADR+kcJZFa8tXN1V5SP3VTm+A32wNNbsp6w=;
        b=mxs0jUimXJKgz+wTB1RipBM3cn16PEmawoX9Z7iB41Uv8MWQDM+Ykc74zToGhrtZ+m
         p39hCpnT/bDpYhS8t1t49DTo/90dUE1pePiSmT+d3vg2VIC6pptO9Gcb7ScCV3bswAkR
         R1L1FagQpBMqOMsaVcOwnruBmJzbQS79c7ofhZLqO+KKAte5b5opOZ8bRtFGLrg6Wo4j
         QZpSIRvOysWjm9OsBpjXWlXve2/HI25PBqKSAoa1IXsxDe5xvm3UPQ1OFROFo6O7O+wr
         1CXJSVRnHZVG3Dx1nez75oUcBYQrraC6eymHJ91w3K5s0jF1bC+AXbNlwby2AAWhhBbo
         qhwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u1i8Cx7r;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id u5si579530pji.0.2021.08.12.01.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:57:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id be20so9212724oib.8
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:57:37 -0700 (PDT)
X-Received: by 2002:aca:5301:: with SMTP id h1mr2626318oib.70.1628758657248;
 Thu, 12 Aug 2021 01:57:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <408c63e4a0353633a13403aab4ff25a505e03d93.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <408c63e4a0353633a13403aab4ff25a505e03d93.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:57:25 +0200
Message-ID: <CANpmjNMo0p+pQS=_rL37RpPPdzLFDqYw8D3V+qeCt3_jDu+anA@mail.gmail.com>
Subject: Re: [PATCH 4/8] kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=u1i8Cx7r;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> The HW_TAGS mode doesn't check memmove for negative size. As a result,
> the kmalloc_memmove_invalid_size test corrupts memory, which can result
> in a crash.
>
> Disable this test with HW_TAGS KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>



> ---
>  lib/test_kasan.c | 8 +++++++-
>  1 file changed, 7 insertions(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index fd00cd35e82c..0b5698cd7d1d 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -495,11 +495,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
>         size_t size = 64;
>         volatile size_t invalid_size = -2;
>
> +       /*
> +        * Hardware tag-based mode doesn't check memmove for negative size.
> +        * As a result, this test introduces a side-effect memory corruption,
> +        * which can result in a crash.
> +        */
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         memset((char *)ptr, 0, 64);
> -
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 memmove((char *)ptr, (char *)ptr + 4, invalid_size));
>         kfree(ptr);
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/408c63e4a0353633a13403aab4ff25a505e03d93.1628709663.git.andreyknvl%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMo0p%2BpQS%3D_rL37RpPPdzLFDqYw8D3V%2BqeCt3_jDu%2BanA%40mail.gmail.com.
