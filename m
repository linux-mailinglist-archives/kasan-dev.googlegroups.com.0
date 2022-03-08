Return-Path: <kasan-dev+bncBDW2JDUY5AORBYN3TWIQMGQE52C3BVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 45D664D197D
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 14:45:07 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id p5-20020a17090a748500b001bee6752974sf1507520pjk.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 05:45:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646747106; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTLRRexTe2EH6eYumJUbLdWqNcBPklNHO6uJsbqSGGLqPphyvLzpf97qEGDTo/RdgS
         knSyHEeyRWAO8GIvIac4RTRV1MtRQ+EKci7APwLWmVTgcQP1l+h20q0sGaPd95oy2UxK
         qFv7zgjwMWEPYYAtTMc48C1nCiUX8mx7+3xvIzMzBad0ABP9GMBOcxpX04AWSIY2sxS+
         jWuvQnXIKxplrwZv0Ybh7W9pI4R433DGC7yeZs0wcSGulv9p+/CbLtBD2CMtdo2D3enE
         Blm9jzsr4NdYyNLacJQq2yVFnrIXkG27iA9kxhIjhZ+eQWwzdGMJtyb6f4oOxZZ8nnIA
         JyCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=CkDxuGFHXH3ud9be2taM8vfjhuKRDGeqE6Jc95FIDec=;
        b=s2LHU5aw7MLGjJgjRiogJTqf09CRRDy58upSO1efAn0J28YuYemG2aWSp++nLsX65j
         kctXL6AwOMWkJmBaE6bCIFVLtKYal2sAsdFFnmKwKiI/XEskMTKoPxIFJ4OBxR8WGZIi
         O5Fkods6B71WeErLshqlGeI5jV8UgSxOpwsk/MdROj/R/a+obWWG4Rm4GS72TnaJ8e4T
         /xsIF2TRWmbnYVh3ir15UJ/EszFallNSTp46/b2xxcCOD+yrdVaPdfTtfB96IMj5bcNj
         /1r4QF77zU2hL+17Z2PAz4VGu4e2hLQLmzvAYoZe1cKU9IX0qjAfahdGNaUKv8BniSXP
         J8ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="o/y1YVgR";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CkDxuGFHXH3ud9be2taM8vfjhuKRDGeqE6Jc95FIDec=;
        b=ZYkPiJKSo8F1680Tj3/GZG0B+o7cm2ZibW3FDEoGeqbf1SdS5b7gaFQvc+zt0QfP2W
         dEiotHtfzRlXgvHsIDwgm1E6asaJ21FbWTBq0cpQiYkoa8kk0cWQDAKefvPVncy/x9hn
         kRn4tq89NvzHDVPh5lBN4E8mdDcSFn7z6rfQY8q8MiruwsX9ye5e4kuJGbR5gQN0v0Vj
         EMfqcRurmEKHHGm7yHQdt5nN+dAHZ5TX9kp5ALHZPJU/0GkMTqRxUZ3/Hh6u5Vp/zhPa
         VK0FxL01ZNvnm3V2uGmUeNX6wEgLTeoXWkXP/HVuUsDnLy8oh0iSm7dQAowFoTF27Xto
         F5tQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CkDxuGFHXH3ud9be2taM8vfjhuKRDGeqE6Jc95FIDec=;
        b=dOoBE9lE0TbP3Qean1wloHbWmj0jxlMPQiiVxittnOHS1ycNWQlNt+hxjBThfHkuA3
         d6+ZFx3LtWEF4h8wpAWVTWnNQ4cyhZSRfOZqhzyddiEeHp7OlQJkQNLUyeb+GO4kOZIy
         GdhlStrBaeRZBkM7/HsVXgXP2LMEzyQXiYF/Paai5aB+y5EOxgdm2/oc2hJw5P5Vf1Vg
         CLIu4Vl6Vy7dQ9lhzxXb+9LG7D1hZmHNd9DjbevcJAVNIIgeLxHrWkIs00cYZoXRhb4W
         d1EZJpcClHnh700fkJpTgSOGNPSSIfmq2OX/8JJVL/brz6blYRW1HZYdO5EuXvRS2Q+P
         1QrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CkDxuGFHXH3ud9be2taM8vfjhuKRDGeqE6Jc95FIDec=;
        b=XakzACXmldoaQGyYEw4Truh/Cab2cwjeVbnLuZeVcphpu/JYpDgWTDXdlHZpM9Dzni
         5kWJjuOuYuPqpaMLoxvj8SEIMR5UNUo2/xissx1RuJwLf7N3LLVLJwThCYWbuur/J4Wi
         I/V5lkqy26l8y2ugtfIYE5QQCGIyD0fciiCUzEsGOlTx8PnTA2/n/xfHv7/9rtyhb+6j
         X20+Rdv8CgfBtfS59HYGJDyFTcW99hybdgkMMm+M2OKw/KvEyFIHdapgWBhjup60ywvo
         BKybAxGsnylG/T+IXUbkdAKL0Vx9L4bInR1Qq4MPdQs0n+f3bmhJesBsjCi+6WoC+g2N
         DsrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bEHY3cveTB6VPzPQxuS/aphVK0SBZgH6M+s1rudeultUaOMIy
	JEEZ+WX5PUQ/Bm/eA7EzhHM=
X-Google-Smtp-Source: ABdhPJyZzd/DrNJmEJsXliUEne9BtJYpt0F5ziMqQxNbEZFOmkHL0NUXkFw6iQG8ZnWYe5llR2ilSw==
X-Received: by 2002:a63:513:0:b0:380:1180:9b48 with SMTP id 19-20020a630513000000b0038011809b48mr12299651pgf.623.1646747105773;
        Tue, 08 Mar 2022 05:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c202:b0:151:f2a1:8a5c with SMTP id
 2-20020a170902c20200b00151f2a18a5cls3869176pll.10.gmail; Tue, 08 Mar 2022
 05:45:03 -0800 (PST)
X-Received: by 2002:a17:903:291:b0:14d:522c:fe3d with SMTP id j17-20020a170903029100b0014d522cfe3dmr17591199plr.100.1646747103575;
        Tue, 08 Mar 2022 05:45:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646747103; cv=none;
        d=google.com; s=arc-20160816;
        b=z5BlgLrkkWvgJ3jDXCavQX1/DVgrmsmndDTV1oQ3WXv3wWBncNADWini6ffIbwKsoW
         4tj8doN6/QTPbk49Scmy9EShdFYlTCrbX1GxBEVlMWZTlTxjGSN4SCMDbilxyMTi7cOG
         NEJ0tNMRTSwn4euO0D9sxK8aD4tYOijbRSgBvCpIxfpFXi2dCUNG1uJ3pbTfAPrQOfzY
         E6wFkyDaWN5MxDV2YyHNDNgjRVzWrXV9RaIsiniu43koKGVq8oyIkqwn2UCWPJ6Kiz3J
         wfkWUoElRUdApg2ra8bVEYDzKwowEJiVcJSWlYWdVAraHzx1GmDmLeWh8b4OKxJ/AH74
         4FJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wOTmPPxRGAGavYaBI0ES2ExVC8hASPRKrb33K4sd3F0=;
        b=mvhf/W6pkG4+b5Fpj8hZjAMZANTnTd4V/Mzx8zgTS1eMDgxhA8zTPPQF7pSIFnGD8y
         Kb2mHV8jFtJPE+MS/jOKSkDAyyUzGa37d4FmWnPI8hHWkzT9WLUBsVlDopPPlLUUm3sb
         g2/FSMqK4eZuzRvcsqeuPA5ct78UAQs6r0oFMU79Jwbx2lope3DfjHfztQtSHR6DFAbS
         Q60VJduoPI90bXF09upf3DaAeIXWQGUryltaTuY8ZJco4V+MrUsG1YIJ70EqkFpYUOGu
         rM/5lCiUQzp7AU0R1+9BXPie/7Y2K5U/hygYPpzzMm3PePSR9xpBRb/cU50EFSDgXppd
         UhTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="o/y1YVgR";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id k11-20020a170902c40b00b00152070a088esi58392plk.13.2022.03.08.05.45.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 05:45:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id l13so4333551iln.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 05:45:03 -0800 (PST)
X-Received: by 2002:a05:6e02:164e:b0:2c6:59b4:9f60 with SMTP id
 v14-20020a056e02164e00b002c659b49f60mr3053300ilu.235.1646747102985; Tue, 08
 Mar 2022 05:45:02 -0800 (PST)
MIME-Version: 1.0
References: <20220224002024.429707-1-pcc@google.com>
In-Reply-To: <20220224002024.429707-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 8 Mar 2022 14:44:52 +0100
Message-ID: <CA+fCnZfeUnCk1zLAjaoWdChyUqaRNLsbdbwJXF-bQEzWSyN6XA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix more unit tests with CONFIG_UBSAN_LOCAL_BOUNDS
 enabled
To: Peter Collingbourne <pcc@google.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Daniel Micay <danielmicay@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	stable@vger.kernel.org, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="o/y1YVgR";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Feb 24, 2022 at 1:20 AM Peter Collingbourne <pcc@google.com> wrote:
>
> This is a followup to commit f649dc0e0d7b ("kasan: fix unit tests
> with CONFIG_UBSAN_LOCAL_BOUNDS enabled") that fixes tests that fail
> as a result of __alloc_size annotations being added to the kernel
> allocator functions.
>
> Link: https://linux-review.googlesource.com/id/I4334cafc5db600fda5cebb851b2ee9fd09fb46cc
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Cc: <stable@vger.kernel.org> # 5.16.x
> Fixes: c37495d6254c ("slab: add __alloc_size attributes for better bounds checking")
> ---
> v2:
> - use OPTIMIZER_HIDE_VAR instead of volatile
>
>  lib/test_kasan.c | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 26a5c9007653..7c3dfb569445 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -185,6 +185,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
>
>         kfree(ptr);
> @@ -295,6 +296,7 @@ static void krealloc_more_oob_helper(struct kunit *test,
>                 KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
>
>         /* For all modes first aligned offset after size2 must be inaccessible. */
> +       OPTIMIZER_HIDE_VAR(ptr2);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
>
> @@ -319,6 +321,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
>         /* Must be accessible for all modes. */
>         ptr2[size2 - 1] = 'x';
>
> +       OPTIMIZER_HIDE_VAR(ptr2);
> +
>         /* Generic mode is precise, so unaligned size2 must be inaccessible. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> --
> 2.35.1.473.g83b2b277ed-goog
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

This patch seems to be in partial conflict with the "kasan: test:
Silence allocation warnings from GCC 12" patch by Kees, which is
already in mm.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfeUnCk1zLAjaoWdChyUqaRNLsbdbwJXF-bQEzWSyN6XA%40mail.gmail.com.
