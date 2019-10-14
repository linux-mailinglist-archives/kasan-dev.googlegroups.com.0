Return-Path: <kasan-dev+bncBCMIZB7QWENRBTFBSHWQKGQE2SF4JLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 75E55D606F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:41:17 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id h10sf17475772qtq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049676; cv=pass;
        d=google.com; s=arc-20160816;
        b=cx8px4rV6EhJ2KfXrqRNkRUsSr6lWrvSsFHcl7nB9Lm0hCcXUwcEksAl2ZarhoU7We
         oWlu9+OwHOreAJZ5SAuzsDLso9RR6mvJs8SAqnHkLwzSe94ShIf/GqNJsG0zC70CohVB
         y3Iv+BvLk+2fQ07FpDPAfNawLGQ5WiV7czO51Qsjumi4bsui0pOln9DyltIm/NFerVN+
         tw+tmcQyQg/lZ5seeHa8hnDT4A0C2GefL2N0WYqCij2axb+utGNnh14ZRg/1jpjwvGBc
         qb+9H1v2bLM7nCEmPYmpTfVFpyzm/LQbho8Yscm0cXoAh0PVWucbjXQE5VEkn3GtEdek
         odTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tmHy2d+4LLF43Rd/oYabyNz+n3DsIWXNcNaHzmOIdbI=;
        b=oDKKnEg8p3JafPn5pljy8tWY+TX0Y3X7q989Jfd840Mf/nn6GHD58LkcvnmqiPSrid
         byiqbfffLWE50n8Ky0GivmWCU4eXAGQLMPEDZioH2R6/Pr6QsjLgf+fqnqn5ykm1ZLhq
         4/eQIukU686dhuR5t1mr6xcNtKjDsDjdApAWXivWr2oMbNzwxcYZIkqZt8mHVG0704/V
         TS42au8mJrw+lXqu50JJSGHjN9uk/pVPRgN/iB2M63F/5wgstyK3e6mxizN8FucXDBZZ
         tnNqdD/ZHsezNC2TR7vX89r/3nWRFGKeX6EcyTsmxR+1TWsQCSWAOHem3Vb4jb/fV+eI
         mySg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rV8Qq1zT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmHy2d+4LLF43Rd/oYabyNz+n3DsIWXNcNaHzmOIdbI=;
        b=jcG3YtBMKHNl4tYKgJqo+rzRgNbjRQYpsYYI0aM30wsJCgws2qGiXfMZbwPMvAKVU0
         Ogo4UabwqRDI8Bg9OjXc+o8pTM6KocKe18O4dkk2ZPw2yDcmgjBeOTLkrqisIsmukzTj
         niQt6+uejj6D9MOZ6VYhrB4/INBctnGgiPao1SwhWQX0tg9ULlfsULXuIDBK1pfoElUb
         RQFhu3VfDJOoz4xDFKhIX5sx9g9hzOOTsSVTjhDH1nMJ3xEtPJAOtUXiAfuR3pWTvWZR
         O9gSb21jUyuFMy1qD+u5BVBoGpvO2Ef3iCmlxqujnWjkoPGHhGqPQ8WwrqbEIc7haqZN
         D7vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tmHy2d+4LLF43Rd/oYabyNz+n3DsIWXNcNaHzmOIdbI=;
        b=QVGquS5vOxphPw5tpYwG2TFirbrZ7EgJPQGwSIu/g/qK24Mk3Mg4Mn4XBEKOit00UU
         6C4/c+tHqkfkXiWX9aRm5mB7DT7f0fT0bmzw2ySfjNCaYlGnzQ31vGRPOIdZnhBnaP4p
         2k068tHMMJYbWwB0s2t6+KEJbzQ86Mxc4T/ehNnYn9oLglgB2l0hC2bDtL6qLfTF+8GN
         C4v38Nf0Adbz2DqyC90tL9QeMCnRKb1pceSHEf0opq4Af1enhD7rVKPaSRL98TlzJbRP
         yS6cz6rK42gVO0ZTFDkUWd3XhN3MeUE8p07uIXQxXdw39HjsEXAKscLJH5sXETEbrM5o
         9Gow==
X-Gm-Message-State: APjAAAXio6zmh3W8CZW5eNAIL0aXHGTuEaJY1jtuK+pvOj5FOEBSbLF3
	XhXZlCMj6RPE8+T6cHxE8OI=
X-Google-Smtp-Source: APXvYqy+Ev70vGSNl9ni7gbyM3NXqqiGY7bc7edYWj+D4sq762C0kS3rxgKBhWEa/Tu4FZE6L+PJFQ==
X-Received: by 2002:a0c:902f:: with SMTP id o44mr11394603qvo.192.1571049676498;
        Mon, 14 Oct 2019 03:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3809:: with SMTP id q9ls3765602qtb.5.gmail; Mon, 14 Oct
 2019 03:41:16 -0700 (PDT)
X-Received: by 2002:ac8:529a:: with SMTP id s26mr31286023qtn.322.1571049676283;
        Mon, 14 Oct 2019 03:41:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049676; cv=none;
        d=google.com; s=arc-20160816;
        b=mdiGA5CRw7//FFv0aArkzZ4NmmZUIPlhaVBhN/OYKUQDjZ0Ixg4QKUePozdUoEza8z
         0sPnhFxYWqVQtVVaVCeBVhnT3WynO30RM9yAYEXW9lXA3cmG3r5lCuZh9PiA3gOVQnZQ
         jtXK1qQxSnaDe0AJt3BYjT7n6s7J4+qtt04NM9fdx1H+w5IYks6NFsLX1oOp+e9fPZCB
         yypjh0bKo+CK4zKMeUrEalpgbS10eLXyFpS3CWjI1ELnNHdNJTl0Zu9mVnaQRTvR3v9F
         9IuLGw4fhPKgZDtDBm/+tGHW4t5GOHciwPMjTuINlDFNwUPeqMjjss2bUEGvJ4IEUWNo
         TWug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/mDM4m3k7JTmmCNbrikY7f4R5yxUjjMcbeuuaXG2YC4=;
        b=w3sHCVKQPp3L5YcOkUsylEww9uOLGIAh54DY42r0UdxL+1jorxQX0D8owpLkgS4N0M
         97veU4+J3xRHd3CwhOKuD5Nt1V56v9P1weE0rTZCSRwRP+1pKgHvoBNloDKDrvrwIjHa
         StFPGSAuhRKyMnb/wV74M/wOeGHIhYWrGoXFtI8swvtZ0TNnTZYTDHPGGFHT8uIXmFdF
         1eeOtPO11StG88nsZI1c1tTg193FYxjcLuR4+4U4Ezu4vvVtR9nA86Eyuwb6rnzLqJzI
         07W9cMLBjXu+TaH6VXgpr2CkAIcTSVRQZ43EjcsqSsp+wPj3J92kPjGLe0TB3R+Nbi8Z
         Fzrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rV8Qq1zT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id u44si1922015qtb.5.2019.10.14.03.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 03:41:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id f16so15414581qkl.9
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 03:41:16 -0700 (PDT)
X-Received: by 2002:a37:4a87:: with SMTP id x129mr28464725qka.43.1571049675564;
 Mon, 14 Oct 2019 03:41:15 -0700 (PDT)
MIME-Version: 1.0
References: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 12:41:04 +0200
Message-ID: <CACT4Y+YOwMB6bguUwpcgDeaenErqG+CeuqcV-9GmB72C13Fn5A@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: add test for invalid size in memmove
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rV8Qq1zT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 14, 2019 at 12:37 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Test size is negative numbers in memmove in order to verify
> whether it correctly get KASAN report.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks!

> ---
>  lib/test_kasan.c | 18 ++++++++++++++++++
>  1 file changed, 18 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 49cc4d570a40..06942cf585cc 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -283,6 +283,23 @@ static noinline void __init kmalloc_oob_in_memset(void)
>         kfree(ptr);
>  }
>
> +static noinline void __init kmalloc_memmove_invalid_size(void)
> +{
> +       char *ptr;
> +       size_t size = 64;
> +
> +       pr_info("invalid size in memmove\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       memset((char *)ptr, 0, 64);
> +       memmove((char *)ptr, (char *)ptr + 4, -2);
> +       kfree(ptr);
> +}
> +
>  static noinline void __init kmalloc_uaf(void)
>  {
>         char *ptr;
> @@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
>         kmalloc_oob_memset_4();
>         kmalloc_oob_memset_8();
>         kmalloc_oob_memset_16();
> +       kmalloc_memmove_invalid_size();
>         kmalloc_uaf();
>         kmalloc_uaf_memset();
>         kmalloc_uaf2();
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103654.17982-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYOwMB6bguUwpcgDeaenErqG%2BCeuqcV-9GmB72C13Fn5A%40mail.gmail.com.
