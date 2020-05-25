Return-Path: <kasan-dev+bncBCMIZB7QWENRBZVMV33AKGQEUUBTU4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B5AB1E0B19
	for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 11:56:56 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id f12sf13104757plt.9
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 02:56:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590400615; cv=pass;
        d=google.com; s=arc-20160816;
        b=kuI7W8o3ef2wiqHxD0LOiSmID6pxBCuqwd+oyp19aZLvx2HJXLbTNb/TRVWMdZ+ViY
         NygsyT4cQcc5BNOKPWwCNQ1rwr0g9iUnG5sb7YtTO6zpac3M5ONkXYW0GXu7huWC3sRq
         p5Fi0Q4W8gPWuR01EVJ1PnC1lM5GJ1ryzCf97Vp94PFSFErLGUXtzcVNU/JwY4eIMqIG
         +u1qfTZ4jMOkvctiD6S93StQAb9OTwzJSp+yPZkudrYXQFhZdxBmA888OjHI3BoIUxXX
         M39lObb6zcY3iGUei5MgZT/WFH+DGkxXIR25wWn9QcOdI5upeVQPGXdc6S7R6rMBh3Fh
         GzZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ezmC3csQI/c9aabxpKXxBJgMMzEzanfep/0xL6X/mA4=;
        b=YQpNZm0fzobUiQOvHoqc3z6rbMHgkDIFi3MHQJGGVwVxNf6qxFTvxFrDvVN5Yxzj88
         GoQFDUau+36GYJmYfecX64M45KrnTfE7Y4ReMok4CSf88ffcg0vjypBIq2Vry7O4dDAJ
         mzv7RaqNxJgZCYNqIsX8EaJPtB1idrYnUFhm84Bm8nermwn+iGiSGWwEvCIsjVksZzpb
         2NOcrJd8hDThnrACLMzftW9JbGvRQutyKybLw+9JU6vIzhp90rN3OCReLGhItcgvA0Kt
         dMhsjZj76hX82RBwJRdNmApez8JNWfo/elAa6JVM02EwuTu6sj4KxqIo1issl3tRs0dp
         MyAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jy+KUYg4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ezmC3csQI/c9aabxpKXxBJgMMzEzanfep/0xL6X/mA4=;
        b=HswH590nZeWOe0Kp5121vwFklQUXU4hCcekeaMohwZduGJCf+zkZfY5e0Fr5fo3n1T
         4vHX1ZY+GXjRk8utr2JizWFDrtmAWbnRrKvOv8yz7pc/cNc7zLZhWsRkqWpVCCExzVb4
         826pjHEf7nsNcnP4HwWfKtnNvRuv04+8F9uxTyG8P1ypcAXkyfAiFY68DQJ4k3m6mS8d
         23QKaSioYxaE66wmRYMxyfnHYXw2gS05VcUtBU+R3X7SHAO9NFE6qhwSYc7wEs8KQXxo
         IZDZ0hy0MRphIk4pbQBudXWX1pchQpQW9JlUdxyrH915z8FDThh3A7CXSxp51F5hFFBX
         uNHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ezmC3csQI/c9aabxpKXxBJgMMzEzanfep/0xL6X/mA4=;
        b=pxUbvVMwWuXvBPtYJGwXQRw5tC1XWBcrobTLjPQz1fP0VlONsXpI2PNkUrXcgKGvk2
         bjeo+Ltliyr+oIu5zO4sVY4Flls33L5s76c1a/jH0Uooti5WvMeow0L5LQbzoXxJ0dTY
         NeIU4tyclIMP4hNudbtGHtRAcK5JApoNjk5Smo9L23eYRqk2zTXJBsinWaTcJj8t6Q0C
         bmJap7XhcyYFhKe9EWAMUnXEhMP/GYipM7qfgyXw6/9eA3b7pXsmdWuslfZSRYVpHdJA
         OWxINoO4G8/hkiNb7OKe4ClzRarYE1cz+FILD5x946f8jsSrfFHMWM/Uzd9Q79t+23Mt
         Fz8A==
X-Gm-Message-State: AOAM531QrIpijdWKWdnasugoIuqV0b0xN+CkMiw0oz+3gFdvnnfK8IeX
	2HbVWbK2VGIBG5CrpJYQFpw=
X-Google-Smtp-Source: ABdhPJxjr1+YdW0mCU0nQdkx2TX+NqFjcb26z5Oo8OcYwHobcTojRKJ4BJitEy3NFMmhpJf5Ygzeig==
X-Received: by 2002:a17:902:7609:: with SMTP id k9mr6340483pll.55.1590400614905;
        Mon, 25 May 2020 02:56:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:920f:: with SMTP id o15ls2662194pgd.11.gmail; Mon, 25
 May 2020 02:56:54 -0700 (PDT)
X-Received: by 2002:a62:fcc9:: with SMTP id e192mr17043378pfh.244.1590400614535;
        Mon, 25 May 2020 02:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590400614; cv=none;
        d=google.com; s=arc-20160816;
        b=cJGWdOw/Ys58LsS3WKQ2oYRuXb0om4SSDtyrgDv1AK66AbOjK1Oeio8rzzCJp5SOoG
         0o+Ab8QD9xLYC8QQZaceWGS+a2wsCapZV6JmLNhz2tlwMkKRM0eBmYHfub95uoRJTdqx
         k13Llqo785G49O9AJTAW4kAHgqgd432p9o+vd96hHoBl55yYQ1f7bWuZB2hTDwGtGWvo
         hqU5GYkOCC/m1D9DH8xHgGnkFFdvzEBN+w0DtEI0zbxfFde4uNnuZPFBUELt2brbiOw9
         iQ0NYVcRBpJVwNkmN8owr5/KhJBJ5H+lIACEenbFCKF8zdlZY9KAIUwo1k4gqJPxhxBR
         pIrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W3OPQj+6MaWJ3brcNW2aa4WZVKniXvFNcmel059rH8E=;
        b=bZKfYoohp6vuLrDdPQK2ujchQf46dJPLPs4kjp5PGhAdZYRQ1u31V7elc1ZXn3tF/V
         our8t24xHadvmwaJCuL3WyHfgU8D6YGd90UDSTbmu/F0v70PR7WX0qTgusiLYH8jZDoW
         rjsW9evOaMMLxY9FIDB/e3XSlet1RZPu+2U1VgqUNWKa1FQzFs0lS2pXhr+JbmteuM8y
         WVJLAwfukN/aCuWnr28oEWe3dWnN++e+Pqby10TxsPq5WXFOdgtEJhqb7XREJSKFQQBn
         sFKM9Ap+LwJGimq1Y213BrTqr2nUkCg6y4JoBYmGKm82f/MDgu7mY+aO21hynj6TQz6n
         P5Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jy+KUYg4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id j204si1191129pfd.1.2020.05.25.02.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 May 2020 02:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b6so16949729qkh.11
        for <kasan-dev@googlegroups.com>; Mon, 25 May 2020 02:56:54 -0700 (PDT)
X-Received: by 2002:a05:620a:786:: with SMTP id 6mr1210763qka.407.1590400613522;
 Mon, 25 May 2020 02:56:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200522020151.23405-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200522020151.23405-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 May 2020 11:56:42 +0200
Message-ID: <CACT4Y+axrVeCwdEg_yWH57jF7gcKT429J4wVwsNGPuARcPMiLg@mail.gmail.com>
Subject: Re: [PATCH v6 3/4] kasan: add tests for call_rcu stack recording
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jy+KUYg4;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Fri, May 22, 2020 at 4:02 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Test call_rcu() call stack recording and verify whether it correctly
> is printed in KASAN report.

Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>

> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> ---
>  lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
>  1 file changed, 30 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e3087d90e00d..6e5fb05d42d8 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -792,6 +792,35 @@ static noinline void __init vmalloc_oob(void)
>  static void __init vmalloc_oob(void) {}
>  #endif
>
> +static struct kasan_rcu_info {
> +       int i;
> +       struct rcu_head rcu;
> +} *global_ptr;
> +
> +static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
> +{
> +       struct kasan_rcu_info *fp = container_of(rp,
> +                                               struct kasan_rcu_info, rcu);
> +
> +       kfree(fp);
> +       fp->i = 1;
> +}
> +
> +static noinline void __init kasan_rcu_uaf(void)
> +{
> +       struct kasan_rcu_info *ptr;
> +
> +       pr_info("use-after-free in kasan_rcu_reclaim\n");
> +       ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       global_ptr = rcu_dereference_protected(ptr, NULL);
> +       call_rcu(&global_ptr->rcu, kasan_rcu_reclaim);
> +}
> +
>  static int __init kmalloc_tests_init(void)
>  {
>         /*
> @@ -839,6 +868,7 @@ static int __init kmalloc_tests_init(void)
>         kasan_bitops();
>         kmalloc_double_kzfree();
>         vmalloc_oob();
> +       kasan_rcu_uaf();
>
>         kasan_restore_multi_shot(multishot);
>
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020151.23405-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaxrVeCwdEg_yWH57jF7gcKT429J4wVwsNGPuARcPMiLg%40mail.gmail.com.
