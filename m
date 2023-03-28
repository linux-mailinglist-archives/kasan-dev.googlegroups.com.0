Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSFLROQQMGQE6FHW6FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id BCD426CBE30
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 13:55:54 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id h4-20020a170902f54400b001a1f5f00f3fsf7465150plf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 04:55:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680004553; cv=pass;
        d=google.com; s=arc-20160816;
        b=bpJU8GUkfEb7OBkOv9I/B1NQLVn9Zl9zx7YMIsneNCgrjFdSnRsyOrgrVrBXkfH5ao
         QEzPvBcoxMKtqrhU5cuZfIeSrDLf3TH7Yq8HHaScvU/7nTfT7efm78C0NobyTSr2aHLn
         Q7WSsvhUruFhydImq2K0gxQiIvnjOOB2jdmTYKCo61zfkAxOYONixmYQho23eegF0pe5
         jqMZTXClukMHtgqXzzglHKN8ET/29p2hN9kc9rDrw72Li/b1L4Wxo8L9RTVOgl4pkNJa
         jRMA0jy7ssK9dZ9OiggdRW30xUZJMF0ElDN/+ITEArS23cLERnxPcM+UALVdeEg2z3b6
         zr8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nc86lWXuM+FvogW2wNDbspn07OsurEejUpjK/1KRZQA=;
        b=ElKe6YgXiLWDDe3tQ4gCZwpBKdzd5AcuoksBv6O1B1bMtG7E54DU+5IW03IsYubb0F
         UNFSnTEHHEGVDK6Aokl0+f4YXiBPNSwCRwK0mN3XW9fRT1L2VoT8IqOWIksS+iIODeNS
         tqE+NF2Pc/qwIcqeZ5EJMlYGDEUTJqxS2UjAfzhSzj3q4OqwgZYHPyVvk9/L52u2D9Dx
         Od/PQ66wDKR2v+Zti7eUmxYJgT2NGjM6JkRKtxLsODZZzloAFxpyVyc+ptkVpSDJmxn2
         jgaEWvpZKO5pxR1g7orTwMv4Al1co2QAPMMxn7mLL0cja7HVupVC+2qJGTXta95sLj71
         MxFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KcnVfpk4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680004553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nc86lWXuM+FvogW2wNDbspn07OsurEejUpjK/1KRZQA=;
        b=iU05hKu/gG44/Puz0tQ9kzdHDC0I1xigMSVOs5GpP+Q74KFCrtV6PjciwuKooWqdyM
         mpnQ6B6610YtMjQUBPJp9OSXG/p3ldT1sWIkoFVGDwLJbgQNXIiywOtlryMtM7BKTdrj
         KwsWiFXhm0+LeHcOC7qZrKveLorVlkjEtRuiXhd9WVFpa0KOkTtUzz5H+xvqEFA57JiV
         ltQa4ir5LSuYHynod9/JM74T37IVoStP8j83AjicBkMtcocWlXcvYL5Bzhc+lLKs1HmY
         ztDFYKzsVwFRx3pcKOw1aczfzbf3q9V50XUP57sldRpdo/AA4hUj4C6G8u4HS6Uwg1Gz
         4E+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680004553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nc86lWXuM+FvogW2wNDbspn07OsurEejUpjK/1KRZQA=;
        b=uKP65q4EB1/re9y69opE2Tw2xkSs2QjA4SOeKLQsCMaCWfHQfD7LO1Sb3ckO6lD2j4
         0N9Qo0hm0s7xlKdcHqIQlKGFrO0oV5r/XjyoRZ+5zFSmyi5IxyFDtGU8ZxGo6L4t7jsO
         VqQPbnfg7i7dNoZCMXSlKX92NPhGUiRFGTN6chA8JPEr4s9r7usr6dJYxwlvWMNcqbEk
         nJb/HuBWvT2ZvFpUunTz7CYChEOgmucI0ZQXDT+lxZwzTj+TpmWQzBcZSuIFb3xQV9Z3
         9D351LoM/fYPBsq9AsKUwouTYGszN8oH8Ob+/cCY/tVvuZbKyPHTGMBp6KEyVhDfJ1/n
         GGiQ==
X-Gm-Message-State: AAQBX9d4wetvMdDP033PQpEOg2fJ657/7XwgiLWiQNRtmvRSnOdmMZWu
	n0kwoAJIsiyIK9LxRpnPbCU=
X-Google-Smtp-Source: AKy350YmRMOYJkBOW/DiSnc6INblqdc80sGD7jgo/jy4uGuJtZ/iFvrmZiavJKrVRcfH7M10P9H77g==
X-Received: by 2002:a63:c49:0:b0:502:fd71:d58c with SMTP id 9-20020a630c49000000b00502fd71d58cmr4168920pgm.9.1680004552880;
        Tue, 28 Mar 2023 04:55:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f7cf:b0:19c:a86d:b340 with SMTP id
 h15-20020a170902f7cf00b0019ca86db340ls9859071plw.9.-pod-prod-gmail; Tue, 28
 Mar 2023 04:55:52 -0700 (PDT)
X-Received: by 2002:a17:902:ea06:b0:1a2:7d:17ea with SMTP id s6-20020a170902ea0600b001a2007d17eamr19422704plg.56.1680004552026;
        Tue, 28 Mar 2023 04:55:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680004552; cv=none;
        d=google.com; s=arc-20160816;
        b=S83qQT9XZMuVs7dlBzNrtSn8JAwzKgAYWoJTkcEvFzVSuylC+U9F1ctpWC2kDb9GcZ
         CiLny0wkX04pycmC3TEHlTStK9L3jEJzV3mX5r/UnJwHxYWbpqzGqUwEetnizRELddC9
         AP2iIkoJoKilG+gGYK2IrJajIkPfj/8pMHDEDgpNG7Yl36Yx5aS7xazVwYLLOKAYRa25
         gOpKxb8RzVmuCmjDMksE4isMsyv6HuxYYkBSniVHJ3gjO392snnqRK7nXdbxNIQ0t9qL
         mQOYGEsxFxUylQ8GgQVyJVyIPZzDNJQ78zxRRjB5rjgtxOKIU6tzCTkzQc1bm5ACZjmC
         UOjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0RDSxhLBnZBh5cghIRz0nx4zak4on0GX/pcez2mBW0M=;
        b=e44jGqJ7pUaGmww//s3mqCxr4HLlflcZSnK6KunA8VLmimyvIWAheFzt9ivR+JCS5V
         NR1/VH/JSQDUPZ5qPhHQLW3UQXPDeP+SHdbyQl2cxN1KyAI7WaaTVwoXY/9UWOtT8xy7
         k2KusIwk7bTqbdDlxPW/8DIJevW6JcIuboGIh2JNY2G0YU3wfc8U8s3jLYuhaMtrBuZS
         55c4QbrgT/Jhb1gst6nB8lZyWX/MPeVGl6wjlVejGxgbDh8NYG8ztIsliqrfp2uuiDfD
         5etaPc0FPTVbaZPtYFciXd1DFf+HsZ5WYpBm0BsG1VIMFeZcXQ0yqJkjUtRyfzJW9Hh/
         L6bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KcnVfpk4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id e12-20020a170902b78c00b0018712ccd6e0si922338pls.2.2023.03.28.04.55.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 04:55:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id p15so14615988ybl.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 04:55:51 -0700 (PDT)
X-Received: by 2002:a25:add7:0:b0:871:fad3:b2ab with SMTP id
 d23-20020a25add7000000b00871fad3b2abmr13285046ybe.65.1680004551546; Tue, 28
 Mar 2023 04:55:51 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-2-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-2-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 13:55:14 +0200
Message-ID: <CANpmjNP+nLfMKLj-4L4wXBfQpO5N0Y6q_TEkxjM+Z0WXxPvVxg@mail.gmail.com>
Subject: Re: [PATCH 1/6] mm: kfence: simplify kfence pool initialization
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KcnVfpk4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Tue, 28 Mar 2023 at 11:58, Muchun Song <songmuchun@bytedance.com> wrote:
>
> There are three similar loops to initialize kfence pool, we could merge
> all of them into one loop to simplify the code and make code more
> efficient.
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 47 ++++++-----------------------------------------
>  1 file changed, 6 insertions(+), 41 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 7d01a2c76e80..de62a84d4830 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -539,35 +539,10 @@ static void rcu_guarded_free(struct rcu_head *h)
>  static unsigned long kfence_init_pool(void)
>  {
>         unsigned long addr = (unsigned long)__kfence_pool;
> -       struct page *pages;
>         int i;
>
>         if (!arch_kfence_init_pool())
>                 return addr;
> -
> -       pages = virt_to_page(__kfence_pool);
> -
> -       /*
> -        * Set up object pages: they must have PG_slab set, to avoid freeing
> -        * these as real pages.
> -        *
> -        * We also want to avoid inserting kfence_free() in the kfree()
> -        * fast-path in SLUB, and therefore need to ensure kfree() correctly
> -        * enters __slab_free() slow-path.
> -        */
> -       for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(nth_page(pages, i));
> -
> -               if (!i || (i % 2))
> -                       continue;
> -
> -               __folio_set_slab(slab_folio(slab));
> -#ifdef CONFIG_MEMCG
> -               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> -                                  MEMCG_DATA_OBJCGS;
> -#endif
> -       }
> -
>         /*
>          * Protect the first 2 pages. The first page is mostly unnecessary, and
>          * merely serves as an extended guard page. However, adding one
> @@ -581,8 +556,9 @@ static unsigned long kfence_init_pool(void)
>                 addr += PAGE_SIZE;
>         }
>
> -       for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +       for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
>                 struct kfence_metadata *meta = &kfence_metadata[i];
> +               struct slab *slab = page_slab(virt_to_page(addr));
>
>                 /* Initialize metadata. */
>                 INIT_LIST_HEAD(&meta->list);
> @@ -593,26 +569,15 @@ static unsigned long kfence_init_pool(void)
>
>                 /* Protect the right redzone. */
>                 if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> -                       goto reset_slab;
> -
> -               addr += 2 * PAGE_SIZE;
> -       }
> -
> -       return 0;
> -
> -reset_slab:
> -       for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(nth_page(pages, i));
> +                       return addr;
>
> -               if (!i || (i % 2))
> -                       continue;
> +               __folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
> -               slab->memcg_data = 0;
> +               slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
>  #endif
> -               __folio_clear_slab(slab_folio(slab));
>         }
>
> -       return addr;
> +       return 0;
>  }
>
>  static bool __init kfence_init_pool_early(void)
> --
> 2.11.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BnLfMKLj-4L4wXBfQpO5N0Y6q_TEkxjM%2BZ0WXxPvVxg%40mail.gmail.com.
