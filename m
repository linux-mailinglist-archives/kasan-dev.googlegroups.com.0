Return-Path: <kasan-dev+bncBDW2JDUY5AORBOGJUWKAMGQEDEFJTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F3F352FFBF
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 00:16:26 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id rj11-20020a17090b3e8b00b001df51eb1831sf9084464pjb.3
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 15:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653171384; cv=pass;
        d=google.com; s=arc-20160816;
        b=QZ+nKfjbcQkRA7UKmVZh4GWZblf9OcuqgZHmmamBzclsaBsg98MkyTcega88hOc+c+
         eYUGZZdqLi3ChZwT5qhTAVK9oe4g0EZFePdRPzgjtOwknVUGCJuiJPQK0AOx2wgdZCbF
         K12ZR7EmEYiQQXYNX1Bk3IjI6G3BZwdkpiJqL7rFMApzwTPpu7n+ll39hmosM1i9zlFj
         7wOV2JmxQCVQ9MWvv5ddBk7FPQKKYso/ouz7PtBTVumMYwIDbhDSxRelssTGcweuJnDm
         fEcOTQO2ptX5f6BepU82bjAXcut76UyDPwziV6DVKbgGeUUC/kPkMGnc4F2kl+agqJLQ
         mf0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=deJiMorol+MjzzDhEfgVO1RbhyUdaM3lmL5iwWyzY+w=;
        b=Bs4Sk7LCParySIvlmb0cTuEJ0+ShkYwJlaTAR6rieRogwP2oyp76Pdz+UKYZB897pi
         Q0wGLSOzCaKma59NRlFy8Fb/NwzaU2XQ4iOUKFVP04gtOLFb2f1YExI6Onq2bv4sjro5
         JvlfY4RvNJdJd7okK5R+XLDyNmNNw/2rimsTPgN5yCfNGSYxc1wiAICbZsWj8DHgFrHT
         0o70SLr316nLgtlitNm77FV1sNbQME5kNRdX6bQ0bIyGCvCQP/kAgmpN8gy3zwfDltT3
         7uCNpkS3cok6bOmno7YcL7mV/RABHHnM9WQj3/DuG4yD64dwaH3nH49kpoCrWP0zj23i
         CxPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=grKmiARW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deJiMorol+MjzzDhEfgVO1RbhyUdaM3lmL5iwWyzY+w=;
        b=NYsXrnJwoN0ewUh2jQp5xHpNiJ9aaM+OSjgxCfMG58NfR/fLmWjTufCuVibAT7t/f+
         /LqVYMJGn68PiGAOXSpxOCSwQR9A/JhAeeXTqCsZnz6t7ibR7eh7wo117xEwdvxCvWHp
         L8UHSVKEhiPQbj+ZdbsWmjxNfRzuOFbctKLcL4zkqrASxL9+geZxVm83qmzOo0orZg1X
         3lPr26H29OJX8yKb7s/ZDgMQowS3aIyeis9JsxosbTQ7Ir1NfJSujyiSpPqZb65YTblV
         3caIC9x2PANtPVItBEttSLzspt9j4V456lWZfZPRGwUtoZlI36+glDVZa4tugWsOgNCG
         e+8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deJiMorol+MjzzDhEfgVO1RbhyUdaM3lmL5iwWyzY+w=;
        b=HzeSXviuioHU6WcJVJ04N0ivSRloed1mdl6OglVz5M28nd/YZfWXv729rImpnGeNIf
         NVF8N2vZlzxVEV8A1eDsDt4Ek0P6r9NhNL+OEAfxr2+UNj4IMeq2zSJa0nMmA6RoMnMU
         BKdJPsqzpYHLS9AH+E+7knmHZgee/3AfSLNcCOULsuibiFZ9tK+Cu2bG1Hahs9dk8Wc7
         cooSB+uOIWyYD7IqlE6/5Y2vj0MMW2W59arTJnQFv3AEdAQ4YY2b2oEeQlgBKmAQj0CW
         +0CAH7/4AipuW6nv1e3XYthAsNYyvVzN4qORr8X4dzMvvV2eGLzSW3VgcIzIRRmqCGQL
         QIVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deJiMorol+MjzzDhEfgVO1RbhyUdaM3lmL5iwWyzY+w=;
        b=xvo1V7LOd1mO8YeRPP5btxoRIDvCkjxqexbfqDDjVcDEidexIltJUJdtxzVCqMh3Lg
         6GVE49etxTv9Sbd6PGuzdn7sPsbSwY7d8JxmaKQ2WdXe4m4cymCnCMYRXdC6fafnm1t/
         wZxfo7kEpHiNohDCa+TtlktNrNip2amstTwDrejBl4eeq91w/NWMZdvnU7wIGpKYwafy
         Fr2ubYDm3jXeYKRdT91T12bQSWlDjOxKbBSm2swQOsp/N1sQQuLj0nLEj6e8j9JNc3nS
         Q3KhtRo3/cCN7LyrPQsiOvGJa3OqFmwBvwCHPmIVf6C8nDo7WF/VJPyXh52i1fpIaTQm
         fU+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531neaVoc2M+lxccbI7Q0vC4SVbSX+0qq8kZQKWDNbjrS1PvMcvL
	LTb42PUfSaeMVUCqwZctEd8=
X-Google-Smtp-Source: ABdhPJzMqm0zuAkVa8Hj4Sdzh+XttYhPAcc02VZ5vnqVnXgb5uLHBY9BEomcRIfJq/xoBL7xET15rg==
X-Received: by 2002:a63:3d87:0:b0:3f6:1c54:b315 with SMTP id k129-20020a633d87000000b003f61c54b315mr14553906pga.432.1653171384345;
        Sat, 21 May 2022 15:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:31d8:0:b0:3f6:657b:78c8 with SMTP id x207-20020a6331d8000000b003f6657b78c8ls2389943pgx.11.gmail;
 Sat, 21 May 2022 15:16:23 -0700 (PDT)
X-Received: by 2002:a63:1e55:0:b0:3db:84c2:8b2c with SMTP id p21-20020a631e55000000b003db84c28b2cmr14163498pgm.546.1653171383649;
        Sat, 21 May 2022 15:16:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653171383; cv=none;
        d=google.com; s=arc-20160816;
        b=BH3jtDTrMRw3LRzCZ24xGEu7GzOVD4ftKq9hyU+Bw5PZnjRp+LcR6m4pngCAXzHvIi
         c/32h9qNWLFlZamnGucGsr6avQMJD1QxqisUJaa3kBkvIaspydl3Bm2VK5/pmIKcyAzR
         4dLvthBw1kQQcYQjmT3Gwjv1PFM67fdDfThRZKZpPYMg+6xv4iWTzs7zMdZtMHi246nd
         5W4mMSobbOLxRCr5+gS2+XZJaAK4t0MCYKjUYw+XA0ewpNgY26tyaSPrR47V0aLGXfy9
         lpgyYEbf3CmNyokHThfej1kFNCPj3Nn/7cQTMEBP59hOfSOCBUYzltvFdqoYSiZ9qD0e
         88Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qYdob3aQ7jNkxWqVlbfUqmdutai3OIv6tnI9DeVJxnw=;
        b=DRfj3H/PIvLWGV41gGPFBrMoEsWXEhP521rqnAzja065bXrwMndUP5Qqh/NGLygFOv
         KNjY16pKEWy2Gzsw0RTZgkPCH7GH+iK0kouOT7jkzRu4FJ141YidUQGZ6/SDW6BVePbF
         uu1G3YNPkoHGwnHxILIbks9FfMZRBv0CHYeS+2YekK8ZzpzRH6ojmWTDGvSpSU+n02Hf
         SFPImLgHYQ0VTLCiAcLzsNYwpZAHhAgTf2h0xbtTfAgSU7Ge9hDOCjU3mlTNuTnnxAvA
         EoQhLDKV1QXwkXq+Inmosp4DO2xzfyJppkG5M+RRIihVJkvHKiS9Ldg3d9Nz3mcVpVIm
         7lnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=grKmiARW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id s11-20020a17090302cb00b00156ad216c72si126787plk.8.2022.05.21.15.16.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 15:16:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id f4so12001261iov.2
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 15:16:23 -0700 (PDT)
X-Received: by 2002:a6b:3115:0:b0:660:d5f1:e3b6 with SMTP id
 j21-20020a6b3115000000b00660d5f1e3b6mr1815101ioa.99.1653171383147; Sat, 21
 May 2022 15:16:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com> <20220517180945.756303-4-catalin.marinas@arm.com>
In-Reply-To: <20220517180945.756303-4-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 May 2022 00:16:12 +0200
Message-ID: <CA+fCnZfFphBhHWu-xm0xinPMhuZUqGRz=SywF7N_RvwkcX1wOQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] arm64: kasan: Revert "arm64: mte: reset the page tag
 in page->flags"
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=grKmiARW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
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

On Tue, May 17, 2022 at 8:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> This reverts commit e5b8d9218951e59df986f627ec93569a0d22149b.
>
> On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
> kasan_unpoison_pages() sets a random tag and saves it in page->flags.
> page_to_virt() re-creates the correct tagged pointer.
>
> If such page is mapped in user-space with PROT_MTE, the architecture
> code will set the tag to 0 and a subsequent page_to_virt() dereference
> will fault. The reverted commit aimed to fix this by resetting the tag
> in page->flags so that it is 0xff (match-all, not faulting). However,
> setting the tags and flags can race with another CPU reading the flags
> (page_to_virt()) and barriers can't help:
>
> P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
>                                   Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
>                                   Rtags=0   // fault
>
> Since clearing the flags in the arch code doesn't help, revert the patch
> altogether. In addition, remove the page_kasan_tag_reset() call in
> tag_clear_highpage() since the core kasan code should take care of
> resetting the page tag.
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> ---
>  arch/arm64/kernel/hibernate.c | 5 -----
>  arch/arm64/kernel/mte.c       | 9 ---------
>  arch/arm64/mm/copypage.c      | 9 ---------
>  arch/arm64/mm/fault.c         | 1 -
>  arch/arm64/mm/mteswap.c       | 9 ---------
>  5 files changed, 33 deletions(-)
>
> diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
> index 6328308be272..7754ef328657 100644
> --- a/arch/arm64/kernel/hibernate.c
> +++ b/arch/arm64/kernel/hibernate.c
> @@ -300,11 +300,6 @@ static void swsusp_mte_restore_tags(void)
>                 unsigned long pfn = xa_state.xa_index;
>                 struct page *page = pfn_to_online_page(pfn);
>
> -               /*
> -                * It is not required to invoke page_kasan_tag_reset(page)
> -                * at this point since the tags stored in page->flags are
> -                * already restored.
> -                */
>                 mte_restore_page_tags(page_address(page), tags);
>
>                 mte_free_tag_storage(tags);
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 78b3e0f8e997..90994aca54f3 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -47,15 +47,6 @@ static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>         if (!pte_is_tagged)
>                 return;
>
> -       page_kasan_tag_reset(page);
> -       /*
> -        * We need smp_wmb() in between setting the flags and clearing the
> -        * tags because if another thread reads page->flags and builds a
> -        * tagged address out of it, there is an actual dependency to the
> -        * memory access, but on the current thread we do not guarantee that
> -        * the new page->flags are visible before the tags were updated.
> -        */
> -       smp_wmb();
>         mte_clear_page_tags(page_address(page));
>  }
>
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index b5447e53cd73..70a71f38b6a9 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,15 +23,6 @@ void copy_highpage(struct page *to, struct page *from)
>
>         if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>                 set_bit(PG_mte_tagged, &to->flags);
> -               page_kasan_tag_reset(to);
> -               /*
> -                * We need smp_wmb() in between setting the flags and clearing the
> -                * tags because if another thread reads page->flags and builds a
> -                * tagged address out of it, there is an actual dependency to the
> -                * memory access, but on the current thread we do not guarantee that
> -                * the new page->flags are visible before the tags were updated.
> -                */
> -               smp_wmb();
>                 mte_copy_page_tags(kto, kfrom);
>         }
>  }
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 77341b160aca..f2f21cd6d43f 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -926,6 +926,5 @@ struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
>  void tag_clear_highpage(struct page *page)
>  {
>         mte_zero_clear_page_tags(page_address(page));
> -       page_kasan_tag_reset(page);

This change is not a part of e5b8d9218951e59df986f627ec93569a0d22149b
revert. I think it should go into a separate commit.


>         set_bit(PG_mte_tagged, &page->flags);
>  }
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index a9e50e930484..4334dec93bd4 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,15 +53,6 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
>         if (!tags)
>                 return false;
>
> -       page_kasan_tag_reset(page);
> -       /*
> -        * We need smp_wmb() in between setting the flags and clearing the
> -        * tags because if another thread reads page->flags and builds a
> -        * tagged address out of it, there is an actual dependency to the
> -        * memory access, but on the current thread we do not guarantee that
> -        * the new page->flags are visible before the tags were updated.
> -        */
> -       smp_wmb();
>         mte_restore_page_tags(page_address(page), tags);
>
>         return true;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfFphBhHWu-xm0xinPMhuZUqGRz%3DSywF7N_RvwkcX1wOQ%40mail.gmail.com.
