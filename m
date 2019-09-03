Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZUAXLVQKGQERGC3QHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 30EFEA6C25
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 17:02:00 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id 34sf2062988uak.12
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 08:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522919; cv=pass;
        d=google.com; s=arc-20160816;
        b=hj5c6VjlM0D8n9Ija/400VFz4D2xrw/ADAHyWwodIrxIw5/GIW3NLNTX8B59Lb7YnV
         vQTP0VeA00/HvyqBvV2DzwV/iKqx8JTTHYGx4ks92R2DolgPRy6BKpfMbn/F63E0jhej
         US2pQCWxVafoGWwJ8vtOniT0+MwlmMR9VJerVuBRX4I2fgDnS3ISWWn/YFkFy4U4BBan
         X0LK0Om6NhJL0KMLYAr6cyMkPcgmXfpWcgHh9+MR5BX4GpY8PnyORqO/9lLRCewh9HQ9
         V9G56epAw6evxlDokRogNavCEkUlJC1dx9Dk1QPZfzDFm3nd9XZUeS4EL/O0uPDPhFNz
         5sTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+X3op+LY1wL8Zwp4PJ3ks8jDUDAi8Jjnf8T5r466uOM=;
        b=aRBqEltCMr+jOsu/xPyoFPxUtKEBPdD8PhSjc2quKIg009bBxQvMoHuRJ2rvq6dPaF
         L0NUshfiox89V/gPpwnuWrcTo9VYMI2sFyKDeC8dQpNGX43TPR6YyD872ZJvAWwYhxJO
         c9bAOTvIyk5naJKOxl3A/w0JUxnXhmSUSTuki2eAmw4bjaWX7ocl0mCVxMLTez9RhtFy
         fPiDQmDJJ3udGyfD326Aps4Oc9DVCUqD9O1uBbCNniik/p/xl908ij8K6wEQjAYu0oJg
         IhJpH5HzFXmixax8NVwzV6dWxDHxEXV/wpN6yBlRWkJyiKKbN9QKBWFCJfSgxMbRJeHJ
         XEZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKTgxbew;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+X3op+LY1wL8Zwp4PJ3ks8jDUDAi8Jjnf8T5r466uOM=;
        b=gTlgi+n0OgqlHooT2aljRAcdauae2vjHU16xdgFwfWvP7rJZQCiVDYCrVLMqtaq+jR
         STa6QMTX/dd6/I7MqYjuyaHN2wA6UQP/C2RLtH3M8uMQQ8eyjmAOYP8yzk8E0PxvWqjG
         0vlA5vWdpGXl4PzFqcqHC5x9poEWxXiEGPDqYhcYsVGCD+xXUHX9C7wa1iU4+6hrsRzB
         VoyVo2/rfk813cur99uBpr+3VKAylmkm3itoVo1Hc2cQNkJFLjW0O2w/WmUufQdbQUY/
         4BT1v80pZJjOdh26HFdafZE+md15WO+hB+PI8rsnKw6nO4BzXcugXNbmc18b5zDrIvmv
         xA6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+X3op+LY1wL8Zwp4PJ3ks8jDUDAi8Jjnf8T5r466uOM=;
        b=p69A96a26RQjMueFAkrZVSGVG9+NaJO3fubTV/iwkP5N+mfXnTaYD4Yc4YH8+bgCBi
         69CZuVa/h5lndLr/taSsAfQ6W+6YmP0oe9xwCLagEM4PwU+rQsrdYdvSmqAGzCzREwx3
         kXc77LvUL7SKmPnPltTkLAnsAqgUHkF9nLosQt37EqI9nGFhKXNg67ZuNqPHiLyD2gHa
         XJcDOf5L3OC/tfSY6VYrgGvbR1S5uff47PL4ZhXaxvFWBxyRnNRd5sMDEL9+JNE9k3/g
         QxEgMrOSW5x6tLjGdnKHaMApRFOcrP16wx+YRnlK/iERED2eLytPI7RZnjrqfV0lN8cN
         BEOA==
X-Gm-Message-State: APjAAAVN+keKMPBetH6ItSZftuAhOJZfNvAVf72UQ4ow+pL/vYfG/FLy
	zzoLREKvFYg/iDXb7MsOrVI=
X-Google-Smtp-Source: APXvYqxDhBhQaggE0aYL8NylED1QoaFoHjkqMIY9CeauvGWCoSU3X11m7S8JmXzBW8WrBdHUkyDuNA==
X-Received: by 2002:a67:ff07:: with SMTP id v7mr8677428vsp.227.1567522918844;
        Tue, 03 Sep 2019 08:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:380b:: with SMTP id p11ls869650uad.0.gmail; Tue, 03 Sep
 2019 08:01:58 -0700 (PDT)
X-Received: by 2002:ab0:6790:: with SMTP id v16mr16135324uar.5.1567522918531;
        Tue, 03 Sep 2019 08:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522918; cv=none;
        d=google.com; s=arc-20160816;
        b=ccoQ/EXyZytoEjAIlwzW12e38ye8DzkUZbfsENNIZdwiH+GwcygaXnsOsnI3dAOvca
         tJ4oeAlhM3u+ctBZsC1Us3rf3qxx1LpXOvU3yVbEXW6svuaEqc1CgcEVTr46Ssvo5UTT
         rkKq/J8C6bOlQqz7RM59mXgto1iNk2/90rv4dXXOOjbkyao9oifAk5ouAh2o3sjdsIdM
         I5FkqMKfjH9MMvhVnFee4r15pQxorbkiwZJkn/QyBV/Ao7u2r/CdRfjtSfUg82CE+Psw
         osm/nW5zC5V5rdGGfQyHe/ifFmJiWc1/iluiwkMzRfKLfDrh/kWhuzq6oacLMZZCgWwe
         WMbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a2fhN1NcP29VAX6Q4kuHnoYPTW0IlOqHifPZstOm4mo=;
        b=YyNLWosq0B+eDYfv9yUXQ89L5oXyrzIb+4L/3c6PsiVNYiafaONv6TxjvkDzycZxM+
         LUegLiGP0uhT3OoxTzzV7BqS1YJKAqOV5e6kXzjBv/CkOqCP+In3/hDAfd5u5jnioAik
         lMAztAs3uieZTNHIcdK2aOjALCvbatuddYjcHMqfnHq2P+luyU4HbTnzmgtFaFUT/1yM
         zNFoviNmIqCtnUtDL14f9+tHeiBU37BvPU5BoL66H+W/CaNiR6z2P/DmDmACA3R8+7pC
         Z8orPfmBmmIhLBIvSOdKvoN3xN5RJ3uBZ+hTEFTDxd17iNcDY2f8UBocQrh/E6ND0Z4C
         ygKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKTgxbew;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id v22si746843vsm.0.2019.09.03.08.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 08:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id u72so5109336pgb.10
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 08:01:58 -0700 (PDT)
X-Received: by 2002:a63:3006:: with SMTP id w6mr30960993pgw.440.1567522917541;
 Tue, 03 Sep 2019 08:01:57 -0700 (PDT)
MIME-Version: 1.0
References: <20190903145536.3390-1-dja@axtens.net> <20190903145536.3390-6-dja@axtens.net>
In-Reply-To: <20190903145536.3390-6-dja@axtens.net>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Sep 2019 17:01:46 +0200
Message-ID: <CAAeHK+w_HKVh___E0j3hctt_efSPR3PwKuO5XNpf=w5obfYSSA@mail.gmail.com>
Subject: Re: [PATCH v7 5/5] kasan debug: track pages allocated for vmalloc shadow
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, PowerPC <linuxppc-dev@lists.ozlabs.org>, 
	gor@linux.ibm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jKTgxbew;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Sep 3, 2019 at 4:56 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Provide the current number of vmalloc shadow pages in
> /sys/kernel/debug/kasan_vmalloc/shadow_pages.

Maybe it makes sense to put this into /sys/kernel/debug/kasan/
(without _vmalloc) and name e.g. vmalloc_shadow_pages? In case we want
to expose more generic KASAN debugging info later.

>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> ---
>
> Merging this is probably overkill, but I leave it to the discretion
> of the broader community.
>
> On v4 (no dynamic freeing), I saw the following approximate figures
> on my test VM:
>
>  - fresh boot: 720
>  - after test_vmalloc: ~14000
>
> With v5 (lazy dynamic freeing):
>
>  - boot: ~490-500
>  - running modprobe test_vmalloc pushes the figures up to sometimes
>     as high as ~14000, but they drop down to ~560 after the test ends.
>     I'm not sure where the extra sixty pages are from, but running the
>     test repeately doesn't cause the number to keep growing, so I don't
>     think we're leaking.
>  - with vmap_stack, spawning tasks pushes the figure up to ~4200, then
>     some clearing kicks in and drops it down to previous levels again.
> ---
>  mm/kasan/common.c | 26 ++++++++++++++++++++++++++
>  1 file changed, 26 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index e33cbab83309..e40854512417 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -35,6 +35,7 @@
>  #include <linux/vmalloc.h>
>  #include <linux/bug.h>
>  #include <linux/uaccess.h>
> +#include <linux/debugfs.h>
>
>  #include <asm/tlbflush.h>
>
> @@ -750,6 +751,8 @@ core_initcall(kasan_memhotplug_init);
>  #endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
> +static u64 vmalloc_shadow_pages;
> +
>  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>                                       void *unused)
>  {
> @@ -776,6 +779,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>         if (likely(pte_none(*ptep))) {
>                 set_pte_at(&init_mm, addr, ptep, pte);
>                 page = 0;
> +               vmalloc_shadow_pages++;
>         }
>         spin_unlock(&init_mm.page_table_lock);
>         if (page)
> @@ -829,6 +833,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>         if (likely(!pte_none(*ptep))) {
>                 pte_clear(&init_mm, addr, ptep);
>                 free_page(page);
> +               vmalloc_shadow_pages--;
>         }
>         spin_unlock(&init_mm.page_table_lock);
>
> @@ -947,4 +952,25 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>                                        (unsigned long)shadow_end);
>         }
>  }
> +
> +static __init int kasan_init_vmalloc_debugfs(void)
> +{
> +       struct dentry *root, *count;
> +
> +       root = debugfs_create_dir("kasan_vmalloc", NULL);
> +       if (IS_ERR(root)) {
> +               if (PTR_ERR(root) == -ENODEV)
> +                       return 0;
> +               return PTR_ERR(root);
> +       }
> +
> +       count = debugfs_create_u64("shadow_pages", 0444, root,
> +                                  &vmalloc_shadow_pages);
> +
> +       if (IS_ERR(count))
> +               return PTR_ERR(root);
> +
> +       return 0;
> +}
> +late_initcall(kasan_init_vmalloc_debugfs);
>  #endif
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-6-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw_HKVh___E0j3hctt_efSPR3PwKuO5XNpf%3Dw5obfYSSA%40mail.gmail.com.
