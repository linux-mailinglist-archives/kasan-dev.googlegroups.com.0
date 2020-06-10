Return-Path: <kasan-dev+bncBCMIZB7QWENRBN7LQH3QKGQEVN5TUMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B04ED1F4D55
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 07:55:04 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id d23sf618762ooh.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 22:55:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591768503; cv=pass;
        d=google.com; s=arc-20160816;
        b=muP3IQLpkjYSSNVNDdKT4S+IYnvZR4bi/zbTbQ/C8JKUwx9TxYmh9Q71r/VKlrpzAQ
         5wFQD6/yNIrEnB1KDOmi79NlR/x6pPzJYlXnVG7zF/msSlWCnm5L+gjSfi9LRx8Mp3j/
         9QhqOZ6ScaC5eAIaHzxsfH0vdZmCMhd7SWQ3ahx77sTsABplpXXwHzb72bZFttCePPPh
         XnFtvt++JvcZOOSW+P2zwvoYQYJ1fYzQWBsAzKI0MTvVTwrpbUzQf0PxA2DXskdQtNvq
         9fbX5a225T8r+Jzsy6n6PxXkYwCeFM9vhjtXpKWLhzKqeoc49XyjnwfsqdyvI4lHdnfx
         pf+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aHGlvuvKP0yxcEaJyn8g5gwhlNhMIQ+4KccuOdMBGXQ=;
        b=xSCqCTH8qJKC3I1/Z8foMEaK7Ge65kC/dLE4ODCwkbBZpw00sk2eIvjb0pSOQc8XMt
         vHd2DqFZ/7mGgKpcvV292XC0opN2CSeWkgqWNHLAWHTcnyjelMpTHTRcAGT6jNLw0VjU
         dgwJo1oYjRmD9e7PUXRcr4QAMKhwq0+i7i77oie7+BwDPBlObvjr8uyD9XXe+PbHzegW
         uXx8PQ7AEsaTSI8Ax6nIJ4dKlktJqlzscsimYM4uBXWtOdIujSHkLoUGjln5Q4pSmblA
         CQy5dMKPhU6gXebj7agmxjs1PwKETZm5zZDuIPWwD/6r4FXnD8tzZx/KhjtOkUPD9/x/
         vYWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iAqAoTvA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aHGlvuvKP0yxcEaJyn8g5gwhlNhMIQ+4KccuOdMBGXQ=;
        b=dXmCdd92IUoL6KeXGYqmRVqR8U7WJs7iY3qrPTpwMPFc4FGQrTmrtuxweNpDOodHIi
         eia5+B77z140E0YwvJjI5oWSkuvvtOrypZGKXSvFv9RHUxiGH4TjGolArKI2f2Id1qPD
         l5aC+26RkkCbe2SHh/TWjaHzlGsx4KQpPspz97qC4b86OhEYpBzZwtzGrK1s+j+07RBq
         NGrvyqViknrjioqzJKKqVCt3aGoGuaBs0zuloYYiTdK9hpH/k0HRnmIRk4t2aX200iw2
         ydNxq9r9XNad4IXxnAsRutoDBriStplCVBvPmK9teCN3dHRoCQHbZKlUtiOJl5jbsRXE
         QqvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aHGlvuvKP0yxcEaJyn8g5gwhlNhMIQ+4KccuOdMBGXQ=;
        b=Tx5FYS1L+B5MgQSeeo5AF4x0dHVOOKlF4OwPtGDV/IULgW6Kk5Kv6zGWxgZniFHSrf
         EYR9dyOJjITO0RfJPGGh7fyHpb+iDC/au2G0WMh83TDSkk9SO05IPDXJuyiUUYJZ6bfh
         YCEAc8RI9rHI1Oi/k2NTMQaNIbSnZfJYYwkXw1KMoT4u45ow6n52XkDPwY+6tYpo0qy9
         +m4RrI5IWk8Sqzh2u7FunPqoCg65+j4MOKOVg2mtHFgXAXwO9qyNVmY+cEEdLzmHTQjn
         G3fAFwh9y5LvR9GF1mdlwZYdny43I2aujfUG891wlVdidrasmHFXiCc0xgzbgXQpNdHB
         Pxjw==
X-Gm-Message-State: AOAM533toLodWsKrfKd91nLHn7AQjrk5RXXpwvjGwAItzEFisql3msmk
	7cMyd3eLHqt4/67KKo7FXH0=
X-Google-Smtp-Source: ABdhPJwNFNr677XEzKXMOY3yE5rPWPgIHYB3pjp2lmX8ue9ClRKmKd+JhyclVmQi9l0+jTlZkcGXYw==
X-Received: by 2002:aca:cf58:: with SMTP id f85mr1306256oig.50.1591768503460;
        Tue, 09 Jun 2020 22:55:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1db7:: with SMTP id z23ls3592636oti.9.gmail; Tue,
 09 Jun 2020 22:55:03 -0700 (PDT)
X-Received: by 2002:a9d:6958:: with SMTP id p24mr1462220oto.17.1591768502760;
        Tue, 09 Jun 2020 22:55:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591768502; cv=none;
        d=google.com; s=arc-20160816;
        b=znA9Q5peRNtQyQ3yFqQxA5Lk5E1MH25hP0G5aNuMLypV2AocT2RpKMLJTQlJJ/Z3Me
         snRu86wui4GkGlWIwHPWv0Es3n/JQp7sjLcCwHfTnnO6j5+uUA7RUox0KeeqFpA+5IZ2
         PHf7pKfwpX5IpQSYZKwmmT80eF5pbsHg5mgKjykCTeYv98dc26L8Ij0JrFh/lOb88se3
         07hFN1AbvTxsiKWeJY+ygh3hbnBsx+t9g+SO2Ul4g/CdvoF2YBs0NRXgufTNBfK6pnyx
         HROvyqerM6AsuPWs4DlYZqSeHtc0GtUY+JRFB+QzQE1+4xmgCh88A8YXCSyJ9r/gCSB2
         UWmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gXeXhMtb00GflCcome0aHfH/SxNK2VTYdZLVXM019as=;
        b=OTwAJhCCy/UdrB0a0zqw1vAkmdTVZrp/SYeYiGIFzs1Ap6eGCbilFDbvlsZN8yXtZE
         MVremsIpvmuTMx90AamdBJx8uUDN9JwvtTaHNKAA1k6OBTd9ewmq/m17A8ugK0ub/E6W
         4dvAUku9OF03FPWH3ZCYMaKDCRyT8FR+Thjc5/vRoRAHsH7vUn2QqU+e10L5IRcIXtIW
         /ZopZAxGpodRnCTYzQ7ePX3gqzjGIMhMV1iFpdwYkOrKAyc4abmHsb9s4ofyTXeGA3Yo
         /wv1/CxllDNJEZDU+Lh81tpzN3zSq70OEWIvTK5NWklCiLUgIBUS9s4bAPpJmSPb9wDM
         t6Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iAqAoTvA;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id o199si933833ooo.0.2020.06.09.22.55.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 22:55:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id z1so895274qtn.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 22:55:02 -0700 (PDT)
X-Received: by 2002:ac8:260b:: with SMTP id u11mr1541245qtu.380.1591768501932;
 Tue, 09 Jun 2020 22:55:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200610052154.5180-1-cai@lca.pw>
In-Reply-To: <20200610052154.5180-1-cai@lca.pw>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Jun 2020 07:54:50 +0200
Message-ID: <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Christian Borntraeger <borntraeger@de.ibm.com>, Alexander Potapenko <glider@google.com>, 
	Kees Cook <keescook@chromium.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-s390 <linux-s390@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iAqAoTvA;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Wed, Jun 10, 2020 at 7:22 AM Qian Cai <cai@lca.pw> wrote:
>
> kernel_init_free_pages() will use memset() on s390 to clear all pages
> from kmalloc_order() which will override KASAN redzones because a
> redzone was setup from the end of the allocation size to the end of the
> last page. Silence it by not reporting it there. An example of the
> report is,

Interesting. The reason why we did not hit it on x86_64 is because
clear_page is implemented in asm (arch/x86/lib/clear_page_64.S) and
thus is not instrumented. Arm64 probably does the same. However, on
s390 clear_page is defined to memset.
clear_[high]page are pretty extensively used in the kernel.
We can either do this, or make clear_page non instrumented on s390 as
well to match the existing implicit assumption. The benefit of the
current approach is that we can find some real use-after-free's and
maybe out-of-bounds on clear_page. The downside is that we may need
more of these annotations. Thoughts?

>  BUG: KASAN: slab-out-of-bounds in __free_pages_ok
>  Write of size 4096 at addr 000000014beaa000
>  Call Trace:
>  show_stack+0x152/0x210
>  dump_stack+0x1f8/0x248
>  print_address_description.isra.13+0x5e/0x4d0
>  kasan_report+0x130/0x178
>  check_memory_region+0x190/0x218
>  memset+0x34/0x60
>  __free_pages_ok+0x894/0x12f0
>  kfree+0x4f2/0x5e0
>  unpack_to_rootfs+0x60e/0x650
>  populate_rootfs+0x56/0x358
>  do_one_initcall+0x1f4/0xa20
>  kernel_init_freeable+0x758/0x7e8
>  kernel_init+0x1c/0x170
>  ret_from_fork+0x24/0x28
>  Memory state around the buggy address:
>  000000014bea9f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  000000014bea9f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >000000014beaa000: 03 fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>                     ^
>  000000014beaa080: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>  000000014beaa100: fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>
> Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>  mm/page_alloc.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 727751219003..9954973f89a3 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1164,8 +1164,11 @@ static void kernel_init_free_pages(struct page *page, int numpages)
>  {
>         int i;
>
> +       /* s390's use of memset() could override KASAN redzones. */
> +       kasan_disable_current();
>         for (i = 0; i < numpages; i++)
>                 clear_highpage(page + i);
> +       kasan_enable_current();
>  }
>
>  static __always_inline bool free_pages_prepare(struct page *page,
> --
> 2.21.0 (Apple Git-122.2)
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZe%3DcddKcU_bYf4L%3DGaHuJRUjY%3DAdFFpM7aKy2%2BaZrmyQ%40mail.gmail.com.
