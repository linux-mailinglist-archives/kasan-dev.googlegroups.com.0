Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4S56LQMGQEX3AJKNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 461F6596085
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 18:43:25 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id m19-20020a05620a24d300b006bb85a44e96sf354452qkn.23
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 09:43:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660668204; cv=pass;
        d=google.com; s=arc-20160816;
        b=g64wGg/CCw2BfUBTbJEEmpmNbzozwbKktRYgXFa00ZVitZW3TDx8ww4if+AyGaJCt1
         +kXcqBN9s6ZaYuHQd9TrQGg0odFvBMExVkovQXIB72wO+B8C6ukCUpDKwmu06jfo+C3/
         RthIvytcw1MUkk27frUx4Tm9sK4uLGEMmPXyPt0upf0ut3EFnUWquId9bToyI2F4tfdN
         z4P/SDKgogJnd3GWWpUU9mfGPYlQcxLmncm6tRF/mlgnsHAlLflBMjXi6UxwdmNJ0av+
         0Xl4TWemkVxSrs33SC0+eSuSsYnCZewpz5ISKvi80DXIe6CLTy0GRAYkiHpbWWQgGbLz
         Qo4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=njG/lsmzhSrVN6Vf90T6si44A6OPe4/Ycfmhblfdtyo=;
        b=wbwrVwszhXDQQFEaAXY6hHzX/mMU4e9MXhcnAo/fbJ0/aVxWJ8J4foRU3o1Dmz7HJX
         OEEPTeHWdqd6KALJCAxE4Ir4DAFHifJzkKtUX30ywdxkNObHzJ+TxYNa32yhI3D6gOtL
         vK993262VXqzbLSBlWvtEVOhk2/c0SLlYu2x5x5Gvgat+wRRrpIUHZjlwCcedr9WMd/c
         SrBIGaZ90I10E9iz3Oyo1bj5LpG1lvZ4+MdQQXN/+ElB8XCMKb8uoSFCOC6hjHhxh3cG
         BMKZ/E1FumXiaOtJ9nAwcEOJ0/9Lq34aLUh8Yfx8jKWviKoqgLA7jXMPPSf39VvzaXbF
         KCcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MTj13ZQO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=njG/lsmzhSrVN6Vf90T6si44A6OPe4/Ycfmhblfdtyo=;
        b=pwBCcZiHB+j05CqZrq38IvjVh0ClZRE6a6R12iLzNmpPPUMzEqfB+9Z9i8/TdkAZGB
         cAdSgPOpg+Ta+nwqK725fybp2mJ+hq9ta97gFoQacOCZnnJ3898FcCB9lv5J2PeTIExS
         M5yBdkCzVvzdtl1gjfJ1xijuqv2anIEqHw8AWGDlg/YvgHCsb4vUObXN3z49PSO3x5g+
         zjl/k0tMIna+Ac4aIFuhPcxvynOiI0IEMKoRMbI9oYe6IJgvX1yE3XyqdvkbcXU+UNTC
         TWU9rx0ObZEmISd40S9VCXcNM4QFkgRlItwBYB/SuoLLqbNLyxmVlbSTE9yGZ1twQNDT
         hanw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=njG/lsmzhSrVN6Vf90T6si44A6OPe4/Ycfmhblfdtyo=;
        b=qqfFjDG/hhZfyma7YakbjsDs6so7ae9Y21wp6uHgMrIBKNymNRAUSppKkimkXA1RFk
         Z/eq3oW3guwlxZz1ihxDWhyBZzmGTh5sJiPPPbenB0j83RzunrFOMJomVje6aSHjF4X9
         RN/fY2+eW3dA8hQgCO5LK6EpjhLzv2ke7/QHtqmdzAK4j0VFx0Bchdny9LqwOLgX640w
         7QC1yCCreWDkFNKYmOpUSgl5HTqYIksCk119K2BYIk1/FEPZthxra0OnhDJKe1hF5VOC
         8f57s9YJLSlnj25QGm98QXOnCez5EY9yKR7XOsJXGJZuBIthrZkpr+UIz2hWR9rGFeCc
         NRXA==
X-Gm-Message-State: ACgBeo07Vr7Kn582LOTefdtD7F7VAvdi7umnwSAF979g1FsjNLZF6+Wg
	aHRXGYQjkx/3JEnc8R5DEOk=
X-Google-Smtp-Source: AA6agR7tJ1mmP1IbIZHGm0dDlw+tOYyLD9HPuYkGWuNRnYtLV9VbKLN2nC6SK3TthwuN5BrG2kMgyg==
X-Received: by 2002:ac8:5cc2:0:b0:344:50c9:5308 with SMTP id s2-20020ac85cc2000000b0034450c95308mr13293411qta.602.1660668203987;
        Tue, 16 Aug 2022 09:43:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4204:b0:342:fcdc:2d4d with SMTP id
 cp4-20020a05622a420400b00342fcdc2d4dls9819419qtb.10.-pod-prod-gmail; Tue, 16
 Aug 2022 09:43:23 -0700 (PDT)
X-Received: by 2002:a05:622a:5d3:b0:344:6be6:82c8 with SMTP id d19-20020a05622a05d300b003446be682c8mr5819267qtb.115.1660668203352;
        Tue, 16 Aug 2022 09:43:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660668203; cv=none;
        d=google.com; s=arc-20160816;
        b=xiRMY6f7vZgsYMxT6bm0SrmvCinaWZo2v07tVUBPaffCC2dLfB950EyNKTq2lc2oeO
         ACdCSLNY4i/ToDXVGs5A05mAOwnUtdfoYiTOoR6vfk5P1mDnqRcjz3WFUYuEa0IwiRE7
         J9CMAXugtqgu9cRYEM8Yb1eO4p1Wt2TIHOYLfykaYDJUFUh0ajlSWyvlfbIoxa0euFYo
         nOLAKhh1krXdOxfer5o5ZAzSlSKc+464kQRJCJxcU2zjdjJ4Og8gM9lIcTD+MnHWVDub
         8QlGTlOEioYhFjlsM7p25I4BGap9Mb+cHe/hJUEO+kT3Q4VYWIgZHDv4deOr/SsegDKZ
         y5gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FOpQGOCCCOeHXcTTEf2Jf8cH6crBmZD9kljFNdM3FZI=;
        b=xiL+KHFKB51mykWYclaa142H4PTPjcTOsdNL4xO3lBRB9z2hhofDIeW/r2GcnPgSkp
         oqOASFvEg3yl5jLEHDecPRFzQnyh5Ow+TavezuJuM3lDTQ/qgkW1Gn5j1jHYkflFQYxw
         8y48y/aQ/WbfBB8hoAcEc7cNuNJqRdK0jkCF3G5brqKxCgV2qI2I+FzGPwcbPgG8Wdfu
         R25/HQklzTNrAoNDaROw6Ojpnd7xmPd5YBz2O69CVbeACwhauiyRg5lPqT1Vjymg9s5V
         hXPq1neLGf2Azg89XnF37DRwpQ/XJC3WXEHI3qKwxd6kbCfghzuJyufMwPtsCOzcWe3p
         Fjgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MTj13ZQO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id z6-20020ac87ca6000000b00343082fe19asi604084qtv.3.2022.08.16.09.43.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 09:43:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-32868f43dd6so166229507b3.8
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 09:43:23 -0700 (PDT)
X-Received: by 2002:a81:500a:0:b0:333:9bcd:8a41 with SMTP id
 e10-20020a81500a000000b003339bcd8a41mr2849801ywb.4.1660668202873; Tue, 16 Aug
 2022 09:43:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220816163641.2359996-1-elver@google.com>
In-Reply-To: <20220816163641.2359996-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Aug 2022 18:42:46 +0200
Message-ID: <CANpmjNP0TMenugBVCqCYLT4AGCTH80RafcmgQRN7X8SzGjoQ6g@mail.gmail.com>
Subject: Re: [PATCH 5.19.y] Revert "mm: kfence: apply kmemleak_ignore_phys on
 early allocated pool"
To: elver@google.com, stable@vger.kernel.org, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediatek.com>, 
	Max Schulze <max.schulze@online.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MTj13ZQO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as
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

On Tue, 16 Aug 2022 at 18:37, Marco Elver <elver@google.com> wrote:
>
> This reverts commit 07313a2b29ed1079eaa7722624544b97b3ead84b.
>
> Commit 0c24e061196c21d5 ("mm: kmemleak: add rbtree and store physical
> address for objects allocated with PA") is not yet in 5.19 (but appears
> in 6.0). Without 0c24e061196c21d5, kmemleak still stores phys objects
> and non-phys objects in the same tree, and ignoring (instead of freeing)
> will cause insertions into the kmemleak object tree by the slab
> post-alloc hook to conflict with the pool object (see comment).
>
> Reports such as the following would appear on boot, and effectively
> disable kmemleak:
>
>  | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
>  | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
>  | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
>  | Call trace:
>  |  dump_backtrace.part.0+0x1dc/0x1ec
>  |  show_stack+0x24/0x80
>  |  dump_stack_lvl+0x8c/0xb8
>  |  dump_stack+0x1c/0x38
>  |  create_object.isra.0+0x490/0x4b0
>  |  kmemleak_alloc+0x3c/0x50
>  |  kmem_cache_alloc+0x2f8/0x450
>  |  __proc_create+0x18c/0x400
>  |  proc_create_reg+0x54/0xd0
>  |  proc_create_seq_private+0x94/0x120
>  |  init_mm_internals+0x1d8/0x248
>  |  kernel_init_freeable+0x188/0x388
>  |  kernel_init+0x30/0x150
>  |  ret_from_fork+0x10/0x20
>  | kmemleak: Kernel memory leak detector disabled
>  | kmemleak: Object 0xffffff806e24d000 (size 2097152):
>  | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
>  | kmemleak:   min_count = -1
>  | kmemleak:   count = 0
>  | kmemleak:   flags = 0x5
>  | kmemleak:   checksum = 0
>  | kmemleak:   backtrace:
>  |      kmemleak_alloc_phys+0x94/0xb0
>  |      memblock_alloc_range_nid+0x1c0/0x20c
>  |      memblock_alloc_internal+0x88/0x100
>  |      memblock_alloc_try_nid+0x148/0x1ac
>  |      kfence_alloc_pool+0x44/0x6c
>  |      mm_init+0x28/0x98
>  |      start_kernel+0x178/0x3e8
>  |      __primary_switched+0xc4/0xcc
>
> Reported-by: Max Schulze <max.schulze@online.de>
> Signed-off-by: Marco Elver <elver@google.com>

The discussion is:

Link: https://lore.kernel.org/all/b33b33bc-2d06-1bcd-2df7-43678962b728@online.de/

> ---
>  mm/kfence/core.c | 18 +++++++++---------
>  1 file changed, 9 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 6aff49f6b79e..4b5e5a3d3a63 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -603,6 +603,14 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> +       /*
> +        * The pool is live and will never be deallocated from this point on.
> +        * Remove the pool object from the kmemleak object tree, as it would
> +        * otherwise overlap with allocations returned by kfence_alloc(), which
> +        * are registered with kmemleak through the slab post-alloc hook.
> +        */
> +       kmemleak_free(__kfence_pool);
> +
>         return 0;
>  }
>
> @@ -615,16 +623,8 @@ static bool __init kfence_init_pool_early(void)
>
>         addr = kfence_init_pool();
>
> -       if (!addr) {
> -               /*
> -                * The pool is live and will never be deallocated from this point on.
> -                * Ignore the pool object from the kmemleak phys object tree, as it would
> -                * otherwise overlap with allocations returned by kfence_alloc(), which
> -                * are registered with kmemleak through the slab post-alloc hook.
> -                */
> -               kmemleak_ignore_phys(__pa(__kfence_pool));
> +       if (!addr)
>                 return true;
> -       }
>
>         /*
>          * Only release unprotected pages, and do not try to go back and change
> --
> 2.37.1.595.g718a3a8f04-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP0TMenugBVCqCYLT4AGCTH80RafcmgQRN7X8SzGjoQ6g%40mail.gmail.com.
