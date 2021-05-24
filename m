Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXUVWCQMGQEQBFRIXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 96B4E38E3A2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 12:04:31 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id w11-20020a4ad02b0000b029023970099d97sf2620228oor.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 03:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621850670; cv=pass;
        d=google.com; s=arc-20160816;
        b=b6RhX/CKLnYDGSDcOdwIn7RDKLfhSFidFmweo1O28N14TH0/utSv1ZVMhqLSb6IdR0
         LsTmP/6ApP4Ri42JgifmJfJ5Kd48GQ7XG+w8kpOOaHz3Pb1M8DadaRs6ZHLtxpGIhDvg
         RsOQspUdrxLkrZhGM1iFBlqCUkKNv63UULGJSuW9hPSpymYhswx6+Mj+CAgbn24EW4A6
         cWKUg09/tMlK3ztPUJErF2s0YKerooZQU08dqVuNPQryTkMXcB70rq2D91P1Q6KBRQ6a
         nWURCeTbzqnP8oBlbidgmgdiqMro3wRsNrxzKd0jIZomPbm24xLmYQujIsfb/LycWPXT
         vOcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G3Rp2GM8i7qQAtDci/uyKW/hb6ufDr9O7HJJqRsJtyo=;
        b=b3y68MoT+YrbHQvHwFqvHq/Srzqhzet7Z9MdGm49Ui1F/v940q8wydnlgTR9T9cDCz
         BQJ7uh3X/R7yEvk1g0qXvqAGKgFncUI2blnklSmW5kCW6UzO9aJIaxhLVZI+U3wVgcR2
         w0AZERxg6v6/V6gvn/Fuf0aSrf3e2d98azgjKznWoVHfsqBsOlZTPGawx+1jW+8dr5o2
         zroJlUhrcz2QtSTZrCOjkH0O9nfuUSnwSuPHtwA/NsENdGXokIqusBOLERzZbcTwqCvt
         IPGaUxuB64SOenO+0UknXupJTn2zsWHzxzqKiD1OUn/mfs47r4NFlWILWyi9SQecH6Ph
         UuxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rQkzdS5d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3Rp2GM8i7qQAtDci/uyKW/hb6ufDr9O7HJJqRsJtyo=;
        b=VGRv3VFuJWHeERO8HNiMBwx+kJS0ph52ZxIkA5bxsVGjcJ6UPPBTZKeKUWQ3Rfybb5
         3fexqfQL8cUdGOlEgdVg9SgXuLlnspfVrwxiJtPHxFyIVWFx6aAWj1Hwgy+SUDS6EW2u
         MhAhWe8K7wzOlPHWpBA/EEyueWOxmQx8HP6ICU0gefDGkGeC6TJha41GONJmfbS1+m8R
         VlFOItzq+gWjjJHEG2P8IsbBMfwnEGLv3TTiSFlacKgClqrVRzh5ZIYP4auhC/xWMSTD
         ivBG2h7aRGr5hd2P7bsGXEOMxa5TLTmiRMKFGyfgWyX8tVGxshd0vvCA6XLtMx+0G7Sd
         CaeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3Rp2GM8i7qQAtDci/uyKW/hb6ufDr9O7HJJqRsJtyo=;
        b=gX2X8ypy746rH+2+5UxrqUtqLuIv4pbTpKRSHP1D0posvrXketK1Je3fJNMbzMrSPS
         xCY3xpAHpYAP+AmIrCxSjUgKiyRRJmhyJsi4fLVT3t9gbyb/khnarEd4wS0hJVHYY7ys
         pCcqNs9hVbqHcNl/84x742/mkAE/vbB4FTGLfGmam0UKTEuFtcUrjO1t9jOe00LKngMj
         PUC4iXfqgYikzSDQXCajusu1xP0tO8zM2pKBV4bFIlLju/oqQbbmPPsUZ72so+mJPA3G
         /YUUTPGZcPt50QjCQIFuMx+Y+H4hmbY9M1ANc8UDlqq8WxLe6cqT9KaYl8vyOSGb74td
         dRCQ==
X-Gm-Message-State: AOAM531tAyNA+j5Mmc9J11nszN8acmhSp0glIy3ID0edlFBRZBH9FuT+
	hOQ9cK43gpSO/O8xf3LM4D8=
X-Google-Smtp-Source: ABdhPJxMrhznSflfU+D57m5tdlUd1R0QKNCkRszDzA3qDtCtpuvh1JLhSdcLZHeFbP7+TG39cb+C8Q==
X-Received: by 2002:aca:c3cb:: with SMTP id t194mr10263411oif.165.1621850670329;
        Mon, 24 May 2021 03:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7858:: with SMTP id c24ls4099877otm.6.gmail; Mon, 24 May
 2021 03:04:30 -0700 (PDT)
X-Received: by 2002:a9d:6145:: with SMTP id c5mr18384141otk.58.1621850669950;
        Mon, 24 May 2021 03:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621850669; cv=none;
        d=google.com; s=arc-20160816;
        b=s5/rHEDfgcDKl1oEK+abbzCiQpzgPANIh/G9nStaytnWo8vH65Oy6XGkTZNO9hZjKe
         einNA1i7I5Ko9x0kLEIAcuOXvtrtX+2stFS5pZq19Db6ZOlPhCXhdp7FsSQTucbSqvuo
         lxK09DwmprnbssrpILgMO1GxLFO2zgBP1JZ5iWcvN/qGacflpd6LvumvP2azxsP4AM+K
         yNSDB+kqIT/OJZRJ0r1SZIeXbpYfqfrY6COS4wlypta6lfBxkNammVWRBkMGfns63uJ6
         ogcLLEHZU0I5VZGY73LH5P/Nrvd8TSJdgVMtPNFEPN0nKBosUuO57YN0jszzhNPnPvsO
         C4BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5LIVDxSTAx+v+3BlB7H3HwH9zYuBEuDEtS9LHuHrcO4=;
        b=m+z2dXoDgG9JJdam9gqjxL56FaZSWNSP3Yiw9zLJTE/QxRRlZDotvAL/atdSaIP8sV
         v8yzK4rmjMCHSpiC5Rq/BgmJWoclTLus5Y0iBYK35p+dlpcUerkjcRzlkBDiKwHRjwK7
         tbYg+c9xpCvi7CGX9CtJ4kseA9z+epXpBQ2FEDIL5Sbl36FV9jrny4W3Vvif02Vyg4gU
         IzE47zgYS1Q9U7iFJYSS8Xo4Fidt4hXfyZwNMib3lEu11RMWWLXvPS/zQ0SqNRiNfuil
         mNiO07qOE/ddwpS4tGzDVqhsN5mAWshKLc4X/nod5HLX+/LgUVZ0OEHVLU3QDkMvulrb
         ar4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rQkzdS5d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id b17si2293717ooq.2.2021.05.24.03.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 May 2021 03:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id i23-20020a9d68d70000b02902dc19ed4c15so24772779oto.0
        for <kasan-dev@googlegroups.com>; Mon, 24 May 2021 03:04:29 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr18932645otu.251.1621850669515;
 Mon, 24 May 2021 03:04:29 -0700 (PDT)
MIME-Version: 1.0
References: <20210524172433.015b3b6b@xhacker.debian> <20210524172606.08dac28d@xhacker.debian>
In-Reply-To: <20210524172606.08dac28d@xhacker.debian>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 May 2021 12:04:18 +0200
Message-ID: <CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
Subject: Re: [PATCH 2/2] arm64: remove page granularity limitation from KFENCE
To: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rQkzdS5d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

+Cc Mark

On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.com> wrote:
>
> KFENCE requires linear map to be mapped at page granularity, so that
> it is possible to protect/unprotect single pages in the KFENCE pool.
> Currently if KFENCE is enabled, arm64 maps all pages at page
> granularity, it seems overkilled. In fact, we only need to map the
> pages in KFENCE pool itself at page granularity. We acchieve this goal
> by allocating KFENCE pool before paging_init() so we know the KFENCE
> pool address, then we take care to map the pool at page granularity
> during map_mem().
>
> Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
> ---
>  arch/arm64/kernel/setup.c |  3 +++
>  arch/arm64/mm/mmu.c       | 27 +++++++++++++++++++--------
>  2 files changed, 22 insertions(+), 8 deletions(-)
>
> diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> index 61845c0821d9..51c0d6e8b67b 100644
> --- a/arch/arm64/kernel/setup.c
> +++ b/arch/arm64/kernel/setup.c
> @@ -18,6 +18,7 @@
>  #include <linux/screen_info.h>
>  #include <linux/init.h>
>  #include <linux/kexec.h>
> +#include <linux/kfence.h>
>  #include <linux/root_dev.h>
>  #include <linux/cpu.h>
>  #include <linux/interrupt.h>
> @@ -345,6 +346,8 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
>
>         arm64_memblock_init();
>
> +       kfence_alloc_pool();
> +
>         paging_init();
>
>         acpi_table_upgrade();
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 89b66ef43a0f..12712d31a054 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -13,6 +13,7 @@
>  #include <linux/init.h>
>  #include <linux/ioport.h>
>  #include <linux/kexec.h>
> +#include <linux/kfence.h>
>  #include <linux/libfdt.h>
>  #include <linux/mman.h>
>  #include <linux/nodemask.h>
> @@ -515,10 +516,16 @@ static void __init map_mem(pgd_t *pgdp)
>          */
>         BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>
> -       if (rodata_full || crash_mem_map || debug_pagealloc_enabled() ||
> -           IS_ENABLED(CONFIG_KFENCE))
> +       if (rodata_full || crash_mem_map || debug_pagealloc_enabled())
>                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>
> +       /*
> +        * KFENCE requires linear map to be mapped at page granularity, so
> +        * temporarily skip mapping for __kfence_pool in the following
> +        * for-loop
> +        */
> +       memblock_mark_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> +

Did you build this with CONFIG_KFENCE unset? I don't think it builds.

>         /*
>          * Take care not to create a writable alias for the
>          * read-only text and rodata sections of the kernel image.
> @@ -553,6 +560,15 @@ static void __init map_mem(pgd_t *pgdp)
>         __map_memblock(pgdp, kernel_start, kernel_end,
>                        PAGE_KERNEL, NO_CONT_MAPPINGS);
>         memblock_clear_nomap(kernel_start, kernel_end - kernel_start);
> +
> +       /*
> +        * Map the __kfence_pool at page granularity now.
> +        */
> +       __map_memblock(pgdp, __pa(__kfence_pool),
> +                      __pa(__kfence_pool + KFENCE_POOL_SIZE),
> +                      pgprot_tagged(PAGE_KERNEL),
> +                      NO_EXEC_MAPPINGS | NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +       memblock_clear_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
>  }
>
>  void mark_rodata_ro(void)
> @@ -1480,12 +1496,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
>
>         VM_BUG_ON(!mhp_range_allowed(start, size, true));
>
> -       /*
> -        * KFENCE requires linear map to be mapped at page granularity, so that
> -        * it is possible to protect/unprotect single pages in the KFENCE pool.
> -        */
> -       if (rodata_full || debug_pagealloc_enabled() ||
> -           IS_ENABLED(CONFIG_KFENCE))
> +       if (rodata_full || debug_pagealloc_enabled())
>                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>
>         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
> --
> 2.31.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210524172606.08dac28d%40xhacker.debian.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNuaYneLb3ScSwF%3Do0DnECBt4NRkBZJuwRqBrOKnTGPbA%40mail.gmail.com.
