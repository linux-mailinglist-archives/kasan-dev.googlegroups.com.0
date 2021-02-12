Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXXCTOAQMGQE2ILZDHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52FDB31A6C5
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 22:21:35 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id v10sf512055qvn.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:21:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613164894; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOfCySirsYt7o40yQYVYsaN1OwNol/zi/AK5QahxnAeHCNTTcyRRgQSJL6VjpG5DmM
         xzM1zhwh+mWz6Y4EVPSVRWUa6JOuMtG/wxT7Z/XCIQZylvVYh9VXj8MB4j76c9Y5lfi3
         Ft+T+DkgrCb6Jczbu0xuDEzQJSG+aQLKEX4gVkETLA5faq0YJw6nz6jvqfMr+z/qLN+B
         M3Z36cA6GqzVyiNOfzwIsWS2U08X8bokQg4hB4iDEiISaKuGM56bJbsSN5Ia4R/6MLmZ
         KfuXxZMXFmNqeJm7tvkbIcihkqAhxMCSSmd/7oS4oNospEWLL4Tsw/IZS5IkKXLDpfaD
         2Grw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KNZ2pFgUw2V6nzjN77oMBzRSTS7gCiBpO2L742qvzo4=;
        b=aMAeOGx1l8IeQRvMEy0sZFuF0Y92dsxmv+UnD4T82iWD2rtWKh5euL+Oq9t2ereJaz
         RtBTQXTbtntpzR1SlFYTizX3JJBFP1Ju4VXhDwWDRW4e0x/7gqgTGnuhPXGU3tyxn2KC
         lkQtEmfPd8v+TfCDAsHlNdkv5IFzd5ZjKwST3bi1PNK5XLqGYcNkdumIuoQ+V7FYTaAS
         4Gvr2pIMZ0GWj3CU7VeiNA2XQy1ssQ+jdqoZ8ImLgWrgehd6QvudtMuq97FdfM9ngXsI
         wCMGUJFhzo9CEDB15d2KmB5AdoXJv0QIflYQAqFX8FiVipzjj2p0pgmP9dpfKtF6JZXP
         Dmvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A2cdLkHx;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNZ2pFgUw2V6nzjN77oMBzRSTS7gCiBpO2L742qvzo4=;
        b=KW3aJ1lHmGjjRokwizxB6ivUPGWm6PAJg6nlbJSY3svmNUbB/MJbHeuXZWuA96fgp0
         CyYnK67qu5bYPUBa94P90H93d3k/+HrVG+XCZKKHWtOlllrnEZY/TujuQpm0waXy3o8O
         DBi0NQB4E0E20LzH3FEwKVD3XNl91Ap3edq45Xkb0t5H8SP2vW2eNrZgTtuJ8UXKiM/c
         NQLZyftS2NELXq1QDn5aodK19Xcu7EMQXuMYXz2EBVucobBul5+s8caBND2z/YnFLesC
         k0gpJ69q5bfMvCjjNbD8IonhYoWu98vuFIkEtd0Zxh/C8fyWFOGO5F6stnhBANFS9qJ7
         dAOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KNZ2pFgUw2V6nzjN77oMBzRSTS7gCiBpO2L742qvzo4=;
        b=YH8hS6DBMQCDk/D7G7V1XVTm8yUwuYdmtahfRkrTsKsUvLDB8FC/wZ822d00atHpqz
         8dRgpawIXEPEkJ5NFTQvOfBnbQshExj1iipHKRkaS/ttJXn481nPLzj85IcS6/HdbO7W
         C8oUm8TEsr3Z3oV/0qfGO76K13kgnmzgcW8KEc5Q6db98g3BuXAgiCVczXJ9vye2FIxH
         30Dxx9Sx82/7MSZ2kbFjWRgNERCtCT5trNMOgb4M3TJw63UgvbT/Pydg3fvOoY1sFnY1
         lZ7UG/R5gih/qCKfLEzrCV1RUFU/miNB9BGvtkzCfdY/Pff6ntJoTTDpdTDdU5+hTHyo
         393A==
X-Gm-Message-State: AOAM5337K+yXjg0lhshuDTqnlVHJAulLNtcFO/w/Z0VIRfwQUTxAU4sI
	x6VLaJi3zwXsvgdwzP12pBc=
X-Google-Smtp-Source: ABdhPJwFpxRwAtUunXUGb4A8UtzleDQq/zVGXggUNICOmyo9E9vl8ALc8uoDJCdduPNHmm3sDjPRxg==
X-Received: by 2002:a05:620a:209c:: with SMTP id e28mr4706800qka.188.1613164894252;
        Fri, 12 Feb 2021 13:21:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9c2:: with SMTP id 185ls5220846qkj.8.gmail; Fri, 12 Feb
 2021 13:21:34 -0800 (PST)
X-Received: by 2002:a05:620a:5b4:: with SMTP id q20mr4735536qkq.218.1613164893944;
        Fri, 12 Feb 2021 13:21:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613164893; cv=none;
        d=google.com; s=arc-20160816;
        b=V1YQslrwLmu2STaOKhDBBngDQL0+tGPTO2wfkfFfeo7TZ69nYg752yVcs00DcCpX08
         2CR+DSTh5FrQ+m7semZsU16mzJWeVeUqgjzdZQlGCGtdic7H5iY7KpdDMR2kZmBq+3kv
         heJYDDIAnolScRDaD/fYShnokpaQQMUP+uK9KUMEL+HsWF6etm+/7U6h/6bhRz9hNurQ
         /ez51TSw4qezmRShsRoFPivhO7vDY6GjiYY1O5JL5Iecfi37aMRCn1HSmAzFCR+v+jaY
         z1RXunBySMUQ8zh/cWiJMoks0z7NYsVhI4yyy0ajAIQ3VnPNhW+c2rfMiVsW/iDdjKrK
         /69A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CYGVljwTyH8i7AMEtS7EVdeNyV8alpknPsckcxn4xKQ=;
        b=BC9rdpaZYNjdibJd3roz7utMPCYVXMFMtuMkjW1XXHgoVKVS04Nx+ERQXvClwlaWZa
         IPziRJOrcixUu5nCFepYho24m6FTtXgU0OjjPF4aQO2pAJrUTok2/TprChJivHNopbZ+
         1KpEE+yp42M3iDe/oEVsA66qXPbXYcEycIk03AjVhC5cKvQ7f5ujrYKDE3rKdzNfXF65
         xpoI+8E/DtBVlNEq4B5yGI5cG+G57rG3WPxyxMufOBNm0F4G9kBwev5rTuzLVmpY0ezI
         awxN6i8nNHO9VdGivfIbQP2O9gE4l9+vE5FAkNdIbf1McsJUCsvmZcZOE8CH6SK0Va2I
         A5PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A2cdLkHx;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id m8si655175qkh.4.2021.02.12.13.21.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 13:21:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id fa16so330673pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 13:21:33 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr4400262ple.85.1613164892940; Fri, 12
 Feb 2021 13:21:32 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-1-vincenzo.frascino@arm.com> <20210211153353.29094-2-vincenzo.frascino@arm.com>
In-Reply-To: <20210211153353.29094-2-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 22:21:22 +0100
Message-ID: <CAAeHK+xM1VHvSF_9ELf=_nDwJsUV2S1=LQy-rU-O0oyrNexzXw@mail.gmail.com>
Subject: Re: [PATCH v13 1/7] arm64: mte: Add asynchronous mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A2cdLkHx;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030
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

On Thu, Feb 11, 2021 at 4:34 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE provides an asynchronous mode for detecting tag exceptions. In
> particular instead of triggering a fault the arm64 core updates a
> register which is checked by the kernel after the asynchronous tag
> check fault has occurred.
>
> Add support for MTE asynchronous mode.
>
> The exception handling mechanism will be added with a future patch.
>
> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
> The default mode is set to synchronous.
> The code that verifies the status of TFSR_EL1 will be added with a
> future patch.
>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  3 ++-
>  arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
>  arch/arm64/kernel/mte.c            | 19 ++++++++++++++++---
>  3 files changed, 25 insertions(+), 6 deletions(-)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index c759faf7a1ff..91515383d763 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -243,7 +243,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  }
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define arch_enable_tagging()                  mte_enable_kernel()
> +#define arch_enable_tagging_sync()             mte_enable_kernel_sync()
> +#define arch_enable_tagging_async()            mte_enable_kernel_async()

We need to update KASAN usage of arch_enable_tagging() to
arch_enable_tagging_sync() in this patch as well. Otherwise, this
leaves KASAN broken between this patch and the next one.


>  #define arch_set_tagging_report_once(state)    mte_set_report_once(state)
>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>  #define arch_get_random_tag()                  mte_get_random_tag()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 7ab500e2ad17..4acf8bf41cad 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -77,7 +77,8 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>         } while (curr != end);
>  }
>
> -void mte_enable_kernel(void);
> +void mte_enable_kernel_sync(void);
> +void mte_enable_kernel_async(void);
>  void mte_init_tags(u64 max_tag);
>
>  void mte_set_report_once(bool state);
> @@ -104,7 +105,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  {
>  }
>
> -static inline void mte_enable_kernel(void)
> +static inline void mte_enable_kernel_sync(void)
> +{
> +}
> +
> +static inline void mte_enable_kernel_async(void)
>  {
>  }
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index a66c2806fc4d..706b7ab75f31 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -107,13 +107,26 @@ void mte_init_tags(u64 max_tag)
>         write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>  }
>
> -void mte_enable_kernel(void)
> +static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  {
>         /* Enable MTE Sync Mode for EL1. */
> -       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
>         isb();
> +
> +       pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
> +}
> +
> +void mte_enable_kernel_sync(void)
> +{
> +       __mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
> +}
> +EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
> +
> +void mte_enable_kernel_async(void)
> +{
> +       __mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
>  }
> -EXPORT_SYMBOL_GPL(mte_enable_kernel);
> +EXPORT_SYMBOL_GPL(mte_enable_kernel_async);
>
>  void mte_set_report_once(bool state)
>  {
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxM1VHvSF_9ELf%3D_nDwJsUV2S1%3DLQy-rU-O0oyrNexzXw%40mail.gmail.com.
