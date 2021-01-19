Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD6BTSAAMGQE5VNV4TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C422FBE98
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:10:24 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id b131sf26800625ybc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:10:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611079824; cv=pass;
        d=google.com; s=arc-20160816;
        b=QjIAXL3VciR19LG3oqsO3eXgXScWJEHi1AeVZH+Q+euYwYWzLJqXeprZ6ZCUQkhmBj
         EbynyBkx/V85lbbITzBzxa/tRg9bJetx7PdIzG3Y2OXH0YdPM7iafVFh5KRt/B32O+w/
         7VExgHMhbKYNOImmEYrkMMxvaLhoe449BeBSPXFA6KZKLCCVIdiGM6cmfiX6vjX/AoZN
         FAvJNGBA3rzGh+Ma2WbpXhKFqkdOeG89kIQojDuYLOjtx1eqRELiS0DLeG8jgmdTXg6B
         FTem35Yv+lrodxAqDedzwf45+XYjkJ85uKECIz3ZGq8NY8Cq3bmDOgxHyL99Fx/x3fL9
         wV5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/bv5F7rCNpT5ctr4PbEupxIZ2oNweoSAZFysH+AT4aE=;
        b=mr8xQhtGA109YuFVK8vMkIvTa/27eNRpWyRqppKg0SlpqBrzWOnlx/CmqN6XpJ1Dyb
         TJnb3JwgwHQ8EIk4lX7r9PD+v4zDVUAprXFQzBeQPIAO6oTX/3OmjHqljiMITwfONT/Q
         iuGI8i30oGAcy7j3DbZHmJK5p/9q94UkgHDphTjEHiDp0JgUsfsynXrQNFsFOpMVKLu1
         BZ1X2bs5YFO5mnTAafGYA6weYaJZzfRpMaMkFnbswtNGHSSVi6jfb/hX3fwFr0z7zWYp
         d/+OTkyshYXMLzbCFXRN+/tEeiBN4B5bPukhesb1UgI5GJl8VrSYOYha3ovAsNdU1N5h
         JoUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RPraS7hB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/bv5F7rCNpT5ctr4PbEupxIZ2oNweoSAZFysH+AT4aE=;
        b=lfk1f4WUHth76GKtmjE63xTG9ZsUvx+tel5BpW1hP84fv+2nSGJPmOPvWesOuIW4TR
         3+vMPVlPb4ld1MiR68KSCEThF6SjbNT2Nc6lHEIOt3l3mKT6AkwwSFOmqA6VXB5Hu8ZX
         q9FZlvvXbIuf5xUh+1alscMUPMMpVUpg6UDwq23f1SdDc3PtyQocoXsVHgaVWCOj2AyY
         qE6A26xvkTacq4NiVjXBZo0MZWyMEHLuw1tYUTRjRowD8LHlxehyDUnkwLj8W7bQL/Gk
         O2WFqRdKmYBNQ9sfxl+uqMNtuP3rKXScGhL/JEQZYhc8ccIt2ToyV0J8H5de6IBvnY+B
         RNBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/bv5F7rCNpT5ctr4PbEupxIZ2oNweoSAZFysH+AT4aE=;
        b=Q9RCGinVqZfx7Bf3aD66ItdJn/lZZX2azNSpJY9+jFOKw3qamaAJb9ITKs4mHlbPhB
         pDBCUf5xZCbfu5laqPcWa59qk0B3iu1TcC9/zXIiXl9e5YA63sGFYaAhEX9bzvC4pwSO
         9cW/FaWLiYjwzyBCBY37AlOElDL49bjryXvkv+X5md80Gsd98wBWu2V400KqNv3LUzaq
         0JyJn/N4UtVUhwJ/76FmBKSMZHeVUirCiP1W/t/xFBkGVjAb8LqVKg8qUewJDbXUyFMT
         SPxKE3JtMVrm79CRudfe+VD7DBxFIrm9Peplj2A9cZkKnO9B4eHOtsTRxK5qev/9CiYL
         PofA==
X-Gm-Message-State: AOAM533J9hOGL6m+rBuBnozgW5hNityxzN9CZ80Xk7lwcGvrWe0VkH4h
	foT/aHO2nX+IS7WOIg+cjz8=
X-Google-Smtp-Source: ABdhPJwZaPSeAp0VnNh8E6rOC2wVDDj8Mi3ugI4QD9iMejTxyhv0YKECKWFKmhPvPpmRLbOlDUvG0g==
X-Received: by 2002:a25:3897:: with SMTP id f145mr7241521yba.2.1611079823910;
        Tue, 19 Jan 2021 10:10:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f84:: with SMTP id v126ls7174742ybv.11.gmail; Tue, 19
 Jan 2021 10:10:23 -0800 (PST)
X-Received: by 2002:a25:2f91:: with SMTP id v139mr8239841ybv.491.1611079823511;
        Tue, 19 Jan 2021 10:10:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611079823; cv=none;
        d=google.com; s=arc-20160816;
        b=ELwyzlKPXgIBUnSAIlgO+/Do0OWWp7Ud8rm3XzhT2HzKVFTnxbq6xJSBpvYe5HnmrQ
         smiPiaMD5sBX2JRnoGCCwNv1EwPF+AdGEDOrC7YnO8/8zFxRitEfK9L0gEQdgamJaSjR
         yDW/Xp5lwSmjjorQ5q3fYsTrCp2bZFO9P+iTJ68Tw7pO7javO5Q+ABODtMpa7aiBJrn5
         ka4W7QLqhkNf419deq/Jdj52H+us/KO6/OYO45xcN5mf803kKE9JMrsjoiFBfPMSiYG7
         vcAEgScu4e3gJtu4cdT8UOOCqMGcu7hf6XvbWTyhU4wkv1scJA52PxRKEnFhE8ZWgWgs
         w/Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dnrMrldg8mnofkcXZdxW4LOH+ARI4N3c8/lAl3ZaiEY=;
        b=Gz1qQglJefYg5PviA708Zj2JwmENQZUyhs11hf/30WIeN0HE3+798EJhX/9FLZ/jcn
         h8btLZJ44yf8rc8acXn26SD7fHgNLzR25qILrUsWhOHtki96S/ur++/qnulfgSnEx1Ux
         446jzyGzsWdK/zCz4obvfjo73h5AEKygWTmftArlpd6R4S0nwGCXIH1gV4QLygRrklOh
         Yt3LzjV6xEZhyvlBSJerPywm5mW3eA5OxoQPsDtxTV5ci5Pzvi5cPOxTsWlRqWAGtaH5
         oda/As6b6xGEpIvRoBs4AFDQSocpIdWOqEai43Ry5urUUiKAlqV5e1fWcDwrbSHfaY+L
         XP6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RPraS7hB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id s187si2094409ybc.2.2021.01.19.10.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:10:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id v19so13418636pgj.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:10:23 -0800 (PST)
X-Received: by 2002:aa7:8597:0:b029:1b9:38bd:d0dc with SMTP id
 w23-20020aa785970000b02901b938bdd0dcmr5074425pfn.24.1611079822481; Tue, 19
 Jan 2021 10:10:22 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com> <20210118183033.41764-2-vincenzo.frascino@arm.com>
In-Reply-To: <20210118183033.41764-2-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:10:11 +0100
Message-ID: <CAAeHK+xMk=7pkOi2UtYZzxOhrnVRe+CYcyjBBHKUW3jmfg64Ww@mail.gmail.com>
Subject: Re: [PATCH v4 1/5] arm64: mte: Add asynchronous mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RPraS7hB;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532
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

On Mon, Jan 18, 2021 at 7:30 PM Vincenzo Frascino
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
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    |  3 ++-
>  arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
>  arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
>  3 files changed, 23 insertions(+), 5 deletions(-)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 18fce223b67b..233d9feec45c 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -231,7 +231,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  }
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define arch_enable_tagging()                  mte_enable_kernel()
> +#define arch_enable_tagging_sync()             mte_enable_kernel_sync()
> +#define arch_enable_tagging_async()            mte_enable_kernel_async()
>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>  #define arch_get_random_tag()                  mte_get_random_tag()
>  #define arch_get_mem_tag(addr)                 mte_get_mem_tag(addr)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 26349a4b5e2e..9a5e30dbe12a 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
>  u8 mte_get_random_tag(void);
>  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>
> -void mte_enable_kernel(void);
> +void mte_enable_kernel_sync(void);
> +void mte_enable_kernel_async(void);
>  void mte_init_tags(u64 max_tag);
>
>  #else /* CONFIG_ARM64_MTE */
> @@ -52,7 +53,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>         return addr;
>  }
>
> -static inline void mte_enable_kernel(void)
> +static inline void mte_enable_kernel_sync(void)
> +{
> +}
> +
> +static inline void mte_enable_kernel_sync(void)
>  {
>  }
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index dc9ada64feed..78fc079a3b1e 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -151,11 +151,23 @@ void mte_init_tags(u64 max_tag)
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
> +
> +void mte_enable_kernel_async(void)
> +{
> +       __mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
>  }
>
>  static void update_sctlr_el1_tcf0(u64 tcf0)
> --
> 2.30.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxMk%3D7pkOi2UtYZzxOhrnVRe%2BCYcyjBBHKUW3jmfg64Ww%40mail.gmail.com.
