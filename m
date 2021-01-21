Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQHZU2AAMGQEHST5ZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B00E22FF22A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:41:20 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id v7sf1590713wra.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:41:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250880; cv=pass;
        d=google.com; s=arc-20160816;
        b=PmA7dkvAgM7ewVtUbO/U2hlM+W+w37W7NFxMh3rYznoeG61m/06peExcmfOFNpxUIm
         QVvIfrHz6TGqioycmN8L7EnXRHKwolAnEkRvmiQzQNwNlSqa39zk7AaWmA/VkgjSTsWj
         Bc2sX1TBiBbyfmQPUcdMDIG9fPgVaqTxcZvmD64bKEQvl9tVluGZACE3dNuvdE7IDnNn
         LLYN9G8ChajyZPs5OpPMvP0bA7fT6BlcyAMW08KqF0jqKONoa8vUuL6jZNsy73HfHEb2
         FbegTSo7auw26lzSF8YMPBT2Q3f+Nxc4Bn9fFUfp+C7Ue6j4XnKsdwuMFhofpzcMnGnk
         h12g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aHAN8xjcW6tFsJTeo6DPolHqFBqxVqIf2uZ0h3peCe4=;
        b=TDWLV5Ms6uGiu5qoqRvhjqLkA48NVo4GgmxdaR3eqsDj1WUXSVzmY+8awnUC1L8HJ9
         KlRF7BbnJkgTrb8VGpV7s1jsuhNhFiq0V5HVjgY8JCSyaVSkgqz0qYxE5meAv93ZpRmA
         ilbRzPPcxA4OFAaz9QQbyoBcQ5vcLZmSX/5785iS5eXZRuwYgEYlHYV3hiV436dijjIP
         bsaXzsrYBI64aNDZ/cWEIMzhzPhGk3XKMqg7ZE7oDwRGJcLHgF/Y19y3JzemR/hK0zD8
         s2tMYZ2qRcBJeIP6UHXGsLNBnaghIMHQZH4+eXcBQ9/AdcEDubTU+vlItQmdgRHvgWx9
         08BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CgTgPusW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aHAN8xjcW6tFsJTeo6DPolHqFBqxVqIf2uZ0h3peCe4=;
        b=IVe/nVcYTvvLD6fihsof9KMM7cdbEO/6M5EAfOcDOgqK89WJkZYACkU6h1ipKqxI+I
         hpGL3kmfFH5p+RaqPIJ7cQTVw6lR98E9d+JkyWKI+ZrdzRwiBdrUjzZm4jDe1TwrAMDd
         sQnrrl5B7v6Lsug2u5BsAhcsPQyLXVxU41Il94pYBeyE/AZfYxQzMfHrtYjRySjmbyDe
         +/FTlbYvu+8jTyXe4YXx2Bp91BIjapZf6shYJSBEe+ahn35Tk4Jt4lxUS4K3lKViBFRI
         Wm9KauFCvtoOF0CdbgS4x1FAlH8t610YlWUtO2PDNEAwe1zA2BeYMNU9PmtGY4ZR9WOG
         NFpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aHAN8xjcW6tFsJTeo6DPolHqFBqxVqIf2uZ0h3peCe4=;
        b=g8TEm+7p3xQGVxcZPA2QTS4oCYLbTEtqtk/pO9jsePL0fKofs4bEvLZos+KVqF3JPB
         vqWuSMDfmMTomueb4seQPqcjocywmuX05t0r5CRSpZaFsMXQ3gBCkR2g8QbBlsHwZcbw
         94+67qTCc1/i5IO23oRxPZI4r2d1yr3wwko8G+a7suCyMMU/YbGhA9RWvxHerVUfM3Kg
         5kN9ScY+0sCfVS0y8tDeGg7212xqbLSq9IWoIzjzoPaWH9UJlol/dReHBcWtHSk8qp9A
         PwbhJMJIGrUa+j331bXtl202118W6EwMjglwiCduCUUkV8P1eWIvGEIpchx0RHPhwLWP
         tZwg==
X-Gm-Message-State: AOAM533uKAj/oLVKtDmJ/UU6BQa2SDQ1J8mFIMxmJCrMpNB/o/fhWOKi
	cNJqXSrur4oxGEJg2HPCBJQ=
X-Google-Smtp-Source: ABdhPJxAYeSf8oEpo2BBhvDJ1Rq9+4vEx84wj5ygOKRsSFAZXmNwQ+FMjMtWkMBTcTby05a9F12Cbw==
X-Received: by 2002:a05:6000:254:: with SMTP id m20mr582749wrz.300.1611250880532;
        Thu, 21 Jan 2021 09:41:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:bb0b:: with SMTP id l11ls1749867wmf.0.gmail; Thu, 21 Jan
 2021 09:41:19 -0800 (PST)
X-Received: by 2002:a1c:2288:: with SMTP id i130mr400072wmi.181.1611250879620;
        Thu, 21 Jan 2021 09:41:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250879; cv=none;
        d=google.com; s=arc-20160816;
        b=NXf6OfjeEltUk1Tk2jWsiAb999haUxOpZELlbcRTpMxXjOOryG9eX1WbnEDghfX0q8
         dMAWhijGk/tcliWx4YW1H+7qeYHCgV+Sm1Y86LGRUqSxRY/QsZmLG2c6gq8YPgx3u7mD
         OGVuh6QxUn2EaXM84TeHsP3Nv5NUgE3dhG18XjTLUbxC0B806z2I9mENjgLeDouk7x6z
         I21KXqx0vK522c6ymHfeqot802/GM7uUJsVqrCzizg5BzR3farCJD4CXwORv0y9idSqA
         +LtMSpmuwkJfNS55ZZiqV9Aea1ZukTffgJk73ZcNjyM/4aR23tEbDg1ipZo0ynvLWB/a
         rXPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6niekSQOjT6sl668qL1auwEOgCZByDONjvQaO9EkZdk=;
        b=uBi+SxURbi6sYeHAUW3SGpadthTO14Q6ZPlEZokHI+oVkOvSoUzFCWk6Ec9XAtVF7R
         WBXVIzpPKcgrg1HKNYJWLDd2lxit36XIya22rYlOMW0bE/Kfv5ApqafCb7DzdAgrgUy3
         eCX3uvEchnG5UXMSRcftJ+G+MvO92EZ1tBsgSeVEUR0/9L2yrxigbSq/ruavUy8bLHhR
         Ss8cFBlptAE2wGDFF84pTgaLCmPPJMgaqHbnZhbYxuYwmbCYwJm2QV1/UwbIlmNMcz1F
         w5r8gMLWx4J4Suez3AMy41eQ8thVZ5Sf4a55t16ia1bcYisCW+yL/rl0n2JCkueim1NU
         QqAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CgTgPusW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id w11si290553wrv.0.2021.01.21.09.41.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:41:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id x23so3447471lji.7
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:41:19 -0800 (PST)
X-Received: by 2002:a2e:b5ce:: with SMTP id g14mr200976ljn.493.1611250879144;
 Thu, 21 Jan 2021 09:41:19 -0800 (PST)
MIME-Version: 1.0
References: <20210121163943.9889-1-vincenzo.frascino@arm.com> <20210121163943.9889-6-vincenzo.frascino@arm.com>
In-Reply-To: <20210121163943.9889-6-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:41:07 +0100
Message-ID: <CAAeHK+y9Je7nwRAJ+t5Yw0d3Bmrrn-mhqdw4uqLMSdHaRjZm1A@mail.gmail.com>
Subject: Re: [PATCH v5 5/6] arm64: mte: Expose execution mode
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
 header.i=@google.com header.s=20161025 header.b=CgTgPusW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::22b
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

On Thu, Jan 21, 2021 at 5:40 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE enabled arm64 HW can be configured in synchronous or asynchronous
> tagging mode of execution.
> In synchronous mode, an exception is triggered if a tag check fault
> occurs.
> In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register
> is updated asynchronously. The kernel checks the corresponding bits
> periodically.
>
> Introduce an API that exposes the mode of execution to the kernel.
>
> Note: This API will be used by KASAN KUNIT tests to forbid the execution
> when async mode is enable.
>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h    | 1 +
>  arch/arm64/include/asm/mte-kasan.h | 6 ++++++
>  arch/arm64/kernel/mte.c            | 8 ++++++++
>  3 files changed, 15 insertions(+)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index df96b9c10b81..1d4eef519fa6 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -233,6 +233,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define arch_enable_tagging_sync()             mte_enable_kernel_sync()
>  #define arch_enable_tagging_async()            mte_enable_kernel_async()
> +#define arch_is_mode_sync()                    mte_is_mode_sync()
>  #define arch_set_tagging_report_once(state)    mte_set_report_once(state)
>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>  #define arch_get_random_tag()                  mte_get_random_tag()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 76b6a5988ce5..c216160e805c 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -31,6 +31,7 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
> +bool mte_is_mode_sync(void);
>  void mte_init_tags(u64 max_tag);
>
>  void mte_set_report_once(bool state);
> @@ -64,6 +65,11 @@ static inline void mte_enable_kernel_sync(void)
>  {
>  }
>
> +static inline bool mte_is_mode_sync(void)
> +{
> +       return false;
> +}
> +
>  static inline void mte_init_tags(u64 max_tag)
>  {
>  }
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 7763ac1f2917..1cc3fc173b97 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,6 +26,7 @@
>  u64 gcr_kernel_excl __ro_after_init;
>
>  static bool report_fault_once = true;
> +static bool __mte_mode_sync = true;
>
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
> @@ -169,9 +170,16 @@ void mte_enable_kernel_sync(void)
>
>  void mte_enable_kernel_async(void)
>  {
> +       __mte_mode_sync = false;
> +
>         __mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
>  }
>
> +bool mte_is_mode_sync(void)
> +{
> +       return __mte_mode_sync;
> +}
> +
>  void mte_set_report_once(bool state)
>  {
>         WRITE_ONCE(report_fault_once, state);
> --
> 2.30.0
>

(See my comment on patch #6.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By9Je7nwRAJ%2Bt5Yw0d3Bmrrn-mhqdw4uqLMSdHaRjZm1A%40mail.gmail.com.
