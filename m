Return-Path: <kasan-dev+bncBCMIZB7QWENRB35BZ2HQMGQEUBGENWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D56249F3C9
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 07:45:04 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id y124-20020a6bc882000000b0060fbfe14d03sf3868541iof.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 22:45:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643352303; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/GZ81KenOgCPi0Hj3ckY/NvSF2qJnxOklf9lnGQF/pnuFyHWoKg1D33uvnjAeCKgY
         SIkafHdPoHika1+5IVUAoZjhuey/4pkMIBrcOcLDWx3tFM9RlT1tq9Ulg0FG7YSX54MN
         14aaTy+o4N72LO2H9KWHhAT6+wXyjFuH/sSOQPy2L3tLGSucq+ZO/C128R7dEjUyKUvi
         yGO+OZms5L6dEd2ki+sU2XNOQluKMG01gsVZK7hd+68gwW1xlF1bnxEVWKUg5YDWeh2/
         IIGBGQVMqe9q2ldqntHHfLuFbJIhicXwJoOx4dnxMqDjsqWsBqSRdbfYeXMw+qJYc8gf
         AB2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lBKm+7BdDQLavK71Gk4gYEGCqoJ7lbzUE+IcfYC4rrA=;
        b=ezbjOAsHEId2CDz9iWkPvGXehPkMAjxsxZB/lQQtoMHTxAG4dqHVbDlm1AGQ2lNdvo
         c8voxdJv9SjoXCePgF7zivsYx+/WMtiMRKKFOhjTykB8gByI8892rNszIxJqTB6OaS3J
         V1DmiY/lL8coECz7U4Ttbro43fsVF4vchGGbEe+02LVe59rUJ10d1IOhksTBEiuVunSU
         B87Ltl1mSBLY30nSaTV2HLF1rERyxICnHSHo8sLBxqkxunBS9EOilwiOFLlSK6j3iZ/o
         MYz5RlmGsoCWI1jETR+m5niAzX//ZOKHxG4wmIgAh0PvNzMuDCXP9RGnzB75WOvLVNji
         pytg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sIvai0pL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lBKm+7BdDQLavK71Gk4gYEGCqoJ7lbzUE+IcfYC4rrA=;
        b=a9wBbWgzFgqebEkONRvQBJVSItVKsEC562NcGakIZxTHNZqXkopaEhdhDUe9jIo0U1
         vAtDEGlkYaZoWUSb8M/G4EM3kmEQwH7kEZj4eXDkEau3UYEG1s5/kQkwaCMZGJbAOPtx
         rQ9Id2LH5lc83K8sbigyxzbOkFg23q8fxF0ERM+tTG2UGL9MEAfcX3N/L8o9DDiaub2J
         6kd6OxXXgoc/7CBw9yNmvsrGu4bRZUpix7UhX5SjQTwsATOSjjhLbSFp7Ji0yLGLMkMB
         t4SSLbvmoVlYWMQkyw3O0M00KzQlP12JuwyZiw5ssfsK5hMomXxrvAIKnLPXFbcjVUIy
         Z9Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lBKm+7BdDQLavK71Gk4gYEGCqoJ7lbzUE+IcfYC4rrA=;
        b=BSOr05VCN5skQvoxFrWjvbw6kphUhJGjuOX0WwaX5HvXFrZWGQIDDNkHgQc1zOY8mV
         v8kibU3ZyqalGlfLJLdTx8SCc4wFFbSLxQ/ra5Eb+fVRfZsEEos0nxQ5fyDU5r2dTgEF
         hWri4NdsekMS+HbX1FTVKQpcXQ0iIi5nRVal/SdHboZrTCvNiMjfACpnUh+mKGKMBOp0
         X7FLD7DFOqoHdPWNL11uKN9xIrg7NtQCCgQX0bKn7EiGa5eKNHLHGyUEAzKWnT9NiMaF
         AcG8MPOt60JybuxnPrxn28z5mQAORv+GTFQ6UdNi+PPaneAwN9OOXfHeJozDu3uysIjJ
         BkXw==
X-Gm-Message-State: AOAM530AJ9t9R1mRu7VI56a71typY3v/+J6PWg/HW3mmOFV7YWbp7bv+
	JKDb+icROW8cfL0BhPaRZoQ=
X-Google-Smtp-Source: ABdhPJxAs/fMQV5KKpjLnMP6F/Dh7vMrtemn997/WcTShgTL/eHxp7ZY+FL1dgj5/UHDlOosciyNww==
X-Received: by 2002:a05:6602:2dd4:: with SMTP id l20mr204368iow.115.1643352303286;
        Thu, 27 Jan 2022 22:45:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:cc5:: with SMTP id c5ls1835157ilj.8.gmail; Thu, 27
 Jan 2022 22:45:02 -0800 (PST)
X-Received: by 2002:a05:6e02:1609:: with SMTP id t9mr4170180ilu.72.1643352302865;
        Thu, 27 Jan 2022 22:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643352302; cv=none;
        d=google.com; s=arc-20160816;
        b=nn099Un2aXEcrv4ihrh+HuQqAUz8UlYN1Di2MYWlpXGv3/9rpWy8HULHdn8aR9nLyr
         +MBTyFlH1lOXqP3c6JtJ4jaX1mGbTohvyVDHIVlRR3hdm0QXMbD9Q9ntgp7Heo46D0jG
         xGW+idJdW5d2ewPFX+wjQbRgJp9jWQepw6Yj9qJw1ZxBatSraTsefU+hGGtjXCmLNwXt
         pfcHFcjGuPjD2vTEd1ZvVmkqtavgJVYAuHouTNW09F+qwsAiY2gsPCq7tzcpq0M5JOhi
         oLfDBXx/qB1GesG7EGWwwLD39SOUWx7l+eIyM3Uk5JuSzv6tqkJtmfmZTWXXGELLmd0f
         Ru5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9Xk+4cliWQ8pKs4/H9QbNIvJzjxoe0JvtSnu86eAs+0=;
        b=uN04sBvmbTflDo44oizLGAoTJ/QKzqD5j8mqzAM7RRkcaRyjn8gQR7z3/hOoOQrqs3
         n5qiC56JlegwL+p8FDsEU00kGJOFOsUvODCU9MmcHSjF+IREi0+am+Cho7zYKEgfieNE
         TH7qdolM6UVVkJ+k1CMS9cOc/RK7VxYyPVOC19Onp9C4vU4VXszn7pWZE4kpTfZM/Emg
         TRNzDzETHRhiqniZUltDZ641obe4XMZ8uktVghysSD0o6ne5kTF80v9S1coH9YOukEvY
         PRU9ka3gjBoKxLvtAJPHaqVGFI1c6CDx2/dPJxkNiZD3Lq/QPLm3PiqHbL+KFZ/w3+Ty
         AD4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sIvai0pL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ay13si372398iob.4.2022.01.27.22.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Jan 2022 22:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id x52-20020a05683040b400b0059ea92202daso4862956ott.7
        for <kasan-dev@googlegroups.com>; Thu, 27 Jan 2022 22:45:02 -0800 (PST)
X-Received: by 2002:a9d:6319:: with SMTP id q25mr3982948otk.137.1643352302180;
 Thu, 27 Jan 2022 22:45:02 -0800 (PST)
MIME-Version: 1.0
References: <20220128000752.2322591-1-jannh@google.com>
In-Reply-To: <20220128000752.2322591-1-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jan 2022 07:44:50 +0100
Message-ID: <CACT4Y+aF7xQiPCxN8YsqsYWwotyWr+hy-F+OiBPSFDJ0EswN1A@mail.gmail.com>
Subject: Re: [PATCH v2] x86/csum: Add KASAN/KCSAN instrumentation
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sIvai0pL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32a
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

On Fri, 28 Jan 2022 at 01:08, Jann Horn <jannh@google.com> wrote:
>
> In the optimized X86 version of the copy-with-checksum helpers, use
> instrument_*() before accessing buffers from assembly code so that KASAN
> and KCSAN don't have blind spots there.
>
> Signed-off-by: Jann Horn <jannh@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks

> ---
>
> Notes:
>     v2: use instrument_copy_{from,to}_user instead of instrument_{read,write}
>         where appropriate (dvyukov)
>
>  arch/x86/lib/csum-partial_64.c  | 3 +++
>  arch/x86/lib/csum-wrappers_64.c | 9 +++++++++
>  2 files changed, 12 insertions(+)
>
> diff --git a/arch/x86/lib/csum-partial_64.c b/arch/x86/lib/csum-partial_64.c
> index 1f8a8f895173..8b0c353cd212 100644
> --- a/arch/x86/lib/csum-partial_64.c
> +++ b/arch/x86/lib/csum-partial_64.c
> @@ -8,6 +8,7 @@
>
>  #include <linux/compiler.h>
>  #include <linux/export.h>
> +#include <linux/instrumented.h>
>  #include <asm/checksum.h>
>  #include <asm/word-at-a-time.h>
>
> @@ -37,6 +38,8 @@ __wsum csum_partial(const void *buff, int len, __wsum sum)
>         u64 temp64 = (__force u64)sum;
>         unsigned odd, result;
>
> +       instrument_read(buff, len);
> +
>         odd = 1 & (unsigned long) buff;
>         if (unlikely(odd)) {
>                 if (unlikely(len == 0))
> diff --git a/arch/x86/lib/csum-wrappers_64.c b/arch/x86/lib/csum-wrappers_64.c
> index 189344924a2b..c44973b8f255 100644
> --- a/arch/x86/lib/csum-wrappers_64.c
> +++ b/arch/x86/lib/csum-wrappers_64.c
> @@ -6,6 +6,8 @@
>   */
>  #include <asm/checksum.h>
>  #include <linux/export.h>
> +#include <linux/in6.h>
> +#include <linux/instrumented.h>
>  #include <linux/uaccess.h>
>  #include <asm/smap.h>
>
> @@ -26,6 +28,7 @@ csum_and_copy_from_user(const void __user *src, void *dst, int len)
>         __wsum sum;
>
>         might_sleep();
> +       instrument_copy_from_user(dst, src, len);
>         if (!user_access_begin(src, len))
>                 return 0;
>         sum = csum_partial_copy_generic((__force const void *)src, dst, len);
> @@ -51,6 +54,7 @@ csum_and_copy_to_user(const void *src, void __user *dst, int len)
>         __wsum sum;
>
>         might_sleep();
> +       instrument_copy_to_user(dst, src, len);
>         if (!user_access_begin(dst, len))
>                 return 0;
>         sum = csum_partial_copy_generic(src, (void __force *)dst, len);
> @@ -71,6 +75,8 @@ EXPORT_SYMBOL(csum_and_copy_to_user);
>  __wsum
>  csum_partial_copy_nocheck(const void *src, void *dst, int len)
>  {
> +       instrument_write(dst, len);
> +       instrument_read(src, len);
>         return csum_partial_copy_generic(src, dst, len);
>  }
>  EXPORT_SYMBOL(csum_partial_copy_nocheck);
> @@ -81,6 +87,9 @@ __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
>  {
>         __u64 rest, sum64;
>
> +       instrument_read(saddr, sizeof(*saddr));
> +       instrument_read(daddr, sizeof(*daddr));
> +
>         rest = (__force __u64)htonl(len) + (__force __u64)htons(proto) +
>                 (__force __u64)sum;
>
>
> base-commit: 0280e3c58f92b2fe0e8fbbdf8d386449168de4a8
> --
> 2.35.0.rc0.227.g00780c9af4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaF7xQiPCxN8YsqsYWwotyWr%2Bhy-F%2BOiBPSFDJ0EswN1A%40mail.gmail.com.
