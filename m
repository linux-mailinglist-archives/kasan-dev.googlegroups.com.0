Return-Path: <kasan-dev+bncBDW2JDUY5AORBOWWZKHQMGQEJWOTPHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id DD6A649E48B
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 15:24:59 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id i28-20020a9f305c000000b00305923be96asf1612087uab.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 06:24:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643293498; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ttOyjyNF0ih7bEAA7FGtixAlqmWzsF6P9Wx/Q6W6NN+6WBva7+xolNL6NR0I0mRJ5
         mUrbw7ZpYUJ01/+dr5f3ujmV+NBvpbvvtxcLBr2AeuJfjRHJbYsQ9A2uhjbHZ5PtnlOR
         YYtFPVkPxL858thUKIxWdoToDQS/BQncX3wi03StNJFLHp/NFTGCfR0fYhLJrxjwcy4G
         wJB3IY/uNAzrqHk6AZOVrfeiyS9OD9rm1ykIzUW524tKqK+IQiK1r5gaDLK4+eKx4Z7v
         hAltGknbCNJVvetZ8mEriNGp1oqNUZ1LXCe1S3wI9a6q4ALy42l/L9SVzMXVT/G3xcVo
         BYkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VikX96bw2r6JEzKcC6Hvx9gGW9tnBdPUOX+zJ7C10rQ=;
        b=Ke1AB9qC4i1KwMyiFeU9cNO2kwbfL/pSTaYEqltDgr4RzCgMDWGZI3R11axvZs6vNg
         rlgTFNgtymOw2EmJ5OtiiRisKBk086517p8Kdh14eT1Y0N80IZAXe/qd/qmgLs78/gy2
         u2eLmlw7hA1KF/sO/yeAUfBp78XlBhCgSgRl1C+P3x79LsJvlDAO2l/rdOgvdnvWYiru
         /OdsGSrA5N3CdOPBbfUpGaGOLEm5YtmnOb0V3IOOKvpsm5kbI+t4v7ckzOH+jN8ppIOu
         +ia+IG3nH3JvwdKkrqd+0nYTfn5Up58whORoBYyY2esx6JT66LONEFqJNQIX5POj1RNn
         ur7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FntJC53E;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VikX96bw2r6JEzKcC6Hvx9gGW9tnBdPUOX+zJ7C10rQ=;
        b=pjYOWrIs7mpYi7PXl0RdUU6xUjl0iaMnr0rONDialWNXMT50t7WGFbl1RVL4GbLmXy
         4hg6gn3KzSj1sJZ8cZwug4+DHPiZOA5KGd4DswNgDpix1JbwRYzsGpW7R9WcLYp9kUWl
         yV6DWImiivaWLsXhEo3tAazb+IAR+Z7XamQRcMQEOK5kfkAl7jJzu7sltq4VsxFoI+J7
         k0O76PxlDwuHi8MX3nxEqJI704t/HPnzMyYJ91PbHuxm0kZo3GS2vC33HU9hBDWY4zq1
         nJ7hWnr9PbB3YFdm41kT0WO6LgYS3jQ1F+fF0dXJzQWMhO58ZnjImFRvAOV82Wnz+Fyb
         vDlg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VikX96bw2r6JEzKcC6Hvx9gGW9tnBdPUOX+zJ7C10rQ=;
        b=p7sp9gyufRJXazS7TSnQfWm8x42dM1fMfN05PG/Wu18LqGDrnkEsbR/qJTuw78UpcD
         JQPABo09HPsguqqjqBsNG3uR9nQZQ8k4gOZEfel9W5rZOcnPfs75SbUsPIcdMIcp4E4F
         NcSMYejA77jqQEruPnyxAwgoIwFhRL/XyXYzO711fHbzurLW9/Um2Frvycwk+WoLiZW2
         5dwmYYCIbx0Q7xuTD+32nLdxWCyqoE5UzUwBSrMDT29TH6cGi5n2DossLzVSTRoGsi6V
         ovFR29QIYWMoYC7aiTcwdF1W3iXxDCBRp3h4X522RJH9wedJd4e+bz+qKAy5DwULqADQ
         +UeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VikX96bw2r6JEzKcC6Hvx9gGW9tnBdPUOX+zJ7C10rQ=;
        b=JH/3jZV1jYXlz0NmherZXEPJq2f+vGiSBkbvCuAv4XNFggAdRIh80S0IgLQ9aq4AMl
         gU9o3+iXFUQoSvtqXb1f70KZR5sFZfPqZ5HhMWVubLtmlKnBxrAULwlrYjAk7aX4JFow
         +M4gKThFZIptwjk/LX1BHBPgQ1OyTVQ5t5DEnd66mRQ6LQERr12YUxLfN0MP0wS6SzHN
         4ih25wz0P3K6ENEmIuWg4gizadFkCmbp5ZtArZPzC+IYm2RK1Wmuos6ZRFT0Ni9AaBPW
         K7br4rMI7BXGHRbeD9VZHO7YrKMWkHhAu2PSURSTUkgaq0i+yk/72yQshHUyjqn50qR7
         tKgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YS8RegM8P+5wRJZCkr/aTgDXzqOMfsQkpvLyCucRzgWplBFVR
	C1waq5ABJRfCQz6zWnEj0dc=
X-Google-Smtp-Source: ABdhPJzSrkr1fmuBD314M5UcDX3680MRh8Lv8IyHS6z2zpmJc1XwLNxZKAlT/200gMxtcJlRBSdx3w==
X-Received: by 2002:a05:6122:7cf:: with SMTP id l15mr1545004vkr.27.1643293498605;
        Thu, 27 Jan 2022 06:24:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d111:: with SMTP id u17ls1023509vsi.4.gmail; Thu, 27 Jan
 2022 06:24:58 -0800 (PST)
X-Received: by 2002:a67:3341:: with SMTP id z62mr1635612vsz.70.1643293498118;
        Thu, 27 Jan 2022 06:24:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643293498; cv=none;
        d=google.com; s=arc-20160816;
        b=LS/yl1K2uT4PeiQo1M1V3dQ64MM9MNQu5anqd0Kr5E03ZgbUwmYeaxAgBi8X5aOM/9
         BQDPj2mMEd6Pis2Lh0UoAQPzP4YOfQ3nG6cMFNhrF7pnzteJbMzAbiMDRZ+iqZwrzM9n
         nAMJUWBb6OY0EDIHkVnw4jhTdHE/IiT+RTPEJz2WTfQoNNxF8q6z1l6c84pYbBI5a6Ru
         IzdP2IvADe6bgdVf4F7sCbM/WB7d1ndGhHh36eUfRV0nNx8Z6GFvHphEt0ogl1ibchpK
         Sk3+wcQijOp9tt4HlYg37ueX1GBoMgrhYeHByZq9d6wgW5ItSo/6vdoTNR3omLm8Uc9r
         x0XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FezwsF5GfO3GymnMg24LAESoR1ooXl9Ccmmz2bdgDaY=;
        b=nShxWIq6sanY2ozOCOAWLX2r0lGL4Lg6nPFyDx8lNazj97TO3B4vOD3ECnDRD2fvkc
         9QxZhZ7u2tb8A27VkgOvbNeudTr38gsrpEv561dtanpbykDKp/ZhNZYzRqiWMuH/HhRE
         PyKeaHu03R+1JuHgsC7f9v4IuPBT67Wi8P+AikyIVuZNqfW0QZBBirrbRTPMddXgqmC7
         HGqIxPVG4KRWmc6yGdVSR3mFJ6mz4VPxiumgIVq08o63jBDujp9B/yaLiwgAC5l5kb37
         DTMTBOpsNaeEfZzNu0ypQoxGWpyT2DnZ5qtCly7LTf2p8+nm+TZha1Y72p1qMAiMdREA
         W7Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FntJC53E;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id x11si85421vsj.2.2022.01.27.06.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Jan 2022 06:24:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id s18so3696233ioa.12
        for <kasan-dev@googlegroups.com>; Thu, 27 Jan 2022 06:24:58 -0800 (PST)
X-Received: by 2002:a05:6638:102c:: with SMTP id n12mr1859068jan.218.1643293497579;
 Thu, 27 Jan 2022 06:24:57 -0800 (PST)
MIME-Version: 1.0
References: <20220126171232.2599547-1-jannh@google.com>
In-Reply-To: <20220126171232.2599547-1-jannh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Jan 2022 15:24:46 +0100
Message-ID: <CA+fCnZf0=RNkR0JnMSq-0xYUDf=rcUk0oMs_ySed6LaZtPAQjQ@mail.gmail.com>
Subject: Re: [PATCH] x86/csum: Add KASAN/KCSAN instrumentation
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=FntJC53E;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
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

On Wed, Jan 26, 2022 at 6:13 PM Jann Horn <jannh@google.com> wrote:
>
> In the optimized X86 version of the copy-with-checksum helpers, use
> instrument_*() before accessing buffers from assembly code so that KASAN
> and KCSAN don't have blind spots there.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
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
> index 189344924a2b..087f3c4cb89f 100644
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
> +       instrument_write(dst, len);
>         if (!user_access_begin(src, len))
>                 return 0;
>         sum = csum_partial_copy_generic((__force const void *)src, dst, len);
> @@ -51,6 +54,7 @@ csum_and_copy_to_user(const void *src, void __user *dst, int len)
>         __wsum sum;
>
>         might_sleep();
> +       instrument_read(src, len);
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

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

It would also be nice to add tests to check these, but since we still
don't have tests that check atomics [1], csum tests can be added
together with them once someone gets to doing that.

Thanks!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=214055

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf0%3DRNkR0JnMSq-0xYUDf%3DrcUk0oMs_ySed6LaZtPAQjQ%40mail.gmail.com.
