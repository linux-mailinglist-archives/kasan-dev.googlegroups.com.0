Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYH7VSBAMGQEUPCF5ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07EF23389D7
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 11:18:10 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id e188sf7047716vke.18
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 02:18:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615544288; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZ9uhTCo50OVq8m1bw3aiQvR3/hVQazqQ5S7joBiYW5rOht6TQhs8YmAG6jp31gStA
         AcPzYO0N6MPXRMNSpp7dDZL4BO+OCPgP1s0GMaQRgBaI4wnsXrnXfSTbSYUqQsSjuQKH
         vtW8kWVFJpO4J+k4vIlinbo1b2jEnlQ2bu5CpZdf2Bn+evMF0IeQDtPAk6fM3hqcePrB
         zW5Kh9dekf7O9fyUJ06EUKtAnCYP8NRjEMFwvylkEzCZ/8Q3wqOzmYldlNGwm9R3NpYB
         4qAAOb0XjLevTG40h02/xGFQtO3yMlBUDYqj/dmiiPRNsuQa43/aDypQHfASuAjWPUzi
         nMTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LEgTn4GvUogMixBZKLXtQQM0VQ/LcXROhz3CGn9qkhY=;
        b=uav8Isw0kJtZt7sJHFMB7r+UO4VDy/6AnwMQ8iQbxR7W1J88zCrb6pN+gVBfBKeuSn
         +SMDHX4fcyx23zFpJNH6E3tyc5CPafav+MT8aA2JvPxc88LjW2Fi45AfHdGoWdX4Ii7+
         FoHlGDiVZlAKVOHZ27XJp8vXAH1kmV62I9ML1W3xjR0OGrJpkM3V8a0z5m48aDJCSwzv
         sDDlvWqo4XkHvCUXTDW//kvA9xWhy3GCywHpo45Sy2hfCMlLan5GtdV1YExlmWLtKz5D
         2EjlqGXV6xAmGUJxScdsOeeUCs/BcBQ0vj/3vCSXhS9vgmbr94GJZyISHVc4vsURO8Ng
         wedg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ou5hyZQa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LEgTn4GvUogMixBZKLXtQQM0VQ/LcXROhz3CGn9qkhY=;
        b=RE9DLbZpwp2bZHPYAen9CthSHIQXDG7kTIxdpUVpX15xo7pOteQouYiq6MP3s3OG6S
         +zpz72ySBgj8OvRgz2RtPo+n4upkLBDGuiSYVNr9Vo/7608/4RtD3KCos44tRm6RXS+Z
         /WTBkjbz8SZewx7BWEqiCJt+k2UBPQGm3OmVOuIf0Ued+TIoWfmhZ7hCjx1LtgvBbFWW
         k0qpGtI5aPW0suy+xf+zJaRYiohrJZn7dk9WNPNkxyA1YD9AfMwrQQLO74fK1drc4W5J
         Z2oUatxpBAxl4CtUZcy4ZTlp7z61gaw0hTGcGuq/uj/XxweosgDj+esatvrDwIrc7r95
         9hnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LEgTn4GvUogMixBZKLXtQQM0VQ/LcXROhz3CGn9qkhY=;
        b=bQwZjD4UySLyaBhbivGGho44hz36RV7pNhoPmdTfVdpgwOOibc3D6aiy0dSGXxvh9n
         nsBYcvsnOvfcUwFYEXovCuQUZsz/IikrE1PfPqVdmgWInWaKsAQJnwNRTgEPjmONlRLr
         e862FmhbsTXvS5nCMP9Q7sH4Vtqk4GqPFk/SrYUhoxIX+0HdTB3or5wC1f9GBey7EOGC
         NEvTXzxmW1tiiT8feeedg4A+9kiP8ue6Wqzywicpi4BCHUgh9NKmknYsULARoCsEaOaa
         NBuiLd+oCNGLMAaBVpx+LkESYnzzjPigTq3TgAegUS7+BcaYSBYJdNEXhd9oJp8fQS1x
         N7Sg==
X-Gm-Message-State: AOAM530k+9QQdizIPttUNW3dJ1z2L3tidPTvand2/YmAiG3Pgyf7kcP+
	4c1uOkZYliZx73/DWV8AJkg=
X-Google-Smtp-Source: ABdhPJz/zcMzzQScOxm9dEheY13ABPwbij9qiv+QiYoGVNNgL4FBQ25rkVmZh/8ME+DyJ1HbK67g+g==
X-Received: by 2002:a67:ed09:: with SMTP id l9mr7958540vsp.4.1615544288702;
        Fri, 12 Mar 2021 02:18:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a98e:: with SMTP id s136ls458971vke.4.gmail; Fri, 12 Mar
 2021 02:18:08 -0800 (PST)
X-Received: by 2002:a1f:b686:: with SMTP id g128mr7016305vkf.25.1615544288146;
        Fri, 12 Mar 2021 02:18:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615544288; cv=none;
        d=google.com; s=arc-20160816;
        b=B7kTQ2XfPinCYqxrIv7gj5r84219Om+yTUh+WIgqcfxfee95nzIubjRfkB8D/USv71
         W8nGePwByQa4y00NHIomjRPNcmQ0JqfltoZ0J3bzMizCeODZB7pwc7WjBj1wr5wlQJh5
         08h3IESB4OyTfrAieNSomoFcAIRqniJ4622hckJ6y9Sp/xAMD2fhBfJV68E9oOCoITMm
         foIa2cKCO60ErcxGam+15uhItAETe1BvsSnHve0IhigMwwkCM5dXwG7m3TVmv6qjptI+
         7QAwT71rwNPlGvJM6yCyrIqL6YPh892BNmXRSFN/DAk9FnEH0llCi1KxhQv91TUaEZ56
         piTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P9nT1kdDzpw5kqt3CYTv0XonbOcWSwDlZvC3/pVxkrE=;
        b=tqizYbB0DNkDbLSnt+woVNihQok1RWDXYlk69GJ8ZF7ZuntZy7MNAMl+14dUd+MIKz
         leBj7MpZHYOu/gBbl1+t5sal//f5i0wLZr0vZQof2vi04IhWYGYIg1RoapUK0G7nlizl
         PkqgifQquuH7WdewC4ieYGg95hbucenGWOVMJdipAkCVBGKxlJseat02NEZxmCCHEQg8
         Svhj6tTA28LGiZCEdS/QGROyHrmD4G2uvV5h+QQ5P1jL8+ZwjohHfuLxwzsySoj+VyYi
         y2rQ31BeWLdijBHyZFVG/CWpKicVB3xheUUkf9r1e7Yru+Ps+o6sVKS5keUezFLX/v7G
         oTag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ou5hyZQa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id i8si317748vko.4.2021.03.12.02.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 02:18:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id o22so16581658oic.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 02:18:08 -0800 (PST)
X-Received: by 2002:aca:530c:: with SMTP id h12mr9374370oib.172.1615544286829;
 Fri, 12 Mar 2021 02:18:06 -0800 (PST)
MIME-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <da296c4fe645f724922b691019e9e578e1834557.1615498565.git.andreyknvl@google.com>
In-Reply-To: <da296c4fe645f724922b691019e9e578e1834557.1615498565.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 11:17:54 +0100
Message-ID: <CANpmjNP3bHe2h1=-W7r-64Vg9vr9vREzY0M97uh_QRDr3tVEYQ@mail.gmail.com>
Subject: Re: [PATCH 02/11] kasan: docs: update overview section
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ou5hyZQa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Thu, 11 Mar 2021 at 22:37, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Update the "Overview" section in KASAN documentation:
>
> - Outline main use cases for each mode.
> - Mention that HW_TAGS mode need compiler support too.
> - Move the part about SLUB/SLAB support from "Usage" to "Overview".
> - Punctuation, readability, and other minor clean-ups.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 27 +++++++++++++++++++--------
>  1 file changed, 19 insertions(+), 8 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c9484f34da2a..343a683d0520 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -11,17 +11,31 @@ designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
>  2. software tag-based KASAN (similar to userspace HWASan),
>  3. hardware tag-based KASAN (based on hardware memory tagging).
>
> -Software KASAN modes (1 and 2) use compile-time instrumentation to insert
> -validity checks before every memory access, and therefore require a compiler
> +Generic KASAN is mainly used for debugging due to a large memory overhead.
> +Software tag-based KASAN can be used for dogfood testing as it has a lower
> +memory overhead that allows using it with real workloads. Hardware tag-based
> +KASAN comes with low memory and performance overheads and, therefore, can be
> +used in production. Either as an in-field memory bug detector or as a security
> +mitigation.
> +
> +Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
> +validity checks before every memory access and, therefore, require a compiler
>  version that supports that.
>
> -Generic KASAN is supported in both GCC and Clang. With GCC it requires version
> +Generic KASAN is supported in GCC and Clang. With GCC, it requires version
>  8.3.0 or later. Any supported Clang version is compatible, but detection of
>  out-of-bounds accesses for global variables is only supported since Clang 11.
>
> -Tag-based KASAN is only supported in Clang.
> +Software tag-based KASAN mode is only supported in Clang.
>
> -Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
> +The hardware KASAN mode (#3) relies on hardware to perform the checks but
> +still requires a compiler version that supports memory tagging instructions.
> +This mode is supported in Clang 11+.

Doesn't HW_TAGS mode work with GCC as well? While the sentence doesn't
say "exclusively", the mention of Clang 11+ makes me think it's only
Clang.

> +Both software KASAN modes work with SLUB and SLAB memory allocators,
> +while the hardware tag-based KASAN currently only supports SLUB.
> +
> +Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
>  and riscv architectures, and tag-based KASAN modes are supported only for arm64.
>
>  Usage
> @@ -39,9 +53,6 @@ For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
>  CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
>  The former produces smaller binary while the latter is 1.1 - 2 times faster.
>
> -Both software KASAN modes work with both SLUB and SLAB memory allocators,
> -while the hardware tag-based KASAN currently only support SLUB.
> -
>  For better error reports that include stack traces, enable CONFIG_STACKTRACE.
>
>  To augment reports with last allocation and freeing stack of the physical page,
> --
> 2.31.0.rc2.261.g7f71774620-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP3bHe2h1%3D-W7r-64Vg9vr9vREzY0M97uh_QRDr3tVEYQ%40mail.gmail.com.
