Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF6R6CXQMGQEHFNGO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6273888591B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 13:31:21 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2299abdcb65sf1080085fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 05:31:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711024280; cv=pass;
        d=google.com; s=arc-20160816;
        b=qSsZQNc4om6zsvO0enAtLsNRpD1SQxUxNKyENkWuUuBPXf9x93US6vpiZgdFhUNXp6
         CtPxq3wNiK3SDeA+8SYrNnOuH1CoU7SQciuEDhxpE2nqCvS3BsVGh4w72PKa0DTsCUMO
         zmouWEhWAuXFciaG+bLgqYD4aBdUcQOPGwTLA8wZcBeVIeBjDKiWdjkBF/YxgTMI2Lak
         HbnkuTVPynFydthwquMmXG4MRdbUCcBW0qL/pCg5msko5lIzMq1lpan75YOK8mPPnIFu
         +TsPPiF3YMU9SwPtEBMAncOqZWQJD7bzFIiNq0G0Tcm1DbwNS99BEGZh/hUCqXNLSzl0
         Q3hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Aky011m5Y6VTsBQsnZGSLsIn2xyJd6qhYj8/oxpv2A0=;
        fh=e0BHmPXmWaigopdwTzA99biimWToeM/rxqpwUmV4BVY=;
        b=i0VbS/rtMyF5JgXP9HxTP0VP8ly9DhXkBV6BSi3s5d3B4GYfcKX800NJvJ1DM4D/n8
         CZVSGt3DDouEgbZ1WYL6hzev5EbSOUnp89V8xiee64aqR01frZcZ/onpHtFbmzGlJhnq
         n3cYIIev2I7b8dgw6jVmsEEiOo1mhSMoMm9tjeOQ0XJCWIP+8CtlEUs8cjxsYPuLU5sX
         DR4tCgKKvK/FGFylGBZ6Nqlxw9lkT756qsqJqZri2+HS5SvtCwztVC9FtAqfnliYZgbD
         tBMqplW5M6KIQjo/DDFMOJwM0EmeTGVHyp3qVBqY6ySbep82jC7eOfW8SO6tz7a3yfyJ
         BWyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PoN1MhKP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711024280; x=1711629080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Aky011m5Y6VTsBQsnZGSLsIn2xyJd6qhYj8/oxpv2A0=;
        b=IZCmtfpUlOBEh6Qoy7rhRXNsUcHF74Zz6wimp0X35dozt5bSqc5IlEbA/LgBut1yY0
         mA0cb7fndUfuZrnsft+dvG+DEKgP90BV+qUICXP+tVsKmjN2wN19yF+J9LllKlettGED
         J6v63FPG1anA5dW1B4FWtTtnEUGtbnAKafwiavpQPSzJE8ylhed8r62sBFpf6pzYiYrq
         +YlYc/nP09zTFp3futBjkErGrcP9WUNH7FaxFf+HJxtATZQffrpu4c4eTN0gfoXTmx8R
         1gaAqJs1WRVFQPjTdyLQyGj+gITunGycTfUg/y+WZJXWHriQGzUjm+Dg3jWkh9DkxL/D
         0Qtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711024280; x=1711629080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Aky011m5Y6VTsBQsnZGSLsIn2xyJd6qhYj8/oxpv2A0=;
        b=EQsOdsI2vCWlgSICxucyA+rEi6rngJ9I2kzWzFOalDEVkSZythCVwVQyOLLSUJxVMG
         mvxTuuVi2nL6C/R+q6iauix49AQGdTdGlVAHEZIYMa5RNw16LrraWMzRGYCci8yS5oWX
         53XwgY1eTOA9F6APNwmo5PFFLg+ubs67aVQCmmTeAiRKgNXRoKmDmZ8u4A6SqnK52DA7
         +B9YEQUbCF0xYhhzzWB/lzlKg/3rTeL/6uHRmIjK3uOf49W5Jp7fmRasq050Xze5IL3y
         Ibzlk9oekMvWlX1LZjriqv6rWeT7aeLzjdcDKiH6qsfs8kPS6/BhxKhCwbxgQr3MB+hZ
         WbxQ==
X-Forwarded-Encrypted: i=2; AJvYcCUuKlJrFroHmCUhXkxn/C2UXIVaxJKVCJpyPaFScuRne5b6RpUStUWbVfZ0Vb7FW34tXlRruiUhvr17yVGc8nA7FpywGZy67Q==
X-Gm-Message-State: AOJu0YxGMSqysJB+NIRlPTRFQX/d5Wsr9P+HR56Yoco6xUQx+7QM3P8P
	vCVbvb7Pp0qWkDLggM4lJPdZpOKMvvQXyQp/ibdgHZXLjEOMowek
X-Google-Smtp-Source: AGHT+IHcvOBe0j61cdIWel9aDr2UIMIU4UGkeEEL0fyRgYvaZxZF7oNtVEBcrc+KKXXiSWw1JvP+zg==
X-Received: by 2002:a05:6870:c6a8:b0:222:d78:14ce with SMTP id cv40-20020a056870c6a800b002220d7814cemr23704852oab.48.1711024279994;
        Thu, 21 Mar 2024 05:31:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5c43:b0:229:bae2:4503 with SMTP id
 os3-20020a0568715c4300b00229bae24503ls986055oac.1.-pod-prod-01-us; Thu, 21
 Mar 2024 05:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZjlIiGAckc2GA5zpZhESdB5KYN1WNvoG/X8RFYaH5oADpOXNibjNmBX83QFTo/I1QcTUt3sAcB2jdMs/CBnq1zxFrfdjCWSFuoQ==
X-Received: by 2002:a05:6870:fba2:b0:21e:635c:a5b9 with SMTP id kv34-20020a056870fba200b0021e635ca5b9mr23545793oab.52.1711024279200;
        Thu, 21 Mar 2024 05:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711024279; cv=none;
        d=google.com; s=arc-20160816;
        b=D+ld93LxHVexvBS7ANmeXhoXebHBhD/KT/3Xr4f3SB0SkStI5qG+0LVR/wLoU+hQl6
         XIeG2J+UqF0vbwltIhCN6/ZLoFueK7VivC/JOQ1fENai8Br3W5A/z0b4VbEhkcVhhxsj
         ET9zl+4DnS+K5jPw52W8wkfO+659vBkc1YIf84FcLJjM8IVPK8lN1bvQcp+smWP8r/O8
         ukejD2hw4CXXA0fzUBtf4QzP98omz1pYhbCr6U+WWfReY4XDp/ahGHZkXkA2pZhKaiyY
         8UYp8CljzPLSsjLUPGiAHoVDpAkfXddj4akQxnQn8GyWSShTlRXkJot6CTPkRg0RTtos
         LkhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B4nWxDL2LITioaRby7yvh7M2SRX3O9JMXDxwR9Igm8M=;
        fh=CVXLXVLnVdAGXKOha+K9MR/Thrd2edPLGntc66SnUGs=;
        b=k+juoUFwdxnLEMZUQSyo5Tvh2H2rNXmh7ASGIMjo53yTV0AI7Tde2dH4aQyFcMb7wI
         Nw7n1dC/66DSxdI09AaMdsHx6AMnwtLLJ6uM/LVpxPttjgQnQZb/FYew64JBob6qLhFM
         N6Xk6jcTAfxrKrEAj0b2ZztmqjeLAaLkGie3x2Qiim2xeBZRPmoCMgDnesUCJML0Fbis
         8RDX8hM1D8NxieVTMseIhEaZi8NHf8NYzQC+GRIRM5GKK0Y1StZi3Zh7NVg4YCU6lGhn
         WRwf8ABr/Sk0Yz+AQDRCxi3zswSLXJcHEPOOThT+Sw2bwK5t/zJR0b7TdevPQccPjP2d
         8KzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PoN1MhKP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id kf10-20020a056214524a00b006965f40ae76si29879qvb.8.2024.03.21.05.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 05:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id 71dfb90a1353d-4d453ae6af5so416146e0c.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 05:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVAFPd9SvIj5OGM/ZHvX0w/8jfnoqKVkNaxO1TuMy+9NyY3uwJEX+6cycpJpeH0KsJksUKAf5hpJJX4M9BH12XzrDrsEzYwNXn1GA==
X-Received: by 2002:a05:6122:c85:b0:4c9:f704:38c with SMTP id
 ba5-20020a0561220c8500b004c9f704038cmr19496827vkb.11.1711024278613; Thu, 21
 Mar 2024 05:31:18 -0700 (PDT)
MIME-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com> <20240320101851.2589698-3-glider@google.com>
In-Reply-To: <20240320101851.2589698-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 13:30:42 +0100
Message-ID: <CANpmjNOetpgqju_ujuEauY7HZ_BbFUz9ZeBHc6M6aWe=hYu7=Q@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] x86: call instrumentation hooks from copy_mc.c
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PoN1MhKP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Wed, 20 Mar 2024 at 11:19, Alexander Potapenko <glider@google.com> wrote:
>
> Memory accesses in copy_mc_to_kernel() and copy_mc_to_user() are performed
> by assembly routines and are invisible to KASAN, KCSAN, and KMSAN.
> Add hooks from instrumentation.h to tell the tools these functions have
> memcpy/copy_from_user semantics.
>
> The call to copy_mc_fragile() in copy_mc_fragile_handle_tail() is left
> intact, because the latter is only called from the assembly implementation
> of copy_mc_fragile(), so the memory accesses in it are covered by the
> instrumentation in copy_mc_to_kernel() and copy_mc_to_user().
>
> Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> v2:
>  - as requested by Linus Torvalds, move the instrumentation outside the
>    uaccess section
> ---
>  arch/x86/lib/copy_mc.c | 21 +++++++++++++++++----
>  1 file changed, 17 insertions(+), 4 deletions(-)
>
> diff --git a/arch/x86/lib/copy_mc.c b/arch/x86/lib/copy_mc.c
> index 6e8b7e600def5..97e88e58567bf 100644
> --- a/arch/x86/lib/copy_mc.c
> +++ b/arch/x86/lib/copy_mc.c
> @@ -4,6 +4,7 @@
>  #include <linux/jump_label.h>
>  #include <linux/uaccess.h>
>  #include <linux/export.h>
> +#include <linux/instrumented.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
>
> @@ -61,10 +62,20 @@ unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned
>   */
>  unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
>  {
> -       if (copy_mc_fragile_enabled)
> -               return copy_mc_fragile(dst, src, len);
> -       if (static_cpu_has(X86_FEATURE_ERMS))
> -               return copy_mc_enhanced_fast_string(dst, src, len);
> +       unsigned long ret;
> +
> +       if (copy_mc_fragile_enabled) {
> +               instrument_memcpy_before(dst, src, len);
> +               ret = copy_mc_fragile(dst, src, len);
> +               instrument_memcpy_after(dst, src, len, ret);
> +               return ret;
> +       }
> +       if (static_cpu_has(X86_FEATURE_ERMS)) {
> +               instrument_memcpy_before(dst, src, len);
> +               ret = copy_mc_enhanced_fast_string(dst, src, len);
> +               instrument_memcpy_after(dst, src, len, ret);
> +               return ret;
> +       }
>         memcpy(dst, src, len);
>         return 0;
>  }
> @@ -75,6 +86,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
>         unsigned long ret;
>
>         if (copy_mc_fragile_enabled) {
> +               instrument_copy_to_user(dst, src, len);
>                 __uaccess_begin();
>                 ret = copy_mc_fragile((__force void *)dst, src, len);
>                 __uaccess_end();
> @@ -82,6 +94,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
>         }
>
>         if (static_cpu_has(X86_FEATURE_ERMS)) {
> +               instrument_copy_to_user(dst, src, len);
>                 __uaccess_begin();
>                 ret = copy_mc_enhanced_fast_string((__force void *)dst, src, len);
>                 __uaccess_end();
> --
> 2.44.0.291.gc1ea87d7ee-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOetpgqju_ujuEauY7HZ_BbFUz9ZeBHc6M6aWe%3DhYu7%3DQ%40mail.gmail.com.
