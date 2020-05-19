Return-Path: <kasan-dev+bncBDX4HWEMTEBRBN4USH3AKGQEBQUZVVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A84E1DA32F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 23:06:00 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id b7sf1384330qkk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 14:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589922359; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7Yu1tTFZL7grGTgmDytTQp9mdS1v+PKr4iznzwI4TeHyl8Jg8Y/TbwxRqDEH2SyaW
         iNKjoEXOfhgsvhHkZO06tVSRf8yfDa1TumEjw6/kWzecbsRNI6jvLz/8LL1EB0Y5wmIj
         GAHgugC91K4ApWcp0KgJJdCU+erA+KbNOGCCvLKS7SckdBwE0bc63G47/J0xl+//UkxC
         dg59vXOoHUM3vQuIqcSG/l7Lcp4rXPBJpiAA4L6F6BmOaXzsojf4YCnMvIrXoOZZxx/b
         2ZLYXUzSBiPMXJeFPm+aj6TYU5t1LiSPOX6i64qu4DopsrD6ilg0+uPvAyirFS61jyAl
         VQvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tRv25rBPB68VvFnZyRMotrTgG9wzVFEU7I8D8N2uP4k=;
        b=vFQqYc+v+q9yGEEkmL52ldZNIpS0WvDo3/aYCzjjM92iGPuyg2NNUkvJn1W53n5vSy
         5/Yu8+/DkqrWdClyxqM8y/PYHL66toxzaaM8IQTpfZ568YnzUlwKqarTUP+sSXW9SbUI
         3EEaLvQ0WLHKHiPrAN+44o8T/3SKmn8pfHxRJmbzU52JvAirDldk3Jqm0cpYN12e3Duv
         JmRsXK1SVQJXoP0aLWnC32ElVfRlKPP/C51m70bZA8HTKB/2q2bCsoT96pSEIzsArZdA
         aOdJsPwdukYMIPHmnHh6eOoMsci5QRkt5HJqWADM+GV+ij3m/GXydfLoClsNsDqAGQk5
         cCvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JHczdhHq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tRv25rBPB68VvFnZyRMotrTgG9wzVFEU7I8D8N2uP4k=;
        b=lHt9D9vV39mpUSOV0lI/Rlx5Tl/UBoqf8D0X/CIulcMNLZbreon1hVxjF+yLjCXOFF
         kC3rS37ZCMt5xmz3oCKC2Y+XThbK3+kSbti2TFK+aMtkfDROwfJGLxI65y7DB0Rr3n7G
         WfnhH5Jae0sQQYLT/d/qBW7SVOHzW6RZfDKq68QsIf+D8Jg3ELbkXLZyKaXV5gFitmOL
         sjCEh8d7Am5Ur5Hj48i249CMGliH1jeEKdFBO/A3YWQZAUmElFgZLrGxYyaH0mYTxkvG
         26eyP1ZJmcmgsTWZMSgiYTICIC1Tgek3hT7QvYdMWOTvj559pgQh+w+0Z+O7qZ2I4IBZ
         IbdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tRv25rBPB68VvFnZyRMotrTgG9wzVFEU7I8D8N2uP4k=;
        b=HMF9e4sSWVxEp+hS0fSCu8zX6VCqqCupgLBfl4wNXTbao3b7gqH5z0qAjy7Zg1udF6
         Q/r4bYKCXbpm0zLJYvQCXDZXAj/hlYIoLUsG4G4NG0oMmqmrHz5xWre7lUhDrs9Di6cC
         0sSlamGeGEmfOXLNKCq3sqOimbVIIVlUGPHm4Ca/h8Ka2cjFfIw4SxCI9BkjgnNGMr+j
         JaOz7ccVr1Q1Oui4Sc0K0PbxQBYaqDMPLcNI5yTj192FeS7Kji23D5MEk0QnFj6Te2Cp
         LuaMUGpq8sHGVU5+8jqDzlJHKTUlRMenRTE4/B77/yy/GAeumzXR/ECg4b90SI7SI5c3
         nDrQ==
X-Gm-Message-State: AOAM533xD23v5niCVfX50Gbdss/ADIfCMz5+9AVARvMhJTIZgs09Kebx
	4LSiGUCAGe54qYQ7ejKJNN4=
X-Google-Smtp-Source: ABdhPJwhGj04OkkXdbqmfCiMFongmqb7Mod282HLGUMBN3pvDK3agl9Ibw4NAplKwN7h5Td0eQ/DpA==
X-Received: by 2002:ac8:82b:: with SMTP id u40mr1895966qth.369.1589922359366;
        Tue, 19 May 2020 14:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:12ba:: with SMTP id x26ls547578qki.7.gmail; Tue, 19
 May 2020 14:05:59 -0700 (PDT)
X-Received: by 2002:a05:620a:146a:: with SMTP id j10mr1476684qkl.333.1589922359046;
        Tue, 19 May 2020 14:05:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589922359; cv=none;
        d=google.com; s=arc-20160816;
        b=VxVDdtexEe5k43D7ssHK2yPE+54jSYPX2DU017WiyHTQuqkdWnnniPGbIpyXmsvLiP
         3Xn9WpIUW9VI9EUfEXE8gFGqtGFqFt3GKG4vfKryfRFzJShmNpX99/4HpSdXWefn/4aa
         lRRTx1yaMa/7XFJno30PduWiyzw1cq5om8cMNYQd+DoF5IIVlgw8HR6hqc7y0gboaUXG
         TxCGwdjKuyzHxUU+Eq+Lpzccwkpgjx7Qrqw58WRkU2vpIg078SH5d5Yw/Qt93DBrwpPW
         TENmXpzGh50g4YnsplbqMhPIWHkkCmScuLZRZmjbdJf/j10+oV4WyPyFSkiKjsfX6abU
         2UzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FAwUQNuHSy6Ybc5wRFORWg7jUHg+WoIVkThuFrr1qaY=;
        b=qoo/VkU8+TyrSiEA3skQoxy/eoTaTfLHE/MYeDhBiSBdW/lnS+f+jfC8FokgusJj+w
         FIc+Xfp9ENtTYGvda/AT86C0Vqoy7kpQwsewkw9zks1IQ3TY962lLEFGbCD4KmQ9cjga
         oEiht7GqGKIt5Il7XzWU69TriJ07BZieAT5fuFSPX1Z1Uqdx8eFNQ7koGokAfZk7FwP1
         ufTih4WzPeUqX83w1aErpswqqOwD+UAnZERoqus+fE8bZJY3kUyyAgxbDZpGtOlVAg1W
         svl332U21vvY+aTWX72ao70sIJxveN7e1y4Zp89JQKfjMhVls7ltKPk8TblE5HzDSm1u
         Q0IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JHczdhHq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id h15si64781qtr.4.2020.05.19.14.05.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 14:05:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id q8so479854pfu.5
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 14:05:59 -0700 (PDT)
X-Received: by 2002:a63:2bd3:: with SMTP id r202mr1039983pgr.130.1589922357767;
 Tue, 19 May 2020 14:05:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200519182459.87166-1-elver@google.com>
In-Reply-To: <20200519182459.87166-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 23:05:46 +0200
Message-ID: <CAAeHK+wcrmo=Hhwvqzd8kC-=5UR+fzRcA_4mo8wccWCTdrEzEQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Disable branch tracing for core runtime
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <rong.a.chen@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JHczdhHq;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Tue, May 19, 2020 at 8:25 PM Marco Elver <elver@google.com> wrote:
>
> During early boot, while KASAN is not yet initialized, it is possible to
> enter reporting code-path and end up in kasan_report(). While
> uninitialized, the branch there prevents generating any reports,
> however, under certain circumstances when branches are being traced
> (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> reboots without warning.
>
> To prevent similar issues in future, we should disable branch tracing
> for the core runtime.
>
> Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
> Reported-by: kernel test robot <rong.a.chen@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kasan/Makefile  | 16 ++++++++--------
>  mm/kasan/generic.c |  1 -
>  2 files changed, 8 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 434d503a6525..de3121848ddf 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -15,14 +15,14 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> -CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
>
>  obj-$(CONFIG_KASAN) := common.o init.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 56ff8885fe2e..098a7dbaced6 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -15,7 +15,6 @@
>   */
>
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> -#define DISABLE_BRANCH_PROFILING
>
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
> --
> 2.26.2.761.g0e0b3e54be-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwcrmo%3DHhwvqzd8kC-%3D5UR%2BfzRcA_4mo8wccWCTdrEzEQ%40mail.gmail.com.
