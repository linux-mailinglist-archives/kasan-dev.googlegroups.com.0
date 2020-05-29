Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKV7YX3AKGQEUHRYERQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7C4B1E8775
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 21:16:59 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 99sf1681229oty.6
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 12:16:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590779818; cv=pass;
        d=google.com; s=arc-20160816;
        b=bd9WZsGIIKACBV6aAno4Bj0N8fpmdcO3N3lWUB9Fl+SYEm0w1i0OYodanDHGKXEr4h
         o4ttgbs0ehEAJGnKyN3kvSl3cVvGiHSGXOm+i8yKzZ3502MYqcy3HKMSUWFPKMm6uFdZ
         rrxt/Y1ufhcHGG296iRrAeZUD773gfk1D3o1Bjb7QBYSSDFQdFn+Ze6xFAbR5vTOoE66
         BiN6KwvIe+OCUYQbZV0TadShOz2Y1hLemyA2mqYJNivnCEQEI/XWQD71/029cH3dsK4N
         Ohc+HrqzDkCxoqmi4NGqTyqspz53J+ugx4tIkIa8502OoybB4YoKVJJhBcz8Os5QRps1
         i2ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8TekEI8iTF5xUwViA1LYx8ZP/ih3lJBC2Mrpji7g6vI=;
        b=ja2WY4yJM9QKnmdjnUbg0HskthM5g8ikgElbJrmNdjIzZcMVCxgMV4T47/eZNGsoeH
         CUF4RhstT2DolyVrbOb8Ir8mzjLzUmrEAyrRy3YtFzeQ+1r8uW16fA1unDjyC1J9CGhj
         /qPd3J217ckv5TXhMi3bHOpfy21C+bnxRMrT6KJH3i8ERa2O58OEY6Ncei+24bPbvHtK
         emU/gTaD+8TgZhQkEvqDAJbJJ0SNT7HM+5qA8Yp22b5NaPnqeZmL6JUy/389R/T8NykA
         QWeA5eD9VDoORaeB8JBDPoN1Zqu2UiW6QAUzUJB1d9siCSXNES+fD/g4SQi8lK6Lry0P
         o4yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sqaXB7Zj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8TekEI8iTF5xUwViA1LYx8ZP/ih3lJBC2Mrpji7g6vI=;
        b=hkhNmz8UXSSE10eQqB4X1xFcSQgjd5F8SGIZj3b8TYschBpMKYJ6gSx3c2NOEiRaEr
         +dvFMvL0afEYjOP+fEaytj4LY6fKNyDIq+nxAr7HVbIFe/pGWVzIie6LrSVS0qqibRN8
         5O3ePivVX6DAeI7Uj+lXcefEK3Wfpf1SXSpHCW45kNH9LweC8pjQNG3r5fUABUHQNoDH
         wR9kw5EWFsxBGZ3WX9YM3csEwCcr4P8YibO12pkibiDcV75JO3gNLehwllWPCiFjGsjY
         f28C7O/pwrQDEywJ2fmHx/zJot/wrsr+jrW3pmhq32iE3T02AW/dAYuZGezfv8yrbdkT
         /k9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8TekEI8iTF5xUwViA1LYx8ZP/ih3lJBC2Mrpji7g6vI=;
        b=EM76UH/+hDCXOgk6zNgGokeIMH69gGcahktLn+GLseVIkBxN0LPOlH+YL6hTYRPsHt
         HjtnAelURUQV7yCeoH69SfFROkn5WE+NpO0HqsFwECREaiGoq8Xeab7nbmxVviInyAQu
         DjIjAxD15+TmkNrcHZO2MHhHHosXFxlXoKc6ghqg3wcaF+DjAU58ijhTjo8QJm3M8YrK
         Vl+ddupceWH4FDeaTON/p2xm7K9GHt6fQ1N86ZY+LbxeQWd1gNMYMer+Wf/hvfHj3ION
         W/F2MuWvD/DP3kO1s3hdxCEc/IYZd/jm7CHuxOiDZkHXG9cu4l1iZdhk7nPE3JKhJ7/f
         JvPg==
X-Gm-Message-State: AOAM533a81S1FNFPQZ/8o0MCO8yiyHhI0wfRjMtDd06tX48ELOu0vH24
	rq1kzEiBi7Q6/nZlDN+mZ54=
X-Google-Smtp-Source: ABdhPJzOd3njFcyprCOh/CmpEDaw7vCRWNccXZ8EVtgC1HfJCmJffl99hjWDvVvSBbBtV/nimrUDJg==
X-Received: by 2002:a9d:4c19:: with SMTP id l25mr5162717otf.193.1590779818521;
        Fri, 29 May 2020 12:16:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:61c2:: with SMTP id h2ls1462387otk.10.gmail; Fri, 29 May
 2020 12:16:58 -0700 (PDT)
X-Received: by 2002:a9d:705c:: with SMTP id x28mr7519532otj.180.1590779818050;
        Fri, 29 May 2020 12:16:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590779818; cv=none;
        d=google.com; s=arc-20160816;
        b=FYFblj2JpvIROykpL6ao8dgx5wniJHFCzGIFHsoXPTsQW6l9RiL7qp4W84xlJkWpBZ
         fOzWNg7/8SkiMJY0NU6jCpC5qZXndXXuTlSulAxIMJcKNTdWjaG8ginOg22ICZWYqaHH
         U/WcTQ/5vShlCknPLExsgQVqclNlqvHWujyq4FOVHa6XO8E4gaD5T5VY8uijbc0sAcnL
         9Z1Dzxn08hQ+QjWJDQTcW+Cft81WGnRkLoeNoLaDAZxYBpZuRTcF1eApszkOYNJHI7b2
         sxXr45BAhCu92kdfYltdBI2CNVU6/ZeOWDaiDel2r0bOJBJslgH2ddKrTpsBeK9DrIVP
         d/fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Xc0lhcTiVdyNEJ9vgqNoCxeQd0IZqdiHS4mWcX+XOo=;
        b=OSe8b+w0Y8F5JMsNMTDS0IQjLmZBrRu/zGv0sk2htkt42Jgyjyuxv9GxUqfAivzPOO
         JbRdAxhn5r6qQhbg2+TGBGxp8VT9YOUCuxMLx2amM+G5rty01WdzChZ9b2GOqOfmGYAp
         OxNsN3BwH204pMOdGqbQCWhb7icMK5zLTl3f6o5zpthwJtITlNNBg8Jy+g+mfT4VOOI8
         fmN0/0VvxWYxUABs97ff6FIDEnOTyD/W8AWtYcEiyCjlPRn6ik0yh3aTnDdSTwYDLXJZ
         CV49ty18eweLNHUSXSZFTJMfm44x04mS0zYnAELcZdnwL4lf9eMQCNpst4SBKMJCmHF9
         fWOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sqaXB7Zj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id u15si968965oth.5.2020.05.29.12.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 12:16:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id g25so2758372otp.13
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 12:16:58 -0700 (PDT)
X-Received: by 2002:a9d:518a:: with SMTP id y10mr7801677otg.17.1590779817471;
 Fri, 29 May 2020 12:16:57 -0700 (PDT)
MIME-Version: 1.0
References: <c2f0c8e4048852ae014f4a391d96ca42d27e3255.1590779332.git.andreyknvl@google.com>
In-Reply-To: <c2f0c8e4048852ae014f4a391d96ca42d27e3255.1590779332.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 May 2020 21:16:46 +0200
Message-ID: <CANpmjNM3TiVi3EXEND5KwCt0CNJ9xu2wFT=j79=j5C__QGd9EQ@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix clang compilation warning due to stack protector
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sqaXB7Zj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 29 May 2020 at 21:12, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> KASAN uses a single cc-option invocation to disable both conserve-stack
> and stack-protector flags. The former flag is not present in Clang, which
> causes cc-option to fail, and results in stack-protector being enabled.
>
> Fix by using separate cc-option calls for each flag. Also collect all
> flags in a variable to avoid calling cc-option multiple times for
> different files.
>
> Reported-by: Qian Cai <cai@lca.pw>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>
> Changes v1 -> v2:
> - Renamed CC_FLAGS_KASAN_CONFLICT to CC_FLAGS_KASAN_RUNTIME.

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
>  mm/kasan/Makefile | 21 +++++++++++++--------
>  1 file changed, 13 insertions(+), 8 deletions(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index de3121848ddf..d532c2587731 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -15,14 +15,19 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> -CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> +CC_FLAGS_KASAN_RUNTIME := $(call cc-option, -fno-conserve-stack)
> +CC_FLAGS_KASAN_RUNTIME += $(call cc-option, -fno-stack-protector)
> +# Disable branch tracing to avoid recursion.
> +CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
> +
> +CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) := common.o init.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> --
> 2.27.0.rc0.183.gde8f92d652-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM3TiVi3EXEND5KwCt0CNJ9xu2wFT%3Dj79%3Dj5C__QGd9EQ%40mail.gmail.com.
