Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4EQYKTAMGQE5AYQ6SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id BA4807719D1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 08:00:17 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3176fe7b67bsf2049301f8f.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Aug 2023 23:00:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691388017; cv=pass;
        d=google.com; s=arc-20160816;
        b=wFHNRY777V6+qwde17odekldZZ1KVXmkB0oGd1V9ea5ZkYkQm+XszFzQXcAnIFdxDH
         CkwbdBQgDfeDNSQRelXxKLhpacS3qavowkwfpZlEJ444dE87JStskj9Xc99IHwzmxfRt
         uF91WyCgq1lwDfuKJMSOxLDDbSA4vilyOxRba7V93gi91XxYId909myXiAnjawmvltpZ
         kfZkEHWL0l20lQ+80HZmmM9Ri5TrBZS/gm7H3CtehchKvEN4I0lQVwfIAqc1+GgvDr2B
         rBU2oPPoX0iUUw3ORo8E8WaHqU79yNK6g0wkF59rqgtrOQZUx8lN6oOiYuUyk3skZjRW
         pW/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9r9FCApxDw/NN0VRpQm7SPDMU2N1Yzsz2Zv3HqN9sv4=;
        fh=sWFtOPPGHpNJXQWtLrYh1a49Jm/Kd/s7mSG/GhLdwos=;
        b=kuYX7/Aw5vtancqMkGvIyFIu9gd+LU+bqrt404r4wfeIsutpoaHrAA6E/ap9vSyr3D
         8y+aHM0vopIAUxNECfvJlGlqzkadhFR4MDOrybMnBYWTMhqU8ZmdPLE+OQ5xyKQvyK5h
         G3lzmNrE9458CvP4eVHbhY+Qvkdz/NsaEQAj8jMIZIHX5pwbvmBR6v2H2dtNKOay1mMr
         G59OmdihqOspixeK7iCdrK0nxzahiKiHcUiz9Sdzmr31iEuvNJE+urRbbWLWNaSrAYm5
         KX2IU1mGiqHaOzsJImExMhH1aVMNt94wCrzG8OKAA5HPPBrVfbf7DPg2Clg8NMnwgThv
         ZpkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ing8uEaE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691388017; x=1691992817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9r9FCApxDw/NN0VRpQm7SPDMU2N1Yzsz2Zv3HqN9sv4=;
        b=UFn1sGLpWZWy4ZWSZgvDQm9CMdcbseqa55QtdhBsPA7dtTEP22rTZAbvXwbA5w6XXZ
         P9qPvyDEJy8vN9I4LIQI/pBi3pd9/pEcg1cLf1VsvQ+NnEQjXaW+i6gCABgf4mx83DbY
         xqiAU+2zZQ61famY/nhdnVwI1xYofP1Ivu7kf3MGLuoOVZR9LO2WoZ9scHKkysOCyTMb
         6OjMQV9sZakH87hQFJ7nByBJrfwiJZqiSBiun/DuicU36G0ccjNDQZIby0nbbQ9NsRt7
         jX6yCQpCRQh8XF16Sg+lVWgN0R3hHwIEk0mV1Si13+80HUkyDw4PqQ8e2n5GHxdfqsGi
         37SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691388017; x=1691992817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9r9FCApxDw/NN0VRpQm7SPDMU2N1Yzsz2Zv3HqN9sv4=;
        b=ilma/1JfM4eevsKLJslGhCe4h6mhcSfbMO7mM55Wqp05ptjIPg0boEXnMVKXbC0sWX
         WO3K24ARg1EKvNn1qCuEnSyZLRkHyyUSkcNOWIEh6WnpoEVyT0H1USKA3HBlcDx495U3
         LWuwg/e0dS6zgMbaza/kVAkhDOsV6IeZD5boQivafHf3YwEDozCIhseeWoCH4u3IfG8R
         I2dxtZ0mHOilbFdVzeEb6FIbtkZw4KlCfKLJKONrDJFqMQyJ/8fEuLxaBRRp2+JezUJu
         bM/jPwFsrS4CPA1NtrcmfjBbtlxnrGWJgyGJ0sWU109S9lzM9paNEZeD0ugH2+zlx1e+
         T/lg==
X-Gm-Message-State: AOJu0YwwFB88EMqYZciVLi57+tuKAUJy3i/BB1x6aVk4Msy72y2/5Q7c
	vnRYRd2RgvOlHPb81twT82g=
X-Google-Smtp-Source: AGHT+IG8RiM37cd1ieU1xE02QHKDwekI+YEPun10+bV6YzuknzGC5p2pIbUb1ByEqSD2zzS3yVb1MA==
X-Received: by 2002:a5d:444b:0:b0:317:5c82:10c5 with SMTP id x11-20020a5d444b000000b003175c8210c5mr5198039wrr.17.1691388016812;
        Sun, 06 Aug 2023 23:00:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6016:b0:3fe:2d78:7ffa with SMTP id
 az22-20020a05600c601600b003fe2d787ffals803667wmb.2.-pod-prod-03-eu; Sun, 06
 Aug 2023 23:00:15 -0700 (PDT)
X-Received: by 2002:a7b:ce86:0:b0:3fb:9474:54cd with SMTP id q6-20020a7bce86000000b003fb947454cdmr4726851wmj.19.1691388015001;
        Sun, 06 Aug 2023 23:00:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691388014; cv=none;
        d=google.com; s=arc-20160816;
        b=h7+znl6fsMNxPAPvs2Mp88sg1LAWGAPQIjKC98H/H5hsq9yYwcyxoILRMI5fpDIFLo
         4cvkzKxwPY81IK0PmLvq7X27zVOj4OWVsO8GQVPD3LHhN7zvPrysAQIrn26qIAuUc/4G
         I9jyarB1BKwXBH97kFQY27+hlfzrJmuw8ZdU45SPPmo2L8EQ4MTi5HA+D95f8H8mRHqv
         jWEPpe1TTA2CiiU0TnTH8tacKoUxYjxGrEM+Ly5Ejg9kMcKMcdxwyuQUZHPg3JJKug2g
         5ptOM98yRhpvH81Bm385z/VMJC4YmxT/XTXz3LOdm99teH+ggo6iC5cDDBb9QaoaOdTA
         /Ilg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vBFHuRwuyk/hnPCEfjgfoHOKPA/ytrkp+MGxY8mmrKo=;
        fh=K+5CA2Fz5SmlXAYo9iS6wzvTtUNGzIcvVpqma7uas0A=;
        b=IIktieMcJTtxOl+dzMdXu67WWbGaj6zUZuk1tJF8LvMxaQDyEUAj+2aLbyCsDdBS+T
         +DtbNISXWNVkKE9VC23ASm9ZGY22xIzh7gO0mbvZom2asazf2Ip7sFsUg/pUGlfCJ5rn
         uz7OZYU3f1GSVmRxAVkS/bJg6TXJbn9RiicbqQKjdU0j7SiaXJ9nhR+EoKkO/1qRQD7e
         OTiyK1BKroymDbyzrMUn0GbOc3BteRDjj5WlexEUPQU9B6xNDZPTX83JmRWxn84WGMX/
         zHC5mua54bSj0GL+iOKrcrjHikOE/FhZdTM78HtRjWJ+JBEQd/3lrniGH6LQ6CrKMrTv
         jpCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ing8uEaE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id p27-20020a05600c1d9b00b003fbf22a6ddcsi606421wms.1.2023.08.06.23.00.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Aug 2023 23:00:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-3fe12baec61so34910535e9.2
        for <kasan-dev@googlegroups.com>; Sun, 06 Aug 2023 23:00:14 -0700 (PDT)
X-Received: by 2002:a1c:ed03:0:b0:3fb:a102:6d7a with SMTP id
 l3-20020a1ced03000000b003fba1026d7amr4975049wmh.28.1691388014380; Sun, 06 Aug
 2023 23:00:14 -0700 (PDT)
MIME-Version: 1.0
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com> <20230805175027.50029-4-andriy.shevchenko@linux.intel.com>
In-Reply-To: <20230805175027.50029-4-andriy.shevchenko@linux.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Aug 2023 08:00:00 +0200
Message-ID: <CANpmjNPN9JTc9WBSSPTCSmc2FphJ2FK7=x7wkwh3hv+X+E_C8A@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] lib/vsprintf: Declare no_hash_pointers in sprintf.h
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Petr Mladek <pmladek@suse.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Steven Rostedt <rostedt@goodmis.org>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Sergey Senozhatsky <senozhatsky@chromium.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ing8uEaE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Sat, 5 Aug 2023 at 19:49, Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> Sparse is not happy to see non-static variable without declaration:
> lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?
>
> Declare respective variable in the sprintf.h. With this, add a comment
> to discourage its use if no real need.
>
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  include/linux/sprintf.h | 2 ++
>  lib/test_printf.c       | 2 --
>  mm/kfence/report.c      | 3 +--
>  3 files changed, 3 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
> index 9ca23bcf9f42..33dcbec71925 100644
> --- a/include/linux/sprintf.h
> +++ b/include/linux/sprintf.h
> @@ -20,6 +20,8 @@ __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list
>  __scanf(2, 3) int sscanf(const char *, const char *, ...);
>  __scanf(2, 0) int vsscanf(const char *, const char *, va_list);
>
> +/* These are for specific cases, do not use without real need */
> +extern bool no_hash_pointers;
>  int no_hash_pointers_enable(char *str);
>
>  #endif /* _LINUX_KERNEL_SPRINTF_H */
> diff --git a/lib/test_printf.c b/lib/test_printf.c
> index 5adca19d34e2..cf861dc22169 100644
> --- a/lib/test_printf.c
> +++ b/lib/test_printf.c
> @@ -39,8 +39,6 @@ KSTM_MODULE_GLOBALS();
>  static char *test_buffer __initdata;
>  static char *alloced_buffer __initdata;
>
> -extern bool no_hash_pointers;
> -
>  static int __printf(4, 0) __init
>  do_test(int bufsize, const char *expect, int elen,
>         const char *fmt, va_list ap)
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 197430a5be4a..c509aed326ce 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -13,6 +13,7 @@
>  #include <linux/printk.h>
>  #include <linux/sched/debug.h>
>  #include <linux/seq_file.h>
> +#include <linux/sprintf.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <trace/events/error_report.h>
> @@ -26,8 +27,6 @@
>  #define ARCH_FUNC_PREFIX ""
>  #endif
>
> -extern bool no_hash_pointers;
> -
>  /* Helper function to either print to a seq_file or to console. */
>  __printf(2, 3)
>  static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
> --
> 2.40.0.1.gaa8946217a0b
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230805175027.50029-4-andriy.shevchenko%40linux.intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPN9JTc9WBSSPTCSmc2FphJ2FK7%3Dx7wkwh3hv%2BX%2BE_C8A%40mail.gmail.com.
