Return-Path: <kasan-dev+bncBCMIZB7QWENRBQXE5T7AKGQEDCEJE6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C3942DCF73
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:26:11 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id q5sf12599471otc.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:26:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608200770; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOL9OinlMC/0FQb+VhE2/dyE/ERFor36AqLFv1Y8JU8IJ3Fdgqqyo8SOjOuGu9LYuJ
         OfT75ffBjjA299TOXgc2NuZylJDH3ZuPJvARn7em8tPxV9FUw1QfB3vGcC4t05Yg391q
         fQlYM86H8Vu/Py6SwwG4/wvpX9OoYqDQdLYweSqo3hGlIoRII/A5z3IQOlyXj9ccBxOW
         wIJIDVZnZFuq7iPC8hUgky5nEeoFn59fHoddNoG72sKdCeTUe33mIlCw0+WIAlsodXF7
         UfqZ9BOrqgrQKG6tOsw2hH5dAT5sIjp3u9uRzhswZkfcjo/+uar1QY9XaC9zt5ldOlJ8
         kRXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AUT8skGUMFGVBLQcREabCSydUIE8WQUwick3Qf75908=;
        b=DmgPXZBMMlG4YYAMkOJ5+0nLdlCUVf4OI/pS64sKSSfZzJUFFciouw+7ITez5HLRDF
         bwkFc6LxEKBbvUEoRvA7pLWk6T0lzl3RVx9VX7b3CUlQC5KWbSWgfVpm6TDi/lp68D1u
         KiXfXYO4qg7rjNC6sFais6hdJjiW6q/D/U9ikVXZwXHxSBr7tI4FInuCHTEYMmH/BwSI
         uoh7NbyMC3Mg7ItUOFOX+/hL4j42jD4W73D/gcBnRYI7U61IytnH3SuxdSZ4/XpjrLou
         hR/5tU34f1AzX4zixUd0CM8gwExxqUW7LWtbXkrQ1bnGNZiow33cDvxRjDo+XmOYB+fA
         ymyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="YjBwGZ/Z";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AUT8skGUMFGVBLQcREabCSydUIE8WQUwick3Qf75908=;
        b=QzdXsNtjpqEcegOzSmPGOHHFBDT1ftc/9GJdRh5Crh0oWmbfgqhWwNGdlZHrvOotWI
         yCyh5TwbtB5aovN4kY0mTu5AlYY8L1+PlbomuFQf5ZQs95Q9dHQwcfr1fsLgBZk7t7rG
         2R+/dx1jfL8kE+uECxKnyYLSR3QDXibL+II1EIcBCd/0ROYtDAKbx3tEE/TNg+lc0yNt
         SCeBoRqiuMCMLlbXbwQ4kAIlDMBEJU6QjcLwYJBMxCl5fsKIPqri2mic+gKYco6z22/4
         fiPiIElAG9YGtmHHyhlL8oOjabosU0MnOyBsaD7nV9oK9cfRqBzzR48xRoxsMmrwsiAE
         P1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AUT8skGUMFGVBLQcREabCSydUIE8WQUwick3Qf75908=;
        b=kAG3yg+j+I/lrQXYKDt7Bc4Z8XTge9KOgxCYuer6Z4tmbH2vV5gy6ivfXsvy7axCAs
         B3ATR9q3ydccuhX1bg+d2/GjXfVYYIM1+r6kayLPWyymICZTQkdGNx41JeffEyoXJLQk
         sC1qvx7Q05+Xo0FVm+QThoNgB73Z/R9HDZccPPo8O4oU5RNhLdPG53piic8R+wIZU7l6
         CO4QgleA500TNgtCApq0A3ZdQxaERTbn9GA6CfFLKT1+Zs0PzJmDZgcLqdoUqmuiNCwM
         SqbCTq6vCxmlkcW1tm0QeY8Tz+e3nhTciBKhiZzdLQ2FQ65d0lwnHbc65OSKl4zfISV8
         8ZGg==
X-Gm-Message-State: AOAM530AA5aw7eyL/CFEFQhRAIJVxL0wanlSGpqnAvPkgn6gfbkGYFUD
	ZCsRPXN3HEwfVmX7uQwPj/0=
X-Google-Smtp-Source: ABdhPJy4DQVkqhkKC/yj+dFcl6BVzLtx2ytB4s4Fs3P6g8syWqi72Z3VvQddWbPheNc0QksUuudbaQ==
X-Received: by 2002:a05:6808:a95:: with SMTP id q21mr905595oij.6.1608200770416;
        Thu, 17 Dec 2020 02:26:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:140e:: with SMTP id v14ls7215475otp.4.gmail; Thu,
 17 Dec 2020 02:26:10 -0800 (PST)
X-Received: by 2002:a05:6830:22f9:: with SMTP id t25mr29253747otc.14.1608200770122;
        Thu, 17 Dec 2020 02:26:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608200770; cv=none;
        d=google.com; s=arc-20160816;
        b=CvZG1mC1lq0OTnxx4fPyUvAiKy7JDlMnh27rg0yEnLVDa2nv+ErZ4DC6YtIByL6lI2
         N7RlwbCynjkXOsk3NRIq8DQIG/1m95wVaskpHbCiQMt4d6IzRqyspj1fO/ypeA+ufvRX
         sLZJ5FTtbtkBiIoLCT5VYLKHkeGnCBWHKOkqd3dn9m5+9RDn4Jd2TZQnjqUsMNqfDh4h
         bNsB4pj6X0F6JClWBYiKvKj2VYTjzxTwj8k071AxPodCUX67i2DzOKwhsvspxVgsxWbL
         FOwoKDQnEeNmtwJmvpK7MpBNipaYZLGfCmIqgtZswLSK8nhKCJrREYJueNnWZurlCRnr
         RnGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7dPMjrwUyVJ0SctrZbQ7QI+UYy17WeAuqUz3oRrGTfU=;
        b=CkWMVupnFX1evzGYOGIv+7TW0Rd3x1Hxbna+XF3J/7If/Jvk8RpmPlJ0etCcJPlOEJ
         NDDzQ69lkPO5XfQ8nFM3vmJiJI4Ohr0+cd5H1WWZjyT7FHYq2OU3k7rnQ0A0bWZENVm+
         bOvC67RAgr15gU12NbkKXtcLB2ThkW0cUGsjeaQfnm1nF9tFTcvVThIJqsz2yIfx8+bM
         56/fyqHR9n7NdIm4lKWVm09NBTh7/7JMrv7SD0I9e0W8IIvI/w3AHrm+OF7naFuaGHrc
         nKxLTGdFss7YEkcIneLA6xUsZaMzJVI58bzULB1F7aKU4iUALVf9BQ7VDxKBl5Xr+6wS
         V54g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="YjBwGZ/Z";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 7si368285otq.5.2020.12.17.02.26.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Dec 2020 02:26:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id a13so13009111qvv.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Dec 2020 02:26:10 -0800 (PST)
X-Received: by 2002:a0c:b20d:: with SMTP id x13mr48172339qvd.18.1608200769366;
 Thu, 17 Dec 2020 02:26:09 -0800 (PST)
MIME-Version: 1.0
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
In-Reply-To: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Dec 2020 11:25:57 +0100
Message-ID: <CACT4Y+bO+w50rgbAMPcMMTdyvRRe1nc97Hp-Gm81Ky2s6fOnMQ@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Minchan Kim <minchan@kernel.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dan Williams <dan.j.williams@intel.com>, 
	Mark Brown <broonie@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, ylal@codeaurora.org, 
	vinmenon@codeaurora.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="YjBwGZ/Z";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f29
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

On Thu, Dec 10, 2020 at 6:04 AM <vjitta@codeaurora.org> wrote:
>
> From: Yogesh Lal <ylal@codeaurora.org>
>
> Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
>
> Aim is to have configurable value for STACK_HASH_SIZE, so that one
> can configure it depending on usecase there by reducing the static
> memory overhead.
>
> One example is of Page Owner, default value of STACK_HASH_SIZE lead
> stack depot to consume 8MB of static memory. Making it configurable
> and use lower value helps to enable features like CONFIG_PAGE_OWNER
> without any significant overhead.
>
> Suggested-by: Minchan Kim <minchan@kernel.org>
> Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
> Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>
> ---
>  lib/stackdepot.c | 31 +++++++++++++++++++++++++++----
>  1 file changed, 27 insertions(+), 4 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 81c69c0..e0eebfd 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -30,6 +30,7 @@
>  #include <linux/stackdepot.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> +#include <linux/vmalloc.h>
>
>  #define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
>
> @@ -141,14 +142,36 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
>         return stack;
>  }
>
> -#define STACK_HASH_ORDER 20
> -#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
> +#define MAX_STACK_HASH_ORDER 20
> +#define MAX_STACK_HASH_SIZE (1L << MAX_STACK_HASH_ORDER)
> +#define STACK_HASH_SIZE (1L << stack_hash_order)
>  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
>  #define STACK_HASH_SEED 0x9747b28c
>
> -static struct stack_record *stack_table[STACK_HASH_SIZE] = {
> -       [0 ...  STACK_HASH_SIZE - 1] = NULL
> +static unsigned int stack_hash_order = 20;
> +static struct stack_record *stack_table_def[MAX_STACK_HASH_SIZE] __initdata = {
> +       [0 ...  MAX_STACK_HASH_SIZE - 1] = NULL
>  };
> +static struct stack_record **stack_table __refdata = stack_table_def;
> +
> +static int __init setup_stack_hash_order(char *str)
> +{
> +       kstrtouint(str, 0, &stack_hash_order);
> +       if (stack_hash_order > MAX_STACK_HASH_ORDER)
> +               stack_hash_order = MAX_STACK_HASH_ORDER;
> +       return 0;
> +}
> +early_param("stack_hash_order", setup_stack_hash_order);
> +
> +static int __init init_stackdepot(void)
> +{
> +       size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
> +
> +       stack_table = vmalloc(size);
> +       memcpy(stack_table, stack_table_def, size);

Can interrupts happen at this point in time? If yes, they can
use/modify stack_table_def concurrently.

> +       return 0;
> +}
> +early_initcall(init_stackdepot);
>
>  /* Calculate hash for a stack */
>  static inline u32 hash_stack(unsigned long *entries, unsigned int size)
> --
> 2.7.4
> QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbO%2Bw50rgbAMPcMMTdyvRRe1nc97Hp-Gm81Ky2s6fOnMQ%40mail.gmail.com.
