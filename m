Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTOPY6NQMGQE4AG4MHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF0A3627630
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 08:01:34 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id c19-20020a05622a059300b003a51d69906esf7517053qtb.1
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Nov 2022 23:01:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668409293; cv=pass;
        d=google.com; s=arc-20160816;
        b=j/7jLMyAX2G2453n8Du+AqQcw3o7KVltAgeExlLw8Q7U78Wrglorqi3JyluBEdliHS
         xiS86Z6RLWBZpkA0+xqwrrokekW9CssXU/UrwE8dPxzzD1ar3Cqm73f7rNwNFePINBoB
         I1OkSviMxQTITfxEc2TAf5MD9LEXw82mmWYUTRCfEb0uAG35/JBCXFDJdCSCkSEc0UZj
         Bx1wGszTZk3g51fBhnA1SYiOCfz2PHJ3zx5v5wRbTTcm5lugcBecxdG/4o5TTuA0O2pu
         6HCAOl3/pSUlaXcy/PTYSt9iiVFu9Setrb70kGTXUVGFabJf9jDLEl8L6XV2uAkUUrc+
         hFnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kzMcT5+Ve18p+bbY5Y0JoMXbIU5I5x0vz91sRk03eMU=;
        b=QuZ8T+mp6ch6LSynlDEq8J2cQ6Cw4890GzU61SNRtLS75jaF+wCAf7pg77I2BFIKiN
         DXyVCpLBnhwuVA+c/JzqUGH1L4iJIm9uqh0/axYJJ+5vx5aicKfEs3Pe8d1SKOHmkCKx
         nX09YT3NyVzF+bfDH3djhD4oX0PjAk1rms4X0gnFynV5JM6EB9w/prh02CJ+ZTshPYi+
         /u9RzeLtZk3qyDe9xcH14LU0L5bJ7+kLnSWbtM6mm6YQ2NJ3sQ+t2Prd0kcCmYqn4mC1
         biefUx5MaOT7WsnYDljmNo3o3y6Q7ZGXdARbzPnjOQBqAbElEGcalhOR29mFWGHl9qUf
         pnEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Mit4/wrb";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kzMcT5+Ve18p+bbY5Y0JoMXbIU5I5x0vz91sRk03eMU=;
        b=DvMPitw4EuVovRZRvzrJ678CCjK2oROMKCEVTR4DR6PGYH9oFhfK0Mx5rDBKSy1D3Y
         jmS5HgikOI4y+lHxQPQKfzkNKAYUVi7R76oMsAN7s+DUCZFuMrjJ+km8r2dd1pQX4Lya
         wqJoGuc//DH712HlXemGRhoIWUmmYDYpPOW7e4CHohS70Lmb4By54DcorOWv0JTvw6sw
         6IUkn5XULv4k98v9U8i4k8HPM7eDWMElpB6SsOvbY1VjeGBproNJqm421Xj0LP11nMNV
         aXxnI5pM9PQR/EMDjVWs73cVfQt88u+oX0eGhyLPlFB2St/srt0L8aBAxA5xPwiK5fEq
         7bIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kzMcT5+Ve18p+bbY5Y0JoMXbIU5I5x0vz91sRk03eMU=;
        b=lGxqKb5KKTsC27x9N4q7zwUlyhxsgl58uLWziTkh4WeYYoUwHz+n0fKfnCwrpjp7LD
         7AzFwEtVAaJRL42nNKqt6RH5JEEOXVJVhbUoQgEzf3fxTQU9+qo/aYAORgJVfUqqEgKl
         /QNV+yrnd147ttt2Z0kD0tMspeut8vyLPXowjWkb3iFqxg5usjWCQ7V0X2GNaV1o7MD9
         51oDxtAxMm/IgU3LCdv/EFyuvsPhGZ4wZgR+1l3BZCLElsVHNA7sE3X8m2HVbWCo/idO
         LQkFdK1fpX9xilXIcj2j6azytZwt9ucZB06VI12IfzROnvIIzzNGEDhlSVT3YG7yRmq0
         Ttaw==
X-Gm-Message-State: ANoB5ple9BlEwM8rj5DXbkXlepLDQfB8IHVzUZjyJ2B3hDeBsaSeNloX
	mJ+MYIxm2ytPe9QijwOQMzc=
X-Google-Smtp-Source: AA0mqf5zwzEnslebBKWJJOzb+rYs2u+OE+YH4kQ88Dgk9vKd3U+wzq+2JjBl8a5xzQag2+Tj5Ye8vw==
X-Received: by 2002:a05:622a:4ac9:b0:3a5:36cd:a5a4 with SMTP id fx9-20020a05622a4ac900b003a536cda5a4mr11543214qtb.81.1668409293578;
        Sun, 13 Nov 2022 23:01:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4895:b0:35d:5bc0:6460 with SMTP id
 fc21-20020a05622a489500b0035d5bc06460ls6223280qtb.1.-pod-prod-gmail; Sun, 13
 Nov 2022 23:01:33 -0800 (PST)
X-Received: by 2002:ac8:6905:0:b0:3a5:8423:ebb7 with SMTP id bt5-20020ac86905000000b003a58423ebb7mr11010808qtb.593.1668409292971;
        Sun, 13 Nov 2022 23:01:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668409292; cv=none;
        d=google.com; s=arc-20160816;
        b=Yx+ukxAogykWkWfEOZ2cfA7lqUHrB76fTwQ2x8aVZaGoeK/p/toz/ocH6kaDPw97iP
         iFSw8hzhgqawJsif1t3X5FZ7/l1oczVKr7KHCpo42+LYCO5d1rbXwI9+3e+ftf+Q8t5+
         1WBmNHK3zpSn+IQlhRUgT2ZFJeBBoCyyyDAqLvlXDQueTu2GyIn769oFBmPj08u1mFly
         KXr+Yc3pqhqUH4cpAh2zdkHL8qFRcf3z/7QrKVeWLtllQ2ECfHEQwj+uv2txO+ZcyIvj
         aos2ozniGIkez1sd4Cd/duWgP82udqapE+To7/l+1EPK1cquHS3rtIliU035fNRKR3vS
         w4eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T8++jjvsG0oXPi9XkXPJNv66frIPVuEbhLDe6tRY0RU=;
        b=oGzaFKDEypYnRtm+vZD/THS6CTJcYiWkwvDBkecfMlz3qo8iC7v+F5zho9Xd9NF/tc
         kVqK/BASxKmAeCNvLrf1G+Qr5FenaOmzE0cOW82y1aodV+WZ8wY3dEs5u99aZVyJ9WV5
         U0P53G51Sk+eFh8SEHh6hMWHxiLEaZYwqyKWidtPXF6+PPxt93eMgnSlx+mJ7aaQr7eY
         Ycqe7Pv0+iXfCWwi9J0fI5nrSw3RPi38ZIsVZGUAW5r2atSvd9zA9TuqB2wq/rDQWLEk
         ToLI+0u8wvZs+2x+qJp6K/vnj2kguUcymbQ2LQZvuDA0n46Owpg08z10d5XeNCRsY0nB
         rZ2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Mit4/wrb";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id r13-20020ac85e8d000000b003a4f2725cd1si359656qtx.4.2022.11.13.23.01.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Nov 2022 23:01:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-369426664f9so97557837b3.12
        for <kasan-dev@googlegroups.com>; Sun, 13 Nov 2022 23:01:32 -0800 (PST)
X-Received: by 2002:a81:13c1:0:b0:373:4460:e8bd with SMTP id
 184-20020a8113c1000000b003734460e8bdmr11548114ywt.11.1668409292543; Sun, 13
 Nov 2022 23:01:32 -0800 (PST)
MIME-Version: 1.0
References: <1667986006-25420-1-git-send-email-quic_pkondeti@quicinc.com>
In-Reply-To: <1667986006-25420-1-git-send-email-quic_pkondeti@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Nov 2022 08:00:00 +0100
Message-ID: <CANpmjNNYRg7sYTxKN_YCts7wqGfr-2YZbw+pwdO5nTZp_bBVfg@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: remove hung_task cruft
To: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Peter Zijlstra <peterz@infradead.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Mit4/wrb";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as
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

On Wed, 9 Nov 2022 at 10:26, Pavankumar Kondeti
<quic_pkondeti@quicinc.com> wrote:
>
> commit fdf756f71271 ("sched: Fix more TASK_state comparisons") makes
> hung_task not to monitor TASK_IDLE tasks. The special handling to
> workaround hung_task warnings is not required anymore.
>
> Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>

Good riddance, thanks.

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 12 +-----------
>  1 file changed, 1 insertion(+), 11 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 1417888..08f5bd6 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -26,7 +26,6 @@
>  #include <linux/random.h>
>  #include <linux/rcupdate.h>
>  #include <linux/sched/clock.h>
> -#include <linux/sched/sysctl.h>
>  #include <linux/seq_file.h>
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
> @@ -799,16 +798,7 @@ static void toggle_allocation_gate(struct work_struct *work)
>         /* Enable static key, and await allocation to happen. */
>         static_branch_enable(&kfence_allocation_key);
>
> -       if (sysctl_hung_task_timeout_secs) {
> -               /*
> -                * During low activity with no allocations we might wait a
> -                * while; let's avoid the hung task warning.
> -                */
> -               wait_event_idle_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
> -                                       sysctl_hung_task_timeout_secs * HZ / 2);
> -       } else {
> -               wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
> -       }
> +       wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
>
>         /* Disable static key and reset timer. */
>         static_branch_disable(&kfence_allocation_key);
> --
> 2.7.4
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNYRg7sYTxKN_YCts7wqGfr-2YZbw%2BpwdO5nTZp_bBVfg%40mail.gmail.com.
