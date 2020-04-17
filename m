Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXL4X2AKGQECXUDOFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BFAF1AD9B6
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 11:23:19 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id v27sf646089uaa.22
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 02:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587115398; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGKXETRQpLGJHvnLwp/vIyiYxkx33V6ZUiiks4ABmmR4NXfMgiBq1UMsNGY/d6kwIe
         +8eDDcRbF/+PEdZ3EKG2PLMMXSRt0Ets0gGC3SI2nIdhu9V4rGUhd1LxsJIe7wYemSty
         rIM1Jylya/aufSOTgFq5kKzLHPvSxomOQZdVUHnalK3SAjQv/iPjG9mFP3PjF8BYEo9N
         HEjopyRCQNt1ibhb1Q7peNy0tgbjsvaGRz8qBqTfRwiFUK+npbhKiOKV+3pupqUWh5cB
         RMVpf/sGOi/+P9AkC5O7jW4Y6BndnW3KaRqcxitCli3JTbdBk4SR+nHcryZu3rwQ2qFM
         Qx8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XnmPi3mhMK0cAK7TuMGZRpJYKjf75QKetyIKv99QF3U=;
        b=KiK9/k0K6eOJH9HV1MSJavtei0rufGWnwDksbRtZBgJ8VgswRM+UYHISwlnoYfi1vR
         XujImNu6v4EQRvaLfpiOvDgoSHCaXCWiuTxck4XdnQFLhOf5fJF4OgQsJJtfq5GgxIzp
         wlKKcv6po7JPxc1TLkti0YOTf8lc4c/IBBBMg+EJvNwKESgRlb+kNvV2CJHdzK7q2ctd
         llFdG5VnNuaAOwjQ0PF4WwYTzNVms7Co5bCX34EgN2BWcDrZaUbIdE3/y0ohSsdRLuqC
         fXe+KTviApZ8dt+FTkYs/1i3mpywOqhpd8m1iXb4NbonMWxL2P5APhHiiIcszcRhFcwD
         20MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dGzqBcT2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XnmPi3mhMK0cAK7TuMGZRpJYKjf75QKetyIKv99QF3U=;
        b=XvpGl7J6USQrdF2N6S546+1ZJOxjisrDZnn7pt1uiH6erniMUrI3XqcQdoMgwzSKSC
         SSh/7Razg6PYKH/GMvGJlGkBICVigKBzcvsUMKxnnaLYd31+F6KqO8/Ae7KZv0SXQOlK
         UShNUzTnCHwExJLAOBSAaa68nw09pWROqGmIZCmmlAERxeYyZ8zSy6KHjXaNZ0UoKDFN
         0I3hJEOFmeamdeQQ3l5ksKaJOoxu783jwLEKOViyoAnSUYsubl08z1WIKZLa87VI+YGN
         LkjWIGK4N1ywJuUyVxRspkQ4wSByFhaXtNQQn9oApnkhqUy5QOtp1zflPDey924gAd7I
         PloQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XnmPi3mhMK0cAK7TuMGZRpJYKjf75QKetyIKv99QF3U=;
        b=Rf0TR+vIimPYC3z9N1Ag0zW3fCbeGdDEGynI2Yjl2alYCO362pcPD1mvkDpvkKbAEB
         8a6V1Ckj8hOpJ/XxL419SuTcPgcK4PDaxNwBd6OFQ1IDpEG+wD9wONyYxmg2lPydMArS
         z1tOFo1ewhRStOWc8lnYy2NMGWtlw88M6dD/0dnZzAtHlRtNwnRXmk/PYYa2LphthKv7
         lnXP0SdZ5XqJc4DyuR8RQ/V83VvdCU7zNBavFIgmL7c5ijCfsjFXV7sVVRomDxeH7jsu
         IH/NHw/HMMsCzTnZ1hJ9Tn5SchZQ1Ve9cvwTxaE05fkdfwnTJrBO669KjwU7F8VgGKsf
         L3iw==
X-Gm-Message-State: AGi0Pua/WDKxSTHywYI/b/C8JzPdL3mSEYxWKg9GdahKxhdCtXphIYn1
	uhchnq5WzpJ+iwwAiGcU1Bg=
X-Google-Smtp-Source: APiQypKNnRxbKkpiwnS4ZmPIaQqLVF3jL3xytReYnip73tlZvwfSuIMpNJnxbMu5nczQamG+fB4c1g==
X-Received: by 2002:a67:7d10:: with SMTP id y16mr1526318vsc.23.1587115398303;
        Fri, 17 Apr 2020 02:23:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:1248:: with SMTP id p8ls235840vsg.2.gmail; Fri, 17
 Apr 2020 02:23:18 -0700 (PDT)
X-Received: by 2002:a67:68c4:: with SMTP id d187mr1480732vsc.92.1587115397968;
        Fri, 17 Apr 2020 02:23:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587115397; cv=none;
        d=google.com; s=arc-20160816;
        b=X5vDwgIjWCrwgfX16Ail5BdJG30zbniqPRXjIokWETW+d3kiAdaIDdJBeXHXJnfrqt
         0CQcVi6z4PwMB3x4oQX28wH+A9K/ozID1zuk92nbOqPWg5q9/RMLVxhMKFBtjNcoDc9N
         j4WnRXRcLn7ayHzbHU0mKOXYwlYmxq04t2Gk5taW1iPey4HGx43uBvGn1m/6WtcnOK7S
         30UuGnYyvpQcCax+zNEiOwERuiHxOjUweYOkPTWZxu5fwKxvDSdKyPOF7ql3u3cmpsiy
         lgz+chfjrkHGySS8nXxTuzKJCgdu5YMPCYxxirsWUnSvIN+5TsTopoqKqiDxnD3Kqhz+
         KQqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eJOO3sCXHry7MojuN8dC/zdHSghVm7s+SjPlK2NGqPk=;
        b=Ce8aoQe26HVHuTUp7QUn3GKr4E8YeJswy167XV0Nk9Y8ncFJ5sDV0+QTTwksN2bgK9
         NBq25MEhO9cvqcA/vNSOi2OJgvxdD1ws1dC5Hd1NMM4f600RDnjylO4l7NvUqa0zwFdg
         +6g7B5ISOTayq/zXAn68g7v/VaHimqoTYrtPXc/dUUe4M0pb6hjLE/3IsN/YE8xAMLsM
         FDEapa6LeD19LT3a4Q1EwYq905hVa6l82efoVt56As4DS9aJBgO8/PPrZi51aRrloDOS
         oW/8Dfr76I6lT/FBiIRRfTX8D0gwo01B3dYNitJWx7OMI+ExdmpkFtpDre2PqoJxYwD5
         gxwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dGzqBcT2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id s64si613901vkg.1.2020.04.17.02.23.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 02:23:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id i22so876826otp.12
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 02:23:17 -0700 (PDT)
X-Received: by 2002:a9d:509:: with SMTP id 9mr1919206otw.17.1587115397215;
 Fri, 17 Apr 2020 02:23:17 -0700 (PDT)
MIME-Version: 1.0
References: <20200417025837.49780-1-weiyongjun1@huawei.com>
In-Reply-To: <20200417025837.49780-1-weiyongjun1@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Apr 2020 11:23:05 +0200
Message-ID: <CANpmjNMzwqFaaA-zQh0Nv4SUdoJUFO_yTmTjfbMFqyxBea1U+Q@mail.gmail.com>
Subject: Re: [PATCH -next] kcsan: Use GFP_ATOMIC under spin lock
To: Wei Yongjun <weiyongjun1@huawei.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-janitors@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dGzqBcT2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Fri, 17 Apr 2020 at 04:56, Wei Yongjun <weiyongjun1@huawei.com> wrote:
>
> A spin lock is taken here so we should use GFP_ATOMIC.
>
> Signed-off-by: Wei Yongjun <weiyongjun1@huawei.com>

Good catch, thank you!

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  kernel/kcsan/debugfs.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 1a08664a7fab..023e49c58d55 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -230,7 +230,7 @@ static ssize_t insert_report_filterlist(const char *func)
>                 /* initial allocation */
>                 report_filterlist.addrs =
>                         kmalloc_array(report_filterlist.size,
> -                                     sizeof(unsigned long), GFP_KERNEL);
> +                                     sizeof(unsigned long), GFP_ATOMIC);
>                 if (report_filterlist.addrs == NULL) {
>                         ret = -ENOMEM;
>                         goto out;
> @@ -240,7 +240,7 @@ static ssize_t insert_report_filterlist(const char *func)
>                 size_t new_size = report_filterlist.size * 2;
>                 unsigned long *new_addrs =
>                         krealloc(report_filterlist.addrs,
> -                                new_size * sizeof(unsigned long), GFP_KERNEL);
> +                                new_size * sizeof(unsigned long), GFP_ATOMIC);
>
>                 if (new_addrs == NULL) {
>                         /* leave filterlist itself untouched */
>
>
>
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMzwqFaaA-zQh0Nv4SUdoJUFO_yTmTjfbMFqyxBea1U%2BQ%40mail.gmail.com.
