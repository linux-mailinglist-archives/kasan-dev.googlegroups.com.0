Return-Path: <kasan-dev+bncBCMIZB7QWENRBKOE4OHQMGQEOXPMTTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 01C944A57C4
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 08:32:59 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id ay31-20020a056808301f00b002d06e828c00sf1461015oib.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 23:32:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643700777; cv=pass;
        d=google.com; s=arc-20160816;
        b=VP7FCt5Lan+zZ8XdNUEEohTpA0/9JnPzi3taSzYWIZpkzw6wyPSyRJ0IbXRzJzxxyo
         s1fiCQZnT3WmrKjZUueL5y5O/h0QerBjT1ghjYBbIVK4QRjtAp6X5YcJSdo0FUeypFa4
         bQzRprl/Zk+tH5oRencjGkuOw+jsetBqJR8vpg7Mw+RCDRbwe+LROt7ip+xx1zbdoHMm
         cyj7sN3WdQh1TleS0MBplvYE6lHeqLfdwquB/617sYX5aH5RHP0HhY2eXfjE+ixpboiD
         sLUkFDP4gp9G0y+EnwreLjr7IpSTQI2x1VrqttOUXSbORaYyJSkwcVHVrhjE5os6vcYg
         fwBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zrSqHrb5EoFp2APecX8E2Sw1qw86/cr96z+sNxnAgcw=;
        b=lb5szp2SSSW8HBTBKOKja77OzAr6XdlEpr2dGvj5ipz3VGk2SuaX89tjk4Swcsr/f2
         qm9Dh2NcOkh4vk7fv0EgEHJnN3zRuDOnbt+2PlMcBQ3V36jLTpF887wAEWHzDJAMZHgX
         es/Zz6qp4O2/bX/CnDI5uOn5VNGNeLZ8wgNN2NOCdw6JsHGrnHsr4f9+FCgEjCDpXW1q
         DVfT1IsnirHAyAWqzKdAqW7xr/DCsl4KZfHtGeD3VQ8qa87OsVJSFlmXV0Zewl5glm0M
         vvGZIEW0WSdT8o0bLJ2l63lBiDce4Td3ytkIE37NwsNYX7OVdXjHBoCPeVoA7wBubB4k
         2xfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LJlQ0q/u";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zrSqHrb5EoFp2APecX8E2Sw1qw86/cr96z+sNxnAgcw=;
        b=MYtL1nxDgWBpz1IhQuSFhuIth1I3kgKV1Tx9uYQsLFyamgcZ7SS0WFftMg9uXtBAhY
         500lTUbOxWEqU79HLLxVNAExTtzl6lSJ2fUJNCbnQidpOsEXHtkp/4VGU33kx4kiH2TV
         fPecLNgfEcnfkKQVnsqS4tmdrVTEhdvdYdvKk2RqBjNc1uW5Kl5Q65p9qqc0wRt5t5Zg
         wyavxnu1Ye6qh0lvtmFhqya4drcfQamYLtfDK3oPvvbhAwQm1UKhOHfpNe2pRJehIMvJ
         Z9xmnze52yCODCu/g3wx4xV7J9tvpsyFKf0JdPZTRnSte8b0njXTCFjgfrfOmwUHSppP
         an5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zrSqHrb5EoFp2APecX8E2Sw1qw86/cr96z+sNxnAgcw=;
        b=q1AkN9WcpKBHNUJdjpDjsovOhL6JdACZ6Uszled2WL64tY23GPBQbzWtGl29HmTk1J
         FtvcduveuSjFC61+0TNAhfcZpphsRjAwL4ppaSlE8Op8NrfaJP0HCW592/8LQRcbqLQ2
         EeQMdyt32r73wi1fh80OhqvSBEYYHCO55FTCq3XpuyDTPTb16j3EgDCXJbyeC0k3zJBU
         3ohyevjoCX1pkwnfsgO3fQNGVjybSCAmVSHWTJ/jdAXxa9Mt5UYn0d6PuH9/mjg+zveO
         CHjHwisjckP7wrISq++pWxwi+t++yPrXBUWUN0+0ulddgTXxSLJv5ni9JhsJbsvx58Hf
         ahtw==
X-Gm-Message-State: AOAM532AvPSLQ1bTNEq5ZsumqQJJvssCueClrtuTlqBWH8DdwHgNhXlR
	B9lNKNH9QImMIM8NwaewKto=
X-Google-Smtp-Source: ABdhPJzh3NG9p9tcAxRn24Xmycx6pEgZWQkz1JPLjFoHOwqFkXUozCIpSTdLL/wx3Ci9kYeB2RlSQw==
X-Received: by 2002:a05:6808:14c1:: with SMTP id f1mr431794oiw.12.1643700777718;
        Mon, 31 Jan 2022 23:32:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2017:: with SMTP id n23ls3525538ota.8.gmail; Mon, 31 Jan
 2022 23:32:57 -0800 (PST)
X-Received: by 2002:a05:6830:40af:: with SMTP id x47mr5045923ott.362.1643700777385;
        Mon, 31 Jan 2022 23:32:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643700777; cv=none;
        d=google.com; s=arc-20160816;
        b=Vg3ARxQZiu256h8gMZ0hODUCFeNPkn+3yIvV4kaWlqomTaa0BZlOB7KfJCtgOfxf+Y
         AEPJu9xRfDJ2xRkf+cNh0/0Tz6pV0GMO8K+VQPs+VMTXorUGV+xIWZiJ2ac8Tm1cwdOa
         xVX0mDSf4ggJn3KBnu0Zu0zgp2+CFhyu5MUi9h9Q9if5iLor+fgZ+ovOfPHnrj+85OeI
         v1+RCJn1OFzmeWejQqsqjWwoMPIZY/mfv5zkDGzbuS6ZOGzmOgEkzMD9mBVaLA0jXx9U
         J3Rp96Zps0KUrl4kop4XdBn+v/SIEKd9PltxuT8B0Y3tZy/yeQR8LMiJDIJ4BQ2SrIU3
         /Pmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IJSDBj0HvFrkS4TLKuPLvlZS13YusH/7w8kLNZ4wxGA=;
        b=dkFb3nZJy2CFfbDmUIm8QLqUvV+PE2pyVuChUF8zjE0OZQx3IOW23Qc4ofikqvrvSM
         n4FxPtuJobAGvi4/yjXTHPL0De4ETqenD9zPz+6jOdq58xKa2v33czEHtlxGjHRTDFMn
         hSILjzJOyJxQuTzyMslEejuojm4kp1yFRmFj29y4GiLbcRnVUp0ESde6EYM1tyfBtBlj
         uYeqlm5L9flnaXHHZ0J5A3B8LD6sKSKkhLCcjcxhF+O3otQz6I+C1SmLfOvWadRrdKkU
         oYdv/A+vPZ6kt0ApaisZm3x8uK+8VqGqujD7WEFhwPfdmm6H9m1pJfaDnT3kEv8MfwNw
         Xj1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LJlQ0q/u";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id u43si2186861oiw.2.2022.01.31.23.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 23:32:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id n6-20020a9d6f06000000b005a0750019a7so15401653otq.5
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 23:32:57 -0800 (PST)
X-Received: by 2002:a9d:356:: with SMTP id 80mr13762561otv.335.1643700776891;
 Mon, 31 Jan 2022 23:32:56 -0800 (PST)
MIME-Version: 1.0
References: <20220131103407.1971678-1-elver@google.com>
In-Reply-To: <20220131103407.1971678-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Feb 2022 08:32:45 +0100
Message-ID: <CACT4Y+Zcg9Jf9p+RHWwKNDoCpfH-SBTzPpuQBBryyeopMONmEw@mail.gmail.com>
Subject: Re: [PATCH 1/3] perf: Copy perf_event_attr::sig_data on modification
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="LJlQ0q/u";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c
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

On Mon, 31 Jan 2022 at 11:34, Marco Elver <elver@google.com> wrote:
>
> The intent has always been that perf_event_attr::sig_data should also be
> modifiable along with PERF_EVENT_IOC_MODIFY_ATTRIBUTES, because it is
> observable by user space if SIGTRAP on events is requested.
>
> Currently only PERF_TYPE_BREAKPOINT is modifiable, and explicitly copies
> relevant breakpoint-related attributes in hw_breakpoint_copy_attr().
> This misses copying perf_event_attr::sig_data.
>
> Since sig_data is not specific to PERF_TYPE_BREAKPOINT, introduce a
> helper to copy generic event-type-independent attributes on
> modification.
>
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks for the quick fix.

> ---
>  kernel/events/core.c | 16 ++++++++++++++++
>  1 file changed, 16 insertions(+)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index fc18664f49b0..db0d85a85f1b 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -3197,6 +3197,15 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
>         return err;
>  }
>
> +/*
> + * Copy event-type-independent attributes that may be modified.
> + */
> +static void perf_event_modify_copy_attr(struct perf_event_attr *to,
> +                                       const struct perf_event_attr *from)
> +{
> +       to->sig_data = from->sig_data;
> +}
> +
>  static int perf_event_modify_attr(struct perf_event *event,
>                                   struct perf_event_attr *attr)
>  {
> @@ -3219,10 +3228,17 @@ static int perf_event_modify_attr(struct perf_event *event,
>         WARN_ON_ONCE(event->ctx->parent_ctx);
>
>         mutex_lock(&event->child_mutex);
> +       /*
> +        * Event-type-independent attributes must be copied before event-type
> +        * modification, which will validate that final attributes match the
> +        * source attributes after all relevant attributes have been copied.
> +        */
> +       perf_event_modify_copy_attr(&event->attr, attr);
>         err = func(event, attr);
>         if (err)
>                 goto out;
>         list_for_each_entry(child, &event->child_list, child_list) {
> +               perf_event_modify_copy_attr(&child->attr, attr);
>                 err = func(child, attr);
>                 if (err)
>                         goto out;
> --
> 2.35.0.rc2.247.g8bbb082509-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZcg9Jf9p%2BRHWwKNDoCpfH-SBTzPpuQBBryyeopMONmEw%40mail.gmail.com.
