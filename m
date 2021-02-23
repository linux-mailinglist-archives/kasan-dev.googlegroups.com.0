Return-Path: <kasan-dev+bncBCMIZB7QWENRBWFR2SAQMGQEOC46I2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 13183322D0C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 16:01:46 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id u123sf136064vku.15
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 07:01:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614092505; cv=pass;
        d=google.com; s=arc-20160816;
        b=zEdBa9dbyi5H8Yd7Gqu/JmzPBesjWP7UnSvqrarlN0nN9dDC9/64Z1IpIbOcpjXo3M
         bR4WI5v3pUTEBQH6kbTv5z71u0mDr5HYzNs5rsDAVYP1r4E/tcSTFHJI7YQu/oRm718q
         +MxwU+JEaGEnemwIb8ncrU0ZosEfUr02WTKbHeZZuZ4k8Lejg6JoJ4X9F823/ze3EVLw
         zChalIL/53ngrqh1mjoQs40uDXgUwk38+30ohjeNk2Mw6LKp+HZdovPDqNb929Yn+HTN
         YiL9AvrmfQlECpU9PNH3gE1x88ScIYbZegLJMqMuGLZR9+AgZu7skAFW51cbKW5IJOms
         J+uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IV/ye52NyumGxtsvaoA0c95fOZr+oLQgqjKQ/lDUAds=;
        b=wAyZEG8YsjeBtiQVUQ+gBRbTTOiMcRC2WXfnFmzE4ENWW+UCQl6Kau0gNnz1543McV
         c/8dKjJZtai65YTA/OnYU/C53i3PQgirzdYa+ZiTwAnUwvw93d2j7NYO6VGCFuyoWnXB
         Ff88dXgBnovcfR4OpSpFsCPmCSbvHy+GmVtQ6gcLZWrYDxu1VdvaHrwEhIAIZ0LJ2XBn
         ooHSkrxzEbewJrOomB84XD2LPgvAhsLtH/RGsiex3JCNI/D8Ez55Ru4uLtJ+SEbf3gAr
         BQJOyGiqjPKr8ujLQSTopz8cZNK/krMCQPbybKh0aX4Iy6P+8GiyCCdV6dk/WsoTl3h5
         VpIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NpoxNpI2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IV/ye52NyumGxtsvaoA0c95fOZr+oLQgqjKQ/lDUAds=;
        b=UCwiHa0mX4vLHe3vm/VukeDphSGyyBBfqOkvjqyRasQB2o1QkmxBxWGGyOt2hV2lgh
         t1F1SHXqDdvF4OfM5boel5vC/Oa6AQdSSTGZk0KCzNdws7qMVFyJZ7UbpdhxFgEn9lmA
         gsarwT+kv2+C2Abq6MfgifARlKJDkkXm3COaxm6mKwLoygk/2QAN+1xt8b8IZKiP60ML
         PgkjtuOiFghCV9YcB4y1KGfwWQASJu6lyUuYi/zUmm+X3D7np32bFyFOTQthRiUt+irz
         n0iuftok5FF+TCbfcCIvWwM4bCR6ekKRV/PjEjL4VSXW/30GINKVQguNlIOQ8LlOJqS2
         CRaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IV/ye52NyumGxtsvaoA0c95fOZr+oLQgqjKQ/lDUAds=;
        b=SXncxVZ0pqcycctgRs6lxc1vNoNDHMc7MNNHdDHxUZPsr79+4+usqGW5J29E5dbAZt
         SlJ7wGQ+4DQAoWCp11iVqlxN0D60/xw0YMDFtlrI7t+k30LstGdnC+hoGO9an407A7k2
         mgMOQIMoajG+e0AtlB03xtAYgr+UPP5oZssOOHftU+HFG+IFdryJraz5SWf4JuX8N8hE
         KZeEjH449GAO3A2VNzhfViyahhw0VeqHwo8KkJmQpAQLhb6GbRjv2sjtCxPY9jk29I+/
         KWEjTumOMo7btHTz5QU8aYgTn43AEEaVsQdFzove620brILXnPqygNPXLp1JcV5DUsBp
         F4wg==
X-Gm-Message-State: AOAM531/2OVGz++cEKHgHueNCeYT67S8rrdTDDA7FQFiXYOPEBVMxH+9
	NaID6yI3c3nmLDK9sPYiras=
X-Google-Smtp-Source: ABdhPJxlBzdb05zOe5Is/66VBpBXepzPtvJVt6BsXn5oNAEYbeae14UEQHThs4mL8Duim/i53AGFxQ==
X-Received: by 2002:ab0:6e91:: with SMTP id b17mr19005747uav.50.1614092504306;
        Tue, 23 Feb 2021 07:01:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:604b:: with SMTP id u72ls1003052vkb.0.gmail; Tue, 23 Feb
 2021 07:01:43 -0800 (PST)
X-Received: by 2002:a1f:e501:: with SMTP id c1mr1236264vkh.12.1614092503898;
        Tue, 23 Feb 2021 07:01:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614092503; cv=none;
        d=google.com; s=arc-20160816;
        b=JvawvzJ61lyx64cfy0e5fRZvbXzL/SWCgzaL7m7Xu4wkF/whczs+DcaQ73/tXnp2B1
         dhRRKGCAVAgTJbehLuYLgQWdb7jZNu8DQ5vV+AVMDPIR5fOCtFYHEEAssyiTyfYZmc9c
         0JW55GLCxlW2Z5hcpLXa5BRZr7ghDqzios4nKup4tcC8Wq8uhHdgXiLYlfqjzBvU6Yjr
         TunDSzZkulA9buRjneTQMPUy153JF26yX8xr1pQSSGmVHbFTCqzFkv2BqENUiQvhA6Lc
         sX/Bz+jeTqFPwIdkfT2sM8oCB2ZHWSqjkcGrEK7To1ciN0/7J7RJd1b1qMTYq9mOziiv
         iJag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Hp3qEo1mGTYNWoUMN5eqstUYboCeaha+fsI0VeFao8I=;
        b=CwNCCFeKBu2LU5spB9VsIa4F7iflvX8HYDWS0rWWhB2GQOkL1xWnBkxU6ThPQ6EniI
         Jrf+YZPEDQJaiLvS/DZ9p2epMKxHXg8mJ/Bbwftho2zbEXcvBcOh1nowmZ68SrxfHBy2
         nU3u2HOmQgOq+N3n7ydKJW2QHZG643taZuKnnS38MP/ggXKQH++MRhFA6ftH0WI3IGxu
         vzcfez4va1OhQ2qlIgeVSJjozggjPSCxhJIh1hQyDBVtcnLEehTuKmL+go+jienWaS2T
         vU79iMYVA/3R5DzGuC/bMLaaKxjFlFL9Uc70Fj/3RYhEGeMW+bgzuY70/MDMq12HTV11
         nu5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NpoxNpI2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id p16si48886vko.0.2021.02.23.07.01.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 07:01:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id w19so16314617qki.13
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 07:01:43 -0800 (PST)
X-Received: by 2002:a37:46cf:: with SMTP id t198mr26670036qka.265.1614092503361;
 Tue, 23 Feb 2021 07:01:43 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-5-elver@google.com>
In-Reply-To: <20210223143426.2412737-5-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 16:01:32 +0100
Message-ID: <CACT4Y+aq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ@mail.gmail.com>
Subject: Re: [PATCH RFC 4/4] perf/core: Add breakpoint information to siginfo
 on SIGTRAP
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NpoxNpI2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733
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

On Tue, Feb 23, 2021 at 3:34 PM Marco Elver <elver@google.com> wrote:
>
> Encode information from breakpoint attributes into siginfo_t, which
> helps disambiguate which breakpoint fired.
>
> Note, providing the event fd may be unreliable, since the event may have
> been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> triggering and the signal being delivered to user space.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/events/core.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 8718763045fd..d7908322d796 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6296,6 +6296,17 @@ static void perf_sigtrap(struct perf_event *event)
>         info.si_signo = SIGTRAP;
>         info.si_code = TRAP_PERF;
>         info.si_errno = event->attr.type;
> +
> +       switch (event->attr.type) {
> +       case PERF_TYPE_BREAKPOINT:
> +               info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> +               info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> +               break;
> +       default:
> +               /* No additional info set. */

Should we prohibit using attr.sigtrap for !PERF_TYPE_BREAKPOINT if we
don't know what info to pass yet?

> +               break;
> +       }
> +
>         force_sig_info(&info);
>  }
>
> --
> 2.30.0.617.g56c4b15f3c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ%40mail.gmail.com.
