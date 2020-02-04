Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPE343YQKGQEW5VQUBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38D1B151D3E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 16:29:02 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id b62sf11684301pfb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 07:29:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580830141; cv=pass;
        d=google.com; s=arc-20160816;
        b=yJyWmAKT1oGYalhf7PKI+JamWy5o9FcZK9haSXcoQBpx++M4JAGtX3vSekwVF5qll0
         2tdAcjYo7KZFwii6cnDSGLHOrmSk6NmIXdaI/77NWjPIJ0mZRUb4xcnNurVh0JsNQOyL
         T3saQ0ifiG9O0o3P6p5l582RFeiNo2Zqm4bT8+ZyoihGPEW6vxmdBlsR13m9YaFvJIVW
         gdoP5JKBIULWRn6yviLVOINkScLs0w1cUvzMud1nO1Nqvprwbp1mR+uklrsN8jbY4O35
         zmHyA0T9g8ArcumRPINZZ/wtb+ldqKPLX6n5Jx1ln5sqSRQp0BQTkSUWkyjU8PF06cTm
         1waw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1kvMG75aN92xkmqq5XA5EtCBGLxn/xt1rhTi8F1ou5A=;
        b=ykU5YEsLKlLhwHD/xrSROGuYSnRH74YPTpQb0eXP6E1/VbBTcLUE4HokyM96WpmGkw
         gO/rcnfobyHPXe+VO2sAa0SKB/nvcOhmzE1Auk9ByipU+Zutlb6iC5hMBms9dXX81cBa
         dzY9XyBheCZZlX+f32SSpI89/35m5sNKmG6Mjk2mfd0/kzL5SMiQEK42tRPiGgJXcYAA
         ZhezD7WN4jzleNq1smFBrhPgO4KIq2iTYtNeuf3yE+cjTrNBBMkFJA5h+zoefsPGBeZQ
         oKc9RF16HXjl8Pdj8WJa0HY7TvL/euRTjLOUu/pKWV2vnMakGjADwCgJro0GO3UU8HFk
         Erjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LQ0OsNu+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1kvMG75aN92xkmqq5XA5EtCBGLxn/xt1rhTi8F1ou5A=;
        b=n3PrrSvUh/3CQ8smJRjNRIOQoCVMOFOOH6X4IZULpNVOtFjWfTw+3r8KBnb+Kcdq/x
         17jFtD72i+JFVY0LKI9ztLwJxnl6EgKmFkou/DI/gDj6RZXJQGAk20KSPPtumE6NmgfZ
         mzeQeIcQX4nX2jYKvvrItH+zU5L79vRnVKNA7ON6VGDxfCzwa7dsC0ssMWhIc5pxbpPS
         xhDK7sw+2nH4LRiZon1uRqGZNUvF6cfjklNldKHmagEtpw/K4jsx8tS/gAgDF4+kwLaK
         qLDNDsEGagiYFzaTpNJoQ4VXab6iua6UPQ981AHFnRVrFGERX5FBoKxfKpG4OoKUgMwv
         QNPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1kvMG75aN92xkmqq5XA5EtCBGLxn/xt1rhTi8F1ou5A=;
        b=iUHijwqPd/IcUZ8tgWBEi0Yi5rZH8qqaQEhRUMgJkOaQwo5M1LZzH2B12+0ML/ypwH
         MJmJC+7cJQEUDhnNgmNaq1rsKtd8En9oO1FsnhBa9h3G2N7z1xd6wqHnNcPMqD3VpMfs
         8z2Dw7NqjbVnTv4YepXQDLYBks43/eH16WfNNVNanTC4y+s2uuotycY34h2EqmBsu4W3
         M16bykQ/oZ/Q4cDVegDUgx1DdUTkbT8kv5ROFt842/Q8Nr0dhOgDTdpbcnRd7LW2/VhZ
         2XWsOJ/wH7P++ZmS4ZLzFkc5jVKvjzPXpiBB/EZxI0ov88mM59IolG7eL+cD34TuZjaj
         fsMg==
X-Gm-Message-State: APjAAAUozQvnduDi6UQFcY5gaVouSoGoucAg2Foka8ap1lEkS1utbGy4
	pPziY1ECKWlmWGXzykXAn1w=
X-Google-Smtp-Source: APXvYqynzqB2OccrJBZZLOESgjynsvLzCoXdCYhp4FY997I90aDieRc/k6AMDVLOYaegJrY1tYInPw==
X-Received: by 2002:aa7:8283:: with SMTP id s3mr31295179pfm.106.1580830140874;
        Tue, 04 Feb 2020 07:29:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b789:: with SMTP id e9ls1360969pls.4.gmail; Tue, 04
 Feb 2020 07:28:59 -0800 (PST)
X-Received: by 2002:a17:902:45:: with SMTP id 63mr30534569pla.109.1580830139849;
        Tue, 04 Feb 2020 07:28:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580830139; cv=none;
        d=google.com; s=arc-20160816;
        b=OC0P2J3cZBwTb6G6meb7RymleNedON4Ns8VoMuFeVMQoitCJilic3YYDJlVAh4jciR
         CnvH7RX8O+0nBO9cPRyeCTV5fJdEFOlbsIwhv3Oo3LEXZWqbE38fXWDMuWMaoQhi/93j
         rqXPiftlA98a10W8evxQF8KBlEuNNfZ3A1qxF8fVDFYWEyK8xpbHC35jjdYZQgBEixTH
         zrBXY3elPTKdMPQVgnAsuzgRPZ/WSEjKW7bEY4sobV17GAGJ227xj4mLyEHn9Nki90t8
         Ry8Q4q6GhF/CJu9qDdZljaLBfgbxWHjE95fAerd5rE+CP/DfFryfyCbTfT/5NcFrAdV6
         QpxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xNS0/F/vPTaGhHs2E+Os0bqOMJct5E1nmxxVhGRFeMM=;
        b=Jj1AfqoWG0hgwckV4ZIn6nnmC9rgnzZahtnNfAJwAPuEMt2TWj1kz4WHsI0WURsiy/
         mtFOn2ADw3Qyd5IDlXUdUzhTdreuUbLu3wf7SJRx4Z+QlyfYZOB/sr+RtuSANu/QPd0o
         WONHDbYAb69tdhJJmgVZX4ha7uDPtryCWeIL02fjw4wCwud0+AJPD+ZAu+dKbpMSIHPv
         1D0qo9oGJGHjHGBWPQIyXSzQyhSAMyfx9iUMqwz6BZspsO88grivZvQefByvScBAB5pH
         PYNs3xfzDp1CKn2VJ/cEllUznP87+KEgykhAJVqqY9vj6PTNjXHUiVg/ryHcF2iONSxq
         JMDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LQ0OsNu+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id c13si1143270pfi.3.2020.02.04.07.28.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 07:28:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id 66so17452260otd.9
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 07:28:59 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr23290235otk.23.1580830138835;
 Tue, 04 Feb 2020 07:28:58 -0800 (PST)
MIME-Version: 1.0
References: <20200204140353.177797-1-elver@google.com>
In-Reply-To: <20200204140353.177797-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Feb 2020 16:28:47 +0100
Message-ID: <CANpmjNMF3LpOUZSKXigxVXaH8imA2O5OvVu4ibPEDhCjwAXk0w@mail.gmail.com>
Subject: Re: [PATCH 1/3] kcsan: Add option to assume plain writes up to word
 size are atomic
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LQ0OsNu+;       spf=pass
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

On Tue, 4 Feb 2020 at 15:04, Marco Elver <elver@google.com> wrote:
>
> This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
> writes up to word size are also assumed to be atomic, and also not
> subject to other unsafe compiler optimizations resulting in data races.

I just realized we should probably also check for alignedness. Would
this be fair to add as an additional constraint? It would be my
preference.

Thanks,
-- Marco

> This option has been enabled by default to reflect current kernel-wide
> preferences.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/kcsan/core.c | 20 +++++++++++++++-----
>  lib/Kconfig.kcsan   | 26 +++++++++++++++++++-------
>  2 files changed, 34 insertions(+), 12 deletions(-)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 64b30f7716a12..3bd1bf8d6bfeb 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -169,10 +169,19 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
>         return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>
> -static __always_inline bool is_atomic(const volatile void *ptr)
> +static __always_inline bool
> +is_atomic(const volatile void *ptr, size_t size, int type)
>  {
> -       struct kcsan_ctx *ctx = get_ctx();
> +       struct kcsan_ctx *ctx;
> +
> +       if ((type & KCSAN_ACCESS_ATOMIC) != 0)
> +               return true;
>
> +       if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
> +           (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long))
> +               return true; /* Assume all writes up to word size are atomic. */
> +
> +       ctx = get_ctx();
>         if (unlikely(ctx->atomic_next > 0)) {
>                 /*
>                  * Because we do not have separate contexts for nested
> @@ -193,7 +202,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
>         return kcsan_is_atomic(ptr);
>  }
>
> -static __always_inline bool should_watch(const volatile void *ptr, int type)
> +static __always_inline bool
> +should_watch(const volatile void *ptr, size_t size, int type)
>  {
>         /*
>          * Never set up watchpoints when memory operations are atomic.
> @@ -202,7 +212,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
>          * should not count towards skipped instructions, and (2) to actually
>          * decrement kcsan_atomic_next for consecutive instruction stream.
>          */
> -       if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
> +       if (is_atomic(ptr, size, type))
>                 return false;
>
>         if (this_cpu_dec_return(kcsan_skip) >= 0)
> @@ -460,7 +470,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
>         if (unlikely(watchpoint != NULL))
>                 kcsan_found_watchpoint(ptr, size, type, watchpoint,
>                                        encoded_watchpoint);
> -       else if (unlikely(should_watch(ptr, type)))
> +       else if (unlikely(should_watch(ptr, size, type)))
>                 kcsan_setup_watchpoint(ptr, size, type);
>  }
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 3552990abcfe5..08972376f0454 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
>           limiting reporting to avoid flooding the console with reports.
>           Setting this to 0 disables rate limiting.
>
> -# Note that, while some of the below options could be turned into boot
> -# parameters, to optimize for the common use-case, we avoid this because: (a)
> -# it would impact performance (and we want to avoid static branch for all
> -# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
> -# without real benefit. The main purpose of the below options is for use in
> -# fuzzer configs to control reported data races, and they are not expected
> -# to be switched frequently by a user.
> +# The main purpose of the below options is to control reported data races (e.g.
> +# in fuzzer configs), and are not expected to be switched frequently by other
> +# users. We could turn some of them into boot parameters, but given they should
> +# not be switched normally, let's keep them here to simplify configuration.
> +#
> +# The defaults below are chosen to be very conservative, and may miss certain
> +# bugs.
>
>  config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
>         bool "Report races of unknown origin"
> @@ -116,6 +116,18 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
>           the data value of the memory location was observed to remain
>           unchanged, do not report the data race.
>
> +config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> +       bool "Assume that plain writes up to word size are atomic"
> +       default y
> +       help
> +         Assume that plain writes up to word size are atomic by default, and
> +         also not subject to other unsafe compiler optimizations resulting in
> +         data races. This will cause KCSAN to not report data races due to
> +         conflicts where the only plain accesses are writes up to word size:
> +         conflicts between marked reads and plain writes up to word size will
> +         not be reported as data races; notice that data races between two
> +         conflicting plain writes will also not be reported.
> +
>  config KCSAN_IGNORE_ATOMICS
>         bool "Do not instrument marked atomic accesses"
>         help
> --
> 2.25.0.341.g760bfbb309-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMF3LpOUZSKXigxVXaH8imA2O5OvVu4ibPEDhCjwAXk0w%40mail.gmail.com.
