Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG46ZCNQMGQEMPFXTXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CB149627971
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 10:49:16 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id q6-20020a056e020c2600b00302664fc72csf843457ilg.14
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 01:49:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668419355; cv=pass;
        d=google.com; s=arc-20160816;
        b=atUPs2SOorElLYCcodIGXwZm2+KGYec6RyKbPL1aGnpRhKxJqNUkowObcyWjojBXDA
         f3Az4uqAaLdMuSuUCmo/Xt18dsm/cZ0IiHXewvBOv2lgyrZEsQcQEPaD4MI03HkBT/8t
         8K6cIpvpiH1DiZiRmctHTit46cxkSsn334AZWYICDU7cApH0JXnP6vR8x+Sk0vDbq1AO
         JpL2jWtW5tFe8L/+aegMSz0jy/EGVyeWExkYlLIDGU7Erkqr1Ux7hKDI5m2mFmQy1kPf
         RwFqtnrkyN5DXY0FcqURTC9lM/0byPVQ/wqhmswyuTpMydtDR9vQjGJEy04PMmIUVENp
         9mQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xvQ6aHOYEeMGlrxNB0yt9D2UHRV6IbhoRDM2aCn/6fY=;
        b=vMfxRar6DMrIdnD4yGg7sHb57xv5NHJVmKzpUSYguszqyrO7U/6G2ANVaHjpeb0C/m
         f8iz8RjVc9r9db3JafUhu37ac3qDDsKEUNjZmFDyE8SJFoOWSj36fq1PKnqzR57hzdf6
         HH4wPMrqePGrIoiHab9dnaYJgw17cA2Ln/SK9cPvs7gltU1nePdzOv+gjEpSOtBe3+W3
         Nc/69tjN0Xu6tdjZ23Dfw6GJitzRL/OrmkxP7gVMfcT3+eOQSo/lr1b57v2nSLEjjRT8
         RddQI8Un6IAzV/ACD4k/1m4iOsewwhD6JTpKjNjhdG3ETffVSpbxi3xrgdfUxEt04g5B
         vnhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NwOHpbDr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xvQ6aHOYEeMGlrxNB0yt9D2UHRV6IbhoRDM2aCn/6fY=;
        b=qoTU4q3A44urWTvtKHsfMTnZU7oODtu5x7OL23AlH5QRp9kb90tVvYOQVaNsDKuPUH
         aVgY7TTVEV9FKWRinA0AbVFkiSHpxiD1ZUXNc0HDowqgDn7+Oeyv1lR31Clf4ObjgaXC
         h3K5nQ6glItxQeEDUbg5i1PlWVJmL8ehR+6U9LQQjLd6c5SHFujpfzf8LHNwMxAvuLhx
         K572MYmHrDL5Arnvvjv25rZ91syafBIqseF/HckH6ROZrCrS9AHZhEb2zKXxNGmX99v5
         4LCH57QSKVQ6TvzpBknkXtE5lauhCEwAxunpgSOzDwpiofgxPZXsO9D2M91csNftW/Pd
         Bjbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xvQ6aHOYEeMGlrxNB0yt9D2UHRV6IbhoRDM2aCn/6fY=;
        b=2Mbufcq6h3QS2rOcdrmXWorah5gkasJG5CAUBAx1N/j7oNWqZF227CMvZXU4iW7My2
         cIjiwr/JwvCP0TIZRwDAoOX63muoAlJ0uSX3vJFHgMGIXwdwuJO82TWXCyf4FUNwB41W
         B6qm/ObjfrUQ36rN+fc998BIwDsQ8pICgJcpVRQA1/cpYGHKwdLQhH5n+H1KtF+kpRDf
         IfhJpoMfvIJXINVaW5guDGIrEBkFhTxCs/nX84d3pjlx4hwdd/Rbewzx2SWmRL301jLp
         5AR1Jq19X6yfWrayEELaUzGkFK7LjVKekaUWMe6ps6UEG1F8duiFecfins3kEFDBgB3H
         Q81Q==
X-Gm-Message-State: ANoB5pmvkYo6WQ2tpbcCK1nNfG2QlX0apgoTHGpYbiNib5jbSzytVdC/
	fSWtXPaEv3Y9KIg+rM0Dkhw=
X-Google-Smtp-Source: AA0mqf4/uE1ufizMIsFs00jRvOxcTHn3B/LCwAt3FIutgBjU2fvBT4BCGBZ0qKz78A+J0h4zrze4ig==
X-Received: by 2002:a02:cbb4:0:b0:373:9d0a:33a0 with SMTP id v20-20020a02cbb4000000b003739d0a33a0mr5398132jap.286.1668419355353;
        Mon, 14 Nov 2022 01:49:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:8667:0:b0:369:7404:3a4c with SMTP id e94-20020a028667000000b0036974043a4cls2211078jai.10.-pod-prod-gmail;
 Mon, 14 Nov 2022 01:49:14 -0800 (PST)
X-Received: by 2002:a02:ce87:0:b0:370:ea9a:65dc with SMTP id y7-20020a02ce87000000b00370ea9a65dcmr5157546jaq.280.1668419354866;
        Mon, 14 Nov 2022 01:49:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668419354; cv=none;
        d=google.com; s=arc-20160816;
        b=OYEL2XiJ/v2FfZH6p+/aPhWbbFCnna/C2Z8MtQDY42B3deWDor1vck11jE6m4hZBNg
         W3Ck3CjDRyOVxgpa0Lp5NDDW4HGmNIGS1MHFXYGShH6dAxxMLDyS7TFsM9sGK/GPZida
         4OJUmqaT76ojFR7zdMfCmME72X3LU1JsWvMb7IEMabUFKLMRdPPQF674go5U/nI+szY9
         fOUNVjV+pICLQA48E2ILJSo/bUN5Wwwe5UE6+qDt2+A2olJEJGy6Gaj0/Kp4uJUGD9T0
         IW2hlfLU6VYZiezZTn1sXyhs/n4ftXnT6K2r+68yfqS7fVfIJzIkznaBS+heLR8se2tf
         Ww+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l4csSnMcWReSkj8cBG0QioRbqv/IdxWbBKHzfzblSQo=;
        b=NspaJaxkDCciHwsx371deAHKdIJtSweh+24obqK3iYf9Zh5KIClfEHWlqn+KCf6vI3
         UyprvYKUKXnj+c6lkLyNW/y7LCsGr+dKdGlvvuxIpmH5PxYBeGjwifa9zUoRpy98Jb/H
         cExEG+y2FOrtyUby5JdFIP6TvPax0VGwMgWWfe7/2rTcT+8elFFrTpjEWhAMrdlkpf9z
         Q0hZOoxOz/O0q94f5dhNVrywuOCivoxLm5N7Rh8xwi3Y0zsR2dWCQyef07CC2YrxHLtY
         2NqJmY7DV+eYuXbUQ5h+PU5pk5lSY95JdQN7TGb+6hWjatsYLEa77QZaeIT9MBMuu2Aj
         F+Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NwOHpbDr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id d124-20020a6bb482000000b006d9c1177a7dsi380463iof.3.2022.11.14.01.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 01:49:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id b131so12090739yba.11
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 01:49:14 -0800 (PST)
X-Received: by 2002:a5b:c4c:0:b0:6df:1528:d64c with SMTP id
 d12-20020a5b0c4c000000b006df1528d64cmr10081798ybr.143.1668419354248; Mon, 14
 Nov 2022 01:49:14 -0800 (PST)
MIME-Version: 1.0
References: <20221109194404.gonna.558-kees@kernel.org> <20221109200050.3400857-5-keescook@chromium.org>
In-Reply-To: <20221109200050.3400857-5-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Nov 2022 10:48:38 +0100
Message-ID: <CANpmjNO_ujNwaFxpsAWWXhBajhV8LJMXQjCHiSLHKG2Dc+od4A@mail.gmail.com>
Subject: Re: [PATCH v2 5/6] panic: Introduce warn_limit
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Baolin Wang <baolin.wang@linux.alibaba.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Petr Mladek <pmladek@suse.com>, tangmeng <tangmeng@uniontech.com>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, linux-doc@vger.kernel.org, 
	Greg KH <gregkh@linuxfoundation.org>, Linus Torvalds <torvalds@linuxfoundation.org>, 
	Seth Jenkins <sethjenkins@google.com>, Andy Lutomirski <luto@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Luis Chamberlain <mcgrof@kernel.org>, David Gow <davidgow@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Anton Vorontsov <anton@enomsg.org>, 
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NwOHpbDr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Wed, 9 Nov 2022 at 21:00, Kees Cook <keescook@chromium.org> wrote:
>
> Like oops_limit, add warn_limit for limiting the number of warnings when
> panic_on_warn is not set.
>
> Cc: Jonathan Corbet <corbet@lwn.net>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
> Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> Cc: Eric Biggers <ebiggers@google.com>
> Cc: Huang Ying <ying.huang@intel.com>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: linux-doc@vger.kernel.org
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  Documentation/admin-guide/sysctl/kernel.rst |  9 +++++++++
>  kernel/panic.c                              | 13 +++++++++++++
>  2 files changed, 22 insertions(+)
>
> diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
> index 09f3fb2f8585..c385d5319cdf 100644
> --- a/Documentation/admin-guide/sysctl/kernel.rst
> +++ b/Documentation/admin-guide/sysctl/kernel.rst
> @@ -1508,6 +1508,15 @@ entry will default to 2 instead of 0.
>  2 Unprivileged calls to ``bpf()`` are disabled
>  = =============================================================
>
> +
> +warn_limit
> +==========
> +
> +Number of kernel warnings after which the kernel should panic when
> +``panic_on_warn`` is not set. Setting this to 0 or 1 has the same effect
> +as setting ``panic_on_warn=1``.
> +
> +
>  watchdog
>  ========
>
> diff --git a/kernel/panic.c b/kernel/panic.c
> index 3afd234767bc..b235fa4a6fc8 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -58,6 +58,7 @@ bool crash_kexec_post_notifiers;
>  int panic_on_warn __read_mostly;
>  unsigned long panic_on_taint;
>  bool panic_on_taint_nousertaint = false;
> +static unsigned int warn_limit __read_mostly = 10000;
>
>  int panic_timeout = CONFIG_PANIC_TIMEOUT;
>  EXPORT_SYMBOL_GPL(panic_timeout);
> @@ -88,6 +89,13 @@ static struct ctl_table kern_panic_table[] = {
>                 .extra2         = SYSCTL_ONE,
>         },
>  #endif
> +       {
> +               .procname       = "warn_limit",
> +               .data           = &warn_limit,
> +               .maxlen         = sizeof(warn_limit),
> +               .mode           = 0644,
> +               .proc_handler   = proc_douintvec,
> +       },
>         { }
>  };
>
> @@ -203,8 +211,13 @@ static void panic_print_sys_info(bool console_flush)
>
>  void check_panic_on_warn(const char *reason)
>  {
> +       static atomic_t warn_count = ATOMIC_INIT(0);
> +
>         if (panic_on_warn)
>                 panic("%s: panic_on_warn set ...\n", reason);
> +
> +       if (atomic_inc_return(&warn_count) >= READ_ONCE(warn_limit))
> +               panic("Warned too often (warn_limit is %d)", warn_limit);

Shouldn't this also include the "reason", like above? (Presumably a
warning had just been generated to console so the reason is easy
enough to infer from the log, although in that case "reason" also
seems redundant above.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO_ujNwaFxpsAWWXhBajhV8LJMXQjCHiSLHKG2Dc%2Bod4A%40mail.gmail.com.
