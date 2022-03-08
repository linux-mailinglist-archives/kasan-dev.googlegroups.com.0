Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIWPTWIQMGQEVVBISQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id A34AD4D1A6E
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 15:26:43 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id b123-20020a676781000000b003209539ae10sf844599vsc.13
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 06:26:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646749602; cv=pass;
        d=google.com; s=arc-20160816;
        b=ty1yEvg1RVN59aCNzyuR1X4E/MBvqx7eJFRj4T6lmY3S7Y1ktSfTp7Bt/MxRSK6Zzh
         ZJnkrcOF5VFjdpejEZ35RvhfAbQV2aOcgu4wBpHwzKQZVaSOLBFUxmYPalvIFqZD1Hnl
         VOSgWaKefljHPqVcLNO6t9gtcnXp0BeBLsUV5jl8n59P3upizX0zzha/zHxUM2oyEIxd
         GPgEU3Tp5nvvlT88jiymZXk2uP3lctDgTnVW5Lu15sovS5agpv+I5VMTV7Kkm+Q8AsQj
         86kGHv07yVVxyZ0a8bPwfKCEYTDdFNdY+Z4/uPfbwnTbcS+0jrndZYqV/Yr9dtTb43Jl
         RVSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Knlf8af3DJnwSmS9yCtxdozarbOyHovdFJ1WbEXwF1w=;
        b=djuafQJayIvrOQ+q17i0HYXeucHYT9LpkCdhESXouv/IDtWJ9nRROsgN8hktG4Kk+Z
         8uanJkYrJr7rwivK8VDesHukut9D3702SdqNUZSF+U2of8B7J/e18zJ32cEDiWYPWNHd
         i7mzJrvZzK1jaeu2ce0gitdMtPyAsQn5ME5m2hlnEddvuBd7EDmvEQ5mauq0Js220lN9
         HdDp6bKpX+cmegUgsTsV9k9fdEGzPct2mblHvh9MLr1BAAQPm8vEoZu/XI572PxbLhnX
         V+uJaT++21vsQkdedUB+NOc96jRjAUWp/39tfovBBiqski42dyNVpBMTTPul17yjl0wI
         1eNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="mm/r7zUm";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Knlf8af3DJnwSmS9yCtxdozarbOyHovdFJ1WbEXwF1w=;
        b=YZmstN9nbELo2ou+TQgtYbuKyu7xOFqD7otzfLqPaGfNkQYkJuXZNhYSRDtzyNaYjF
         epAMuW3S/PgM9LOZLOt4R0qqJPLKQbCiwjRtZAdmRHX+X7SeEuZsgp8gAZGgwrRE8bPg
         +Le8zBze8MJVGHn4hykqsBWFdJU6YjdaEBDQ8o9eEfYnkFffN7hnnr5wo8N5uSkwwFq1
         sZBtmaKUIAaRJUHcjHL8nCA2tH5ao0bCbQhGfGGtydeRECPwxZq8S9Lfbx3f4bezuz2Q
         As9dhaTcO0dloNjuYc2pjLYi8BZE3Q9yATcfJSnDGzXqYonkuiDK0vLEDQ19nA0DOWaD
         jY4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Knlf8af3DJnwSmS9yCtxdozarbOyHovdFJ1WbEXwF1w=;
        b=qHJSEOoWsbm/T7RYZcMRw4q08P1o9tAkYFW8o21iQA9MSzJhzh1kHSwMa6tHu8VJWw
         QEnF9LPBSzyzxVSHuQuG5E9J12kqRu5jt6ODXYWTwMV8EjPFaPMCofriH891ISRvwaDz
         pp26O8FSwwT+jndfu332TkO/4JKqSZHn9tUbYFVXHGcdBwZxKzqu8qDmSfqeet5BSh07
         eS7LjRVdfVulB7QIbc7xHpi8WxIDVJUMjWt+nahEfVLndp8qhvuKtkGzghOl7ADq40xK
         uHNw7jf6IN7hgJM8GYrGHHT1/WhcwUbe+9g0YCL+uI5a5yibejCE5Et1WVgS5rbTeUBi
         LMug==
X-Gm-Message-State: AOAM532RSwncPpr3ArtHS1kUv5c9M9Zg9/Wu+vE4hlzk0j4ay21xhGf+
	TmcqW3BqyhiQP4tSaMRKZnU=
X-Google-Smtp-Source: ABdhPJzjTiL+3OerfDikdFFaIRYAXhWQ2JsZ+J1RlEHxz7oYTBVDAhcmWFerNinlkJYyIsagrfjikQ==
X-Received: by 2002:a67:1784:0:b0:320:c218:99cc with SMTP id 126-20020a671784000000b00320c21899ccmr4193937vsx.36.1646749602660;
        Tue, 08 Mar 2022 06:26:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3098:b0:322:79fb:890e with SMTP id
 l24-20020a056102309800b0032279fb890els260823vsb.8.gmail; Tue, 08 Mar 2022
 06:26:42 -0800 (PST)
X-Received: by 2002:a05:6102:a90:b0:31b:6ed9:7702 with SMTP id n16-20020a0561020a9000b0031b6ed97702mr6905486vsg.70.1646749602114;
        Tue, 08 Mar 2022 06:26:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646749602; cv=none;
        d=google.com; s=arc-20160816;
        b=IYX+ckI9gZaFlimTqAfLwCAnQK5TgUTPbXmb+wtcwzaqJSJ7Ibp1UVT2Ev2C8FFN2G
         zDWpA3tq9dKRSVJwjPdwxgjYWCC1Z6ufg1y0zEPhHlEJptJIKrqiswB4AakHE8O5YD4l
         F2aVaygEEliZXy2Ag3xtUq8gpRDDbxrR28f+k/L+DF8mCOJYirnXEGc7ryODk4eDTrKu
         +yBQ8kFywdSIl7ALd2NcRUozHSD22gaIRVFYvxKFBNQEDdFU6dSAUPFglosnufd/vVo/
         e691GJWv2qHbt1O5yDlzyjEkJrcVmvwgJDx2VH1VuVh+hK6c9DcJpTm7b2udoGuAxIxN
         cB0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O5s1Kk/lxO3O1i26XInZyMyYmKkC+n7Z3tXbuJ1ASrM=;
        b=JyqI8whPrklli4i/Q54aWXwQxLllcqGDAtf7xGTPwnHXdWvBFyIBdguwu8nD6wIlw7
         IDg1Bc3AWY495ghDDMQVTDbVttbHM7eGUWu+AcER/Yi3gbKjiKpd7f1xMgxdAXy+dHpa
         NZNJNhqP/Y8etqXfZ4mBqq1mPAXpilnU0gigsMCAmRnrxEkKillZT51oa9ZSEPJPiPn+
         rFKAJkhPBW/t8oG/W5hmjMSrxS3AHfBMEf+RDwCHlGQ0xN/HY2/LjlyEhBxsX2G3RrUt
         B+W1hS6OwPIXirtwSe8vkt9IA0RmHd3qSKRZRfAH4voBZlJBf1e064O76SpUNlLJw+sk
         rjLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="mm/r7zUm";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id x8-20020a67e888000000b00320914873cfsi706866vsn.2.2022.03.08.06.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 06:26:42 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id c4so16241494qtx.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 06:26:42 -0800 (PST)
X-Received: by 2002:a05:622a:18a6:b0:2dd:2c5b:ca00 with SMTP id
 v38-20020a05622a18a600b002dd2c5bca00mr13533464qtc.549.1646749601587; Tue, 08
 Mar 2022 06:26:41 -0800 (PST)
MIME-Version: 1.0
References: <20220308141415.3168078-1-elver@google.com>
In-Reply-To: <20220308141415.3168078-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Mar 2022 15:26:05 +0100
Message-ID: <CAG_fn=XafP3dDdbMeePghNWFvuHPhLXqx0ktwUeqVMC-LwPNYw@mail.gmail.com>
Subject: Re: [PATCH v2] kfence: allow use of a deferrable timer
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: multipart/alternative; boundary="00000000000009cd1405d9b5c5ce"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="mm/r7zUm";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::833 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--00000000000009cd1405d9b5c5ce
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Tue, Mar 8, 2022 at 3:14 PM Marco Elver <elver@google.com> wrote:

> Allow the use of a deferrable timer, which does not force CPU wake-ups
> when the system is idle. A consequence is that the sample interval
> becomes very unpredictable, to the point that it is not guaranteed that
> the KFENCE KUnit test still passes.
>
> Nevertheless, on power-constrained systems this may be preferable, so
> let's give the user the option should they accept the above trade-off.
>
> Signed-off-by: Marco Elver <elver@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> v2:
> * Add more documentation.
> * Remove 'if EXPERT' from Kconfig option since it's configurable via
>   kernel boot param anyway.
> ---
>  Documentation/dev-tools/kfence.rst | 12 ++++++++++++
>  lib/Kconfig.kfence                 | 12 ++++++++++++
>  mm/kfence/core.c                   | 15 +++++++++++++--
>  3 files changed, 37 insertions(+), 2 deletions(-)
>
> diff --git a/Documentation/dev-tools/kfence.rst
> b/Documentation/dev-tools/kfence.rst
> index ac6b89d1a8c3..936f6aaa75c8 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -41,6 +41,18 @@ guarded by KFENCE. The default is configurable via the
> Kconfig option
>  ``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=3D0`=
`
>  disables KFENCE.
>
> +The sample interval controls a timer that sets up KFENCE allocations. By
> +default, to keep the real sample interval predictable, the normal timer
> also
> +causes CPU wake-ups when the system is completely idle. This may be
> undesirable
> +on power-constrained systems. The boot parameter ``kfence.deferrable=3D1=
``
> +instead switches to a "deferrable" timer which does not force CPU
> wake-ups on
> +idle systems, at the risk of unpredictable sample intervals. The default
> is
> +configurable via the Kconfig option ``CONFIG_KFENCE_DEFERRABLE``.
> +
> +.. warning::
> +   The KUnit test suite is very likely to fail when using a deferrable
> timer
> +   since it currently causes very unpredictable sample intervals.
> +
>  The KFENCE memory pool is of fixed size, and if the pool is exhausted, n=
o
>  further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS``
> (default
>  255), the number of available guarded objects can be controlled. Each
> object
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 912f252a41fc..459dda9ef619 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS
>           pages are required; with one containing the object and two
> adjacent
>           ones used as guard pages.
>
> +config KFENCE_DEFERRABLE
> +       bool "Use a deferrable timer to trigger allocations"
> +       help
> +         Use a deferrable timer to trigger allocations. This avoids
> forcing
> +         CPU wake-ups if the system is idle, at the risk of a less
> predictable
> +         sample interval.
> +
> +         Warning: The KUnit test suite fails with this option enabled -
> due to
> +         the unpredictability of the sample interval!
> +
> +         Say N if you are unsure.
> +
>  config KFENCE_STATIC_KEYS
>         bool "Use static keys to set up allocations" if EXPERT
>         depends on JUMP_LABEL
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f126b53b9b85..2f9fdfde1941 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -95,6 +95,10 @@ module_param_cb(sample_interval,
> &sample_interval_param_ops, &kfence_sample_inte
>  static unsigned long kfence_skip_covered_thresh __read_mostly =3D 75;
>  module_param_named(skip_covered_thresh, kfence_skip_covered_thresh,
> ulong, 0644);
>
> +/* If true, use a deferrable timer. */
> +static bool kfence_deferrable __read_mostly =3D
> IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
> +module_param_named(deferrable, kfence_deferrable, bool, 0444);
> +
>  /* The pool of pages used for guard pages and objects. */
>  char *__kfence_pool __read_mostly;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> @@ -740,6 +744,8 @@ late_initcall(kfence_debugfs_init);
>
>  /* =3D=3D=3D Allocation Gate Timer
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */
>
> +static struct delayed_work kfence_timer;
> +
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
>  /* Wait queue to wake up allocation-gate timer task. */
>  static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
> @@ -762,7 +768,6 @@ static DEFINE_IRQ_WORK(wake_up_kfence_timer_work,
> wake_up_kfence_timer);
>   * avoids IPIs, at the cost of not immediately capturing allocations if
> the
>   * instructions remain cached.
>   */
> -static struct delayed_work kfence_timer;
>  static void toggle_allocation_gate(struct work_struct *work)
>  {
>         if (!READ_ONCE(kfence_enabled))
> @@ -790,7 +795,6 @@ static void toggle_allocation_gate(struct work_struct
> *work)
>         queue_delayed_work(system_unbound_wq, &kfence_timer,
>                            msecs_to_jiffies(kfence_sample_interval));
>  }
> -static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
>
>  /* =3D=3D=3D Public interface
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D */
>
> @@ -809,8 +813,15 @@ static void kfence_init_enable(void)
>  {
>         if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
>                 static_branch_enable(&kfence_allocation_key);
> +
> +       if (kfence_deferrable)
> +               INIT_DEFERRABLE_WORK(&kfence_timer,
> toggle_allocation_gate);
> +       else
> +               INIT_DELAYED_WORK(&kfence_timer, toggle_allocation_gate);
> +
>         WRITE_ONCE(kfence_enabled, true);
>         queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +
>         pr_info("initialized - using %lu bytes for %d objects at
> 0x%p-0x%p\n", KFENCE_POOL_SIZE,
>                 CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
>                 (void *)(__kfence_pool + KFENCE_POOL_SIZE));
> --
> 2.35.1.616.g0bdcbb4464-goog
>
>

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erhalt=
en
haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen,
dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by mistake,
please don't forward it to anyone else, please erase all copies and
attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXafP3dDdbMeePghNWFvuHPhLXqx0ktwUeqVMC-LwPNYw%40mail.gmai=
l.com.

--00000000000009cd1405d9b5c5ce
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Tue, Mar 8, 2022 at 3:14 PM Marco =
Elver &lt;<a href=3D"mailto:elver@google.com">elver@google.com</a>&gt; wrot=
e:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0=
.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">Allow the use=
 of a deferrable timer, which does not force CPU wake-ups<br>
when the system is idle. A consequence is that the sample interval<br>
becomes very unpredictable, to the point that it is not guaranteed that<br>
the KFENCE KUnit test still passes.<br>
<br>
Nevertheless, on power-constrained systems this may be preferable, so<br>
let&#39;s give the user the option should they accept the above trade-off.<=
br>
<br>
Signed-off-by: Marco Elver &lt;<a href=3D"mailto:elver@google.com" target=
=3D"_blank">elver@google.com</a>&gt;<br></blockquote><div>Reviewed-by: Alex=
ander Potapenko &lt;<a href=3D"mailto:glider@google.com">glider@google.com<=
/a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0p=
x 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
---<br>
v2:<br>
* Add more documentation.<br>
* Remove &#39;if EXPERT&#39; from Kconfig option since it&#39;s configurabl=
e via<br>
=C2=A0 kernel boot param anyway.<br>
---<br>
=C2=A0Documentation/dev-tools/kfence.rst | 12 ++++++++++++<br>
=C2=A0lib/Kconfig.kfence=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0| 12 ++++++++++++<br>
=C2=A0mm/kfence/core.c=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0| 15 +++++++++++++--<br>
=C2=A03 files changed, 37 insertions(+), 2 deletions(-)<br>
<br>
diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/k=
fence.rst<br>
index ac6b89d1a8c3..936f6aaa75c8 100644<br>
--- a/Documentation/dev-tools/kfence.rst<br>
+++ b/Documentation/dev-tools/kfence.rst<br>
@@ -41,6 +41,18 @@ guarded by KFENCE. The default is configurable via the K=
config option<br>
=C2=A0``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=
=3D0``<br>
=C2=A0disables KFENCE.<br>
<br>
+The sample interval controls a timer that sets up KFENCE allocations. By<b=
r>
+default, to keep the real sample interval predictable, the normal timer al=
so<br>
+causes CPU wake-ups when the system is completely idle. This may be undesi=
rable<br>
+on power-constrained systems. The boot parameter ``kfence.deferrable=3D1``=
<br>
+instead switches to a &quot;deferrable&quot; timer which does not force CP=
U wake-ups on<br>
+idle systems, at the risk of unpredictable sample intervals. The default i=
s<br>
+configurable via the Kconfig option ``CONFIG_KFENCE_DEFERRABLE``.<br>
+<br>
+.. warning::<br>
+=C2=A0 =C2=A0The KUnit test suite is very likely to fail when using a defe=
rrable timer<br>
+=C2=A0 =C2=A0since it currently causes very unpredictable sample intervals=
.<br>
+<br>
=C2=A0The KFENCE memory pool is of fixed size, and if the pool is exhausted=
, no<br>
=C2=A0further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` =
(default<br>
=C2=A0255), the number of available guarded objects can be controlled. Each=
 object<br>
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence<br>
index 912f252a41fc..459dda9ef619 100644<br>
--- a/lib/Kconfig.kfence<br>
+++ b/lib/Kconfig.kfence<br>
@@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pages are required; with one containing =
the object and two adjacent<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ones used as guard pages.<br>
<br>
+config KFENCE_DEFERRABLE<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0bool &quot;Use a deferrable timer to trigger al=
locations&quot;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0help<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Use a deferrable timer to trigger alloca=
tions. This avoids forcing<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0CPU wake-ups if the system is idle, at t=
he risk of a less predictable<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0sample interval.<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Warning: The KUnit test suite fails with=
 this option enabled - due to<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0the unpredictability of the sample inter=
val!<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Say N if you are unsure.<br>
+<br>
=C2=A0config KFENCE_STATIC_KEYS<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 bool &quot;Use static keys to set up allocation=
s&quot; if EXPERT<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 depends on JUMP_LABEL<br>
diff --git a/mm/kfence/core.c b/mm/kfence/core.c<br>
index f126b53b9b85..2f9fdfde1941 100644<br>
--- a/mm/kfence/core.c<br>
+++ b/mm/kfence/core.c<br>
@@ -95,6 +95,10 @@ module_param_cb(sample_interval, &amp;sample_interval_pa=
ram_ops, &amp;kfence_sample_inte<br>
=C2=A0static unsigned long kfence_skip_covered_thresh __read_mostly =3D 75;=
<br>
=C2=A0module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, u=
long, 0644);<br>
<br>
+/* If true, use a deferrable timer. */<br>
+static bool kfence_deferrable __read_mostly =3D IS_ENABLED(CONFIG_KFENCE_D=
EFERRABLE);<br>
+module_param_named(deferrable, kfence_deferrable, bool, 0444);<br>
+<br>
=C2=A0/* The pool of pages used for guard pages and objects. */<br>
=C2=A0char *__kfence_pool __read_mostly;<br>
=C2=A0EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */<br>
@@ -740,6 +744,8 @@ late_initcall(kfence_debugfs_init);<br>
<br>
=C2=A0/* =3D=3D=3D Allocation Gate Timer =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */<br>
<br>
+static struct delayed_work kfence_timer;<br>
+<br>
=C2=A0#ifdef CONFIG_KFENCE_STATIC_KEYS<br>
=C2=A0/* Wait queue to wake up allocation-gate timer task. */<br>
=C2=A0static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);<br>
@@ -762,7 +768,6 @@ static DEFINE_IRQ_WORK(wake_up_kfence_timer_work, wake_=
up_kfence_timer);<br>
=C2=A0 * avoids IPIs, at the cost of not immediately capturing allocations =
if the<br>
=C2=A0 * instructions remain cached.<br>
=C2=A0 */<br>
-static struct delayed_work kfence_timer;<br>
=C2=A0static void toggle_allocation_gate(struct work_struct *work)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!READ_ONCE(kfence_enabled))<br>
@@ -790,7 +795,6 @@ static void toggle_allocation_gate(struct work_struct *=
work)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 queue_delayed_work(system_unbound_wq, &amp;kfen=
ce_timer,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0msecs_to_jiffies(kfence_sample_interval));<br>
=C2=A0}<br>
-static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);<br>
<br>
=C2=A0/* =3D=3D=3D Public interface =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */<br>
<br>
@@ -809,8 +813,15 @@ static void kfence_init_enable(void)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 static_branch_enabl=
e(&amp;kfence_allocation_key);<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (kfence_deferrable)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0INIT_DEFERRABLE_WOR=
K(&amp;kfence_timer, toggle_allocation_gate);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0else<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0INIT_DELAYED_WORK(&=
amp;kfence_timer, toggle_allocation_gate);<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 WRITE_ONCE(kfence_enabled, true);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 queue_delayed_work(system_unbound_wq, &amp;kfen=
ce_timer, 0);<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_info(&quot;initialized - using %lu bytes for=
 %d objects at 0x%p-0x%p\n&quot;, KFENCE_POOL_SIZE,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 CONFIG_KFENCE_NUM_O=
BJECTS, (void *)__kfence_pool,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 (void *)(__kfence_p=
ool + KFENCE_POOL_SIZE));<br>
-- <br>
2.35.1.616.g0bdcbb4464-goog<br>
<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde.<br><br><br>This e-mail is confidential. If you received this commun=
ication by mistake, please don&#39;t forward it to anyone else, please eras=
e all copies and attachments, and please let me know that it has gone to th=
e wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DXafP3dDdbMeePghNWFvuHPhLXqx0ktwUeqVMC-LwPNYw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DXafP3dDdbMeePghNWFvuHPhLXqx0ktwUeqVMC-Lw=
PNYw%40mail.gmail.com</a>.<br />

--00000000000009cd1405d9b5c5ce--
