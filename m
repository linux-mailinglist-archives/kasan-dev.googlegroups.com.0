Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVNW7FQMGQEQMROYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B57D39F35
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 08:00:56 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-6492220c4b8sf1736792d50.0
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 23:00:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768806054; cv=pass;
        d=google.com; s=arc-20240605;
        b=VvdnS3K67nEDsf993beDV0xk46lJVjSDn1eyJV7eOojaGiYI/yGzhB2nOnDxaGejQV
         hsA0y+t0CUxwCjC182JpZTJ+cE5HsrT9XFZvPu4A4gGhdOUmrxRVsKhzXPz8g37ktTMR
         nKkm+blvuYrPurPEkjBfvvBRffxxvQJ/AMVadPeZZmKOl8VSqcz6JREF/SbyOaE4Dgeg
         8jge/WzhpVKGapyXWwlbmTR/K5fgveBY0OlOGnVCxlxkM4vS5B4V3wKxH4m/3cG94rtv
         9q4tn/BAci9AGGisVzq/OWAXcTZhJcF+u596JZGRUE6f5PWY8y2zoqaxiJRn5MUxOM+j
         Fp2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qIhMM5LJ41LY4HdMsmdKiQmmDYs7EMGQf4zngFHGhyM=;
        fh=3czU4DShq+MGNliL2aNXOFcFSf3hdtfHtd8sMvPPoLo=;
        b=lyFKUf8BvQEFVR34v1JUZuDMOHo2fUHDF6rmfHGYGposv53ZliUbrk/teW4PGKDyC9
         kam7oaenRmetJzpknQjc9ihU+0Zi7s4D2p7ILe/VrtS9mvMWfahIwxcmnH2sgVcny9Yg
         OWiDnFyQIgPKzYpcxele2hJTDmy8NzLvlirBSN5S/JHMAx8hZqYl/5zAgjRWSKQIrGYm
         WbpX36jXH24z3pKCgaFC8rz3xYKJKnSn7LUh5XDFAIJj9vGmc/oqhrxBn+WCfO0Td+YZ
         qfmSvsgJrjgxqVzPF/CfrEKW2LBHNnBy5zVM2SIdkeQMmRyI0oVmTI3pIi3HUFde49z/
         b+2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k4SCOoc9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768806054; x=1769410854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qIhMM5LJ41LY4HdMsmdKiQmmDYs7EMGQf4zngFHGhyM=;
        b=sXO7Dg96sFhJoHVCn460mOiOlUwngDHQk09CX61gdk5LBhlboLvgtLK+a6/vn4kvBe
         eYZHIeJz8S4FbRAkV6qw+jUYAbfl1/iAREBT1N1bK5h9rTtYsoQlNTIIpEgIVJEGgYxc
         J/0bpOkt3Jgkv4+2zPWlC6iL5n7xkyIxRHB8JVt4KsBlh2gpykFPFjT0LyNWZ8U2tvRr
         1MARg8p1Rnz9+3jBxeCnvKKEanyb1vqSM7d6DqtFqIfsEkroTkOYP8Me62l4ecSizGYP
         tcXpdR/fpQA8l9XvKQ3JskaCwCjTtqEiMdxfkZRg2Ni5QZj/ddBuLGaELUZG7093Yjsf
         RHzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768806054; x=1769410854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qIhMM5LJ41LY4HdMsmdKiQmmDYs7EMGQf4zngFHGhyM=;
        b=V6SkcPtJokC//BViJ1k9zkK5jvXqejQYlmWN2cH3riI3QTsVU1qXItmykA92I/y2hP
         p8snc5a28zAmZlccADeHAa8OMHLeAeEKFQYNmUPuTG2ys3W6hFV7Zy/hy8fJ0jEfkvtm
         qsT8OI5ayv8Ek8qNlLL5Da676su8tffYpoQtMdxdQvvFVsNlXoFM1yoUGUD+3+sHW8va
         Z/rAyMA030M5PtyRV5xdqg0ba/SjPyBFxBX4CbmaLGJ+U5xuXYbbSzRHbFa3z8nTJt2j
         HgZ7eXMGQ4GW2JI2kSq6ZCQE/qH/WLMMEC6syJ2Qmo3Dr9TXive/petnbKWXY+rlf9Yp
         qw3Q==
X-Forwarded-Encrypted: i=2; AJvYcCWVucpCUDCbiW3NrWbXsFWGLwBMrh1179JrOimVNbXJ2Ni+N8XtzcaOEsQ2MNilPJlFODUrjQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz7HpILnuVhUT/U2/mf6o/LKa36R0ch4rvzvUH3Li54/pv/xYuO
	6oUQ0mVugDWLmV4E73PehjM/kD3j4tEuQdrQd1/jtOa0rEO+i7z9+gmR
X-Received: by 2002:a05:690e:150a:b0:645:61fc:43c2 with SMTP id 956f58d0204a3-6491648acbcmr7920823d50.8.1768806054377;
        Sun, 18 Jan 2026 23:00:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HlccR45K2PatN+xGL6MKRMATKvA5gvmaQGs5nb1UtV4g=="
Received: by 2002:a53:bb05:0:b0:647:27b0:1aa2 with SMTP id 956f58d0204a3-6490b940ddels2794725d50.3.-pod-prod-02-us;
 Sun, 18 Jan 2026 23:00:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWW3ZtDkyH2SblYhdv1F0QPB4hh9RTMan0Ll0LjDHBsTeSRyj0C0Aj7T2UYjy8dA9lDbk9OJ7bpV4=@googlegroups.com
X-Received: by 2002:a05:690c:7346:b0:78f:ab02:f847 with SMTP id 00721157ae682-793c52b24f4mr92714937b3.30.1768806053153;
        Sun, 18 Jan 2026 23:00:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768806053; cv=none;
        d=google.com; s=arc-20240605;
        b=Q7vKweQXJcaVYS6Fd9wbz8TfSnlWZk5zuzq3FukAsYqG4HfbqTG+5oaQJKkASzKAPT
         AKY1P1+SQCSfwypRoSZ7fkRE30IGDxFbEXYrU6XEO3Yt859eMNCIMoKCykI31AdAfEcw
         Fl0bLpBR00DTibfXLQpxXrjgRRAC5H8n0WcU5IpG8aJLlybIaNa8z6dGDGDNCKCWgC7A
         fBsU/9SDalgXYOVVmq4Vimy7roaPXdOQ84vZGpDhe8cgLbWkVEt5owc3VVT9jhMuX6de
         70DZBlrPBxlbtt3Atm4/hvSNNkGmwayH6Se8m9KGYwL74m90ow5sexQWL9CDlxqeFLRw
         FLHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fo5muEEC/4uiFscWJK7IYUZtOorTUjdByfuGa30k45c=;
        fh=TNxZjkhnifwe1mARbHzsgHr0qaG9/BS//V2fX3F9knI=;
        b=G+Eyqp2UcE/ZXtgGi65wzLsq1+ikDEYv48t50l6uzctEatELlD32B3isGPhdDu8Cb7
         lae7CG4cBZCY8DNgsI2fdid8p80MKU7bp6iwtZevYRaGUaGYDpDjrt3voE4sw2WNlCER
         9Or9nkRrCwYirQXriQocXaDaMSuO/2WjvNfFIjNO0NAFH0M6IgcCcXC5/froL2L8SyJm
         7N/Fc7lthQuZ8K9/7TkS11mo3dx6rGQugfdHdHT8qqR9+hGn3/5BhIM6FswQ5fmxwYHk
         /7iWqnVgHxYDqc9U57Dn5QcKOP2iA6/7E6ENtBUUQ+XVbxWbnOvy2aObFgb2HUHNp5yC
         dbjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k4SCOoc9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1234.google.com (mail-dl1-x1234.google.com. [2607:f8b0:4864:20::1234])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c680fecbsi2209147b3.6.2026.01.18.23.00.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Jan 2026 23:00:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) client-ip=2607:f8b0:4864:20::1234;
Received: by mail-dl1-x1234.google.com with SMTP id a92af1059eb24-12331482b8fso5857815c88.1
        for <kasan-dev@googlegroups.com>; Sun, 18 Jan 2026 23:00:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUp/xnk7nH6XVSuB+h31L4DqALII7ChdQ4nw94vIuuBM9kqAfQH31DlwMQbxxLhBdMw6tx5nP8zBlM=@googlegroups.com
X-Gm-Gg: AY/fxX6Mxklbs82cIk0pCG8dV4IfCuM9tZxHo31H/3zsdiyXYkKakziu3EQZPsgzwal
	tljF8DAYHyuniGXZe5HQWofcxsVHadvjspdu389ZHi4Xk8fYx03ZK16xqnKuBgpAJDRiPmxgsN3
	H0bJWYxclSG8IsPySc7uwDH08J+mVqzEIMALfDuab6X9W4Bi9SZyheONCvMW0uLjwbo3EYqCJou
	to6RzAi7ulKejWADUAhYBfruOhuP9iSaYyRBbFZEslvDvzG0rMdEoRHMIoxEGXVn5R7jn5uv8li
	wC7QZMNuvSAMJxBIlO9MkMcXEQ==
X-Received: by 2002:a05:7022:e24:b0:119:e56b:959c with SMTP id
 a92af1059eb24-1244a780e97mr9208724c88.33.1768806052109; Sun, 18 Jan 2026
 23:00:52 -0800 (PST)
MIME-Version: 1.0
References: <20260116-kfence_fix-v1-1-4165a055933f@debian.org>
In-Reply-To: <20260116-kfence_fix-v1-1-4165a055933f@debian.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Jan 2026 08:00:00 +0100
X-Gm-Features: AZwV_Qj-7_C5RZeZFEzQ_TdoyMwljOGRCUd8lyAzdaF4C9d9CcGc1VCTIQrXvPk
Message-ID: <CANpmjNP5R3ALvtuMyLVhHGZpyZ2MoR7hq07jJFcSAN62Cnig2g@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: fix potential deadlock in reboot notifier
To: Breno Leitao <leitao@debian.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, clm@meta.com, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=k4SCOoc9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 16 Jan 2026 at 16:49, Breno Leitao <leitao@debian.org> wrote:
>
> The reboot notifier callback can deadlock when calling
> cancel_delayed_work_sync() if toggle_allocation_gate() is blocked
> in wait_event_idle() waiting for allocations, that might not happen on
> shutdown path.
>
> The issue is that cancel_delayed_work_sync() waits for the work to
> complete, but the work is waiting for kfence_allocation_gate > 0
> which requires allocations to happen (each allocation is increated by 1)

increated -> increased

> - allocations that may have stopped during shutdown.
>
> Fix this by:
> 1. Using cancel_delayed_work() (non-sync) to avoid blocking. Now the
>    callback succeeds and return.
> 2. Adding wake_up() to unblock any waiting toggle_allocation_gate()
> 3. Adding !kfence_enabled to the wait condition so the wake succeeds
>
> The static_branch_disable() IPI will still execute after the wake,
> but at this early point in shutdown (reboot notifier runs with
> INT_MAX priority), the system is still functional and CPUs can
> respond to IPIs.
>
> Reported-by: Chris Mason <clm@meta.com>
> Closes: https://lore.kernel.org/all/20260113140234.677117-1-clm@meta.com/
> Fixes: ce2bba89566b ("mm/kfence: add reboot notifier to disable KFENCE on shutdown")
> Signed-off-by: Breno Leitao <leitao@debian.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 17 ++++++++++++-----
>  1 file changed, 12 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 577a1699c553..da0f5b6f5744 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -823,6 +823,9 @@ static struct notifier_block kfence_check_canary_notifier = {
>  static struct delayed_work kfence_timer;
>
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> +/* Wait queue to wake up allocation-gate timer task. */
> +static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
> +
>  static int kfence_reboot_callback(struct notifier_block *nb,
>                                   unsigned long action, void *data)
>  {
> @@ -832,7 +835,12 @@ static int kfence_reboot_callback(struct notifier_block *nb,
>          */
>         WRITE_ONCE(kfence_enabled, false);
>         /* Cancel any pending timer work */
> -       cancel_delayed_work_sync(&kfence_timer);
> +       cancel_delayed_work(&kfence_timer);
> +       /*
> +        * Wake up any blocked toggle_allocation_gate() so it can complete
> +        * early while the system is still able to handle IPIs.
> +        */
> +       wake_up(&allocation_wait);
>
>         return NOTIFY_OK;
>  }
> @@ -842,9 +850,6 @@ static struct notifier_block kfence_reboot_notifier = {
>         .priority = INT_MAX, /* Run early to stop timers ASAP */
>  };
>
> -/* Wait queue to wake up allocation-gate timer task. */
> -static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
> -
>  static void wake_up_kfence_timer(struct irq_work *work)
>  {
>         wake_up(&allocation_wait);
> @@ -873,7 +878,9 @@ static void toggle_allocation_gate(struct work_struct *work)
>         /* Enable static key, and await allocation to happen. */
>         static_branch_enable(&kfence_allocation_key);
>
> -       wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate) > 0);
> +       wait_event_idle(allocation_wait,
> +                       atomic_read(&kfence_allocation_gate) > 0 ||
> +                       !READ_ONCE(kfence_enabled));
>
>         /* Disable static key and reset timer. */
>         static_branch_disable(&kfence_allocation_key);
>
> ---
> base-commit: 983d014aafb14ee5e4915465bf8948e8f3a723b5
> change-id: 20260116-kfence_fix-9905b284f1cc
>
> Best regards,
> --
> Breno Leitao <leitao@debian.org>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP5R3ALvtuMyLVhHGZpyZ2MoR7hq07jJFcSAN62Cnig2g%40mail.gmail.com.
