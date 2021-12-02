Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOHHUKGQMGQEESC6QIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A9B4662C7
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 12:53:29 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id bl6-20020a05620a1a8600b0046803c08cccsf37224617qkb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 03:53:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638446008; cv=pass;
        d=google.com; s=arc-20160816;
        b=uHp0Buq90c6cH6G8IO5Yvn5lZTyOYJlLPE4HGo5qI0F9lnX5Ze35eU0jOWjsrtGYP+
         gROGiThAZmSAHSDrNnOxh0vOB8OybrM9mIEpg4Oum1/kTdi4lLcs1X85UqpD1E64Amia
         o4Wu8Tnba+nFizpd1pWJ6g/6p3yN3GpIM+xyuIJiOt62ySrc+mV5EpAetJveI4MgH+ut
         wYFHuRd8DK2yFjbJf+/pocDiAtiJGcayYMPRzRbWHUboQTchRJZUyVsjrK3xzvmEdwjp
         kX+LGc8opuPgRe2N7ckA8swyTCmhFOdE6jJjlrABIuPsp4F6OqbgJi9wO/2xXCVEVAZP
         YdCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mjlGXLikpyolt4Dd2chFNgQcDL/UebwSW2N/o/V/s40=;
        b=nLl+oeZaOC/RgiKFNsB2nnZzoZhOhVBJUOmHEEDLWX1/kLOd1DU9fP+bT//N/50dF+
         mNi+M+vaMdFyIQsCHIGc9NOoaOBTautsjaeJ9BInb3Fh6kcqSOlCO6wrpGs7nEjakwBB
         N8fO3VtPxV1qr4bai01WoDo0ZUdd/vi5f7cJOWc6k1hjJ8t3w2/6TXU2t/EoMHV0y2Ms
         qqdIQOXHI7ImMbgWDn63jrBH3TNBJ6ALrQY2dAeYsdgYGQFnGtHFTVlho9uT0jMO0lmV
         MqSeU/IuEEEghjF2vOJZ1Z/n9+EcZ/5Uj2aOOsd1sSKOUqDvfap++dweyYCHT84xvX+z
         G1YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=blIsLDwR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mjlGXLikpyolt4Dd2chFNgQcDL/UebwSW2N/o/V/s40=;
        b=qM+Z1P4PBUlQFA6l5pAoEECIQVfaGuG1zrnDkgLjpCEHMsKK3rMDzyWkzpcJBDJFxG
         0DsTE15F4fhZk0hXc7JFXE6L5cTRTxrKhZZQKC0QNnE79AEH8ZagBxgcS3cYaJK7bugw
         NFiHlII3Lt9IxPqTUedKx96bPwxfnPdkuXfjKonQUbcAq7q0Mb18COO6FR9+CH2/npjU
         PXeWATlVQBD2prkeohb4tJ40XVi88Hhya5MWgElOK0pv0AZLCmycM40wQd7/F+dthAZb
         GWpX6Q7p7Z2n1zepZrZOIRarGv2OPx9Hgj7s1luB/QUHCzstGK+VivprwU3wJayqFZOa
         JAsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mjlGXLikpyolt4Dd2chFNgQcDL/UebwSW2N/o/V/s40=;
        b=8HFnwgJveaBz2xvPDVUnuA5UOxllkUEItMZUeZ9Pr+aGAk7jlkfJ6TNrLR1XeYQEc3
         M4E4P0tBzJPrkr0i+EOSHs6VBhwyABUCj5wFpeTlwI0ShijiaZjnCwUrDwi05igE+MFZ
         Oye0+VdjfPsB+qYmQ0CKN7t50UJRHPAm2F/WnFkz3jbxWJth+JSNszB1qQgpONbrrQ1J
         i2gN60LH1fHbxzBE9BLT6rJl73r3qW3PfaBMC6YsKPOeM4gy2NjgI33U2Z3af/L56EJ0
         nQdTKyzYE/OErQTM8R91rAXy/V3mTwUT6eqwTqHeDhduE9acXISckN5f4Io43z43FXya
         dg/w==
X-Gm-Message-State: AOAM532/8YihywSQtC2lg/Z17+pphVcTrpSdvsA8BlBB7pmEj2eupTFM
	xVKgOzXVJs5JalRcEunpBfw=
X-Google-Smtp-Source: ABdhPJy9VFwDQ6qXA3vaG0E1B/DG5WZ4R4YfJSyt9zgjU9IcABpcyDne90cIKPMe8Qj+bXJUARRGNA==
X-Received: by 2002:ac8:5a07:: with SMTP id n7mr13065288qta.197.1638446008089;
        Thu, 02 Dec 2021 03:53:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1926:: with SMTP id bj38ls3790910qkb.7.gmail; Thu,
 02 Dec 2021 03:53:27 -0800 (PST)
X-Received: by 2002:a05:620a:4722:: with SMTP id bs34mr11659275qkb.181.1638446007668;
        Thu, 02 Dec 2021 03:53:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638446007; cv=none;
        d=google.com; s=arc-20160816;
        b=YKaPO6bjfYgUjOliilSt/p6gw9f56fqrojGdjPI7BECtqDHZZtsiicc3mbOjJ4tHOO
         Nx5P/NvweeX3enmR0Ae2cmzt4kMpEvzlWsHJjUuyMdQEZ3NvPp7lPkLhB/CIpri3zGbE
         RmQfy34DYpd0exVCckmt37FxKrA59SefOyqwxFV1KAplBxAwkcQDhONKcpd0hvc98p9E
         /1kj1tAmAM6sbOYzGQMqn/MmifLc3P0fLZWOSc5fI4TegcBLOfBnESHrtgjVd2DPrbiv
         TP/5NcTKIUBkaAIpMzxubtWCMFEc0iKJGkuMr97XAEgPx6/l/Y28mrXjTsuws5FN5p77
         rx9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ERyjVDLbvXPFw+1ZHIpwSYVMUQxNY4scWpUY/y6O0Jc=;
        b=ZkBv0RE4oIeZGgxIz7e0kjgUJ5phccD+yWTyGehh1rF4AYhCcUt+gd+69RO9E0r/Cr
         2gAG3Y9hSJRpbjN7sFLsaDajSCui0ajD8gCIE9hUmPVJ9dZhjWXsNnzHI9KZ4u2cvL/O
         AAa+Hac2Ok1S3BkWq8Upig4hQzrlC2+0KCStitv7YUsc3r26KDNRQb2hfbsDX2+8+iN7
         +b0zXhlkZeq/7ZC1UveWWdEhlsDfQn5qt95MUq8KoMB7Zc6SADfSegBN7CMY6OMsSJZu
         Ds7WjlqI5ZRzPOOZQVHhBLkc/DpgcIVZ5ijtx9OVyYaYKP9e6x73eUP2w8CWYE72kc1y
         NBUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=blIsLDwR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id u2si485235qkp.6.2021.12.02.03.53.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 03:53:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id r26so54880921oiw.5
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 03:53:27 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr4149176oie.134.1638446006972;
 Thu, 02 Dec 2021 03:53:26 -0800 (PST)
MIME-Version: 1.0
References: <20211202101238.33546-1-elver@google.com>
In-Reply-To: <20211202101238.33546-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 12:53:14 +0100
Message-ID: <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
Subject: Re: [PATCH] locking/mutex: Mark racy reads of owner->on_cpu
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>, 
	linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Kefeng Wang <wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=blIsLDwR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Thu, 2 Dec 2021 at 11:13, Marco Elver <elver@google.com> wrote:
> One of the more frequent data races reported by KCSAN is the racy read
> in mutex_spin_on_owner(), which is usually reported as "race of unknown
> origin" without showing the writer. This is due to the racing write
> occurring in kernel/sched. Locally enabling KCSAN in kernel/sched shows:
>
>  | write (marked) to 0xffff97f205079934 of 4 bytes by task 316 on cpu 6:
>  |  finish_task                kernel/sched/core.c:4632 [inline]
>  |  finish_task_switch         kernel/sched/core.c:4848
>  |  context_switch             kernel/sched/core.c:4975 [inline]
>  |  __schedule                 kernel/sched/core.c:6253
>  |  schedule                   kernel/sched/core.c:6326
>  |  schedule_preempt_disabled  kernel/sched/core.c:6385
>  |  __mutex_lock_common        kernel/locking/mutex.c:680
>  |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
>  |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
>  |  mutex_lock                 kernel/locking/mutex.c:283
>  |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
>  |  ...
>  |
>  | read to 0xffff97f205079934 of 4 bytes by task 322 on cpu 3:
>  |  mutex_spin_on_owner        kernel/locking/mutex.c:370
>  |  mutex_optimistic_spin      kernel/locking/mutex.c:480
>  |  __mutex_lock_common        kernel/locking/mutex.c:610
>  |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
>  |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
>  |  mutex_lock                 kernel/locking/mutex.c:283
>  |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
>  |  ...
>  |
>  | value changed: 0x00000001 -> 0x00000000
>
> This race is clearly intentional, and the potential for miscompilation
> is slim due to surrounding barrier() and cpu_relax(), and the value
> being used as a boolean.
>
> Nevertheless, marking this reader would more clearly denote intent and
> make it obvious that concurrency is expected. Use READ_ONCE() to avoid
> having to reason about compiler optimizations now and in future.
>
> Similarly, mark the read to owner->on_cpu in mutex_can_spin_on_owner(),
> which immediately precedes the loop executing mutex_spin_on_owner().
>
> Signed-off-by: Marco Elver <elver@google.com>
[...]

Kefeng kindly pointed out that there is an alternative, which would
refactor owner_on_cpu() from rwsem that would address both mutex and
rwsem:
https://lore.kernel.org/all/b641f1ea-6def-0fe4-d273-03c35c4aa7d6@huawei.com/

Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvPepakONMjTO%3DFzzeEtvq_CLjPN6%3DzF35j10rVrJ9Fg%40mail.gmail.com.
