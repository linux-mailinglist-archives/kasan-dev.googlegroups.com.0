Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOMDWD6QKGQEEDCVS7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AAB72AF4A7
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:22:34 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id t70sf1917874qka.11
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605108153; cv=pass;
        d=google.com; s=arc-20160816;
        b=fBB9ypewWuhgkPOzV/GLD8qsGNxK/zujT/0ApL9E9DMggl8M8rNPTI/uRtqEMnvohc
         I7Ojk1tsHnZ2qP5zCj8Dp+tP8hbqt77Umef2uoUUaIag/B3FGp8RzyFNAiBe2dIcDIe3
         3A0ASUiwgwgH7YCotKVJwPCA+lAV7iGrbzI72BTlyCmySpNd0slYJK3Ftr20oTUHQ9xs
         YydpmdTk/GIfZHxoTgBoPSHCu3d29zpTCTkLdWo0JLXTpeO4+gEHPibjy+5nR8GSe+D9
         Z4LQ9ZnLX96I2Pc8XmM3ElvaYy+D152A18Vy1iJN0kyR2o4eSJp6N/twkcGjvvdeeM/t
         zzHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ev5TfjPY/k5YA3sJ4jKIQtbiWkljOy7x6EeUUsVvKvg=;
        b=ScfgOiHZptUsEJoBHEMSSEl20hLP0wPGydF81jWuD2uyp6HgCKAIswERRUvXK6DO10
         WY6R4RH4D2CqiDW6KDs3etm8xeiQv6XUAMLG3S1kOwsuXJxqNI5xUiMGadiXwTEuIPbE
         3lr6NLYgZp2Chob7FEJ5OvENWCoGj0twXAdpJSfoUqE04YjatuoVoNkjupi9sNvhMPwm
         9Dqg8SzicieymYQ37J1RxdtstrLn10urVsS8To4nXyhfY0eV0/32KHrQD+GbWFO9Dcqt
         QNXg/AITBKZeAEV8qNpJpZRHQ4M/UMlHKsbceOG5DXouaGnSZOhdLkwo+Gv5bL8hua5e
         ijvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="doby/aOl";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ev5TfjPY/k5YA3sJ4jKIQtbiWkljOy7x6EeUUsVvKvg=;
        b=GjfZyG2d1oxWhFSoVySh6Y2h/8EsyLT5JHs3/Rv1k2S0g03CPGEI4Z9LQcd/ClfFdW
         j+L7ZbmcRYLyWY9s7aGWIPVMoS5SiR37VIgeOADNOsDz+pdSL7JRZptV0FYpC1+r+Pf8
         bDbfLZq8ApqxD6NC4E+ti2FtTujUlp8T8VjuySrdnjui9xebQJHF2OSYcyXtaITZXUsc
         z9fOpdkAr9CgwE70prWPWue2yS0uaGuRPn3X87C1m3tdXsYtgzbyFRpgK0/ye2Sx1Din
         UY1EMmzbMSrcHP/Hqqi4JGB1VxveilVT2Wa3lD4dZg/OGySzGvvOKE6+FlOaC+iGEYRG
         5naw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ev5TfjPY/k5YA3sJ4jKIQtbiWkljOy7x6EeUUsVvKvg=;
        b=dZISuZJtLTHo7fbjHK99Mfsj1PFpDoKmnz7oHqfGQA1Brl5QCRAi2HeKOqmo1fcQV2
         vnNpHavbhzrte4Ok/i1QD8/dB2tAHWQMqYAVa6j1jf+CBJkO1/JdJRQ2Gy3ZDDIsj+n0
         fLifj9RHTPPCWUsmwIbWjOVXYx2TsrdZZnHNE5P8AMNxTHcNZM3Ufjs9KB7Lj40LOsOa
         KE8YrXP7D8RyedIALXfkt8Ccr43v1aAFRyjqygXsMXyAobfPkQeUDlYrW4qHQD4rUsV/
         V9MKqA6AWPCjIQF45uDqK1iCz4z2grcvYOC/kftGfwG6FEEpzrJFr5BYlALB4ZqEi0UX
         lQrA==
X-Gm-Message-State: AOAM533ATVubP1CD9M4eDo+Q1QIVMM/Sh+LfHNBi2nCqDuGcpMhbTW5m
	VnIR9tHhNkrj3udTUwf/u+o=
X-Google-Smtp-Source: ABdhPJz8P5jDGn/V4MY4hxrakf/YvXzr3gsbOHZS5DUNTb/NPoL1tA22L7z9MWO1j3WmeAFIFRxo4w==
X-Received: by 2002:a0c:b586:: with SMTP id g6mr18620951qve.3.1605108153699;
        Wed, 11 Nov 2020 07:22:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:776d:: with SMTP id h13ls3504974qtu.7.gmail; Wed, 11 Nov
 2020 07:22:33 -0800 (PST)
X-Received: by 2002:ac8:d48:: with SMTP id r8mr23653687qti.69.1605108153204;
        Wed, 11 Nov 2020 07:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605108153; cv=none;
        d=google.com; s=arc-20160816;
        b=wa+OvJLc3Xs7SDWBWyA3uJaVHqiDfIhFPnZXiR2B61m9daXVHKj+oOjyxyDeKVR0hn
         pSmLDjrneMDk72UURvV4ZDv8yHGzQ9enmGjpqT6C9J6/yt+myfl6dbuDsvlMKkRJBWaP
         axmSUzTrV63Y+1h7LLy5MEfSWKyT8Cz2bDkb1rJ5lgjKdgjmyx2J72XdyEuECvySNQuE
         jsumx4XMLRmUZF4qp9bOR9SeoYAAGRw64BiBgcEZsP0OFVLuauhO2BpT2CyaPtGdSt2D
         JnhSwrjAsSvAcwDc9b++2XCuvRfOfujF4LOtxthtIi0fzCCww6QLu6zk3HlTXygLRZz4
         jdxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0qXuq3ha015RB7+Wp6T10l2uYM1lO9pj4+Ev82Ko6MA=;
        b=g1Zvf8C5k9tQOf4QbMk+MS63rLn/ZY4X2jZYaGZOvPpUl63uFx+KUaA5Glsy30KsOP
         bwQvlqD6EfVz/niFvFs/4AT0RURRLzwlc1K7WapKXqHmVezox6kR2o8g7+IoHUPaWOWh
         UqmhzdkcNAi1gXrjaFW/Wio5a9jRq1S0uf5CV1uIebnp3HO2n+ZrP8AknF+vq8L7dTis
         kOb+teduP+FitSiBGgoe7DwLFXb/4IrvND0qhIOZwGBaKrecpGz9YhveT2YY25kJf/+n
         PZW3DMBR1jLm8MDRlYBoIEuzSgS8hXBmRTqZ7BxytfK7vS12nJUaTpUF1BtkC5gS1ovF
         S3KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="doby/aOl";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id m21si150082qkn.6.2020.11.11.07.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id n15so2449435otl.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:22:33 -0800 (PST)
X-Received: by 2002:a9d:65d5:: with SMTP id z21mr16777802oth.251.1605108152557;
 Wed, 11 Nov 2020 07:22:32 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com> <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com> <CADYN=9LtdW3Bs29VSq2ygnNcb3ub_UBLj8tZg5ff5Zvojr5FWg@mail.gmail.com>
In-Reply-To: <CADYN=9LtdW3Bs29VSq2ygnNcb3ub_UBLj8tZg5ff5Zvojr5FWg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:22:20 +0100
Message-ID: <CANpmjNMBUR-gxDbq5ip4J38PwRHbwOk=zoG5ScVuF6aW326mxQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="doby/aOl";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Wed, 11 Nov 2020 at 16:01, Anders Roxell <anders.roxell@linaro.org> wrote:
>
> On Wed, 11 Nov 2020 at 09:29, Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> > [...]
> > >
> > > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> > >
> > > I eventually got to a prompt on next-20201105.
> > > However, I got to this kernel panic on the next-20201110:
> > >
> > > [...]
> > > [ 1514.089966][    T1] Testing event system initcall: OK
> > > [ 1514.806232][    T1] Running tests on all trace events:
> > > [ 1514.857835][    T1] Testing all events:
> > > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > > flags=0x0 nice=0 stuck for 65s!
> > > [...]
> > > [ 7823.104349][   T28]       Tainted: G        W
> > > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > [ 7833.206491][   T28] "echo 0 >
> > > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > > 1872 ppid:     2 flags:0x00000428
> > > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > > [ 7889.178334][   T28] Call trace:
> > > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > > [ 7905.326856][   T28]  0xffff00000f7077b0
> > > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> > >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > > [ 7934.053677][   T28] Call trace:
> > > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > > [ 7934.146631][   T28] Kernel Offset: disabled
> > > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > > [ 7934.161476][   T28] Memory Limit: none
> > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > > blocked tasks ]---
> > >
> > > Cheers,
> > > Anders
> > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
> >
> > Thanks for testing. The fact that it passes on next-20201105 but not
> > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > kfence.sample_interval=0), does it boot?
>
> This is my qemu cmdline with kfence.sample_interval=0
> $ qemu-system-aarch64 --enable-kvm -cpu cortex-a53 -kernel
> Image-20201110-test -serial stdio -monitor none -nographic -m 2G -M
> virt -fsdev local,id=root,path=/srv/kvm/tmp/stretch/arm64-test,security_model=none,writeout=immediate
> -device virtio-rng-pci -device
> virtio-9p-pci,fsdev=root,mount_tag=/dev/root -append "root=/dev/root
> rootfstype=9p rootflags=trans=virtio console=ttyAMA0,38400n8
> earlycon=pl011,0x9000000 initcall_debug softlockup_panic=0
> security=none kpti=no kfence.sample_interval=0"
>
> This is the result, I managed to get to the prompt. see
> https://people.linaro.org/~anders.roxell/output-next-20201110-test-2.log

Hmm, you still have a ton of

   BUG: workqueue lockup - pool ...

and other warnings in that log though that weren't there in
next-20201105, so I do not trust the results until those are fixed. To
me it looks like KFENCE's timer helps uncover a new problem, but
trying to work around this new problem in KFENCE seems wrong for now.
We need to understand why these "BUG: workqueue lockup" warnings are
there. I Cc'd a bunch of folks in that other email that might be able
to help.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMBUR-gxDbq5ip4J38PwRHbwOk%3DzoG5ScVuF6aW326mxQ%40mail.gmail.com.
