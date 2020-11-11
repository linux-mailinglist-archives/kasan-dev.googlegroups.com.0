Return-Path: <kasan-dev+bncBDOILZ6ZXABBBWXZV76QKGQEM5JLO3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D0F52AF450
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:01:48 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 194sf508093lfm.22
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:01:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605106907; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIAUD3rfJE25yPmV0aytd4rBl8PORTa0JvQstaQbdHlU3uI4BCiq/C8YvQf9rKQZh0
         lKendxVPxQbK2YjZJR7LT+QIT2Q2zIzUgYflwioQUDevcLeRjjR2uUYB/qeOgCZsTpEo
         aAunFvuHPwdH9+XriDjN7sP3r7Q4oVq4mt8+6Uylej4UBaHXS/KEG04c3FIIZp/FWUPX
         p5XJqNkXdaXo6LuIBOJ68cyACX4DrbEDZ1R5vH0i+dFwzL+F3d/+G7DdyKitD5OXODYp
         t0tGwR8cH3VKK8wbun48fA7vpgs2YoIMIflj9NnW7lTCHV3KMmqSE32WNwYPjJyYXdAU
         z9jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=uzUsar7A7JSXjnYdHvMgVKDDaQCbP0jCDagUXosQYdg=;
        b=eo/cP6jgxJAzWLbUR6HXYjoIRRszwo5JhNsHnG/pxJ65z+rGKiCxuh1ZB8ucz0ocXr
         dfckU5bO7e3n9X80cako8egiCs1t4TgLpbfS7EHyICQUaZqiJgNso3yHiLqq4aocE2bu
         ZMXs95uMK8NYW5EzN9W35DlBFWd6tTS0slf/TFeM/kFjTvaD2tYeWiXO6BkSdQHdD9bD
         xoZoBoetp7/D4/w3Z25Nv0CItzEx9o2NoCCR33JxodnHe94xkzcvWbdPulXrx6tT6+R1
         xMgXpoxnWSEOlzYkSasVoVBjX0bJ8xaCfrfEGO0Vj7hwyfsMjhEzcI7ydjCIuD6mvbZB
         xi/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=RmKRnEeu;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uzUsar7A7JSXjnYdHvMgVKDDaQCbP0jCDagUXosQYdg=;
        b=g5CpQhoXFmGlTQXEoK/vTQvMsuSO3j0byp17IpQOvrK1/YdVjrcB0a1ZOKuJmkP9NI
         eQoZEXiXkzfShvecV18nXrYZpRqVWl+Be0etDm+rtUWdBnqQVZ3aD1/J/3Um2DqclN5k
         GaN4Xs9NTdSsAp3Q0TaLyj+XmvBVIoX/61nG4QKcnL2L0+1IAUcXVUGOZ0VcNm2afJqK
         9ajhhMlROj/8dMKZWRU6IrGmsfZvApRIp3PT8spT/EOiY/Veh7MfVbPs3kiu4hWqe7Jq
         uT++nt0omDZ6ODMo0d60sj6sj3cG+kPbME12L0OUXDuo4b08LTfLOVGUStZ18RNq/gD9
         dXPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uzUsar7A7JSXjnYdHvMgVKDDaQCbP0jCDagUXosQYdg=;
        b=Zdctv4KDA2x7n670O9UJ3XVQBBPD3OPbZjd3hWpSpfu/vsqjwEzflCD67KiXr6hUM+
         Z1LS4AIQ0oXu6cnI5g0qQZb7cjjzkaZxTWiu3b3T5JoNUY3iYe3gBn3FfRi0qccghtCD
         ltnfaS4WvAgkhAS9LXq+xWVvsBEY4KXkz2pxCV+K92zRcBJuqpq2Ykh+8nFjRoQ9AfA9
         /eDorchF/kK6061mSHTHo0NqG+MBA8D4dcNCyv9bV0LBMjSAlzFt4LT9R7GiBMgCqoC9
         Ll6PhMwQWr4pWKvRc28XrtQpJjzrDJMayRmz+j8z6MREW+Roi8/iovOYuYYs6pDvKCEv
         NNhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AtFSa/c5w5M3aIJdKwtzK7V38OL83DARX7K2kJ1d2tSPEPZTV
	7WX3tsWjgqSkfFHDmbPiLP0=
X-Google-Smtp-Source: ABdhPJx9DIRVGAQRQoNPO7J39FtiBH5mvj/j6RqnLeiJAEcdrhXxofwurCeM2V8MJIaQVVw16ohQXA==
X-Received: by 2002:a19:414e:: with SMTP id o75mr9365425lfa.28.1605106906915;
        Wed, 11 Nov 2020 07:01:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:914c:: with SMTP id q12ls1475120ljg.8.gmail; Wed, 11 Nov
 2020 07:01:45 -0800 (PST)
X-Received: by 2002:a2e:8750:: with SMTP id q16mr9891591ljj.53.1605106905523;
        Wed, 11 Nov 2020 07:01:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605106905; cv=none;
        d=google.com; s=arc-20160816;
        b=x2Duo79yfFJFRsvgcC0Y69tkOB9tBApFWntiS8tZFoKYT35c/LOKeQju+/N6rBmE4I
         VVXU4XaFdNj6AQnVY+vaoiOSfbsFYeFvlY17T3fMfNR3T+FO5ucJiXxGqF74sTKN7eFj
         ABDfFXFSZe3pfBtWfpKuipOBk1cmKS9dDX7WutUpnt+/2fmY64GQCgli6SM/CVsuevp4
         OfoXq4Tt6Ka6BC9RDfJF1unCpVD9zM8H2wDkObTWy88ZzNrcOtAFuJqRo9XRwMaNvErO
         x9SopoZoHi+pqUz8RoHqfaWxg7ZlZvu4biCWWq1F3jQpWEkZRrxJnEC0PAfLkKNjgBkE
         mH/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cBLmYkGf36dydiwFqnzHp6MitrhQHxL3O/6ldq0sG2I=;
        b=hgkwe3bcQXR+mjDXZ1PAy1vhGzJS7HmY8Vt2BDCQ+HgsSN2mW3YubTyBg1LUd86G5V
         0AA1qa0UmohAWLBbvMW/rSke5MeHDrcEizLgdRRN6V7fd7rNa+RzAw89aSuil/Ob/v64
         st+N0vJbzaUTrxVJJXjIkt+XrQQBtr4LajfpMo6kT+2TM48+W8tQ5BvT1ZROdQNjpwtD
         mZ5oY2qNlSiF1/Nm/e8N58+O6OR9cZX8KRAteH/9vhP+iBvMGtI3wmPojwlpnpbrgPFn
         jpZlCo/rbP4bEyT8ywzNsyJOryQRRtlBHvT/yLsmVieGgFiRngVkAMVnczenZChXS/OV
         CPUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=RmKRnEeu;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q16si60117ljp.8.2020.11.11.07.01.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:01:44 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id y16so2452282ljh.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:01:44 -0800 (PST)
X-Received: by 2002:a2e:5450:: with SMTP id y16mr11307487ljd.288.1605106904415;
 Wed, 11 Nov 2020 07:01:44 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com> <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
In-Reply-To: <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
From: Anders Roxell <anders.roxell@linaro.org>
Date: Wed, 11 Nov 2020 16:01:33 +0100
Message-ID: <CADYN=9LtdW3Bs29VSq2ygnNcb3ub_UBLj8tZg5ff5Zvojr5FWg@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=RmKRnEeu;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, 11 Nov 2020 at 09:29, Marco Elver <elver@google.com> wrote:
>
> On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> [...]
> >
> > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> >
> > I eventually got to a prompt on next-20201105.
> > However, I got to this kernel panic on the next-20201110:
> >
> > [...]
> > [ 1514.089966][    T1] Testing event system initcall: OK
> > [ 1514.806232][    T1] Running tests on all trace events:
> > [ 1514.857835][    T1] Testing all events:
> > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > flags=0x0 nice=0 stuck for 65s!
> > [...]
> > [ 7823.104349][   T28]       Tainted: G        W
> > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > [ 7833.206491][   T28] "echo 0 >
> > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > 1872 ppid:     2 flags:0x00000428
> > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > [ 7889.178334][   T28] Call trace:
> > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > [ 7905.326856][   T28]  0xffff00000f7077b0
> > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > [ 7934.053677][   T28] Call trace:
> > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > [ 7934.146631][   T28] Kernel Offset: disabled
> > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > [ 7934.161476][   T28] Memory Limit: none
> > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > blocked tasks ]---
> >
> > Cheers,
> > Anders
> > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
>
> Thanks for testing. The fact that it passes on next-20201105 but not
> on 20201110 is strange. If you boot with KFENCE disabled (boot param
> kfence.sample_interval=0), does it boot?

This is my qemu cmdline with kfence.sample_interval=0
$ qemu-system-aarch64 --enable-kvm -cpu cortex-a53 -kernel
Image-20201110-test -serial stdio -monitor none -nographic -m 2G -M
virt -fsdev local,id=root,path=/srv/kvm/tmp/stretch/arm64-test,security_model=none,writeout=immediate
-device virtio-rng-pci -device
virtio-9p-pci,fsdev=root,mount_tag=/dev/root -append "root=/dev/root
rootfstype=9p rootflags=trans=virtio console=ttyAMA0,38400n8
earlycon=pl011,0x9000000 initcall_debug softlockup_panic=0
security=none kpti=no kfence.sample_interval=0"

This is the result, I managed to get to the prompt. see
https://people.linaro.org/~anders.roxell/output-next-20201110-test-2.log

Cheers,
Anders

>
> In your log [2] I see a number of "BUG: workqueue lockup ..." but that
> doesn't make sense, at least I don't think the KFENCE work item is
> causing this. It'd be interesting to bisect what changed between
> 20201105 and 20201110, but I have a suspicion that might take too
> long. Short of that, let me see if there are any changes between the 2
> that look like it might be causing this.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADYN%3D9LtdW3Bs29VSq2ygnNcb3ub_UBLj8tZg5ff5Zvojr5FWg%40mail.gmail.com.
