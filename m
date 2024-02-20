Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFZ2GXAMGQENNJPGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 370A685B458
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 09:03:10 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6e427f6974dsf3714827a34.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 00:03:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708416189; cv=pass;
        d=google.com; s=arc-20160816;
        b=0vm+TwV9blXKRRSX2zAQWFNcXE3ySTOrwtlf8yYVMZuD7P4U7nZ4w9Kn6rOmlZCEbT
         jZ3/DYq9UMbSck+cN8bX/xn8PHXeRsS2p7Fwb9UYzsOe0F7O/P95dOoWj2IlqK3HGA6N
         UE0udJp3Ic7i04RREdY0dAMKJm0V+1LFqhcOGANu9vT+rf53nUOMe6wat+rafmmEb31j
         MI4P0ntGcY2ShxQnhFEKr1JhS0JKuq2LMoTbxfHxu8HLB+hUXvpHobBD+Xc69FnWX7Fy
         zaGJYabKSSefBxXTU97yspHleXXoKOseH1W57NIZPZtq1TEO55RAusVPyi8JLSPwvT9t
         tGqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ijui4Dbgf8TzlbnEpbRg7bk09+BeO0jcgKn/JRf8Pl4=;
        fh=SvlDA8e2DER5v4ywGBciljycgOx0aU4aREaHtyj1t2w=;
        b=h2gnw8ieXKcefosZfOn7skucLhIRZXdYhejBzQtDE6VmZ+Gla+A4vsfHo24wbc1AUh
         l9PnhbuaV6VUj1Ux5oK+unStfG7WTQ5npOZqqNoh7qWvk+si/x/VIZJjqaG9AGb83/fP
         OPRi0EJrCuZtvLPPUDKdh/ICWnlaHHxfmNrSzqUGuS7MWB4pSxdVA8i2gQiJVwL0X3ae
         SAq94QLfbQxVR5kJABR9AEI/Zq7xCD/Y5khAsG2Xc8AsRPHdBTq71O1b0C5gDbbfZSh0
         cwKHNleiK1UMjbc7xubKUYCrgAafjcM+i+nMGpujiSufG0LReyEfDKrHE126DsmFOdZe
         wYbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PQybSkW7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708416189; x=1709020989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ijui4Dbgf8TzlbnEpbRg7bk09+BeO0jcgKn/JRf8Pl4=;
        b=EJzRl8Dok2FDltoCboRD3rugZ3urt44JdT0s4Ppm7oKw2f0d5/SSX/BOpgXxjkMPCT
         Fc3AuMuB8/XWdWs6Q1aWPn5nJHkcgwHWS4jCtd6EGhaK3pcYkCimFGhzJrgE7TMuUczG
         6E0pa+E1qRcn0neGUBD1MR6hXG+cNXaTyQ/fjWrtadua6dxPI+GpXbyIAQJUl4yBvqs5
         9Vw0gr/Qjg+eTevmSy36Du8eIdo7XwexoOWg+rEJ5O+uMmdCTrJ4mLIuG9Hd3iUvojp7
         z4JR6GcK8loZ3MfM6Oi42aD888UULm9w9hN3iKvypeLhXpmLwbKDeIio1HQBw7XPyDes
         lgcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708416189; x=1709020989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ijui4Dbgf8TzlbnEpbRg7bk09+BeO0jcgKn/JRf8Pl4=;
        b=ThMxmnqRuNwrFPdyqw+MxUiGGcEGpECPM9uu9Zxx3gS+URgoSoiG6ugYBSIDamMw9A
         nD4GXPdVGx7y2QeuVXwn5CrfoeUv+yfu6yHoAuMsNrkk4/kjueClEaCq5JXK1utQnk6Y
         K53KjOJfr3dQsiglM8OlAEL4NXcn7xQ5Zbfyomypv9nBMy10xqPXiJeDRoQkSWt1WQHF
         i79/L1evjeXdrcgaC3f5hp32YZwi0H6Yd8zKHVzSQP81gVSAzII8b9ZgSRued2pY1G1S
         8mYPadmT5b+DruRNPPwdpVcGA9pgvdPkgmZWOFx4mZo58pVQi9sM9YyMeqlvlMUhWh90
         XN6g==
X-Forwarded-Encrypted: i=2; AJvYcCXYPahTSEHSPTVUutcfq8ZzRj5dPRyqCS/OWjCHGI/qWcK6xw8ccqP4SyubeWPngnTewHJLv/heGmkjsPAC38xlYh3n385fkw==
X-Gm-Message-State: AOJu0YzhqAbQhkNvN8um2EXJdIJo9Z99OkTuC50Zhcv5NJLiPlcOwDqA
	lL9gZum3fVtcl7fgpkqBnzy9WkmBiDG6ngTAiQxMxx4cWwDDTcKL
X-Google-Smtp-Source: AGHT+IEIRHrI6GNbN2Dp2d09seBebfL+zPrsI490wpZUQtNpYqs59eNgXYXXiEmpU+SqWUKx8OQ2xg==
X-Received: by 2002:a05:6830:1409:b0:6e2:b5fd:440d with SMTP id v9-20020a056830140900b006e2b5fd440dmr15547229otp.6.1708416188725;
        Tue, 20 Feb 2024 00:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1ac1:0:b0:598:db3f:b1ae with SMTP id 184-20020a4a1ac1000000b00598db3fb1aels3973939oof.0.-pod-prod-04-us;
 Tue, 20 Feb 2024 00:03:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUAxia+mFm8bgKTCPL9KoHbT9jVrDXhBiPGy/PnPN4QEmgSisdzEQF2xyvH9gmchCvkLa6oI3EUwY/zZFMclJy5GZTOhoMSNX/3sg==
X-Received: by 2002:a05:6808:2e87:b0:3c1:41fc:d012 with SMTP id gt7-20020a0568082e8700b003c141fcd012mr15059176oib.34.1708416187889;
        Tue, 20 Feb 2024 00:03:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708416187; cv=none;
        d=google.com; s=arc-20160816;
        b=SOfOaAi/ehRkYjxim4VRdGnmw2hFObCD5t7TSqLDIZnmiGYkFOpOycRNrzND4H/K6L
         TJlF7pIbheoFrPbA27o6UvGJyoxIxv6csiBb9dGQvP3euNolnsqI5/73UILqYGLL47Ya
         XGfSa9BljtP9j6pd7REdx8xZUT8wVrs4OSwhvr7hTMFHpP8wQpuaAWj+UrCQDmh+L1GY
         Lh9bwG7or6MvD77ALwnR8eth+9ExOHf43Y/ziflpOX8HZB//eQQLmHegP0c9kN6sisRu
         cTjtena6/oS8QpfGYAD73HmVhBEb74OQlMLMAy3xidSTWJ3GFZi5Zg1pr/dYTm11EnVW
         MuHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q8cERgU0ZSCW6FWHFRH3BebgYcwtul5dolkTErrkCLA=;
        fh=GeYWgORh4ViR0eW7lth9A95PzmLEmaMD9dJen+ReoWg=;
        b=MpI7jPum1dZUwFzmzBNKiWSr54+4rfnl8SkvIJgR/SnDl1zTn/HkYck7HrzbVmYjtC
         e0qX4D8+ZLlpx1Vn8uqmv/5biB4EiH/JO0f/gwGYc0RwMj2SL1RN9/kCty/DEV6NeZ/t
         gKtESk/M3CD5hepFrAg2Mz7eZRMCd38phXAlwpWl9hLlcZhi7UdNC01HuLGuGE+lonHI
         QXjr4d4E5QllGRKMw2BaVAi7TA3kIWPquI+EXznlMEvcDLoPashFWsgD8s/wS2W8CxYH
         yNhgG+M8Q4znXr4Btm4Fdaod1f8BdT2fMobn6d/5Xmsn7sdEgyAUGoqvEycQ5qzXkJiR
         2Urg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PQybSkW7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2e.google.com (mail-vs1-xe2e.google.com. [2607:f8b0:4864:20::e2e])
        by gmr-mx.google.com with ESMTPS id t17-20020a92c911000000b00364371a54ffsi614360ilp.0.2024.02.20.00.03.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Feb 2024 00:03:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2e as permitted sender) client-ip=2607:f8b0:4864:20::e2e;
Received: by mail-vs1-xe2e.google.com with SMTP id ada2fe7eead31-4704e6dd739so325475137.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Feb 2024 00:03:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVH4bEojUJdpjGjSt3XblJSxHSybb/bXe4ogKTMEIQzWkprLxm18ZyeC83SmMNZZ+IpnX0QPBiWLu9PccCZ9vBX0Rmpqc9EAD1jsQ==
X-Received: by 2002:a67:eb94:0:b0:46e:c865:6b4a with SMTP id
 e20-20020a67eb94000000b0046ec8656b4amr11196789vso.34.1708416186959; Tue, 20
 Feb 2024 00:03:06 -0800 (PST)
MIME-Version: 1.0
References: <202402201506.b7e4b9b6-oliver.sang@intel.com>
In-Reply-To: <202402201506.b7e4b9b6-oliver.sang@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Feb 2024 09:02:28 +0100
Message-ID: <CANpmjNNGCkfFBNiSsc+DOm1EDzXZoNLQy_jnEZjt9WuxP5aayw@mail.gmail.com>
Subject: Re: [linux-next:master] [kasan] 187292be96: WARNING:suspicious_RCU_usage
To: kernel test robot <oliver.sang@intel.com>, "Paul E. McKenney" <paulmck@kernel.org>, RCU <rcu@vger.kernel.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Neeraj Upadhyay <quic_neeraju@quicinc.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, 
	Boqun Feng <boqun.feng@gmail.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PQybSkW7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2e as
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

On Tue, 20 Feb 2024 at 08:35, kernel test robot <oliver.sang@intel.com> wrote:
>
>
>
> Hello,
>
> we noticed this is a revert commit, below report is for an issue we observed
> on this commit but not on its parent. just FYI.
>
> 113edefd366346b3 187292be96ae2be247807fac1c3
> ---------------- ---------------------------
>        fail:runs  %reproduction    fail:runs
>            |             |             |
>            :6          100%           6:6     dmesg.WARNING:suspicious_RCU_usage
>
>
> kernel test robot noticed "WARNING:suspicious_RCU_usage" on:
>
> commit: 187292be96ae2be247807fac1c3a6d89a7cc2a84 ("kasan: revert eviction of stack traces in generic mode")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

This commit didn't touch rcutorture or the rcu subsystem in any way,
so I currently don't understand how rcutorture would be affected.
While stackdepot has started to use RCU, this already happened in a
previous commit, and this particular commit actually reduced RCU usage
(no more evictions and re-allocations of stacktraces).

The only explanation I have is that it improved performance of a
KASAN-enabled kernel (which the config here has enabled) so much that
previously undiscovered issues have now become much more likely to
occur.

[+Cc rcu folks]

> in testcase: rcutorture
> version:
> with following parameters:
>
>         runtime: 300s
>         test: cpuhotplug
>         torture_type: busted_srcud
>
>
>
> compiler: clang-17
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
>
>
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202402201506.b7e4b9b6-oliver.sang@intel.com
>
>
> [  292.513535][  T653] WARNING: suspicious RCU usage
> [  292.514923][  T653] 6.8.0-rc4-00126-g187292be96ae #1 Not tainted
> [  292.516369][  T653] -----------------------------
> [  292.517743][  T653] kernel/rcu/rcutorture.c:1983 suspicious rcu_dereference_check() usage!
> [  292.519310][  T653]
> [  292.519310][  T653] other info that might help us debug this:
> [  292.519310][  T653]
> [  292.523130][  T653]
> [  292.523130][  T653] rcu_scheduler_active = 2, debug_locks = 1
> [  292.525644][  T653] no locks held by rcu_torture_rea/653.
> [  292.526974][  T653]
> [  292.526974][  T653] stack backtrace:
> [  292.529271][  T653] CPU: 0 PID: 653 Comm: rcu_torture_rea Not tainted 6.8.0-rc4-00126-g187292be96ae #1
> [  292.530780][  T653] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [  292.532329][  T653] Call Trace:
> [  292.533524][  T653]  <TASK>
> [ 292.534696][ T653] dump_stack_lvl (lib/dump_stack.c:?)
> [ 292.535941][ T653] ? __cfi_dump_stack_lvl (lib/dump_stack.c:98)
> [ 292.537221][ T653] ? lockdep_rcu_suspicious (kernel/locking/lockdep.c:6712)
> [ 292.538523][ T653] rcu_torture_one_read (kernel/rcu/rcutorture.c:?) rcutorture
> [ 292.539887][ T653] ? __cfi_lockdep_hardirqs_on_prepare (kernel/locking/lockdep.c:4312)
> [ 292.541226][ T653] ? rcu_torture_timer (kernel/rcu/rcutorture.c:1955) rcutorture
> [ 292.542621][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c:2055) rcutorture
> [ 292.544012][ T653] ? init_timer_key (include/linux/lockdep.h:135 include/linux/lockdep.h:142 include/linux/lockdep.h:148 kernel/time/timer.c:847 kernel/time/timer.c:867)
> [ 292.545262][ T653] rcu_torture_reader (kernel/rcu/rcutorture.c:2093) rcutorture
> [ 292.546579][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.c:2076) rcutorture
> [ 292.547872][ T653] ? __cfi__raw_spin_unlock_irqrestore (kernel/locking/spinlock.c:193)
> [ 292.549108][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c:2055) rcutorture
> [ 292.550341][ T653] ? __kthread_parkme (kernel/kthread.c:?)
> [ 292.551425][ T653] ? __kthread_parkme (include/linux/instrumented.h:? include/asm-generic/bitops/instrumented-non-atomic.h:141 kernel/kthread.c:280)
> [ 292.552489][ T653] kthread (kernel/kthread.c:390)
> [ 292.553504][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.c:2076) rcutorture
> [ 292.554689][ T653] ? __cfi_kthread (kernel/kthread.c:341)
> [ 292.555749][ T653] ret_from_fork (arch/x86/kernel/process.c:153)
> [ 292.556792][ T653] ? __cfi_kthread (kernel/kthread.c:341)
> [ 292.557852][ T653] ret_from_fork_asm (arch/x86/entry/entry_64.S:250)
> [  292.558920][  T653]  </TASK>
>
>
>
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240220/202402201506.b7e4b9b6-oliver.sang@intel.com
>
>
>
> --
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNGCkfFBNiSsc%2BDOm1EDzXZoNLQy_jnEZjt9WuxP5aayw%40mail.gmail.com.
