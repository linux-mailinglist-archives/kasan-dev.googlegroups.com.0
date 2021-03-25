Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMPP6KBAMGQECTRDADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DD3A349687
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 17:17:54 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id d11sf1453956lfe.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 09:17:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616689073; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fc2po2ip9q9lmP9P4ezIPrT+46iby8X7AwW81+9kb3S95FCtzVaUrE6dso4uAWdntC
         0vlMUK7wIIrelTMUnSP62wFqXWjhK83X1rFNEuhrtutmHMNaDPWnwZxsL+0gyvzCKzXa
         HlYF7S7p2nPb/X8KXS0csPbrp4xx2fsz2oNbwW4uTgT96OY5F6cKcvEWxYaCsLC60/l6
         jE3HAt0HxpAb4VADOhH5z/U1nIRHfiMD8cl1SfFbgRy/L+O0P3cqhuHoff8gfYr3Bhi8
         /TPZD7IdV+9Cf3roKo5smC2cvCAwQczcgImeYP4WoASJcHiISrCTo+CTaFLZ+s67GjR8
         8DAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=PaMXodXwmieOOeO8/melXVGXYR2Nn3qt9mTp3d8WOeA=;
        b=PSzcQSsVNNA4FpIkq0/8nmayBH3htSbM+9eIsUowrjUvY/aZRkWrxTA6rzNJmYplCJ
         C+oB8zTP6/CLHAaAVoJlgEw+4e79r7XI5u8QCjOdw7eulwBQlu2Qed7sa/9mwqXO91Ry
         CHnou2XdZOJ66zerkIoMHcozZD03tmW576QCEDh69pGMdiigT4kmayIrvjaMabNp6C5I
         oWqYM8Id7Fwdnydb8g7+2T5OCd10f4fas5eb1rNQrsTBlhI1S/6e5ejqfEmNnMDo3Ovl
         EzaJbQFK5u2SiaZiKf+KKStEXRvsocx+Wr9S9ypYsiX3t7KcWbnAAs0tQoWbACGCdF3D
         jRdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oXVmWZsg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=PaMXodXwmieOOeO8/melXVGXYR2Nn3qt9mTp3d8WOeA=;
        b=tY3ItOwmpfTZgfiBOPWMO+koCgxJ0gK8PQnMxvK2It6bpXu3dcOestbZ2mE/INknps
         znJgwB7mgfr+5/3xt/meKZbDN7O+OgUs59orN2IHGa8hE/4eY5BoRBEYtEebjmONZqsn
         ZH2XCNcLaDrJ3QKSa4/mtnibGZYluaY/7p/uM3CIwE80/5L6TLtGDHdgpPOMzmI234Qv
         CAtQacQ1j6cNeNLgm3nYvzZuMspyTeDRWwXyvvlgPhP2t5WivMLICogN7qQP0yb6MaB2
         9j7Aso2PQUZa1WVTK32aBo2QoNpZ5zxSnQ9j/D2Z2Zjrxl1TYt6d6LQSdTr9jyLYO6iK
         YYKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PaMXodXwmieOOeO8/melXVGXYR2Nn3qt9mTp3d8WOeA=;
        b=UMY+e3geWwWitU/VvHvir42E2jtI00y4irGUYz2dgJO3GRzluFeMOfwAu7G6fPf+tB
         VKDlDlQNWdp+ODmyWSz4eL1i9TkKODtzY3MQE/CHFciU+2/lmKmwiiEY331Q3dN8EMo8
         fOLcPL5ciADgzBdQB3FThAPpLcSSP9czrcHKcvMQCBGACpm7SnKk7H0wGMlxH89niVaI
         94nFJ1Z36lRcAyFbPIPUrBqoE9rJa86v2eb2OqL3O7wRGl1ZcHt4dzq+QFk3ADIvRxhD
         Jh0Q6wC6bSq+u707pCTbndR0jgr1g4/KwOcy3uIzQeSQMsEkBdq6DhtvfP9NxtRhMrLz
         bsLQ==
X-Gm-Message-State: AOAM533uPEifrjfroKV9eum8xRy8Q1pS6bAIJyw04/JIiN5AH1qE8a29
	MvyWS32UU/koCJwABZXFTd8=
X-Google-Smtp-Source: ABdhPJwhGQGNZxSRcQEWbRiBAKxYyFt6VljkLvl+J6tsQ1aAy9Q/kUblKt8xyovDp8GlKe5EZ9gyzQ==
X-Received: by 2002:a19:414a:: with SMTP id o71mr5593797lfa.78.1616689073758;
        Thu, 25 Mar 2021 09:17:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b54d:: with SMTP id a13ls1404911ljn.3.gmail; Thu, 25 Mar
 2021 09:17:52 -0700 (PDT)
X-Received: by 2002:a2e:a707:: with SMTP id s7mr313423lje.35.1616689072568;
        Thu, 25 Mar 2021 09:17:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616689072; cv=none;
        d=google.com; s=arc-20160816;
        b=JJS79qee25TUJkl2EFmZDAO3i2fJIu0O0WmTb1u6Cdh3ZO2YqJKBnIQVl9N3R5hlZ3
         /QEWaoWod68PIu4COsXAyRMiQhzW64uwqA4pzrTDjkrKjziTUwWsf69QWc1EWGPNfkRx
         FzK2jfnblv7BTCikd2cyRiYVG19VZ7Gjei8/YT/tBljCWjH0XexUqw2DL/2iP9JbXv6p
         U9gAHVsuCEjXh74OCSxXT+UPXmH+1QLqyqnK5g62oC+ytjxmjUk167YXg+fHL2KeBNxh
         pVKiSGNVYjUUobHOH9ILrZorF70z+Fwe6nBe8/bqUHK3/31G4iC2rvrcub/yqrwuu5A9
         NvSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kAKXJ7/VxJwil6v6M/XIYvLEph0e/Kmn7nzemfetRbI=;
        b=bqajsjiFDmWl4eAqb8dmHcseBYPGvBwbxKmtpuYtDOM0au9cSl2GiD2yvc+xZF+vIn
         FjEdomw3j7eENPHc1625MpVR/jVqaAy1uucgCwXhZ7ElvlJY4iQe01bnV7JRN8oS3rGO
         bAus8SkR+DoHdKOO6P3uQ90PB1qj9oiGjZRwvtQ4bf2/a9f1TqEamhkireKJFV/dj35p
         4sQgYsoBDlye5TTtPcGNVtaaKcvlBb0sBwVgxblt/toCedorL8DPG/vlvdI8jQ/hWvQu
         LYruD5w0ondWqO1oNwsqDNpNrpKABQ9KMtI+qH1/WUpmovTsROYlojhQmdMonIgeyBPu
         Twnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oXVmWZsg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id n13si313356lfi.5.2021.03.25.09.17.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 09:17:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id j9so1149075wrx.12
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 09:17:52 -0700 (PDT)
X-Received: by 2002:adf:f148:: with SMTP id y8mr9590134wro.107.1616689072002;
        Thu, 25 Mar 2021 09:17:52 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:248e:270b:f7ab:435d])
        by smtp.gmail.com with ESMTPSA id q4sm6777560wma.20.2021.03.25.09.17.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 09:17:51 -0700 (PDT)
Date: Thu, 25 Mar 2021 17:17:44 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v3 01/11] perf: Rework perf_event_exit_event()
Message-ID: <YFy3qI65dBfbsZ1z@elver.google.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-2-elver@google.com>
 <YFxjJam0ErVmk99i@elver.google.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="5kCBKIUkt7XGNemg"
Content-Disposition: inline
In-Reply-To: <YFxjJam0ErVmk99i@elver.google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oXVmWZsg;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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


--5kCBKIUkt7XGNemg
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Thu, Mar 25, 2021 at 11:17AM +0100, Marco Elver wrote:
> On Wed, Mar 24, 2021 at 12:24PM +0100, Marco Elver wrote:
> > From: Peter Zijlstra <peterz@infradead.org>
> > 
> > Make perf_event_exit_event() more robust, such that we can use it from
> > other contexts. Specifically the up and coming remove_on_exec.
> > 
> > For this to work we need to address a few issues. Remove_on_exec will
> > not destroy the entire context, so we cannot rely on TASK_TOMBSTONE to
> > disable event_function_call() and we thus have to use
> > perf_remove_from_context().
> > 
> > When using perf_remove_from_context(), there's two races to consider.
> > The first is against close(), where we can have concurrent tear-down
> > of the event. The second is against child_list iteration, which should
> > not find a half baked event.
> > 
> > To address this, teach perf_remove_from_context() to special case
> > !ctx->is_active and about DETACH_CHILD.
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v3:
> > * New dependency for series:
> >   https://lkml.kernel.org/r/YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net
> > ---
> 
> syzkaller found a crash with stack trace pointing at changes in this
> patch. Can't tell if this is an old issue or introduced in this series.

Yay, I found a reproducer. v5.12-rc4 is good, and sadly with this patch only we
crash. :-/

Here's a stacktrace with just this patch applied:

| BUG: kernel NULL pointer dereference, address: 00000000000007af
| #PF: supervisor read access in kernel mode
| #PF: error_code(0x0000) - not-present page
| PGD 0 P4D 0
| Oops: 0000 [#1] PREEMPT SMP PTI
| CPU: 7 PID: 465 Comm: a.out Not tainted 5.12.0-rc4+ #25
| Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
| RIP: 0010:task_pid_ptr kernel/pid.c:324 [inline]
| RIP: 0010:__task_pid_nr_ns+0x112/0x240 kernel/pid.c:500
| Code: e8 13 55 07 00 e8 1e a6 0e 00 48 c7 c6 83 1e 0b 81 48 c7 c7 a0 2e d5 82 e8 4b 08 04 00 44 89 e0 5b 5d 41 5c c3 e8 fe a5 0e 00 <48> 8b 85 b0 07 00 00 4a 8d ac e0 98 01 00 00 e9 5a ff ff ff e8 e5
| RSP: 0000:ffffc90001b73a60 EFLAGS: 00010093
| RAX: 0000000000000000 RBX: ffffffff82c69820 RCX: ffffffff810b1eb2
| RDX: ffff888108d143c0 RSI: 0000000000000000 RDI: ffffffff8299ccc6
| RBP: ffffffffffffffff R08: 0000000000000001 R09: 0000000000000000
| R10: ffff888108d14db8 R11: 0000000000000000 R12: 0000000000000001
| R13: ffffffffffffffff R14: ffffffffffffffff R15: ffff888108e05240
| FS:  0000000000000000(0000) GS:ffff88842fdc0000(0000) knlGS:0000000000000000
| CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
| CR2: 00000000000007af CR3: 0000000002c22002 CR4: 0000000000770ee0
| DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
| DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
| PKRU: 55555554
| Call Trace:
|  perf_event_pid_type kernel/events/core.c:1412 [inline]
|  perf_event_pid kernel/events/core.c:1421 [inline]
|  perf_event_read_event+0x78/0x1d0 kernel/events/core.c:7406
|  sync_child_event kernel/events/core.c:12404 [inline]
|  perf_child_detach kernel/events/core.c:2223 [inline]
|  __perf_remove_from_context+0x14d/0x280 kernel/events/core.c:2359
|  perf_remove_from_context+0x9f/0xf0 kernel/events/core.c:2395
|  perf_event_exit_event kernel/events/core.c:12442 [inline]
|  perf_event_exit_task_context kernel/events/core.c:12523 [inline]
|  perf_event_exit_task+0x276/0x4c0 kernel/events/core.c:12556
|  do_exit+0x4cd/0xed0 kernel/exit.c:834
|  do_group_exit+0x4d/0xf0 kernel/exit.c:922
|  get_signal+0x1d2/0xf30 kernel/signal.c:2777
|  arch_do_signal_or_restart+0xf7/0x750 arch/x86/kernel/signal.c:789
|  handle_signal_work kernel/entry/common.c:147 [inline]
|  exit_to_user_mode_loop kernel/entry/common.c:171 [inline]
|  exit_to_user_mode_prepare+0x113/0x190 kernel/entry/common.c:208
|  irqentry_exit_to_user_mode+0x6/0x30 kernel/entry/common.c:314
|  asm_exc_general_protection+0x1e/0x30 arch/x86/include/asm/idtentry.h:571

Attached is a C reproducer of the syzkaller program that crashes us.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFy3qI65dBfbsZ1z%40elver.google.com.

--5kCBKIUkt7XGNemg
Content-Type: text/x-csrc; charset=us-ascii
Content-Disposition: attachment; filename="perf-nullptr-deref.c"

// autogenerated by syzkaller (https://github.com/google/syzkaller)
/*
Generated from this syzkaller program:

clone(0x88004400, 0x0, 0x0, 0x0, 0x0)
perf_event_open(&(0x7f00000003c0)={0x4, 0x70, 0x40, 0x1, 0x3, 0x1, 0x0, 0x6, 0x10001, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x80000001, 0x2, @perf_bp={&(0x7f0000000380), 0xd}, 0x1000, 0x6, 0x0, 0x4, 0x1, 0x4, 0x8}, 0x0, 0xffffffffffffffff, 0xffffffffffffffff, 0x1)
clone(0x8000, &(0x7f0000000200)="3017248985480229c715f01f2776139977f49770d8181077dce816423a929ed5e59bf26ca77f2ba311b783dda29870d621ff2394424d9c799be5fa29f1ee42102645b56fd9727401d2fe52073c20023d4623dd48522d13dff56af96e4d73f53d62f3de841a58436c591733b58072f04a49bd5cf0473e3f568b604959c06365a82e0e1350550271c25298", &(0x7f0000000100), &(0x7f0000000140), &(0x7f00000002c0)="8c0e32ae8f2716cdf998f341eb4ff0b404c7dca07d9e895c109603d3552c42f07c0190860e4c880d03ba867e8d5d738172839bdbe974d38580e5bc8a91713bee4b859c1a4500f61f197d3610ef2f515474d0b302af29f64053899418054cdf0afe2e75f313f92daf84b3f77cdb10d9d002c44bf43d0cb532cce29b249aab4d6e8218e2528c95453d255e31715422b9d3014c35603fa361ec70136322a7366868f53b78b7c369496dc39cf8ea248b7345e378")
*/

#define _GNU_SOURCE

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type, htobe, addr, val, bf_off, bf_len)               \
  *(type*)(addr) =                                                             \
      htobe((htobe(*(type*)(addr)) & ~BITMASK((bf_off), (bf_len))) |           \
            (((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))

int main(void)
{
  syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
  syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
  syscall(__NR_clone, 0x88004400ul, 0ul, 0ul, 0ul, 0ul);
  *(uint32_t*)0x200003c0 = 4;
  *(uint32_t*)0x200003c4 = 0x70;
  *(uint8_t*)0x200003c8 = 0x40;
  *(uint8_t*)0x200003c9 = 1;
  *(uint8_t*)0x200003ca = 3;
  *(uint8_t*)0x200003cb = 1;
  *(uint32_t*)0x200003cc = 0;
  *(uint64_t*)0x200003d0 = 6;
  *(uint64_t*)0x200003d8 = 0x10001;
  *(uint64_t*)0x200003e0 = 0;
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 0, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 1, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 2, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 3, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 4, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 5, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 6, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 7, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 8, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 9, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 10, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 11, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 12, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 13, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 14, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 15, 2);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 17, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 18, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 19, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 20, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 21, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 22, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 23, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 24, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 25, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 26, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 27, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 28, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 29, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 30, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 31, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 32, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 33, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 1, 34, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 35, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 36, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 37, 1);
  STORE_BY_BITMASK(uint64_t, , 0x200003e8, 0, 38, 26);
  *(uint32_t*)0x200003f0 = 0x80000001;
  *(uint32_t*)0x200003f4 = 2;
  *(uint64_t*)0x200003f8 = 0x20000380;
  *(uint64_t*)0x20000400 = 0xd;
  *(uint64_t*)0x20000408 = 0x1000;
  *(uint64_t*)0x20000410 = 6;
  *(uint32_t*)0x20000418 = 0;
  *(uint32_t*)0x2000041c = 4;
  *(uint64_t*)0x20000420 = 1;
  *(uint32_t*)0x20000428 = 4;
  *(uint16_t*)0x2000042c = 8;
  *(uint16_t*)0x2000042e = 0;
  syscall(__NR_perf_event_open, 0x200003c0ul, 0, -1ul, -1, 1ul);
  memcpy(
      (void*)0x20000200,
      "\x30\x17\x24\x89\x85\x48\x02\x29\xc7\x15\xf0\x1f\x27\x76\x13\x99\x77\xf4"
      "\x97\x70\xd8\x18\x10\x77\xdc\xe8\x16\x42\x3a\x92\x9e\xd5\xe5\x9b\xf2\x6c"
      "\xa7\x7f\x2b\xa3\x11\xb7\x83\xdd\xa2\x98\x70\xd6\x21\xff\x23\x94\x42\x4d"
      "\x9c\x79\x9b\xe5\xfa\x29\xf1\xee\x42\x10\x26\x45\xb5\x6f\xd9\x72\x74\x01"
      "\xd2\xfe\x52\x07\x3c\x20\x02\x3d\x46\x23\xdd\x48\x52\x2d\x13\xdf\xf5\x6a"
      "\xf9\x6e\x4d\x73\xf5\x3d\x62\xf3\xde\x84\x1a\x58\x43\x6c\x59\x17\x33\xb5"
      "\x80\x72\xf0\x4a\x49\xbd\x5c\xf0\x47\x3e\x3f\x56\x8b\x60\x49\x59\xc0\x63"
      "\x65\xa8\x2e\x0e\x13\x50\x55\x02\x71\xc2\x52\x98",
      138);
  memcpy(
      (void*)0x200002c0,
      "\x8c\x0e\x32\xae\x8f\x27\x16\xcd\xf9\x98\xf3\x41\xeb\x4f\xf0\xb4\x04\xc7"
      "\xdc\xa0\x7d\x9e\x89\x5c\x10\x96\x03\xd3\x55\x2c\x42\xf0\x7c\x01\x90\x86"
      "\x0e\x4c\x88\x0d\x03\xba\x86\x7e\x8d\x5d\x73\x81\x72\x83\x9b\xdb\xe9\x74"
      "\xd3\x85\x80\xe5\xbc\x8a\x91\x71\x3b\xee\x4b\x85\x9c\x1a\x45\x00\xf6\x1f"
      "\x19\x7d\x36\x10\xef\x2f\x51\x54\x74\xd0\xb3\x02\xaf\x29\xf6\x40\x53\x89"
      "\x94\x18\x05\x4c\xdf\x0a\xfe\x2e\x75\xf3\x13\xf9\x2d\xaf\x84\xb3\xf7\x7c"
      "\xdb\x10\xd9\xd0\x02\xc4\x4b\xf4\x3d\x0c\xb5\x32\xcc\xe2\x9b\x24\x9a\xab"
      "\x4d\x6e\x82\x18\xe2\x52\x8c\x95\x45\x3d\x25\x5e\x31\x71\x54\x22\xb9\xd3"
      "\x01\x4c\x35\x60\x3f\xa3\x61\xec\x70\x13\x63\x22\xa7\x36\x68\x68\xf5\x3b"
      "\x78\xb7\xc3\x69\x49\x6d\xc3\x9c\xf8\xea\x24\x8b\x73\x45\xe3\x78",
      178);
  syscall(__NR_clone, 0x8000ul, 0x20000200ul, 0x20000100ul, 0x20000140ul,
          0x200002c0ul);
  return 0;
}

--5kCBKIUkt7XGNemg--
