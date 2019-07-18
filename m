Return-Path: <kasan-dev+bncBCMIZB7QWENRBF5LYLUQKGQEIVNF3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 669946D166
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 17:51:51 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id g2sf13890404wrq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jul 2019 08:51:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563465111; cv=pass;
        d=google.com; s=arc-20160816;
        b=LJwa484LCEcifgmYkU7b37H0otmvIZDO4QrdZK+9rYflYtFwcD8eMNf9w4+nYTDHPe
         txyLHcjJng9NUf2iJ22V+21OK4tMUgIL26qaaOy+nXsSeRzaT+f0jj6NQSyHpAyoZ1xM
         Dg6wfumCX1894Dy9H5VbngQxQAGV1FWDHGSCNv6fa3ugDVhJZN04PeqNLseY9c8S2HOC
         F7z/qngxgApzEQtSoemvaqE+6XAJSnEiNi4QSV3pTOC+WP9ftn8ZVXpoSPvyv//8ws4S
         q89GFZW4cLXTAKblfjil0G+OOzKWThQrXs9JJ+pg8d8FSU8LLLpm8pWnW1uXqTfMVqPU
         Fwlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xoUo+/ppExpvhDBUJ0M5CWAOw222ospU7INETPI7QR4=;
        b=qIzZKrJzl0W0As5r2gXTPb5YVtsHruH/vjEDauMXx/zfOmhjDRte0GL+/qv0YgLTwY
         UOBBOlVjiiukKjQWKUWGG1MqaG781K8tioNaptEEEPu50iV2CuTaSxSEPGYvl2yaifFH
         7cb6Nmm1X4+cSh/J6b3IreenkGkuelPFcQSZdf25p/IfI5QOCOjRHEDSXy/zijYy8xsb
         L0v4Arcdud7tak6YiTkpt23++iNRV3K6ch4Mx9jM5ktaqB1VDdLykU9KPUqibxqK1jLe
         ggSJ6ebt1+Gs14vA2urJCYKRonsim6v+zb6+Uxqa0S7YEBaJymP/CQQ+A5bifCiebNw/
         F67Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rrnpLwV7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoUo+/ppExpvhDBUJ0M5CWAOw222ospU7INETPI7QR4=;
        b=fHjcy4hq/Jcnq4yB19mc7I2BgYRupuHeKJn2JVk5LONxPj+jc9aotSj46mm7LP8Ps4
         cCi+KktoHO9TMao4ZVu4MxYgNhpKOPRukM4ssgoA5T3RFvTeWfLR5EiJ/3dhHyRurnkA
         1NVz3IkU/vV8rnpHyv4scIjs4jD5DAw1vIohuw0JyAUiGbjDhl45ezVRE4tOfDclchW5
         erBGeFGWg8u5r73Csi2CAT+YWReUn1PHc+eCUkpOJ+DbomZW/OgXN8j83RyXVCoPPmin
         bKee6MunYAMlOtwq2E5k5TONtfhpJJWDv8KN3hz1zls8ssYVwRcbLevs36FV8aj0A1p+
         CGqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoUo+/ppExpvhDBUJ0M5CWAOw222ospU7INETPI7QR4=;
        b=dhFlRqNAcnslgY0HsoyLikEHuDkbWPwK/hl3Pur7e5+CzjYXTZVcJy1jIzixDiyWi2
         k5RFj4AmmvcJUSxFnhg8z3r+IyYsL0S9z1ynE4EywOwyc/5mr5xX5ID1kzyAsLHJWhPV
         7LrjaekI2339fvva/30K1togt87AJANPg+q7Zf9+Pa+sVHOtxGRTr9J7ZtZJz1cmhxF4
         hwH7TXEhwWj8xNpV4SYFqWhnOBhBKCW6GfswjtxEcXO6OmX05A3LaDubMxl5eOutHRF5
         0c5wBKbH9siCG8JnIC/ZP/+5SxHszyCHIQKLcVFKUdSHvFKdwem9ImVxv5/TpgXePv7T
         TaPg==
X-Gm-Message-State: APjAAAWsVH1kraqQoILJb0nYN3RQDB2TRbCamfxd3+S6D9Ax3RVyuCHW
	u922EP5PKhmKK9CQ2fPe3hA=
X-Google-Smtp-Source: APXvYqxM8UaYMPX0iJeK8F13O7OqJVoXlkrqNLtITf/OaqexeaQ4AFD3kq7jv4oSB2yIIRJb7qooVA==
X-Received: by 2002:adf:d081:: with SMTP id y1mr52814497wrh.34.1563465111097;
        Thu, 18 Jul 2019 08:51:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d11:: with SMTP id t17ls10663340wmt.0.gmail; Thu, 18
 Jul 2019 08:51:50 -0700 (PDT)
X-Received: by 2002:a1c:a7ca:: with SMTP id q193mr45994303wme.150.1563465110683;
        Thu, 18 Jul 2019 08:51:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563465110; cv=none;
        d=google.com; s=arc-20160816;
        b=xQ3bVNvYjnGmMePQXtJadD403dliY2/S4rUdYlOL1okFp1Apf+DTWE6o6BieyxOHP7
         IwfjmdNP+MQ+3AJRkIkKu4nzzw9pXtNc2cnEgRexSKcRJ8RXi1abZwSo6EgbcQv0kg5A
         a8UPJMRQ+kEhdJmwyTICKcnWsl58a3z2gvgC0BklHKJYztbDnwAJIsRu904to9++Tge2
         WEutvLsHMIBso3BXdYJMIXgz8UOr0xmHuXL4RcyWU3VOlxZKy2ETnE2r7b4foSkB8EzJ
         M9GA+BTV2947/0k73DBuBoU8szIExUyzDSlc34h2WvR43/t0KpX2cuo/3vRsjeBSWIpI
         RnmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o1/2Vj7xsNu11SnVwjU6bjgxspYgWkQ65EmdfVPZ5+g=;
        b=E13c5yFvSuchFRdCAm8KzUkuYbu/WIfD3FZ1CLABkVyke5aGQz8Sm0RHeLwHmGVKkI
         abxvVXjaw1xuYysEUrEyGDoAoSZS7bGeyq5Iao1Y7sRSW/wQ+4JjlwZw+UXxvz8poZVb
         NHtBcmTgNXw03c6kWDQq1MhoPR3VZ3rMgkUUYY7Tq2XKlUjfezvHYoAO88MCrwbLZrGz
         fldrDsV9PINzbhlblgJQalyIpSziJM6GyUnszJaFmTme7LwxAuTpBtot4ZFA4Tjlp3WY
         C6YJgoS0mB2F/MWlhgXMCFpjG7fAS4Cz00hV02d/h6Dlr7ytznOqZE7YWCcw5kMbxnvo
         ZhlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rrnpLwV7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id p23si1218794wma.1.2019.07.18.08.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Jul 2019 08:51:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id v15so30778501eds.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Jul 2019 08:51:50 -0700 (PDT)
X-Received: by 2002:a17:906:4bcb:: with SMTP id x11mr36854194ejv.1.1563465110036;
 Thu, 18 Jul 2019 08:51:50 -0700 (PDT)
MIME-Version: 1.0
References: <20190708150532.GB17098@dennisz-mbp>
In-Reply-To: <20190708150532.GB17098@dennisz-mbp>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Jul 2019 17:51:37 +0200
Message-ID: <CACT4Y+YevDd-y4Au33=mr-0-UQPy8NR0vmG8zSiCfmzx6gTB-w@mail.gmail.com>
Subject: Re: kasan: paging percpu + kasan causes a double fault
To: Dennis Zhou <dennis@kernel.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Tejun Heo <tj@kernel.org>, Kefeng Wang <wangkefeng.wang@huawei.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rrnpLwV7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::544
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

On Mon, Jul 8, 2019 at 5:05 PM Dennis Zhou <dennis@kernel.org> wrote:
>
> Hi Andrey, Alexander, and Dmitry,
>
> It was reported to me that when percpu is ran with param
> percpu_alloc=page or the embed allocation scheme fails and falls back to
> page that a double fault occurs.
>
> I don't know much about how kasan works, but a difference between the
> two is that we manually reserve vm area via vm_area_register_early().
> I guessed it had something to do with the stack canary or the irq_stack,
> and manually mapped the shadow vm area with kasan_add_zero_shadow(), but
> that didn't seem to do the trick.
>
> RIP resolves to the fixed_percpu_data declaration.
>
> Double fault below:
> [    0.000000] PANIC: double fault, error_code: 0x0
> [    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
> [    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
> [    0.000000] RIP: 0010:no_context+0x38/0x4b0
> [    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
> [    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
> [    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
> [    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
> [    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
> [    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
> [    0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130
> [    0.000000] FS:  0000000000000000(0000) GS:ffffc90000000000(0000) knlGS:0000000000000000
> [    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    0.000000] CR2: ffffc8ffffffff18 CR3: 0000000002e0d001 CR4: 00000000000606b0
> [    0.000000] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> [    0.000000] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> [    0.000000] Call Trace:
> [    0.000000] Kernel panic - not syncing: Machine halted.
> [    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
> [    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
> [    0.000000] Call Trace:
> [    0.000000]  <#DF>
> [    0.000000]  dump_stack+0x5b/0x90
> [    0.000000]  panic+0x17e/0x36e
> [    0.000000]  ? __warn_printk+0xdb/0xdb
> [    0.000000]  ? spurious_kernel_fault_check+0x1a/0x60
> [    0.000000]  df_debug+0x2e/0x39
> [    0.000000]  do_double_fault+0x89/0xb0
> [    0.000000]  double_fault+0x1e/0x30
> [    0.000000] RIP: 0010:no_context+0x38/0x4b0
> [    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
> [    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
> [    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
> [    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
> [    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
> [    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
> [ 0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130


Hi Dennis,

I don't have lots of useful info, but a naive question: could you stop
using percpu_alloc=page with KASAN? That should resolve the problem :)
We could even add a runtime check that will clearly say that this
combintation does not work.

I see that setup_per_cpu_areas is called after kasan_init which is
called from setup_arch. So KASAN should already map final shadow at
that point.
The only potential reason that I see is that setup_per_cpu_areas maps
the percpu region at address that is not covered/expected by
kasan_init. Where is page-based percpu is mapped? Is that covered by
kasan_init?
Otherwise, seeing the full stack trace of the fault may shed some light.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYevDd-y4Au33%3Dmr-0-UQPy8NR0vmG8zSiCfmzx6gTB-w%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
