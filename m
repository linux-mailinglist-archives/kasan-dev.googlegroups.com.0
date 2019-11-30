Return-Path: <kasan-dev+bncBCMIZB7QWENRBVWDRDXQKGQEVEYWP5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A3010DD11
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 09:01:28 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id v27sf4667960vkn.18
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 00:01:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575100887; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZZDKC3bi8Qm+P9Qwjz0jGBVtUFvUNRdinnImAT6QvzVpjiDC7BXcWwnhuPPWHI/ay1
         YmIK6NV1Ljaiv4kRCsdF+NM0WQRPg5HX3bPkUYlc4i7BboguBb6V7J7vh9XmUNVZf4Pu
         aT2AZV4stPTPEnNQsoa203sg8GcTsF/DRArukkWxVrBqAxcDbgoEjkMEsNmNpqjYFVEc
         jt4EJdhQh/+F0sk7mUiP37MlLec2mssSGhhe4ceEYMmjp4PvOIYi8MF+gqupg9C/LMbZ
         DuTTye9jP9LbjjKIKUeaigzFhQI5JVDYzEaMBpHKSeftZuhYyybcxhq1z8+s/xk2ySHs
         qg0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j/npUInWcrOR/huz9PJbCocy9JETgU9j7X/1Cq/+cuA=;
        b=JOUIZABkAYyOEq8Pkr4JsJKXUDoW6Xg2jiqJxbo3sGkECRie+xOovy2BfTZFgMulrl
         mhNXxgLcXTi8916e+pFz5oh9KM74B8GmfMmJIBokDMbNcnUOm6IdfLCl2E9N/VYy3nTp
         iGa1Z8w+BY1bpyatCl0dgnQVTFZDlFQlC2vKnffk8jZI4aYHmm+MhHHBmj/mpKvZ6dhS
         JesCQoHsMjFc06s7/8mSM5Nw9bTRDl2I8HLpFQWJI/PkEkB/hpslLiJ7PVaj9KW+IaXr
         vuxvO15kbeBAvQHTa5qC6hLu4eOAPAZTFH7CvaKt3blQN4FmuTPB0zMqtScWg9mC92CA
         9FQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WbdOU1MJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j/npUInWcrOR/huz9PJbCocy9JETgU9j7X/1Cq/+cuA=;
        b=gYtL/QYW4NsMWGyuFQUXIo7QQmVbZE/kUXU+q3GMEXoA65L2ueNaPCU3vTGIqoudPZ
         KGOAFGuQiEoEl/uSUUuSgVtIBcE6zn+l6p8LNgjBUiWJHyrYk4hZENnklTbNi/QQOGHd
         d9li5F7pqOvblfFlPYOlwUZPynzrtq+tHmnN/5WMxYNHzSG4zYdv79xfIDwNi48VzEKa
         Zwzv6q7VbQKAraTDEzL7sHvC9gYxU5XweXBELDTPq3C4zjo89kfH0/yxNBLzHSC00THY
         A/hpr4oNV3Lww6HuJMK7O1+6aDWUlYJntNQ0R/UrwZyakTtWzo4tvDyLbWjWqLwYGuDP
         HJDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j/npUInWcrOR/huz9PJbCocy9JETgU9j7X/1Cq/+cuA=;
        b=VP7Jld4IMIx46Z5V+9QrjtREYFm23Snr9CWIFCY5d7AKpU3JzUVhNHGeUUMlh8oXe/
         Py9o19i//m72ADbIEP2bLdYhfmkFymCiGjrdBXCK80KCF8rpv9jrARmCZfRP+1h+2nGX
         vpGtfC7HKgA1tP4gq0Axi0IgpFw3TbXPg2dVlBQljp77+hx5rp7bjs5Tkp9rq5yEmy9Q
         vjEt8QiCyy6aCFS16VEzkNYL31dEI2KzGLDsnpKuHPXh9ysPxzLl8Y3lFnktWp1skKH9
         +YCIAysiVXBhATnqwI0mmSjST2dEMeR+Le5CUKPzH7cgIKWiKcXqiy37LwgeebkB/68R
         R3wQ==
X-Gm-Message-State: APjAAAWXE14cawLnq2/mZgjKvvgO81Zimxv2lJ2rIl2kd9opLMVTOCzl
	naJAn/1+H26+sxHVz9dckE0=
X-Google-Smtp-Source: APXvYqwZRDUQsqp9riIuu0ce0CBnarqG8qqK34glYrZ04ivZt6nYHR90LFKOeo7nseO+KLgaLYlAtA==
X-Received: by 2002:a1f:a20e:: with SMTP id l14mr12202044vke.14.1575100887012;
        Sat, 30 Nov 2019 00:01:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:517:: with SMTP id l23ls610101vsa.11.gmail; Sat, 30
 Nov 2019 00:01:26 -0800 (PST)
X-Received: by 2002:a67:68d3:: with SMTP id d202mr10711031vsc.153.1575100886623;
        Sat, 30 Nov 2019 00:01:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575100886; cv=none;
        d=google.com; s=arc-20160816;
        b=xme4sFVmOE6u1I6V08cAOwbQM31d430u546+uindLEBcsKuA6kjH5zUAHQVuTUiUZt
         YA0uC6yf+EU+0yDlVdpPaX8Of0rQDkEVwatGBIR12NHP/dQzc64kqEyPEwg5guxQrYRT
         LRt0BBKEdegCPGrR3Z3r4cAGKfFzsfCSEqfD3Ade//YFY0ldkyN04BiqMc5MfCye+0In
         MdBIMz+hMiXcc6Nz9szYpHrQxeRgYsO8zEfVfz0QgIGc6siG1vCVP2Aw+TFbHYTvZLjw
         DIULnnj7KGQBgf103ywJR0F8s308fmroT/0J2iP6QXR+/9CkYKABSVt/TOghptNOqx+d
         cazw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xopoO7QTmMqAl137aSAIMPCPz+JISOQuaoX9y1SYgzs=;
        b=JITbi6WFxyUbiWiDjIyoY+FhDGhQScqbEsw2TOqh4C4VIdXmwq1HpzdZbqjCcZrrT9
         xpcUmnvZ0THuy+1mpw9WHZ8zoRem6t2UOdhhUf7tiIjzVNmlAI6mf5URteqBLhiH5S6n
         livk5T0bD+5+vNOei1yorDD5qPgWeVEzupIus8795z4Qpn2FEpWL2D6C3XPT49T+/pqi
         in04LsoRAHJA1vJO603SNMcXYIDtJRfgd6iui0j+fUrqNuKsakPPPvIHEJ/pVY3D1Jf1
         iIo6hn4fzsTIyNDXtcJzkBIacg+tZAB0Np9xlbrAHHh8amYldPV8fGfGdEoGbM7RS3l/
         UgLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WbdOU1MJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id j207si645370vke.2.2019.11.30.00.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Nov 2019 00:01:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id e187so27685020qkf.4
        for <kasan-dev@googlegroups.com>; Sat, 30 Nov 2019 00:01:26 -0800 (PST)
X-Received: by 2002:a37:4782:: with SMTP id u124mr12295484qka.8.1575100885769;
 Sat, 30 Nov 2019 00:01:25 -0800 (PST)
MIME-Version: 1.0
References: <00000000000080f1d305988bb8ba@google.com>
In-Reply-To: <00000000000080f1d305988bb8ba@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 30 Nov 2019 09:01:14 +0100
Message-ID: <CACT4Y+ZFZxXDOEC3=wP8ZAcVoOjCZsvX07vvRP8yrTofg8sh_Q@mail.gmail.com>
Subject: Re: BUG: unable to handle kernel paging request in ion_heap_clear_pages
To: syzbot <syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com>, 
	Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>
Cc: =?UTF-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?= <arve@android.com>, 
	Christian Brauner <christian@brauner.io>, 
	"open list:ANDROID DRIVERS" <devel@driverdev.osuosl.org>, DRI <dri-devel@lists.freedesktop.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Laura Abbott <labbott@redhat.com>, linaro-mm-sig@lists.linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, Martijn Coenen <maco@android.com>, 
	Sumit Semwal <sumit.semwal@linaro.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Todd Kjos <tkjos@android.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WbdOU1MJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Sat, Nov 30, 2019 at 8:59 AM syzbot
<syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    419593da Add linux-next specific files for 20191129
> git tree:       linux-next
> console output: https://syzkaller.appspot.com/x/log.txt?x=12bfd882e00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
> dashboard link: https://syzkaller.appspot.com/bug?extid=be6ccf3081ce8afd1b56
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com

+Daniel, kasan-dev
This is presumably from the new CONFIG_KASAN_VMALLOC and should be:
#syz fix: kasan: support vmalloc backing of vm_map_ram()


> BUG: unable to handle page fault for address: fffff52002e00000
> #PF: supervisor read access in kernel mode
> #PF: error_code(0x0000) - not-present page
> PGD 21ffee067 P4D 21ffee067 PUD aa11c067 PMD 0
> Oops: 0000 [#1] PREEMPT SMP KASAN
> CPU: 0 PID: 3644 Comm: ion_system_heap Not tainted
> 5.4.0-next-20191129-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
> RSP: 0018:ffffc9000c9f7ab8 EFLAGS: 00010212
> RAX: fffff52002e00000 RBX: fffff52002e01600 RCX: ffffffff85d5c229
> RDX: 0000000000000001 RSI: 000000000000b000 RDI: ffffc90017000000
> RBP: ffffc9000c9f7ad0 R08: fffff52002e01600 R09: 0000000000001600
> R10: fffff52002e015ff R11: ffffc9001700afff R12: fffff52002e00000
> R13: 000000000000b000 R14: 0000000000000000 R15: ffffc9000c9f7d08
> FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52002e00000 CR3: 00000000778bd000 CR4: 00000000001406f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>   memset+0x24/0x40 mm/kasan/common.c:107
>   memset include/linux/string.h:410 [inline]
>   ion_heap_clear_pages+0x49/0x70 drivers/staging/android/ion/ion_heap.c:106
>   ion_heap_sglist_zero+0x245/0x270 drivers/staging/android/ion/ion_heap.c:130
>   ion_heap_buffer_zero+0xf5/0x150 drivers/staging/android/ion/ion_heap.c:145
>   ion_system_heap_free+0x1eb/0x250
> drivers/staging/android/ion/ion_system_heap.c:163
>   ion_buffer_destroy+0x159/0x2d0 drivers/staging/android/ion/ion.c:93
>   ion_heap_deferred_free+0x29d/0x630
> drivers/staging/android/ion/ion_heap.c:239
>   kthread+0x361/0x430 kernel/kthread.c:255
>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> Modules linked in:
> CR2: fffff52002e00000
> ---[ end trace ee5c63907f1d6f00 ]---
> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
> RSP: 0018:ffffc9000c9f7ab8 EFLAGS: 00010212
> RAX: fffff52002e00000 RBX: fffff52002e01600 RCX: ffffffff85d5c229
> RDX: 0000000000000001 RSI: 000000000000b000 RDI: ffffc90017000000
> RBP: ffffc9000c9f7ad0 R08: fffff52002e01600 R09: 0000000000001600
> R10: fffff52002e015ff R11: ffffc9001700afff R12: fffff52002e00000
> R13: 000000000000b000 R14: 0000000000000000 R15: ffffc9000c9f7d08
> FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52002e00000 CR3: 00000000778bd000 CR4: 00000000001406f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000080f1d305988bb8ba%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZFZxXDOEC3%3DwP8ZAcVoOjCZsvX07vvRP8yrTofg8sh_Q%40mail.gmail.com.
