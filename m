Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLOG6GBAMGQEU3CE5QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AAD6348DC7
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 11:17:18 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id k16sf2304953ejg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 03:17:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616667438; cv=pass;
        d=google.com; s=arc-20160816;
        b=aIDm1Xi/0KSlIZEHEBh6KNEZw+igYndkgFPfWuG2ny9HoZzR5koqqEupC6Q2OoLBwI
         FtJnSz7sf8jI86U6eJxK5QnaEmwE0MePd7fGV3kxxxmO0Zkjy9pd6Lgz//mdVLDSJV8+
         +/gyqxgy38xyC6sSbLYICNXuDnRG/I6dSA2s+JQdCDGFo2Dv90Rtvd+Er/ethvi+vf/T
         3miA+XsgWQrKKQeiPgPy2laOWEbvcqMb3DRBbupjmGGxKlg1QAWgt23JfngvFoZnjvEK
         +DLbSh5oIND/nEmRP/Q6yQSSb9o647VzvSc3DJXqZCQR5RPMkyLFdE6hS4KFPG4Yn/6U
         1K7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fxQwRprUg+I1RBM9KxCTfCWb//X3iQr4Xz/+6ESHjh4=;
        b=apAh2W4tivtfDar22v0dAnaM/Y8guE9VMy0TfYFyBo46t4s5d2cJydQ146utIHSPqm
         QbW5D0NiWQE0CTrMJA8j74dRAIfZp8M+IWrAgxhCmV/fMZm7j7uubS9VW3wiN10II4k4
         kDZcZ+MA44+LrS+dojyu/6FOXzDImeua/NAV0IIltxhinLhpn4Szu1dhyBFc8wOZw9U6
         nKfo2i2CxRjf5Miu6/0CJgVBZYuGSTnfJetbF9rbVrPW5O5czb8X7rAdzXQIRYQ2mcu+
         49BOoyD15vueBSY8aMY7LdV/+G6OOgi8hNnIgf9eHn4YtRhCXGkdKNGsjhq0hnQrb9NF
         7qwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aDRT36p1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fxQwRprUg+I1RBM9KxCTfCWb//X3iQr4Xz/+6ESHjh4=;
        b=nLXAiFXJmVg5v8f+qE3+00LEaM8qkYx78L6Cv4dDlqt3eRUMeHm5fUHNQSGyD9ZQ8p
         v9WkK5vb1uAqISeel+9FlNQAJuECPT36IMAQVyYQyl0XWhxYI/XDywJ5XVcE3MLpCyOL
         r8r+QRKRjneFpEbxFiFIe4rM5aAJbJ4ue2bUwWS3zrmn8Baomu8Bc3HzkioIaRnr0+yG
         FTeQy6fkgvkh3XXcOBKClbaZssRqq/RfeJ3GsxcSVp699G5YQNKX2Fj/1cQqHWOeLWKt
         KTmf/pH8IgyYC/lHcHu46d/LweVRZLOSWjnWzrWdLaCxBh4+YAXw1tzC/ujyNESr5+vP
         zZpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fxQwRprUg+I1RBM9KxCTfCWb//X3iQr4Xz/+6ESHjh4=;
        b=CaVfY4MWVyDUXKXRrYWurMCQrgb4ldYzcKHV5tBDlwYWYU8+8eQXCWmITFYz/9GIS7
         PcMzLUgJNlJ9llV3rLErE69zG++lzeS4COWd4jYtz0l3y1QZY8uRYQdaYImZAcJpCz1z
         y6C4GlOJkY9tkmsTx0q9r50i+J+3QdZmcvR/ZKvr98tubI3FfX0Pvne+/redk2mFnCE2
         KgZ9J/5qDRqTMmlp4CpZGy/zoyl8Y9YfIXQORnEwelJWaifSB2A6Oxn83fCXt87wQwei
         gYAtob58/Yz/4XyoQDn1xO2wc+VatuhsNFAuakaHBA3LUM6p/Oe+hmfQ6anuLvPOm+S2
         xbcQ==
X-Gm-Message-State: AOAM531jLL8D6CChLEUJioOZtRLafQ0m7Gkqpxyxfd6e3ReaHsMQAhjW
	rzv1JIBhJTVxwwNWM+3lAGM=
X-Google-Smtp-Source: ABdhPJyp4UNXXeqUOL/HpoG7Y5Oyx/OJCqxthbVCHZPgNaQnVqys9MS+Rzx9CwZYD8d64B5QyzPIbw==
X-Received: by 2002:a05:6402:1517:: with SMTP id f23mr8448566edw.272.1616667437963;
        Thu, 25 Mar 2021 03:17:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls2693030edr.2.gmail; Thu, 25 Mar
 2021 03:17:17 -0700 (PDT)
X-Received: by 2002:a05:6402:42d1:: with SMTP id i17mr7950086edc.131.1616667436909;
        Thu, 25 Mar 2021 03:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616667436; cv=none;
        d=google.com; s=arc-20160816;
        b=dw9GJbcgGePcTsSyS0Wm4vlYAQyXiLGdOOv1imTsAjPD3UWWU1L28Z4sQx9kUWISBH
         p8n9pUYAtbtdMSAvmPRSE5JteSEQVjzW7/Qy1jjEruK313gPlTewviVWLsUU+9G1z9JT
         pLVeP/q0vYqQz6FxYcUf4ZgmdkhMnDzQNtY5mMlI8ZGCsjGM3Oj71zoyeICaiJu1wGhW
         9tsFoMuaKxDiXEKQPfyGmbVnc5A8quX6ELfwsXlT9ikK5tTplupLOaHz8CVSWBQ0XMbj
         Km/y8ZWYM52QqeANpSRlO1keSalDSwwDvhnZTNokR+GLDFlyezlFN3izFdXmBpgEmBy3
         VXiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LQYU7AshaChrIv5/sVzoGBNv4W3iyRIKQFQCOFPAGsA=;
        b=D0Mk33GsMsbYCJTY7z0392eVjhXw5aKndhqE238fPZeSsT0CSjF4j3pwQOrtSya/AG
         6+9pWQ+yidhiv4qNQHPpxnoJK5rMQaOwDOdlzNqNHZLYs1RrZnkktD4/QZypQI4WFNlE
         WKRhmBzUAX34E7tQUUnljgmcwlTSD2OuUngc6zl1X3udBP14s7tOZ8h2j0G3uX235Kvn
         bQn+3qAQL2l0pEP+tViBGVCf2LUsQtyqsujas+MmdLs3JkZ9uMc0vCVbgU0E3yK2EHo1
         QufRPTpR0WzlU/2k5Njo5KfFeUdBMmuLxMUeRXUwnanNSB4AL9ZZ1p09BjTkMvdBnUL2
         huMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aDRT36p1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id r21si259203ejo.0.2021.03.25.03.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 03:17:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id d191so844503wmd.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 03:17:16 -0700 (PDT)
X-Received: by 2002:a1c:4986:: with SMTP id w128mr7098059wma.37.1616667436411;
        Thu, 25 Mar 2021 03:17:16 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:248e:270b:f7ab:435d])
        by smtp.gmail.com with ESMTPSA id 1sm5847116wmj.2.2021.03.25.03.17.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 03:17:15 -0700 (PDT)
Date: Thu, 25 Mar 2021 11:17:09 +0100
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
Message-ID: <YFxjJam0ErVmk99i@elver.google.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210324112503.623833-2-elver@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aDRT36p1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Wed, Mar 24, 2021 at 12:24PM +0100, Marco Elver wrote:
> From: Peter Zijlstra <peterz@infradead.org>
> 
> Make perf_event_exit_event() more robust, such that we can use it from
> other contexts. Specifically the up and coming remove_on_exec.
> 
> For this to work we need to address a few issues. Remove_on_exec will
> not destroy the entire context, so we cannot rely on TASK_TOMBSTONE to
> disable event_function_call() and we thus have to use
> perf_remove_from_context().
> 
> When using perf_remove_from_context(), there's two races to consider.
> The first is against close(), where we can have concurrent tear-down
> of the event. The second is against child_list iteration, which should
> not find a half baked event.
> 
> To address this, teach perf_remove_from_context() to special case
> !ctx->is_active and about DETACH_CHILD.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v3:
> * New dependency for series:
>   https://lkml.kernel.org/r/YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net
> ---

syzkaller found a crash with stack trace pointing at changes in this
patch. Can't tell if this is an old issue or introduced in this series.

It looks like task_pid_ptr() wants to access task_struct::signal, but
the task_struct pointer is NULL.

Any ideas?

general protection fault, probably for non-canonical address 0xdffffc0000000103: 0000 [#1] PREEMPT SMP KASAN
KASAN: null-ptr-deref in range [0x0000000000000818-0x000000000000081f]
CPU: 2 PID: 15084 Comm: syz-executor.1 Not tainted 5.12.0-rc4+ #5
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
RIP: 0010:task_pid_ptr kernel/pid.c:325 [inline]
RIP: 0010:__task_pid_nr_ns+0x137/0x3e0 kernel/pid.c:500
Code: 8b 75 00 eb 08 e8 59 28 29 00 45 31 f6 31 ff 44 89 fe e8 5c 2c 29 00 45 85 ff 74 49 48 81 c3 20 08 00 00 48 89 d8 48 c1 e8 03 <42> 80 3c 20 00 74 08 48 89 df e8 aa 03 6d 00 48 8b 2b 44 89 fb bf
RSP: 0018:ffffc9000c76f6d0 EFLAGS: 00010007
RAX: 0000000000000103 RBX: 000000000000081f RCX: ffff8880717d8000
RDX: ffff8880717d8000 RSI: 0000000000000001 RDI: 0000000000000000
RBP: 0000000000000001 R08: ffffffff814fe814 R09: fffffbfff1f296b1
R10: fffffbfff1f296b1 R11: 0000000000000000 R12: dffffc0000000000
R13: 1ffff1100e6dfc5c R14: ffff888057fba108 R15: 0000000000000001
FS:  0000000000000000(0000) GS:ffff88802cf00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007ffcc3b05bc0 CR3: 0000000040ac0000 CR4: 0000000000750ee0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000600
PKRU: 55555554
Call Trace:
 perf_event_pid_type kernel/events/core.c:1412 [inline]
 perf_event_pid kernel/events/core.c:1421 [inline]
 perf_event_read_event kernel/events/core.c:7511 [inline]
 sync_child_event kernel/events/core.c:12521 [inline]
 perf_child_detach kernel/events/core.c:2223 [inline]
 __perf_remove_from_context+0x569/0xd30 kernel/events/core.c:2359
 perf_remove_from_context+0x19d/0x220 kernel/events/core.c:2395
 perf_event_exit_event+0x76/0x950 kernel/events/core.c:12559
 perf_event_exit_task_context kernel/events/core.c:12640 [inline]
 perf_event_exit_task+0x715/0xa40 kernel/events/core.c:12673
 do_exit+0x6c2/0x2290 kernel/exit.c:834
 do_group_exit+0x168/0x2d0 kernel/exit.c:922
 get_signal+0x1734/0x1ef0 kernel/signal.c:2779
 arch_do_signal_or_restart+0x41/0x620 arch/x86/kernel/signal.c:789
 handle_signal_work kernel/entry/common.c:147 [inline]
 exit_to_user_mode_loop kernel/entry/common.c:171 [inline]
 exit_to_user_mode_prepare+0xac/0x1e0 kernel/entry/common.c:208
 irqentry_exit_to_user_mode+0x6/0x40 kernel/entry/common.c:314
 exc_general_protection+0x222/0x370 arch/x86/kernel/traps.c:530
 asm_exc_general_protection+0x1e/0x30 arch/x86/include/asm/idtentry.h:571

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFxjJam0ErVmk99i%40elver.google.com.
