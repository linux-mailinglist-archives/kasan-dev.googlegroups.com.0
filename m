Return-Path: <kasan-dev+bncBCAP7WGUVIKBBN65VG2AMGQEUFAHC3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A054692976C
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Jul 2024 12:32:25 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e035f7b5976sf5250677276.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Jul 2024 03:32:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720348344; cv=pass;
        d=google.com; s=arc-20160816;
        b=MjqIY0jQtbnTRCZ342Zu3wiUw6iFwqffam5LkYbae67M4p9N9OZwhX9BLLzFi9QCOD
         kvUG4YCTe3g4V70dMXolcxQMI4oddbGpLkoQHg7wPE3MGlnhaUvaW1LBSxf04Uvnd1rv
         /f3Qn050WNur+dvY7HSyRWGMKOBfnDmJrKkkdDNZbi9IBRPfwOGYlVfa5r3I6XET36Te
         3dVz/ElyaiqkUwU75irR8nNPTP9w6g2nZy287JiebQSM+/2b5EPc5SsUB7/DiB74K39s
         mya4wipgm0/cOonLFCyBGmvIG+Wn/pzRiuAPo9SL9SK1sMXvc99nI6VbVYyX0ldPGF/v
         PLGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=1HVIKs0todmkk/L09+0pAKFd4E34Ca2MX632CqBKQA0=;
        fh=voL0jh7QHoTlc3fo8lPd4eOuQLYhfErzfGuC4wFomEc=;
        b=l+P6tPjaaGvnclgS3dd+wJc2z5tbUQ15taV1DlcklgbXplyxfxEn2iaTD3M6v0Rw2p
         Jzz40NHSEUFhsh+NXPZnahc2ZLT5diFA9wVNuXkEJ72AW3+tcRqhLXP3kgYMkuItRVCh
         yYbBVcRPbM2dslliOm12FNK4dpF9zUQemSBL63Ds3jExNmOOGs/qtHI8DUL/zgM4jq0T
         DVhSXtUnJ7KexXFPFUtk4YxeP/SY5EAq0L1LZHw2LP8w6uCJvSXJyxo6ts5G3JHSnSks
         lEQejF9NYh6AyuL2uBkb9f8GJyIXZ0FZZ0xf1AsmKiZRFj1YTp9CvHl6urLcMFJ9qK7x
         Kg2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720348344; x=1720953144; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1HVIKs0todmkk/L09+0pAKFd4E34Ca2MX632CqBKQA0=;
        b=TcNRkw24GzCxD065aChxkGlacnkLP82CjQfFgTBaXozX0ZEF6lSvmyqoQaJGG03iDN
         3xUpS/mgOlPWIu3+RYAgM9osVAzUKtETmuxPtsZCYTu2sV79Qhc9zoilnzdpgwpkAGX1
         OlwbW8ZNKa9jlerUgCIPcuZGfKJbGyyuVYyb6Cp1y6JqCU4M5/VFPygV57RUJOLL/4S8
         WBSYjOhZaHsl6Y0aAUioxCf7B6PNmw+qqqbsPS4mbTy00/oGgoYdDwP8K6TUpF044a4U
         OhLAUgftNk4ALGDzg0oYNAx+1Yl2BAz1ipUmIIE05NiEB27wl8IKxp+W9MqU9xwws1Vk
         7Csg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720348344; x=1720953144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1HVIKs0todmkk/L09+0pAKFd4E34Ca2MX632CqBKQA0=;
        b=PgygwRb1zED8SFNoLASiwn48+1QIWIxaneWqft173/sLzIjJl/OYBlcqVTjpe75deg
         FPfp7uRGELljnFqCHDZIyfQAj3w9LXBXQgLG8PbgRoqdnNPe98i04s3tuxfU2TqH7RN3
         /YXK9DzCX3MfGCCFTEAYNgirmxxZTlakz2gnun7u0k0lZOE9iedSvnIzAH6JyOvOu+OC
         pJCdPlCxauFa86zqHBuTWKrVA3LzJPIrK+yKr1+ptXuGuHFx35geW8pGmpIlINIPxNjJ
         7KnXNSF8S8qp/VMGJpu4ubIvvusRJhDHTCz9JRz+CklloJyJuJQ7GVFx02XBlwBO1X20
         KwSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1OTRWX+oL4U4lszSgcIT8ZCK6exv0FBI3w5EPNMG8wzepZjkEvg5x/dCGj7ZVyzE0hkD/hOFrY3rSjRV2Jwx/8tOh1uuaMA==
X-Gm-Message-State: AOJu0YzeKwiFA2qxXOIJCdUYSwsQZ6b0uW2Vjp3mR4hhm5XClvz/nbMC
	OWWGA/UJzG/AkNo9pME/QPbh/ufly/EwmBDhWXxstUiBlOTYeG9W
X-Google-Smtp-Source: AGHT+IEnV48DuF/jOZRP/2aQbHVdu1weGsCq8+mx2ki9CwsfrQX+SH3AXQp6U5I82GUqdrpbDBU9PA==
X-Received: by 2002:a05:6902:4ce:b0:e03:5a2b:8b00 with SMTP id 3f1490d57ef6-e03c28a57demr5876922276.1.1720348344023;
        Sun, 07 Jul 2024 03:32:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:18c6:b0:e03:62ce:ce8c with SMTP id
 3f1490d57ef6-e03bd143ea1ls1633841276.2.-pod-prod-00-us; Sun, 07 Jul 2024
 03:32:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMHJ4TVSgjHRcskaYJ/CtRx/hH9GLg2XljWgjPNbvBBl7vtgofYHQ1hOz/kf2tedjqD1v9iDlzSCNvEKavBz2WDTnueabxGGFFwQ==
X-Received: by 2002:a25:9089:0:b0:dfb:c41:1abe with SMTP id 3f1490d57ef6-e03c2b51a06mr5083497276.31.1720348342994;
        Sun, 07 Jul 2024 03:32:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720348342; cv=none;
        d=google.com; s=arc-20160816;
        b=P0hcsBQslgpCgGm1CUFBtbfPbrCjeYTjPUOk3XqzcVyiZIZ7KNLvoRRx1cQkMRh4OD
         TsyHIJKEWY+u9Ko6a+6s+2w40jVQQlPAT7aOC+VB66OVV36TwtBFSYc8+z7W/6+LllRG
         Iz6AXhO5X5GPkV6kphc47S+ct3lZt2NJH9UBBCRIrdpTDULnuOsrS0b6b2So/cHLR2iT
         ZorrpKnONa13hHetHUjglzhuIGLtiY4Aci9saTl1awBXSXWLariRWmA99Z9PA7rXDX0L
         0o+6hvYzitFtMcGQwzQsdF3dkjKNGL7fLS3InDrKfAsCxI9XyvfBN+WAaa4DZZzA6URt
         U3IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id;
        bh=Rh8OjDVSEtxqcOK+7T+/rsIZv+IyqePzR/tqvDLyv5Y=;
        fh=pkRkJKxV1Ht9Xu56AyjyrK/Z+FH3yoXk+SFweWykk+4=;
        b=f5NoqNTcSCrNNgeine6bBbIHb7iTX7Aq8TSJIKI8C0f5UdIWhH3aSRS31UM4LVXTib
         E89rWe7Lhn+dUf7aT2Mg8rRFJwUqToYnMuXZiFzP7eyRI3/UW6QtDa715BQ+r6j0Lmrt
         bepwNyqchM3WOVCAdfupWGavGFTbMUJeTk5kctRWqt9+7D1LwONe54MhFBCJ8dWdau1o
         QAOv7LcJUvHEbTZUJEbB/Uv84/fgE+M2aUdLeFWK33yFQReSYfwf+O15rpOwf+Vkr7+g
         Sd1DfwJQnqWF8zKSTu2XN9QAO/drWHUGbskvkvRnwMauW5Jvrv9dVlE2ROeG0d+uhnlG
         wmNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e039add9cf4si520696276.0.2024.07.07.03.32.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Jul 2024 03:32:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav413.sakura.ne.jp (fsav413.sakura.ne.jp [133.242.250.112])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 467AW6WL050735;
	Sun, 7 Jul 2024 19:32:06 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav413.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav413.sakura.ne.jp);
 Sun, 07 Jul 2024 19:32:06 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav413.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 467AW5mV050731
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sun, 7 Jul 2024 19:32:05 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <5136bcc7-3db7-4fc2-abde-a3aceeaf17c2@I-love.SAKURA.ne.jp>
Date: Sun, 7 Jul 2024 19:32:05 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs
 (2)
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>,
        linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        bp@alien8.de, dave.hansen@linux.intel.com, hpa@zytor.com,
        mingo@redhat.com, tglx@linutronix.de, x86@kernel.org,
        Andrey Konovalov <andreyknvl@gmail.com>
References: <000000000000a8c856061ae85e20@google.com>
 <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
 <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
 <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com>
 <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
 <CA+fCnZfxCWZYX-7vJzMcwN4vKguuskk5rGYA2Ntotw=owOZ6Sg@mail.gmail.com>
 <1df448bd-7e22-408a-807a-4f4a6c679915@I-love.SAKURA.ne.jp>
Content-Language: en-US
In-Reply-To: <1df448bd-7e22-408a-807a-4f4a6c679915@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

Guessing from IRQ entry hint, I found
commit 37ad4ee83642 ("x86: kmsan: don't instrument stack walking functions") and
commit 6cae637fa26d ("entry: kmsan: introduce kmsan_unpoison_entry_regs()").
I guess that we need to disable KASAN for the same reason as well as KMSAN.
Alexander, can you write a patch description for below change?

diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index a7d562697e50..01edff4a9d6b 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -192,6 +192,9 @@ static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
 	int graph_idx = 0;
 	bool partial = false;
 
+	/* As with KMSAN, disable KASAN for the same reason. */
+	kasan_disable_current();
+
 	printk("%sCall Trace:\n", log_lvl);
 
 	unwind_start(&state, task, regs, stack);
@@ -304,6 +307,8 @@ static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
 		if (stack_name)
 			printk("%s </%s>\n", log_lvl, stack_name);
 	}
+
+	kasan_enable_current();
 }
 
 void show_stack(struct task_struct *task, unsigned long *sp,

On 2024/07/03 0:21, Tetsuo Handa wrote:
> On 2024/07/02 23:29, Andrey Konovalov wrote:
>> One other thing that comes to mind with regards to your patch: if the
>> task is still executing, the location of things on its stack might
>> change due to CONFIG_RANDOMIZE_KSTACK_OFFSET while you're printing the
>> task info. However, if the task is sleeping on a lock, this shouldn't
>> happen... But maybe a task can wake up during sched_show_task() and
>> start handling a new syscall? Just some guesses.
> 
> https://syzkaller.appspot.com/bug?extid=d7491e9e156404745fbb says that
> this bug happens without my patch. It seems that this bug happens when
> printing registers of a preempted thread. 5.15 kernel does not have
> CONFIG_RANDOMIZE_KSTACK_OFFSET config option, but
> 
>   __schedule()
>   preempt_schedule_irq()
>   irqentry_exit_cond_resched()
>   irqentry_exit()
> 
> pattern in 5.15 resembles
> 
>   __schedule()
>   preempt_schedule_irq()
>   irqentry_exit()
> 
> pattern in linux-next.
> 
> [ 1008.224617][T14487] task:syz-executor.1  state:R  running task     stack:22256 pid:14483 ppid:   434 flags:0x00004000
> [ 1008.224656][T14487] Call Trace:
> [ 1008.224661][T14487]  <TASK>
> [ 1008.224669][T14487]  __schedule+0xcbe/0x1580
> [ 1008.224689][T14487]  ? __sched_text_start+0x8/0x8
> [ 1008.224709][T14487]  ? ttwu_do_activate+0x15d/0x280
> [ 1008.224732][T14487]  ? _raw_spin_unlock_irqrestore+0x5c/0x80
> [ 1008.224758][T14487]  preempt_schedule_irq+0xc7/0x140
> [ 1008.224781][T14487]  ? __cond_resched+0x20/0x20
> [ 1008.224802][T14487]  ? try_invoke_on_locked_down_task+0x2a0/0x2a0
> [ 1008.224829][T14487]  irqentry_exit_cond_resched+0x2a/0x30
> [ 1008.224851][T14487]  irqentry_exit+0x30/0x40
> [ 1008.224874][T14487]  sysvec_apic_timer_interrupt+0x55/0xc0
> [ 1008.224900][T14487]  asm_sysvec_apic_timer_interrupt+0x1b/0x20
> [ 1008.224923][T14487] RIP: 0010:preempt_schedule_thunk+0x5/0x18
> [ 1008.224950][T14487] Code: fd 85 db 0f 84 98 00 00 00 44 8d 73 01 44 89 f6 09 de bf ff ff ff ff e8 47 e4 8f fd 41 09 de 0f 88 88 00 00 00 e8 89 e0 8f fd <4c> 89 e0 48 c1 e8 03 48 b9 00 00 00 00 00 fc ff df 0f b6 04 08 84
> [ 1008.224970][T14487] RSP: 0000:0000000000000001 EFLAGS: 00000000 ORIG_RAX: 0000000000000000
> [ 1008.224991][T14487] RAX: ffff88811532d948 RBX: ffffc900072ef560 RCX: ffffc900077e7680
> [ 1008.225009][T14487] RDX: ffffc900072ef5b0 RSI: ffffffff8100817a RDI: dffffc0000000001
> [ 1008.225027][T14487] RBP: 0000000000000001 R08: ffff88811532d948 R09: ffffc900077e7690
> [ 1008.225043][T14487] R10: 1ffff92000efced2 R11: ffffffff84bfe126 R12: ffffc900077e7680
> [ 1008.225062][T14487] ==================================================================
> [ 1008.225071][T14487] BUG: KASAN: stack-out-of-bounds in __show_regs+0x252/0x4d0
> [ 1008.225098][T14487] Read of size 8 at addr ffffc900072ef4f8 by task syz-executor.3/14487
> [ 1008.225117][T14487] 
> [ 1008.225123][T14487] CPU: 0 PID: 14487 Comm: syz-executor.3 Not tainted 5.15.118-syzkaller-01748-g241da2ad5601 #0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5136bcc7-3db7-4fc2-abde-a3aceeaf17c2%40I-love.SAKURA.ne.jp.
