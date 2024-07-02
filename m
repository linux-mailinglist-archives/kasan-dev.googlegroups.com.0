Return-Path: <kasan-dev+bncBCAP7WGUVIKBB4FVSC2AMGQEGPXJTFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E2792423D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2024 17:21:22 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2598b4c44f0sf5318871fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2024 08:21:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719933681; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7GLQwBXgWPIpjSIZcPcanhoD2kogkN2Mvi64GDvQxSFhk8e+DaQe1+8THLH2d7KEy
         CnQgV9Mt34JOV+S3OXqzlGsMotRINJs32u3L/+SAwovA573UMo/iEYMpP8gaNFfIIvad
         csPxLzuKU+W5wKJdC6/AV34CMi7MCk+ljLlrdhLnaJaWzph8qaZbms5CbR22BHUvWYMJ
         sE/8vWyZhisxIDK0HdZFn2JW8MoppSem0p7OEaFg44OS6i2xOUleiKpZSGMagcu7UBA5
         L2inNAlLrOCnpLHAFUP2qEsGhEsw64lUmp+Lr6wmRAsEtkbcs417uiGXTWil8B9JPH0K
         DKqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=jysaioHpx0wcy7P6p+vZYOW8wgH0pvfYuoR9tCGKH14=;
        fh=EzNca8keaqlk702MqmWUbdWXpCBS4aUzk/k0CW12MYU=;
        b=YFXgnES3bp/4km4krjpttBuP7H4GCw/Tyjab98EASjoDc/AEyJuVsj+/XoPTK6H3gr
         Op8zZxSduIlXU2htYvKzlgzeEsL7rULLWD25WAdfHZMXLR1iOHtXR992s8U8II3JBgmR
         X0cOg3ARXZZJC72lCAAvuRpeetwJAZi1V3dgucWgMuRb3ZwVBfS9ze9tc3TKwEmcfMtg
         uGdGmD1cXhPVBuh1xdbp4vxjVuQx+/fvvqSf/ovAaBOm56+XBRQ5Cyhu3f1TmbKMF+o4
         zahscMwKg36TfN9aoEH2XC1boMzNDRGArStUpmVLrpDaTqAOcKT01Vay7ayOwxqBBA7Z
         SYCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719933681; x=1720538481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jysaioHpx0wcy7P6p+vZYOW8wgH0pvfYuoR9tCGKH14=;
        b=a+rlGM9tG3Tg5HiKUuF8wnFnkandBBTkKr3i16u4ULzUYS1QmSy/q3JPRCtth9WIgN
         ztYIx/0qrILOtickM3uBFZMSdmWN+Dt8sEN3PgSojAWEo+FC6RyHAKRyKJhzVTcfOZ7V
         0MJhud/saBQfeAr24rH5rvK5ZjXX5e2F3I4JMaodR3yjOOvPgZ5GLaTkEPnOAiEXXWAe
         Dlu5fcpHHqE5qnDhJiwNRf3JId21by5f6yOYMMsvi980Uq9/1fwADTlXAvr/oGkrNKjS
         coKj8lzAIn3w5f0a6M0GI86TfaK8VpMAbs8xB6Emjk7wKoRmCOB8AL/vMhLlsfHINd1J
         UU3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719933681; x=1720538481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jysaioHpx0wcy7P6p+vZYOW8wgH0pvfYuoR9tCGKH14=;
        b=ja6PX+mEwR+Xis/3L098MyvFzM/4IQ4VYCKF75CIOqWGxtMVrx+fE/Du7vbVtr3jZo
         0lqg/ihhQpMAzqO0b5DZW3OIX3fHcG8xrwuX32IY6mRlKdBIYnHoKfnWuFdWliVCWS90
         V0A790MrfUGHHvJKdOVkTb3AJJryunlpVz1WOiZGhVuFyKPIrmvsJQfnmiky0xn9BEVI
         FJSyFdhO5GmSt9LfMLmCBZC3azmzHJo3OyLrCahdBNZ1UyVf6FEcLx4eHDacLHt/ZRmR
         gRgs9MuunhHu2cAIBQTi+ABWXEkmVtPjJD8BGQmQmW+jVB9KAiimABj/mr34zTnf8hiT
         /Dmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKZ5z4xP7QHBD90/3nGSR4ZzsxtBgQ8+Gqfmzr/KNmqrB04TH2k14kWcEnpSahsVWl/cyalnRveXVOFz4e/gVCHjsSVU+dyA==
X-Gm-Message-State: AOJu0YxfTVGmTdGiy02P1rQriSSU1SfOq3pprLJJPYe97/RS5yddZMpA
	DBqnxpnd43rML883QQczZU/b5IuQRxHKLQ6KTqa77WqKouFNzqvD
X-Google-Smtp-Source: AGHT+IHAC5xo0O2Yer0u+RKuWMGJJiIka6uxM8JxuT+22aDDWl97vPAv+yKwAQ7n1SEc3HMg0L3/eQ==
X-Received: by 2002:a05:6870:f150:b0:254:d05e:4cd5 with SMTP id 586e51a60fabf-25db35af44cmr7716583fac.38.1719933680483;
        Tue, 02 Jul 2024 08:21:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8a23:b0:25c:b2bf:2226 with SMTP id
 586e51a60fabf-25d953a3ea9ls1685336fac.1.-pod-prod-07-us; Tue, 02 Jul 2024
 08:21:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW76AftcD9JZQFQm0IqAy1xy78Uz9gQpxZn5IdEpVbqjwbOb+35P1qbj2CFH/Hx7oCp6GzQNiAlZVIRd7b7gXL5050Y6+VOo9OeFg==
X-Received: by 2002:a05:6871:714:b0:259:80dc:13e3 with SMTP id 586e51a60fabf-25db340e4e8mr8020595fac.23.1719933679046;
        Tue, 02 Jul 2024 08:21:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719933679; cv=none;
        d=google.com; s=arc-20160816;
        b=l53NrXbdFd9XFFa1TfsHNHvI3sg3LNEH4eD9zXQm4XNKp5YmeHhU4wFzJV+7Etw+It
         dg56EqKKEfb9DMGZGqj5ffZFLt2YstzU89RUIN9F8lzOxlx0mCw5B7ofeHK3NW/wwWqq
         Zsloxb/AbD2tNZfxVrHqTcWNkl5cGdtcpipxQx2U2QLT0Ex2kLFmpv8rglB2AVhskm8t
         vpDCe+JVfVrfEEvhO1Yn0GhLscNPXSRR4ZikwXzW2gwKw5vfqQ+jMLJ78I3mpo3/s2FN
         vnhFG/URF4IHPeR+CpevSJRpyl2RY1nppW4NK+wbF14i3VKiQPCvwCllEhOmkGITRo4O
         fTMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=2Yku3KEdt2E+QBgpAr0o2bHQ4OlzwbC2rf0Va4//w3I=;
        fh=/X6ch4A1P7mqFjFzh04ZrXpxVqEtT2Yo7A5UxE4IwbE=;
        b=UZHeiuPODdHEB+GzkIFfxGgMpPvWnjS4Bwoc08hb1E7maqP2sFWbOYdPaO84NfwE6l
         wnQdBtANboT6oyCraoh5Vt77IkRJgs6qoFoK2nBkIAKq5aBmtSyU9DMZH1ALf21j75sP
         DAs28kBOj5dFmeiv0tAyQIgcFWLjtSvERlvYmuFK5zIkzat5yxeEKwUyP3Gr9IS9+DrM
         DhKOMTSlPwzWlOERSPrbT3bSTSs3n61qfW7z/ARYTBqPo4KRXlVOZ2PY6lRzwS1bf1r0
         WlJo5kVAVAdZy1DO+j9SEuufx53dTBTmLKlJh/irbQZw9Qg5xyIvjbML3XXAo4YZcQpt
         WLzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25d8e46b4acsi423328fac.5.2024.07.02.08.21.17
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2024 08:21:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav414.sakura.ne.jp (fsav414.sakura.ne.jp [133.242.250.113])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 462FL8IA090276;
	Wed, 3 Jul 2024 00:21:08 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav414.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp);
 Wed, 03 Jul 2024 00:21:08 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav414.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 462FL8AB090273
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 3 Jul 2024 00:21:08 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <1df448bd-7e22-408a-807a-4f4a6c679915@I-love.SAKURA.ne.jp>
Date: Wed, 3 Jul 2024 00:21:08 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs
 (2)
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>,
        linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        bp@alien8.de, dave.hansen@linux.intel.com, hpa@zytor.com,
        mingo@redhat.com, tglx@linutronix.de, x86@kernel.org
References: <000000000000a8c856061ae85e20@google.com>
 <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
 <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
 <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com>
 <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
 <CA+fCnZfxCWZYX-7vJzMcwN4vKguuskk5rGYA2Ntotw=owOZ6Sg@mail.gmail.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CA+fCnZfxCWZYX-7vJzMcwN4vKguuskk5rGYA2Ntotw=owOZ6Sg@mail.gmail.com>
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

On 2024/07/02 23:29, Andrey Konovalov wrote:
> One other thing that comes to mind with regards to your patch: if the
> task is still executing, the location of things on its stack might
> change due to CONFIG_RANDOMIZE_KSTACK_OFFSET while you're printing the
> task info. However, if the task is sleeping on a lock, this shouldn't
> happen... But maybe a task can wake up during sched_show_task() and
> start handling a new syscall? Just some guesses.

https://syzkaller.appspot.com/bug?extid=d7491e9e156404745fbb says that
this bug happens without my patch. It seems that this bug happens when
printing registers of a preempted thread. 5.15 kernel does not have
CONFIG_RANDOMIZE_KSTACK_OFFSET config option, but

  __schedule()
  preempt_schedule_irq()
  irqentry_exit_cond_resched()
  irqentry_exit()

pattern in 5.15 resembles

  __schedule()
  preempt_schedule_irq()
  irqentry_exit()

pattern in linux-next.

[ 1008.224617][T14487] task:syz-executor.1  state:R  running task     stack:22256 pid:14483 ppid:   434 flags:0x00004000
[ 1008.224656][T14487] Call Trace:
[ 1008.224661][T14487]  <TASK>
[ 1008.224669][T14487]  __schedule+0xcbe/0x1580
[ 1008.224689][T14487]  ? __sched_text_start+0x8/0x8
[ 1008.224709][T14487]  ? ttwu_do_activate+0x15d/0x280
[ 1008.224732][T14487]  ? _raw_spin_unlock_irqrestore+0x5c/0x80
[ 1008.224758][T14487]  preempt_schedule_irq+0xc7/0x140
[ 1008.224781][T14487]  ? __cond_resched+0x20/0x20
[ 1008.224802][T14487]  ? try_invoke_on_locked_down_task+0x2a0/0x2a0
[ 1008.224829][T14487]  irqentry_exit_cond_resched+0x2a/0x30
[ 1008.224851][T14487]  irqentry_exit+0x30/0x40
[ 1008.224874][T14487]  sysvec_apic_timer_interrupt+0x55/0xc0
[ 1008.224900][T14487]  asm_sysvec_apic_timer_interrupt+0x1b/0x20
[ 1008.224923][T14487] RIP: 0010:preempt_schedule_thunk+0x5/0x18
[ 1008.224950][T14487] Code: fd 85 db 0f 84 98 00 00 00 44 8d 73 01 44 89 f6 09 de bf ff ff ff ff e8 47 e4 8f fd 41 09 de 0f 88 88 00 00 00 e8 89 e0 8f fd <4c> 89 e0 48 c1 e8 03 48 b9 00 00 00 00 00 fc ff df 0f b6 04 08 84
[ 1008.224970][T14487] RSP: 0000:0000000000000001 EFLAGS: 00000000 ORIG_RAX: 0000000000000000
[ 1008.224991][T14487] RAX: ffff88811532d948 RBX: ffffc900072ef560 RCX: ffffc900077e7680
[ 1008.225009][T14487] RDX: ffffc900072ef5b0 RSI: ffffffff8100817a RDI: dffffc0000000001
[ 1008.225027][T14487] RBP: 0000000000000001 R08: ffff88811532d948 R09: ffffc900077e7690
[ 1008.225043][T14487] R10: 1ffff92000efced2 R11: ffffffff84bfe126 R12: ffffc900077e7680
[ 1008.225062][T14487] ==================================================================
[ 1008.225071][T14487] BUG: KASAN: stack-out-of-bounds in __show_regs+0x252/0x4d0
[ 1008.225098][T14487] Read of size 8 at addr ffffc900072ef4f8 by task syz-executor.3/14487
[ 1008.225117][T14487] 
[ 1008.225123][T14487] CPU: 0 PID: 14487 Comm: syz-executor.3 Not tainted 5.15.118-syzkaller-01748-g241da2ad5601 #0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1df448bd-7e22-408a-807a-4f4a6c679915%40I-love.SAKURA.ne.jp.
