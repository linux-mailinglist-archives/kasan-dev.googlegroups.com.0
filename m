Return-Path: <kasan-dev+bncBDAMN6NI5EERBFH3Q2FAMGQEXOUIH3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B443140C2CE
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 11:32:04 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id z18-20020a1c7e120000b02902e69f6fa2e0sf1167507wmc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 02:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631698324; cv=pass;
        d=google.com; s=arc-20160816;
        b=F9mlB/NcKxUlRh0LU1bUr9NsnYdWitwfZGZYa85V1w3vPD8Pw6x7xgaLNwsbODHsbW
         7RHwmaO7R0/+iWOKfLHluZkjlWl5WokxvfCkG7eIZXBuQl7RcE47hgwIXP0nb9z52Ced
         KS2z0attMwtO0EknhTBrjjciM3xZ509Yo8xcvWD0V90CaIRsICBzkZ5drWP+/z1w7xtC
         eloC8j+GwAJlKpX+B5Ncvw+WJKSg8ySOQDpnL7MGrT0s01wq9mHSQGJTRbYz/n1VQBou
         3idkq7NFVwNKh3J+YxwLpJdc4GrFtJ77Q8tSzfAlCJPA04ox8CgyEjEl59gtOHvWqREb
         zXzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=txD6fh38aZPoY95O0SchN+Dg14rkCZtzjRhk2ksok4k=;
        b=O9Tf+O7/LV5D1YS7kvrNvTXq5bJ2AJRlf+KvbiOpILm50Cw06Y8oWgEIXidSRR+h96
         lj3MavC1Sy4rt3TyHVcUTb9EDOJ8wfZ3aUG4d75EVixRZjJO3iNA8FrTIzq9poyBqPmi
         ASypTKMX+tsnTWBEt0hvmWXND35EPOBzth/snlO+M6VT8Bqy+Mt4YbXz41isWUK8rBLl
         pjNvFiG/QOggdB+J4yCFj5zynA5+JMWMEQwrACZYGQatu/hm6mjD3JqnPrHjsO8e1dVc
         SRZYz5az2TVU1OpartbNjJjIt2vyhMkHlrvnSqXt1gdQco1RagZst56wDk20xvnB9f6A
         4ubg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=PnQrEKGe;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=txD6fh38aZPoY95O0SchN+Dg14rkCZtzjRhk2ksok4k=;
        b=jcr7kOqLMzHIvzdmXF5YWWBEeGE8kqrnpEVmBJzdxrOqqp8Zh/Hb2N0OBwy5tk6hTq
         YwIIl3Hh9FHI18c/rmwDmdHq/IpesJTvFtt+RLfxh42WK5oNmolakK3PgCz0XKtstk97
         Z8RpFIMZqvNfyh9IOvufRMm+CKA5mtkDkOZ9TBHBF7z2L1X4JEfaqG5UDcP60hSLXAYp
         cG8+ZGoCjojgLYnMb+M2QAXShvw98yUQsWsMQ8GHoSJs4n4Np5e/bMqguKAlzlpNcInK
         0gTm4xEBzUFiywkon7z/AinlYNlTIyr5cpAfGH7sRqGpqmHgtFET2hkWB59IkhwEZdHf
         NdWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=txD6fh38aZPoY95O0SchN+Dg14rkCZtzjRhk2ksok4k=;
        b=dgk9KSLiPdPNkUVJonHE0urnddzyrEYTXFi7aadOxEQtYAQTxbQ+frAbBizW0+sQPG
         2GYe1gz609BV+yViU3kU31Rgh71cTobOXR9O/251ZIeBzXdHUbXlwo5Ov7CDf28BfVVQ
         q71XQajqHXCT2nedJNr19YB/lxMguKUuXCehSc8ZqCaIQ717KGCdYGXXrGuu9zPBNa35
         6Ioorrb8U28mAMuM8GBmcBi0NG8WAzVzhJViu0ZrvNvSZBMDH0Grxpq7x5x3qAhGDnQP
         gtvz2bf2PlaaZwjPmThTC7lqLnRxVgBJeBPrZgAky49G0dkXcxkqqh8T9idlraJ89MkH
         QWDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530G4XJuDL0HZfUBi2F+RjtBlAKODK7SFMmcOO+JLvuwtLlhD1y7
	TT2++5f2H6BFg8LzNId5Cf4=
X-Google-Smtp-Source: ABdhPJwWGfxDe9ODu2Y+uYNfucfY4en1jRwfWXUhFq92rNWd2JS7eZhmwuWzRYHm8HdNKLld3Ad1SA==
X-Received: by 2002:a1c:234a:: with SMTP id j71mr3323278wmj.11.1631698324402;
        Wed, 15 Sep 2021 02:32:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f8e:: with SMTP id n14ls867663wmq.1.gmail; Wed, 15
 Sep 2021 02:32:03 -0700 (PDT)
X-Received: by 2002:a1c:4645:: with SMTP id t66mr3350452wma.130.1631698323439;
        Wed, 15 Sep 2021 02:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631698323; cv=none;
        d=google.com; s=arc-20160816;
        b=A85r91n2EyDbFJrG3tp37Wxrl5ckaMz4+EJtwCxkkmvembLQHyHUOYhW4o5A6wNkGF
         JVrrmsGyfVydlj5Z2Of5csmH2M+32sIo6PtY+6+n8N3DWKakEeMoX633r0VaG6sonsiL
         /PtyR9XqH2/15A+g9QctdHTKKQ5hM8p7bepTGbYdH0WpnXERjlfn1mewDOQ4o27RdNM+
         /SAiLgTMNMY2zVD1J2TnzHhYgJfk6UUtxDE37wcTUmqOrsuE1Kxzg5ZTIOkAWgvZpEyL
         AglJVKwMcaCvvSAP3jPze0WYxcnWuJ75CPObM/pmgAOSsrXuRlugJ+SFW8KKdiJGYUaz
         iI0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=WbtaLyN7bc/D5y/kWdbb4hJQoxC3BRCKmIuJD4Msv60=;
        b=PVm69mE48JLaOG1Hs+FPJnBn6RSHpJ8cSt57G4s1712OH+rSG7cEpyKMmzIy5qD3r/
         e05M02ccZfK/w754z2LO4JxdHAf0iMV0LuoxS4m9hqg1ftv5zUs2iLB6wVkg+92rD/as
         /W9gnrdvSYYCp7a8F0UjORA+QXiyaoW/csdj+3LjpqNQm7mKnK4okmvSCCsQ8xhABR1G
         7ZZuhcGXrtD2V72mo4q1HVZH1waYaqjfPVYSPUc7ZRtY5397V44jl/iqTO6EEcnR50/s
         YvpX8CLAz0UYmBHDTNyNdk7Rxr3tRhZEbfrQyMGTl9PJN1WYv4sYWaJ6Ab4Xxkz6ZArP
         pAlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=PnQrEKGe;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 193si287093wme.0.2021.09.15.02.32.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Sep 2021 02:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Hillf Danton <hdanton@sina.com>, syzbot
 <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>,
 linux-kernel@vger.kernel.org, paulmck@kernel.org,
 syzkaller-bugs@googlegroups.com, Peter Zijlstra <peterz@infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Johannes Berg
 <johannes.berg@intel.com>, Kalle Valo <kvalo@codeaurora.org>,
 linux-wireless@vger.kernel.org
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
In-Reply-To: <CACT4Y+avKp8LCS8vBdaFLXFNcNiCq3vF-8K59o7c1oy86v-ADA@mail.gmail.com>
References: <000000000000eaacf005ca975d1a@google.com>
 <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
 <87mtoeb4hb.ffs@tglx>
 <CACT4Y+avKp8LCS8vBdaFLXFNcNiCq3vF-8K59o7c1oy86v-ADA@mail.gmail.com>
Date: Wed, 15 Sep 2021 11:32:02 +0200
Message-ID: <87k0jib2wd.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=PnQrEKGe;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Wed, Sep 15 2021 at 11:14, Dmitry Vyukov wrote:
> On Wed, 15 Sept 2021 at 10:57, Thomas Gleixner <tglx@linutronix.de> wrote:
>> That made me actually look at that mac80211_hwsim callback again.
>>
>>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
>>
>> So what this does is really wrong because it tries to schedule the timer
>> on the theoretical periodic timeline. Which goes really south once the
>> timer is late or the callback execution took longer than the
>> period. Hypervisors scheduling out a VCPU at the wrong place will do
>> that for you nicely.
>
> Nice!
>
> You mentioned that hrtimer_run_queues() may not return. Does it mean
> that it can just loop executing the same re-armed callback again and
> again? Maybe then the debug check condition should be that
> hrtimer_run_queues() runs the same callback more than N times w/o
> returning?

Something like that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k0jib2wd.ffs%40tglx.
