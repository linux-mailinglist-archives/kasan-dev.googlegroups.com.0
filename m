Return-Path: <kasan-dev+bncBCAP7WGUVIKBBOONR22AMGQEDPEHZ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5482E91EFB6
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2024 09:05:31 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-70a95a33c06sf3205722b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2024 00:05:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719903929; cv=pass;
        d=google.com; s=arc-20160816;
        b=wCZTyjyQtw+rbj+iNQRhq+m1qAvEWuOyxq5mdaXf3Oa9ZUoGtw1pgGAjPW4y77KrtA
         YGALoUt9trFSbzaq8dlDqhzQxqMi6WG6BgWH5UDdqLhNRgvqXAdbhhsEfaBoF2NvFamF
         4hmFYWz6KblROq8LLh+GZLjpzzzENdhO7abrm1UHC7aNHPyyC8TRKC/r6FwabodOer7H
         3xG1TeZV5VmKb4dVZNZIOkVyc7fD7NdyXD+yyyOCqgfM3zDYvfF0DYay5FYmcPwRtfeT
         iPrYMnGgQCQJ3ldo1ITNi3AoB+JV7Oe4uMreIoxpUkkEls11Nq34BcTVA53r61ZMgqYv
         jN1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=w+9Z4l7Z/B6TgQYr5lHcL9K3wKlfmEz2KWYtk8ncqQ0=;
        fh=BMXpsO5aNf8kavupEIepgi0+Dnvd+99WkCXfJNB6S+s=;
        b=KZC3eJ/XgKpFjMgGG5wbWW8KAk2azrhUjldoeQjrXTzJQ27sJDB8O4BRaZv1/6iidn
         fCyrO/V6f1tMit68cI3sez7qpsKa2FvD11lDYe6z6C/OqscO2RvgzPZOoirftol5D51m
         R/ZjdwPkU/RG+G6M03D+u6ApAjsK6wfxbWkwtf5FqMyMqgIYxbEs22rNy+ktLjtWNAur
         HV0ZtfzYFlgaIrQOct7tTbwSVBVaVuOBkqM3Qx3SQS1u/2FxD1ySLBKQI9lVXmc2duni
         Ld1LfY9gRbVKdO7HUJrzvd3iQYj7MgY4bMXQ+WaxtbHt67iPDjnCNSZlS/EsaNmNOOmx
         03ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719903929; x=1720508729; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=w+9Z4l7Z/B6TgQYr5lHcL9K3wKlfmEz2KWYtk8ncqQ0=;
        b=SxbBKh1jMHF77Kt6v/dtdzsmVmL8WRHlUP5GKDWjEs1p5plL/R4UEd/BAMaMhegCpH
         z5S0b3fREmy/04sLqrnOUzo+J7FNxPDf6eMeFWSoBfPkyXzgG6koDyTrH3+MC/B0EiRm
         etyIXMsPFRLhqA6RLK27SVTSj1dVEvx8z5OU+MiHmaYYnm2Vk1fFxiPywkWgP02UQ1p5
         lS3cMcP1DzYGPAx+NlgfmOBy8nnZCzM3jNV5GFoQKX21bg+XNPNvTeixdYEQKzgvhJSu
         cFY4O29AOg2s/YUpXd5Jbxn5I8oTNkD2pybJffNHEb8TbV9biG3PJoiwwgegI4/6sNdP
         l0Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719903929; x=1720508729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=w+9Z4l7Z/B6TgQYr5lHcL9K3wKlfmEz2KWYtk8ncqQ0=;
        b=f/ramMbKetZPJB8lZVSNLxb8US7NlpCwQv1/BZTAnwvqBR/S4LuHv5FXjFGWBWxGEM
         IlupNNvhNIiyiD+anLeORMKwtiJnIwxgg5hKkpfommcf8qeqjxw037B9kq94sMFA399s
         M6U4/NG1sNWnnhE2yu0Yfzh1ksV4RF1ebP1ns88S5lJCD56p/O4AtSqJUkYvAP9LWYKZ
         9ZEsrcWHDZkunWzP2nNQNyvpppUtbf/M3SQQTZeAE9rKsKBs3jwJwginaN6wznsIhqbl
         UYJ/lNLTL6WdPk1Hlff7/lli4HvdxW1DNkVT8+WdIB4N7ea9USqXRcA79Gvnn0h6buVW
         bbFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzt3zd5J0YxSEyEkBhR2i9VZkilZtz+/04Yicv25koteFZbD9Si8HjuWRYAqOQX9feonI9yhQluuBSBkZYs7NtwqedqoLzSw==
X-Gm-Message-State: AOJu0YwlECUDeyDBNqP5I/43z9fOqn0lCrkhrT/d9mGrtoIPJDKPHJYg
	vLTQJ2LOIvO0glKgyEi5BtY2gQ7helrkDQ24/7F6dhb9bT6lhYuX
X-Google-Smtp-Source: AGHT+IGbMvcu36wj1Z7f8pCfSODd3wivs0QGMbGgr7z6SvwC+Zgw355qJlWmYgC5Af58STKHAHY5nA==
X-Received: by 2002:a05:6a20:12c1:b0:1be:e53c:7fa2 with SMTP id adf61e73a8af0-1bef60fd05bmr12145379637.25.1719903929452;
        Tue, 02 Jul 2024 00:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd82:b0:2c9:5a8b:a1a3 with SMTP id
 98e67ed59e1d1-2c95a8bad25ls182109a91.1.-pod-prod-03-us; Tue, 02 Jul 2024
 00:05:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWWhrwc8KU4NIDnSgpGQ0Kd7+oFVALe9+vy5XHpLGxLdS24S3R7E930IoQE7ycZrLNRU3YmeUaTR6jOSERpdigZSYLHDBiGfZNWA==
X-Received: by 2002:a05:6a20:1593:b0:1bd:24f6:576 with SMTP id adf61e73a8af0-1bef61ed45emr11736054637.48.1719903926559;
        Tue, 02 Jul 2024 00:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719903926; cv=none;
        d=google.com; s=arc-20160816;
        b=ItU8wNyg3JmXg9y1JboSfuRhiR+3mg+WE4L+e0+MZWCwPXgxiAVpWlTK/im1gAiZnC
         RavXa79TGBB4AjsY2kq7ouqZW3ybq34ORAbISXplslKA/AkjVPis3ZcER0oBNpJg+R/p
         jsn3DiZDy3Ujrbb6Ox34KU4PLzRwl8+tW6L4w3RxNcjPV4wtrHK8DTi2GgtbQTlfbA2A
         Yp21mH3fZdgKLgZvSW5yNcNHzXYWTG42AKQOWwq1f3gdWqai7lyIkqn9NBAK4t2ANC3X
         Xqn8tnbsN4iKLmmpc177YYRfQdzPto2lAnfFTmB8PiBFBgVVHUyXqylNRJWspWwF1UAW
         BxTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id;
        bh=2O7S3CPHkKccchE+oHEsUVgFVu+p/JNDepLodXCAaa0=;
        fh=/X6ch4A1P7mqFjFzh04ZrXpxVqEtT2Yo7A5UxE4IwbE=;
        b=MvSGg5QzA+Ila9iI3AQruTON7fc7M8Fqtw8PzwFwMJN53HfjV2gq7LuxrUFgYMx+BF
         KqLp6xQaR7yT77mBPIubbSpUXUSqKjMaykICMPbqJSKeMqy/hr3yh0nxTOHtch36LS/Q
         ebaxAZyHrDiCdbm3YVwIrIaI4hZJttJgR5mskS5GhJC9ag2PWVE8Zon0redWSDTomUks
         sWnGaKOch46GXsi9vPSN0NzVdFAkRoVLBwguQvPUvzqOJqxwr9Hp9gg8+kTzEJKLCO/m
         OCsvv95Bm4R+EUAN2iN/I/fhrHz1FByfhySeMNs4RobN0oYZua9WlT3SuKmcQpEXUfBW
         QS+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c91c80277dsi370884a91.0.2024.07.02.00.05.26
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2024 00:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav111.sakura.ne.jp (fsav111.sakura.ne.jp [27.133.134.238])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 46275JJp069284;
	Tue, 2 Jul 2024 16:05:19 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav111.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp);
 Tue, 02 Jul 2024 16:05:19 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 46275JB6069281
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Tue, 2 Jul 2024 16:05:19 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <e045dcff-a6cd-4110-83e0-6fc2a56d0413@I-love.SAKURA.ne.jp>
Date: Tue, 2 Jul 2024 16:05:19 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs
 (2)
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
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
Content-Language: en-US
In-Reply-To: <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
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

On 2024/07/02 15:11, Tetsuo Handa wrote:
> Well, KASAN says "out-of-bounds". But the reported address
> 
>   BUG: KASAN: stack-out-of-bounds in __show_regs+0x172/0x610
>   Read of size 8 at addr ffffc90003c4f798 by task kworker/u8:5/234
> 
> is within the kernel stack memory mapping
> 
>   The buggy address belongs to the virtual mapping at
>    [ffffc90003c48000, ffffc90003c51000) created by:
>    copy_process+0x5d1/0x3d7
> 
> . Why is this "out-of-bounds" ? What boundary did KASAN compare with?

I think I found a hint. The KASAN message is printed when the call trace
starts with

  __schedule()
  preempt_schedule_irq()
  irqentry_exit()

. That is, when preemption happens, KASAN by error tries to compare with
unintended stack boundary?

[  504.507489][    C0] DEBUG: holding rtnl_mutex for 3212 jiffies.
[  504.513708][    C0] task:kworker/u8:5    state:R  running task     stack:19992 pid:340   tgid:340   ppid:2      flags:0x00004000
[  504.525827][    C0] Workqueue: netns cleanup_net
[  504.530890][    C0] Call Trace:
[  504.534213][    C0]  <TASK>
[  504.537244][    C0]  __schedule+0x17e8/0x4a20
[  504.541874][    C0]  ? mark_lock+0x9a/0x360
[  504.546279][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  504.552396][    C0]  ? __virt_addr_valid+0x183/0x520
[  504.557711][    C0]  ? __pfx_lockdep_hardirqs_on_prepare+0x10/0x10
[  504.564121][    C0]  ? lock_release+0xbf/0x9f0
[  504.568918][    C0]  ? __pfx___schedule+0x10/0x10
[  504.573835][    C0]  ? lockdep_hardirqs_on+0x99/0x150
[  504.579189][    C0]  ? mark_lock+0x9a/0x360
[  504.583592][    C0]  preempt_schedule_irq+0xfb/0x1c0
[  504.588984][    C0]  ? __pfx_preempt_schedule_irq+0x10/0x10
[  504.594785][    C0]  irqentry_exit+0x5e/0x90
[  504.599421][    C0]  asm_sysvec_reschedule_ipi+0x1a/0x20

[  463.514954][    C1] DEBUG: holding rtnl_mutex for 993 jiffies.
[  463.528845][    C1] task:kworker/u8:10   state:R  running task     stack:19856 pid:5725  tgid:5725  ppid:2      flags:0x00004000
[  463.536743][ T9938] rock: corrupted directory entry. extent=41, offset=65536, size=8
[  463.540652][    C1] Workqueue: netns cleanup_net
[  463.553421][    C1] Call Trace:
[  463.556740][    C1]  <TASK>
[  463.559706][    C1]  __schedule+0x17e8/0x4a20
[  463.564304][    C1]  ? __pfx_validate_chain+0x10/0x10
[  463.569611][    C1]  ? __pfx___schedule+0x10/0x10
[  463.574628][    C1]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  463.580760][    C1]  ? preempt_schedule_irq+0xf0/0x1c0
[  463.586149][    C1]  preempt_schedule_irq+0xfb/0x1c0
[  463.591401][    C1]  ? __pfx_preempt_schedule_irq+0x10/0x10
[  463.597269][    C1]  irqentry_exit+0x5e/0x90
[  463.601834][    C1]  asm_sysvec_apic_timer_interrupt+0x1a/0x20

[ 1558.178669][    C1] DEBUG: holding rtnl_mutex for 536 jiffies.
[ 1558.184806][    C1] task:syz-executor.3  state:R  running task     stack:25968 pid:6351  tgid:6345  ppid:6200   flags:0x00004006
[ 1558.196699][    C1] Call Trace:
[ 1558.200068][    C1]  <TASK>
[ 1558.203055][    C1]  __schedule+0x17e8/0x4a20
[ 1558.207638][    C1]  ? __pfx___schedule+0x10/0x10
[ 1558.212585][    C1]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[ 1558.218675][    C1]  ? preempt_schedule_irq+0xf0/0x1c0
[ 1558.224004][    C1]  preempt_schedule_irq+0xfb/0x1c0
[ 1558.229196][    C1]  ? __pfx_preempt_schedule_irq+0x10/0x10
[ 1558.234986][    C1]  irqentry_exit+0x5e/0x90
[ 1558.239503][    C1]  asm_sysvec_reschedule_ipi+0x1a/0x20

[ 1104.439430][    C0] DEBUG: holding rtnl_mutex for 578 jiffies.
[ 1104.445729][    C0] task:kworker/u8:3    state:R  running task     stack:18544 pid:53    tgid:53    ppid:2      flags:0x00004000
[ 1104.459070][    C0] Workqueue: netns cleanup_net
[ 1104.464170][    C0] Call Trace:
[ 1104.467478][    C0]  <TASK>
[ 1104.470481][    C0]  __schedule+0x17e8/0x4a20
[ 1104.476080][    C0]  ? mark_lock+0x9a/0x360
[ 1104.480776][    C0]  ? __lock_acquire+0x1359/0x2000
[ 1104.486043][    C0]  ? __pfx___schedule+0x10/0x10
[ 1104.490987][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[ 1104.497017][    C0]  ? preempt_schedule_irq+0xf0/0x1c0
[ 1104.502486][    C0]  preempt_schedule_irq+0xfb/0x1c0
[ 1104.507809][    C0]  ? __pfx_preempt_schedule_irq+0x10/0x10
[ 1104.514030][    C0]  irqentry_exit+0x5e/0x90
[ 1104.518689][    C0]  asm_sysvec_reschedule_ipi+0x1a/0x20

[  926.207053][    C1] DEBUG: holding rtnl_mutex for 517 jiffies.
[  926.213142][    C1] task:syz.1.1365      state:R  running task     stack:24672 pid:11152 tgid:11152 ppid:10992  flags:0x00004006
[  926.225053][    C1] Call Trace:
[  926.228434][    C1]  <TASK>
[  926.231441][    C1]  __schedule+0x17e8/0x4a20
[  926.236054][    C1]  ? __pfx___schedule+0x10/0x10
[  926.241130][    C1]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  926.247265][    C1]  ? kasan_save_track+0x51/0x80
[  926.252225][    C1]  ? preempt_schedule_irq+0xf0/0x1c0
[  926.257705][    C1]  preempt_schedule_irq+0xfb/0x1c0
[  926.262899][    C1]  ? __pfx_preempt_schedule_irq+0x10/0x10
[  926.268725][    C1]  ? __pfx_pfifo_fast_destroy+0x10/0x10
[  926.274379][    C1]  irqentry_exit+0x5e/0x90
[  926.278903][    C1]  asm_sysvec_apic_timer_interrupt+0x1a/0x20

[  940.917894][    C0] DEBUG: holding rtnl_mutex for 1611 jiffies.
[  940.924066][    C0] task:syz.2.2274      state:R  running task     stack:24336 pid:15954 tgid:15954 ppid:14850  flags:0x00004006
[  940.936192][    C0] Call Trace:
[  940.939550][    C0]  <TASK>
[  940.942540][    C0]  __schedule+0x17e8/0x4a20
[  940.947134][    C0]  ? __pfx___schedule+0x10/0x10
[  940.952070][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  940.958362][    C0]  ? kasan_save_track+0x51/0x80
[  940.963266][    C0]  ? preempt_schedule_irq+0xf0/0x1c0
[  940.968628][    C0]  preempt_schedule_irq+0xfb/0x1c0
[  940.973790][    C0]  ? __pfx_preempt_schedule_irq+0x10/0x10
[  940.979610][    C0]  ? __pfx_pfifo_fast_destroy+0x10/0x10
[  940.985227][    C0]  irqentry_exit+0x5e/0x90
[  940.989731][    C0]  asm_sysvec_apic_timer_interrupt+0x1a/0x20

[ 2120.744289][    C1] DEBUG: holding rtnl_mutex for 1675 jiffies.
[ 2120.750440][    C1] task:syz-executor    state:R  running task     stack:20288 pid:2431  tgid:2431  ppid:1      flags:0x00004006
[ 2120.762291][    C1] Call Trace:
[ 2120.765647][    C1]  <TASK>
[ 2120.768615][    C1]  __schedule+0x17e8/0x4a20
[ 2120.773210][    C1]  ? __pfx___schedule+0x10/0x10
[ 2120.778152][    C1]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[ 2120.784188][    C1]  ? kasan_save_track+0x51/0x80
[ 2120.789118][    C1]  ? preempt_schedule_irq+0xf0/0x1c0
[ 2120.794445][    C1]  preempt_schedule_irq+0xfb/0x1c0
[ 2120.799621][    C1]  ? __pfx_preempt_schedule_irq+0x10/0x10
[ 2120.805378][    C1]  ? kvm_kick_cpu+0x26/0xb0
[ 2120.809965][    C1]  irqentry_exit+0x5e/0x90
[ 2120.814423][    C1]  asm_sysvec_apic_timer_interrupt+0x1a/0x20

[ 1465.514982][    C1] DEBUG: holding rtnl_mutex for 583 jiffies.
[ 1465.521071][    C1] task:kworker/u8:2    state:R  running task     stack:20232 pid:35    tgid:35    ppid:2      flags:0x00004000
[ 1465.532945][    C1] Workqueue: netns cleanup_net
[ 1465.537846][    C1] Call Trace:
[ 1465.541164][    C1]  <TASK>
[ 1465.544132][    C1]  __schedule+0x17e8/0x4a20
[ 1465.548730][    C1]  ? mark_lock+0x9a/0x360
[ 1465.553148][    C1]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[ 1465.559257][    C1]  ? __pfx_lockdep_hardirqs_on_prepare+0x10/0x10
[ 1465.565697][    C1]  ? __pfx___schedule+0x10/0x10
[ 1465.570636][    C1]  ? lockdep_hardirqs_on+0x99/0x150
[ 1465.575968][    C1]  ? mark_lock+0x9a/0x360
[ 1465.580381][    C1]  preempt_schedule_irq+0xfb/0x1c0
[ 1465.585599][    C1]  ? __pfx_preempt_schedule_irq+0x10/0x10
[ 1465.591383][    C1]  irqentry_exit+0x5e/0x90
[ 1465.595895][    C1]  asm_sysvec_reschedule_ipi+0x1a/0x20

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e045dcff-a6cd-4110-83e0-6fc2a56d0413%40I-love.SAKURA.ne.jp.
