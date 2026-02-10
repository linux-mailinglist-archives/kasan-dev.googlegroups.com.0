Return-Path: <kasan-dev+bncBD3JJNUUIQIPZF5MZQDBUBALWMMOO@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IFFmI/8Li2lXPQAAu9opvQ
	(envelope-from <kasan-dev+bncBD3JJNUUIQIPZF5MZQDBUBALWMMOO@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 11:44:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 09ADA119C08
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 11:44:15 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-8c71500f274sf74668085a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 02:44:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770720253; cv=pass;
        d=google.com; s=arc-20240605;
        b=flpE6/cOYOtW+iP4yblYVLOzdbgI0QccDqSOqZN+lCEFz7D8wzeLYpmUcJreME/F5B
         7XwxEFmxjVF9LV8fMpJ0fe1eh9em6Y6RSAOfGUGY1NL1AmSC2DaVmZu/tgV8t6Csw9L0
         Ux2MRzMp4EaszsS+ad2G1kqZSw3tm1RNrgcAkl0gSxtTmJouRZE2R4Dd+LrlO8JOtEsT
         i8KijThtOiZCILRB5wvleB79BvTJy/OuvvZMyIXH+9zKuY9rfljh0YYIFW4XLnQ1vrJ1
         N7z+/UZFHZMof4eJgooOSYiPdgSjzmRvTChW8YOlXPQw35O1hn5CaGNfBKWQVNR5AXwE
         29Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=5Tz3Gy2T6rzDH48jkeZbuikHVTV+ol1HPsVKcJBcAD4=;
        fh=KhGOcr3Cif/cfsgkvpI896oodCZCUMaqDgoeiQevE74=;
        b=av5GPAcJSpFjqxheA4OwYdLPls5ZGMJQHHxtQGwoyAAy6b1IZaFKmio517TWBama/R
         wJ7+j7ZORF2guiU9UKJx+OYozbI/gOAVxWXc1rkWDBeYgt3WNR+2jHYmzrK8Xh2l7hL0
         N4SX1FpDV9azgHxXiMDSZAW56rGNCEoKy6r+jjffXXM3IYotff3UVqmgwHA3tqgZUV9/
         6xe4vIHXC3uCJwAachUMJBoWC8HjvsbxT/YAidYvrGq/2W4YZKJ55XEkL8lJtiqYHAfE
         YakCAJI91h+jGsSw5rQEvMj+EjTQkYVhLcbioPQHe8hGoV3DQw10tTJxQ8r9ZVfmtFEV
         cwgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SLbSW3yd;
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770720253; x=1771325053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5Tz3Gy2T6rzDH48jkeZbuikHVTV+ol1HPsVKcJBcAD4=;
        b=WhG//EXE1cQVYV9PqnB31wUn6ogRQLNRAV3NIa4AxaX+6h52uFV5rPscMglbErcjXe
         FYf1mU+DuRJZicKeWX5s/sfze0VvnHymLzbP5E+phnjOl2iLhiRYd7WgrkCZIFkZ/RE4
         pkeyoD5LW8fPumUlPbLt88H6SyijfibKLRrryL6LflFKnjoQfvCvclV0WnQUx/1RtY0y
         wireFWrCaqRxUJ7vXFcuHenS73TMmsiKaZ72w46fkyG4H7JAAqAV3vcTAP8K4wFlPJBJ
         KPKf6s6k/Dk/MDjTia6Qq2rZDPeSyo8C8wsytBeY1ZCqzpia1FZBMVpJo2hhYJvXbJGq
         Br0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770720253; x=1771325053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Tz3Gy2T6rzDH48jkeZbuikHVTV+ol1HPsVKcJBcAD4=;
        b=JYuh3DTDfIPiH6R0td17YmE5n8Ptq9u4o1RqnU644HM2x5PpCS0YiE1KBWfKisc0w4
         hNy5ozsZ56DDVxg7tr/ALfa41kmao4FZC6yBwjdIJHy0ExUjZ5wTcqPfiqdrrItf46LS
         0RERCHnIq/QQsJ0vYSVp0bjZY6k6qxVfe4Z8sy3Unut+JQU3hpkK+CXR3ZzQwaq8APBr
         0xvwPEsDw5NZRSaSvCh2s4GR2IaeffS7veJ4NJ74D/lpe5niAy8Y0dpWSVJ3Iws3KJum
         p0ntnXHBjfI4aNLOFyR0ZcuR5X5NGWF7KyXvEr9PV5BCD7au5LwRsyYWzxH4QLfTaEtq
         kfQw==
X-Forwarded-Encrypted: i=2; AJvYcCVoE1JKkcarvAfm+EVvgKtvl0t4vJs6PWNrYsUBbpby05xfRTPBievq4QlGvpWqFIgv2T8u1w==@lfdr.de
X-Gm-Message-State: AOJu0YyNebWdOHRRXoyvLvazB52oDy1yBCInBz4f/cb4HJerhbCKjXkn
	jTXzRbiv3eYifi/gz8XqmHHLum6bPlk1BuweMdswRJAce93kGuxI1uk9
X-Received: by 2002:a05:622a:134c:b0:501:1466:8419 with SMTP id d75a77b69052e-5063990fa5bmr198149331cf.29.1770720253219;
        Tue, 10 Feb 2026 02:44:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G52V+gClhQs2gStQjhwUjnh3OjD1naBScrZF2MkrT5kA=="
Received: by 2002:ac8:5ac2:0:b0:505:e7a5:2c02 with SMTP id d75a77b69052e-5062aaefb8fls85885031cf.2.-pod-prod-08-us;
 Tue, 10 Feb 2026 02:44:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMYJ8VUgsnZPwvWXEzf7JIEcj+Ocd8loxphrqB8MbR5dCnqJkujNYcJ/FqTWNTEunSos1fKWiYgEA=@googlegroups.com
X-Received: by 2002:a05:620a:440a:b0:892:7dd2:9f0f with SMTP id af79cd13be357-8caef02764amr1825009885a.19.1770720252073;
        Tue, 10 Feb 2026 02:44:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770720252; cv=none;
        d=google.com; s=arc-20240605;
        b=E2LxLTmdHnHQvlUPVUMk8bTfJeXgM7yjxuhKPF/tJlc4/M9Bpeec1zrI9dxQz8fSDo
         F3UWIPqmyfN4TNxuEgfFzYMXNWQlOJnawjfC+GnFDT+PeJ9ClR6GQuAXQLb7H0XvBhaP
         63D5uWb9ibewLKqGAucbijUgN7XJfaV1L7qG4tkGxTE6w25tHi5TtBeh9QMbtZKscmUV
         1yv4665XiRb0/c3ShldmlL74bir/gJDM9iPvLqxyqu6QgWD1Ck0BHKZJBGlhnczMLy1Q
         FsVxtju7eQZ2V73LIM8utYiiOUAFlnhzSncYVMAqvOqTpH4SFeSE4lOSxpAmKah+lLN8
         U8JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=QdO/3uBjaPfslhm4kUXZOUuuRThqPt/JFB13b+6U0Y4=;
        fh=g89W8E+cxgeG/MPJ7mSG8vl7ltdoaX2IyWy0jQrvOSs=;
        b=UdQ/DbCM16NoX+pmxwprF3ypnOPJP1ZYlAKKg++D+neVfKvHs/uxCrqVwdN5Q/2TzY
         ew5zW4QoDbt2zpWIREjE2+V/xfqUllCjQyc4fKzcn9+zE/l1W2uA6qPmOF/KOOS/RsZs
         wbdDvrtrMW/0+ToStbXRWX6p1vpYF4qWVWr4XOC/kucL7PI09Hr9ofyzOF4jvQPYZZR1
         CR5R00wt5FxvUF0UrPfW1KViDld9XQKJJkB+bQIBTbPMg/kgy4sNElH9vRHAIhrT6fEo
         DuZtcZuCD43oXEAAIAOR+LGExZsh6iREaW8FeEBwXqRDRTewDUryKzMWjBMWFQPZKCHG
         srSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SLbSW3yd;
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8cb07f173e8si36766985a.5.2026.02.10.02.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Feb 2026 02:44:12 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7501160136;
	Tue, 10 Feb 2026 10:44:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 946C9C16AAE;
	Tue, 10 Feb 2026 10:44:10 +0000 (UTC)
From: "'Thomas Gleixner' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Ihor Solodrai
 <ihor.solodrai@linux.dev>, Shrikanth Hegde <sshegde@linux.ibm.com>, Peter
 Zijlstra <peterz@infradead.org>, Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>, Michael Jeanson <mjeanson@efficios.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, kasan-dev@googlegroups.com
Subject: Re: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
In-Reply-To: <aYrewLd7QNiPUJT1@shinmob>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
Date: Tue, 10 Feb 2026 11:44:07 +0100
Message-ID: <873438c1zc.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SLbSW3yd;       spf=pass
 (google.com: domain of tglx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=tglx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Thomas Gleixner <tglx@kernel.org>
Reply-To: Thomas Gleixner <tglx@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBD3JJNUUIQIPZF5MZQDBUBALWMMOO];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	HAS_REPLYTO(0.00)[tglx@kernel.org];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-qk1-x739.google.com:helo,mail-qk1-x739.google.com:rdns]
X-Rspamd-Queue-Id: 09ADA119C08
X-Rspamd-Action: no action

On Tue, Feb 10 2026 at 07:33, Shinichiro Kawasaki wrote:
> On Feb 02, 2026 / 10:39, Thomas Gleixner wrote:
>> When a exiting task initiates the switch from per CPU back to per task
>> mode, it has already dropped its CID and marked itself inactive. But a
>> leftover from an earlier iteration of the rework then reassigns the per
>> CPU CID to the exiting task with the transition bit set.
>> 
>> That's wrong as the task is already marked CID inactive, which means it is
>> inconsistent state. It's harmless because the CID is marked in transit and
>> therefore dropped back into the pool when the exiting task schedules out
>> either through preemption or the final schedule().
>> 
>> Simply drop the per CPU CID when the exiting task triggered the transition.
>> 
>> Fixes: fbd0e71dc370 ("sched/mmcid: Provide CID ownership mode fixup functions")
>> Signed-off-by: Thomas Gleixner <tglx@kernel.org>
>> Reviewed-by: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
>
> Hello all,
>
> While I evaluated v6.19 kernel, I observed a BUG KASAN. The KASAN is recreated
> in stable manner by running the test case zbd/013 of blktests [1] on some of my
> test systems. I bisected and found that this patch as the commit 007d84287c74
> triggered the KASAN. When I reverted this patch from v6.19 kernel, the KASAN
> disappeared. Of note is that the KASAN symptom slightly varies for each run. I
> observed KASAN slab-use-after-free [2], use-after-free [3] and slab-out-of-
> bounds [4]. All those KASANs happened "in sched_mm_cid_exit".

And none of them make any sense. The patch does:

 -				mm_cid_transit_to_task(current, this_cpu_ptr(mm->mm_cid.pcpu));
 +				mm_drop_cid_on_cpu(mm, this_cpu_ptr(mm->mm_cid.pcpu));

Both access mm->mm_cid and mm->mm_cid.pcpu. mm is valid at that point as
this is way before the task disconnects from the mm.

The new code also accesses the CID bitmap which is at the end of
mm_struct. But the subsequent mm_cid_fixup_cpus_to_tasks(mm) touches all
of those too. So none of this makes any sense at all.

> [   65.768341] [   T1296] BUG: KASAN: slab-use-after-free in sched_mm_cid_exit+0x298/0x500

Can you please decode these symbols (file/line) so that we actually see
which access is flagged by KASAN?

Also .config and compiler version would be helpful.

Keeping the splats below for the KASAN folks to digest.

Thanks,

        tglx

> Actions for fix will be appreciated. If I can help by trying trial some patches
> on my test systems, please let me know.
>
> [1] https://github.com/linux-blktests/blktests
>
> [2] KASAN slab-use-after-free
>
> [   64.540760] [   T1234] run blktests zbd/013 at 2026-02-10 11:06:48
> [   64.638773] [   T1252] null_blk: disk nullb1 created
> [   64.749061] [   T1252] null_blk: nullb2: using native zone append
> [   64.764569] [   T1252] null_blk: disk nullb2 created
> [   65.767294] [   T1296] ==================================================================
> [   65.768341] [   T1296] BUG: KASAN: slab-use-after-free in sched_mm_cid_exit+0x298/0x500
> [   65.769378] [   T1296] Write of size 8 at addr ffff888149792410 by task cryptsetup/1296
>
> [   65.770700] [   T1296] CPU: 1 UID: 0 PID: 1296 Comm: cryptsetup Not tainted 6.19.0 #571 PREEMPT(voluntary) 
> [   65.770705] [   T1296] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-4.fc42 04/01/2014
> [   65.770709] [   T1296] Call Trace:
> [   65.770711] [   T1296]  <TASK>
> [   65.770713] [   T1296]  dump_stack_lvl+0x6a/0x90
> [   65.770718] [   T1296]  ? sched_mm_cid_exit+0x298/0x500
> [   65.770721] [   T1296]  print_report+0x170/0x4f3
> [   65.770725] [   T1296]  ? __virt_addr_valid+0x22e/0x4e0
> [   65.770729] [   T1296]  ? sched_mm_cid_exit+0x298/0x500
> [   65.770732] [   T1296]  kasan_report+0xad/0x150
> [   65.770737] [   T1296]  ? sched_mm_cid_exit+0x298/0x500
> [   65.770742] [   T1296]  kasan_check_range+0x115/0x1f0
> [   65.770745] [   T1296]  sched_mm_cid_exit+0x298/0x500
> [   65.770750] [   T1296]  do_exit+0x25e/0x24c0
> [   65.770755] [   T1296]  ? __pfx_do_exit+0x10/0x10
> [   65.770758] [   T1296]  ? lockdep_hardirqs_on+0x88/0x130
> [   65.770761] [   T1296]  ? entry_SYSCALL_64_after_hwframe+0x76/0x7e
> [   65.770764] [   T1296]  ? do_syscall_64+0x1d7/0x540
> [   65.770766] [   T1296]  ? do_raw_spin_lock+0x124/0x260
> [   65.770769] [   T1296]  ? lock_acquire+0x180/0x300
> [   65.770771] [   T1296]  ? find_held_lock+0x2b/0x80
> [   65.770775] [   T1296]  __x64_sys_exit+0x3e/0x50
> [   65.770780] [   T1296]  x64_sys_call+0x14fe/0x1500
> [   65.770784] [   T1296]  do_syscall_64+0x95/0x540
> [   65.770787] [   T1296]  ? lockdep_hardirqs_on+0x88/0x130
> [   65.770790] [   T1296]  ? _raw_spin_unlock_irq+0x24/0x50
> [   65.770792] [   T1296]  ? _raw_spin_unlock_irq+0x34/0x50
> [   65.770795] [   T1296]  ? __x64_sys_rt_sigprocmask+0x23d/0x400
> [   65.770798] [   T1296]  ? __pfx___x64_sys_rt_sigprocmask+0x10/0x10
> [   65.770800] [   T1296]  ? rcu_nocb_unlock_irqrestore+0x87/0xb0
> [   65.770804] [   T1296]  ? rcu_do_batch+0x867/0xd90
> [   65.770809] [   T1296]  ? lockdep_hardirqs_on+0x88/0x130
> [   65.770811] [   T1296]  ? entry_SYSCALL_64_after_hwframe+0x76/0x7e
> [   65.770813] [   T1296]  ? do_syscall_64+0x1d7/0x540
> [   65.770816] [   T1296]  ? __pfx_sched_clock_cpu+0x10/0x10
> [   65.770819] [   T1296]  ? lock_is_held_type+0xd5/0x140
> [   65.770824] [   T1296]  ? irqtime_account_irq+0xe4/0x330
> [   65.770827] [   T1296]  ? lockdep_softirqs_on+0xc3/0x140
> [   65.770829] [   T1296]  ? __irq_exit_rcu+0x126/0x240
> [   65.770832] [   T1296]  ? handle_softirqs+0x6c5/0x790
> [   65.770836] [   T1296]  ? __pfx_handle_softirqs+0x10/0x10
> [   65.770839] [   T1296]  ? irqtime_account_irq+0x1a2/0x330
> [   65.770842] [   T1296]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
> [   65.770844] [   T1296]  ? irqentry_exit+0xe2/0x6a0
> [   65.770848] [   T1296]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
> [   65.770850] [   T1296] RIP: 0033:0x7f96978fef89
> [   65.770854] [   T1296] Code: ff 31 c9 48 89 88 20 06 00 00 31 c0 87 07 83 e8 01 7f 19 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 31 ff b8 3c 00 00 00 0f 05 <eb> f5 89 95 74 ff ff ff e8 9a d0 ff ff 83 bd 74 ff ff ff 01 0f 85
> [   65.770856] [   T1296] RSP: 002b:00007f9691de0d30 EFLAGS: 00000246 ORIG_RAX: 000000000000003c
> [   65.770861] [   T1296] RAX: ffffffffffffffda RBX: 00007f9691de16c0 RCX: 00007f96978fef89
> [   65.770863] [   T1296] RDX: 0000000000000000 RSI: 0000000000800000 RDI: 0000000000000000
> [   65.770865] [   T1296] RBP: 00007f9691de0df0 R08: 0000000015fc5864 R09: 0000000000000000
> [   65.770866] [   T1296] R10: 0000000000000008 R11: 0000000000000246 R12: 00007f9691de16c0
> [   65.770867] [   T1296] R13: 00007fff8d18af10 R14: 00007f9691de1cdc R15: 00007fff8d18b017
> [   65.770875] [   T1296]  </TASK>
>
> [   65.805902] [   T1296] Allocated by task 668:
> [   65.806662] [   T1296]  kasan_save_stack+0x2c/0x50
> [   65.807400] [   T1296]  kasan_save_track+0x10/0x30
> [   65.808130] [   T1296]  __kasan_slab_alloc+0x7a/0x90
> [   65.808842] [   T1296]  kmem_cache_alloc_noprof+0x238/0x7a0
> [   65.809569] [   T1296]  getname_flags.part.0+0x48/0x4d0
> [   65.810280] [   T1296]  do_sys_openat2+0xa8/0x180
> [   65.810972] [   T1296]  __x64_sys_openat+0x10a/0x200
> [   65.811637] [   T1296]  do_syscall_64+0x95/0x540
> [   65.812267] [   T1296]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
>
> [   65.813538] [   T1296] Freed by task 668:
> [   65.814189] [   T1296]  kasan_save_stack+0x2c/0x50
> [   65.814884] [   T1296]  kasan_save_track+0x10/0x30
> [   65.815545] [   T1296]  kasan_save_free_info+0x37/0x70
> [   65.816318] [   T1296]  __kasan_slab_free+0x67/0x80
> [   65.817002] [   T1296]  kmem_cache_free+0x1ae/0x6d0
> [   65.817700] [   T1296]  audit_reset_context+0x3c7/0xeb0
> [   65.818401] [   T1296]  syscall_exit_work+0x17f/0x1b0
> [   65.819124] [   T1296]  do_syscall_64+0x2fe/0x540
> [   65.819812] [   T1296]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
>
> [   65.821100] [   T1296] The buggy address belongs to the object at ffff888149792200
>                            which belongs to the cache names_cache of size 4096
> [   65.822824] [   T1296] The buggy address is located 528 bytes inside of
>                            freed 4096-byte region [ffff888149792200, ffff888149793200)
>
> [   65.825027] [   T1296] The buggy address belongs to the physical page:
> [   65.825856] [   T1296] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x149790
> [   65.826846] [   T1296] head: order:3 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
> [   65.827840] [   T1296] flags: 0x17ffffc0000040(head|node=0|zone=2|lastcpupid=0x1fffff)
> [   65.828768] [   T1296] page_type: f5(slab)
> [   65.829405] [   T1296] raw: 0017ffffc0000040 ffff888100902b40 ffffea0005314600 dead000000000002
> [   65.830402] [   T1296] raw: 0000000000000000 0000000000070007 00000000f5000000 0000000000000000
> [   65.831493] [   T1296] head: 0017ffffc0000040 ffff888100902b40 ffffea0005314600 dead000000000002
> [   65.832644] [   T1296] head: 0000000000000000 0000000000070007 00000000f5000000 0000000000000000
> [   65.833723] [   T1296] head: 0017ffffc0000003 ffffea000525e401 00000000ffffffff 00000000ffffffff
> [   65.834798] [   T1296] head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000000000008
> [   65.835827] [   T1296] page dumped because: kasan: bad access detected
>
> [   65.837253] [   T1296] Memory state around the buggy address:
> [   65.838039] [   T1296]  ffff888149792300: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [   65.838991] [   T1296]  ffff888149792380: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [   65.839939] [   T1296] >ffff888149792400: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [   65.840894] [   T1296]                          ^
> [   65.841569] [   T1296]  ffff888149792480: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [   65.842554] [   T1296]  ffff888149792500: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> [   65.843504] [   T1296] ==================================================================
> [   65.844500] [   T1296] Disabling lock debugging due to kernel taint
> [   71.925834] [   T1650] device-mapper: zone: dm-0 using emulated zone append
> [   72.474170] [      C1] hrtimer: interrupt took 1119829 ns
>
> [3] KASAN use-after-free
>
> [  145.885127] [   T1246] run blktests zbd/013 at 2026-02-10 10:57:04
> [  145.985394] [   T1264] null_blk: disk nullb1 created
> [  146.091908] [   T1264] null_blk: nullb2: using native zone append
> [  146.106425] [   T1264] null_blk: disk nullb2 created
> [  147.822863] [   T1479] ==================================================================
> [  147.823592] [   T1479] BUG: KASAN: use-after-free in sched_mm_cid_exit+0x298/0x500
> [  147.824479] [   T1479] Write of size 8 at addr ffff8881185cb050 by task cryptsetup/1479
>
> [  147.825468] [   T1479] CPU: 2 UID: 0 PID: 1479 Comm: cryptsetup Not tainted 6.19.0 #571 PREEMPT(voluntary) 
> [  147.825472] [   T1479] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-4.fc42 04/01/2014
> [  147.825476] [   T1479] Call Trace:
> [  147.825478] [   T1479]  <TASK>
> [  147.825480] [   T1479]  dump_stack_lvl+0x6a/0x90
> [  147.825484] [   T1479]  ? sched_mm_cid_exit+0x298/0x500
> [  147.825487] [   T1479]  print_report+0x170/0x4f3
> [  147.825490] [   T1479]  ? __virt_addr_valid+0x22e/0x4e0
> [  147.825494] [   T1479]  ? sched_mm_cid_exit+0x298/0x500
> [  147.825496] [   T1479]  kasan_report+0xad/0x150
> [  147.825500] [   T1479]  ? sched_mm_cid_exit+0x298/0x500
> [  147.825504] [   T1479]  kasan_check_range+0x115/0x1f0
> [  147.825507] [   T1479]  sched_mm_cid_exit+0x298/0x500
> [  147.825510] [   T1479]  do_exit+0x25e/0x24c0
> [  147.825514] [   T1479]  ? lockdep_hardirqs_on+0x88/0x130
> [  147.825517] [   T1479]  ? __pfx_do_exit+0x10/0x10
> [  147.825520] [   T1479]  ? irqtime_account_irq+0xe4/0x330
> [  147.825524] [   T1479]  __x64_sys_exit+0x3e/0x50
> [  147.825526] [   T1479]  x64_sys_call+0x14fe/0x1500
> [  147.825529] [   T1479]  do_syscall_64+0x95/0x540
> [  147.825531] [   T1479]  ? __pfx_handle_softirqs+0x10/0x10
> [  147.825534] [   T1479]  ? irqtime_account_irq+0x1a2/0x330
> [  147.825536] [   T1479]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
> [  147.825539] [   T1479]  ? irqentry_exit+0xe2/0x6a0
> [  147.825542] [   T1479]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
> [  147.825544] [   T1479] RIP: 0033:0x7f505e211f89
> [  147.825547] [   T1479] Code: ff 31 c9 48 89 88 20 06 00 00 31 c0 87 07 83 e8 01 7f 19 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 31 ff b8 3c 00 00 00 0f 05 <eb> f5 89 95 74 ff ff ff e8 9a d0 ff ff 83 bd 74 ff ff ff 01 0f 85
> [  147.825549] [   T1479] RSP: 002b:00007f50585fbd30 EFLAGS: 00000246 ORIG_RAX: 000000000000003c
> [  147.825553] [   T1479] RAX: ffffffffffffffda RBX: 00007f50585fc6c0 RCX: 00007f505e211f89
> [  147.825555] [   T1479] RDX: 0000000000000000 RSI: 0000000000800000 RDI: 0000000000000000
> [  147.825556] [   T1479] RBP: 00007f50585fbdf0 R08: 00005566eb14ea20 R09: 00005566eb14ea38
> [  147.825558] [   T1479] R10: 0000000000000008 R11: 0000000000000246 R12: 00007f50585fc6c0
> [  147.825559] [   T1479] R13: 00007fff4289e220 R14: 00007f50585fccdc R15: 00007fff4289e327
> [  147.825564] [   T1479]  </TASK>
>
> [  147.844213] [   T1479] The buggy address belongs to the physical page:
> [  147.845137] [   T1479] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x10 pfn:0x1185cb
> [  147.846323] [   T1479] flags: 0x17ffffc0000000(node=0|zone=2|lastcpupid=0x1fffff)
> [  147.847389] [   T1479] raw: 0017ffffc0000000 dead000000000100 dead000000000122 0000000000000000
> [  147.848662] [   T1479] raw: 0000000000000010 0000000000000000 00000000ffffffff 0000000000000000
> [  147.849887] [   T1479] page dumped because: kasan: bad access detected
>
> [  147.851495] [   T1479] Memory state around the buggy address:
> [  147.852479] [   T1479]  ffff8881185caf00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> [  147.853600] [   T1479]  ffff8881185caf80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> [  147.854690] [   T1479] >ffff8881185cb000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> [  147.855852] [   T1479]                                                  ^
> [  147.856798] [   T1479]  ffff8881185cb080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> [  147.857855] [   T1479]  ffff8881185cb100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> [  147.858857] [   T1479] ==================================================================
> [  147.859888] [   T1479] Disabling lock debugging due to kernel taint
> [  153.349607] [   T1982] device-mapper: zone: dm-0 using emulated zone append
> [  153.715923] [      C3] hrtimer: interrupt took 475570 ns
> [  282.408372] [   T3034] null_blk: disk nullb0 created
> [  282.409360] [   T3034] null_blk: module loaded
>
> [4] KASAN slab-out-of-bounds
>
> Feb 09 15:14:28 testnode2 unknown: run blktests zbd/013 at 2026-02-09 15:14:28
> Feb 09 15:14:28 testnode2 kernel: null_blk: disk nullb1 created
> Feb 09 15:14:28 testnode2 kernel: null_blk: nullb2: using native zone append
> Feb 09 15:14:28 testnode2 kernel: null_blk: disk nullb2 created
> Feb 09 15:14:29 testnode2 kernel: ==================================================================
> Feb 09 15:14:29 testnode2 kernel: BUG: KASAN: slab-out-of-bounds in sched_mm_cid_exit+0x298/0x500
> Feb 09 15:14:29 testnode2 kernel: Write of size 8 at addr ffff8881580db050 by task cryptsetup/136938
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: CPU: 3 UID: 0 PID: 136938 Comm: cryptsetup Not tainted 6.19.0 #571 PREEMPT(voluntary) 
> Feb 09 15:14:29 testnode2 kernel: Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-4.fc42 04/01/2014
> Feb 09 15:14:29 testnode2 kernel: Call Trace:
> Feb 09 15:14:29 testnode2 kernel:  <TASK>
> Feb 09 15:14:29 testnode2 kernel:  dump_stack_lvl+0x6a/0x90
> Feb 09 15:14:29 testnode2 kernel:  ? sched_mm_cid_exit+0x298/0x500
> Feb 09 15:14:29 testnode2 kernel:  print_report+0x170/0x4f3
> Feb 09 15:14:29 testnode2 kernel:  ? __virt_addr_valid+0x22e/0x4e0
> Feb 09 15:14:29 testnode2 kernel:  ? sched_mm_cid_exit+0x298/0x500
> Feb 09 15:14:29 testnode2 kernel:  kasan_report+0xad/0x150
> Feb 09 15:14:29 testnode2 kernel:  ? sched_mm_cid_exit+0x298/0x500
> Feb 09 15:14:29 testnode2 kernel:  kasan_check_range+0x115/0x1f0
> Feb 09 15:14:29 testnode2 kernel:  sched_mm_cid_exit+0x298/0x500
> Feb 09 15:14:29 testnode2 kernel:  do_exit+0x25e/0x24c0
> Feb 09 15:14:29 testnode2 kernel:  ? __pfx_do_exit+0x10/0x10
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  __x64_sys_exit+0x3e/0x50
> Feb 09 15:14:29 testnode2 kernel:  x64_sys_call+0x14fe/0x1500
> Feb 09 15:14:29 testnode2 kernel:  do_syscall_64+0x95/0x540
> Feb 09 15:14:29 testnode2 kernel:  ? sched_tick+0x330/0x960
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  ? trace_hardirqs_on_prepare+0xfd/0x130
> Feb 09 15:14:29 testnode2 kernel:  ? do_syscall_64+0x1d7/0x540
> Feb 09 15:14:29 testnode2 kernel:  ? do_futex+0x1bf/0x210
> Feb 09 15:14:29 testnode2 kernel:  ? __pfx_do_futex+0x10/0x10
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  ? profile_tick+0x18/0x90
> Feb 09 15:14:29 testnode2 kernel:  ? __x64_sys_futex+0x22f/0x4a0
> Feb 09 15:14:29 testnode2 kernel:  ? __pfx_do_raw_spin_lock+0x10/0x10
> Feb 09 15:14:29 testnode2 kernel:  ? lock_release+0x242/0x2f0
> Feb 09 15:14:29 testnode2 kernel:  ? __pfx___x64_sys_futex+0x10/0x10
> Feb 09 15:14:29 testnode2 kernel:  ? timerqueue_add+0x207/0x3c0
> Feb 09 15:14:29 testnode2 kernel:  ? enqueue_hrtimer+0x1f0/0x290
> Feb 09 15:14:29 testnode2 kernel:  ? sched_clock_cpu+0x65/0x5c0
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  ? trace_hardirqs_on_prepare+0xfd/0x130
> Feb 09 15:14:29 testnode2 kernel:  ? do_syscall_64+0x1d7/0x540
> Feb 09 15:14:29 testnode2 kernel:  ? lock_release+0x242/0x2f0
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  ? trace_hardirqs_on+0x14/0x140
> Feb 09 15:14:29 testnode2 kernel:  ? kvm_sched_clock_read+0xd/0x20
> Feb 09 15:14:29 testnode2 kernel:  ? sched_clock+0xc/0x30
> Feb 09 15:14:29 testnode2 kernel:  ? sched_clock_cpu+0x65/0x5c0
> Feb 09 15:14:29 testnode2 kernel:  ? irqtime_account_irq+0xe4/0x330
> Feb 09 15:14:29 testnode2 kernel:  ? kvm_sched_clock_read+0xd/0x20
> Feb 09 15:14:29 testnode2 kernel:  ? sched_clock+0xc/0x30
> Feb 09 15:14:29 testnode2 kernel:  ? sched_clock_cpu+0x65/0x5c0
> Feb 09 15:14:29 testnode2 kernel:  ? __pfx_sched_clock_cpu+0x10/0x10
> Feb 09 15:14:29 testnode2 kernel:  ? flush_tlb_func+0xb5/0x760
> Feb 09 15:14:29 testnode2 kernel:  ? irqtime_account_irq+0x1a2/0x330
> Feb 09 15:14:29 testnode2 kernel:  ? rcu_is_watching+0x11/0xb0
> Feb 09 15:14:29 testnode2 kernel:  ? trace_hardirqs_on_prepare+0xfd/0x130
> Feb 09 15:14:29 testnode2 kernel:  ? irqentry_exit+0xe2/0x6a0
> Feb 09 15:14:29 testnode2 kernel:  entry_SYSCALL_64_after_hwframe+0x76/0x7e
> Feb 09 15:14:29 testnode2 kernel: RIP: 0033:0x7fca4fbf5f89
> Feb 09 15:14:29 testnode2 kernel: Code: ff 31 c9 48 89 88 20 06 00 00 31 c0 87 07 83 e8 01 7f 19 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 31 ff b8 3c 00 00 00 0f 05 <eb> f5 89 95 74 ff ff ff e8 9a d0 ff ff 83 bd 74 ff ff ff 01 0f 85
> Feb 09 15:14:29 testnode2 kernel: RSP: 002b:00007fca497fad30 EFLAGS: 00000246 ORIG_RAX: 000000000000003c
> Feb 09 15:14:29 testnode2 kernel: RAX: ffffffffffffffda RBX: 00007fca497fb6c0 RCX: 00007fca4fbf5f89
> Feb 09 15:14:29 testnode2 kernel: RDX: 0000000000000000 RSI: 0000000000800000 RDI: 0000000000000000
> Feb 09 15:14:29 testnode2 kernel: RBP: 00007fca497fadf0 R08: 0000557abe711cb0 R09: 0000557abe711cc8
> Feb 09 15:14:29 testnode2 kernel: R10: 0000000000000008 R11: 0000000000000246 R12: 00007fca497fb6c0
> Feb 09 15:14:29 testnode2 kernel: R13: 00007ffc5119c9c0 R14: 00007fca497fbcdc R15: 00007ffc5119cac7
> Feb 09 15:14:29 testnode2 kernel:  </TASK>
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: Allocated by task 136663:
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_stack+0x2c/0x50
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_track+0x10/0x30
> Feb 09 15:14:29 testnode2 kernel:  __kasan_slab_alloc+0x7a/0x90
> Feb 09 15:14:29 testnode2 kernel:  kmem_cache_alloc_noprof+0x238/0x7a0
> Feb 09 15:14:29 testnode2 kernel:  mempool_alloc_noprof+0x150/0x250
> Feb 09 15:14:29 testnode2 kernel:  bio_alloc_bioset+0x1d7/0x720
> Feb 09 15:14:29 testnode2 kernel:  blkdev_direct_IO+0x3a7/0x1f40
> Feb 09 15:14:29 testnode2 kernel:  blkdev_write_iter+0x52b/0xba0
> Feb 09 15:14:29 testnode2 kernel:  aio_write+0x33a/0x7c0
> Feb 09 15:14:29 testnode2 kernel:  io_submit_one+0xd97/0x1a00
> Feb 09 15:14:29 testnode2 kernel:  __x64_sys_io_submit+0x15d/0x2b0
> Feb 09 15:14:29 testnode2 kernel:  do_syscall_64+0x95/0x540
> Feb 09 15:14:29 testnode2 kernel:  entry_SYSCALL_64_after_hwframe+0x76/0x7e
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: Freed by task 37:
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_stack+0x2c/0x50
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_track+0x10/0x30
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_free_info+0x37/0x70
> Feb 09 15:14:29 testnode2 kernel:  __kasan_slab_free+0x67/0x80
> Feb 09 15:14:29 testnode2 kernel:  slab_free_after_rcu_debug+0xf5/0x200
> Feb 09 15:14:29 testnode2 kernel:  rcu_do_batch+0x37a/0xd90
> Feb 09 15:14:29 testnode2 kernel:  rcu_core+0x6f1/0xad0
> Feb 09 15:14:29 testnode2 kernel:  handle_softirqs+0x1ee/0x790
> Feb 09 15:14:29 testnode2 kernel:  run_ksoftirqd+0x3b/0x60
> Feb 09 15:14:29 testnode2 kernel:  smpboot_thread_fn+0x2fd/0x9a0
> Feb 09 15:14:29 testnode2 kernel:  kthread+0x3af/0x770
> Feb 09 15:14:29 testnode2 kernel:  ret_from_fork+0x55c/0x810
> Feb 09 15:14:29 testnode2 kernel:  ret_from_fork_asm+0x1a/0x30
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: Last potentially related work creation:
> Feb 09 15:14:29 testnode2 kernel:  kasan_save_stack+0x2c/0x50
> Feb 09 15:14:29 testnode2 kernel:  kasan_record_aux_stack+0xac/0xc0
> Feb 09 15:14:29 testnode2 kernel:  kmem_cache_free+0x4af/0x6d0
> Feb 09 15:14:29 testnode2 kernel:  mempool_free+0xbe/0x110
> Feb 09 15:14:29 testnode2 kernel:  blk_update_request+0x443/0x1190
> Feb 09 15:14:29 testnode2 kernel:  scsi_end_request+0x70/0x7b0
> Feb 09 15:14:29 testnode2 kernel:  scsi_io_completion+0xea/0x1440
> Feb 09 15:14:29 testnode2 kernel:  blk_complete_reqs+0xa8/0x120
> Feb 09 15:14:29 testnode2 kernel:  handle_softirqs+0x1ee/0x790
> Feb 09 15:14:29 testnode2 kernel:  run_ksoftirqd+0x3b/0x60
> Feb 09 15:14:29 testnode2 kernel:  smpboot_thread_fn+0x2fd/0x9a0
> Feb 09 15:14:29 testnode2 kernel:  kthread+0x3af/0x770
> Feb 09 15:14:29 testnode2 kernel:  ret_from_fork+0x55c/0x810
> Feb 09 15:14:29 testnode2 kernel:  ret_from_fork_asm+0x1a/0x30
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: The buggy address belongs to the object at ffff8881580daf00
>                                    which belongs to the cache bio-264 of size 264
> Feb 09 15:14:29 testnode2 kernel: The buggy address is located 72 bytes to the right of
>                                    allocated 264-byte region [ffff8881580daf00, ffff8881580db008)
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: The buggy address belongs to the physical page:
> Feb 09 15:14:29 testnode2 kernel: page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x1580da
> Feb 09 15:14:29 testnode2 kernel: head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
> Feb 09 15:14:29 testnode2 kernel: flags: 0x17ffffc0000040(head|node=0|zone=2|lastcpupid=0x1fffff)
> Feb 09 15:14:29 testnode2 kernel: page_type: f5(slab)
> Feb 09 15:14:29 testnode2 kernel: raw: 0017ffffc0000040 ffff88810536c500 dead000000000122 0000000000000000
> Feb 09 15:14:29 testnode2 kernel: raw: 0000000000000000 0000000000150015 00000000f5000000 0000000000000000
> Feb 09 15:14:29 testnode2 kernel: head: 0017ffffc0000040 ffff88810536c500 dead000000000122 0000000000000000
> Feb 09 15:14:29 testnode2 kernel: head: 0000000000000000 0000000000150015 00000000f5000000 0000000000000000
> Feb 09 15:14:29 testnode2 kernel: head: 0017ffffc0000001 ffffea0005603681 00000000ffffffff 00000000ffffffff
> Feb 09 15:14:29 testnode2 kernel: head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000000000002
> Feb 09 15:14:29 testnode2 kernel: page dumped because: kasan: bad access detected
> Feb 09 15:14:29 testnode2 kernel: 
> Feb 09 15:14:29 testnode2 kernel: Memory state around the buggy address:
> Feb 09 15:14:29 testnode2 kernel:  ffff8881580daf00: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> Feb 09 15:14:29 testnode2 kernel:  ffff8881580daf80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> Feb 09 15:14:29 testnode2 kernel: >ffff8881580db000: fb fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> Feb 09 15:14:29 testnode2 kernel:                                                  ^
> Feb 09 15:14:29 testnode2 kernel:  ffff8881580db080: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> Feb 09 15:14:29 testnode2 kernel:  ffff8881580db100: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> Feb 09 15:14:29 testnode2 kernel: ==================================================================
> Feb 09 15:14:34 testnode2 kernel: device-mapper: zone: dm-0 using emulated zone append
> Feb 09 15:16:09 testnode2 kernel: null_blk: disk nullb0 created
> Feb 09 15:16:09 testnode2 kernel: null_blk: module loaded

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/873438c1zc.ffs%40tglx.
