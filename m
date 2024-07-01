Return-Path: <kasan-dev+bncBCAP7WGUVIKBBA6JRK2AMGQEWJKB65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id D60C691DF9F
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2024 14:43:49 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1fa9184f751sf6221005ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 05:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719837828; cv=pass;
        d=google.com; s=arc-20160816;
        b=QawglQZWkBlmCrc3+Qcvg23WseY+tjde3sIWCpAOsczLdTof7JaFMx5UEB1+Hc1Zdj
         2cFKu7wP//8yBJHfgrl4vYYV3P5hbghos4uhoU95bks4Q9ADeBvsHWs6Nu8agbSWlpYV
         0hVG7yB/Y9wC5cmd0WhqjHuYR+oTMhnO1ZksZKb7s+X7En4j3lNJzoAhkTIjhJJGtc9c
         j5nIi8dIgS6LlAoyuAaxBRz5cOkEOifWaGtWVNgk15CnV5mfnMsGPesDOdSSqptCQ/R0
         KWd+7keOQsYQfucI/dDw1+C3/A6OWhi2MXUIExxn4SDB7wOI3tDOac/M4zjv9mA1Dp8Q
         ohSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:cc:content-language
         :references:to:from:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=SWpfX5oePaE9kcVFqr0esHGyE843Iveiep8IZOSjPX4=;
        fh=VvYtDpn1NUrk2L6iSJtrZrZY80zi0ClqE2d1C6yxcCo=;
        b=AUaihuo1YLeci0HEY57cAnM3YyjZoet2MHP8JO17ZmZMCl069HLYoVmVeC27Cl3j9I
         l3CzDhTBmSC1bBxzouANBcTULCkT7bSeYIMCAyEUgkts0XTQml2JyFJYSE+OwLi5oCfB
         0IboA04PpxR2h+z1DdtrDkdwZnP0bYhZemW4PGBqIBHorzoN13nlW/J+Qm0HzPer6Mb7
         C1Al61SZZXAiGwgRdDa/rbqpTIMX+JemEysZrDe2lgWyUPFMt2gblVytliWNji/zOvjS
         dhf5TftyN4PErIE1CxgJSO7YZNfmLhd/1Ce1JGcbKERP3BlMF7rvHV0gbZ1RTRfm5BeV
         9ryQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719837828; x=1720442628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:cc:content-language:references:to
         :from:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SWpfX5oePaE9kcVFqr0esHGyE843Iveiep8IZOSjPX4=;
        b=kY2pV7KFJ3iL2ohRHe88wrERkJYpIz7iniLKq1krNiXf0DlNBV7Kv92IdQIalZ+Ga8
         4VX2Us8c5jvVVTZQfJa06LNMa8QKd4RBqqZMRMzIs3VblSzMfEGoupxFXu6Nh7CrejPb
         HI/rSJWvd4iMdwoq2uKp4Yk0wfLANrQpEl7cn6Uq1ao6L62gRXBzzYWCzDRqI3unGddV
         dQ4cqUMWydyCvuTHoTbGeE8pnaefSSSLu9/Kxg3gjG61teJ0KwQKOwa3rwI043sTxEWb
         C+lM0eGUaejK74A5hP5mliLMnNdGcCvNZWQYtejmbup8OElRyVdKeqdJ+jSPkfX09mxl
         7GRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719837828; x=1720442628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to:cc
         :content-language:references:to:from:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SWpfX5oePaE9kcVFqr0esHGyE843Iveiep8IZOSjPX4=;
        b=wGYxh7us/Yxz05MR0as+J1M4bVTjUPbtgsOOYXEtjWz1c/KplBri2tAW3RcLbWLFfw
         jr4N/u/Gwo2Vp3yA5uePwDUyF0WomZeyGVpPSgpVZ6mtlmRQd+lfNNTkrYXgWu8WqFv1
         PHIBt1WxfgOsvp5qrpVYCzp9YwFhWZjby4H1qYfOsZO0z1+6G0doSJq9dIsRcmlZDpkH
         yNAk1slvAvqwsXKtvwMxik3siZ+WPlLFYAfqu7V4nqbe4NhgikI77SpBZtaqDo1a8Tmn
         UwhbtUSE/5ImwqDJ0QGZBK946Brk+u3ns3lXL9atTJZUKH15q9a8EdG298sIup83Q8BF
         5C9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+kNTdxJ/z8W9xYxl21FIUnK/9KrkE8Eaku43qdMtbUbtcqAHXKxNsck+9YwGGoy/yM5LhJVWqLgq4DCeLS3Ri87T2ERh2tw==
X-Gm-Message-State: AOJu0YxF56HhchlsQ0dAVdrsE22XcRd31+DKATCe8FB7UvH/RTUsXsRe
	XLN08eAhj0r/E4tB/d0C0607eh8FULOPrfsHjF2ebdWBU32ygaMZ
X-Google-Smtp-Source: AGHT+IHcd5Vub1FhVOY+5qmslzsq+K4VAfjNFQAeIyGMwqdhDy5LqJJee+EJEFjLSUAljIWy+96puw==
X-Received: by 2002:a17:902:7ec8:b0:1f8:5767:b114 with SMTP id d9443c01a7336-1fad7ec463emr4362995ad.0.1719837827967;
        Mon, 01 Jul 2024 05:43:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:360d:b0:2c5:128e:240 with SMTP id
 98e67ed59e1d1-2c921d62c94ls1655476a91.2.-pod-prod-06-us; Mon, 01 Jul 2024
 05:43:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVT6d25Qk7sPsxn+/S04GCCKZHrXgY4EYu6Mhx118VMTj2ovC8xriaDTCZMO6CDj+FRecEAEoXGD7iGfHHR4sv9L78IHTf8uI7qQQ==
X-Received: by 2002:a17:90a:448d:b0:2c2:e97f:89d8 with SMTP id 98e67ed59e1d1-2c93d704026mr4482710a91.13.1719837826573;
        Mon, 01 Jul 2024 05:43:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719837826; cv=none;
        d=google.com; s=arc-20160816;
        b=opPvQhrMymok36tlmHZL5SrpMuQvfwU8aV6QhC/d0cPLIOpskNTfTGvzeAuXU0zBZm
         NP5/PwI4p1J3/pzf0vulv80PBJ0svGnK1aN3kJusoW0ktxAgsbWt1+vo1Bv1u1IEJ6lc
         EZXeMOYwFFwr0arU8LmYoVxrVe5WO9GfdIVf4IJTgajKPIkJabDIDmYNoLbiH1cH57Uu
         NTPY8mtHXV1tmekGf3/jyjnoNS6sQy8e7c0/kfgXhkBwv4NiDCliQy+bJghv0gkvcyvC
         YtYycADriO2dSCJdX/4n1BpiQ2CeiezXpyPQKYJDmfbw5fQD73dax4EBMACBc6hsSfdH
         QbMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:cc:content-language
         :references:to:from:subject:user-agent:mime-version:date:message-id;
        bh=Sn0IbiuitZ8dk+p9qhbHjquKUzy84KTjeWLXyIPBsKk=;
        fh=0wiO0kLupa3MQ2cAxS/E7evWVPCPddOjkFYgOzoCAas=;
        b=vnTmUstDnNGUcHl2wPoBRcRSgubCbZB2/2PmpzWEE+JRUu6OWONX1/EvIemPoDLwac
         kgWuniwVUTofElpDP+eCpZrzlxJvlS0S0zr8og9mKNvm6BZP+7Nf6r9Wq297sk/ydCRy
         sG8M6m8RdceP/Vt9Y1iKpcr1ZQoew8XBWQEP1IUFeXtxdVgwK0wDzaM1az2bASJFQhI9
         W3qXPXWSqZZTaEDjV3tZIkWgS38LnkVdk8Ew+it6JXIRtB0B35tpMukHFdQ3msgK6CV8
         lmxioBhwoMHlhMoMLAine7yEe3lXEO0+3WAkvJHwgXyQPjWTtEdKuQOu/aPHSOrfMb/t
         20/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c91d3f7763si278890a91.3.2024.07.01.05.43.45
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Jul 2024 05:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav412.sakura.ne.jp (fsav412.sakura.ne.jp [133.242.250.111])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 461ChdIE041283;
	Mon, 1 Jul 2024 21:43:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav412.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav412.sakura.ne.jp);
 Mon, 01 Jul 2024 21:43:39 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav412.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 461ChX55041268
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 1 Jul 2024 21:43:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
Date: Mon, 1 Jul 2024 21:43:30 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs
 (2)
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>,
        linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
References: <000000000000a8c856061ae85e20@google.com>
 <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
Content-Language: en-US
Cc: bp@alien8.de, dave.hansen@linux.intel.com, hpa@zytor.com, mingo@redhat.com,
        tglx@linutronix.de, x86@kernel.org
In-Reply-To: <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
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

Hello, KASAN people.

I suspect that KASAN's metadata for kernel stack memory got out of sync for
unknown reason, for the stack trace of PID=7558 was successfully printed for
two times before KASAN complains upon trying to print for the the third time.
Would you decode what is this KASAN message saying?

Quoting from https://syzkaller.appspot.com/text?tag=CrashLog&x=119fd081980000 :

[  226.304791][    C0] DEBUG: holding rtnl_mutex for 555 jiffies.
[  226.310883][    C0] task:syz.1.750       state:R  running task     stack:24672 pid:7558  tgid:7558  ppid:5945   flags:0x00004006
[  226.322705][    C0] Call Trace:
[  226.326074][    C0]  <TASK>
[  226.329029][    C0]  __schedule+0x17e8/0x4a20
[  226.333672][    C0]  ? __pfx___schedule+0x10/0x10
[  226.338599][    C0]  ? __pfx_lock_release+0x10/0x10
[  226.343744][    C0]  ? _raw_spin_unlock_irqrestore+0xdd/0x140
[  226.349775][    C0]  ? schedule+0x90/0x320
[  226.354042][    C0]  schedule+0x14b/0x320
[  226.358254][    C0]  synchronize_rcu_expedited+0x684/0x830
[  226.364012][    C0]  ? __pfx_synchronize_rcu_expedited+0x10/0x10
[  226.370239][    C0]  ? __pfx_wait_rcu_exp_gp+0x10/0x10
[  226.375579][    C0]  ? __pfx___might_resched+0x10/0x10
[  226.380877][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  226.386897][    C0]  ? __pfx_autoremove_wake_function+0x10/0x10
[  226.392985][    C0]  ? __pfx_lockdep_hardirqs_on_prepare+0x10/0x10
[  226.399381][    C0]  synchronize_rcu+0x11b/0x360
[  226.404181][    C0]  ? __pfx_synchronize_rcu+0x10/0x10
[  226.409555][    C0]  lockdep_unregister_key+0x556/0x610
[  226.414991][    C0]  ? __pfx_lockdep_unregister_key+0x10/0x10
[  226.420908][    C0]  ? lockdep_hardirqs_on+0x99/0x150
[  226.426160][    C0]  ? __qdisc_destroy+0x150/0x410
[  226.431211][    C0]  ? kfree+0x149/0x360
[  226.435414][    C0]  ? __pfx_pfifo_fast_destroy+0x10/0x10
[  226.441013][    C0]  __qdisc_destroy+0x165/0x410
[  226.445888][    C0]  dev_shutdown+0x9b/0x440
[  226.450334][    C0]  unregister_netdevice_many_notify+0x9c7/0x1d20
[  226.456717][    C0]  ? __lock_acquire+0x1359/0x2000
[  226.461786][    C0]  ? __pfx_unregister_netdevice_many_notify+0x10/0x10
[  226.468602][    C0]  ? __asan_memset+0x23/0x50
[  226.473208][    C0]  ? skb_queue_purge_reason+0x2de/0x500
[  226.478815][    C0]  ? __asan_memset+0x23/0x50
[  226.483423][    C0]  ? skb_queue_purge_reason+0x2de/0x500
[  226.489025][    C0]  ? do_raw_spin_unlock+0x13c/0x8b0
[  226.494244][    C0]  unregister_netdevice_queue+0x303/0x370
[  226.500013][    C0]  ? __pfx_unregister_netdevice_queue+0x10/0x10
[  226.506317][    C0]  __tun_detach+0x6b6/0x1600
[  226.510942][    C0]  tun_chr_close+0x108/0x1b0
[  226.515574][    C0]  ? __pfx_tun_chr_close+0x10/0x10
[  226.520705][    C0]  __fput+0x24a/0x8a0
[  226.524742][    C0]  task_work_run+0x24f/0x310
[  226.529352][    C0]  ? __pfx_task_work_run+0x10/0x10
[  226.534482][    C0]  ? syscall_exit_to_user_mode+0xa3/0x370
[  226.540265][    C0]  syscall_exit_to_user_mode+0x168/0x370
[  226.545967][    C0]  do_syscall_64+0x100/0x230
[  226.550580][    C0]  ? clear_bhb_loop+0x35/0x90
[  226.555306][    C0]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  226.561215][    C0] RIP: 0033:0x7f2470375b99
[  226.565668][    C0] RSP: 002b:00007ffd71072888 EFLAGS: 00000246 ORIG_RAX: 00000000000001b4
[  226.574109][    C0] RAX: 0000000000000000 RBX: 00007f2470505aa0 RCX: 00007f2470375b99
[  226.582119][    C0] RDX: 0000000000000000 RSI: 000000000000001e RDI: 0000000000000003
[  226.590129][    C0] RBP: 00007f2470505aa0 R08: 0000000000000008 R09: 0000000871072b9f
[  226.598153][    C0] R10: 00000000005f3974 R11: 0000000000000246 R12: 000000000003603f
[  226.606256][    C0] R13: 0000000000000032 R14: 00007f2470505aa0 R15: 00007f2470504078
[  226.614265][    C0]  </TASK>
[  226.617357][    C0] 
[  226.617357][    C0] Showing all locks held in the system:
[  226.625107][    C0] 3 locks held by kworker/u8:0/11:
[  226.630259][    C0] 2 locks held by getty/4850:
[  226.634966][    C0]  #0: ffff88802a6860a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x25/0x70
[  226.644790][    C0]  #1: ffffc9000312b2f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_read+0x6b5/0x1e10
[  226.654971][    C0] 2 locks held by syz.4.185/5862:
[  226.660012][    C0] 2 locks held by syz.3.241/6079:
[  226.665073][    C0] 1 lock held by syz-executor/7179:
[  226.670288][    C0] 2 locks held by syz.1.750/7558:
[  226.675345][    C0]  #0: ffffffff8f5feac8 (rtnl_mutex){+.+.}-{3:3}, at: tun_chr_close+0x3e/0x1b0
[  226.684379][    C0]  #1: ffffffff8e33abf8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: synchronize_rcu_expedited+0x381/0x830
[  226.695348][    C0] 2 locks held by syz.0.757/7594:
[  226.700384][    C0]  #0: ffffffff8f6682f0 (cb_lock){++++}-{3:3}, at: genl_rcv+0x19/0x40
[  226.708731][    C0]  #1: ffffffff8f5feac8 (rtnl_mutex){+.+.}-{3:3}, at: nl80211_pre_doit+0x5f/0x8b0
[  226.718045][    C0] 1 lock held by syz.3.764/7609:
[  226.723082][    C0] 2 locks held by syz.2.767/7615:
[  226.728152][    C0]  #0: ffffc90000007c00 (net/core/rtnetlink.c:83){+.-.}-{0:0}, at: call_timer_fn+0xc0/0x650
[  226.738338][    C0]  #1: ffffffff8e335820 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x55/0x2a0
[  226.748268][    C0] 3 locks held by syz-executor/7617:
[  226.753568][    C0] 
[  226.755932][    C0] =============================================
[  226.755932][    C0] 
[  227.343278][ T5144] usb 3-1: new high-speed USB device number 9 using dummy_hcd
[  227.536711][ T5144] usb 3-1: config 0 interface 0 altsetting 0 endpoint 0x81 has an invalid bInterval 0, changing to 7
[  227.568067][ T5144] usb 3-1: config 0 interface 0 altsetting 0 endpoint 0x81 has invalid wMaxPacketSize 0
[  227.598514][ T5144] usb 3-1: New USB device found, idVendor=05ac, idProduct=022a, bcdDevice= 0.00
[  227.621562][ T5144] usb 3-1: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[  227.651457][ T5144] usb 3-1: config 0 descriptor??
[  227.814998][    C0] DEBUG: holding rtnl_mutex for 706 jiffies.
[  227.821075][    C0] task:syz.1.750       state:D stack:24672 pid:7558  tgid:7558  ppid:5945   flags:0x00004006
[  227.831413][    C0] Call Trace:
[  227.834732][    C0]  <TASK>
[  227.837686][    C0]  __schedule+0x17e8/0x4a20
[  227.842246][    C0]  ? __pfx___schedule+0x10/0x10
[  227.847165][    C0]  ? __pfx_lock_release+0x10/0x10
[  227.852388][    C0]  ? _raw_spin_unlock_irqrestore+0xdd/0x140
[  227.858350][    C0]  ? schedule+0x90/0x320
[  227.862622][    C0]  schedule+0x14b/0x320
[  227.866849][    C0]  synchronize_rcu_expedited+0x684/0x830
[  227.872517][    C0]  ? __pfx_synchronize_rcu_expedited+0x10/0x10
[  227.878773][    C0]  ? __pfx_wait_rcu_exp_gp+0x10/0x10
[  227.884098][    C0]  ? __pfx___might_resched+0x10/0x10
[  227.889440][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  227.895470][    C0]  ? __pfx_autoremove_wake_function+0x10/0x10
[  227.901561][    C0]  ? __pfx_lockdep_hardirqs_on_prepare+0x10/0x10
[  227.907960][    C0]  synchronize_rcu+0x11b/0x360
[  227.912758][    C0]  ? __pfx_synchronize_rcu+0x10/0x10
[  227.918117][    C0]  lockdep_unregister_key+0x556/0x610
[  227.923521][    C0]  ? __pfx_lockdep_unregister_key+0x10/0x10
[  227.929465][    C0]  ? lockdep_hardirqs_on+0x99/0x150
[  227.934718][    C0]  ? __qdisc_destroy+0x150/0x410
[  227.939964][    C0]  ? kfree+0x149/0x360
[  227.944062][    C0]  ? __pfx_pfifo_fast_destroy+0x10/0x10
[  227.949668][    C0]  __qdisc_destroy+0x165/0x410
[  227.954466][    C0]  dev_shutdown+0x9b/0x440
[  227.958940][    C0]  unregister_netdevice_many_notify+0x9c7/0x1d20
[  227.965321][    C0]  ? __lock_acquire+0x1359/0x2000
[  227.970390][    C0]  ? __pfx_unregister_netdevice_many_notify+0x10/0x10
[  227.977386][    C0]  ? __asan_memset+0x23/0x50
[  227.982011][    C0]  ? skb_queue_purge_reason+0x2de/0x500
[  227.987621][    C0]  ? __asan_memset+0x23/0x50
[  227.992237][    C0]  ? skb_queue_purge_reason+0x2de/0x500
[  227.997854][    C0]  ? do_raw_spin_unlock+0x13c/0x8b0
[  228.003082][    C0]  unregister_netdevice_queue+0x303/0x370
[  228.008865][    C0]  ? __pfx_unregister_netdevice_queue+0x10/0x10
[  228.015177][    C0]  __tun_detach+0x6b6/0x1600
[  228.019812][    C0]  tun_chr_close+0x108/0x1b0
[  228.024437][    C0]  ? __pfx_tun_chr_close+0x10/0x10
[  228.029623][    C0]  __fput+0x24a/0x8a0
[  228.033651][    C0]  task_work_run+0x24f/0x310
[  228.038319][    C0]  ? __pfx_task_work_run+0x10/0x10
[  228.043546][    C0]  ? syscall_exit_to_user_mode+0xa3/0x370
[  228.049341][    C0]  syscall_exit_to_user_mode+0x168/0x370
[  228.055042][    C0]  do_syscall_64+0x100/0x230
[  228.059667][    C0]  ? clear_bhb_loop+0x35/0x90
[  228.064374][    C0]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  228.070336][    C0] RIP: 0033:0x7f2470375b99
[  228.074815][    C0] RSP: 002b:00007ffd71072888 EFLAGS: 00000246 ORIG_RAX: 00000000000001b4
[  228.083252][    C0] RAX: 0000000000000000 RBX: 00007f2470505aa0 RCX: 00007f2470375b99
[  228.091289][    C0] RDX: 0000000000000000 RSI: 000000000000001e RDI: 0000000000000003
[  228.091369][ T5144] appletouch 3-1:0.0: Geyser mode initialized.
[  228.099291][    C0] RBP: 00007f2470505aa0 R08: 0000000000000008 R09: 0000000871072b9f
[  228.099348][    C0] R10: 00000000005f3974 R11: 0000000000000246 R12: 000000000003603f
[  228.099364][    C0] R13: 0000000000000032 R14: 00007f2470505aa0 R15: 00007f2470504078
[  228.099396][    C0]  </TASK>
[  228.099408][    C0] 
[  228.099408][    C0] Showing all locks held in the system:
[  228.099452][    C0] 5 locks held by kworker/u8:7/2895:
[  228.136372][ T5144] input: appletouch as /devices/platform/dummy_hcd.2/usb3/3-1/3-1:0.0/input/input11
[  228.140345][    C0] 2 locks held by getty/4850:
[  228.140365][    C0]  #0: ffff88802a6860a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x25/0x70
[  228.140438][    C0]  #1: ffffc9000312b2f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_read+0x6b5/0x1e10
[  228.140505][    C0] 6 locks held by kworker/1:5/5144:
[  228.140523][    C0] 2 locks held by syz.4.185/5862:
[  228.140539][    C0] 4 locks held by syz.3.241/6079:
[  228.140557][    C0] 2 locks held by syz.1.750/7558:
[  228.140571][    C0]  #0: ffffffff8f5feac8 (rtnl_mutex){+.+.}-{3:3}, at: tun_chr_close+0x3e/0x1b0
[  228.140639][    C0]  #1: ffffffff8e33abf8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: synchronize_rcu_expedited+0x381/0x830
[  228.140716][    C0] 2 locks held by syz.0.757/7594:
[  228.140730][    C0]  #0: ffffffff8f6682f0 (cb_lock){++++}-{3:3}, at: genl_rcv+0x19/0x40
[  228.140791][    C0]  #1: ffffffff8f5feac8 (rtnl_mutex){+.+.}-{3:3}, at: nl80211_pre_doit+0x5f/0x8b0
[  228.140857][    C0] 2 locks held by syz.3.775/7633:
[  228.140871][    C0]  #0: ffffc9000499fb40 (net/core/rtnetlink.c:83){+.-.}-{0:0}, at: call_timer_fn+0xc0/0x650
[  228.140931][    C0]  #1: ffffffff8e335820 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x55/0x2a0
[  228.140997][    C0] 
[  228.141004][    C0] =============================================
[  228.141004][    C0] 
[  229.184903][    C0] DEBUG: holding rtnl_mutex for 843 jiffies.
[  229.190994][    C0] task:syz.1.750       state:R  running task     stack:24672 pid:7558  tgid:7558  ppid:5945   flags:0x00004006
[  229.202817][    C0] Call Trace:
[  229.206142][    C0]  <TASK>
[  229.209088][    C0]  __schedule+0x17e8/0x4a20
[  229.213626][    C0]  ? mark_lock+0x9a/0x360
[  229.218009][    C0]  ? lockdep_hardirqs_on_prepare+0x43d/0x780
[  229.224013][    C0]  ? __pfx_lockdep_hardirqs_on_prepare+0x10/0x10
[  229.230388][    C0]  ? __pfx___schedule+0x10/0x10
[  229.235286][    C0]  ? lockdep_hardirqs_on+0x99/0x150
[  229.240775][    C0]  ? mark_lock+0x9a/0x360
[  229.245156][    C0]  preempt_schedule_irq+0xfb/0x1c0
[  229.250289][    C0]  ? __pfx_preempt_schedule_irq+0x10/0x10
[  229.256053][    C0]  ? __pfx_pfifo_fast_destroy+0x10/0x10
[  229.261637][    C0]  irqentry_exit+0x5e/0x90
[  229.266098][    C0]  asm_sysvec_reschedule_ipi+0x1a/0x20
[  229.271585][    C0] RIP: 0010:lockdep_unregister_key+0x56d/0x610
[  229.277796][    C0] Code: ff 92 48 c7 c6 d0 b7 6f 81 e8 7f 04 0a 00 e8 ea 18 0a 00 e9 e5 fb ff ff e8 c0 06 21 0a 41 f7 c7 00 02 00 00 74 d0 fb 45 84 f6 <75> cf eb e0 90 0f 0b 90 45 31 f6 e9 62 ff ff ff 90 0f 0b 90 e9 a1
[  229.297447][    C0] RSP: 0018:ffffc90003c4f820 EFLAGS: 00000246
[  229.303630][    C0] RAX: dffffc0000000000 RBX: 1ffff92000789f0c RCX: ffffffff947f3803
[  229.311661][    C0] RDX: 0000000000000001 RSI: ffffffff8bcad5e0 RDI: 1ffff92000789f0c
[  229.319713][    C0] ==================================================================
[  229.327779][    C0] BUG: KASAN: stack-out-of-bounds in __show_regs+0x172/0x610
[  229.335174][    C0] Read of size 8 at addr ffffc90003c4f798 by task kworker/u8:5/234
[  229.343506][    C0] 
[  229.345910][    C0] CPU: 0 UID: 0 PID: 234 Comm: kworker/u8:5 Not tainted 6.10.0-rc6-next-20240701-syzkaller #0
[  229.356229][    C0] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 06/07/2024
[  229.366301][    C0] Workqueue: bat_events batadv_nc_worker
[  229.371979][    C0] Call Trace:
[  229.375266][    C0]  <IRQ>
[  229.378119][    C0]  dump_stack_lvl+0x241/0x360
[  229.382825][    C0]  ? __pfx_dump_stack_lvl+0x10/0x10
[  229.388052][    C0]  ? __pfx__printk+0x10/0x10
[  229.392661][    C0]  ? _printk+0xd5/0x120
[  229.396840][    C0]  print_report+0x169/0x550
[  229.401361][    C0]  ? __virt_addr_valid+0xbd/0x530
[  229.406407][    C0]  ? __show_regs+0x172/0x610
[  229.411022][    C0]  kasan_report+0x143/0x180
[  229.415549][    C0]  ? show_opcodes+0x148/0x170
[  229.420251][    C0]  ? __show_regs+0x172/0x610
[  229.424865][    C0]  __show_regs+0x172/0x610
[  229.429297][    C0]  ? asm_sysvec_reschedule_ipi+0x1a/0x20
[  229.434949][    C0]  ? wq_watchdog_touch+0xef/0x180
[  229.439991][    C0]  ? asm_sysvec_reschedule_ipi+0x1a/0x20
[  229.445645][    C0]  show_trace_log_lvl+0x3d4/0x520
[  229.450700][    C0]  ? lockdep_unregister_key+0x56d/0x610
[  229.456267][    C0]  sched_show_task+0x506/0x6d0
[  229.461051][    C0]  ? report_rtnl_holders+0x29e/0x3f0
[  229.466361][    C0]  ? __pfx__printk+0x10/0x10
[  229.470970][    C0]  ? __pfx_sched_show_task+0x10/0x10
[  229.476270][    C0]  ? _raw_spin_unlock_irqrestore+0xdd/0x140
[  229.482180][    C0]  ? __pfx__raw_spin_unlock_irqrestore+0x10/0x10
[  229.488536][    C0]  report_rtnl_holders+0x320/0x3f0
[  229.493671][    C0]  call_timer_fn+0x18e/0x650
[  229.498279][    C0]  ? call_timer_fn+0xc0/0x650
[  229.502974][    C0]  ? __pfx_report_rtnl_holders+0x10/0x10
[  229.508624][    C0]  ? __pfx_call_timer_fn+0x10/0x10
[  229.513749][    C0]  ? __pfx_report_rtnl_holders+0x10/0x10
[  229.519403][    C0]  ? __pfx_report_rtnl_holders+0x10/0x10
[  229.525056][    C0]  ? __pfx_report_rtnl_holders+0x10/0x10
[  229.530709][    C0]  ? _raw_spin_unlock_irq+0x23/0x50
[  229.535920][    C0]  ? lockdep_hardirqs_on+0x99/0x150
[  229.541145][    C0]  ? __pfx_report_rtnl_holders+0x10/0x10
[  229.546796][    C0]  __run_timer_base+0x66a/0x8e0
[  229.551946][    C0]  ? __pfx___run_timer_base+0x10/0x10
[  229.557433][    C0]  run_timer_softirq+0xb7/0x170
[  229.562312][    C0]  handle_softirqs+0x2c4/0x970
[  229.567095][    C0]  ? __irq_exit_rcu+0xf4/0x1c0
[  229.571877][    C0]  ? __pfx_handle_softirqs+0x10/0x10
[  229.577184][    C0]  ? irqtime_account_irq+0xd4/0x1e0
[  229.582405][    C0]  __irq_exit_rcu+0xf4/0x1c0
[  229.587017][    C0]  ? __pfx___irq_exit_rcu+0x10/0x10
[  229.592330][    C0]  irq_exit_rcu+0x9/0x30
[  229.596591][    C0]  sysvec_apic_timer_interrupt+0xa6/0xc0
[  229.602250][    C0]  </IRQ>
[  229.605190][    C0]  <TASK>
[  229.608128][    C0]  asm_sysvec_apic_timer_interrupt+0x1a/0x20
[  229.614125][    C0] RIP: 0010:rcu_is_watching+0x3a/0xb0
[  229.619525][    C0] Code: e8 4b 3b 17 0a 89 c3 83 f8 08 73 7a 49 bf 00 00 00 00 00 fc ff df 4c 8d 34 dd 40 6a de 8d 4c 89 f0 48 c1 e8 03 42 80 3c 38 00 <74> 08 4c 89 f7 e8 8c ac 80 00 48 c7 c3 98 7c 03 00 49 03 1e 48 89
[  229.639321][    C0] RSP: 0018:ffffc90002fe7a00 EFLAGS: 00000246
[  229.645414][    C0] RAX: 1ffffffff1bbcd48 RBX: 0000000000000000 RCX: ffffffff816f8930
[  229.653403][    C0] RDX: 0000000000000000 RSI: ffffffff8c207ae0 RDI: ffffffff8c207aa0
[  229.661389][    C0] RBP: ffffc90002fe7b48 R08: ffffffff8faf796f R09: 1ffffffff1f5ef2d
[  229.669374][    C0] R10: dffffc0000000000 R11: fffffbfff1f5ef2e R12: 1ffff920005fcf50
[  229.677448][    C0] R13: ffffffff8b5b3d7b R14: ffffffff8dde6a40 R15: dffffc0000000000
[  229.685523][    C0]  ? batadv_nc_worker+0xcb/0x610
[  229.690482][    C0]  ? lock_release+0xb0/0x9f0
[  229.695095][    C0]  lock_release+0xbf/0x9f0
[  229.699531][    C0]  ? __pfx_lock_acquire+0x10/0x10
[  229.704573][    C0]  ? batadv_nc_worker+0xcb/0x610
[  229.709525][    C0]  ? __pfx_lock_release+0x10/0x10
[  229.714577][    C0]  ? batadv_nc_worker+0xcb/0x610
[  229.719556][    C0]  batadv_nc_worker+0x28b/0x610
[  229.724427][    C0]  ? batadv_nc_worker+0xcb/0x610
[  229.729383][    C0]  ? process_scheduled_works+0x945/0x1830
[  229.735214][    C0]  process_scheduled_works+0xa2c/0x1830
[  229.741055][    C0]  ? __pfx_process_scheduled_works+0x10/0x10
[  229.747056][    C0]  ? assign_work+0x364/0x3d0
[  229.751662][    C0]  worker_thread+0x86d/0xd40
[  229.756278][    C0]  ? _raw_spin_unlock_irqrestore+0xdd/0x140
[  229.762193][    C0]  ? __kthread_parkme+0x169/0x1d0
[  229.767245][    C0]  ? __pfx_worker_thread+0x10/0x10
[  229.772373][    C0]  kthread+0x2f0/0x390
[  229.776460][    C0]  ? __pfx_worker_thread+0x10/0x10
[  229.781595][    C0]  ? __pfx_kthread+0x10/0x10
[  229.786210][    C0]  ret_from_fork+0x4b/0x80
[  229.790645][    C0]  ? __pfx_kthread+0x10/0x10
[  229.795257][    C0]  ret_from_fork_asm+0x1a/0x30
[  229.800050][    C0]  </TASK>
[  229.803075][    C0] 
[  229.805402][    C0] The buggy address belongs to the virtual mapping at
[  229.805402][    C0]  [ffffc90003c48000, ffffc90003c51000) created by:
[  229.805402][    C0]  copy_process+0x5d1/0x3d70
[  229.823040][    C0] 
[  229.825368][    C0] The buggy address belongs to the physical page:
[  229.831782][    C0] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x8 pfn:0x60439
[  229.840815][    C0] memcg:ffff88801ae90502
[  229.845059][    C0] flags: 0xfff00000000000(node=0|zone=1|lastcpupid=0x7ff)
[  229.852190][    C0] raw: 00fff00000000000 0000000000000000 dead000000000122 0000000000000000
[  229.860795][    C0] raw: 0000000000000008 0000000000000000 00000001ffffffff ffff88801ae90502
[  229.869388][    C0] page dumped because: kasan: bad access detected
[  229.875810][    C0] page_owner tracks the page as allocated
[  229.881541][    C0] page last allocated via order 0, migratetype Unmovable, gfp_mask 0x102dc2(GFP_HIGHUSER|__GFP_NOWARN|__GFP_ZERO), pid 5945, tgid 5945 (syz-executor), ts 214193789047, free_ts 213702691290
[  229.900048][    C0]  post_alloc_hook+0x1f3/0x230
[  229.904836][    C0]  get_page_from_freelist+0x2ccb/0x2d80
[  229.910401][    C0]  __alloc_pages_noprof+0x256/0x6c0
[  229.915617][    C0]  alloc_pages_mpol_noprof+0x3e8/0x680
[  229.921098][    C0]  __vmalloc_node_range_noprof+0x971/0x1460
[  229.927002][    C0]  dup_task_struct+0x444/0x8c0
[  229.931782][    C0]  copy_process+0x5d1/0x3d70
[  229.936391][    C0]  kernel_clone+0x226/0x8f0
[  229.940907][    C0]  __x64_sys_clone+0x258/0x2a0
[  229.945685][    C0]  do_syscall_64+0xf3/0x230
[  229.950289][    C0]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  229.956189][    C0] page last free pid 6079 tgid 6077 stack trace:
[  229.962513][    C0]  free_unref_page+0xd22/0xea0
[  229.967289][    C0]  __put_partials+0xeb/0x130
[  229.971890][    C0]  put_cpu_partial+0x17c/0x250
[  229.976665][    C0]  __slab_free+0x2ea/0x3d0
[  229.981093][    C0]  qlist_free_all+0x9e/0x140
[  229.985702][    C0]  kasan_quarantine_reduce+0x14f/0x170
[  229.991174][    C0]  __kasan_slab_alloc+0x23/0x80
[  229.996036][    C0]  kmem_cache_alloc_noprof+0x135/0x2a0
[  230.001536][    C0]  alloc_buffer_head+0x2a/0x290
[  230.006397][    C0]  folio_alloc_buffers+0x241/0x5b0
[  230.011522][    C0]  create_empty_buffers+0x3a/0x740
[  230.016644][    C0]  block_read_full_folio+0x25c/0xcd0
[  230.021940][    C0]  filemap_read_folio+0x1a0/0x790
[  230.026979][    C0]  do_read_cache_folio+0x134/0x820
[  230.032104][    C0]  do_read_cache_page+0x30/0x200
[  230.037057][    C0]  sysv_find_entry+0x1af/0x410
[  230.041836][    C0] 
[  230.044183][    C0] Memory state around the buggy address:
[  230.049816][    C0]  ffffc90003c4f680: f2 f2 f2 f2 00 00 00 00 00 f3 f3 f3 f3 f3 f3 f3
[  230.057889][    C0]  ffffc90003c4f700: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
[  230.065961][    C0] >ffffc90003c4f780: 00 f2 f2 f2 00 f3 f3 f3 00 00 00 00 00 00 00 00
[  230.074059][    C0]                             ^
[  230.078915][    C0]  ffffc90003c4f800: 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00 f2 f2 f2
[  230.086983][    C0]  ffffc90003c4f880: 00 f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
[  230.095056][    C0] ==================================================================
[  230.103224][    C0] Kernel panic - not syncing: KASAN: panic_on_warn set ...

On 2024/06/25 10:22, Tetsuo Handa wrote:
> Hello.
> 
> This report is triggered by my debug printk() patch at
> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/net/core/rtnetlink.c?id=5210cbe9a47fc5c1f43ba16d481e6335f3e2f345
> but I can't find where the bug is (x86 bug or mm bug or kasan bug or my bug).
> 
> On 2024/06/15 16:06, syzbot wrote:
>> Hello,
>>
>> syzbot found the following issue on:
>>
>> HEAD commit:    a957267fa7e9 Add linux-next specific files for 20240611
>> git tree:       linux-next
>> console output: https://syzkaller.appspot.com/x/log.txt?x=171e6e56980000
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=9a880e96898e79f8
>> dashboard link: https://syzkaller.appspot.com/bug?extid=e9be5674af5e3a0b9ecc
>> compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/daad75ac-9fd5-439a-b04b-235152bea222%40I-love.SAKURA.ne.jp.
