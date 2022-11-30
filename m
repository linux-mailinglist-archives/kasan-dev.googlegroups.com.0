Return-Path: <kasan-dev+bncBCT6537ZTEKRBKX6TWOAMGQECHKUBCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id A7FF263DA2D
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 17:05:05 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id a33-20020a630b61000000b00429d91cc649sf12161645pgl.8
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 08:05:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669824304; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqxEu0dM8Wi5wS5o5QdYQYb4WX8rR6xWqmKSixxb0pkrFbzwQ8EWpzxw9AxnJ2v3kD
         KZDlDkenaa5z6AIwB/ZC60EzTDa8IsqZDlc0s/sPuDuWuLg3A33RzpDhKjpP2TJriD9/
         krOMkxeH4/zAMlLoXbkc5bzz1/9wJi0I0QJv5Sp5At1zwTVKD+l3aCCHch5x6p4XGbth
         Gc10dSlFBXV2YUvV0tst1lUDw8d+L0iPSyO1+RL5Rj1iWFydrVMMQ4v01eiZzYrqSPCv
         Lyc0/RQoFhXAY9WgF6WVfTkPS0reYfffjMyGnfmsf/qlj59iq/CVa6I4UpclQToJ1y2b
         8NgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=zEfiw2Bd3H4gZS/K7LdfDwc6l8r0t0Y0E7rYTU22/8w=;
        b=VGI8pDk7UX+V6uBtxiimqu895daqn38lIx8EHZyecEkj03U2WSu8VGrvWD7yLFCu7r
         AGFsxZMw/+sk5EwRbrQFZs5rFFYg7UkdupDHP23kYByaGkzqkzm6AMnAffb3znKQgegy
         JL1YsFDv/bUEkKvqgCZ02QgXgmtakoqmBom0sJSpUVVymDSoauK2rqPnMM8pWs/lZnVH
         bsioZ/V9UwZEx/0Gc1T9BNVi8q28497T/NxeZY/3mb2Hdpu3UVGjIwxFIqgKBzlrCeq/
         ToldXS812rbUBPdfPyCopAq8uIoV9++KX4kGhz6y1r7bffJmhe129v5vdRrc+h6nX7zW
         CTEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=J1m3mfhE;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zEfiw2Bd3H4gZS/K7LdfDwc6l8r0t0Y0E7rYTU22/8w=;
        b=S/G67XaFbpewQZ+RZNGDZn70ZMgQRC/seXf3EwETnDfml4WySQL1BEG7JhP9o6w9az
         BxfZuEB2oQJPzqCV/6WvMoYk+CCWXZoRKMGpty1NkfsDms3TCYXWgQxq/u7EMrhInAUt
         a4Bmi/TPLmtpj1xFGwYI+ZlPQ4qSMmw5PqBocpe8Htrkzh97agGRU69H8bDLmCzHp15A
         x06ess1rI2jW5UCOF1YWZfqEIRce4WZgx3foxUhD51pSddgdvBw7RlOjTgVMxfOnVzD1
         G1848nkSxQdktRcrWlNFvDsZ1MSd+MKNASZ1/1cBSSXxaCQFGY59J939diJHviAmS2hL
         kd8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zEfiw2Bd3H4gZS/K7LdfDwc6l8r0t0Y0E7rYTU22/8w=;
        b=Ce7zILMNzqXEgWyeDZMj0WomYQrHuCMWlud6n/yPzfuYt3Ylu8vsUAHZkNlNXLqZu/
         tDVkuWxwRNvWYwgHnkFZqMtjAdReiBEP7qI/GtfTleK5TJQTHl0gWgAu4PbPxYdSR3Sx
         3b0XBzbyDo82aNZuCdelYbxdBCqfjp7HjfFEpwbs0+DUF6hrJJNgvXs8B3TWHZACtemh
         IE93e9wvDBIhqLDd3EACoyfguypZVnOvliPUqucZtY4361J7H46kBon2e7Z6Pwi7K5cC
         eA9My7KzIvZ5YdmgTN8DsANTgTX6Ip45yl4fkUCRErqqUPQ8p+GAQ0bWceinCmXE7xjs
         +jgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnuwVCBXJNfkUdaClulaRRlS25ngJiuHKjsqpXtFsEsDQBVCTvd
	ja5QM0gixQglXXOY23Q79IY=
X-Google-Smtp-Source: AA0mqf5owE/7QVA2ugkedBL65cyEN2CswNAYVzbi6lsvJSYY0YZ8ljXaeP90cUDEY8SbcbLLuoEywA==
X-Received: by 2002:a17:902:f312:b0:189:6077:5598 with SMTP id c18-20020a170902f31200b0018960775598mr30143986ple.100.1669824298719;
        Wed, 30 Nov 2022 08:04:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:53c1:b0:219:5f59:9dfc with SMTP id
 y59-20020a17090a53c100b002195f599dfcls923517pjh.0.-pod-preprod-gmail; Wed, 30
 Nov 2022 08:04:57 -0800 (PST)
X-Received: by 2002:a17:902:f293:b0:189:9313:9e55 with SMTP id k19-20020a170902f29300b0018993139e55mr12579929plc.76.1669824297775;
        Wed, 30 Nov 2022 08:04:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669824297; cv=none;
        d=google.com; s=arc-20160816;
        b=VBdpJAhcOIVgLL+GOaIHI7GucP1JGlrNZfrTlGn+4XwEBqUwomLg/CZKuuD/UIYmoV
         jlnizrnzgz5hjDMA6jaJSAP/ZCafKdGi7NPyP4Fb1zk2qdU0oQmPI5juPQc+4XApIwdq
         fw/T5pvuo1Iimdbh+hSZQ+/t4FakiZyL4hMFX3dWD33KGWOaWleqnoouT0/9khfJWCsj
         6WS1OOEKldvJK9NW7n+jXA+dyyHd5JRfdLhe4dL+3oOYcktLkdLuYfnxJ2ng+5ieEAKD
         E+VMgZu7QGt7qiJW35bXkk8j96RWJBU8ABhs1tPKwXHMv6PK0+0w94DEWEFsElRpJdUM
         ChpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wZCbfhHEURT6YoJPfOz2Og1G1Wn3P59DX6ySKyknVeU=;
        b=GaJ218jNdYlcFZxgy+uRcW7bsQ7eqVwywfFaefB9CC7/hsW4pBXVcLV5cW95ABjM+w
         2sw/HHSp1cqrZz7/UudMek8CXJT7NSenGqZLrOKTGA/f535QLSnfpR409KHnrdsixLyi
         p4VWdF6LJtFXkhYSrAk9IsEcs0lLSknxI+JjbcRcBbcO4THkefMqdKb1iirVtDlp6vyB
         msutpTIaY4hlRErorI3J3NUCVTDJYjled8X3QnqXhZwEi2skzBHHF3C/1P6VaFPzyrpO
         OxuhsJVisobcILD3zYho/NDBnUrZkPr3xt8kkjI3m8UiaDp0NNz1bwm137w2oWyUF3z6
         PcJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=J1m3mfhE;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id m3-20020a170902db0300b00188a88cc62fsi87965plx.12.2022.11.30.08.04.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 08:04:57 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id v206so5416875ybv.7
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 08:04:57 -0800 (PST)
X-Received: by 2002:a5b:f0f:0:b0:6d2:5835:301f with SMTP id
 x15-20020a5b0f0f000000b006d25835301fmr49093210ybr.336.1669824296918; Wed, 30
 Nov 2022 08:04:56 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
In-Reply-To: <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Wed, 30 Nov 2022 21:34:45 +0530
Message-ID: <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: Marco Elver <elver@google.com>
Cc: rcu <rcu@vger.kernel.org>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dominique Martinet <asmadeus@codewreck.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=J1m3mfhE;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, 30 Nov 2022 at 18:25, Marco Elver <elver@google.com> wrote:
>
> On Wed, 30 Nov 2022 at 13:50, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> >
> > [Please ignore if it is already reported, and not an expert of KCSAN]
> >
> > While booting arm64 with allmodconfig following kernel BUG found,
> > this build is enabled with CONFIG_INIT_STACK_NONE=y
>
> Unsure why CONFIG_INIT_STACK_NONE=y is relevant.

I agree.

This is from qemu-arm64 boot log.

>
> > [    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
> > [    0.000000] Linux version 6.1.0-rc7-next-20221130 (tuxmake@tuxmake)
> > (aarch64-linux-gnu-gcc (Debian 11.3.0-6) 11.3.0, GNU ld (GNU Binutils
> > for Debian) 2.39) #2 SMP PREEMPT_DYNAMIC @1669786411
> > [    0.000000] random: crng init done
> > [    0.000000] Machine model: linux,dummy-virt
> > ...
> > [  424.408466] ==================================================================
> > [  424.412792] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
> > [  424.416806]
> > [  424.418214] write to 0xffff00000a753000 of 4 bytes by interrupt on cpu 0:
> > [  424.422437]  p9_client_cb+0x84/0x100
>
> Please always provide line numbers and kernel commit hash or tag (I
> think it's next-20221130, but not entirely clear).

It is the Linux next-20221130 tag.
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/?h=next-20221130

>
> Then we can look at git blame of the lines and see if it's new code.

True.
Hope that tree and tag could help you get git details.


> > [  424.425048]  req_done+0xfc/0x1c0
> > [  424.427443]  vring_interrupt+0x174/0x1c0
> > [  424.430204]  __handle_irq_event_percpu+0x2c8/0x680
> > [  424.433455]  handle_irq_event+0x9c/0x180
> > [  424.436187]  handle_fasteoi_irq+0x2b0/0x340
> > [  424.439139]  generic_handle_domain_irq+0x78/0xc0
> > [  424.442323]  __gic_handle_irq_from_irqson.isra.0+0x3d8/0x480
> > [  424.446054]  gic_handle_irq+0xb4/0x100
> > [  424.448663]  call_on_irq_stack+0x2c/0x38
> > [  424.451443]  do_interrupt_handler+0xd0/0x140
> > [  424.454452]  el1_interrupt+0x88/0xc0
> > [  424.457001]  el1h_64_irq_handler+0x18/0x40
> > [  424.459856]  el1h_64_irq+0x78/0x7c
> > [  424.462331]  arch_local_irq_enable+0x50/0x80
> > [  424.465273]  arm64_preempt_schedule_irq+0x80/0xc0
> > [  424.468497]  el1_interrupt+0x90/0xc0
> > [  424.471096]  el1h_64_irq_handler+0x18/0x40
> > [  424.474009]  el1h_64_irq+0x78/0x7c
> > [  424.476464]  __tsan_read8+0x118/0x280
> > [  424.479086]  __delay+0x104/0x140
> > [  424.481521]  __udelay+0x5c/0xc0
> > [  424.483905]  kcsan_setup_watchpoint+0x6cc/0x7c0
> > [  424.487081]  __tsan_read4+0x168/0x280
> > [  424.489729]  p9_client_rpc+0x1d0/0x580
> > [  424.492429]  p9_client_getattr_dotl+0xd0/0x3c0
> > [  424.495457]  v9fs_inode_from_fid_dotl+0x48/0x1c0
> > [  424.498602]  v9fs_vfs_lookup+0x23c/0x3c0
> > [  424.501386]  __lookup_slow+0x1b0/0x240
> > [  424.504056]  walk_component+0x168/0x280
> > [  424.506807]  path_lookupat+0x154/0x2c0
> > [  424.509489]  filename_lookup+0x160/0x2c0
> > [  424.512261]  vfs_statx+0xc0/0x280
> > [  424.514710]  vfs_fstatat+0x84/0x100
> > [  424.517308]  __do_sys_newfstatat+0x64/0x100
> > [  424.520189]  __arm64_sys_newfstatat+0x74/0xc0
> > [  424.523262]  invoke_syscall+0xb0/0x1c0
> > [  424.525939]  el0_svc_common.constprop.0+0x10c/0x180
> > [  424.529219]  do_el0_svc+0x54/0x80
> > [  424.531662]  el0_svc+0x4c/0xc0
> > [  424.533944]  el0t_64_sync_handler+0xc8/0x180
> > [  424.536837]  el0t_64_sync+0x1a4/0x1a8
> > [  424.539436]
> > [  424.540810] read to 0xffff00000a753000 of 4 bytes by task 74 on cpu 0:
> > [  424.544927]  p9_client_rpc+0x1d0/0x580
> > [  424.547692]  p9_client_getattr_dotl+0xd0/0x3c0
> > [  424.550564]  v9fs_inode_from_fid_dotl+0x48/0x1c0
> > [  424.553550]  v9fs_vfs_lookup+0x23c/0x3c0
> > [  424.556144]  __lookup_slow+0x1b0/0x240
> > [  424.558655]  walk_component+0x168/0x280
> > [  424.561192]  path_lookupat+0x154/0x2c0
> > [  424.563721]  filename_lookup+0x160/0x2c0
> > [  424.566337]  vfs_statx+0xc0/0x280
> > [  424.568638]  vfs_fstatat+0x84/0x100
> > [  424.571051]  __do_sys_newfstatat+0x64/0x100
> > [  424.573821]  __arm64_sys_newfstatat+0x74/0xc0
> > [  424.576650]  invoke_syscall+0xb0/0x1c0
> > [  424.579144]  el0_svc_common.constprop.0+0x10c/0x180
> > [  424.582212]  do_el0_svc+0x54/0x80
> > [  424.584475]  el0_svc+0x4c/0xc0
> > [  424.586611]  el0t_64_sync_handler+0xc8/0x180
> > [  424.589347]  el0t_64_sync+0x1a4/0x1a8
> > [  424.591758]
> > [  424.593045] 1 lock held by systemd-journal/74:
> > [  424.595821]  #0: ffff00000a0ead88
> > (&type->i_mutex_dir_key#3){++++}-{3:3}, at: walk_component+0x158/0x280
> > [  424.601588] irq event stamp: 416642
> > [  424.603875] hardirqs last  enabled at (416641):
> > [<ffff80000a552040>] preempt_schedule_irq+0x40/0x100
> > [  424.609078] hardirqs last disabled at (416642):
> > [<ffff80000a5422b8>] el1_interrupt+0x78/0xc0
> > [  424.613887] softirqs last  enabled at (416464):
> > [<ffff800008011130>] __do_softirq+0x5b0/0x694
> > [  424.618699] softirqs last disabled at (416453):
> > [<ffff80000801a9b0>] ____do_softirq+0x30/0x80
> > [  424.623562]
> > [  424.624841] value changed: 0x00000002 -> 0x00000003
> > [  424.627838]
> > [  424.629117] Reported by Kernel Concurrency Sanitizer on:
> > [  424.632298] CPU: 0 PID: 74 Comm: systemd-journal Tainted: G
> >        T  6.1.0-rc7-next-20221130 #2
> > 26b4d3787db66414ab23fce17d22967bb2169e1f
> > [  424.639393] Hardware name: linux,dummy-virt (DT)
> >
> > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >
> > --
> > Linaro LKFT
> > https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYs55N3J8TRA557faxvAZSnCTUqnUx%2Bp1GOiCiG%2BNVfqnw%40mail.gmail.com.
