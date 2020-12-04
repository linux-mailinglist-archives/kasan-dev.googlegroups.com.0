Return-Path: <kasan-dev+bncBCT6537ZTEKRBI4QVL7AKGQEGXOZGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B4BA2CF47A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 20:04:04 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id w6sf544524lfl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 11:04:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607108643; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNAeDkBLcnb/U3IEIAnyrvEspxpR0uDkvfWnJykyrk2dBZi070TEFwahciECaJf/5/
         Bi3AvJWgL4HF5qMkPHTPLjKX0Y+rkaQp7qM3tmA1jYmqbOUTLRTmMGmo1D+mpZAIvrTz
         A2GO58kvJ2xlnb6ANpC1iprCvZ66tNOxdNrRW8lhjc5TlRtdEx3dHFdKe6TSqjnfoLku
         DNFyewfeHVmSANeXPCL7h2J+AJX9vtATm/ux8f7G57hXV8LQx6QraIVUbi5CiwFlfSLu
         F0nPCeM8JerFOPGSOTg3lpmu5ryOyEP98Q8jtg4fkqtPDVTQtjzHd8p0gUOXVVOnJRle
         8O5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=UPLJX6VNcA5BASH0ASuuRzTTSlyCVh/fDVEZpGQkpp4=;
        b=XdNbx7usApfM/Xew/g/8OjvdyX99h2ywbXxQCS8pIRd1Yna0jcAMIUyzoaXykCI6q6
         f0MvWJX1GCR/nVD2j9/zG99JSpkTDf25HnCrpYB8+kTFe78DnAOryX6yAbizSbtETWT6
         BjnnJPb7BIGh2zv3s4rZCOQnKspy3norEN9vdZFb5PJXPFEgp+X7r8Tf57YVvMgNb3sJ
         BCD0Wklx2FCRsK9mEuw2BsZzqNF0vRY1xLYNQoZ/a9FaVUPYdyehIAYayzFgQ4KSs2mC
         UXBBriE6oiphORUhFPT1tAbVEepx1ZGSI4wMXB1Ha3HeA/wrGbNEGdYjw9CVaj3d70x5
         UX3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cKh7YAPy;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPLJX6VNcA5BASH0ASuuRzTTSlyCVh/fDVEZpGQkpp4=;
        b=H65bSu34uZckmG3YF7CL37NGMiXYNDBOQK9V2ar2X9ZiB5MVFkhVXjRd1ZgM7qei6e
         gg2pxe/ajCYge5KUlyAOvhkgDGqXcm4VZRY18QlX9Na+mdIyUS3D+qKmWBdZ+5Jn1HSE
         rg1QvJo6ttob8aFo4ejTZDJQtFLfhPQ4XtMqa7tdMgp26yxY2HRq9w2NpH8v0OcZYwfo
         piSyhlkvOTLcQDriLAgzCHcAHNl8w4vx4Ov0Sv1khqHWAIHKXndTo8C+7gxGON6kN7fj
         qgZrFKcwfXobQXLvI5MUkEnNbApaEAt95FrN7GlyqkPcc5VRuigRilfIsEJa1a/JxtOx
         qKEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UPLJX6VNcA5BASH0ASuuRzTTSlyCVh/fDVEZpGQkpp4=;
        b=RwSRHlQ4b1jj2+nKbdsvrj5o1PDvwb9fEQN6ldUylGr4MaMcnMS28n1fPgN66iBpfA
         CadBzzK9vfv+wFdCG9Efy2IodL8oFpZBivLjqUrksEmzQ4VgFTDoFRFOd3pPhqGNjstZ
         edpHpxn5B64RXeLySLVUBcfzKS7Azg/kZuHxysqRnEcOFoCwQE5Urc/iAo+A7Ij6NWtc
         CRE1eG04vrxv1hlXghkuHvLoeFFPW+E5vW/HWsfqgKpgNAOXMdV7jgwszOz9h3jJl3hI
         jEAdza9ttJ/XVVNsFzh8UlfxcoIcfhgQkfM5nSY/mc4iqZMGrJ/Va9v00xSJ7LZqRirA
         9pqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306xMVsHMD4gG5Eig9gHvD7iq5ffWYlRi0ItNfhN4FR/ZqQDMR7
	enouP0I7TsGlH0ZSXxzJD2o=
X-Google-Smtp-Source: ABdhPJyJecfIBnXreVw6w9uvyLoNteu8WtgObZgzsoGXzVWqjPw3FvSYZhMDWSCEihD16iN2mUQ0QA==
X-Received: by 2002:a19:4ad6:: with SMTP id x205mr3912535lfa.128.1607108643659;
        Fri, 04 Dec 2020 11:04:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a02:: with SMTP id q2ls3452816lfn.1.gmail; Fri, 04 Dec
 2020 11:04:02 -0800 (PST)
X-Received: by 2002:a05:6512:3137:: with SMTP id p23mr3642313lfd.67.1607108642562;
        Fri, 04 Dec 2020 11:04:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607108642; cv=none;
        d=google.com; s=arc-20160816;
        b=genRrOQWSlP3dGmHLET36/bEQjBrZMyp+GyKtE0vS1PpnCPf1sTQw997cccYgQXwTg
         7QtVPqRDMqkc3Tj8clI6sWxGYYMbazJ9k0g5/0yM950nxGrJnhsPqzr6kzPltv3parbD
         kz4GKZftLYptMdTM40VvHoLYIRqYJ/gaVJDrtGa4mUfNQHXgSws4VfXENiOBtY5DqcYN
         QTXKWIo0wNsdA/ehelBT0Hkh8wTLCbMO4jbqZjWdXW+w2b7/kMuOTgLqteeHwrSW/Bly
         oqyAzVp5XuN9803bGErupbE7dXl8DS9AWsDAL12V1OezqGT6JgjmfFbcGKw0Zov4qZlE
         n9yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=MqRGZy01kstwz9ClfAxBNg8au7mjb5Di2jtSuxAThnw=;
        b=q5S43e8YAYtxp2i3J1mVacV/VcfEiACnZX2gQDcIKazkStA5vITtvHpAizCHYM9jnn
         oL9+xr1KCyPRTJ6gNQJeP9zEJ2CmUMNq9WaoUDJWIMzjMls4oyvzM20UUqIPuvUx0UXZ
         +xgYN7sFPD7IatKnRG3ndQ4a8PUufK1t3usX4omC54qg+KwW22yNE7h/45x7Gu3dj007
         +7+hqusgI8InkwX9crLp+ELvJMNcBHqc0RyitLhHYVP/t2Jdhim+8LBtp9+ZXGbBh+2I
         Ge0lyS1qYsPiWfSpSsDDx6J/0g+fPmwvE6e+pc0XycMP1eM4lfmTo2SEFqMcngcGOgIW
         2sgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cKh7YAPy;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id p13si248801lji.4.2020.12.04.11.04.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 11:04:02 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id v22so6924203edt.9
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 11:04:02 -0800 (PST)
X-Received: by 2002:aa7:da8f:: with SMTP id q15mr8904092eds.239.1607108642178;
 Fri, 04 Dec 2020 11:04:02 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Sat, 5 Dec 2020 00:33:51 +0530
Message-ID: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com>
Subject: BUG: KCSAN: data-race in tick_nohz_next_event / tick_nohz_stop_tick
To: open list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	rcu@vger.kernel.org, lkft-triage@lists.linaro.org
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, fweisbec@gmail.com, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=cKh7YAPy;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

LKFT started testing KCSAN enabled kernel from the linux next tree.
Here we have found BUG: KCSAN: data-race in tick_nohz_next_event /
tick_nohz_stop_tick

This report is from an x86_64 machine clang-11 linux next 20201201.
Since we are running for the first time we do not call this regression.

[   47.811425] BUG: KCSAN: data-race in tick_nohz_next_event /
tick_nohz_stop_tick
[   47.818738]
[   47.820239] write to 0xffffffffa4cbe920 of 4 bytes by task 0 on cpu 2:
[   47.826766]  tick_nohz_stop_tick+0x8b/0x310
[   47.830951]  tick_nohz_idle_stop_tick+0xcb/0x170
[   47.835571]  do_idle+0x193/0x250
[   47.838804]  cpu_startup_entry+0x25/0x30
[   47.842728]  start_secondary+0xa0/0xb0
[   47.846482]  secondary_startup_64_no_verify+0xc2/0xcb
[   47.851531]
[   47.853034] read to 0xffffffffa4cbe920 of 4 bytes by task 0 on cpu 3:
[   47.859473]  tick_nohz_next_event+0x165/0x1e0
[   47.863831]  tick_nohz_get_sleep_length+0x94/0xd0
[   47.868539]  menu_select+0x250/0xac0
[   47.872116]  cpuidle_select+0x47/0x50
[   47.875781]  do_idle+0x17c/0x250
[   47.879015]  cpu_startup_entry+0x25/0x30
[   47.882942]  start_secondary+0xa0/0xb0
[   47.886694]  secondary_startup_64_no_verify+0xc2/0xcb
[   47.891743]
[   47.893234] Reported by Kernel Concurrency Sanitizer on:
[   47.898541] CPU: 3 PID: 0 Comm: swapper/3 Not tainted
5.10.0-rc6-next-20201201 #2
[   47.906017] Hardware name: Supermicro SYS-5019S-ML/X11SSH-F, BIOS
2.2 05/23/2018

metadata:
    git_repo: https://gitlab.com/aroxell/lkft-linux-next
    target_arch: x86
    toolchain: clang-11
    git_describe: next-20201201
    download_url: https://builds.tuxbuild.com/1l8eiWgGMi6W4aDobjAAlOleFVl/

Full test log link,
https://lkft.validation.linaro.org/scheduler/job/2002643#L2019

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg%40mail.gmail.com.
