Return-Path: <kasan-dev+bncBDE6RCFOWIARBDHXZD3AKGQEXX6NOZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4841E90A8
	for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 12:55:08 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id o12sf2486383edj.12
        for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 03:55:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590836108; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvJiIXMsbKBgJ5xE+phzdgVKit+XLnQSPU+knTSRf31oc4ZQL5+IK0FPjxlmxpHR13
         m8lVxB89vPGTfsGKwbaDblQwxcWIsqunm2BG7ngQjsdcQW2VodS4F8Q8lgghCz73DLyR
         qapsnCiLmEr4u90AKE+4sEwCJhuf1YoVoZdBIKue/ffnKfSXxZ72MupNYVeuz1uYSdwR
         MhQL/UBpB9/kuIP9B2CBeedf6M5l8qLa7U4yqdNsEKSaF8dBe6vz/2g0dS/9/OqujgCH
         axiPoq1H46MGlkTyB4wsq1tt6nQpqamZ39W0Hq/lIbYG5gt+WYwYboJ9IdcnWX0eZ4Xl
         BE3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=GWfjyv68zLpnKAI8XkHDKtHk34Oz/DqTknN2lg14mPY=;
        b=pbYV4cKq/+HWVr1PsiLSqiWc4+ZRFIfdkIj1fdb2hucfLIlh7uoXZvWci29ZYbyNWn
         DjKyLx7NMcYkDwfFBwEjtwGE+2ywsRQc8c1tqcxHdzWcYHIVof5uSQuMNPpDBXrl+S6v
         Sudjl9YLM3X9no6AjPrAaX1RS5h9nxQZafUxauq3p5xyUAms1ik3wrdF1ayemAuFPBqc
         9/PuTpYHFP4yT9dOxP9dF4APSH1DYPD4aQoDh7dcLH0EQNMqpAnZK/wdsOn++hP3FHZQ
         wLdsEzgJ2SfRpm36hVtE1OlEnyW5yNzpZL6u7Fz7kdHnmtsyublQtBnu1zO1vB+Vg7R8
         cEzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nCYy+rWU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GWfjyv68zLpnKAI8XkHDKtHk34Oz/DqTknN2lg14mPY=;
        b=fwH/M88RnZM7LqDGlLNeUoMO1jBflkIoTOXpclaQu4RreHyUnPn3fzSh3Dxxrv2B4u
         Ct7iufYjHltbznVk8qcskUxPqXGAwK7y+kBavTOf89UalXdG3Y5WX0FZxZ5NrhQIDY/F
         encOJ01R8UKX9m9f6n6PM9r8daavFdiRVEZyxTlWdYnWJ8E+IIrkAvpE8cZvzr9E60Sr
         wLTvpLABZ7+ikQ1foadS+VOCxUrlnzE/2SFAfjt/P85PZ6oKHtABqCr3eZGNZZQVS+xC
         A3TyABAHnvMcPSheI4vysOgc7XzpkqePYQD7eSCfQDr/zBYNUGc+pNBhkCX/YzKcSQrd
         hTmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GWfjyv68zLpnKAI8XkHDKtHk34Oz/DqTknN2lg14mPY=;
        b=eSFSQEmtG/GwtVhDwVwm1GI3E7gBseZV6m3XUfuZCpPSyR85FXX3Gm/6AMf0kuW8Ai
         YtOG5TGs5ZgX8Stfz36CHcoZOz2xJ5+CdTW/LDMuUXkgn5cKYIpZvIybP+mGsMSYEOuP
         C1kt5g25lhj5LoxufE/OXB+JDVxX8SEQx1ooxBQA28VWN6Nqn/M5++jQLqhpzC5lf182
         k6m/+TFXftKfsy9oePCfFTWmbAq/sWfAUoA2iWWTs4w6jovKGtm6np5clH/pvBCI0a8B
         RgD5BunZ/oOSjh0wp0+ik0MUiz0vXJaQHgKTleiq7ujkFqz7XkI7VuOaeN3QKx1Wm7HB
         cF/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IhsH7a89hMdowPJaxf2LzWplh89sRlz4RmyrsIPTzzT0JLH0y
	iYzxzsRRgaSex8HvjsLnMnQ=
X-Google-Smtp-Source: ABdhPJwqInP99GENkbMxNYURZhCd+3oBgOSmtQcJJBvakQ8OTdDuLEhTVNyf9oCHg5nM6OynujiqHQ==
X-Received: by 2002:a17:906:6997:: with SMTP id i23mr12092519ejr.347.1590836108221;
        Sat, 30 May 2020 03:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f21:: with SMTP id b30ls1848714edf.1.gmail; Sat, 30 May
 2020 03:55:07 -0700 (PDT)
X-Received: by 2002:a50:a7e3:: with SMTP id i90mr12889345edc.6.1590836107759;
        Sat, 30 May 2020 03:55:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590836107; cv=none;
        d=google.com; s=arc-20160816;
        b=pWJXEK1oSX0RP0twhj2v0WazKbFtqNlvL0PGspAb9GA6fNIXyQMp4cDW1pUy/WGp8I
         9flHvSHO7R31gOIpu7wRxeYgNqNcUbEm2Z9iGEuCcnhWqv0rq8eoA4P+z0AZA+jf4zlg
         C10qCyeNTMbYlOaD5REO7f6jrrBpZWGd8dZ51Mnij6VWDPs2nbxDT54YRH7HsYPdx465
         w7rUJW/DSSiJDYM6g/MoMfB4pL4pP0lvPxwEC6R288hheD27rJiyLzps1TeFPRS4VZkJ
         s6eBCsXBndoUBNcQnfrAeEqIoHzteA2hZRI/OkZikQt4oN3EQUyGbDv4/6T+hy2w3uQq
         yd/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4uRLAtcSBsHA51Xx+s4FYE9j6/b2Ug2Fl2TuLRqnGjA=;
        b=VxAfAIqLo4vR7Qni+iyKK2O9SQOSj7guasBkhqm2MU6ScPMHa/p16UENql7/++bM4S
         5aKUMQ4gIr6Sr2nISq8pWLTOe0hh5UQxJYrR4c2Ls7WePIHcT8YJZU6etlni/76Y8X0o
         qs6UdTxPUaAUVUmXh/rsX4zxabiKR2UUMSkBHJnkkPCIVhyA+JDlnMCsSK4KzcU0EkWW
         Z+Qbtn9tSHBzhB9RgNNV7C9vdDbhEHiIyUmuS5eo2UUlK/MzZ/70hVUIcAvzuM7LLowZ
         awMfSLpndsoEWWTNLOKHgLdbnsV5QlY7oG04MwCAn6zBr7B/jZnNKPvj+GXTkJKSQwAs
         99LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nCYy+rWU;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id a23si180250edn.0.2020.05.30.03.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 May 2020 03:55:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id z6so2303988ljm.13
        for <kasan-dev@googlegroups.com>; Sat, 30 May 2020 03:55:07 -0700 (PDT)
X-Received: by 2002:a2e:544a:: with SMTP id y10mr1430969ljd.144.1590836107122;
 Sat, 30 May 2020 03:55:07 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com> <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
In-Reply-To: <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sat, 30 May 2020 12:54:56 +0200
Message-ID: <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=nCYy+rWU;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Sat, May 30, 2020 at 5:54 AM Raju Sana <venkat.rajuece@gmail.com> wrote:

> I took all the patches-V9   plus one @ https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
>
>
> and I  hit below  BUG ,
>
> void notrace cpu_init(void)
> {
> #ifndef CONFIG_CPU_V7M
>         unsigned int cpu = smp_processor_id();
>         struct stack *stk = &stacks[cpu];
>
>         if (cpu >= NR_CPUS) {
>                 pr_crit("CPU%u: bad primary CPU number\n", cpu);
>                 BUG();

That's weird, I can't see why that would have anything to do with KASan.
Please see if you can figure it out!

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1%2BjrLZNqVrLvKQWA%40mail.gmail.com.
