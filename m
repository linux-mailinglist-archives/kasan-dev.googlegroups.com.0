Return-Path: <kasan-dev+bncBDE6RCFOWIARBQ5KU2AAMGQEIQRYCSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29F8C2FED7B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 15:52:52 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id m16sf972342ljb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 06:52:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611240771; cv=pass;
        d=google.com; s=arc-20160816;
        b=DET36ke4SDlTeGxec0fJykgagrr4u5/QTGyMW379rdgCX7hVzR32PnbtG8XnPhdPYH
         vSVLSNrH5Ze/8rWfWf7T1EJWZASPNkYSZhTp2pNoKc+VhcayrnedB9jtbH+2qZJnVLK/
         cFi+45Rg5Sby/5D1A4dXoe2bAxwuFT1dr04TExVF/dldWlLPS11nchFNrILgPO1buGot
         MTX6BGd0+4tsPFDoh6N/PMJO8wd9ak8a+UC5fSrG96iDjImCvlInWmK4PcHWFarOuErv
         PUhntlp65xTT92rWMznn6+h3Pu2e82gg/olDyZGQrJb7dPPjvLp+BrqvHZv0pZD9lpmH
         6Diw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JYTsV+v58jjkZ8tXj7PCZcQETyI7qG6mNHyn18R+Q6k=;
        b=VZVQg9OMI7/oPFeFYjOpKyXDAGoCeiIk3aiXalLqLur01agL+P4zvoOWKA0yZXVthL
         /iH3I1grkfYYsNCAlbTAwQ5tQ2lX/OZpT9OvJK/WVmu7kKLdfVhoFfex5rlYZzRBqr45
         sqd9MyOPzvyKkFDwO431K4y87G7QbMK1oXdRC92qiCWiro3GiMD5YEmzvH6qEEU1DJq0
         +XPk899mvZCBDf6q7VOjHDqhf+JVDDNnINfnKYan+yB/cWG/WHXW3bQz9W0+kkxPMXw7
         YsYATquJgR3OHx7O+wXeASNTE/9BRixejy0vuCSHdSszVrSuEXc0xgB9G8a8kVfZguan
         uGdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mBZ0FAgN;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JYTsV+v58jjkZ8tXj7PCZcQETyI7qG6mNHyn18R+Q6k=;
        b=jkxsFxsmfyro0GoklVzXSNkxlGB/yc982jBW1Z5/m7KPvVRlarzENGvABS7SrI+/rW
         gxAsOHwKdqo7HRXeIAMe/Jfv1fT0J4hnC9FPk7TTRO3IN9QeAtDQaMVgMM1Ygz3RRV90
         ltLmnXvrZcaevy4uWce8DJkArhJthXhiLjaGiGkZO6+pb2BHTK8uULBwesHMYEDYd7FD
         2SbT0jSVA7hn4IIuSpopfOpQtP+fMzspFwkVqPpAVVrfQjOLSJRNynoFFpJwg27GC+Bs
         SKII3vKEgN1dHknDChgj1VvTTuLCY0Y4yrvLR6utMeAmIhFISQ2GcqiwMJ2qNcm8eLBY
         Mi8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JYTsV+v58jjkZ8tXj7PCZcQETyI7qG6mNHyn18R+Q6k=;
        b=MUDSMF5VltutoFK6JfLFfQMHhtKutv87N0HfT2MrkBWiX4mPR6h6oEo9jMdYOkWAMP
         zGyhxSuQOBdFTBgOQjCfXeJ5MM1SgGMTt8pp6gIoDkZYnIi6xm52ybZe3XC8HJKrWRnC
         3LeWMg3/x+3yA/ODn+4mh4XncVzpKNy7dwlUCT4kfecrGCh1Cfw3x1g9rh7x8LlmkJ7i
         gIpL4Vp9NlCCmURGtqyq7sNXnTsP+DsutZ6gf9sokuZtTkDiaG+T8PhGlIfles/wAquL
         /QaE9G1vASuPwXI2I/GNXu8DtagvokOMDIuYkRaZlmEC1sOH7nxjNwliVC1qcFb8p8FC
         UQqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BV8cP2y6qRRTVTIX7xW+BrfxRf0UCNKMmaM+3E96dvT6hePxk
	zEzFa5cLSIeGdwHMvI6cE7Q=
X-Google-Smtp-Source: ABdhPJxBuGGlMpOnJcC4fxY6QUmE3e2ptEuQnDpD9YS1pdj24VdR+M+XuklYxE+ePz3wss+te9+p+A==
X-Received: by 2002:ac2:4431:: with SMTP id w17mr6393454lfl.223.1611240771320;
        Thu, 21 Jan 2021 06:52:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:51c4:: with SMTP id u4ls113194lfm.0.gmail; Thu, 21 Jan
 2021 06:52:50 -0800 (PST)
X-Received: by 2002:ac2:430a:: with SMTP id l10mr7183119lfh.22.1611240770266;
        Thu, 21 Jan 2021 06:52:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611240770; cv=none;
        d=google.com; s=arc-20160816;
        b=jWQht2DGjKx2pUrNRwtlAJhPt+7ylbyFaOCU0kCywr00NKaXmJZ9r8wSjKtttqoGVs
         uzfnyE6dBx02EEs5uf3E5VoBAmEAp40MnrplSd9BBdlDoA6YUFE7ywXsPm8aJBgijCwT
         TooHso22ctCqf4b51ajHr0Aer3SONhemygAlieVsAIs1z9Ml+wmdiRkGADcdggLLEbCC
         +LceVwfdr5RAc4AbNpIcyEGZNW4S5crrrb//gfzK2lSsjk0o0dlAjln2D+EgPYwpLRqF
         Elv/y3x8LP1eaVZUpQM5vQLPDD/6shYMY1xClSAAaAWAKOTN3OMJ5ksnfI0epCrlX6PF
         c2ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pj1k4tZdyOybbXZMQ1aye2tDNTPXV8JLnKiAXS+mxPg=;
        b=Aoh8kEfOwHnauY9luLPcUVP2TVFx2EEgutt67M7ik4vRQ/gtbpLYiq6ACthFNKEo11
         xmH6dbCxaVLSxt6w94Tq+CTRWxTM/Uwunm4gzNYUySIUa8+byp6X831PMaiIH4b5PWud
         aa60E6Hvb7cGaJuqfy6ZH1uwPOm+r7Zrrkz9SoemdZ8/CNRb/DuKAj8RsHdDkCTOcRos
         x6fjPIpU1finXxKJow7Rl4aHxhMZOyHMC6z6gJBUrEXtoqKxGnsXc3+eICsnyXLkbNef
         VlUQrCov33VZz507dD34fIOtuWB7VILhg4aHcOyMe0Wiy1Q4uA9SEvDMtSCp7IwjQDNk
         gn6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=mBZ0FAgN;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id z4si345359lfr.7.2021.01.21.06.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 06:52:50 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id b26so2864584lff.9
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 06:52:50 -0800 (PST)
X-Received: by 2002:a19:495d:: with SMTP id l29mr6551541lfj.465.1611240769943;
 Thu, 21 Jan 2021 06:52:49 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
In-Reply-To: <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 21 Jan 2021 15:52:38 +0100
Message-ID: <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=mBZ0FAgN;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Thu, Jan 21, 2021 at 2:59 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> I think allowing qemu to modify dtb on the fly (rather than appending
> it to the kernel) may be useful for testing purposes.

Agree.

> In future we
> will probably want to make qemu emulate as many devices as possible to
> increase testing coverage. Passing dtb separately will allow qemu to
> emulate all kinds of devices that are not originally on the board.

At one point I even suggested we extend QEMU with some error injection
capabilities. For example PCI bridges can generate a lot of error states
but the emulated bridges are exposing kind of ideal behavior. It would
be an interesting testing vector to augment QEMU devices (I was thinking
of PCI hosts but also other things) to randomly misbehave and exercise
the error path of the drivers and frameworks.

> However, I hit the next problem.
> If I build a kernel with KASAN, binaries built from Go sources don't
> work. dhcpd/sshd/etc start fine, but any Go binaries just consume 100%
> of CPU and do nothing. The process state is R and it manages to create
> 2 child threads and mmap ~800MB of virtual memory, which I suspect may
> be the root cause (though, actual memory consumption is much smaller,
> dozen of MB or so). The binary cannot be killed with kill -9. I tried
> to give VM 2GB and 8GB, so it should have plenty of RAM. These
> binaries run fine on non-KASAN kernel...

It looks like Go uses a lot of memory right?

Your .config says:

CONFIG_VMSPLIT_2G=y
# CONFIG_VMSPLIT_1G is not set
CONFIG_PAGE_OFFSET=0x80000000
CONFIG_KASAN_SHADOW_OFFSET=0x5f000000

This means that if your process including children start using close
to 2GB +/- it runs out of virtual memory and start thrashing.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj%2BxuS67mFAK14T%2BKO7FQ%40mail.gmail.com.
