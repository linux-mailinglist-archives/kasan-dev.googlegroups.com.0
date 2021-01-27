Return-Path: <kasan-dev+bncBDE6RCFOWIARBIXSYSAAMGQEWQ4LTAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B4D930578A
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 10:57:55 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id e15sf668434wrm.13
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 01:57:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611741475; cv=pass;
        d=google.com; s=arc-20160816;
        b=EXR3bvJjdfjfhgf78LRks1Ld3VRM1Tls7Ex5kZoovxWbLdvu78kteHSND9tPqwHICk
         QHaADm5Bfmblgd6Q4xWF1ihuzb+y5bdkdJZnd/ddZH7Y4IH0RDzdYlELrpWSce4lmJ3x
         czXUqZPFU7F5zkcfSDSJBAvJxZ5PzHcr/BdQeNvPNskYFepAKsjWX5A4pbCZj8ejt2sJ
         PwkSODn4yEO4yBW6E6EMWj+dIYVUj/NRsQfzzl738cAmOPZOOfYvfyCmGwvti+XenTIP
         khEKguwegGgyLNAh6a185b3XxRjhOiKKXNR5xVZykh50FVURTrXh/V+F6i6UgNQU9LfQ
         aisg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=28bAOXOydDHsu+tTSCwF1tvsI3iS7NjC+Cppb5pGN8Y=;
        b=gXs+fy3u+/9oMvtRuYbRf4Oie5tZYbbPDNS/lZhQOV4f1YNq93D1OmYYZXLvsUq0KW
         grUGPOOAnMcQhWGJ/ssO6CjnVXl79USO1I/PpDpDgxfMy5HydI8vBL9FCUsQfNJUCgnz
         lr8NPxzJYUzTyG5UOZMOPWyvZ+hVeJXOyCdfBcquLnD3LOUN6UHFeM7XR6DffsuNgJRb
         ADeBXCmzomGenCGQjdOUwswkt8A/FGKOb3lGZRxQmIugfMHW6jPJEIDSS4rJXUMwbYUe
         ZkNU8OtgxfFEdpGCJVtiQrMHZ/gTnVtFOmUDmH4Du/cRaYnnKT4H7eiRZ8Rm7+DrOPt3
         cwkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=w67+eRqh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=28bAOXOydDHsu+tTSCwF1tvsI3iS7NjC+Cppb5pGN8Y=;
        b=MOaTP21HPyome3xOHQFluGOmxp52OrJnKe8H2gU47YvrLGKzeWbJ2rQvIeQskLiqGI
         lG7RRmQgUbpXiFgjnX8ROQOPgWAZgi4yOiLUbzCe4Sy1ROd/Bd14GnZLw4d2K6F4rlB6
         3w555pXuW965F+5u2c+aeRheHZGVMWM/Tz1fidg7rvqFiHORzeKBig1NvQdW2iFW/5AW
         hB9bgTux7STf8iyIpWsgKotHL3942WBhOg0qnZIKxH3Lo8NcZ/MTAofgT/RqzdNNKTtA
         0q1dDB9H+EzmJndFBty9UptVEYkKpdsvtn39+HZ/39MbrVGmxqpXFFOLfFzCd2h2rxnq
         UufA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=28bAOXOydDHsu+tTSCwF1tvsI3iS7NjC+Cppb5pGN8Y=;
        b=BExCI0dL6aBPdYjLLgzJqMw1ww7f77p04+YwlGm3XzU8Yic1zcu67A8KA3hH3zekzf
         /v1KNs3UsrZZTaBpq2yCR+m3KoiiO/470pkicoE4pMi0H1XPVnGVzX0mSDmzQcuF4RLO
         Bsq9xqyie51ksy/RA/2Kf9PVbNi/Zak8Ps8uhaGWQjtUR24e6XU3c2KuoablN/Szt3MO
         PQ8Xd70Il+E7dWK1fWRgYfeK+yq7DKEklava3YGlwrVgv5Lc6AjpOE0l3q5toN58IGKK
         2C6HxaBJc2ILYNEoaynfy343ma+syl32crnE8cubm5j9S/0Q4UsrBzfV1ncG8Z+oNKsw
         941Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rSinXT4lbq7ruXasSlfEdHpiRBUh34UU/fvfM7zwDwMn568/G
	CztZWuw9Eo85D8v+vAhhKGM=
X-Google-Smtp-Source: ABdhPJwyP+HUWuxPyWWE0pu2WCWW7XznmssRTeM0WcFF/elJ8Si1bdkbYy2fga/rMHaWiU5GIJdFjQ==
X-Received: by 2002:adf:ecc1:: with SMTP id s1mr10821556wro.146.1611741474954;
        Wed, 27 Jan 2021 01:57:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4482:: with SMTP id r124ls656768wma.1.canary-gmail; Wed,
 27 Jan 2021 01:57:54 -0800 (PST)
X-Received: by 2002:a1c:2c0b:: with SMTP id s11mr3325803wms.13.1611741474231;
        Wed, 27 Jan 2021 01:57:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611741474; cv=none;
        d=google.com; s=arc-20160816;
        b=hE1YhyyYaNrRpb1SeHzjGSV54X4wHoPfWRpSsto9QtZ53EbrIX5v5f5Cv+aeO67cWN
         Puc9HEBoEsLurdjsdT/N+YWTT1+p1EIyzghwiZ0PPUZciBya88xzB3TZlHnxoRzuOSv3
         Lw/TWojN8oZ0nzUgQ83bmyXj7OcbDMYZTW542688hww/eTVXZR9V5w33NLRaXQBmek54
         7VYIqHvA+5kvMSGPgjAEQkV5Ze/pG8loYi2FEUsvFSgxNDN4kIKikVJiP9URhbK6LUGA
         7N0SeBJffhCbh53XnNhW/AM7HB5LZv7N8WgYWCeEaS7ZwOwMZlKnbQc7BFq6cBckfC7f
         fKlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FQKHrApe4BlEDcrrI/niVsFX0HAF/8KAjUP9bDOpfEI=;
        b=Jx3jmYR+x2YAksArdhofehnh7YTyTnsXTJzNcNLgLszsSbkEjH2iDC/ti6xgQYbK4S
         MDEvTQn0xVQqeRUEIIp4jocUewe09RY4O9P7X7Tz98Pxce0H5wBnnCoWLNRxVU0aVy1F
         VjLyuVrUfW/n0d5ZRQHmwSLjaT1PLXy0L0MwIu4CNNbJGoPDylrAMzOYNZtC2nzPHGbW
         wHWBl62E226FUns0OGTFAxK0ZyoxSRsStNl5bHt1FqAFLjIhADJUx5KpuX/t68JCou4F
         TG6onOg3EK0v9uCpad7xmB/onMUwQAr9HnoUPqEKw0ytoStwszo1+1tEpJ3SZh/ap9YP
         BA0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=w67+eRqh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id w11si101043wrv.0.2021.01.27.01.57.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 01:57:54 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id h7so1797806lfc.6
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 01:57:54 -0800 (PST)
X-Received: by 2002:ac2:5c45:: with SMTP id s5mr4690428lfp.586.1611741473670;
 Wed, 27 Jan 2021 01:57:53 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com> <CACT4Y+Za1P7-g8ukSJOcy-TWurz4HXxW4wau0VsEDEgoUvuZLQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Za1P7-g8ukSJOcy-TWurz4HXxW4wau0VsEDEgoUvuZLQ@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Wed, 27 Jan 2021 10:57:42 +0100
Message-ID: <CACRpkdbQeYuy2DoG4uWi1nqP+KCU1LTcVPjsV_j61N2LL4ugjw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=w67+eRqh;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Wed, Jan 27, 2021 at 10:39 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> It's qemu-system-arm running on x86_64.
> But I don't think that bug is related, it seems to affect arm32 in general.

Yep. I am trying to reproduce with your defconfig.
It seems you are not using vexpress_defconfig:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm/configs/vexpress_defconfig
?

Instead this looks like a modified multi_v7 config, right?
Then a bunch of debugging options have been turned on as it
seems.

multi_v7 "should work" too but I haven't used that.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbQeYuy2DoG4uWi1nqP%2BKCU1LTcVPjsV_j61N2LL4ugjw%40mail.gmail.com.
