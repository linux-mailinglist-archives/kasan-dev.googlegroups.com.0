Return-Path: <kasan-dev+bncBDE6RCFOWIARB4WRUX6QKGQE5WHIPWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E99872AC079
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 17:06:10 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id h12sf1598841ljc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 08:06:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604937970; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZWnN3tYrRPPuOXLw3kt0Rm/5oeJ1RqiqZED9QLlOP9QHs7pHeCpwJfIMULAWn+PnE
         R9p9jaY42Rz0zVQ72oSTIrmwiRR7HG9fSJaKRH+QMl/0/rNSVz6kJIa7e/+DFVqHJZqk
         lwSVNgAxryqRvwEi+bdH50oszmzMwM8ylvsOJVoCh2F7wOmEHH4FwmD9qLlvVegsr6pa
         qvjEep9WKBzGXfBCP/8LQyNC0JZIjf0DrRRSpXXd+5Esg9lojcRDh8flPuG4NHmaRBWJ
         gx54rM3Qi90GEV/9h68BwJu9oJ4+2vGFgvqMJ1L//9erydHXFtuz4Vk+pVq2pYnJ3EI6
         nHhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tz4T7+YR83A3F57nKCDrZo+Rbv/6IamXZgfHgNX4GjI=;
        b=lDRzCzfUO28N1XSBuwr9tGzZ2KiU3RYfUgsWkVzlMeZTj4W+awKK6Zxgf3e9DTzCPb
         R6PizpdApvyp2wmpDvxF7jmSh8G9MngmSe4v3Auwx/bl8Zyr4Lrc3yld7bN3TE9HyN+S
         bmjjevDtG0GHBr2KNvE4HFjm9Lt2UW9FJDoRXw9jCumgsmuRLBoE1FHpX3L1lketzvPf
         Tl5ixm+LXyNbOExeAGDE7ZD5o79MGREzuzKRzX21dU1s1iQOhOkC5Ehb1YLzNKtcDEDt
         kL8/xtdTze9qep4/LjhnXMhPhP8Vlo3UvrrSZVjqI58KNRgEgB6z2+txk2a4u3PCA42e
         EwWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SVyp6cCy;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tz4T7+YR83A3F57nKCDrZo+Rbv/6IamXZgfHgNX4GjI=;
        b=Vux3JHxyENzdToiy4kAizNf0IHZsozRG+k2ZhLI1x3ssOM70qwGSL8G3UwBgIwjytD
         /zqj4PgGg8i5tuDt07SAWOHLORSXROp7Vt52nmtDhyDrCYZiq9dml3KvOOslpHAnVp/1
         Qqaz8vMIEWtSZsegWYhQtQHJUnN8+aV5PDT1618KuTVU3kqLQhvTGvr6FCBAdIleLWnt
         n8Ani/6EM3cTpi54Uo1v7IspPaLbRy7h2IZ5JJJ07NSfV9q5TCed+b2tGAe4MNExRfMG
         59rY4sLPIQaw5rlAWn6vhPGJvcrOSM/b2r6s5GUca+XvTUtiwKx9R9ZMDj6YPftORj3j
         MAhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tz4T7+YR83A3F57nKCDrZo+Rbv/6IamXZgfHgNX4GjI=;
        b=ViA0d/B16u6Ec0B88lLaCdDBVWUaC8oDiU6Z1lVyBPUj0pb7TCenpndMlYclJirP8y
         mHeWlTcyDaB6xWkXogUxHBv3pMhgsMCvNEh9NEAbKHyzYT33g6eihRHknPd6+dLWzywG
         +taEcWV6Rw1FhkUVQoO4lvvnohxi1QdUUGluuGVMlAYGctTHWIELwinEmWf4O60u/VsF
         AjfkiRO/cskLaA/hyj5m+60Hq4WJnFh7Pdsr5u8hkCFYWKKCJmw6ENpaVj9Kl0aUFZmA
         5GT1kg8eTlALkEKpVSYbMqtfBE3wq9qeKVwH7rN/KFoHg6jfwZVyN+59SXMRX/TWY1dw
         eHNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pU/jurPqEUkDqw3wImfICVrpkdfhLHao+4ovoQ9/x8NBNjhUx
	P1mHw4lTCIhfggWvFsikzLk=
X-Google-Smtp-Source: ABdhPJxXoLnbjxv7ugInaU1HwQMBBr9GyLOqjSwYlZSI4OonMgm8MZicZeiaipYbjvkUp7zIoRbohA==
X-Received: by 2002:a2e:a492:: with SMTP id h18mr6704397lji.103.1604937970502;
        Mon, 09 Nov 2020 08:06:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:: with SMTP id z26ls1522454lji.7.gmail; Mon, 09 Nov
 2020 08:06:09 -0800 (PST)
X-Received: by 2002:a2e:a405:: with SMTP id p5mr6883617ljn.62.1604937969368;
        Mon, 09 Nov 2020 08:06:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604937969; cv=none;
        d=google.com; s=arc-20160816;
        b=t54Q5+2Lr15dAHWmjm2ALtHUUGu/la3Fn82moJx20Qs0vzO1qgn7ttp3ra1ACvnPqH
         6viXKqpeDZAMjntlWeYkMMMGWMs4gsNsb394VK2kJlhNNVdVwRCuANZVpO046PDYmzto
         tBOIxolhiTL9pk++TIsW0bOBhul+nR1+inJdYGNM2WA6Isi2UcwXaXDeMi8K59IlrA/6
         xzdFxL7L+p/Ar3NSUaG5N1XIKfoi+ONfg6kv6vnjKa+MKzRAE7ljl9NgKoGdKYHn70M2
         jcuDYWeLkPP2jAxJCNO1QXnIPoJKFu9yIvbP44SSk9FQgIsTg3ohdCy43hLyxXAbzWOb
         /exw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IFQygj4KvBcSz0ButIzxQiZomFCuva3ZirqjbWYLGz4=;
        b=vly0k0DbMeGOAenQP1xVPILZuupOYVk07K3mng+7uPkSMVZWhROmzhoj4MgjRevPTs
         07qqvskszE7l4dnOuYXwcGAEm//yDFe/lfNDwt6snq7xy5YY11ghJ2Wdri50UP52BF9x
         FasJivryhraxjFMxUPABmYaJZI95phj5uSB1Dm+8E3g1V7BfzLFXPBrcOfQ1+VBw0DBU
         uPl1B/8JxRVl0UqcgxNJd7g2OumXW5FnX+VsgT1TgLwjTxLIgbQdDWdZOdDTyrHD7S0h
         E7wPWo/HvdDWECiRGyxqNSA9+YtjRu2YqYy5fCnzIK6NJxNqDjwIAy+TCzIXLyUZKgw4
         TIvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SVyp6cCy;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id y84si264331lfa.6.2020.11.09.08.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Nov 2020 08:06:09 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id o24so4293051ljj.6
        for <kasan-dev@googlegroups.com>; Mon, 09 Nov 2020 08:06:09 -0800 (PST)
X-Received: by 2002:a2e:8604:: with SMTP id a4mr6277015lji.100.1604937968956;
 Mon, 09 Nov 2020 08:06:08 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
In-Reply-To: <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 9 Nov 2020 17:05:57 +0100
Message-ID: <CACRpkdbKLqMmJbMdvw0cNyu3T4HH1KyNFmkR=AS8uOLPkR3Xnw@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=SVyp6cCy;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Fri, Nov 6, 2020 at 2:37 PM Linus Walleij <linus.walleij@linaro.org> wrote:

> Is this one of those cases where we should ask Stephen R
> to carry this patch on top of -next until the merge window?

Apparently this is being handled by "post-next" which I have no
idea how it works, seems like a merge quirk path, but if it works
out, I'm happy :D

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbKLqMmJbMdvw0cNyu3T4HH1KyNFmkR%3DAS8uOLPkR3Xnw%40mail.gmail.com.
