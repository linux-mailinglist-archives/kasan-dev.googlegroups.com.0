Return-Path: <kasan-dev+bncBDE6RCFOWIARB4H3WT6QKGQEMNNBBDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96D052B0705
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 14:51:46 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id c65sf1824267lfg.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 05:51:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605189106; cv=pass;
        d=google.com; s=arc-20160816;
        b=UFeHKtRTi/WumCt/VG/gnr3TCHmv0UVLESqlvTlq0L8pq9+QexAMke0ynKp5kloARX
         ZJ9n98wRizok6e3m1+S481mJnY/4lWk4L2T//jphKjkGNgdTiaW0VdZ4hgHHlK6916dl
         SbY2WH4MbCNJj6MNrPJ7wQwvkClP2CODpM+fSNS3P9ooTyxqNjsYvEpCjgEXefX31DJk
         1c9DsfkLc5x1qCnrkk9MzNLPxgUq+d9W7WFn5cbltCSwd3YgwkhF0gARPSOcK8FnjbaI
         dDXZxwvdFVcbW/2q4BGND2Wk7gEM0Le3/Epqxq3brwR8hfMH7jwZgLZ7bEmReB26M93o
         DwNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=vu4sBp8aRdYm2xpfdI9T7g2evbb5Bwwn9jGfunH24Ns=;
        b=jdSRCKvdiSc8IF7CooJG05SDWHvCDQFgOQzU46oM4q4XrN7pWGs10CAVtTm36YOoYF
         Ri1vnjrQnusLnZx/XsUNb3GYJfAXr8cmIMF9qGTbFYso+5GDVJUPgVHLa0ps+NFM1AhB
         gP+nTz0TVoCkeFQPrZleRr8Raspy+kKP4z2zy3hPDhXrqqVUZkZ4Us7IVXMQoJ5IMZdX
         K/RxyIf/Ul2BySlpaGk7r5AxVYQQtpnn8Y7PaCUQXQGye1ycYcWu/0zY/Q23jF0Ez46e
         XURD8uvRCEvaXb2HyVQJQ2VyG97e/LgO//Ii/8IHDz39ZmnDP6dsurz2dgG4mCfRLIyC
         Vv+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cYCXhCMh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vu4sBp8aRdYm2xpfdI9T7g2evbb5Bwwn9jGfunH24Ns=;
        b=RqGFbxuMtkwtnurmoA8pF1aD8gJ7G/4ECgI1ErREOxKVQb6aPvQKS2e6v0cOeQXE/e
         cAujkA/Tw2xnayixMxj6/sHc+rW9AzRPDqgFv0pumDVNfoRyz5EH3eC6W0gbZwFE/SVX
         JdtLYuePNyFI2walMW3DvZzGHvCHBXh8YMHYWakdQS5RsyK3nKC52W33eskUcgH77Moy
         v+VUBmb7JKOKSbTOLqD663whCLnIA/bfLjaDNZnmikjtfykfX66DdqSq5fmLvjX7xIyz
         uOCZT6yypv8i7nhjCQrVNe7N7brgSU/l758+4F2EvSrk15YIz8Rt4pEas9cKza0+yTWf
         4Ohw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vu4sBp8aRdYm2xpfdI9T7g2evbb5Bwwn9jGfunH24Ns=;
        b=Egj1RUfzAxVXilDqM8ZD6NF0UOJp7GzCl+QWL44PZxmJlY5RDnaml8JU0tbyvbfoLm
         6qBda/0pi7TAqEdpz9DM6OnAHajiOjXbukkVFayf83GfuIqyfyIGmCTj03pWRCPpbi2y
         bCpxhJe3R4OVpBxsgfTjnV879IIs6kI0JPKNJoH+aa30dwqGNa2yCsazzO6M3zkIAm93
         xsi9Xq0Zs/cLlnO+rTYYo9jZHI/cBfsyHfFkLPcsbwRXB9ywsiMKWnAOtUUfdQq0EBee
         GQ+GjpufJR7i3ytyOSYle6R1exyDKFHEe+HeKa1vHi71VC0NTXwoa1OxHvcUgFns9sli
         upvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fUNJxbdsH/JGvyjCcWJ/iUG9YIcc/BY1+HgT+KU8ObyvUr7Ic
	gkwdfsnba4TNDpfrBygmKU0=
X-Google-Smtp-Source: ABdhPJxk96jIA0huGfyKmD2yxTU8B7m9GEyETavrSnqK7TfjGqV/w2oJpDKpFFP2hz2IjJSB4eiVhw==
X-Received: by 2002:a19:7f48:: with SMTP id a69mr12692436lfd.379.1605189105123;
        Thu, 12 Nov 2020 05:51:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls2142897lfa.1.gmail; Thu, 12 Nov
 2020 05:51:44 -0800 (PST)
X-Received: by 2002:ac2:5607:: with SMTP id v7mr9286899lfd.71.1605189104032;
        Thu, 12 Nov 2020 05:51:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605189104; cv=none;
        d=google.com; s=arc-20160816;
        b=lgkdy2fYKADgjxM89y/msqb3oBnqZg54n/+3N7lnKIOaloBY3VVOUW2KTpkUGJ196F
         qMCx96ih2F6sf9za1zP4U5zWJTE2ScqcHr3nWodXO663nu6p1xo1L9wDqWgKxdPGZs5P
         u9/2VkO82Xuy3YeWXAHM2EPBlg/2za4+PFDy7+na4LeJvGExiSaV6yNtuVSBJGrtmxXq
         Ppw68Gm9PCRyCUWDESCiSr9lu+1bo6IZ2L5Mf4LEFKMEPzkT72xirN9oHGtqUxpESnl+
         9Q+OtcJlCzpR4XxB73UZqmX4c61ugRrplmVtv+cdw91f8sJ7OLYnBo0/g7L6WXyLa3Qw
         Mbvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t8cfrsKjQnUN/OsiactPd1ob2JZxW02VqUHHoZOWl6g=;
        b=SEtbzQ65UifdFkT1lq4fBePbVh0OGa8okG309YjspjaoINFOMMGusLeiwFX8ohEjzW
         RdXBnU2f85uWTyhN6wbkUpACvPkUTe7K+5v5d8GZ5LJyu6CVfhtZkcZvmCL960qkfjGs
         WTbRqO0mpO1Fmg3DtDMEIcXPYF7ST+37U22drP3Si4zqF7GWw/wEZdYVdTWeqPHT+n1M
         LrOwXtyoTiFzbB4K83/3BtgtgPCOQVeighZW55TmZ6KHLCy2B/j37olbIT/y1YkBQ814
         TeSruXTOyIhFa7MB2vCP00PAr7U+1CjBlYRi7V2UU4t9/L9h+b07yEnfUc3xuJF5CWBZ
         qMtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cYCXhCMh;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id p1si177070ljc.0.2020.11.12.05.51.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 05:51:43 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id y16so6251042ljk.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 05:51:43 -0800 (PST)
X-Received: by 2002:a2e:321a:: with SMTP id y26mr3305815ljy.293.1605189103738;
 Thu, 12 Nov 2020 05:51:43 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk> <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
 <20201109160643.GY1551@shell.armlinux.org.uk> <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
In-Reply-To: <CAMj1kXFpJNFNCSShKfNTTAhJofvDYjpuQDjRaBO1cvNuEBGe+A@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 12 Nov 2020 14:51:32 +0100
Message-ID: <CACRpkdZ1PwT13-mdPBw=ATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Nathan Chancellor <natechancellor@gmail.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Florian Fainelli <f.fainelli@gmail.com>, 
	Ahmad Fatoum <a.fatoum@pengutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	Abbott Liu <liuwenliang@huawei.com>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=cYCXhCMh;       spf=pass
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

On Tue, Nov 10, 2020 at 1:05 PM Ard Biesheuvel <ardb@kernel.org> wrote:
> On Mon, 9 Nov 2020 at 17:07, Russell King - ARM Linux admin
> <linux@armlinux.org.uk> wrote:
> >
> > On Mon, Nov 09, 2020 at 05:02:09PM +0100, Linus Walleij wrote:
> > > On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
> > > <linux@armlinux.org.uk> wrote:
> > > > On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:
> > >
> > > > > Aha. So shall we submit this to Russell? I figure that his git will not
> > > > > build *without* the changes from mmotm?
> > > > >
> > > > > That tree isn't using git either is it?
> > > > >
> > > > > Is this one of those cases where we should ask Stephen R
> > > > > to carry this patch on top of -next until the merge window?
> > > >
> > > > Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> > > > until the following merge window, and queue up the non-conflicing
> > > > ARM KASan fixes in my "misc" branch along with the rest of KASan,
> > > > and the conflicting patches along with 9017/2 in the following
> > > > merge window.
> > > >
> > > > That means delaying KASan enablement another three months or so,
> > > > but should result in less headaches about how to avoid build
> > > > breakage with different bits going through different trees.
> > > >
> > > > Comments?
> > >
> > > I suppose I would survive deferring it. Or we could merge the
> > > smaller enablement patch towards the end of the merge
> > > window once the MM changes are in.
> > >
> > > If it is just *one* patch in the MM tree I suppose we could also
> > > just apply that one patch also to the ARM tree, and then this
> > > fixup on top. It does look a bit convoluted in the git history with
> > > two hashes and the same patch twice, but it's what I've done
> > > at times when there was no other choice that doing that or
> > > deferring development. It works as long as the patches are
> > > textually identical: git will cope.
> >
> > I thought there was a problem that if I applied the fix then my tree
> > no longer builds without the changes in -mm?
> >
>
> Indeed. Someone is changing the __alias() wrappers [for no good reason
> afaict] in a way that does not allow for new users of those wrappers
> to come in concurrently.
>
> Hency my suggestion to switch to the raw __attribute__((alias("..")))
> notation for the time being, and switch back to __alias() somewhere
> after v5.11-rc1.
>
> Or we might add this to the file in question
>
> #undef __alias
> #define __alias(symbol) __attribute__((__alias__(symbol)))
>
> and switch to the quoted versions of the identifier. Then we can just
> drop these two lines again later, after v5.11-rc1

I was under the impression that there was some "post-next"
trick that mmot apply this patch after -next has been merged
so it's solved now?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZ1PwT13-mdPBw%3DATAGOifu4Rr0mxUgb7qm-gN5Ssn0mg%40mail.gmail.com.
