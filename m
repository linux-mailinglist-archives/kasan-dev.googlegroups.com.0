Return-Path: <kasan-dev+bncBDDL3KWR4EBRBGUD2CBQMGQERWSM23I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 712DF35BBE4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 10:15:23 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id u23sf592740vsc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 01:15:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618215322; cv=pass;
        d=google.com; s=arc-20160816;
        b=bhMKYbmcb4FWdEmc4hJ/n0hxXkLC+SmnqO41+ARymzZovoefp33kEGU2cwVrgQgbMu
         IzpOFqbidXfjjyL4XqhywxktOtRwamNgrO7Vw6iTjs9ND6Kxlf1FpnlLQxiUZQa9ev10
         xiSRVbfbQ4kbBFQk6EvVwS/+Y27MwLho7ptR0qgPRLAHVEHrrodSzhl7SdQgSmayHjMh
         IkXhKZp7rAYgBzz0MkGXVAAbRLbjmJeIb0qkyvtjj/FCmRl9kbsw7nRvPhCLtqzN+2/a
         VhN3LwQwsvfoSoLwVW+bCmsBYdBnRyfNAlTb+uBtDtqpFINj6970UEwzB7wuKcX+0xv+
         1jMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YDllJwuI/W25PFERt1hk6a/XstDnO/3FvIL8tMbQuJw=;
        b=JfDpc2m1e3WRTHLoMQzcjzo0BFsFwBAdE09tIV49N55AOMsKNI84paMPswZCvOmxaj
         c8ylL0xuSDtUVOVsQ5ARxjW/AukTpm7lWkQh1aAF/ylpWseLKTkBtzBrP2qXgY7YaLBT
         qo4yrI8O3kxeWnqZponAOMDCslVgcFHJa8Kd27diP36odb6sAeFTIr/UsKabvktvTIU4
         dMX42DYRQfuci2jZQmpn/3TnPQPoj/msXi1mZYjfJ03HzU374XUnKtg0pY88PZ2pcW8c
         Di1mdiG+MSG94OShZ/Hg9QYvzqWl4DkTIb7seRW7gz05sRV//wsPUiHN1YGpnuLry9bA
         DQMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YDllJwuI/W25PFERt1hk6a/XstDnO/3FvIL8tMbQuJw=;
        b=O4iigkcwlE/XxRQLeCMYCRjRm1WZjCSlbavoPElzWic9dMb4l2qf4uiht6g3baRqTx
         7trsxaDkDx7hADrxkyixJMGd8UDRItflVBvK4s0peYlXx50Xfn+W8hU72pfND9tcZaFN
         rXq6L5nl8swlCFzLeSsVdJlmszkev/MGSJLa7JVUlMa4hYCSDIC/IUAa0J8DUaqqX4Jg
         lQKTLCEyo2zljf6pgOzWTiHzKojHddu4toe/b58d56SdrHpHRr9JOx4fh0T2+xmb75yT
         o2t90DuWQYJrWh8BdTJj0qXqjLwvyrLfnBXi4vYlIQN/wekUWlDyMOVd2V3QgY0ynBAF
         o70w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YDllJwuI/W25PFERt1hk6a/XstDnO/3FvIL8tMbQuJw=;
        b=ev7GTBSSYzvQr4d98/CVZRe72UUKqqFBpFEMEboHPBARxanAH4zCTj3T4L0358Pqmf
         hdJq4QF9+KuCU81DHaNycB9tqr6yXPd0dYBX2lNJOENsGkeI6B0/0PLJ1RG0GkmdAMr/
         8yI3ft3NLapeVeTx7Tp3JUUr3YbzfuyryX9mIVRfvILpafMu5m8dHwcTnP2lHJA9SvTs
         E/6xO5XK4OkU7J33/QoO7TTRglYYxbSCZ/xQRfIGMBiKD03lgiU+fc5K7SjRczZyg902
         PzoL03xxgMXV7QitK3rDVnfLiLFi6aOI1BNiL++YBybYBumoyUrOXGVBgGf8IPF/MUeU
         dWcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZMQEPUI4xWM6GGcDhDpfXD1WcqrvSDE61BlDvhgVD+53inGSX
	vDR4d6qCkJdT/E86I6DUwBI=
X-Google-Smtp-Source: ABdhPJy4Or7uZFa9tpqjwdEaDsv50IwZgadHY1vDLYkd+FpQ3+NKpePZK0bNcdrLR3uaeXZG/yVEgA==
X-Received: by 2002:a67:1984:: with SMTP id 126mr18379943vsz.46.1618215322306;
        Mon, 12 Apr 2021 01:15:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:70d3:: with SMTP id r19ls1439344ual.0.gmail; Mon, 12 Apr
 2021 01:15:21 -0700 (PDT)
X-Received: by 2002:ab0:6cb8:: with SMTP id j24mr3337937uaa.120.1618215321759;
        Mon, 12 Apr 2021 01:15:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618215321; cv=none;
        d=google.com; s=arc-20160816;
        b=RgsCoYe0j95lDEwZlhJFLMX5vpGwkWzwUloaBYG4o/vq8rasThtLKfMEubsln3hA0Q
         GaJY/GPc2KgYuuDgNCV5wcPCqP1fRngK5zF2jegqWTul1CEwa3+HUzbWwiQihJUMJL6g
         QvkiY3Oqrdd60gpV0rTBeFyDAXY4BB+f0Q6EevWKqhtzmV72qX84in66AlYPHie5Y27C
         wJGQRdhKXgIWi1bIiXnHSHF9Ey5jRNHKB4qkSIr1XuHKfs4Gt+rMrSxx0y7H9p96Cto9
         2dLwoz8Y8Exh3epjtm+QLx2+okeVV2yJR9a0e1RSJnKiT3W/WphdmMYKzz1eVgI2CjNv
         nxqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=CaFPVzFbf7fzB0behm4q3vs+AcCwPNn/fO4/oYpeYXg=;
        b=Ade3/V0bPL4160ZB/PjKyc2Da7+i5x1S+2DsbPccfCO37UFaof74BNsHCjWQ6Xx5AO
         g2fARrAUL/w/H9b4SfGMO7S/JNmQooh/x73AitPfjv6cmOdZw1+F2p4bbeBRWsJ9KqLw
         rGvQ5SVisfTx3/lqgStuL7kh5pyZkgWb06aq0ahOuStb6u7BfArgYY2Ec7OV0/5vgxWu
         NY1xtFJHx7D+Jmxg4aGT8hI8eV7pnNcP7A0mwtnLMEIVj9DI582LRcxufq62V+j3pU2b
         i7B3i835kBlaKJ7Ejm07w2gtJmG97m0Rk2XgLiaf126g9Kx/d2Vx9pDYAtylrt+hSVQL
         2CQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u13si688215vkl.5.2021.04.12.01.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Apr 2021 01:15:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6F7FB600EF;
	Mon, 12 Apr 2021 08:15:18 +0000 (UTC)
Date: Mon, 12 Apr 2021 09:15:15 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nathan Chancellor <natechancellor@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>,
	Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
Message-ID: <20210412081515.GB2060@arm.com>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
 <CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
 <20210330223637.f3c73a78c64587e615d26766@linux-foundation.org>
 <20210411105332.GA23778@arm.com>
 <20210411150316.d60aa0b5174adf2370538809@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210411150316.d60aa0b5174adf2370538809@linux-foundation.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Sun, Apr 11, 2021 at 03:03:16PM -0700, Andrew Morton wrote:
> On Sun, 11 Apr 2021 11:53:33 +0100 Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Tue, Mar 30, 2021 at 10:36:37PM -0700, Andrew Morton wrote:
> > > On Mon, 29 Mar 2021 16:54:26 +0200 Andrey Konovalov <andreyknvl@google.com> wrote:
> > > > Looks like my patch "kasan: fix KASAN_STACK dependency for HW_TAGS"
> > > > that was merged into 5.12-rc causes a build time warning:
> > > > 
> > > > include/linux/kasan.h:333:30: warning: 'CONFIG_KASAN_STACK' is not
> > > > defined, evaluates to 0 [-Wundef]
> > > > #if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > > 
> > > > The fix for it would either be reverting the patch (which would leave
> > > > the initial issue unfixed) or applying this "kasan: remove redundant
> > > > config option" patch.
> > > > 
> > > > Would it be possible to send this patch (with the fix-up you have in
> > > > mm) for the next 5.12-rc?
> > > > 
> > > > Here are the required tags:
> > > > 
> > > > Fixes: d9b571c885a8 ("kasan: fix KASAN_STACK dependency for HW_TAGS")
> > > > Cc: stable@vger.kernel.org
> > > 
> > > Got it, thanks.  I updated the changelog to mention the warning fix and
> > > moved these ahead for a -rc merge.
> > 
> > Is there a chance this patch makes it into 5.12? I still get the warning
> > with the latest Linus' tree (v5.12-rc6-408-g52e44129fba5) when enabling
> > KASAN_HW_TAGS.
> 
> Trying.   We're still awaiting a tested fix for
> https://lkml.kernel.org/r/CA+fCnZf1ABrQg0dsxtoZa9zM1BSbLYq_Xbu+xi9cv8WAZxdC2g@mail.gmail.com

Thanks Andrew. I didn't realise it was sent and then dropped.

However, we should decouple (or rather reorder) the two patches. There's
no functional dependency between removing the redundant config option (a
fix for an existing commit) and adding support for KASAN_SW_TAGS with
gcc-11, only a conflict in scripts/Makefile.kasan. Walter's original
patch applies on top of vanilla 5.12-rc3:

https://lkml.kernel.org/r/20210226012531.29231-1-walter-zh.wu@mediatek.com

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210412081515.GB2060%40arm.com.
