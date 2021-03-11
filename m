Return-Path: <kasan-dev+bncBDEKVJM7XAHRB4G6VCBAMGQE3NNY56Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 049BB33763C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 15:55:45 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 73sf4158355wma.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 06:55:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615474544; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJjk3CwnRaA90v3MIo2hIxPkfPAvbSjl6SvIbGPmwwuv4oOumjasWdiHzZ6Dity5LS
         +oLdK4skzekWSmmnnG5DGWLJFlvxkclmr1I0fskmp5N2U2Fv1vtvnctEieDoTwZ249EW
         ExNGuOJmZlbogLD4NRZthNoLVCCZ08/+j3hQOO24PP6uJviXUAJSSuWqwiYwVxh+4Pau
         p1SZU/R4w/8iQc0QJBZDAb8T8R9VKh2+n3875j9s+4agPIerLmr7ndEoJaAgr8HB4YVb
         amRck6jpug8IO/G7UPUcD6+OeEcs95CjBf5ItYycnBgZgMYknk13+y70ZooSj7bSL34n
         nj5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=PTgFEtX7SissoQdtCznv9bRMterCmNo/XaWYTzGV+x0=;
        b=NUye6tKwFArzK1v8k4g/Mo/eAd4GZhPkr0VdTASXi8xxHeJmW1H7afkwXswYh0sVJc
         ZdFNsgI7AZeiHggJr/yvRy2pArjL1VFSdZrh2sIvycArz3ybGxfKHMHEz/FHXKguE5N5
         A7gRoCUflIGN98SVqweIrDPIaHM10TswAmEqeHmoneU+X8o2MRJAMQ0C5owpD36+7TfR
         FG5FIcsjoO/n2bmRhI+DcrZ1dkH96d2eTuMBnaxMUutS/1rySjy47sGifQ8Zj4j5uR7J
         FXQ2MeMi+eNV6zfyRBa1BoQakh/4lWRqi8OVqt1uQHT+AiOP3uBJK+KlwqVkcoLPm7Vh
         jlvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PTgFEtX7SissoQdtCznv9bRMterCmNo/XaWYTzGV+x0=;
        b=av8DRJUhT3XeoMKF+IwoOqk6gmHmatdXxZmaJd/n2VwkmAoITr5OlXOXpPfKnpaPWd
         VyPRKfXnspmSWZvYPcJtWMqmI4yYkhw74IKVLnBwftWUNtGe0qnj7w4MU99jiP9ETmWB
         UOAUF6VLyLtaWCr3FwKr6ljGBMFd+Sm6FPLEYQoQLwgE9jqDTEG4VsX6B/omVG+Q/akP
         hACM/0FMha+8yarkN0If7gPkcdCai9k4rf0GnnxmJlHRGdPe5sN3V5vI+kZlVmOYY132
         cUR0CSwEGozXcGD2W+hr9mqU8QRE7KaTscfzvW3RHKNBSP2HksqVE+i74IxU2Ib+F7tz
         B8oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PTgFEtX7SissoQdtCznv9bRMterCmNo/XaWYTzGV+x0=;
        b=d0ZV1uFlEdVwBm1bd0GHTMg3xmnY1iqKuii+xBIiK70j72D2qPJ/ApYjjq1EQ7DCcM
         BUMFbY4EtPG8+0S0xTBACnDQ6y1L63cSGR1tNIOPVtdZguBTFTdmxxR87VQv9SDidlZw
         3R5BGgscdlNyIWCvwIuzgKHyZp4dFIEQKZJwdcqsvfrB2ekbdZofbZlgQWVVbptbmejc
         LgA2Gy2QIPW8r5YXJE47ieep12J+8MO3L3uATAZUUhEDc0HQbBblRyQcN0KKT80N4xjc
         14U1AYsSQwpdhBthZlzNgHCSKqKWrYN5c4jyWdI+rFihbd9KOMmKHEjLA+KT6sN7onXj
         V1EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305Zbh9/upUqOhMUXvY1TR3cDkIkkT8hKtr+Whu3IKDiFzmMg2H
	eDt3cQcBO3AJq6Xfss7jvp0=
X-Google-Smtp-Source: ABdhPJw4OlUTM5vy2fQQN6phMBmqsJaAcnWZp9FZDtxCYJTV4bkmyMdDmeGZ0ZffdNd7ottrLJsdAA==
X-Received: by 2002:a05:6000:10c5:: with SMTP id b5mr8979621wrx.347.1615474544726;
        Thu, 11 Mar 2021 06:55:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls6072148wrd.0.gmail; Thu, 11 Mar
 2021 06:55:43 -0800 (PST)
X-Received: by 2002:a5d:534e:: with SMTP id t14mr8989313wrv.202.1615474543940;
        Thu, 11 Mar 2021 06:55:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615474543; cv=none;
        d=google.com; s=arc-20160816;
        b=ad5F0fO3eOpy4D0imdpMPECSO7JF8x4GvadoBqfpXfmbu9x/5J6MyW7wTRDLrBvYcD
         jdwiOZJfBTpl9fayKqUxF1fKv8+yJ4kUlOfKqUxDHlAEVLYMe3bcFS7N7Is5NoFNPZF9
         JH6vtwrFMLNAs3y537IEbjy9TyooZGrFqIqQy1SgbUSrlAukGg3f8kddBEshzfhtwypx
         Wk8nhY1D9qX6d9gXpLwkZcumtOQwUPJ0WQDV5WeGGCGFxfW59lALJZryhCud173xA/9X
         /NTviKEWgM9ESOc00AjqhiFESfcJYj80f9fbkIBtCNDghq81ouOJM/i/cJkp3A14466l
         9nzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=wHwGDt09HWEdIRuFrVwkqB8XvCJtvg043V/gaLO8G34=;
        b=efsXVR/DjWlXOT4vOoI+f7XhuHYF32Y1XOAZ1V6inGWx5ZUP69AOzmPUFoFt2snhoD
         PYwrdGjqGTT9mu1JieWWGUaJpSL9PBj6gWIY7t0IR2oFBiEkkLDShwmBnPJWRtWvcPma
         VXPAyiFYnUtyqG2PdD9D7cAVVLuoEkuUBxSASdjZdSdLlfI9JFpHT9OWk8INfXV+Wkz/
         NW/JAuPejW2J0HLOfb9aGbNTH32MoDTkyqc08z6tIhibwMpwPOehtsFGIZkQhQ64tVyh
         x5IoiN4myKl3JTRYXFZjo9adXvHHYtxeaKkQt+fdJSWpl7Bs6Zp7Uw0I7KbtbEk5YXmn
         1WGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.133])
        by gmr-mx.google.com with ESMTPS id q145si98472wme.1.2021.03.11.06.55.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Mar 2021 06:55:43 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.133;
Received: from mail-ot1-f52.google.com ([209.85.210.52]) by
 mrelayeu.kundenserver.de (mreue009 [213.165.67.97]) with ESMTPSA (Nemesis) id
 1MuUvS-1lbcQX1OpG-00rZxS; Thu, 11 Mar 2021 15:55:43 +0100
Received: by mail-ot1-f52.google.com with SMTP id b8so1706096oti.7;
        Thu, 11 Mar 2021 06:55:43 -0800 (PST)
X-Received: by 2002:a9d:6341:: with SMTP id y1mr7186603otk.210.1615474542010;
 Thu, 11 Mar 2021 06:55:42 -0800 (PST)
MIME-Version: 1.0
References: <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com> <20210311140904.GJ1463@shell.armlinux.org.uk>
In-Reply-To: <20210311140904.GJ1463@shell.armlinux.org.uk>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 11 Mar 2021 15:55:25 +0100
X-Gmail-Original-Message-ID: <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
Message-ID: <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:Pt+D80bGZR/8NOp0hBq2OafGrnmjoJ5cwpLVLBiqirT24+M5v9J
 2JZWs5YC+xtobEGCFSr4haLi9d8kR2XSMYqyeoZEfhTi32ghSm/OullsAIcuqbyfjj4dfZE
 5AkDS7Ti1KEBcCVv6o+mqXVhTALtVk04an2lWDQZVhrCc2CxpZYgiQZLKlGQXS7bUNtc9O2
 9oHzkOTv1ubzdlXCkVdUA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:3FA9lgG/RIQ=:YZ6wlkqZf8v1RTKdvgaVsS
 y4/5Cd9o25JD0yRKEarBdJbPq1aa8meiRSiTu7d8vNhMfHPljQQqGg4NHaDhoAoru2wfoSI6v
 sxUNq/NlHLyd2Ls0PeOsA6YlLuK1yIKGn2Y/wCXruh/N6r/tTJ3QDRfsKiOwlXekYQS+nxiPx
 SE8V9VwJJXLcV6Z0URwg5DdM2bb0t/oQRSkIDx5bFt2vLgXiKmtKn630SIvt4FWojWYUx986A
 kJ25PZviid9dTmcofXkgefyNCb2hIiyf9xDKZsQ9XJa4P4CYmmSoddsWy41b5DYSNtMFlpFC8
 /MtAkPy+lkhV2xekQ2KuQrVdLReXtM7yDCfBnmU0Fp8CF4KeO+bxtKDXVAt2OQlH0WfiTrjnl
 FEVEtPnnBZrz9GXHjJvenaKXddrgggUKKd0qG6nTQQ1bEPw9Yv0g4/4q1aXUS
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.133 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Thu, Mar 11, 2021 at 3:09 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
> On Thu, Mar 11, 2021 at 02:55:54PM +0100, Linus Walleij wrote:
> > On Thu, Mar 11, 2021 at 11:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> > > https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/
> >
> > I am still puzzled by this, but I still have the open question about how much
> > memory the Go runtime really use. I am suspecting quite a lot, and the
> > ARM32 instance isn't on par with any contemporary server or desktop
> > when it comes to memory, it has ~2GB for a userspace program, after
> > that bad things will happen: the machine will start thrashing.
>
> I believe grafana is a Go binary - I run this in a VM with only 1G
> of memory and no swap along with apache. It's happy enough.
>
> USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
> grafana   1122  0.0  5.9 920344 60484 ?        Ssl  Feb18  28:31 /usr/sbin/grafana-server --config=/etc/grafana/grafana.ini ...
>
> So, I suspect it's basically KASAN upsetting Go somehow that then
> causes the memory usage to spiral out of control.

I found a bug report about someone complaining that Go reserves a lot of
virtual address space, and that this breaks an application that works
with VMSPLIT_3G
when changing to VMSPLIT_2G

https://github.com/golang/go/issues/35677

If KASAN limits the address space available to user space, there might be
a related issue, even when there is still physical memory available.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2JkcvH%3D113FhWxwSFqDZmPu_hKZeF%2By6k-wf-ooWYj-w%40mail.gmail.com.
