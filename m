Return-Path: <kasan-dev+bncBCMIZB7QWENRBDURYKAAMGQE3MC6V6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DAF1F304B2E
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 22:24:31 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id n80sf15609622iod.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 13:24:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611696271; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pj/Sy+5FCagmzC8JJqHgzNvWUZgFj+PtT+lqm2saMvainlq6T7fYRbuDrHD92XRbeE
         itx0cUTPLKqngLeJmpi2fYaBCZKEfHRhpm07dwXaewACWwLEl7pPYi9qAyyPIaylhRMn
         dR3p+G3FPrmEWrlMgfm6ZODMYbQ+qgHXh3/Lokz7tHoSLGrxmN9jsI5LrKdIgNSf1AEm
         /ZVVPF5zAouD0Gj3N6LRMrMmNdbQcjpW4A7BqfZZtx1NoddiHDuzYAj2wJluuQYaw7pt
         gSSd4ed+5bjO+e/Eu6bL/69shR95Hjbb3Y7rhKaYODK9+hTxJCb0P1uu7DvIj2Nnn5WS
         sW8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GBRFv5CbWFF3O2ckiXwgyfNtNWP+51djqsFEkaTbr2I=;
        b=KNKRiWACP0aSTurAa3ZxE2vsajI8DC3av0qf725ThQ1x0HPbeWOFpjvxpeA772L8+8
         PGK+fhnRuButftjxmkPoNI/lz70gd4yInsQqhqjtIOURLNI72A7l+b6EYar6V3N+/lDW
         2NVi5bGKP7+M89VgHQMkGeynXeYvid5aTeg6i6DCW+1PYsWMV3Fgog4H0MVYhHv32EXa
         udNjL6SbDKgpT0FEYs/3EJvmb0IzP0r9BepH2wGp5gH2O+tNYIszqHwaCuq+4NOBIrBJ
         BWWjfkLPbgxjrQdIJnC+VAlICfVP+cTOj+y70T6r3OsfncRX+7K7Ki9seEJ5kEt32rXO
         oR5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s6fn6Zyd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GBRFv5CbWFF3O2ckiXwgyfNtNWP+51djqsFEkaTbr2I=;
        b=jsARA1n++sqxyAqyZxYUsNcJuyzQHemt7xUEttcAq4wzk+yVIxK+PbRFh1FXhXFgKQ
         2PbvcTl5hzN8vssTL1o1ikfU+8z9leuAuWNKwGoUMPhgNV7bxDNt4QvM22QxPtiGl/+i
         n4B7kGdI2qBGqjHLKtCptP59mB5PwEUy4xhTS8vfHvsCasS02vDjh9hNwZYhMvP8EF/3
         VoWw0qoM2XPvHA9eQWZZJUbRsMziBblEES+aVqUwfwl+tmFBxiiraYBnJvdT+D0N/Kt2
         mEG3dSEAJI3yk3n6WsgVCVQ3vRON/mbKR04RGxoOEUAMnNi+LWAIWZ2QbkwsxOJx6WfQ
         BMdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GBRFv5CbWFF3O2ckiXwgyfNtNWP+51djqsFEkaTbr2I=;
        b=ExxEPij/kLJOA/zlI6nJjoQ/dfMPGbM3MU/uTN7M/JcfZjpGc2TdkPgDhnRn7C1CkV
         9MJ5X5Y2WQ8AHuLuqC26++ez5ta97w6ZDj9FGd2arJ/Rp3j8K+NuC25YQ65210cGM8da
         WL1eSjnQJNevjuxm8cVP9vbNa3PHlDdmzyAGjU1j/KGeNgC7JiUf8mf+s96F1lRjIei7
         /P6Ok4yxHaRsmaWATdG+hnU//Nf8lHLEwAEhULgVDkR5iYzgYlVYN2DlwE9H+AofE37t
         fmK6F4ZOorTNSXYz2oeM68ntsSbGDkA6bEIk+nqMPiKqD3KjWKRX2wvC2RJITJI2Xk5K
         feDg==
X-Gm-Message-State: AOAM530fBtTLoIQPkmX9JbC2I0r183M/+yBQdLaCdZoLwdQt25+LPdym
	EwWuwq6/g+2LlJqhqSwfmGE=
X-Google-Smtp-Source: ABdhPJxzfYym69BRUajxPTbiwPWchS2bU0GFCCO360+j9kqMFWSRxLohbO+6ab5BtaRmFqmeWmDbVg==
X-Received: by 2002:a92:510:: with SMTP id q16mr6085418ile.136.1611696270833;
        Tue, 26 Jan 2021 13:24:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9ed0:: with SMTP id a16ls2715951ioe.5.gmail; Tue, 26 Jan
 2021 13:24:30 -0800 (PST)
X-Received: by 2002:a6b:7f45:: with SMTP id m5mr5525649ioq.180.1611696270396;
        Tue, 26 Jan 2021 13:24:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611696270; cv=none;
        d=google.com; s=arc-20160816;
        b=zZ4vVHRruuNH2IC+aRETeDToXHj2GonwlsQ7OcDLC2LZmSq8dqVjmd76GDQSzOOfD8
         XKf/tXCzYSAhP+Qt2RkqbGEvBunMdqy5fpmRKu9rEpZ4k8MeMdlMVs9MzhUcxn+BPYrX
         V7mlQNkT6xnMOMBaZ3E4a/MFOXjSPwQyPS0ku9Xd7l4b91VHZXE4Uo4FIHb1hihX1Hy/
         +QSyZu1UpSmb97KLL1ARnd319+bStvfUwkSIIAmDNj4G4RBtqrY6qB3a/IYGtoHFfrkI
         6ek3b+0dYoB2PDdBE7aQn8GFHYYE4pVgDNA6utSgZ0+HuNzn1f6Ha1UDMa8K8iio0fWu
         kIZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A1fQVwdt2OOiml9EXDGcRx0GMW7sNw8WMhImuxn7QPQ=;
        b=iRG2+p/vfB4QL4JXOp4BA4051LSs3n5drlz7cDWYtXd0SSamjQa+EwbjXn5uMml+sV
         R/yRvH6vD6ue/ML0WPeaxcMIEIgQx9F/C0hety/dKZFFgUs88o1s/6BurYSLb17VTEhM
         hNpVpj5RhFjR71stef1c6v0AfE0LW9X1zgmP0uEw4ZofxcACBZZFv89+WzWcCqX7fwi1
         yIH3zrczccnr9fgeBgsfw86BpaNdSRpaKjTbuOmkPkHDN2wfClZXpEU/ALJC2RjrxFsE
         990RiNpaaHVJY3SsiQF6g3b1NnmVfM2uCkKLCO0mlI6VL3leyBiLNkwMCRwPEDiwrGKh
         bo/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s6fn6Zyd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id v81si855852iod.4.2021.01.26.13.24.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Jan 2021 13:24:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id t63so4849976qkc.1
        for <kasan-dev@googlegroups.com>; Tue, 26 Jan 2021 13:24:30 -0800 (PST)
X-Received: by 2002:a05:620a:49:: with SMTP id t9mr7924523qkt.231.1611696269615;
 Tue, 26 Jan 2021 13:24:29 -0800 (PST)
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
In-Reply-To: <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Jan 2021 22:24:17 +0100
Message-ID: <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s6fn6Zyd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jan 21, 2021 at 3:52 PM Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Thu, Jan 21, 2021 at 2:59 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > I think allowing qemu to modify dtb on the fly (rather than appending
> > it to the kernel) may be useful for testing purposes.
>
> Agree.
>
> > In future we
> > will probably want to make qemu emulate as many devices as possible to
> > increase testing coverage. Passing dtb separately will allow qemu to
> > emulate all kinds of devices that are not originally on the board.
>
> At one point I even suggested we extend QEMU with some error injection
> capabilities. For example PCI bridges can generate a lot of error states
> but the emulated bridges are exposing kind of ideal behavior. It would
> be an interesting testing vector to augment QEMU devices (I was thinking
> of PCI hosts but also other things) to randomly misbehave and exercise
> the error path of the drivers and frameworks.
>
> > However, I hit the next problem.
> > If I build a kernel with KASAN, binaries built from Go sources don't
> > work. dhcpd/sshd/etc start fine, but any Go binaries just consume 100%
> > of CPU and do nothing. The process state is R and it manages to create
> > 2 child threads and mmap ~800MB of virtual memory, which I suspect may
> > be the root cause (though, actual memory consumption is much smaller,
> > dozen of MB or so). The binary cannot be killed with kill -9. I tried
> > to give VM 2GB and 8GB, so it should have plenty of RAM. These
> > binaries run fine on non-KASAN kernel...
>
> It looks like Go uses a lot of memory right?
>
> Your .config says:
>
> CONFIG_VMSPLIT_2G=y
> # CONFIG_VMSPLIT_1G is not set
> CONFIG_PAGE_OFFSET=0x80000000
> CONFIG_KASAN_SHADOW_OFFSET=0x5f000000
>
> This means that if your process including children start using close
> to 2GB +/- it runs out of virtual memory and start thrashing.
>
> Yours,
> Linus Walleij


I've set up an arm32 instance (w/o KASAN for now), but kernel fails during boot:
https://groups.google.com/g/syzkaller-bugs/c/omh0Em-CPq0
So far arm32 testing does not progress beyond attempts to boot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA%40mail.gmail.com.
