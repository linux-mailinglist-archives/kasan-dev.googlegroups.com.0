Return-Path: <kasan-dev+bncBAABBEELZPWAKGQEIM5O6QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DB209C2C4B
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 05:18:41 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id z4sf9318619pfn.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 20:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569899920; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYfT1AJYIlO5e/aOhItEh0Xo4sitdwPus2ZKSdi2S70zSX664fPIdka2+JSX8uUiYB
         8KWA1uHqeo3gv6PAsOMk7fgLg3rR5fxbycf5FCmzSqXtIs1ULj7Fj7jkA4RxHKPMMuWV
         Z6NShTnLvmUedLsQcTtyhICD7svu9Mgy1pML50dmjTb6zxc7IovK+Qq91K0BzoELxo3O
         xwdPzFbGiC3xAaImvITHxiLZxcdFuC6Sq7wluwYFxWgrf5v1GlbbGI46WGOn54G7ThvZ
         L8dqmKlhrqLRYRTwuLK9oeld9YE313zgL7YwmGdw8MWeb0HVGm4hkVMPwA4i4Opt7QTE
         XLkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=7Mbquc/vBWVlQJkDqA7EUfiBnue/XruUWTDorfPYiRw=;
        b=KAX+DHrpFVFnYDHs2t4B+Xdrvsa+lWGEeRKG51IgHkuqVM6RX+575BTgKwOGeOmSs0
         g7pciAxnM92RbKA+eWpxAIcJ2OXxdMkW9sc0v+zWqTsd49zm+u/Uy84DhNuYHoJBL86A
         vQrTPWhgs2CZbgsoP0GOSojLdqKIFtgp16RNDdQ+X6SrxT3px8dGlIBx99SgNAFpmNP7
         kbCZJ86xuo1MGDp2/Lk7tGP4pWBlxkqZAUQAc/j0xjKFdKYUCbZeDJ2bPQdu1sSoVeDt
         ayesS0eySFWWwr5SRWq3/QsDMPd6/H60J/td8kRyk4Ju6UsnmZmVvS4piAbptbVxrD3D
         lAyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Mbquc/vBWVlQJkDqA7EUfiBnue/XruUWTDorfPYiRw=;
        b=XL9JLdbxBVAKgFT4ck0J/ZqUHN5LpodDfpSjd3eA/m9VtkbaUy4A6aZB7w4Tn5lolq
         aq/qaH1sAJlg2sWliE8moY/0p1rlPRhBoUBdcHH3eEBuCHm43KX/bG1kom8d720eis3W
         PFG3qHvG/PDuQ15Jts9cEkrnqQVLvm91YsTCgkeOh12eZnCanUjuZrKfolMpuz9Rtkhn
         Bd9CawoyaoHZD6gCahjh1IKb9EIjkZC28+YGCfDuGCdkR38028biZe2SBuCaf/YCSZam
         plYncAxWfpAs8aZ0k5BG8IqmRFtvelmOPePFRwc0bh/0TiV+TVtbq2xdIzvQlo1AcL3s
         eDxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Mbquc/vBWVlQJkDqA7EUfiBnue/XruUWTDorfPYiRw=;
        b=La6yDBwYTxcD2gNzZTxyhurOBlIOSzQWiLDxzcmZYaeY3y7tWO1DsxSY0KGmsLlv4E
         s0UMyXufppXFoxyWALxH4iy4zBAv6QWjY9YAkYu5EwY6d/Zszq6KzFuvtTjcPUVKw9Sr
         89WKQEpdNGHHg8qxFo4jwsnabmS0z0IXUg0HfSkQjFtvbkn1Fm0SAz9HI9CAfuA/LnLO
         0MjzKqnlYlCri3aVwn3rRC7LYIX8lHOmCFbZvfy90AqZi7SSxtbmx5a2pN0u6tkRKsPO
         6MZLrqHRSbb7+BXPA9ZREZmDjty9zhTsUjAJmLvCszmreARFuHg4TW1Ub2SroOqZFDVG
         1OJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX7vIzWh8+tRSxHE/q6JXuWt11WZSbSD6Xom18r5/blFdFZx6lT
	ZkcPcSiMT1YdmSuX4PceMxQ=
X-Google-Smtp-Source: APXvYqxUXaUUjkAKw/bIO4+t72t8Hi1Z8Sv4khU557W9iZWpioXz1pzUebL5e085Gn8FD9XzOZ+hVw==
X-Received: by 2002:a63:a060:: with SMTP id u32mr28095898pgn.150.1569899920420;
        Mon, 30 Sep 2019 20:18:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:66cd:: with SMTP id c13ls3502188pgw.11.gmail; Mon, 30
 Sep 2019 20:18:40 -0700 (PDT)
X-Received: by 2002:a62:1cf:: with SMTP id 198mr25755679pfb.31.1569899920125;
        Mon, 30 Sep 2019 20:18:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569899920; cv=none;
        d=google.com; s=arc-20160816;
        b=eXFze2qinhe1p9gJ7fMbywRGd0+y0NP2Z8TQtbcEz91ohs9A67ZKGO9td1nF/abIqX
         ac3HC2Ly5tb8j6dBAtiErU5Hkf1kTImospjHPYERwSNv2dBAK0B7bGAgLOuZTwCJKWIP
         tUT0MT+iyD27YVnCoNZlXo6cc0iulzSZ7hi52X1EGQb1ZkmkVeN04bzQ4+VVZ7aYH+mH
         Ilc7qZyrEpbcUBmTDtTDknP+Fr3JEJ2Wffh1yYjNDg9d9nNei4ubouIDfhCY/3G3yiTF
         DQuNpC37o2vzjD2n9wO+zZ0rk/I8sSE79pQ1i1w/Eek7fJEqwuir+e267W7PXthTmDLa
         AUgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=emMCDDZMe+6aBc0tIFk7bJElpP0UFaiXrSWIlmEzTjs=;
        b=e8hPxmU1AvkrHtvwDvdm5HUPlhDQ+s4y178JGXHGxWL1YGTzXGDMPx3Ecn7T93n180
         dZHYPxdF8GKqaCQMw8X+XCyxqTapEwROWQz3Ra1hskVYs2wipiTG2inpkQmP34Apyosh
         LXjG2SjGWZ1+BVwjBD9vICu1E34PU+zWQ4XKSvlBhcVmetJzoypDg6+VAjosWxfH78ZN
         60XoS1+dGkdlii6Qo1kW/1uGQNRHIDU57aTtJFyelZxQXTJ9dYKksxRDj2L9DuBFqSSM
         82zJErfVfedyf7DuKMPkRWJ/+N7Oucei7DzlDYW0tWntk83Q6ioWl0LTGX8rfRxoa6Fo
         ajtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id x137si668943pfd.1.2019.09.30.20.18.39
        for <kasan-dev@googlegroups.com>;
        Mon, 30 Sep 2019 20:18:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 271dd87e884843da8df7176d4f5ca353-20191001
X-UUID: 271dd87e884843da8df7176d4f5ca353-20191001
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1212956700; Tue, 01 Oct 2019 11:18:37 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkexhb01.mediatek.inc (172.21.101.102) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 1 Oct 2019 11:18:35 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 1 Oct 2019 11:18:35 +0800
Message-ID: <1569899916.17361.36.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Marc Gonzalez <marc.w.gonzalez@free.fr>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>
Date: Tue, 1 Oct 2019 11:18:36 +0800
In-Reply-To: <CACT4Y+b3NPemYwJJsD_oC0vde5Ybz1qDNWb=cFu2HpOTMrGSnQ@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <a3a5e118-e6da-8d6d-5073-931653fa2808@free.fr>
	 <1569897400.17361.27.camel@mtksdccf07>
	 <CACT4Y+b3NPemYwJJsD_oC0vde5Ybz1qDNWb=cFu2HpOTMrGSnQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2019-10-01 at 05:01 +0200, Dmitry Vyukov wrote:
> On Tue, Oct 1, 2019 at 4:36 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Mon, 2019-09-30 at 10:57 +0200, Marc Gonzalez wrote:
> > > On 30/09/2019 06:36, Walter Wu wrote:
> > >
> > > >  bool check_memory_region(unsigned long addr, size_t size, bool write,
> > > >                                 unsigned long ret_ip)
> > > >  {
> > > > +       if (long(size) < 0) {
> > > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > > > +               return false;
> > > > +       }
> > > > +
> > > >         return check_memory_region_inline(addr, size, write, ret_ip);
> > > >  }
> > >
> > > Is it expected that memcpy/memmove may sometimes (incorrectly) be passed
> > > a negative value? (It would indeed turn up as a "large" size_t)
> > >
> > > IMO, casting to long is suspicious.
> > >
> > > There seem to be some two implicit assumptions.
> > >
> > > 1) size >= ULONG_MAX/2 is invalid input
> > > 2) casting a size >= ULONG_MAX/2 to long yields a negative value
> > >
> > > 1) seems reasonable because we can't copy more than half of memory to
> > > the other half of memory. I suppose the constraint could be even tighter,
> > > but it's not clear where to draw the line, especially when considering
> > > 32b vs 64b arches.
> > >
> > > 2) is implementation-defined, and gcc works "as expected" (clang too
> > > probably) https://gcc.gnu.org/onlinedocs/gcc/Integers-implementation.html
> > >
> > > A comment might be warranted to explain the rationale.
> > > Regards.
> >
> > Thanks for your suggestion.
> > Yes, It is passed a negative value issue in memcpy/memmove/memset.
> > Our current idea should be assumption 1 and only consider 64b arch,
> > because KASAN only supports 64b. In fact, we really can't use so much
> > memory in 64b arch. so assumption 1 make sense.
> 
> Note there are arm KASAN patches floating around, so we should not
> make assumptions about 64-bit arch.
I think arm KASAN patch doesn't merge in mainline, because virtual
memory of shadow memory is so bigger, the kernel virtual memory only has
1GB or 2GB in 32-bit arch, it is hard to solve the issue. it may need
some trade-off.

> 
> But there seems to be a number of such casts already:
> 
It seems that everyone is the same assumption.

> $ find -name "*.c" -exec egrep "\(long\).* < 0" {} \; -print
>     } else if ((long) delta < 0) {
> ./kernel/time/timer.c
>     if ((long)state < 0)
> ./drivers/thermal/thermal_sysfs.c
>     if ((long)delay < 0)
> ./drivers/infiniband/core/addr.c
>     if ((long)tmo < 0)
> ./drivers/net/wireless/st/cw1200/pm.c
>     if (pos < 0 || (long) pos != pos || (ssize_t) count < 0)
> ./sound/core/info.c
>         if ((long)hwrpb->sys_type < 0) {
> ./arch/alpha/kernel/setup.c
>     if ((long)m->driver_data < 0)
> ./arch/x86/kernel/apic/apic.c
>             if ((long) size < 0L)
>     if ((long)addr < 0L) {
> ./arch/sparc/mm/init_64.c
>     if ((long)lpid < 0)
> ./arch/powerpc/kvm/book3s_hv.c
>             if ((long)regs->regs[insn.mm_i_format.rs] < 0)
>             if ((long)regs->regs[insn.i_format.rs] < 0) {
>             if ((long)regs->regs[insn.i_format.rs] < 0) {
> ./arch/mips/kernel/branch.c
>             if ((long)arch->gprs[insn.i_format.rs] < 0)
>             if ((long)arch->gprs[insn.i_format.rs] < 0)
> ./arch/mips/kvm/emulate.c
>             if ((long)regs->regs[insn.i_format.rs] < 0)
> ./arch/mips/math-emu/cp1emu.c
>         if ((int32_t)(long)prom_vec < 0) {
> ./arch/mips/sibyte/common/cfe.c
>     if (msgsz > ns->msg_ctlmax || (long) msgsz < 0 || msqid < 0)
>     if (msqid < 0 || (long) bufsz < 0)
> ./ipc/msg.c
>     if ((long)x < 0)
> ./mm/page-writeback.c
>     if ((long)(next - val) < 0) {
> ./mm/memcontrol.c


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1569899916.17361.36.camel%40mtksdccf07.
