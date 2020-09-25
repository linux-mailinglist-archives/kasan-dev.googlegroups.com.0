Return-Path: <kasan-dev+bncBDGPTM5BQUDRBENWW35QKGQECHOQVHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D044F27816F
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 09:24:02 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id u190sf514383oif.13
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:24:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601018641; cv=pass;
        d=google.com; s=arc-20160816;
        b=C3D4WHrQxGfnpTjWQSaqalc0m2tPcBVVWZ/4+rfTk19NDm9jmcV/Hqi0oB5ubx2jBB
         Is2sFHN0L4HHWVqIcRzg1zqfDaTzkFGqbzXSLg/wRexOI7xng5S+vC63UUTxyCL1e4+z
         kObDYdTvN9lHWcyfMKYtngrhcFMb9wCVjmhK0HpsTF48zdInoQBELZrqy2uffKWPhqc/
         gqoGa6/CjIjpeSsqkjnh2VlEX33jVxuNin+emqbXkfMhHDRwoTUjB/X3WcLtzLLL6wm/
         aBfdWqJ61SqfS8BKjDVTH8DdjDYPZ5v4QvA4/VZeJ7dYA8ng4ZtXio//7JOwgX/be1Wp
         oFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=QdVOIVLxwPm0sHRrhli6RM/WOH61nLhQGiZFTi6y2xk=;
        b=dLSTpCGgzCmBy8Mrw471C2OVn6VLmDkzH5b0OYsVhQh5f3N88W0Xa9Lbc6zYUIyqxh
         rEAJ5/PEdQa01gCSR036+WyNxlZFIj2j40TcHpfyaoVzLWJa3iCvBp8PgWqLRLzy+tnT
         onbR1Ik8NIdgJAMEhEiXv1HepphteyFH+UlPGdsIB8i5s440DQT+LMR1rJaOuNHdI7OU
         zWDHlDHeFygneah5EKshQWJgKnT3Dr/sPODFb1NIz7bBFu6EoZ1VbSUd6178U6Ok5IiD
         UY/aKqgLdNUUbLwdk7XVh7Akz8k69pq5WLjDa5eFztT2oy/hAuJmgBjUi2dDwB7uNiOC
         i7+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ojRsscfI;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QdVOIVLxwPm0sHRrhli6RM/WOH61nLhQGiZFTi6y2xk=;
        b=QY9pktJshBFcuJVOUAgr4QXuwkaJpdW/ndhK8fS7RqinvkwjlyaqOYkqY6UsWpm9sp
         dpPp64QZfytgPEUTNvgiqdgxucNKgRc4LyAK/H5JU610LMVKAyvZu3XmAG4ohoxCjhG9
         PbV3P2L/64dzUh7LEvsesAGk4wVW5ZQ2AMOIV+bR3C19oC5WgtbGbaHWCD72vyVw8zdm
         3ZYmnpO33sL/E1AVbA6SiU/DD506cq9htQVPIg87SxGg+GcKX0Cw9fAUIq3frYv6XlNk
         4+KRYdHU5+ZcLN+4hFCWMlQ/tJ/2zekMIhIhDGygv3GhcsxpIG8IuR6OO3t6Cgm81M7y
         o2Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QdVOIVLxwPm0sHRrhli6RM/WOH61nLhQGiZFTi6y2xk=;
        b=V2ymzodaAVDHBlc3sm7Dk9JmXupop/K72gNxTyS33adxGhYbzvi3DC0jVsG11vj6Uh
         Y1cPTn0Qv7wXzZf1BomC3koDioKf0ZLVooKEXxhQvcHQkGdLHifTYzVv0lwK2sppkJ+e
         1BFUER+w7qAjWVFlWX4TEsHdLHb9pqSKWINLyfyGqrDBu/M8S0yfCu5R52MR2r24KEGl
         i9sVDNzmDZEnn4h1MT++i/nIm3r+wGLP8no/SDzeLT3McFsM7xQOsLlws2CwDljIuuKw
         hBGruoNbc3LAGCaQGygcYHhIEYhheC7he6sUVJOzq1Hf5+iqLZQufeYjTYvoaOWGo8Th
         b+8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RhuNgqGxTuFcCmy0+KGBvZoOTTz8hfzYMHG3ez0gHFtJv5jTd
	i0GCCndNkORUyZHwVCUZT+M=
X-Google-Smtp-Source: ABdhPJzaTTCLh/KIPGzJZoGEW1mSDXq/k+1KNRomPoXGPu8oBCzPLyu+G1FX5xqNuFt9v4F3OxMZ4g==
X-Received: by 2002:aca:2106:: with SMTP id 6mr792591oiz.115.1601018641685;
        Fri, 25 Sep 2020 00:24:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4d2:: with SMTP id s18ls518668otd.0.gmail; Fri, 25
 Sep 2020 00:24:01 -0700 (PDT)
X-Received: by 2002:a9d:4818:: with SMTP id c24mr2090074otf.128.1601018641350;
        Fri, 25 Sep 2020 00:24:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601018641; cv=none;
        d=google.com; s=arc-20160816;
        b=Wa1pC4/OJxAKCA80W9hChue83Y6jOb6rfsy18Jo03knVvLr85Jzx2clnpJz2ptiz57
         Ru39/9ldh8ieq5Qf4YoS+aX1Y62rglMz30d5yDycd1EZZ4n1t/XGEQU2DDu7aotMN5V7
         BYiEub7+5ObNH3FMcIIOrH5clTNCAK72cAvpFnwRfjGveqsWPNgJwQh0wqMFYFt7ubHL
         yVYUXEt4qvZ4p8CzVDRZQHRBWDJHOCB7D7Z4+RNRiPRm/V7qUJkYUY6TF9JqJHF2n9+d
         WfcuQKI0/hwLUZKUBQNquqExGocbRIUNmpLwiLfEfkqm6dEy2E+ZZvxr9y7eBxcfrmXd
         qnCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=+dWfAWVSC8G82KV3JSBP7Prglhd5Yr0C7+OX0zeM2BU=;
        b=pV7/i6huPaXUmSJ4VdgyhkDcA0VA0AKnXY6PmpntRHz1LksiCysWUX+OZFOZnfnc6E
         49jc3gEXjetUUEa/1pH8CGOMti50BmYX4OG/ZDnrAJQ5Rr37CVT2PSPdrXyQ1v3eE+dY
         DhRI5FSqmjeE2VuTC05m/ZsvsoUge/E7FnjHBN02cADvuFYpkzlN+89dKP9HO5SKcdoI
         7KaoJwSLUsJHioBWx2TeVj16Oz3/9L3yLwm2bOERqq7erLgefV/ztHt4RqMgewJU2IlP
         fy8f1psM8a1L7A+y8jp/B+O0xY8udHY02G5B4v+eveR3jsjEpiIXygmfRsovOzUiBAO6
         b0vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ojRsscfI;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k7si107822oif.3.2020.09.25.00.24.00
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 00:24:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c0dcd319fdae4ed2b6d0e2f26bad7245-20200925
X-UUID: c0dcd319fdae4ed2b6d0e2f26bad7245-20200925
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 271370887; Fri, 25 Sep 2020 15:18:46 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 25 Sep 2020 15:18:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 25 Sep 2020 15:18:43 +0800
Message-ID: <1601018323.28162.4.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Thomas Gleixner <tglx@linutronix.de>
CC: Andrew Morton <akpm@linux-foundation.org>, John Stultz
	<john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver
	<elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Alexander
 Potapenko" <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Fri, 25 Sep 2020 15:18:43 +0800
In-Reply-To: <87h7rm97js.fsf@nanos.tec.linutronix.de>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
	 <87h7rm97js.fsf@nanos.tec.linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 3C3089F7FF02F5E21612A0E8793CCC1F5A4AAE300078785DD5266310F77958DD2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ojRsscfI;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Thu, 2020-09-24 at 23:41 +0200, Thomas Gleixner wrote:
> On Thu, Sep 24 2020 at 12:03, Walter Wu wrote:
> > When analyze use-after-free or double-free issue, recording the timer
> > stacks is helpful to preserve usage history which potentially gives
> > a hint about the affected code.
> >
> > Record the most recent two timer init calls in KASAN which are printed
> > on failure in the KASAN report.
> >
> > For timers it has turned out to be useful to record the stack trace
> > of the timer init call.
> 
> In which way? And what kind of bug does it catch which cannot be catched
> by existing debug mechanisms already?
> 

We only provide another debug mechanisms to debug use-after-free or
double-free, it can be displayed together in KASAN report and have a
chance to debug, and it doesn't need to enable existing debug mechanisms
at the same time. then it has a chance to resolve issue.

> > Because if the UAF root cause is in timer init, then user can see
> > KASAN report to get where it is registered and find out the root
> > cause.
> 
> What? If the UAF root cause is in timer init, then registering it after
> using it in that very same function is pretty pointless.
> 

See [1], the call stack shows UAF happen at dummy_timer(), it is the
callback function and set by timer_setup(), if KASAN report shows the
timer call stack, it should be useful for programmer.

[1]
https://syzkaller.appspot.com/bug?id=34e69b7c8c0165658cbc987da0b61dadec644b6b


> > It don't need to enable DEBUG_OBJECTS_TIMERS, but they have a chance
> > to find out the root cause.
> 
> There is a lot of handwaving how useful this is, but TBH I don't see the
> value at all.
> 
> DEBUG_OBJECTS_TIMERS does a lot more than crashing on UAF. If KASAN
> provides additional value over DEBUG_OBJECTS_TIMERS then spell it out,
> but just saying that you don't need to enable DEBUG_OBJECTS_TIMERS is
> not making an argument for that change.
> 

We don't want to replace DEBUG_OBJECTS_TIMERS with this patches, only
hope to use low overhead(compare with DEBUG_OBJECTS_TIMERS) to debug
use-after-free/double-free issue. If you have some concerns, we can add
those message into commit log.

Thanks.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1601018323.28162.4.camel%40mtksdccf07.
