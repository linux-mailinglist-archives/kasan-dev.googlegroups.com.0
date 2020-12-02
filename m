Return-Path: <kasan-dev+bncBDGPTM5BQUDRBWGYTP7AKGQE34VY4IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E416B2CB237
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 02:22:33 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id b9sf41910qvj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 17:22:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606872152; cv=pass;
        d=google.com; s=arc-20160816;
        b=jyxVNIS5uPSFWFpfe312C5f+4dLQxVbJYou9pBQdv71zQzulq59cFtpSoJMMNbqsWI
         ufTc9uhsE4SCuH/LzjZdsfUnwlW4jcSf6dk1JgpQtL/ZVWo2B7rWJfT2UQzhBvrHHPGx
         GghHEd7HMBlXUXhQzYyEgvBFOARYahgahK3vLSrSdXOsWZ8ywN27zdCPxDQMwIN/UnRD
         WbnZhhxs2ZW9VniiDn3GRQH4qByhZ9IncTOeTGxM6Bau3KNKAqgpha2b2fPARNUnjVBf
         dlzKmQ1AqjjYBPg+oEBju2Y6ygb2GNrR4fRSNvDyw2FQ4miTXnRmEH1awyPqFcYb6NFn
         JwRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Ydl7lmPl3snLpYFStPoxjOhhwqEWiElGYUxCuiDHI/M=;
        b=JGAbH45+vMd439K5Y9Qbybjrc68lRRKxlPdCpKs44bnFl9aW4yWRCATUY7/02wvAXC
         7h9uBLzqr809dsfgzra8Ojs2gBkheo839REJibW2g5BvEPbn3QNXqAWgW3vPGPXh0V8w
         OsvhsLHB7t/t9xEHJyOLFQhQyzEnXBpzzKp8eIlOpZ+/JFMCQOu4i/+0RToM5/zcMb8p
         KXIKSfwNoePo/4+TwlT/CZQqOtIM2TGKbVmqU3E7b1PNsJy+x4URec+HCvhqfqlwbEzq
         a6kMESIJQaYT1uFMjy6at9Eai3PdU4tjF8KKOqfCr/jOYEtkTqjbiHWqS+RH1p3dIA5u
         m9Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BcCp9VTj;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ydl7lmPl3snLpYFStPoxjOhhwqEWiElGYUxCuiDHI/M=;
        b=SDJARm+ClDEFI/rG4cxkEUbi0cbhwkw+zmTAgwxES3luLVkTeVZNzot62C6S+AWi08
         BU9chp5ss1KqRyzHxzBCJ3KGnxZJw9bi0bQ8J+lgZ4CDq9Wbsm1IoIFyxShEJtW8jiRm
         ldaemFbchaWkR641KL51IILRLeOA70qI4pJqF2K84KZ0O7t8cel+MllJoijpjnBOQBGe
         7lvNL7ZCPdJdqqtYvKIXVxt1cgPyD/cRO4EOx+z73Tn9ciJeVXFc/OxtSk4hSf/vRzEL
         WENVqf11XfwqabY47mPdPvoiK+gkEkDZUmx7WMccF4JEYqdxZNrIytfTp/6XmpLj0Iih
         OXRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ydl7lmPl3snLpYFStPoxjOhhwqEWiElGYUxCuiDHI/M=;
        b=UdKfWuNniJpv2eKgu1u1NXd2Smmy+esjXyJCF/L2f65RCwGQ9IhP0ir0HuJqIRc3/E
         xil72OhxBn0mWY406fduEI33+poPbCuTMsxU3KRymYKhPJoiT4fCOnMZ1Ognnaf6glaF
         1uMg0e7/vMVwztxrS9z3FV/dHFES+mQLWXJ9JShEzhJcD3Zs6hOzMXEfVYnMTtfHFlTn
         imnoDDQsKT12ZrKT6F237ZU6FnaAQWBL6Elh1BFSO4D6sOpM2pDwDIiGZ5xF122kd/nS
         YDNstguudrL4fk+lmffbUX+pw7D700AkiGHirCt81vJLpGDe2/bDS7jBtWd5ahrCWtQ1
         QKqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530m17YweZMHJ4/lBFppcmt+NLaFlF6cpa8Obk+m2VLop07EDOSd
	eyaPSRXi23+s6H5pgrWUgek=
X-Google-Smtp-Source: ABdhPJxoJgemmD06E5FqaQ4FxJbDEAIacoDv3dM/uPhX1BHWnoWpySh+wATHClHypCSIZwuez7IrGw==
X-Received: by 2002:a05:620a:22b3:: with SMTP id p19mr346691qkh.180.1606872152831;
        Tue, 01 Dec 2020 17:22:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2985:: with SMTP id o5ls8330qtd.2.gmail; Tue, 01 Dec
 2020 17:22:32 -0800 (PST)
X-Received: by 2002:ac8:545a:: with SMTP id d26mr337914qtq.390.1606872152443;
        Tue, 01 Dec 2020 17:22:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606872152; cv=none;
        d=google.com; s=arc-20160816;
        b=ROYVbE42qGLtHpHhoMjSL7rfouJbQG3YrgxxlpoA/VzzM3JNp9fabvoPdP/UzBtbtU
         bdLoCGq23tK+wfY4+/kQbIUMdIHim6XKAt36oQzf7ItIoVKhhO6lM9D6aYSItYHHZARu
         e/psA9mduOVRYIoapvk6Wb6VWUXx+dBVf4M5IzN6xgShmZzw+ppWlO56yV7WPqqEE5or
         VPPmK8i1IeL2AUc58CUrgwKkTLKflEe6YpTX5eG8saf48NBZ8OMuPVoI7AKqKQZCq5K+
         q6sXE2mGjXsGVY3IWN6wXj4n61um3fo3o4onfFqpo5sBSKy6+3Ukx7IzlAnZlmyKkhPy
         1Gaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=aFh6DrFU7jAcnRRxu+a/aUKMgiC608ISwon0hAJWMbM=;
        b=CqGQxk6mcTcKs7ZaYSrsSejPUxhynNcx8ESsWoiAqfFJ8TiSzTih/qYrfWQmuZ+tF4
         xKmy5XCKsQxK/uvgEW4GIZqKqFlBrPtjR0x/4qxzW/X2TMsK5VOHxvXdyVqnXNOxatdS
         BoiMOg2o4SYSXSPaPa1vdkvkXuSoIaUkSv2A8619wvoq7cTJTRiCrBioowWJbMt/zDOK
         DvBeKf8uZ0jf+7ewjrv7QVHB9d0MOer8qa6oKGkAQvaRTODx+DBWOVRtjYz/J2QCTDgX
         ghnvj0lX/mJwYtge3c96gd040DjZkA7tSzYw+hdZE4lra6QrwlUfnxoNF5p0hZXvVnuW
         MtWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BcCp9VTj;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f16si9930qkg.3.2020.12.01.17.22.31
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Dec 2020 17:22:31 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 9e56c2ef1aff4e988b1401ccd7d4429c-20201202
X-UUID: 9e56c2ef1aff4e988b1401ccd7d4429c-20201202
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 551974189; Wed, 02 Dec 2020 09:22:28 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 2 Dec 2020 09:22:20 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 2 Dec 2020 09:22:20 +0800
Message-ID: <1606872145.1015.5.camel@mtksdccf07>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Thomas Gleixner <tglx@linutronix.de>, Andrew Morton
	<akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 2 Dec 2020 09:22:25 +0800
In-Reply-To: <CACT4Y+Yy8S0L18u3q1Y1K1r-qqXRWzrVVLPNR_En0hJ9nX7Tbw@mail.gmail.com>
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
	 <87h7rfi8pn.fsf@nanos.tec.linutronix.de>
	 <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
	 <1606821422.6563.10.camel@mtksdccf07>
	 <CACT4Y+Yy8S0L18u3q1Y1K1r-qqXRWzrVVLPNR_En0hJ9nX7Tbw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: C1099CD3A8527B7642F07659FBF80227BD8F9D554DF4ECC02ABA034D081813CC2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BcCp9VTj;       spf=pass
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

On Tue, 2020-12-01 at 15:02 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> On Tue, Dec 1, 2020 at 12:17 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Hi Dmitry,
> >
> > On Tue, 2020-12-01 at 08:59 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> > > On Wed, Sep 30, 2020 at 5:29 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > > >
> > > > On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
> > > > > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> > > > > In some of these access/allocation happened in process_one_work(),
> > > > > we see the free stack is useless in KASAN report, it doesn't help
> > > > > programmers to solve UAF on workqueue. The same may stand for times.
> > > > >
> > > > > This patchset improves KASAN reports by making them to have workqueue
> > > > > queueing stack and timer stack information. It is useful for programmers
> > > > > to solve use-after-free or double-free memory issue.
> > > > >
> > > > > Generic KASAN also records the last two workqueue and timer stacks and
> > > > > prints them in KASAN report. It is only suitable for generic KASAN.
> > >
> > > Walter, did you mail v5?
> > > Checking statuses of KASAN issues and this seems to be not in linux-next.
> > >
> >
> > Sorry for the delay in responding to this patch. I'm busy these few
> > months, so that suspend processing it.
> > Yes, I will send it next week. But v4 need to confirm the timer stack is
> > useful. I haven't found an example. Do you have some suggestion about
> > timer?
> 
> Good question.
> 
> We had some use-after-free's what mention call_timer_fn:
> https://groups.google.com/g/syzkaller-bugs/search?q=%22kasan%22%20%22use-after-free%22%20%22expire_timers%22%20%22call_timer_fn%22%20
> In the reports I checked call_timer_fn appears in the "access" stack
> rather in the "free" stack.
> 
Yes, call stack already is useful for it in KASAN report.

> Looking at these reports I cannot conclude that do_init_timer stack
> would be useful.
> I am mildly leaning towards not memorizing do_init_timer stack for now
> (until we have clear use cases) as the number of aux stacks is very
> limited (2).
> 
Got it. I will remove timer patch and send v5.
Thanks for your suggestion.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606872145.1015.5.camel%40mtksdccf07.
