Return-Path: <kasan-dev+bncBDGPTM5BQUDRBVHISH5AKGQE6UMKWMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F9F250ED2
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 04:15:50 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id m185sf4984260pfd.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 19:15:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598321749; cv=pass;
        d=google.com; s=arc-20160816;
        b=c61cer2+Rv0HYlKGDd1uFlegUMEkgM8URK4VPlA71CQg4XwaleI3wkCGMq0RDJ8Jrm
         Qk46EyrTL7zDdEaCkrFpoFUKJ9GF1W0LS61vTHvWcVMS3vRWXqZqC/tb7e2aL+Elxt1g
         W/CxMsdUF7ulf22akS4+Uo58EcaY8jcs0/7SBoXK4Z251+Y2s47SRD8oRp7mG48niuYd
         RpA878VcLQnKPeDrTEzS93ZkI7Lk1gZ0qs3PJxY1u1DjCsV0gbmx+6q2A35LZeP4qrE2
         BdcMFHKyaRK9zNRY6sgu5Ab5bBrJcylgEexpAq0sp44nmDa2kbCufODz67ErmAf3G4cQ
         +eUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=EzAEk5KkCTa+Hex6ZIVw0GVaVZS2eJllC4ZxceO6674=;
        b=NKe9aLZ7apcU1Zv0mHmHmPN4UzoJE6xzJQGpKQWuMMb7eg58q+ClKuQjskvarzFeiM
         nlHGvsNhY7hMDOSFVFTiXjfAv6Xg1WM6uisSBVwl/cNk/dNQQApkWtKrY5Z1DInG9730
         eBYOj0Qmv8sn+WFIACB/HS1CJnajn2HOGo880AG9p/LZj6RTUsKU8/+CZxMP2YRFnijH
         ZKgaEnmoCW3UUWNjfzmde8KW2tIkjDhS6EzgB9X8/AW9JfegDNkaqokWmMrxYR/f+1Be
         bOopEfMGlBintfNHd/0ZaMa8g5BfwMqJ1l55J/gTxDQLJq+vwgklhG9Kp+dXlag69iye
         7uDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=OsgvLxeV;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EzAEk5KkCTa+Hex6ZIVw0GVaVZS2eJllC4ZxceO6674=;
        b=MR0ShxQVzt5ospr2mDWul5Xuuj7BanzdpuOtdwZCd5Ewcjt9q7GJoDeHy5PLjPlKO+
         M0h0pKI2m7x6q9BzMSYOQ1DkHImuUbO9uRPY1ieGxorpRKJYJA6aDo2ioYDEQSxNVUaW
         3pBBMyMWoS2+IuKPsly9U6v58+60Ly3jjkivw+xtHDPZ+k1LsAIAP5BhsObVOfeKkCHn
         GnzqIChZmxJX0PqNYZxRs0ICfx1IG1DOSvtwfns7owS6K8V7q5sHFYC+1PYLJxmbYlXO
         k7ZJBRfIO9DwWszvZ6QCRBIe80kvIaTnh+hr2Do5k/OJuLb8Qm1xriFwXbpdAyO0E/T9
         6Wew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EzAEk5KkCTa+Hex6ZIVw0GVaVZS2eJllC4ZxceO6674=;
        b=NUtRcbfEFCTrVxEHzO0jvK2fz+yuElFA28jL9mYngJSODoulC93j7PWIJznCDBLFQw
         brESWZ+hotd0knw0BfdDfNLm8k0eK1ndJmOiXngph5EXrO0mUeLjJpJFziHFxu6qoDm+
         pM1AqSyad8pQ+m0Ko7d/oNdEa+TaXKMm5TTAAnnUTA0eQED3AQmldXmpLSJopzfgzWPJ
         /b0pX7qGtSDSScwWun64VJ1EBuB74eldyTEimFlGQYfOZoehAFiXzz4KTMMxd8F21Gni
         DAODCMKClSJ4qIjuKQv3blOofg9cxU3NPll3KRRhZomYEwmbYbLNlAvtoaw2cnFKy5J6
         E3pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xxIDvTqPukpKZM12x/b7BCDdNXhzfqsQnkh+Baegzl5iDMw/t
	iTAboW0sPXrFtsTCcJW40aQ=
X-Google-Smtp-Source: ABdhPJzUiBAbI5x1wQ8ILvXMegaxI8NYxbG4lSLyXnjyDt0Hpka9vSDmzOo44pDELx2VUbBcuCD6uA==
X-Received: by 2002:a17:90b:3197:: with SMTP id hc23mr1723335pjb.60.1598321748909;
        Mon, 24 Aug 2020 19:15:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:442:: with SMTP id 60ls5415135ple.4.gmail; Mon, 24
 Aug 2020 19:15:48 -0700 (PDT)
X-Received: by 2002:a17:902:c24b:: with SMTP id 11mr6007932plg.64.1598321748450;
        Mon, 24 Aug 2020 19:15:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598321748; cv=none;
        d=google.com; s=arc-20160816;
        b=SXOJYpzzZoRNoGzJr3pZbqI0AoEMKkprqpjnT2YCGGAszRsosR9+qoyIUdO6A2+F63
         22qIcAejwJrIR0EeMiEeseOwvWUn1Af3pLPfjcl17WWjdruApAi+J4bV1AZKCVIjCeK0
         0G09SdZOkr+ScZp53graGmtPUoWL3mMToj3+o4tkMDPGx/oYmrWT5QW0KBCZmxThr/n1
         DBSUL5QcSFX2sV+R25OOL1qqSr1OD3niUlMERwumFXtWDmCeqzPUOYLZlSVFkW2EMHy5
         BbRpnp9DDXGsxrAO33/wE9z9tVLvPLqMQ15tDxuq1Fsu1+uVQhnlcbRYGLS6LecAmrrH
         sHJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ii64oCh7zep+4Ck47ItpZY3LpD+hSPCz2XQvCSfA6EY=;
        b=BWBoI+rvb0PPQsUUS9OYyf7d5X+QboorIsFS5LJFCHeEtyuI98vtTcnmg0we0KkVuM
         Pu2k5PVWmZuLsbn57Naf9BlGIt9M/MZXlVk1qILfKog0gR7ZWv/W+wpA713EN6HS1VQI
         HlxCGdj6t4bkjy9IV1oZ5mStRTX/8WJDO08MLDh1ntWnCPo9+BMDqz8geBoha7wkrSg1
         NCecp3rollncUFVHNgw6KUxYR6M8la7pnDX61tFHSJSclT4Zy/F0x6NTdDZ0pBRReq67
         CUPguuD8hRB+KXzZJDoIweVQKgToPMpFWtyptX9hStjj2Ks1rOeEasTosbaOsmhEw4K+
         Pk2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=OsgvLxeV;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l2si273429pfd.0.2020.08.24.19.15.48
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 19:15:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 47f6bdc6a8034c698eda1c6a7e7e0617-20200825
X-UUID: 47f6bdc6a8034c698eda1c6a7e7e0617-20200825
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 329853360; Tue, 25 Aug 2020 10:15:46 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 10:15:43 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 10:15:43 +0800
Message-ID: <1598321744.29129.4.camel@mtksdccf07>
Subject: Re: [PATCH v2 0/6] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, "Tejun
 Heo" <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Tue, 25 Aug 2020 10:15:44 +0800
In-Reply-To: <CANpmjNNYhYwyzT3pBzJdb=XCGyLj7X+Fhqui-6JAZJWGys25Rg@mail.gmail.com>
References: <20200824080706.24704-1-walter-zh.wu@mediatek.com>
	 <CANpmjNNYhYwyzT3pBzJdb=XCGyLj7X+Fhqui-6JAZJWGys25Rg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 159432FB446FF43D5236F7CC4F80666B07F364717DF91DA958E52F2F389B3D492000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=OsgvLxeV;       spf=pass
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

On Mon, 2020-08-24 at 13:50 +0200, Marco Elver wrote:
> On Mon, 24 Aug 2020 at 10:07, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> > In some of these access/allocation happened in process_one_work(),
> > we see the free stack is useless in KASAN report, it doesn't help
> > programmers to solve UAF on workqueue. The same may stand for times.
> >
> > This patchset improves KASAN reports by making them to have workqueue
> > queueing stack and timer queueing stack information. It is useful for
> > programmers to solve use-after-free or double-free memory issue.
> >
> > Generic KASAN will record the last two workqueue and timer stacks,
> > print them in KASAN report. It is only suitable for generic KASAN.
> >
> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
> > [3]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> >
> > Walter Wu (6):
> > timer: kasan: record timer stack
> > workqueue: kasan: record workqueue stack
> > kasan: print timer and workqueue stack
> > lib/test_kasan.c: add timer test case
> > lib/test_kasan.c: add workqueue test case
> > kasan: update documentation for generic kasan
> >
> > ---
> >
> > Changes since v1:
> > - Thanks for Marco and Thomas suggestion.
> > - Remove unnecessary code and fix commit log
> > - reuse kasan_record_aux_stack() and aux_stack
> >   to record timer and workqueue stack.
> > - change the aux stack title for common name.
> 
> Much cleaner.
> 
> In general,
> 
> Acked-by: Marco Elver <elver@google.com>
> 
> but I left some more comments. I'm a bit worried about the tests,
> because of KASAN-test KUnit rework, but probably not much we can do
> until these are added to -mm tree.
> 

Hi Marco,

Thanks for your review and friendly reminder.

If needed, I will rebase and resend the test case.


Walter

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1598321744.29129.4.camel%40mtksdccf07.
