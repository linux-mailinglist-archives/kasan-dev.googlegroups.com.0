Return-Path: <kasan-dev+bncBAABBEOT5TWAKGQE6P43DIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 41D0BCE125
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 14:03:32 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id a1sf10886092pfn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 05:03:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570449810; cv=pass;
        d=google.com; s=arc-20160816;
        b=RYxSxDlo2bArmWDRTL4qUwxXnpL8YN7Jl1BHrRvtP8U5mTZvljbGVMbmQ72310tpXb
         JJYJgLSvyynzs2vxy3+7X/n2wg5Fd+PtO+lUyYlkPoyOhztclkjIsokw6aucJpouTtpq
         mwWNBvLWyidZkEOEUlc2sDlN/nrMLWY8DOwHPKxvkuaoFhqEgiY1J/BWLZzTQwEOxXZU
         aX5KpGY49te/U2H2a91TasmyXtxhGRvt76SgqBihIn8AHMZcZf7SQUlkp3fKnklJxOjg
         J5znbEo+9LokyIpyafzMyKaR1mTXMX2zxnET5jKgSt7UBw4Rnxj4F+bRbdEhjFy9Hdiz
         ir3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=qzklJvJVWABx76N5IlIJsvcAku+Cf2DOgB20gkupJ0w=;
        b=fN1fA0/qUhypI8GYbXibTmSEwWWsssub1RE1H+yURfUeBHmS5kp3+7zNy4IeREhq1K
         zoyM9kFei0SXQkc1yqYKF78cfUtEQkRdOgt6RqcKtFhUwHSdXwWWyPMMB3bKCVNGsVgA
         Mr5k18nP9MEe+7Evs8hv2Zc5hzpGgEwHLwmwwPsxS1NRhs/DHjLLhqmBrzTZXRc+lELl
         Q84Ei2j7xmh9O587Cu/IbJdrbI4wObCdXXmcBI0qtg2oPwt66E820xdiLsbxB/l6f5pF
         rhb2rCQ5keyTLZBrP3d++Mv8JPTJYQqrBTfQS4+HeUls+x99ROTEPoZdOPwpFB299Ch9
         kmQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzklJvJVWABx76N5IlIJsvcAku+Cf2DOgB20gkupJ0w=;
        b=AOJeJOH/LbTsj+t8FwiSxOu8ag+orgXsbZIQe6FocGWAozSKU5fVOnTReCnrIlX6Ly
         PGiD7A/aqXfOBm15FX0uFpNVR8em3WBpWd4liN8AmZjP3chkg1lPH7/aXpzynLD1sbju
         8bqeD4Sj2+KNJkOUxbJcHGjguWyxK2/9O0lYQLyUJiPnqi73ovGmJh9uw0VNg/Qiq25G
         aigiZiGoXTu2E2KP04wOOMhsAGaX/CGd8O2IjOBXC9wt5nFT3kiI8Ht+y0aLEFIYwexx
         hTHNZPjqRE3guBAVxEqnT4XZLn8kkVWYFDxcTkzf1NcrhA6M5ueehS1iZ9aFDnfNWpS7
         cyAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzklJvJVWABx76N5IlIJsvcAku+Cf2DOgB20gkupJ0w=;
        b=JyOn9w77w0UVn/98KTkuFr72yi6cv/5GYE9VZmyD8myDZARpX69Uz08PsvoGv2dDwC
         tRZClOrTHch6i/2dQX21yUhOPnKOHZU7lansDJZ40jX/XQN3cE9S5Mfi7UvfuD1WYk+i
         JRvqIR4zK0UbADdV7pfT5TyLhV5mlJtexegW2d7M4BDBK5P91Hbl2/IrcrMWtCR/wGqS
         nXzP+R7zN+fH8kGmklYoJXTF5nxtOP+f2wy29vBRs0i+tVpFj4fFEbVeJaSy/YyAyFaQ
         F47/s0M8Qu3p4QxbR61ryvRZR2xYveJyDdVHrawxx8hTi0+kL71FyYHOfVW9icCUztv1
         A1sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWu8PCSwcwhngx6D6Bx9nfrS+mEY+b4zYezyYGNEJQczb0qf8Zj
	3Tfa4GM9j0QkXiHa5a4QJQE=
X-Google-Smtp-Source: APXvYqwb4QCa6gNR73CFTntQynQrm0T0dufClo2oNcQy1k5jX/n3Ukjb5w9fYn2RUIe0GaNmPeITow==
X-Received: by 2002:a63:ed10:: with SMTP id d16mr16895356pgi.307.1570449810042;
        Mon, 07 Oct 2019 05:03:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6307:: with SMTP id x7ls4435232pfb.0.gmail; Mon, 07 Oct
 2019 05:03:29 -0700 (PDT)
X-Received: by 2002:a65:6644:: with SMTP id z4mr3851409pgv.208.1570449809615;
        Mon, 07 Oct 2019 05:03:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570449809; cv=none;
        d=google.com; s=arc-20160816;
        b=g8XNx0unuv8YCnYElFk3ZgOYVplGB5vxUcyEJ9XoRGXN/BovDNmSiJu+frcKeMugQ7
         SYxYcTm3ZLoZ7/yty/wlQpYEGVRFaEu9FzGemmQcmfjRGnlGbQlUq2u2eGfz3Fku6427
         YkKwI/WtEbeelGdlTp0qzb4KactnO/0Xql+lUiQu0x7KKXxDebPYsR0lXcmOzXIYccF6
         ib/hsAdXMUV97QpJ8CWsQ7ePFBRs0cPdTGq2iIYbEbSSCc5B3o573zSpmSQEl3/opDq5
         Q57tSiSu9Yv1w2L/IYR898A5UOgCbS70LE5p57nD2mmN3dLsTODI8imoeUq8/hSHpUDe
         NDQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=va0NhfGffeEfbqvFkqwglgovgZgL4eK3Navez+FGQxE=;
        b=scONLiMGIwSx3HTHFUATYzV120YmURWgxfDZO3/4rybIFXPkf/tcrwXRj493iOCO2W
         gmp7Ha/EzJpFTDFOW50a0vzqJhqnSDgR1idnudFLNlyZ39VUlc3YqEJGOqT8jPlvIniX
         m67lC/4YiV9JUxb5FS/CpT5U3sKuTpQQEzfv+dFn9lme2G9dOoI/RV/gjnu2v6VwkDbG
         7pRczQrp3zQ2+d/HcTkSi6iJNzOlnHkFq/f6ll4yb4aCKHuGVWcjgZGL43eWWGBkLqOh
         ZExx/9OZKbEBHlTZGCqg5SUKGCFkHoBGWLb3F5D0v0aTfo8YdBBuYF1imDTeAOg1X99J
         Uj+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id o23si44282pjt.2.2019.10.07.05.03.29
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2019 05:03:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d56359e6fd78464abe7d41d9d6483b81-20191007
X-UUID: d56359e6fd78464abe7d41d9d6483b81-20191007
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 906935450; Mon, 07 Oct 2019 20:03:25 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 7 Oct 2019 20:03:22 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 7 Oct 2019 20:03:22 +0800
Message-ID: <1570449804.4686.79.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Mon, 7 Oct 2019 20:03:24 +0800
In-Reply-To: <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <1570018513.19702.36.camel@mtksdccf07>
	 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
	 <1570069078.19702.57.camel@mtksdccf07>
	 <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
	 <1570095525.19702.59.camel@mtksdccf07>
	 <1570110681.19702.64.camel@mtksdccf07>
	 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
	 <1570164140.19702.97.camel@mtksdccf07>
	 <1570176131.19702.105.camel@mtksdccf07>
	 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
	 <1570182257.19702.109.camel@mtksdccf07>
	 <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
	 <1570190718.19702.125.camel@mtksdccf07>
	 <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
	 <1570418576.4686.30.camel@mtksdccf07>
	 <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
	 <1570436289.4686.40.camel@mtksdccf07>
	 <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
	 <1570438317.4686.44.camel@mtksdccf07>
	 <CACT4Y+Yc86bKxDp4ST8+49rzLOWkTXLkjs0eyFtohCi_uSjmLQ@mail.gmail.com>
	 <1570439032.4686.50.camel@mtksdccf07>
	 <CACT4Y+YL=8jFXrj2LOuQV7ZyDe-am4W8y1WHEDJJ0-mVNJ3_Cw@mail.gmail.com>
	 <1570440492.4686.59.camel@mtksdccf07> <1570441833.4686.66.camel@mtksdccf07>
	 <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

On Mon, 2019-10-07 at 12:51 +0200, Dmitry Vyukov wrote:
> On Mon, Oct 7, 2019 at 11:50 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Mon, 2019-10-07 at 17:28 +0800, Walter Wu wrote:
> > > On Mon, 2019-10-07 at 11:10 +0200, Dmitry Vyukov wrote:
> > > > On Mon, Oct 7, 2019 at 11:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > >
> > > > > On Mon, 2019-10-07 at 10:54 +0200, Dmitry Vyukov wrote:
> > > > > > On Mon, Oct 7, 2019 at 10:52 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > >
> > > > > > > On Mon, 2019-10-07 at 10:24 +0200, Dmitry Vyukov wrote:
> > > > > > > > On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > > The patchsets help to produce KASAN report when size is negative numbers
> > > > > > > > > in memory operation function. It is helpful for programmer to solve the
> > > > > > > > > undefined behavior issue. Patch 1 based on Dmitry's review and
> > > > > > > > > suggestion, patch 2 is a test in order to verify the patch 1.
> > > > > > > > >
> > > > > > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > > > > > > > >
> > > > > > > > > Walter Wu (2):
> > > > > > > > > kasan: detect invalid size in memory operation function
> > > > > > > > > kasan: add test for invalid size in memmove
> > > > > > > > >
> > > > > > > > >  lib/test_kasan.c          | 18 ++++++++++++++++++
> > > > > > > > >  mm/kasan/common.c         | 13 ++++++++-----
> > > > > > > > >  mm/kasan/generic.c        |  5 +++++
> > > > > > > > >  mm/kasan/generic_report.c | 12 ++++++++++++
> > > > > > > > >  mm/kasan/tags.c           |  5 +++++
> > > > > > > > >  mm/kasan/tags_report.c    | 12 ++++++++++++
> > > > > > > > >  6 files changed, 60 insertions(+), 5 deletions(-)
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >
> > > > > > > > > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > > > > > > > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > > > > > > > >
> > > > > > > > >     kasan: detect invalid size in memory operation function
> > > > > > > > >
> > > > > > > > >     It is an undefined behavior to pass a negative numbers to
> > > > > > > > > memset()/memcpy()/memmove()
> > > > > > > > >     , so need to be detected by KASAN.
> > > > > > > > >
> > > > > > > > >     If size is negative numbers, then it has two reasons to be defined
> > > > > > > > > as out-of-bounds bug type.
> > > > > > > > >     1) Casting negative numbers to size_t would indeed turn up as a
> > > > > > > > > large
> > > > > > > > >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > > > > > > > > can
> > > > > > > > >     qualify as out-of-bounds.
> > > > > > > > >     2) Don't generate new bug type in order to prevent duplicate reports
> > > > > > > > > by
> > > > > > > > >     some systems, e.g. syzbot.
> > > > > > > > >
> > > > > > > > >     KASAN report:
> > > > > > > > >
> > > > > > > > >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > > > > > > > > cat/72
> > > > > > > > >
> > > > > > > > >      CPU: 2 PID: 72 Comm: cat Not tainted
> > > > > > > > > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> > > > > > > > >      Hardware name: linux,dummy-virt (DT)
> > > > > > > > >      Call trace:
> > > > > > > > >       dump_backtrace+0x0/0x288
> > > > > > > > >       show_stack+0x14/0x20
> > > > > > > > >       dump_stack+0x10c/0x164
> > > > > > > > >       print_address_description.isra.9+0x68/0x378
> > > > > > > > >       __kasan_report+0x164/0x1a0
> > > > > > > > >       kasan_report+0xc/0x18
> > > > > > > > >       check_memory_region+0x174/0x1d0
> > > > > > > > >       memmove+0x34/0x88
> > > > > > > > >       kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > >
> > > > > > > > >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > >
> > > > > > > > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > >
> > > > > > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > > > > > index 6814d6d6a023..6ef0abd27f06 100644
> > > > > > > > > --- a/mm/kasan/common.c
> > > > > > > > > +++ b/mm/kasan/common.c
> > > > > > > > > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> > > > > > > > >  #undef memset
> > > > > > > > >  void *memset(void *addr, int c, size_t len)
> > > > > > > > >  {
> > > > > > > > > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > > > > > > > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > > > > > > > +               return NULL;
> > > > > > > > >
> > > > > > > > >         return __memset(addr, c, len);
> > > > > > > > >  }
> > > > > > > > > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> > > > > > > > >  #undef memmove
> > > > > > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > >  {
> > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > +               return NULL;
> > > > > > > > >
> > > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > >  }
> > > > > > > > > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > > > > > > > > len)
> > > > > > > > >  #undef memcpy
> > > > > > > > >  void *memcpy(void *dest, const void *src, size_t len)
> > > > > > > > >  {
> > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > +               return NULL;
> > > > > > > > >
> > > > > > > > >         return __memcpy(dest, src, len);
> > > > > > > > >  }
> > > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > > index 616f9dd82d12..02148a317d27 100644
> > > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > > @@ -173,6 +173,11 @@ static __always_inline bool
> > > > > > > > > check_memory_region_inline(unsigned long addr,
> > > > > > > > >         if (unlikely(size == 0))
> > > > > > > > >                 return true;
> > > > > > > > >
> > > > > > > > > +       if (unlikely((long)size < 0)) {
> > > > > > > > > +               kasan_report(addr, size, write, ret_ip);
> > > > > > > > > +               return false;
> > > > > > > > > +       }
> > > > > > > > > +
> > > > > > > > >         if (unlikely((void *)addr <
> > > > > > > > >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> > > > > > > > >                 kasan_report(addr, size, write, ret_ip);
> > > > > > > > > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > > > > > > > index 36c645939bc9..ed0eb94cb811 100644
> > > > > > > > > --- a/mm/kasan/generic_report.c
> > > > > > > > > +++ b/mm/kasan/generic_report.c
> > > > > > > > > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > > > > > > > > kasan_access_info *info)
> > > > > > > > >
> > > > > > > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > > > > > > >  {
> > > > > > > > > +       /*
> > > > > > > > > +        * If access_size is negative numbers, then it has two reasons
> > > > > > > > > +        * to be defined as out-of-bounds bug type.
> > > > > > > > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > > > +        * so that this can qualify as out-of-bounds.
> > > > > > > > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > > reports
> > > > > > > > > +        * by some systems, e.g. syzbot.
> > > > > > > > > +        */
> > > > > > > > > +       if ((long)info->access_size < 0)
> > > > > > > > > +               return "out-of-bounds";
> > > > > > > >
> > > > > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> > > > > > > > prevent duplicates. "heap-out-of-bounds" is the frequent one.
> > > > > > >
> > > > > > >
> > > > > > >     /*
> > > > > > >      * If access_size is negative numbers, then it has two reasons
> > > > > > >      * to be defined as out-of-bounds bug type.
> > > > > > >      * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > >      * a  "large" size_t and its value will be larger than ULONG_MAX/2,
> > > > > > >      *    so that this can qualify as out-of-bounds.
> > > > > > >      * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > reports
> > > > > > >      *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
> > > > > > > frequent KASAN bug type.
> > > > > > >      *    It won't prevent duplicates. "heap-out-of-bounds" is the
> > > > > > > frequent one.
> > > > > > >      */
> > > > > > >
> > > > > > > We directly add it into the comment.
> > > > > >
> > > > > >
> > > > > > OK, let's start from the beginning: why do you return "out-of-bounds" here?
> > > > > >
> > > > > Uh, comment 1 and 2 should explain it. :)
> > > >
> > > > The comment says it will cause duplicate reports. It does not explain
> > > > why you want syzbot to produce duplicate reports and spam kernel
> > > > developers... So why do you want that?
> > > >
> > > We don't generate new bug type in order to prevent duplicate by some
> > > systems, e.g. syzbot. Is it right? If yes, then it should not have
> > > duplicate report.
> > >
> > Sorry, because we don't generate new bug type. it should be duplicate
> > report(only one report which may be oob or size invlid),
> > the duplicate report goal is that invalid size is oob issue, too.
> >
> > I would not introduce a new bug type.
> > These are parsed and used by some systems, e.g. syzbot. If size is
> > user-controllable, then a new bug type for this will mean 2 bug
> > reports.
> 
> To prevent duplicates, the new crash title must not just match _any_
> crash title that kernel can potentially produce. It must match exactly
> the crash that kernel produces for this bug on other input data.
> 
> Consider, userspace passes size=123, KASAN produces "heap-out-of-bounds in foo".
> Now userspace passes size=-1 and KASAN produces "invalid-size in foo".
> This will be a duplicate bug report.
> Now if KASAN will produce "out-of-bounds in foo", it will also lead to
> a duplicate report.
> Only iff KASAN will produce "heap-out-of-bounds in foo" for size=-1,
> it will not lead to a duplicate report.

I think it is not easy to avoid the duplicate report(mentioned above).
As far as my knowledge is concerned, KASAN is memory corruption detector
in kernel space, it should only detect memory corruption and don't 
distinguish whether it is passed by userspace. if we want to do, then we
may need to parse backtrace to check if it has copy_form_user() or other
function?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570449804.4686.79.camel%40mtksdccf07.
