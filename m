Return-Path: <kasan-dev+bncBAABB77A5TWAKGQE2UXEHLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C5A4CE1C1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 14:33:04 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id h10sf15132393qtq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 05:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570451583; cv=pass;
        d=google.com; s=arc-20160816;
        b=cov++/jtKlg0wf325g4l76Toz6jevSsqPAjDmxZnF2CiclP8HJ+IJqqtQE/WtZ7He4
         e6hxJ8chW6phkV/+w7y1QHaFyIF1y+w95FsmRKCrJx8rgjCj9KlHbYVWge6kZWqBaU1s
         c4TlbT7zZLut70sTtQD4M+AogqVQ/5/Vzb0MaCm1ZMEEhBKXYBGB17800VmJYnHIVTLv
         KrjMLfxqvpS6kRtg2kxmESjOwpqe5SSW9CzlU6OuAEDbQf+1e73qkllNphJtIDZBwxQG
         ZbWTwyF4cmzVX1WOOathavlCZtixTWNIs/eceu1+krKd+RfxQP6m3ARiIVQv+Xv55YGM
         bveg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Ji+u//xEUn3MWt/TnX+eUmypgHwLGN4A252M+uLYTrY=;
        b=HQMPqm8nGJT9RhxqF8t4C1CUDmnE8kV75ndBQnjOdG/P2PuGK+ZkELQHtOKwFQbx0F
         F9FTz0+2S0mbawWgWv5NQknA7/JNmyHrBBNYYKXPpu8zomvKzHR1m4DxeN0bmBBvYGcJ
         5Sy2SvxVXriZw63nzhynG+Gu/9JDK/EidTSLFrnKqAouYVBvET1ihzpOneoezT9qf0K/
         dHbbPd1K+eGAPc3a2EXycnXhBsoUyHev795G2MBfVjLXVO2ql9rHuHdtKL3c+8FsGvPX
         ugruIr1QxmxALwzmxmlnRgQ+AcCFkdK7HkoS/d3db5sEhgfjsduDO56z6oThKsVKs2/s
         Pumw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ji+u//xEUn3MWt/TnX+eUmypgHwLGN4A252M+uLYTrY=;
        b=Ha0WuPaFRV8Gg2Bu9+Sk1gryOpnj4XrDJC8bPRVI3TYnW/oq3z2T+q4zcycDfAjuJx
         QA6UDc3ip7mgKbto3KFQyTvZ2usYQifgaTK6u6g6VOZpayxL8yHLwd+5jqndsIQMUU+7
         4B2Yq0uYs5ZpwVnGNeZRYxynajof9WSliRdJaKiXiihhZued/U0sUUY7QaJFnNOPpxZO
         BMuhocSh0OUYLWqv1XBvUwrH77knYItGIZqIMOfLIyylqq0HQ4yEsY17K42rlMEwJ8Kw
         4AYQHybNZ8Yo50tH5/z0OV82Cs4TKPXYcQatNBTl19EC98xCj62YEzyKKeTwyKsWi0H0
         F/QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ji+u//xEUn3MWt/TnX+eUmypgHwLGN4A252M+uLYTrY=;
        b=X/UGmDYnb/RDFxw0a8j3UkKscuL9Jhq8CqYQp/OQCiwW2J6tluabSWFzU8oeHHahL7
         gXizJ19kTsLDSzuPaBfPZUy6bFM+p6Rt92E/p7UZSnNz3U4/WxiQhLvZ3K9P5MlQRq8q
         mpr2umrT9ruk3UFH50DfRX57bhbdoFXipc2NVm8TPggSuyBUDzcczzlObxtBbpnbsKp+
         zWAztRr1idMHAkmFtg0dYUUFJZWn6z4mJFXOHemRL2qDlUgjsBA6UseX3ERYPr/2gX9h
         aup6zmnC1IEv1gskwbbyR26RjupU3/mpMzTh5lDgFx8Bj+mV7Gr31CglPmG6IILhEhQE
         CmWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWEGpeYY9VKqwaXeUpxKCrZt1GiFjz4n59Zs8F9rhgxOiGvB7Vj
	TeKNlqLp8faGbKXnI/qUYA4=
X-Google-Smtp-Source: APXvYqzAsplfttl2wgy4rmc5hZ7p2uR5F5aZ7Bhg5RHmQpzVFi58tKIwJ9jNJIADRCyV0NSCQ3SkaQ==
X-Received: by 2002:ac8:71cb:: with SMTP id i11mr29178077qtp.208.1570451583254;
        Mon, 07 Oct 2019 05:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a0d:: with SMTP id 13ls4394995qkk.7.gmail; Mon, 07 Oct
 2019 05:33:02 -0700 (PDT)
X-Received: by 2002:a05:620a:15d2:: with SMTP id o18mr11016086qkm.341.1570451582353;
        Mon, 07 Oct 2019 05:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570451582; cv=none;
        d=google.com; s=arc-20160816;
        b=ec7daTAk2p4f20fbx+rw5wNzkY/RJqF1NkaM12pyr30BfSfcN6NJGDVDTZ/ecxm1T4
         4weFoNbM03rbAJa3D44tgA+fyPs3uxtVNevEDdTcKNdd+H/5+o0qzkkNUUowVz63wMI/
         bSzsd6/OIyZXf8uBrEvSFj0OqySeOGD+4sjaGMpZ1ogg57i9+bvcrd9KY20c0YtbXp6t
         ua2s1FC4hxbUZXi4MaEwG8QapPNmrgx7TN1ebdIX+RJDxuS1nWetDM1RPve7/JCgS48E
         9RgdieOVP7csNceIGQWxEp3iSE1cKwlOQoTd9Yw0jqrGm2e7LaftLhDPOxeepL62bdE8
         6/3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=3AjJaPY3zjFXiX4/vKpJHWEeyMWpmw/vI+lXKhJr9t0=;
        b=mAtXzBz1LWe59Nkjo6d3A+CV/k9ru2dRKVX1VABWzlSK5PpSo5Mg5HDOHyc2XPE1dp
         ABk8NX2k28AO5+RBGvXfBpEd+wUHouo8TiM+Y8/7WbEiqz2chCfsLbD53HkLr/5t6AOX
         D5QrlKBB5vdqw7rU0snvpVQcaFFKokQrOcHEmDHaCb3XEDJKGw0AD3Hw5Hw00zzpeffL
         6ZPh6vJOteBKdgxEFP842wcTIUDzqbKW6v0mwcrqVycNukk4ZWe0gcrL7nhyViuBr9Us
         OEBXZ16A08e45251CDfo1NQrUTzUAXD4pLDtHQEuOFxFi8C+sOvP84B8vzcaPdnihvuc
         x71g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id x44si687926qtc.3.2019.10.07.05.33.00
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2019 05:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: dc1c58b589214748a8568a22798e19f1-20191007
X-UUID: dc1c58b589214748a8568a22798e19f1-20191007
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 730812572; Mon, 07 Oct 2019 20:32:56 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 7 Oct 2019 20:32:53 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 7 Oct 2019 20:32:53 +0800
Message-ID: <1570451575.4686.83.camel@mtksdccf07>
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
Date: Mon, 7 Oct 2019 20:32:55 +0800
In-Reply-To: <CACT4Y+b4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0+MwDcB5hV5K+A@mail.gmail.com>
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
	 <1570449804.4686.79.camel@mtksdccf07>
	 <CACT4Y+b4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0+MwDcB5hV5K+A@mail.gmail.com>
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

On Mon, 2019-10-07 at 14:19 +0200, Dmitry Vyukov wrote:
> On Mon, Oct 7, 2019 at 2:03 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > > > On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > > > > The patchsets help to produce KASAN report when size is negative numbers
> > > > > > > > > > > in memory operation function. It is helpful for programmer to solve the
> > > > > > > > > > > undefined behavior issue. Patch 1 based on Dmitry's review and
> > > > > > > > > > > suggestion, patch 2 is a test in order to verify the patch 1.
> > > > > > > > > > >
> > > > > > > > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > > > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > > > > > > > > > >
> > > > > > > > > > > Walter Wu (2):
> > > > > > > > > > > kasan: detect invalid size in memory operation function
> > > > > > > > > > > kasan: add test for invalid size in memmove
> > > > > > > > > > >
> > > > > > > > > > >  lib/test_kasan.c          | 18 ++++++++++++++++++
> > > > > > > > > > >  mm/kasan/common.c         | 13 ++++++++-----
> > > > > > > > > > >  mm/kasan/generic.c        |  5 +++++
> > > > > > > > > > >  mm/kasan/generic_report.c | 12 ++++++++++++
> > > > > > > > > > >  mm/kasan/tags.c           |  5 +++++
> > > > > > > > > > >  mm/kasan/tags_report.c    | 12 ++++++++++++
> > > > > > > > > > >  6 files changed, 60 insertions(+), 5 deletions(-)
> > > > > > > > > > >
> > > > > > > > > > >
> > > > > > > > > > >
> > > > > > > > > > >
> > > > > > > > > > > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > > > > > > > > > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > > > > > > > > > >
> > > > > > > > > > >     kasan: detect invalid size in memory operation function
> > > > > > > > > > >
> > > > > > > > > > >     It is an undefined behavior to pass a negative numbers to
> > > > > > > > > > > memset()/memcpy()/memmove()
> > > > > > > > > > >     , so need to be detected by KASAN.
> > > > > > > > > > >
> > > > > > > > > > >     If size is negative numbers, then it has two reasons to be defined
> > > > > > > > > > > as out-of-bounds bug type.
> > > > > > > > > > >     1) Casting negative numbers to size_t would indeed turn up as a
> > > > > > > > > > > large
> > > > > > > > > > >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > > > > > > > > > > can
> > > > > > > > > > >     qualify as out-of-bounds.
> > > > > > > > > > >     2) Don't generate new bug type in order to prevent duplicate reports
> > > > > > > > > > > by
> > > > > > > > > > >     some systems, e.g. syzbot.
> > > > > > > > > > >
> > > > > > > > > > >     KASAN report:
> > > > > > > > > > >
> > > > > > > > > > >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > > > >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > > > > > > > > > > cat/72
> > > > > > > > > > >
> > > > > > > > > > >      CPU: 2 PID: 72 Comm: cat Not tainted
> > > > > > > > > > > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> > > > > > > > > > >      Hardware name: linux,dummy-virt (DT)
> > > > > > > > > > >      Call trace:
> > > > > > > > > > >       dump_backtrace+0x0/0x288
> > > > > > > > > > >       show_stack+0x14/0x20
> > > > > > > > > > >       dump_stack+0x10c/0x164
> > > > > > > > > > >       print_address_description.isra.9+0x68/0x378
> > > > > > > > > > >       __kasan_report+0x164/0x1a0
> > > > > > > > > > >       kasan_report+0xc/0x18
> > > > > > > > > > >       check_memory_region+0x174/0x1d0
> > > > > > > > > > >       memmove+0x34/0x88
> > > > > > > > > > >       kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > > > >
> > > > > > > > > > >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > > > >
> > > > > > > > > > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > > >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > > >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > > >
> > > > > > > > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > > > > > > > index 6814d6d6a023..6ef0abd27f06 100644
> > > > > > > > > > > --- a/mm/kasan/common.c
> > > > > > > > > > > +++ b/mm/kasan/common.c
> > > > > > > > > > > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> > > > > > > > > > >  #undef memset
> > > > > > > > > > >  void *memset(void *addr, int c, size_t len)
> > > > > > > > > > >  {
> > > > > > > > > > > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > > > > > > > > > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > > > > > > > > > +               return NULL;
> > > > > > > > > > >
> > > > > > > > > > >         return __memset(addr, c, len);
> > > > > > > > > > >  }
> > > > > > > > > > > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> > > > > > > > > > >  #undef memmove
> > > > > > > > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > > > >  {
> > > > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > > > +               return NULL;
> > > > > > > > > > >
> > > > > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > > > >  }
> > > > > > > > > > > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > > > > > > > > > > len)
> > > > > > > > > > >  #undef memcpy
> > > > > > > > > > >  void *memcpy(void *dest, const void *src, size_t len)
> > > > > > > > > > >  {
> > > > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > > > +               return NULL;
> > > > > > > > > > >
> > > > > > > > > > >         return __memcpy(dest, src, len);
> > > > > > > > > > >  }
> > > > > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > > > > index 616f9dd82d12..02148a317d27 100644
> > > > > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > > > > @@ -173,6 +173,11 @@ static __always_inline bool
> > > > > > > > > > > check_memory_region_inline(unsigned long addr,
> > > > > > > > > > >         if (unlikely(size == 0))
> > > > > > > > > > >                 return true;
> > > > > > > > > > >
> > > > > > > > > > > +       if (unlikely((long)size < 0)) {
> > > > > > > > > > > +               kasan_report(addr, size, write, ret_ip);
> > > > > > > > > > > +               return false;
> > > > > > > > > > > +       }
> > > > > > > > > > > +
> > > > > > > > > > >         if (unlikely((void *)addr <
> > > > > > > > > > >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> > > > > > > > > > >                 kasan_report(addr, size, write, ret_ip);
> > > > > > > > > > > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > > > > > > > > > index 36c645939bc9..ed0eb94cb811 100644
> > > > > > > > > > > --- a/mm/kasan/generic_report.c
> > > > > > > > > > > +++ b/mm/kasan/generic_report.c
> > > > > > > > > > > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > > > > > > > > > > kasan_access_info *info)
> > > > > > > > > > >
> > > > > > > > > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > > > > > > > > >  {
> > > > > > > > > > > +       /*
> > > > > > > > > > > +        * If access_size is negative numbers, then it has two reasons
> > > > > > > > > > > +        * to be defined as out-of-bounds bug type.
> > > > > > > > > > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > > > > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > > > > > +        * so that this can qualify as out-of-bounds.
> > > > > > > > > > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > > > > reports
> > > > > > > > > > > +        * by some systems, e.g. syzbot.
> > > > > > > > > > > +        */
> > > > > > > > > > > +       if ((long)info->access_size < 0)
> > > > > > > > > > > +               return "out-of-bounds";
> > > > > > > > > >
> > > > > > > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> > > > > > > > > > prevent duplicates. "heap-out-of-bounds" is the frequent one.
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >     /*
> > > > > > > > >      * If access_size is negative numbers, then it has two reasons
> > > > > > > > >      * to be defined as out-of-bounds bug type.
> > > > > > > > >      * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > > >      * a  "large" size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > > >      *    so that this can qualify as out-of-bounds.
> > > > > > > > >      * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > > reports
> > > > > > > > >      *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
> > > > > > > > > frequent KASAN bug type.
> > > > > > > > >      *    It won't prevent duplicates. "heap-out-of-bounds" is the
> > > > > > > > > frequent one.
> > > > > > > > >      */
> > > > > > > > >
> > > > > > > > > We directly add it into the comment.
> > > > > > > >
> > > > > > > >
> > > > > > > > OK, let's start from the beginning: why do you return "out-of-bounds" here?
> > > > > > > >
> > > > > > > Uh, comment 1 and 2 should explain it. :)
> > > > > >
> > > > > > The comment says it will cause duplicate reports. It does not explain
> > > > > > why you want syzbot to produce duplicate reports and spam kernel
> > > > > > developers... So why do you want that?
> > > > > >
> > > > > We don't generate new bug type in order to prevent duplicate by some
> > > > > systems, e.g. syzbot. Is it right? If yes, then it should not have
> > > > > duplicate report.
> > > > >
> > > > Sorry, because we don't generate new bug type. it should be duplicate
> > > > report(only one report which may be oob or size invlid),
> > > > the duplicate report goal is that invalid size is oob issue, too.
> > > >
> > > > I would not introduce a new bug type.
> > > > These are parsed and used by some systems, e.g. syzbot. If size is
> > > > user-controllable, then a new bug type for this will mean 2 bug
> > > > reports.
> > >
> > > To prevent duplicates, the new crash title must not just match _any_
> > > crash title that kernel can potentially produce. It must match exactly
> > > the crash that kernel produces for this bug on other input data.
> > >
> > > Consider, userspace passes size=123, KASAN produces "heap-out-of-bounds in foo".
> > > Now userspace passes size=-1 and KASAN produces "invalid-size in foo".
> > > This will be a duplicate bug report.
> > > Now if KASAN will produce "out-of-bounds in foo", it will also lead to
> > > a duplicate report.
> > > Only iff KASAN will produce "heap-out-of-bounds in foo" for size=-1,
> > > it will not lead to a duplicate report.
> >
> > I think it is not easy to avoid the duplicate report(mentioned above).
> > As far as my knowledge is concerned, KASAN is memory corruption detector
> > in kernel space, it should only detect memory corruption and don't
> > distinguish whether it is passed by userspace. if we want to do, then we
> > may need to parse backtrace to check if it has copy_form_user() or other
> > function?
> 
> My idea was just to always print "heap-out-of-bounds" and don't
> differentiate if the size come from userspace or not.

Got it.
Would you have any other concern about this patch?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570451575.4686.83.camel%40mtksdccf07.
