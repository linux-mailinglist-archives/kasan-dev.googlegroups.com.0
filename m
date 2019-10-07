Return-Path: <kasan-dev+bncBCMIZB7QWENRBS5R5TWAKGQES2PWJZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EF1C9CDFA7
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 12:51:56 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id v2sf8350152plp.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 03:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570445515; cv=pass;
        d=google.com; s=arc-20160816;
        b=TydT1dz2ZO8RikfW0lF6KD1j+EuuXbMTqD+CYReAud9QzoZAGZcFVPoHyk+cLdonwZ
         +3cV7a+Z+kFXJgl3zgDfL+IGWUM4TpIilsa+bc+vmKp7lmsZc0fZcV1yV7V9K7KkYjhh
         RrmW6LIgVrnnzrPhr/cFYwMIPy0L7Bu7cKDS3Lg6aFBCBRXhN8C1/av/s6Ocj83pB0A1
         +A2pylT2fL0hG6voG+zdpvfLH+bwoRXgg97wPMjPMoC5GSvlmkI5b4LoZfxa+bEVK1Z2
         3klVwhOKieJP2Dloz61gXsei//WfDTaxypOo82J3578DUqIc7GipLTKdQhDoYCmlXWgd
         pGbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eyiQBcXRwSxwWUUNwEQPnSs+L/7AIhaR+xCHRPeUP6Q=;
        b=Z6iUmRJ25TeolX0T+JQeXUu86Qt9dZf6o/ucg/E2JfOc+Om9zF27nbCC0G64M7eZ6S
         9NaAPMJaQNbW7C0NIqNE2p5o2l8xYJUti8b8R70kwX3Ol+rCjIaMyixzk5zYwmhQR5Gw
         WdbSOGzc1mJOD9MF3egjv34+fcPjZEnuzp2qdRYvuceTT5kP1BZvsWqoYQf+CSBMz66R
         IDu8osZXcLeDf/2A4SpTpr27KoRotejGKESpHh49PxyYk95e0kLmU/SbPcj+bRaTqQxI
         vAgDJ6USnebKTDOUdLkA9jcQbyxlBZ8PZgP2ZmKeT7g76K1aEgodCLkppz51j/PLoqN0
         fKCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZblYnebK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eyiQBcXRwSxwWUUNwEQPnSs+L/7AIhaR+xCHRPeUP6Q=;
        b=ascgQf71asoxfdqJ95DGFcPkZOjXa79TMFAHqqbdLUcm6l6cT667TQ/orupDD2t8HK
         O5byQ/3KIPUzHWqJLgT5+ctNjRlHSUn/QFJw8XGvra2WJkOPfooNCC1wqjDNO4q1U1Sm
         /BBJpAp/V9xU2jOpiZlBcxWbv36I2R4c/P8GofM9IwR0qSqbJSWQYUPHbj8ywJBp0WCv
         CWpEhc3qaE8kb/bugjutQ8TMoId9R0vjitYYmNGs8pKSM8BiFbtMrL+IFTYs41rK03q8
         qRAeGy8iundj7sgy8NQdNA4gnFjiYl0cDR0NnICP2yjvxfCToXB0vZPD2tC/JK4T8fcq
         AfgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eyiQBcXRwSxwWUUNwEQPnSs+L/7AIhaR+xCHRPeUP6Q=;
        b=cZn3363czjWDNRY1JC7GQPdrPyNb8QTOU+C/6+X+MQqB8XGLxeUrPZYTB1K9kN/0Pc
         GV4ndXik+SGRmsCRQOdI9k2Iu3xIQhKLbeB1pGFDEnBLL9CZepP9HI0b69Ab91J1bUFD
         Gs7kQ6t+sDrdyFeLQwNpWCAOl1MEhTf5i41UEtvrwc571wWsihR0M5ZNAcwue+RE+T6E
         cxq1AohO4bKH35JamnFaSDurAThOQGJBXVMyZj9lqVFeVhZVJe72p4tsKHsRDnhcIyRb
         NL6Q36UJj/TscUAtuKUinaKCnEnRQe0bELJ+ZcjUxFc3kKP1lvkertWRGWY7NguCMo03
         Gclw==
X-Gm-Message-State: APjAAAV8M2Y0Z4FnDoW43LxXoPngtO9zaXROmEMilA6KN/MunhmePR03
	FCL+X19nbB9LnnZFkXs1DhU=
X-Google-Smtp-Source: APXvYqwOQTtFFC9BpHpJzOhCfF5NAPToD2tDMqtENHMXHTi3n/ZPb35d3vWgXnDMsrvOR1Gwh3uzkQ==
X-Received: by 2002:a63:46:: with SMTP id 67mr29881609pga.234.1570445515518;
        Mon, 07 Oct 2019 03:51:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2a06:: with SMTP id q6ls4385594pfq.14.gmail; Mon, 07 Oct
 2019 03:51:55 -0700 (PDT)
X-Received: by 2002:a63:4e44:: with SMTP id o4mr29846923pgl.103.1570445515111;
        Mon, 07 Oct 2019 03:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570445515; cv=none;
        d=google.com; s=arc-20160816;
        b=y42i0QjvsI4kvavVLQC6m+YK1Qh4payuhfLfOgv3DfmF9Pu044llTMQbVJn2ekhfnx
         /WIZc0YSLwtJ2uqOxG2BW/pNNpWLMxWLDPdJCIoCId9k1ISzvVUKjTka2vIew6jh3U6G
         6JPlUibayNBzSvrjCmStNB1dwOkrnl9dU9EQ12z1Cz5Qc5Zm8igZbD++nsIyHWxZPw0E
         zQt20wjZm8uaKqeqXNd4Bsxqf6VOOvgtgtlCh2bAym1GnwFOAe6AYO6j6tn76F8yqIAo
         pHEIBThi1BsMVrAUyLaogwAODEsDt9dEBU3+gJaeW3cO80ryF4KSWKM+4cgy9LuAyLS9
         efgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/leRBOsNsqe76Ah8fFAhq4JY83SUXLtPEp8isBCEQQA=;
        b=MYmnUL0fMN7iYLK89IgGkg7iy/UmKEEjGqq9HuOPoay7PMPYKoG1xk+KDv2fCToJ6q
         t9svRoEmM9z1le4rtTU8SLwy/ZlpJdNYYwyR0+7xGakQV+jyin2znJfdCr5yvQku8Twn
         zBno87svLKMAaC/U98hpcI3AyutECAnYGDZap3YardYYNQfcRMoS8FXmjQ0yaEd0IhCn
         Wkst2VOZbOQ8dzoRjAPIluyHdsFT8rAb07DD3cFVeUiNeV4QmcQFO9bX6BI9eN8Gz2eb
         dlzVZDxBf9snPqkhRhZWMgG2nk4j9frC2MmIWxd69asSsCxC0RrbmmDlaQ8V6rLcMZE9
         k0Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZblYnebK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id x2si863091pfq.3.2019.10.07.03.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 03:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id w2so12096484qkf.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 03:51:55 -0700 (PDT)
X-Received: by 2002:a37:9c57:: with SMTP id f84mr23248727qke.250.1570445513471;
 Mon, 07 Oct 2019 03:51:53 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
 <1570069078.19702.57.camel@mtksdccf07> <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
 <1570095525.19702.59.camel@mtksdccf07> <1570110681.19702.64.camel@mtksdccf07>
 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
 <1570164140.19702.97.camel@mtksdccf07> <1570176131.19702.105.camel@mtksdccf07>
 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
 <1570182257.19702.109.camel@mtksdccf07> <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
 <1570190718.19702.125.camel@mtksdccf07> <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
 <1570418576.4686.30.camel@mtksdccf07> <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
 <1570436289.4686.40.camel@mtksdccf07> <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
 <1570438317.4686.44.camel@mtksdccf07> <CACT4Y+Yc86bKxDp4ST8+49rzLOWkTXLkjs0eyFtohCi_uSjmLQ@mail.gmail.com>
 <1570439032.4686.50.camel@mtksdccf07> <CACT4Y+YL=8jFXrj2LOuQV7ZyDe-am4W8y1WHEDJJ0-mVNJ3_Cw@mail.gmail.com>
 <1570440492.4686.59.camel@mtksdccf07> <1570441833.4686.66.camel@mtksdccf07>
In-Reply-To: <1570441833.4686.66.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 12:51:41 +0200
Message-ID: <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZblYnebK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Mon, Oct 7, 2019 at 11:50 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2019-10-07 at 17:28 +0800, Walter Wu wrote:
> > On Mon, 2019-10-07 at 11:10 +0200, Dmitry Vyukov wrote:
> > > On Mon, Oct 7, 2019 at 11:03 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > On Mon, 2019-10-07 at 10:54 +0200, Dmitry Vyukov wrote:
> > > > > On Mon, Oct 7, 2019 at 10:52 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > >
> > > > > > On Mon, 2019-10-07 at 10:24 +0200, Dmitry Vyukov wrote:
> > > > > > > On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > The patchsets help to produce KASAN report when size is negative numbers
> > > > > > > > in memory operation function. It is helpful for programmer to solve the
> > > > > > > > undefined behavior issue. Patch 1 based on Dmitry's review and
> > > > > > > > suggestion, patch 2 is a test in order to verify the patch 1.
> > > > > > > >
> > > > > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > > > > > > >
> > > > > > > > Walter Wu (2):
> > > > > > > > kasan: detect invalid size in memory operation function
> > > > > > > > kasan: add test for invalid size in memmove
> > > > > > > >
> > > > > > > >  lib/test_kasan.c          | 18 ++++++++++++++++++
> > > > > > > >  mm/kasan/common.c         | 13 ++++++++-----
> > > > > > > >  mm/kasan/generic.c        |  5 +++++
> > > > > > > >  mm/kasan/generic_report.c | 12 ++++++++++++
> > > > > > > >  mm/kasan/tags.c           |  5 +++++
> > > > > > > >  mm/kasan/tags_report.c    | 12 ++++++++++++
> > > > > > > >  6 files changed, 60 insertions(+), 5 deletions(-)
> > > > > > > >
> > > > > > > >
> > > > > > > >
> > > > > > > >
> > > > > > > > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > > > > > > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > > > > > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > > > > > > >
> > > > > > > >     kasan: detect invalid size in memory operation function
> > > > > > > >
> > > > > > > >     It is an undefined behavior to pass a negative numbers to
> > > > > > > > memset()/memcpy()/memmove()
> > > > > > > >     , so need to be detected by KASAN.
> > > > > > > >
> > > > > > > >     If size is negative numbers, then it has two reasons to be defined
> > > > > > > > as out-of-bounds bug type.
> > > > > > > >     1) Casting negative numbers to size_t would indeed turn up as a
> > > > > > > > large
> > > > > > > >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > > > > > > > can
> > > > > > > >     qualify as out-of-bounds.
> > > > > > > >     2) Don't generate new bug type in order to prevent duplicate reports
> > > > > > > > by
> > > > > > > >     some systems, e.g. syzbot.
> > > > > > > >
> > > > > > > >     KASAN report:
> > > > > > > >
> > > > > > > >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > > > > > > > cat/72
> > > > > > > >
> > > > > > > >      CPU: 2 PID: 72 Comm: cat Not tainted
> > > > > > > > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> > > > > > > >      Hardware name: linux,dummy-virt (DT)
> > > > > > > >      Call trace:
> > > > > > > >       dump_backtrace+0x0/0x288
> > > > > > > >       show_stack+0x14/0x20
> > > > > > > >       dump_stack+0x10c/0x164
> > > > > > > >       print_address_description.isra.9+0x68/0x378
> > > > > > > >       __kasan_report+0x164/0x1a0
> > > > > > > >       kasan_report+0xc/0x18
> > > > > > > >       check_memory_region+0x174/0x1d0
> > > > > > > >       memmove+0x34/0x88
> > > > > > > >       kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > >
> > > > > > > >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > >
> > > > > > > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > >
> > > > > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > > > > index 6814d6d6a023..6ef0abd27f06 100644
> > > > > > > > --- a/mm/kasan/common.c
> > > > > > > > +++ b/mm/kasan/common.c
> > > > > > > > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> > > > > > > >  #undef memset
> > > > > > > >  void *memset(void *addr, int c, size_t len)
> > > > > > > >  {
> > > > > > > > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > > > > > > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > > > > > > +               return NULL;
> > > > > > > >
> > > > > > > >         return __memset(addr, c, len);
> > > > > > > >  }
> > > > > > > > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> > > > > > > >  #undef memmove
> > > > > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > > > > >  {
> > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > +               return NULL;
> > > > > > > >
> > > > > > > >         return __memmove(dest, src, len);
> > > > > > > >  }
> > > > > > > > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > > > > > > > len)
> > > > > > > >  #undef memcpy
> > > > > > > >  void *memcpy(void *dest, const void *src, size_t len)
> > > > > > > >  {
> > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > +               return NULL;
> > > > > > > >
> > > > > > > >         return __memcpy(dest, src, len);
> > > > > > > >  }
> > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > index 616f9dd82d12..02148a317d27 100644
> > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > @@ -173,6 +173,11 @@ static __always_inline bool
> > > > > > > > check_memory_region_inline(unsigned long addr,
> > > > > > > >         if (unlikely(size == 0))
> > > > > > > >                 return true;
> > > > > > > >
> > > > > > > > +       if (unlikely((long)size < 0)) {
> > > > > > > > +               kasan_report(addr, size, write, ret_ip);
> > > > > > > > +               return false;
> > > > > > > > +       }
> > > > > > > > +
> > > > > > > >         if (unlikely((void *)addr <
> > > > > > > >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> > > > > > > >                 kasan_report(addr, size, write, ret_ip);
> > > > > > > > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > > > > > > index 36c645939bc9..ed0eb94cb811 100644
> > > > > > > > --- a/mm/kasan/generic_report.c
> > > > > > > > +++ b/mm/kasan/generic_report.c
> > > > > > > > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > > > > > > > kasan_access_info *info)
> > > > > > > >
> > > > > > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > > > > > >  {
> > > > > > > > +       /*
> > > > > > > > +        * If access_size is negative numbers, then it has two reasons
> > > > > > > > +        * to be defined as out-of-bounds bug type.
> > > > > > > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > > +        * so that this can qualify as out-of-bounds.
> > > > > > > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > reports
> > > > > > > > +        * by some systems, e.g. syzbot.
> > > > > > > > +        */
> > > > > > > > +       if ((long)info->access_size < 0)
> > > > > > > > +               return "out-of-bounds";
> > > > > > >
> > > > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> > > > > > > prevent duplicates. "heap-out-of-bounds" is the frequent one.
> > > > > >
> > > > > >
> > > > > >     /*
> > > > > >      * If access_size is negative numbers, then it has two reasons
> > > > > >      * to be defined as out-of-bounds bug type.
> > > > > >      * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > >      * a  "large" size_t and its value will be larger than ULONG_MAX/2,
> > > > > >      *    so that this can qualify as out-of-bounds.
> > > > > >      * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > reports
> > > > > >      *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
> > > > > > frequent KASAN bug type.
> > > > > >      *    It won't prevent duplicates. "heap-out-of-bounds" is the
> > > > > > frequent one.
> > > > > >      */
> > > > > >
> > > > > > We directly add it into the comment.
> > > > >
> > > > >
> > > > > OK, let's start from the beginning: why do you return "out-of-bounds" here?
> > > > >
> > > > Uh, comment 1 and 2 should explain it. :)
> > >
> > > The comment says it will cause duplicate reports. It does not explain
> > > why you want syzbot to produce duplicate reports and spam kernel
> > > developers... So why do you want that?
> > >
> > We don't generate new bug type in order to prevent duplicate by some
> > systems, e.g. syzbot. Is it right? If yes, then it should not have
> > duplicate report.
> >
> Sorry, because we don't generate new bug type. it should be duplicate
> report(only one report which may be oob or size invlid),
> the duplicate report goal is that invalid size is oob issue, too.
>
> I would not introduce a new bug type.
> These are parsed and used by some systems, e.g. syzbot. If size is
> user-controllable, then a new bug type for this will mean 2 bug
> reports.

To prevent duplicates, the new crash title must not just match _any_
crash title that kernel can potentially produce. It must match exactly
the crash that kernel produces for this bug on other input data.

Consider, userspace passes size=123, KASAN produces "heap-out-of-bounds in foo".
Now userspace passes size=-1 and KASAN produces "invalid-size in foo".
This will be a duplicate bug report.
Now if KASAN will produce "out-of-bounds in foo", it will also lead to
a duplicate report.
Only iff KASAN will produce "heap-out-of-bounds in foo" for size=-1,
it will not lead to a duplicate report.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ0A%3DZi4AxEjn4jpHk0xG9%2BNh2Q-OYEnOmooW0wN-_vfQ%40mail.gmail.com.
