Return-Path: <kasan-dev+bncBCMIZB7QWENRB6G25TWAKGQEGSTHV5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A6D9ECE177
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 14:20:09 +0200 (CEST)
Received: by mail-yw1-xc39.google.com with SMTP id o14sf12380705ywa.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 05:20:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570450808; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAyLUCVjh1WPaR2BiQgRN6NBkw9X5lX4o6YVKYJHGzZ4uI9Eln9NFpTt15qJcoPxb6
         ClLgMQhX+KEIhODB8/qy87JiNGxpRLlGiL+u92qdbbFKskyZx/7AYXWdqaej84uety7s
         fPPGP+kAAHb2/xUkj+OMdlsq4mMfYTOmKHl984yKPveMr5BJl+bFezY240RCTRdGwKEB
         Y6szkzDk1lj4DR9a5U1pkN/xj1n5Bk6/hkWARUkL0mZBtf7bCKUOkFDbnesouXVeDBS3
         DKcQyiEgWmRwAMeA0gRkIXgWYC3GoCIzfNfSlFo4C7ucpnBxklvI9C4ah3x0iz7T34ul
         OREw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=szwWH8we5ZAnOttOVETPP5ih8j/KjU8riRjPs94StMw=;
        b=SGwXMxHhyukoP5TZNDlc3J5NuGu391QgPA7v8HicYN1voJ534txwVYHDOLlXSvARX7
         5cOV+Qqb8SG8bQLqf0Gc/l/DANrMbX/URB3xAyPJxVpR3FsGWPu5CH6eRm76O05pb3KV
         CSzF1PNNAbkyvSi3rYjaARVhBsSzNW7MCBOeVUiWGqWSKY0ff6rfvXMEYRZD48IcT7VN
         kHRqsoohmzohaVhie2KzQcUOaOU7NgIqOZOEOJBfwKQJviEfsiozguLncJ9r/lbgFd6t
         ePc0vndEvWl1mg0lC0qwOiSwMAtl30a5Zi+9ARrocIm1b3gNhckzt6fHHzI1ZjzBhg7x
         GJKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LHYPKcnf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=szwWH8we5ZAnOttOVETPP5ih8j/KjU8riRjPs94StMw=;
        b=tmk+SsWpC9uk1s2G3p21lHz47z4kMD0IJGjJCfLk3IirK0iw/2ovyV/wLKLhZ8Qhe6
         jqmZQfMdFR7YKvkvvy6xYu2JbZQb0sPrV4Eajp3+xwA1sPv6SskL6paAx+fVbqWBCnhg
         ZLTnlKylGhSexl+DNHfnAFozEWgKDm9NgPCz65BTR8Agj5+WmPUbNUqWDWCB7ZqC2oQP
         mYEA32+jU9DY23KidGUJg4jXC1IBtlPujgI5meT0iEN4TC9dIz07vUWMrZB8A43cdd8b
         5USZ5Quf8V1bo7wEoLNnQhncehKo/fw7eBFZP+cPe1U4qKvntM1ZV3ft+6QzZd3jipKz
         jy+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=szwWH8we5ZAnOttOVETPP5ih8j/KjU8riRjPs94StMw=;
        b=AJWCx1TU7KR06HDQMHkvJbee5WCwUuut9SqnuubpX8XPWL3PlUNBDW3OsLKUCnCsag
         cZJje7xUSnitMzng9y0Kk52VDYynEiqPrK/La/w1MLExr+zkPW1AzkwaqwE9DQw2Q58F
         TMup39KYU+TFo2HPvfgS86fTEuTlP6PJglP9gMyP3TTuG3P24rnBzbXIBxnlAppDbva0
         CXFfAEN+wYsWsF8hWGMKWyL+YKb8oqFskTYn/0ikxgvboa+UBdTd296j3vRP3wI0MgEq
         v624De9FR8kFM1sdDOnoz2sAxpqS8qcHiPQ7jT5IxXPLCGta2F0C0LaLREhPpTzE5QKo
         Kprw==
X-Gm-Message-State: APjAAAWsY8D9yD2ZS09HMkoU9qLbaLg9QRaPqD+unqJhwqnsKgPWAEzt
	j8Cn9VAlwVdYbUxLbw2KMdY=
X-Google-Smtp-Source: APXvYqzb3WpjDLGmy3j/qsiSXmzRJQjmtM0naKm3HOF4FgpdMBiC8VigCH7Ey3jOBe5JCHHX5FZLVg==
X-Received: by 2002:a81:3049:: with SMTP id w70mr21040855yww.254.1570450808612;
        Mon, 07 Oct 2019 05:20:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4303:: with SMTP id q3ls2475789ywa.1.gmail; Mon, 07 Oct
 2019 05:20:07 -0700 (PDT)
X-Received: by 2002:a81:a202:: with SMTP id w2mr21302308ywg.152.1570450807664;
        Mon, 07 Oct 2019 05:20:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570450807; cv=none;
        d=google.com; s=arc-20160816;
        b=EykMbGknmzF0xo4ypVbhtinb5XPF05CAqaYXdE8sNONYYu1dUChXfnq1e/1vjzPgom
         qVFJRTmpa9SZ2ogA9aGwTei2OZWJm7+KivGPpm4pTtEESKJrgBeNg5IiC7YRVpvY+Pyh
         rhSvH2BJB9gMohp9kv/4XKzPtsEAbxPCwTHTHdPIcZFPYtXYRpVIPMVwcWGbzVvvPA8S
         A9tGNGaegbtK0JxhZcvp02n989M9RT8wa0WgWbEIV8sP5hH+Tw5SMRwobp7XHfQIH4f5
         1l+R/mdrV6VmEMpmBgfK/Elxi+Tnj5A2h7Dib8ii/3Y9kGVkQLNySnBoZSBZB7yZ3ZbY
         jcUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=foEkWUCM575fnsqo6dD50iM97OZJEympj2lwIIE9A5g=;
        b=wdF7cvffZcGC0O/1yvG8syf0P8N791PusM6xvmPwLTNocHl6TtTU4/Zjw3H2baCeXu
         dgzg5RGJ2Wt5prSaxEhZV9JiRCcUrtf70g+wi8SLy9dJzNgbn91nrejE9I9Ag3bEQ5nW
         o0D9af4G5IiVPfBPysSYGjKhCWy7wRkw4gvsDPT39kpPGQXGmr+W/nWDmvB6SuZEsKby
         FT5QlVizYrjF/odjs3RX8e+XwTqsN3nsMCGUlKj7NyN5MX35euJteZKbtOI3fFmKe2HL
         IWzwjlMU4PM972rreGeJzhwKENHDgG13LJSQnlvd6Hx9mhnQkC2gCadaBrYO+rlsM+sW
         0o6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LHYPKcnf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id j136si357920ybj.3.2019.10.07.05.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 05:20:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id u40so18745700qth.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 05:20:07 -0700 (PDT)
X-Received: by 2002:ac8:108b:: with SMTP id a11mr29317165qtj.380.1570450806687;
 Mon, 07 Oct 2019 05:20:06 -0700 (PDT)
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
 <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com> <1570449804.4686.79.camel@mtksdccf07>
In-Reply-To: <1570449804.4686.79.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 14:19:54 +0200
Message-ID: <CACT4Y+b4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0+MwDcB5hV5K+A@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=LHYPKcnf;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, Oct 7, 2019 at 2:03 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > > On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > > > > > The patchsets help to produce KASAN report when size is negative numbers
> > > > > > > > > > in memory operation function. It is helpful for programmer to solve the
> > > > > > > > > > undefined behavior issue. Patch 1 based on Dmitry's review and
> > > > > > > > > > suggestion, patch 2 is a test in order to verify the patch 1.
> > > > > > > > > >
> > > > > > > > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > > > > > > > > >
> > > > > > > > > > Walter Wu (2):
> > > > > > > > > > kasan: detect invalid size in memory operation function
> > > > > > > > > > kasan: add test for invalid size in memmove
> > > > > > > > > >
> > > > > > > > > >  lib/test_kasan.c          | 18 ++++++++++++++++++
> > > > > > > > > >  mm/kasan/common.c         | 13 ++++++++-----
> > > > > > > > > >  mm/kasan/generic.c        |  5 +++++
> > > > > > > > > >  mm/kasan/generic_report.c | 12 ++++++++++++
> > > > > > > > > >  mm/kasan/tags.c           |  5 +++++
> > > > > > > > > >  mm/kasan/tags_report.c    | 12 ++++++++++++
> > > > > > > > > >  6 files changed, 60 insertions(+), 5 deletions(-)
> > > > > > > > > >
> > > > > > > > > >
> > > > > > > > > >
> > > > > > > > > >
> > > > > > > > > > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > > > > > > > > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > > > > > > > > >
> > > > > > > > > >     kasan: detect invalid size in memory operation function
> > > > > > > > > >
> > > > > > > > > >     It is an undefined behavior to pass a negative numbers to
> > > > > > > > > > memset()/memcpy()/memmove()
> > > > > > > > > >     , so need to be detected by KASAN.
> > > > > > > > > >
> > > > > > > > > >     If size is negative numbers, then it has two reasons to be defined
> > > > > > > > > > as out-of-bounds bug type.
> > > > > > > > > >     1) Casting negative numbers to size_t would indeed turn up as a
> > > > > > > > > > large
> > > > > > > > > >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > > > > > > > > > can
> > > > > > > > > >     qualify as out-of-bounds.
> > > > > > > > > >     2) Don't generate new bug type in order to prevent duplicate reports
> > > > > > > > > > by
> > > > > > > > > >     some systems, e.g. syzbot.
> > > > > > > > > >
> > > > > > > > > >     KASAN report:
> > > > > > > > > >
> > > > > > > > > >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > > >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > > > > > > > > > cat/72
> > > > > > > > > >
> > > > > > > > > >      CPU: 2 PID: 72 Comm: cat Not tainted
> > > > > > > > > > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> > > > > > > > > >      Hardware name: linux,dummy-virt (DT)
> > > > > > > > > >      Call trace:
> > > > > > > > > >       dump_backtrace+0x0/0x288
> > > > > > > > > >       show_stack+0x14/0x20
> > > > > > > > > >       dump_stack+0x10c/0x164
> > > > > > > > > >       print_address_description.isra.9+0x68/0x378
> > > > > > > > > >       __kasan_report+0x164/0x1a0
> > > > > > > > > >       kasan_report+0xc/0x18
> > > > > > > > > >       check_memory_region+0x174/0x1d0
> > > > > > > > > >       memmove+0x34/0x88
> > > > > > > > > >       kmalloc_memmove_invalid_size+0x70/0xa0
> > > > > > > > > >
> > > > > > > > > >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > > > > > > > >
> > > > > > > > > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > >
> > > > > > > > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > > > > > > > index 6814d6d6a023..6ef0abd27f06 100644
> > > > > > > > > > --- a/mm/kasan/common.c
> > > > > > > > > > +++ b/mm/kasan/common.c
> > > > > > > > > > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> > > > > > > > > >  #undef memset
> > > > > > > > > >  void *memset(void *addr, int c, size_t len)
> > > > > > > > > >  {
> > > > > > > > > > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > > > > > > > > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > > > > > > > > +               return NULL;
> > > > > > > > > >
> > > > > > > > > >         return __memset(addr, c, len);
> > > > > > > > > >  }
> > > > > > > > > > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> > > > > > > > > >  #undef memmove
> > > > > > > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > > >  {
> > > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > > +               return NULL;
> > > > > > > > > >
> > > > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > > >  }
> > > > > > > > > > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > > > > > > > > > len)
> > > > > > > > > >  #undef memcpy
> > > > > > > > > >  void *memcpy(void *dest, const void *src, size_t len)
> > > > > > > > > >  {
> > > > > > > > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > > > > > > > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > > > > > > > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > > > > > > > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > > > > > > > > +               return NULL;
> > > > > > > > > >
> > > > > > > > > >         return __memcpy(dest, src, len);
> > > > > > > > > >  }
> > > > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > > > index 616f9dd82d12..02148a317d27 100644
> > > > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > > > @@ -173,6 +173,11 @@ static __always_inline bool
> > > > > > > > > > check_memory_region_inline(unsigned long addr,
> > > > > > > > > >         if (unlikely(size == 0))
> > > > > > > > > >                 return true;
> > > > > > > > > >
> > > > > > > > > > +       if (unlikely((long)size < 0)) {
> > > > > > > > > > +               kasan_report(addr, size, write, ret_ip);
> > > > > > > > > > +               return false;
> > > > > > > > > > +       }
> > > > > > > > > > +
> > > > > > > > > >         if (unlikely((void *)addr <
> > > > > > > > > >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> > > > > > > > > >                 kasan_report(addr, size, write, ret_ip);
> > > > > > > > > > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > > > > > > > > index 36c645939bc9..ed0eb94cb811 100644
> > > > > > > > > > --- a/mm/kasan/generic_report.c
> > > > > > > > > > +++ b/mm/kasan/generic_report.c
> > > > > > > > > > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > > > > > > > > > kasan_access_info *info)
> > > > > > > > > >
> > > > > > > > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > > > > > > > >  {
> > > > > > > > > > +       /*
> > > > > > > > > > +        * If access_size is negative numbers, then it has two reasons
> > > > > > > > > > +        * to be defined as out-of-bounds bug type.
> > > > > > > > > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > > > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > > > > +        * so that this can qualify as out-of-bounds.
> > > > > > > > > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > > > reports
> > > > > > > > > > +        * by some systems, e.g. syzbot.
> > > > > > > > > > +        */
> > > > > > > > > > +       if ((long)info->access_size < 0)
> > > > > > > > > > +               return "out-of-bounds";
> > > > > > > > >
> > > > > > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> > > > > > > > > prevent duplicates. "heap-out-of-bounds" is the frequent one.
> > > > > > > >
> > > > > > > >
> > > > > > > >     /*
> > > > > > > >      * If access_size is negative numbers, then it has two reasons
> > > > > > > >      * to be defined as out-of-bounds bug type.
> > > > > > > >      * 1) Casting negative numbers to size_t would indeed turn up as
> > > > > > > >      * a  "large" size_t and its value will be larger than ULONG_MAX/2,
> > > > > > > >      *    so that this can qualify as out-of-bounds.
> > > > > > > >      * 2) Don't generate new bug type in order to prevent duplicate
> > > > > > > > reports
> > > > > > > >      *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
> > > > > > > > frequent KASAN bug type.
> > > > > > > >      *    It won't prevent duplicates. "heap-out-of-bounds" is the
> > > > > > > > frequent one.
> > > > > > > >      */
> > > > > > > >
> > > > > > > > We directly add it into the comment.
> > > > > > >
> > > > > > >
> > > > > > > OK, let's start from the beginning: why do you return "out-of-bounds" here?
> > > > > > >
> > > > > > Uh, comment 1 and 2 should explain it. :)
> > > > >
> > > > > The comment says it will cause duplicate reports. It does not explain
> > > > > why you want syzbot to produce duplicate reports and spam kernel
> > > > > developers... So why do you want that?
> > > > >
> > > > We don't generate new bug type in order to prevent duplicate by some
> > > > systems, e.g. syzbot. Is it right? If yes, then it should not have
> > > > duplicate report.
> > > >
> > > Sorry, because we don't generate new bug type. it should be duplicate
> > > report(only one report which may be oob or size invlid),
> > > the duplicate report goal is that invalid size is oob issue, too.
> > >
> > > I would not introduce a new bug type.
> > > These are parsed and used by some systems, e.g. syzbot. If size is
> > > user-controllable, then a new bug type for this will mean 2 bug
> > > reports.
> >
> > To prevent duplicates, the new crash title must not just match _any_
> > crash title that kernel can potentially produce. It must match exactly
> > the crash that kernel produces for this bug on other input data.
> >
> > Consider, userspace passes size=123, KASAN produces "heap-out-of-bounds in foo".
> > Now userspace passes size=-1 and KASAN produces "invalid-size in foo".
> > This will be a duplicate bug report.
> > Now if KASAN will produce "out-of-bounds in foo", it will also lead to
> > a duplicate report.
> > Only iff KASAN will produce "heap-out-of-bounds in foo" for size=-1,
> > it will not lead to a duplicate report.
>
> I think it is not easy to avoid the duplicate report(mentioned above).
> As far as my knowledge is concerned, KASAN is memory corruption detector
> in kernel space, it should only detect memory corruption and don't
> distinguish whether it is passed by userspace. if we want to do, then we
> may need to parse backtrace to check if it has copy_form_user() or other
> function?

My idea was just to always print "heap-out-of-bounds" and don't
differentiate if the size come from userspace or not.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0%2BMwDcB5hV5K%2BA%40mail.gmail.com.
