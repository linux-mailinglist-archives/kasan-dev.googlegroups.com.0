Return-Path: <kasan-dev+bncBCMIZB7QWENRB2MNQ3YQKGQE2JMLXJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E6D6414074C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 11:05:30 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id n9sf18495678ilm.19
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 02:05:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579255529; cv=pass;
        d=google.com; s=arc-20160816;
        b=NFYNnNB2wV6HMo943J9kI80c1JfuKd5RWnBjJDr5qRAttlpELtrGeKmenab2GeR/Sn
         NJo4Evq9bsNTgdNjXH947uj/Y1fSYf3iea7aDJgTsoV+biR3F6+lupvukP4/NPN6Xzwq
         KfkIIqaaFCmUXM5oyT2OMe2YYK5Z3cUBoQPHpYOQq9HFypPAh9js+I4KhPmv+ZT5d1Kz
         R8jiDW64ilVOf/U/6GvKfi0cf2+y8Kr6QrC6jtZWr+JklcQh+l9QsXhFHsoyuL72LC/a
         7Hl36IZ7q5L+xnrBMTXDkEPqB0UDZxcH+vo8PGJt5NDJqlqFNzxmdL0WtJwBXdpGtCQL
         K/Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G+eqzVYlkFx5iRnFVuhii7Z+M577yR7JPoulmGjH5Mc=;
        b=nFmBMw3JbGSAlKx/rnh5T15X4oph61RLn/3JJQrt0uR6A5p0X8MJoWm0epdJkKIZQH
         xoDEPr/uXv5w03LL5lUiNWzsvH7oifp1UW+ArFK32JA2YowNtoHTzdS3zcEB6WZ1pSMH
         mBy9UYfJ5RFM5nWk3Vbq1NFs3oGm19SQH2OTtpUZXlVyFq2VXXFSxU3LqUwYVs1YgERN
         eX5KbfmSEONtC1yS7QPgScwjg5WtUNNtiJdinLBS9MpC69Xivbl3+7uqqGpSV0KZnxYF
         vRQjL4SFJCB64tS7DP63DIw9nyhMcxJpdY67vF7KRqxMetrkB+vcbXPklh6UUK98ac8t
         CeYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mw7wWn7P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+eqzVYlkFx5iRnFVuhii7Z+M577yR7JPoulmGjH5Mc=;
        b=mGY70XQjnlF8nZQ7cPypNuNkGYykRfKmSzZT0vYyaEHGeFqAWGXvGedEqDkZ2s/RC/
         HpIzIY/59KwAYNuR/XhyKZnp9YCu/7RFu4HoZHYvyzTI5LbeyY/v680K/8+26//freBz
         rWscEJ3iHnNCaLFp65ZAqJBkfnhjxhu102dDCA4/D2VZUMs3cHZ2zvfhuNEi+D7lDBTw
         VUErjfPVXQ+hk55IsXQs8fElnkdUD4nqMBdai3WhVlHEtABR1jIy/i1ctHwZh+BbqKG3
         YKYTTN4TF3px9jj2Uj0TA40byGLOcp2HYkuaJg0jqSgUNkriwuaoSHj+RECG7WF3UWLs
         JBQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+eqzVYlkFx5iRnFVuhii7Z+M577yR7JPoulmGjH5Mc=;
        b=N7OMbgnoVTlf1mGNbkITDaap4SazLCyH3mf9sww/jzHVYy6Kz9u0sbmNKXji0SWILd
         Q1SjGl9SZ9gDTujZ4sVgeTCx4dn+LiWnLCaMCsam137AXvi1ZkKLIqU2pOUaov5fR3fL
         oJ1KExyk1BWRIViCY1ue5qoqhRlEWSwA1m8JJThQuADoB659hkRCNl8inWugfTII9KqP
         RWly/AHdiXOW5D2/idx795a4SJdQ78VIsK3/WHxtfshcThCxgJAZY9/ZFge231UhyFd0
         PIulC1I81aha5kO8kLBZ9SWiEkS2Jtl6IhGl12jL6SGP+4fX4LJEZ6fH/Fr99N0DisyT
         hWag==
X-Gm-Message-State: APjAAAUcJijncgwlbzEZhZjzDAyeOOlqnbw28zshIgHM+DJ1Merqyy9U
	P6JCw/DuR31UdiKfZ7KpD54=
X-Google-Smtp-Source: APXvYqy3TWGs7whUHtrUhE8cN/mY081Y2ks8qtEPMynmQab4ORqCrjxx6J3K2P9fEkdxfKcwZnCjzg==
X-Received: by 2002:a02:856a:: with SMTP id g97mr508150jai.97.1579255529271;
        Fri, 17 Jan 2020 02:05:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:8f2:: with SMTP id n18ls4435743ilt.15.gmail; Fri,
 17 Jan 2020 02:05:28 -0800 (PST)
X-Received: by 2002:a92:d185:: with SMTP id z5mr2409105ilz.132.1579255528806;
        Fri, 17 Jan 2020 02:05:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579255528; cv=none;
        d=google.com; s=arc-20160816;
        b=dSNPP5da88YDd5opD7Yrat+ODyaqrQRaZA7OAiHXHxQ8mp1pdx0+YqpCTEkAccyZbX
         ews+VMxSaVOSvFsIIIXZog3N0DZjFHJu9P7hKR+7kvGB7iCbKGET3gksoyKfz7MfV877
         4x+FdrKLIZZAgRheu4sDegXlxeEEtuaiIo65e8NQS0uqzrHGfy8sFpUpaQU0RZrRaTZB
         zGAYAIOmXoRhaKW0OUZ1L8hVpK4Flcq/mR8y0oXeVjal13MwNnilzwC6SHlRvbz4WfIF
         u64+A6fINCqWkB0X30turwKpYVkeGm9AdRaffbUGfNbnrnsR/UEqvDO3BhhXUS5VpEFu
         sn1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w/2c5M/UzJFnbWr1rvLc1suSEZvfABkxh5yg/ucrfTY=;
        b=ZA/wCskHK41Cm5JrU4nzOEqTx7+0M1pu1bdJN+6+HCmtgL+e55ktubU7oyg4yahsqi
         f96xkDLtyVSGhfgf8IkVNnNK4cVTa0ifiSYyh/3ByMKXqR9r/sk2GuKJcozQKJndocLL
         Gtl0hhkq5OUmR4dXVVPJr2K7vEEsE6DXSxeMs9w+OcN3aqRmTGpfmLuNzoYI6TMOq+xv
         +NdVL/3xcSs83F27lLuE2a3qHJe7dACGk7CH8hzFPP2Z+TCPY7ETEwlUYEOgpnNSVBGB
         +kAsokCEBodHbqKg6RiC5UzA52zEA0IJZxi7ntsvNGzx0T5wzQI7xF6t//6C1pbaqo87
         PX8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Mw7wWn7P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id a1si1243339iod.3.2020.01.17.02.05.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 02:05:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id c16so22127348qko.6
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 02:05:28 -0800 (PST)
X-Received: by 2002:a37:5841:: with SMTP id m62mr36462569qkb.256.1579255527934;
 Fri, 17 Jan 2020 02:05:27 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
 <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
 <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com>
 <CACT4Y+atPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF=+Uu5hw@mail.gmail.com> <CACT4Y+bsaZoPC1Q7_rV-e_aO=LVPA-cE3btT_VARStWYk6dcPA@mail.gmail.com>
In-Reply-To: <CACT4Y+bsaZoPC1Q7_rV-e_aO=LVPA-cE3btT_VARStWYk6dcPA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 11:05:15 +0100
Message-ID: <CACT4Y+Z6_CwVyJhr3SdDejFsrXcM11LVY+gh4oKP6k03Pn95AA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Richard Weinberger <richard@nod.at>, 
	Jeff Dike <jdike@addtoit.com>, Brendan Higgins <brendanhiggins@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, David Gow <davidgow@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Mw7wWn7P;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Fri, Jan 17, 2020 at 11:03 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Jan 17, 2020 at 10:59 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Jan 16, 2020 at 10:39 PM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > >
> > > On Thu, Jan 16, 2020 at 1:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > On Thu, Jan 16, 2020 at 10:20 AM Johannes Berg
> > > > <johannes@sipsolutions.net> wrote:
> > > > >
> > > > > On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> > > > > >
> > > > > > Looking at this problem and at the number of KASAN_SANITIZE := n in
> > > > > > Makefiles (some of which are pretty sad, e.g. ignoring string.c,
> > > > > > kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
> > > > > > initialize KASAN too late. I think we need to do roughly what we do in
> > > > > > user-space asan (because it is user-space asan!). Constructors run
> > > > > > before main and it's really good, we need to initialize KASAN from
> > > > > > these constructors. Or if that's not enough in all cases, also add own
> > > > > > constructor/.preinit array entry to initialize as early as possible.
> > > > >
> > >
> > > I am not too happy with the number of KASAN_SANITIZE := n's either.
> > > This sounds like a good idea. Let me look into it; I am not familiar
> > > with constructors or .preint array.
> > >
> > > > > We even control the linker in this case, so we can put something into
> > > > > the .preinit array *first*.
> > > >
> > > > Even better! If we can reliably put something before constructors, we
> > > > don't even need lazy init in constructors.
> > > >
> > > > > > All we need to do is to call mmap syscall, there is really no
> > > > > > dependencies on anything kernel-related.
> > > > >
> > > > > OK. I wasn't really familiar with those details.
> > > > >
> > > > > > This should resolve the problem with constructors (after they
> > > > > > initialize KASAN, they can proceed to do anything they need) and it
> > > > > > should get rid of most KASAN_SANITIZE (in particular, all of
> > > > > > lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> > > > > > (in case it does not work now). The only tiny bit we should not
> > > > > > instrument is the path from constructor up to mmap call.
> > >
> > > This sounds like a great solution. I am getting this KASAN report:
> > > "BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x2a5/0x2c7",
> > > which is probably because of this stack instrumentation problem you
> > > point out.
> >
> > [reposting to the list]
> >
> > If that part of the code I mentioned is instrumented, manifestation
> > would be different -- stack instrumentation will try to access shadow,
> > shadow is not mapped yet, so it would crash on the shadow access.
> >
> > What you are seeing looks like, well, a kernel bug where it does a bad
> > stack access. Maybe it's KASAN actually _working_? :)
>
> Though, stack instrumentation may have issues with longjmp-like things.
> I would suggest first turning off stack instrumentation and getting
> that work. Solving problems one-by-one is always easier.
> If you need help debugging this, please post more info: patch, what
> you are doing, full kernel output (preferably from start, if it's not
> too lengthy).

I see syscall_stub_data does some weird things with stack (stack
copy?). Maybe we just need to ignore accesses there: individual
accesses, or whole function/file.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ6_CwVyJhr3SdDejFsrXcM11LVY%2Bgh4oKP6k03Pn95AA%40mail.gmail.com.
