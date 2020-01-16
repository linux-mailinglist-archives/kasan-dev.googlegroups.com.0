Return-Path: <kasan-dev+bncBCMIZB7QWENRB3OUQDYQKGQECDQXSCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B138E13D692
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:18:38 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id g15sf12922998qvq.20
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 01:18:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579166317; cv=pass;
        d=google.com; s=arc-20160816;
        b=NfmdkXhzInsN701+jYfwBInFITz2GtwCpv1IoXAazC7oHeSHdOSGmsN4/80XT/saAT
         oo/RSFMEIRBavVKjDJN1jECo2AT4VBo06AyQ2s64Lodn2n76R4kJYP+J9+r+umiMWGrX
         iaJJ6kG7hoBoALs2lcsWXKVmpoiY1ms+VU/vbw/VuXLsMzsToeskshfGN1/DPMH9Mqvt
         +xcDq88+TnWwBDXUSL3TOqArzMkZ6LXPJ6P+iiYONnRpfjWWUq4licgykJaGlVQklN34
         FP8wf6lRzMQXeHTLIdnleqeQlmZqgGaEpx+WBmEV4FQTiRSDOoZFQRFyN1gbrBEx4U7J
         888g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ljDZlgvw6vFCFNbz0DdbXEodCt1VptyMc68WH7m8VTc=;
        b=Qv/5cSlOhmgrPjJ+uKUe01QHBni3LrrQkbWsAnel0x2e2BQvR8wjJHJ3mFcLsxYFyi
         qtk0xYjsPHMmWHb9bYNBxO9L38RIabDjA4e1LIYHvT1b6r8Zre8jPeB7dLqVy1UiwePN
         EDRAYfMaqYYgyZrRwSz+Zf3Ng9MVls7itT2QPQIUKiQkPYA6Bk7gsRuHrUSsg+zVyvJ5
         By6NzWuA2q3IvJf0hsMLcy1YVvCQUXCLHAmEXPM4sOV8/JQclM7B5egxwYfUGT4LB2Bx
         mq3YluN/eWOFfgwTDTicA+mKCGs5hoXzHrPICFplegVMXQk4pnrw44YiUGhNauP6UOX5
         ex8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SYYbnAVS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ljDZlgvw6vFCFNbz0DdbXEodCt1VptyMc68WH7m8VTc=;
        b=mobFtsITLLERnnUZg4PPe4659XOgRIq7qAkEArjiM1SIwnQQ7/B4+q9Nz2vNc1ix2e
         Z02wo66CiT2+a0qloUksCon3hfI0+mmITrNTsz+PmLWWygjaOJZfAwmq9ZLV0d7BiKMm
         S4cbve3PIt5VI5Uk/3xY5Du9h+8psYBn4+MHB/t9/GmJ+KpKM94K4Na5CwTz8r2RBLAB
         nVXEpAoqKCrUQfyklXB+pNUQr/06hznLJFJWcZP1pLgX/IJSR1PjS9NzibqpgUl3wU7n
         vNEDfWcSb9E+dkmR5/AZoGc5DCfxq+OCCe3aplMxVVuGj/2ip1GmhewrD3WXSv7yB/M4
         xd4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ljDZlgvw6vFCFNbz0DdbXEodCt1VptyMc68WH7m8VTc=;
        b=sWtiSQmA74gVoIdXHrakOh9v8dVtIF/ZlPVI1KC70mZfQvC28ZhLwReA0AYmZupOeq
         e6mQDlUyjtiYEpIExAWBek4GxSs9ALqsrWn5cvkHXXc9Y3UxUTeEtKvva4atDRuc/xX5
         cDJgoYcj9Fr5X2eFxGG7pn3Otd7MvMvl7wKDz44ImiyLl8kmmXD+jTAMfhgJQdaNufkx
         oD3dddrC7Os4O1L4OToBz+HnH2vflzgYWbdWogFVbbCOPB38XhGUdrkC42NKDY07ThvY
         +6wgK3t5bFpi246HAN16Q0M4niOB2zJhYp9kpUPlJVTfcZSNm4CtMcO68KIMcv1ZbMV+
         zBZw==
X-Gm-Message-State: APjAAAXEyIe303Or4H3c6nNp+phTojhRdIS52Q4u+XdvRggkDUwxl1Ff
	5RHsj/F4iuwijH4qm4utzSU=
X-Google-Smtp-Source: APXvYqzmzhZaYZiXnwsKe46GOfBIPfhk0Udbtt9rnCiDgFQQCc56wYIwJY/y/+25ZWUesduHDmN/qw==
X-Received: by 2002:aed:3b79:: with SMTP id q54mr1416558qte.187.1579166317731;
        Thu, 16 Jan 2020 01:18:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:350c:: with SMTP id y12ls3997341qtb.10.gmail; Thu, 16
 Jan 2020 01:18:37 -0800 (PST)
X-Received: by 2002:ac8:6747:: with SMTP id n7mr1415442qtp.224.1579166317410;
        Thu, 16 Jan 2020 01:18:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579166317; cv=none;
        d=google.com; s=arc-20160816;
        b=KhU/6rIYovucARlJfZLEPPozNhoxf0YQdJ+xXxjrccN41KJ5TTAroviaIMq6z5HWqW
         sUPOdwQCjCMOvuF+2okfY04wXcsHUzcc5W80VBQjBJoHfXfmmNXcBQu5IqNJR6lecE2A
         nyGBBx7qUt3LVtEH0JzWOcw5MFogkAWs5gsi8rkEvVpsBWeYUoppMnCbdVaHGxkSdIe3
         Vky+qJjScKpGxHxdlqZ9eurgXDAd3XDaxHzJLZv3ECnU2S52hQoS1inHOp9pTOLYn6fE
         Fjo4JRsvFAMESyyd24ufY+H4+k+iW4TRpJm4tCgd4x25N+1G9E9wHTEM/ykLbMLVSl3I
         OqZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6aUm9IZBoyzrmlaZrE7sKzVINYzfYj5bNqwcb9Va7iI=;
        b=lhARWOxsMaVmBNe5lKw0GD/Kh2AfQqAUadIlgm71oa++nFMO/ywxpWDeLo0PJAVNoC
         6CODYhbqhEePjg2LUR5+w9/F7fh2UW9uQuikcnCJWBNpwaDO2XZZt5jCBdyzFHfd8o6E
         8apJ1OgcAEtVcvILBLqh9poaPfPkICOIpTJneH++SnzEnqPX6HiMlRzfrBm0Hm9xKnpi
         QIYh+QcCPCrwMS5ytxhXosLDJ+bbVZf1i7F5F+Go9TRC6YwonwFjrEg+CC71azbQZnYr
         tgocGz7jzKDvU4IeX2x6x6zUBLuqmLkB2XxxBDwyDafJ2AtSmBRcSyb+q4q225I4E4S5
         TxeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SYYbnAVS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id r62si724357qkc.6.2020.01.16.01.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 01:18:37 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id u1so8731641qvk.13
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 01:18:37 -0800 (PST)
X-Received: by 2002:a05:6214:1103:: with SMTP id e3mr1646963qvs.159.1579166316797;
 Thu, 16 Jan 2020 01:18:36 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net> <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
In-Reply-To: <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 10:18:25 +0100
Message-ID: <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=SYYbnAVS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
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

On Thu, Jan 16, 2020 at 9:03 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Thu, 2020-01-16 at 08:57 +0100, Johannes Berg wrote:
> >
> > And if I remember from looking at KASAN, some of the constructors there
> > depended on initializing after the KASAN data structures were set up (or
> > at least allocated)? It may be that you solved that by allocating the
> > shadow so very early though.
>
> Actually, no ... it's still after main(), and the constructors run
> before.
>
> So I _think_ with the CONFIG_CONSTRUCTORS revert, this will no longer
> work (but happy to be proven wrong!), if so then I guess we do have to
> find a way to initialize the KASAN things from another (somehow
> earlier?) constructor ...
>
> Or find a way to fix CONFIG_CONSTRUCTORS and not revert, but I looked at
> it quite a bit and didn't.

Looking at this problem and at the number of KASAN_SANITIZE := n in
Makefiles (some of which are pretty sad, e.g. ignoring string.c,
kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
initialize KASAN too late. I think we need to do roughly what we do in
user-space asan (because it is user-space asan!). Constructors run
before main and it's really good, we need to initialize KASAN from
these constructors. Or if that's not enough in all cases, also add own
constructor/.preinit array entry to initialize as early as possible.
All we need to do is to call mmap syscall, there is really no
dependencies on anything kernel-related.
This should resolve the problem with constructors (after they
initialize KASAN, they can proceed to do anything they need) and it
should get rid of most KASAN_SANITIZE (in particular, all of
lib/Makefile and kernel/Makefile) and should fix stack instrumentation
(in case it does not work now). The only tiny bit we should not
instrument is the path from constructor up to mmap call.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbrqD-o-u3Vt%3DC-PBiS2Wz%2BwXN3Q3RqBhf3XyRYaRoZJw%40mail.gmail.com.
