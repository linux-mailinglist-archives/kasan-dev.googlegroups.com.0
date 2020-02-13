Return-Path: <kasan-dev+bncBCMIZB7QWENRBAMZSTZAKGQE574T7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CC3615BAF4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 09:44:51 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id c22sf3177946qtn.23
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 00:44:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581583490; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z7S1XiPY8gdrXnVFsXOtNUY5vDTAAWFwWoRyvuLH6Ve8mAolxEf18HBJM9nRzLKmrq
         kQyzNVE68/JpCmI8KLs6WuEtP7imOcK3Gc7lUjT61bCQFTX6n1mKDwMkBxXlmXhD8klG
         VzqwIkFsi2IdM39yU7HiqGmIJV+oc2NP9o3DdNLU4AhlH/ESOrEu1ut0DAAoM5leR7/+
         DQWvM7DfqDr3WzoFxp1zRavLshgFyzNLRXi6rMV+kmGilGbgAOQj8Irg/0FgyVQHAZy4
         224oEcoTrQTLvYK6L4geql3XPCT5CTiI10TSy/bulgmtlhaJogBBym2JNthA3pSESMoP
         LSdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vyG3n3SUxP7NUDr9eLt2nM+eOTRTE1BWkPrdIMtk8GI=;
        b=ngmqn7eNnJOj25JHqf9xbt0huJDrKo8032OqV+jdeUf2Z/O8HAjHvF77FUP9bNo7O6
         BfU7qPSVWXxOz3set6BCpfvuImFkKxMrvob1x8QVHBquJZXslOG+hhgoaLiQqWb7Hr0y
         7zGcLK0x4aQEqAYA1/itg/7n0aRtkPM18Z61sOpBE7H9/n61Yt2xCBAEsffLvYqgMWh4
         lj7i2qGo1QNTaZUcBCnvF0Wz6F5Ajahy/mC66CURR1tTwWJ3k65Slx5ffgNEHYeAy5Ci
         8fSovtQfn2vEgoTwL0Sc3fHd0B9TGIsTYfO20S1kQKJx1FvRVW4zmQckEw8pCeE5LZS3
         PMpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NPtaUJUr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vyG3n3SUxP7NUDr9eLt2nM+eOTRTE1BWkPrdIMtk8GI=;
        b=lVyFnMZ3g0uZNDJwfSnJjlKAQk3AnTTkOWJbtfdcQZG+X+hlMmr08FIQj85Nh6R4FF
         ZI4XzNXLpdp7oWE2+1ie7ALGmSw0UkIhNsg1MGzgluRcBKjRyP4XaeIGrQb34jDfRjf6
         8qqx210h41G7DO5IlDgIzZzHK+CgwSLcWx+vdTpJQ17jNwaQ6O9JYpPkRMJWSbU4ORdG
         GT9iI71kk7nn3lW2EbAAGRAqWtZ9aN+fqCFa3Bvdr/z2TXiPF4F+rZRQtrtKYl9+PUsV
         JH2PeXVf75c1BEUL5I9KEsQtNWXOeWPLZVZ1g0RmWWvwkxU1IS1sMvMri1gfxSZrtBRj
         cS+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vyG3n3SUxP7NUDr9eLt2nM+eOTRTE1BWkPrdIMtk8GI=;
        b=RBfQagO8j2soSUrCKr6QtyRWw9hPcCRVQTGyZDxkftazqsv1Sgr0cCQDgw3PiBbE6c
         PC6dO4UtRS3Wl7wr1lqsBILmZN5RGifOstmMpMgdzBFqFPm5PgjJTJ4+r8vwaCLv3n4V
         2GSDJTylbewdjPzQgdc7K9F2f+mXvKav37VZf/8R9fnyiKQ6MY7NjuLWc7Qod3LA2ze6
         /OfCXY/rerBJKXKIhdD6F8du/V6GCeiIUyWoJ7bZ6Lnav0UOh4YJ+UsgZswXm6B0n19Z
         t1MKFnB/mQzvUccsKKV28vzdzYQy/sIKGUVYdYGhI4HULAozRaIipQ5rKnw2tJmGGxPf
         3e4Q==
X-Gm-Message-State: APjAAAV+cOkNlCeptH4iXmyMDu7MI13uXw98H2utnAPf1tis4STtQJ5q
	BGC5YKkc0txjfemCNYxN1eY=
X-Google-Smtp-Source: APXvYqxFIqBFc+nPkdQFTcmx/KY3GHIkYbV+zy+KoENm9CTqXt8ywyvB8fmyW6mjlGX4edJ7tZ71fQ==
X-Received: by 2002:ac8:3fd5:: with SMTP id v21mr10692541qtk.345.1581583490096;
        Thu, 13 Feb 2020 00:44:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4526:: with SMTP id l6ls4275862qvu.1.gmail; Thu, 13 Feb
 2020 00:44:49 -0800 (PST)
X-Received: by 2002:a0c:f910:: with SMTP id v16mr23225301qvn.108.1581583489691;
        Thu, 13 Feb 2020 00:44:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581583489; cv=none;
        d=google.com; s=arc-20160816;
        b=WF79gJoUu4lFuiXuZ1Z5S0wUS2UOM3xF3NO3FZKLRO+3p2M3XqESmLhamS8KYYoCJr
         8B3nVbrPV06BYf+zhMozwJeb7OKxdk7aVwISlMisft97a12QkGmBe1TiHXZZ/lh7aEAH
         ++begl/aQ+17cG4/EaYpirvNywz+Gr3WQWch0AayXhMcwosc8/zhgDPcNzQN0snoeqmw
         RZI2P5/hqv5RiNA74bwQBq2FfdCjpR9W4RXfuZIRIfje6h9u7Qp4xSETxf/GDpZrzY/d
         1PoqxfONYtSr2Xb+/9n4mc+mBN57t/OMpPjOINZfBnM0kAvIJZFHSM/8TYniwgeq2hr+
         m9+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KOSVM3SCrmejITCMr3GluXgYMymHjzYiqiilJMCtfIo=;
        b=c6RWbsc7VP0Z6CmFb77yT2aDnrK1Bb9iKLp5Pc6KPz3nsap9oyl+J03eOIXK6Y89Bu
         Vh0kMhZrypMu1iNLQifKUzmCTGoQscVjELmDrL6hMMSi6Lp76CnaOpKrEK2Sulql2lgK
         QQdJLbsYLd+khWGMd5eJOo4MnXUbVqdDzYZUcYJKAbTngkXfGfJF00kdeGbp6JF/QpyH
         gZ+yOJdMw9tzq1fTm5Wkip9D5LCelEtiidAbT45QAErzI4zPpvNPPSxjvzucp1y8BeUG
         UqE73UtBX/bOV9+KTtYDYmexXtKLFJPz0Vd1Twt5GmzKRdP1Frwtlx9rCXpdsgFh/S+/
         SOMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NPtaUJUr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id c19si88972qtk.5.2020.02.13.00.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Feb 2020 00:44:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id h12so3842146qtu.1
        for <kasan-dev@googlegroups.com>; Thu, 13 Feb 2020 00:44:49 -0800 (PST)
X-Received: by 2002:aed:36a5:: with SMTP id f34mr10288280qtb.57.1581583489053;
 Thu, 13 Feb 2020 00:44:49 -0800 (PST)
MIME-Version: 1.0
References: <20200210225806.249297-1-trishalfonso@google.com>
 <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
 <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com> <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
In-Reply-To: <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Feb 2020 09:44:37 +0100
Message-ID: <CACT4Y+ZB3QwzeogxVFVXW_z=eE2n5fQxj7iYq9-Jw68zdS=mUA@mail.gmail.com>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NPtaUJUr;       spf=pass
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

On Thu, Feb 13, 2020 at 9:19 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Wed, 2020-02-12 at 16:37 -0800, Patricia Alfonso wrote:
> >
> > > That also means if I have say 512MB memory allocated for UML, KASAN will
> > > use an *additional* 64, unlike on a "real" system, where KASAN will take
> > > about 1/8th of the available physical memory, right?
> > >
> > Currently, the amount of shadow memory allocated is a constant based
> > on the amount of user space address space in x86_64 since this is the
> > host architecture I have focused on.
>
> Right, but again like below - that's just mapped, not actually used. But
> as far as I can tell, once you actually start running and potentially
> use all of your mem=1024 (MB), you'll actually also use another 128MB on
> the KASAN shadow, right?
>
> Unlike, say, a real x86_64 machine where if you just have 1024 MB
> physical memory, the KASAN shadow will have to fit into that as well.

Depends on what you mean by "real" :)
Real user-space ASAN will also reserve 1/8th of 47-bit VA on start
(16TB). This implementation seems to be much closer to user-space ASAN
rather than to x86_64 KASAN (in particular it seems to be mostly
portable across archs and is not really x86-specific, which is good).
I think it's reasonable and good, but the implementation difference
with other kernel arches may be worth noting somewhere in comments.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZB3QwzeogxVFVXW_z%3DeE2n5fQxj7iYq9-Jw68zdS%3DmUA%40mail.gmail.com.
