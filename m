Return-Path: <kasan-dev+bncBCMIZB7QWENRBYNTR3ZAKGQEZSDJ6CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6926515A137
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 07:23:30 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id z13sf662917otp.7
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 22:23:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581488609; cv=pass;
        d=google.com; s=arc-20160816;
        b=EOSxNN3U4cz4rnijcgkQjA1LYaFbVF18OVUX1BtMPT27Yceq/8SroYvUHSORUyWQ76
         QvKbgVOppHujQdlVDYBhiXBqUBTnHRWrM18T4qFVKJYscsLdqixSBb0vyQ4TvUzlF76I
         EE3s4rBzIKiu5Q/w8zEZ6c9wt9fCaZB7siGRABUA4BV3Kc8Y0huVsViZ61+JahYNd8/0
         krB/pQ0l2Iqro9MGbd8RHZiWzG4e2ucMG0rmzDZhXNW/XT7QpUD7GhtpYM671QGMBTHn
         MBRRblwWwMgQ7KoRWXTw/ycF2EFQcr4Jb0Sv2Y3aotgAeHio6MOI1Hnjy+ZUv0+M+3FQ
         pyqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vH+rchUngcpTf0xwDepUuYp6OebmNhqw6WsKtx/b1d4=;
        b=EPa0Si0ThsYaAbzptSPgIIZ3rTiFPgU/i/Y8xi82Ak0+qoltCDRDvtXy501Y6ECqES
         0jfd2Rq7JknEdAloXiQSWV/T6lSsFkRqYubbh9Ul5ebeGw5f2SFN7/DU2+fNdsFv0bPk
         gJDc9f94AWxQOOS9aa4gl9bINZ1DBcmPSZ6TY1vdHmC9rJPhefvTKjDdR1AvZUJ1pgPb
         uAO6bhC0g+ZXECDa3lkDJRHWGmmLlvOlDXqo/1/9PGm62SeDGCbccL3KsRBpxQlYOlSA
         70dqbZlgOLX8Xs890uUUX3/TluIFO2hKuQ4FtOsjoHwX1krq+BhDlZOFJnDPRyhZCOtv
         g6qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qwHaZKo3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vH+rchUngcpTf0xwDepUuYp6OebmNhqw6WsKtx/b1d4=;
        b=HqOO5woSh0zZsYoD5/YX5f646axD8s/JqCLTmrZGsTUdAzP8i9Vqq16w6IQLLoKKJe
         zi4UMpNIuKQ9ICxAzB0qlGzke+ufUMix2qrfXofc47J8S0e3fIt/FQxvvm8U9qNrZbY7
         wfNcOPZH+v1/J97e9F5M71LKyiRVluiVn4IYYbsb9saoo2eAH37eDPw0kScVPdZtqHil
         4JaQaq9ADBYtffSCPhvewsIuH10rubOy6rqMtSxXrz+wljvV7dLU4r6phRaPeZBBI1lQ
         GqiCcj61cD0T/74KCefgqfq9Wf9DlFpEQjP8vkh1Xsw39QsMvAobpQcLyOiQXaxZziAz
         kfVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vH+rchUngcpTf0xwDepUuYp6OebmNhqw6WsKtx/b1d4=;
        b=cpMo5dApQEIFKBrfvQqBzk/zGHXYnNJPyZRtiRgJhW9A4abczkEYrBoJ/95p3HXXlo
         c5AJEZ6KXZjdkhclLrDylRS7G7IA62o0JbjaMLjtxK9GyHBZhsmENNPr4F9lpHjnlK8H
         H4kjtKevGuBxV6pRERj3OqYXpUsT94blEUh8S+sVnFE2qhSlL1EN7UoUHRsU6sVwjVaH
         ZOdcgLWdj/niluXRbf9v14xkx/hG0GhR9q3zyGfLtMKqW1pnh+mtOXCO+VWCgyiXAk3a
         LCKJqfsoBMIEsRwYrzhsYJ6P2zYomawy0BZ0J6d7YrPHeQ20KMuzmAcckE/bsnlaKRYv
         2cYA==
X-Gm-Message-State: APjAAAV/nsoPqpsFzM6X5GoDHCYv7Chsiiw4QUD5nxiNksie1hwFOfSP
	hoDrKwzIgc2o2YWMqqAuzys=
X-Google-Smtp-Source: APXvYqyveJmY+H6U9zdMfluoFUSBI7tX7R6Q/z4AmTqFfa/yutJM5xAgUkpOwSjddglLvMXZJK1LNg==
X-Received: by 2002:aca:be57:: with SMTP id o84mr5255949oif.138.1581488609239;
        Tue, 11 Feb 2020 22:23:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4e14:: with SMTP id p20ls4163686otf.4.gmail; Tue, 11 Feb
 2020 22:23:28 -0800 (PST)
X-Received: by 2002:a9d:7c9a:: with SMTP id q26mr8474514otn.206.1581488608912;
        Tue, 11 Feb 2020 22:23:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581488608; cv=none;
        d=google.com; s=arc-20160816;
        b=FaDYh2w5EAtXNyagENzJ57I2nX0e2FMxB9G4jBj1Fq2TFFCXc+iwHk/EpPky6mqCUk
         Cu2scbQ2iSx+6D1gbiMf4gTqsVt8ov2cLlXoQbVc/zD+ZIIm2kxjqVWxWN/Es5eghJ+r
         aOtQX+sFYqSX0VYOz7Ngs/Saz0IO3Z5i7iUJJFDqOJJny5OkB756I5093pVoWlD/tH8r
         dM14R9SQIVwae/ezJADVoR0/cBDQk5RLoDnkXSqaISrvgytopMw3nXCgA/+oI/h5IjDl
         DPBiJx95AZ2YAmnP0z62aASW71Lmksex05ppb9f6vhWrKQ7Xd88stNi7br0WawhH7lyb
         mkPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wCIGTDCK3CFLiIsiFAwO9TOgJOimjyz3BYLMXapp1co=;
        b=jQuNh5wwYve5/ZbhOBt+dSBBr5K0XZ00l6Wdf9/V0qp/VsFyfd1zW9fWRWswlAxIIj
         3kfxyEzO+fRabU/0esRbs+LOs++1oLDc3hgIMlHfe0c18VCeJjfNu4QXlrmNLD0jhBr+
         FyoWxLa+9E8qzQwceWAw4S7sz7ywrfht4amN/CYyjr+nQvs/col18Vk+q51C/vbLybIi
         j8NoYZIXDtRhHLY66oLiwJ4kV+rWZtChA2Kikpo1970f8Rl+K9d9ibQdWb5hH3uU7QX6
         GiHf0Bfb6oQc8DJDDf7y/MXA86I6lMl+fTPVhq1uVasPy25CyqR06euNB410g8uxseDY
         OBUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qwHaZKo3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id o11si324448otk.0.2020.02.11.22.23.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 22:23:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id n17so813608qtv.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 22:23:28 -0800 (PST)
X-Received: by 2002:ac8:7159:: with SMTP id h25mr5774429qtp.380.1581488608196;
 Tue, 11 Feb 2020 22:23:28 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <CACT4Y+bPzRbWw-dPQkLVENPKy_DBdjrbSce0f6XE3=W7RhfhBA@mail.gmail.com> <CAKFsvUKhwAOV9O+LWBr=-zLEJCFJvKOH-ePsXMMVJzHotqd3Ug@mail.gmail.com>
In-Reply-To: <CAKFsvUKhwAOV9O+LWBr=-zLEJCFJvKOH-ePsXMMVJzHotqd3Ug@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 07:23:16 +0100
Message-ID: <CACT4Y+aRq9j=3GODWBcnDnW=Pgp4e=N2++FTYEuq-00OmfXpbw@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qwHaZKo3;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Wed, Feb 12, 2020 at 12:48 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Thu, Jan 16, 2020 at 12:44 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Jan 15, 2020 at 7:28 PM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > > +config KASAN_SHADOW_OFFSET
> > > +       hex
> > > +       depends on KASAN
> > > +       default 0x100000000000
> > > +       help
> > > +         This is the offset at which the ~2.25TB of shadow memory is
> > > +         initialized and used by KASAN for memory debugging. The default
> > > +         is 0x100000000000.
> >
> > What are restrictions on this value?
> The only restriction is that there is enough space there to map all of
> the KASAN shadow memory without conflicting with anything else.
>
> > In user-space we use 0x7fff8000 as a base (just below 2GB) and it's
> > extremely profitable wrt codegen since it fits into immediate of most
> > instructions.
> > We can load and add the base with a short instruction:
> >     2d8c: 48 81 c2 00 80 ff 7f    add    $0x7fff8000,%rdx
> > Or even add base, load shadow and check it with a single 7-byte instruction:
> >      1e4: 80 b8 00 80 ff 7f 00    cmpb   $0x0,0x7fff8000(%rax)
> >
> I just tested with 0x7fff8000 as the KASAN_SHADOW_OFFSET and it worked
> so I can make that the default if it will be more efficient.

I think it's the right thing to do if it works.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaRq9j%3D3GODWBcnDnW%3DPgp4e%3DN2%2B%2BFTYEuq-00OmfXpbw%40mail.gmail.com.
