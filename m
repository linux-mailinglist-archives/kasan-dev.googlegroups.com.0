Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSN5XD7AKGQEBBEWG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C76DA2D1080
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:23:38 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id r10sf622678oom.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:23:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607343817; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEkA2cZ4iiycRWzvAE1ksUK45uqSxttHDAJt13gLS0XYVUSgktqHaKlVjWPNJFEF4v
         emr+TdEn90hFSdYCzZM7qUMoHJ5/PwLb9NNh0ZZST80YPK1+DI2Vr6DV77T9AGp6Sklr
         4RmJiNqNc8yhhWJZ/yEswAxLu2xe1hUeslevJzd8ek5YIOce4ujo0t+FuW1h1KTK/jQe
         x1JE6ANvYORpZOSU3E3F/M/3qiTCZm7HxZg+AUVabVdypllStUYxoZbVSsAenjasnM5B
         JNGIigAXv9xkWYzdRVaGo8/sOSfL/d+akNot814bpH+56I0paiFFo6zeGEF+du+/3s1+
         ru/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+4TWq3OM9Zf3yng0hoySCpcpYGom6tlsxAkQFzqkpp0=;
        b=X1Tr7EkI73eFhivgOqTQzefirRAXBknNRCz0njuy1Ymqcd3hPkGVNepGHE8/uCMKD+
         uPcWP2/gepiodO36/CIMwehqcQmpQIU8C9CINbR1IieRmMRHvH0ERu6Vmm3W5c+VICF/
         LiACRYFybRVBCAQltEZgCEXs8evwKTnC/7CHPleBlEiSzW8cG9ZNkayreD6B6A+2x2Co
         SNcEc3zs5BfdBg8QCeKVj+snVKzIThPhj/WawBTAnp/Sj74k/PbJDA2abm1ATXpyPgKA
         dh2sy0pPNRuUHtKAadbrY6cx/wFsBTSPsu79o1P2tsMlLTxiplkN/JW0smOTml+K3ZXa
         ZsCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="b/Javx/Y";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4TWq3OM9Zf3yng0hoySCpcpYGom6tlsxAkQFzqkpp0=;
        b=FF7PH/qZ5A10jhy6peaA9Ieg8eV8k686R1AntBXm44ec6ugXzA7QVf/LSMSxK0ccFE
         K24Nwhp8kLKsFrNhiDOOHyDufhIrJ65QkMNpV+1G6vtU/ajHU4OmYyoRAXMtj5YSpRLd
         9gFPbuM6Fahho+n8Cl2KcLeXHwxM6Fue4ZwujjN3YWnG7srgBBY86B9NgXXZTpgNxYIy
         oOiui+yBmAUt8x+VH9mF9LTcwtOstqWJ4PjtXQQDYPlqcLvGDHG6dtnAiwPAMk7JnaqS
         lMINqATl1UoWp8EpqjL3e85ZtuvA2kxLbK4EpZNvKDYNnHgfrkWHR6/Bn97Qp8GrdnAK
         hhkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4TWq3OM9Zf3yng0hoySCpcpYGom6tlsxAkQFzqkpp0=;
        b=cZIak7ZbrB4t7n5vIm7TMVi9b9jxKJsgSTnAjGakludV3+VrMv9BxnjBjQaQj2vOKS
         c3JZ73q7UID7Ju93e59tg1QpkLwlgIBexBszhLBFH5rBMze+1ecI4JQTnssbeRA3hclP
         c70PM8XBf1trG7ix7XzdHiSum7iD4dN8ClDIsGS3UoaE1j4jgQbqRXq6sxaSS7ElirOF
         mcsimkgtQvl1tfoQZ18uK4i/sutgsvMkusmpMb7mWN9XOXS1uRNpEAi110xq1JEBnTKl
         eIGkQukuSaAP2G1AEUBjCSGCt3s0VcJNajBY7hnZRhQkQ7Jdoq/UipESzk2SyEGnOTAX
         5AMg==
X-Gm-Message-State: AOAM532eMuWDOeEWBFXM9NLXerDPXklKK5kEnwKoWbDm5EgvBlChy6kj
	RDeToBXWFqhjneq4iz1lc0Y=
X-Google-Smtp-Source: ABdhPJypLYmujHmPGuCCcBJke452cwoE+sHIKY/P7rg7YSDWwbfUNJl59yAnHmPvTNPB+UbYl/FzEg==
X-Received: by 2002:a9d:630e:: with SMTP id q14mr5719644otk.83.1607343817745;
        Mon, 07 Dec 2020 04:23:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c8a:: with SMTP id q132ls4225050oib.0.gmail; Mon, 07
 Dec 2020 04:23:37 -0800 (PST)
X-Received: by 2002:aca:de44:: with SMTP id v65mr12090644oig.98.1607343817387;
        Mon, 07 Dec 2020 04:23:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607343817; cv=none;
        d=google.com; s=arc-20160816;
        b=kUBMH4Jb0zuRr2aZtm8L009N7YBcAvstsXb6X5tcVC/iomz/Z+5et7bii2rMrvv3vi
         0qGgsqS5Y8vtawqevBq/TeGnUOvm2Nad9BfyvDt4sdV4ehibkOV6SdPWkXH9CconBpgj
         YlbRuYXZAR5yIi6WCuD5dNez9du9r8NWA0q2lm709hi0m063ozWAiNmTrbnxV58N9/jH
         0KyLkTmYI0IzZJCrEvRL7YXqxgU9Dz9Xovl3ewDwmXo68q+HQbemNJHWRsAn4mCUaQR/
         8UQjL4VpkU7JnClnnQ3cy9lRWNvmaw9SepcVHthR7rU6iBm2k0or88obty+oIDmp6Dxe
         fV/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E6pk4jhfaBDxagsrjqdb98OOZTNvh3pSgPws7wibwpo=;
        b=wMzRP06MM/26vaBVkAT9ZC9ezsBUGjvGqEyMFasCkEcw/s3Zusoezf8Qcy+wLD1QnT
         IG2kXtI0nhJPeeK9JfFwkIsGZCNNwfzBmj867vQBgEZRieG2nHHZznR9nyJAoB7y89PU
         HZGzYBK5uo4AYc/FGuYqAg7B1lbY+N70TUaCSiiB0hRuuo8dG8vbCm7LrX1xmS3auiaT
         ScgcFcQM3j/mmBbx9NnaGG8c0WPuI7FjeHDzPZGsNCccT5XX4savbnYH8XxpMZzloGu7
         LSvAmwBQqvSMBmdljxMKLzwQ6MdkJ3jHm5MxkyL1oLLaz0f+3yik5rHdXrqj1R4AhlXm
         Tufg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="b/Javx/Y";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l192si793731oih.3.2020.12.07.04.23.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Dec 2020 04:23:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id x13so4722223oto.8
        for <kasan-dev@googlegroups.com>; Mon, 07 Dec 2020 04:23:37 -0800 (PST)
X-Received: by 2002:a9d:6317:: with SMTP id q23mr13034529otk.251.1607343816907;
 Mon, 07 Dec 2020 04:23:36 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com>
 <CANpmjNPpOym1eHYQBK4TyGgsDA=WujRJeR3aMpZPa6Y7ahtgKA@mail.gmail.com>
 <87wnxw86bv.fsf@nanos.tec.linutronix.de> <87eek395oe.fsf@nanos.tec.linutronix.de>
In-Reply-To: <87eek395oe.fsf@nanos.tec.linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Dec 2020 13:23:25 +0100
Message-ID: <CANpmjNNdothEQfz6LFN_HHYFQPa6679+WoodMBvsZiPSLndEdw@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in tick_nohz_next_event / tick_nohz_stop_tick
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, open list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, 
	lkft-triage@lists.linaro.org, Peter Zijlstra <peterz@infradead.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, fweisbec@gmail.com, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="b/Javx/Y";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 6 Dec 2020 at 00:47, Thomas Gleixner <tglx@linutronix.de> wrote:
> On Sat, Dec 05 2020 at 19:18, Thomas Gleixner wrote:
> > On Fri, Dec 04 2020 at 20:53, Marco Elver wrote:
> > It might be useful to find the actual variable, data member or whatever
> > which is involved in the various reports and if there is a match then
> > the reports could be aggregated. The 3 patterns here are not even the
> > complete possible picture.
> >
> > So if you sum them up: 58 + 148 + 205 instances then their weight
> > becomes more significant as well.
>
> I just looked into the moderation queue and picked stuff which I'm
> familiar with from the subject line.

We managed to push (almost) everything that was still in private
moderation to public moderation, so now there's even more to look at:
https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
:-)

> There are quite some reports which have a different trigger scenario,
> but are all related to the same issue.
>
>   https://syzkaller.appspot.com/bug?id=f5a5ed5b2b6c3e92bc1a9dadc934c44ee3ba4ec5
>   https://syzkaller.appspot.com/bug?id=36fc4ad4cac8b8fc8a40713f38818488faa9e9f4
>
> are just variations of the same problem timer_base->running_timer being
> set to NULL without holding the base lock. Safe, but insanely hard to
> explain why :)
>
> Next:
>
>   https://syzkaller.appspot.com/bug?id=e613fc2458de1c8a544738baf46286a99e8e7460
>   https://syzkaller.appspot.com/bug?id=55bc81ed3b2f620f64fa6209000f40ace4469bc0
>   https://syzkaller.appspot.com/bug?id=972894de81731fc8f62b8220e7cd5153d3e0d383
>   .....
>
> That's just the ones which caught my eye and all are related to
> task->flags usage. There are tons more judging from the subject
> lines.
>
> So you really want to look at them as classes of problems and not as
> individual scenarios.

Regarding auto-dedup: as you suggest, it'd make this straightforward
if we had the variable name -- it turns out that's not so trivial. I
think we need compiler support for that, or is there some existing
infrastructure that can just tell us the canonical variable name if it
points into a struct or global? For globals it's fine, but for
arbitrary pointers that point into structs, I don't see how we could
do it without compiler support e.g. mapping PC->variable name (we need
to map instructions back to the variable names they access).

Any precedence for this? [+Cc linux-toolchains@vger.kernel.org]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdothEQfz6LFN_HHYFQPa6679%2BWoodMBvsZiPSLndEdw%40mail.gmail.com.
