Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYVHQ75QKGQEBMQO5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id EBB8726BFF9
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 10:59:15 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id e4sf1232736pjd.4
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 01:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600246754; cv=pass;
        d=google.com; s=arc-20160816;
        b=sX7Bl/dDU01L2wWU4tPaNR6zgoi0lybXNsrT5H6W1vd18A0xF/d3mFtnQTXKu7hem3
         4VwKso8tPnzET/+vJVXK5XzNMw0H5N/SsEMDX6UN0cND/Jz+6g/iAq9qI7cn9upzfMFK
         dC8SaT2aD44kM7oORoXFPenbw32Go0I4MlbUuPZ0NU8TJT0J3uL8T65LylrJ/YBSYg5+
         fgJMrBxAxT2iAcvAM5cTGCG47M9wBH3IyXLpSS+sUpxc2rZYxNJioDSTV8LKJBSx+E0W
         jI9cbXzI6QQdg1d4rBs3YN6fzPXuxznkNK3vNCbHVTFG3EZOKX50jQGGF4BpbP8FIers
         T0Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+stJau7+2ImXeIr8Xs4Xd3W8s5NWH/G733smMjnRfrA=;
        b=k5k282HF+K69l+8U6g8s7V6qKsj2fi2V9gYHPL5/QAxgmHWDVaxGUYNFp8smDyrqOP
         DxytM9zi0KWVKXDOwN7ecJ0p64cnyWaflFYt1qLeKif7lHuet0tMCM0ANswVnZ2OPNlb
         c+8avMLFdZeUdTSOWEevQof3/lhgfAXP6rlkgSHuuGArg3wttDzHPslocH5VncRkdTgA
         e6Se32U1aQ2hFX80JvLbLxatfniBySeqmcoVnoKGYLZt19nemmqJsLKj7upoUgcb9Kz+
         ALvICbxXl0LniaEtDO5E2rdR1f/jYYfOuu4HA2STF4pNR/CD6BrYMgHoFo2oNI4yT3Uu
         YExA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kthdyxgm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+stJau7+2ImXeIr8Xs4Xd3W8s5NWH/G733smMjnRfrA=;
        b=a5kzTKcPBQdcbEBPKfZDtm2mQvltKmd0tjH3QT6jj2cZw7GUCFs0Sx1B16Ag/tOCXH
         bmbqjxGlZ8usfM0HcfUfhZTQ4ci4S/iofYhNDapuHX6r5vk0tAqv6bYNGf6h+Ey8lD2u
         NUpOXA12NVO45zeJieBig3jzNPc3j3ZrKeZ8YplS/0rykjIFK9n42fi04FwZu0cEWGbL
         uHeNN+nWY8KMGAXDXVrNGwKh2g222JVyKaetFHX906L2dBX3wrc7djveLFuXi4Z3c+yp
         75hS1d7bPf/8wXaIcMmjco5EBQutD/4kc8nMz0V9Sdm4BhsOL5JmzGSIWgvwBVOpOxt4
         DBGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+stJau7+2ImXeIr8Xs4Xd3W8s5NWH/G733smMjnRfrA=;
        b=fEFK5iClLghExllzWUroAf5XwD5WuOVIs84MFEVSLXE7Huw+0Tnn5WG1ysOYrCN+oS
         slxIZbZpR0gURRv1AaPC1J5+tEfjj/Gn41QujVHJ0p4/VVtl0ctKoyIlyak43uW8kpCj
         kc9xqT1LHsj/5xq56oPW2Bi/3Lc7HPRqa+UUk9lK8AFK4VdV55QkHLK3PpWVjGd7bjnN
         O7HU0L4gM8vG4wC94EQ8wQBfLe26nju3Tl/5gb4UGApz4eTR1vv51YX38BRBaU0cDY9i
         UdTglfBuYVSrv+KJD0Hqms4KcSupBlnEFdDrH1znKYZ/XvBJn0Bd9lkk3m7KfJ9KbbC5
         LqmQ==
X-Gm-Message-State: AOAM533QN9dG15Cv0hr4S2EV3wjpVCiHurOrjV1FYWn8qsiKTqWqJzoG
	8V2yh+4wu0J+1Z2MUrCX62w=
X-Google-Smtp-Source: ABdhPJyUH/INYYyhnbRIvhWIRS9JQ2itVZhCiXLODx2BZEGiL2x9bETWY5qc6xKYl2fAhUp6Sp4Mvw==
X-Received: by 2002:a17:902:ab88:b029:d1:9be2:c683 with SMTP id f8-20020a170902ab88b02900d19be2c683mr22264424plr.24.1600246754575;
        Wed, 16 Sep 2020 01:59:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9706:: with SMTP id a6ls543628pfg.9.gmail; Wed, 16 Sep
 2020 01:59:14 -0700 (PDT)
X-Received: by 2002:a63:d257:: with SMTP id t23mr18057420pgi.212.1600246753975;
        Wed, 16 Sep 2020 01:59:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600246753; cv=none;
        d=google.com; s=arc-20160816;
        b=Swnzy52g64hefteg/s1YFk7KN8jD1VDxQrcZFhXxq1KyA2HN/jh8ieoW6fpHE97lHN
         8JNKoIOX2VEcM2qMvdcNjfhunF63TX8VTCJln5NOEYDAIrTNh/KMHZughMHkcXs0rOj2
         d4SROR9N1yaMZd4XQw2MgNNg6xs9B/U8cQhaCwJ2bu0AWPdhV74LVDbG7rBW+qWK/PA1
         D9LkvNbk1xVieVqpak7heoyMmj6c38wk4RqU5p04GcVpB10Jl4OqdmS8HA9C6V6Q2r8y
         hL1ygwKXF6liNLa5pzVmycd9sgg1hNoMR43R56GxiAKc8kgbx7ZyqLuKKWwX4qFXln6m
         MoXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6uStEpmfYMuBQTe8ptduZVCplRWwuY/KSnqm4IT/S5I=;
        b=zeXuE4Cr/tWORMAyBdAXkXlDqfn+uChqlPyOepiaSF2Tno4gW4iYApyIGheBLOmvRO
         7vskWPuK+QgEylH1F6w6HSOZiy2hpLn3xkRWOFu6BEBIhpLsTUMyQAiukq/JXDl5etxe
         BkPNj9dk75J4BKyr2yYwNrXB5p76se2tIUhS1Gt4s/fKbOa4bttymRf3DJN710CxMrnD
         N7NV+aY3CcfQm0/fjkJTw7S5YewuLt6O5n6rNLwQwYyI6liiKmT6TlMDCtfjaxQLWhnP
         IIqli6K9BiK7ysWEauFQp1mKMXZLR2wpUN6qFC/rLZoN6McHQ0AHemHp1gZLI4bBG/6t
         EsNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kthdyxgm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id z13si821312pgl.5.2020.09.16.01.59.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 01:59:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id b12so1461225oop.13
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 01:59:13 -0700 (PDT)
X-Received: by 2002:a4a:a58f:: with SMTP id d15mr16956575oom.36.1600246753334;
 Wed, 16 Sep 2020 01:59:13 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <CAKwvOdnc8au10g8q8miab89j3tT8UhwnZOMAJdRgkXVrnkhwqQ@mail.gmail.com>
 <20200915204912.GA14436@zn.tnic> <20200915210231.ysaibtkeibdm4zps@treble> <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
In-Reply-To: <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Sep 2020 10:59:01 +0200
Message-ID: <CANpmjNPa8FuTURfO0btWir4ax7jBy79P5x7Z5h08e-Ybea1Fnw@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>, 
	kernel test robot <lkp@intel.com>, "Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Ilie Halip <ilie.halip@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kthdyxgm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Wed, 16 Sep 2020 at 00:34, Nick Desaulniers <ndesaulniers@google.com> wrote:
> On Tue, Sep 15, 2020 at 2:02 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
> >
> > panic() is noreturn, so the compiler is enforcing the fact that it
> > doesn't return, by trapping if it does return.
> >
> > I seem to remember that's caused by CONFIG_UBSAN_TRAP.
>
> Indeed, if I remove CONFIG_UBSAN_TRAP from the 0day report's
> randconfig, these unreachable instruction warnings all go away.
>
> So what's the right way to fix this?
>
> CONFIG_UBSAN_TRAP enables -fsanitize-undefined-trap-on-error  (not
> sure why that's wrapped in cc-option; it shouldn't be selectable via
> Kconfig if unsupported by the toolchain).
>
> Should clang not be emitting `ud2` trapping instructions for this flag
> for no-return functions?

I think this would defeat the purpose of this UBSAN feature. Certain
UBSAN checks are done fully statically, like is done by
fsanitize=unreachable, and could actually be enabled in production
kernels; trapping the kernel in these cases would be a reasonable way
to avoid further damage to the system.

(You could in theory force it to not emit a trap by using
fno-sanitize-trap=unreachable, but I think it's a bad idea.)

> or
>
> Should objtool be made aware of the config option and then not check
> traps after no-returns?

I'd vote for this. And it seems Ilie implemented this already.

> I suspect the latter, but I'm not sure how feasible it is to
> implement.  Josh, Marco, do you have thoughts on the above?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPa8FuTURfO0btWir4ax7jBy79P5x7Z5h08e-Ybea1Fnw%40mail.gmail.com.
