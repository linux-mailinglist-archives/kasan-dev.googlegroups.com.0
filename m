Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB26A5LXQKGQEL6WUS5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA6F712553C
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 22:55:56 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id l5sf2414878ywf.9
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 13:55:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576706155; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtzaszkacQmtq6me1KBMsQug7nVR/Fd0HFoLQOa4jXFperLHGTiPe6gUrenlrpheNH
         EBQg9uM33ETZa4cueWRJamUsjG3920DJL/KOFJZdlQ5kZBB5fY1RZFQ7T6IyDPS8KQfe
         Agfo8pyVC9pXibs2Awrr66XMcb/o9cnRFAgfF4ugxt+wpCnCv2Obg3Ir3Y7s4HDAiKry
         FZBUgGoQO8/HYfsSnIwN5eEAWHmXVfE6VVXYs8c7S18D0mHdO1uuqLSzp9l48i3np12q
         5oeJzABbS7WAnB5sgjYoYJGQzwbZwVMmq5Z19mWHzYFIACzOKy5v61KrDyP1CTc03dZt
         VpZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aUWCSz2z7/Ujc2F4qW4IMUr0kfhXqohLTIiR8OQnUxo=;
        b=OWpoaXQU5b6oYVqiCNfVY506shKF22zZxdUY98Diymv/swuSV5NUOyn9vyBjiddTKb
         veOlOzyxkerBAd8gs7HC2CxuOIF9lpbU6VMG3Pmp9jNGeOYh6DzFV85wpbW/APOm9qDN
         hcj6/JlMobaA8RjMy1ofG6Av8skNuzbE1gORkGeG1h7FvI2DzHEBQ3MSOBmaadAc+lms
         65yxHqsnsDi4XH2zAcPul1r5P4egw6NSUdyLDz6rZOU2mDC3ls+mqXphFOCIGmilv7zl
         zIMLb9YO5WOU3KzOBWW/2trx/t+3TUOZxLcmmFGXVhZ5Olkk/QUZctfWDPPQ0nQCjq7w
         7WoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XCudI/JC";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUWCSz2z7/Ujc2F4qW4IMUr0kfhXqohLTIiR8OQnUxo=;
        b=e2kUYYhTKm+MkMHaWK9VlwjR1PpA6UCE5whC2Ik4QvTim3meHf1RhheSBs7h6B2xHN
         esWUv1qE4Oh0tPqIgTL0fqJiRsqQ33cgIKQJ6vEOT0V6Sb0/i58e0wwmrYOXQT0bm32N
         XHBUnfjqEM4zJMclXonb4zv/wdzIgiuEehPgewLOa7yW4XGo8IXHH1rOvhUIA6O1YK1q
         2ZjSaDOl/a8wO3uTeXlGk061hvaQBOwFtRIUrDUfFS5PSFssoIXFrTG+I+PxnimfVwAQ
         Yn3dAynJaAqyBmOrEcwzki5Co9/RpHx8X1oX/q3SekxvPSQKy2ZUy4q1mFVzACMlWvQd
         fqUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUWCSz2z7/Ujc2F4qW4IMUr0kfhXqohLTIiR8OQnUxo=;
        b=VzIKxokQQRXemRTGdNFFjJEkGMNL4C9soQhAkv+FpaFxW3p2Lqkjj2hbDMG+PltjbZ
         ULiuiSO+DMPj9t+/oER3wJc4GdfvyUqR6Iik57fJv/9AlIoqGrB18reSuMfQf8REpA0F
         1LhE7p8N9N6v8zrkuxJ5FTwkl7yYU1fQLOvGnmLR4GVP2y50ipcDmyNFZ0hUXhaZAdyr
         9SYjLg7PIHrMUkAWwvXGUREYSjE2N4DXtCKXmxKVwp6TUxmskwDlKpRxNTQX90ftE7nJ
         Achz1th4ITgd9geJb8MpjaijlmogX9zwFBlYfBa3UZt+2+iCFPR2eltf0o6zHUL7Z2iD
         QB6w==
X-Gm-Message-State: APjAAAVCa0cdSN/pLWhqLNJYNxSyEtbF17zx/lFHLT/9fCzYny20J319
	radlk44+XPWBisOBmNSKjP4=
X-Google-Smtp-Source: APXvYqx1zDGclHJYi/v3VNw3XDQkJRw9K7EbnGLFeAmft0Qyn5CeKgtdluhCMMW4lvXOQczikYgPRg==
X-Received: by 2002:a81:78d7:: with SMTP id t206mr4061319ywc.104.1576706155796;
        Wed, 18 Dec 2019 13:55:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c64c:: with SMTP id k73ls553852ybf.4.gmail; Wed, 18 Dec
 2019 13:55:55 -0800 (PST)
X-Received: by 2002:a5b:348:: with SMTP id q8mr3946680ybp.83.1576706155456;
        Wed, 18 Dec 2019 13:55:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576706155; cv=none;
        d=google.com; s=arc-20160816;
        b=H06nvxLn9fUR/ZvsHVQOIghAmIIBZGIT1km3iWmWd5JOO/mL9KuGYra9scRmqDS90o
         0yrHm7zSAr3fFmse4IL5SvTzJCVAesv4t/8bYJd8QychAnvi8E33rK2UBczXnW96vTjR
         Q3ZID039rhj5XQbWx1SbyhD7BVqXc+l60V6MF/pecdIDoCwu8We4zJ/SCPpdKaDzmY/Y
         q5yeQvZGKBpU5YNt7W02hfF4q6LqQKssrzuEU3ZRrSbdfIctKKSUZ7kjTFijggiL4nxQ
         TRQvzVvwm+xgIOCbXXhY7jOaZCSaCqOINpOiBr6WsfNDyFXWgomVmZW0tsFPZVrmWixE
         a5CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C2UwPzd2e+JnH6ssOXgfC4uB+eN483cl8wOJHT+wP8M=;
        b=gjpi+dDaP1a3jlG955PXF+Pp2v4MIWlFvNrQMbmwpN+yOmZBzUZ+6Dwd93IWP2boqP
         xZJShvNUMnUNH2FxBTgMa+ueVYdD9mpLTRG5aInkKt1MBOQ0vRsztTvlksCmlQMNo26b
         GYRtDQaKu4UB+3V/rVkGw5vUWhyogH/cpiIMk0Io/Y5LUUCSaEA4mMEQXrZ5riZcnnSY
         pI3LpxVlNbt/hfkEdWeCQgD7TiT/XPCMOMjiHRhTTLIRYylAYPab30stXsTJySXrLZ8E
         aV7bLs6RNq+M0v5hAQRG7m+DhJVQuTAKqphjtgNPyugCAdhMdoA/1NddJxqZQO8gPJvI
         oTOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XCudI/JC";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id j7si173938ywc.2.2019.12.18.13.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 13:55:55 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id k14so4295166otn.4
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 13:55:55 -0800 (PST)
X-Received: by 2002:a9d:6481:: with SMTP id g1mr5082817otl.180.1576706154945;
 Wed, 18 Dec 2019 13:55:54 -0800 (PST)
MIME-Version: 1.0
References: <20191209143120.60100-1-jannh@google.com> <20191209143120.60100-2-jannh@google.com>
 <20191211170632.GD14821@zn.tnic>
In-Reply-To: <20191211170632.GD14821@zn.tnic>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Dec 2019 22:55:28 +0100
Message-ID: <CAG48ez2qGOAPBKiXDBL56_+QqR_bGRrtBSCT73VnKQ3xYsjAEA@mail.gmail.com>
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="XCudI/JC";       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Dec 11, 2019 at 6:06 PM Borislav Petkov <bp@alien8.de> wrote:
> On Mon, Dec 09, 2019 at 03:31:18PM +0100, Jann Horn wrote:
> >     I have already sent a patch to syzkaller that relaxes their parsing of GPF
> >     messages (https://github.com/google/syzkaller/commit/432c7650) such that
> >     changes like the one in this patch don't break it.
> >     That patch has already made its way into syzbot's syzkaller instances
> >     according to <https://syzkaller.appspot.com/upstream>.
>
> Ok, cool.
>
> I still think we should do the oops number marking, though, as it has
> more benefits than just syzkaller scanning for it. The first oops has always
> been of crucial importance so having the number in there:
>
> [    2.542218] [1] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
>                 ^
>
> would make eyeballing oopses even easier. Basically the same reason why
> you're doing this enhancement. :)
>
> So let me know if you don't have time to do it or you don't care about
> it etc, and I'll have a look.

I don't think I have time to do this in the near future. Feel free to
implement this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2qGOAPBKiXDBL56_%2BQqR_bGRrtBSCT73VnKQ3xYsjAEA%40mail.gmail.com.
