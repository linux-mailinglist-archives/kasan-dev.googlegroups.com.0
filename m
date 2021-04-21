Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEMNQCCAMGQE3IXZO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C28736699A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 13:03:46 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id h10-20020a9d554a0000b02901d8bed80c43sf13359105oti.22
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 04:03:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619003025; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzNigU2eG932dbKS4nkb8hx3XWIVr67y4YUxG2g38VMSGE3gO0l4pfRiqT/i0Xp0Nh
         VE8OgPM4YIMU/bJM96wgQT2M7KiYbGER6JGy3fH8TQBQU6Tsw/WdXFCbLyC6I8TUU0QU
         Sfm0Vj+nBAHTetWhFdjkVnMz0Cnl5HHkmBJbHCTp8Oa4FSOgZjbKdTurIR4nbJxS4rad
         eQoQBX8sn+Rq3aYAT4iMJcAqBFDLnfJ2AaLxSIC/S6qw9bT0PSs7pLCaAo/l0rUVAWQ6
         JvK1GYKAJEmGmFMy7FJ2egEzXkGZfjP8xN6iIKQnHjhArZzhV6U9vB2236GFJs7nKmlC
         BCuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z5B8bK/sVMD5DwVRYM7JCGSwlUGKcX2DyVoFDCtuoD4=;
        b=ZMZn9ENSe1YuIVrc2B5dDeXh0fOKwrxAiE7mr4QBPujImsYHo03RFNFimlrUsTCmUf
         JQBKIfCNWtQAEPAbk6kEpdZHYy84vXSPfLQz1cMNp2zr8mcX6sFsy5TnZGSesK1kN06/
         Kki0W9newRWeX+4krXg8dt+Sy01Jkz3Ch8G0Q+fqh5tH1P4Ffb62i2cG2DAEzaJisthX
         inqOx7ZoibRTROwd22sgiaYXBQ64w1pHTHhcMRorVa7zqfrHOpliO1f7+/d39dQi0lWp
         NZAbIlY/05A42a8mKLnQhDUt4eFoq/smgVYYeGbyMmSoKkZAGVTBmwQOrpRjXIOhOBIr
         1IrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T25LZuGf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z5B8bK/sVMD5DwVRYM7JCGSwlUGKcX2DyVoFDCtuoD4=;
        b=mPvsVy1MUXDEyZTLmx8+RhaXnzIr+fjPg7krOBwwH4oR56CPWvHFm82cycR3ZCvsce
         yZ8H5E0wEZ2RXPvDeK1RPVhg+Vi4+RLjZdUrxOIJCCnx+ZlwRTOieEuzySIR+69E1ddO
         /3bBasdDygcBQlyDS23DfZ3FOU7uOhLF4lUO9U08ScUxnDEqBm+pQij67KMg6fLidF0C
         ccEJJnh6le5D4SQXnCHj15PJVlQvjv6uGub9zwoytVnhXAjjWW3tACuGh3iTwanmwOAf
         YdJ1aGJwPcsRmN4Ckv6nsa90PAqN7L6Dl7MMu7/EM9G0Ff9eNVKkUAv6yKW1bbQs5s/a
         WGVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z5B8bK/sVMD5DwVRYM7JCGSwlUGKcX2DyVoFDCtuoD4=;
        b=iSK4+R9XQNjWEfaJyWRsEr4rZ2egH77i5b5n/n87kOudeC1Sagb7MMlbomZIX9vom8
         /bLuE58KzFi8En/FUfY60Ez/22U8X47j2/2wkmH/ZfXbA2OIHc8XjzOLjstlLgwCG9qb
         AvVSztQ3ySzEsMAp6VfXQW03CtS1fAqopTaqH4lgNDwoGW8mP8t6sDlAIiTijJOaJMvp
         JxmF8CrrT997q33feobbTMhQhQHZkggOvwraiVcp+G5013P/rhn8Ej2t79WnS4fCGmt/
         91rNSXUAmn00FtoHuP0Lie81uK5ahp28VxMI02+uzFtOB3rWG1ObfsxAZh4qrDNia/wk
         +NLg==
X-Gm-Message-State: AOAM532UlHk/dY4o3jobuzWmdfdPjB/sq6C5POF+IyA+QNGuAIr+r21F
	wIZxxkrVw2NIgkH34GvT8fA=
X-Google-Smtp-Source: ABdhPJz+ArqcsuxFVZIJyU2w8+R9cOVR7afVJaxHq3EDS2VI1aXs7Y71t4bZCiOwpZjbRNZYTRHMzQ==
X-Received: by 2002:aca:b645:: with SMTP id g66mr6293719oif.64.1619003025191;
        Wed, 21 Apr 2021 04:03:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:605:: with SMTP id w5ls462059oti.8.gmail; Wed, 21
 Apr 2021 04:03:44 -0700 (PDT)
X-Received: by 2002:a05:6830:18dc:: with SMTP id v28mr2133089ote.310.1619003024856;
        Wed, 21 Apr 2021 04:03:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619003024; cv=none;
        d=google.com; s=arc-20160816;
        b=ibcLWiESjLee/NvMBvdqYVhneMp9KaAssESrZXWMGOH3wMZg1+XceElUErrFsgr8o6
         0T2VszflOPkvwtXpoBim6S4vOvxNrarYluCjSupx5MImHpoaTIvkZyuukGjn4ZCLlKXl
         ot+qMO4JqbDLBFDZAzRpjKGzcpHAa1v6G+rWx5fVJarNiAprq0laUo1NJN/VMVMbIELO
         /xgYF6UYUv9x3KlX4bxiUABDzflt9zehRNpoGZ7TuuPOqy41dWEnP/K5xx2jeMouBG26
         QPwvXDs60Ucib2sDGmGTt4piTOKdm8CW64jeELsTDb4NfdMYdprXmmCQTOIkeNZVMY3o
         Ii5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VwvnjSj2op3l1hxnf84tZDl7adPmWlaJUCzqnfca75k=;
        b=q5pgoPidPNElz/71Xjv1O5Zc7Yn7jCVv7Qsd4dv4DL7i0p931LCRjwG0dolUynOa8m
         NVlNgug65i4TRMo7N+RFaAslRZS9BnsjUaitL3DbvU5WE/UwNw3oj8FqlsEqY14wV28V
         Li5+6WAw/Hl5d3k8XSMrGe53BKNbb6q4Tg8hofNW/emRUjTl7qpaOl6TSTi/ij6L1nyI
         bxbdyN8YRDv43OA6nWBpRInw4wbfMmzPKMPkcVQ7xU9Bj6/oy+Quko78Is+TeLGDlE4Y
         bX2oz3K4rG9p99GAkqP8s/NxjOhR3Bz4+hIGMUslk4cyM+15EzUOcdi+u0sUkZPTO1jH
         /jSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T25LZuGf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id b17si198911ooq.2.2021.04.21.04.03.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 04:03:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id l17so10695517oil.11
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 04:03:44 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr6376630oia.172.1619003024370;
 Wed, 21 Apr 2021 04:03:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com> <CGME20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8@eucas1p1.samsung.com>
 <20210408103605.1676875-6-elver@google.com> <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
 <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com> <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com> <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
In-Reply-To: <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Apr 2021 13:03:32 +0200
Message-ID: <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T25LZuGf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Wed, 21 Apr 2021 at 12:57, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>
> On 21.04.2021 11:35, Marek Szyprowski wrote:
> > On 21.04.2021 10:11, Marco Elver wrote:
> >> On Wed, 21 Apr 2021 at 09:35, Marek Szyprowski
> >> <m.szyprowski@samsung.com> wrote:
> >>> On 21.04.2021 08:21, Marek Szyprowski wrote:
> >>>> On 21.04.2021 00:42, Marco Elver wrote:
> >>>>> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski
> >>>>> <m.szyprowski@samsung.com> wrote:
> >>>>>> On 08.04.2021 12:36, Marco Elver wrote:
> >>>>>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
> >>>>>>> si_perf. These will be used by the perf event subsystem to send
> >>>>>>> signals
> >>>>>>> (if requested) to the task where an event occurred.
> >>>>>>>
> >>>>>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
> >>>>>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
> >>>>>>> Signed-off-by: Marco Elver <elver@google.com>
> >>>>>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
> >>>>>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
> >>>>>> regression on my test systems (arm 32bit and 64bit). Most systems
> >>>>>> fails
> >>>>>> to boot in the given time frame. I've observed that there is a
> >>>>>> timeout
> >>>>>> waiting for udev to populate /dev and then also during the network
> >>>>>> interfaces configuration. Reverting this commit, together with
> >>>>>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to
> >>>>>> let it
> >>>>>> compile, on top of next-20210420 fixes the issue.
> >>>>> Thanks, this is weird for sure and nothing in particular stands out.
> >>>>>
> >>>>> I have questions:
> >>>>> -- Can you please share your config?
> >>>> This happens with standard multi_v7_defconfig (arm) or just defconfig
> >>>> for arm64.
> >>>>
> >>>>> -- Also, can you share how you run this? Can it be reproduced in
> >>>>> qemu?
> >>>> Nothing special. I just boot my test systems and see that they are
> >>>> waiting lots of time during the udev populating /dev and network
> >>>> interfaces configuration. I didn't try with qemu yet.
> >>>>> -- How did you derive this patch to be at fault? Why not just
> >>>>> 97ba62b27867, given you also need to revert it?
> >>>> Well, I've just run my boot tests with automated 'git bisect' and that
> >>>> was its result. It was a bit late in the evening, so I didn't analyze
> >>>> it further, I've just posted a report about the issue I've found. It
> >>>> looks that bisecting pointed to a wrong commit somehow.
> >>>>> If you are unsure which patch exactly it is, can you try just
> >>>>> reverting 97ba62b27867 and see what happens?
> >>>> Indeed, this is a real faulty commit. Initially I've decided to revert
> >>>> it to let kernel compile (it uses some symbols introduced by this
> >>>> commit). Reverting only it on top of linux-next 20210420 also fixes
> >>>> the issue. I'm sorry for the noise in this thread. I hope we will find
> >>>> what really causes the issue.
> >>> This was a premature conclusion. It looks that during the test I've did
> >>> while writing that reply, the modules were not deployed properly and a
> >>> test board (RPi4) booted without modules. In that case the board booted
> >>> fine and there was no udev timeout. After deploying kernel modules, the
> >>> udev timeout is back.
> >> I'm confused now. Can you confirm that the problem is due to your
> >> kernel modules, or do you think it's still due to 97ba62b27867? Or
> >> fb6cc127e0b6 (this patch)?
> >
> > I don't use any custom kernel modules. I just deploy all modules that
> > are being built from the given kernel defconfig (arm
> > multi_v7_defconfig or arm64 default) and they are automatically loaded
> > during the boot by udev. I've checked again and bisect was right. The
> > kernel built from fb6cc127e0b6 suffers from the described issue, while
> > the one build from the previous commit (2e498d0a74e5) works fine.
>
> I've managed to reproduce this issue with qemu. I've compiled the kernel
> for arm 32bit with multi_v7_defconfig and used some older Debian rootfs
> image. The log and qemu parameters are here:
> https://paste.debian.net/1194526/
>
> Check the timestamp for the 'EXT4-fs (vda): re-mounted' message and
> 'done (timeout)' status for the 'Waiting for /dev to be fully populated'
> message. This happens only when kernel modules build from the
> multi_v7_defconfig are deployed on the rootfs.

Still hard to say what is going on and what is at fault. But being
able to repro this in qemu helps debug quicker -- would you also be
able to share the precise rootfs.img, i.e. upload it somewhere I can
fetch it? And just to be sure, please also share your .config, as it
might have compiler-version dependent configuration that might help
repro (unlikely, but you never know).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw%40mail.gmail.com.
