Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSUBQGCAMGQES7YYKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AFFF2366ED5
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 17:12:11 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id b2-20020a6567c20000b02901fda3676f83sf10553396pgs.9
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 08:12:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619017930; cv=pass;
        d=google.com; s=arc-20160816;
        b=ibM4HPY6Q7dNHSEeV8czS51IuzYphd237N0Bh81XQemlDUeqZR3O5FJ0QUEaW4GK94
         PlGgC2z5j0dfyXRfF93cT8woKUBkec7ihOVrVl/Tp4XnO4VmybaCUr4h3+XL9LJ27uVu
         lFhGaLyvGk8bFX0TSEiNhQN2SWsqj3VGYhkuP9JVtLKkvRtGr8MbqwX3GrNNkD+8UyZ7
         yTR+ivooiyE7n41zQgekORD3SeBcz2tsS5zVhDDskcImrRGFuC2CX2hTP0/+oyB5uqTZ
         xcXzC7ByjrKHd49G857n1Qfu0sUkF0NEfLCcKX5yXYcQ34KW+kqznjd6Z3wRkC5jc9dq
         nueA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9SKjMSxXImnQZyxK08BtcKUUn9RXLRYEl5dzPqqpB88=;
        b=f320ZdSrvLCJLk29FYsjDYpLjHwj+xFf6DfutSui6iB6PMWn2FdjzGrD4Hv+2/jvO3
         QEQk17mTOiTIxhUlz9kXF09omqUaanRzxTAKNOVcgOinJ3vqKG4GGZkoNIxnA9YQ9FuI
         Lvt7+GGz4xyOeuBozQF23TZLl3amD7dr9BOvFKij4+nNVu1oE9d3WrXrOo3OIKedpDVs
         JZFvbNfskzvowC+oGuM1OdqgOBlrPa/OCB/gOdU7uPeB6KfTJESBa64h4SJUdLNTHzcF
         yfXRaiMga8doBDUcoTeg9fs2b4KT5g7BnaCQBe6vP5SCj2Izkk5N1fAFwNSTMX1QiKRG
         bZiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vo5glLC6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9SKjMSxXImnQZyxK08BtcKUUn9RXLRYEl5dzPqqpB88=;
        b=aMOVochCp1Yy1vQ+1mDE5WLOxHgLVGXkKCethrVLEWxs4rNYMUHhSuvDYH+zFFNQ7I
         vi3mDZYEwZpTXBI3vtsybV8ch8S5ilVW+zPu7SH3e0P+CX1ZjSh4U7EUm5Q4psIZSgSG
         b8Z+b3e0PxSgA1+JyQX+9kjuwEYHuaX0Z2EqhGTvZiU8cZub3/R+lQokE3KouKbuya0S
         TdQcOlFFroKBdyTy5TGoGBkFjuYPF9aSXFXrP1ufCE64epshMPpF03fjH6TqK29mqYw/
         TB07rqHEQg9jHtWI1ffj6yZOoIPaRrjjEPWrev1zPwIi0iZWlQCaYZlOTqHWV9FyCMfz
         BBbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9SKjMSxXImnQZyxK08BtcKUUn9RXLRYEl5dzPqqpB88=;
        b=kRSauglRahanjbAJscZyB0WTMXezXuepgzR5SN1I8fo/rOeVa4wlavmwQey7sntryc
         bLr9GaFHihWPr4huyjsHu45+fKAoc6JkGiZ5XjnOPR9H8tsn17AW7H79eH5JZBo6CfWK
         f2iHCiF16O85c0DM3YH7GgZF24AtuByKbnugH37vhFlC/0ItX9Gk2uWsll38frCgVlvy
         Dl4RoIFmQGixbIkVxhKGKXRFr1ATRWusa4tkxQ2KCsTX6pSTNlgz8D5qTdrhuOaG0mbT
         uSB1wHA0Ofrf/JeQawHtvB6Wogk5bRIS31u3HfEH4YtZnSOXOMceoNFZ7rQslluVY1X9
         plLQ==
X-Gm-Message-State: AOAM530sxHobTckzxnUm9NCAgvZ6FiwEWMCXUFJo+1ggKzgueqYjALHq
	vgmnrDGk1yUz6SVg+zL6kYM=
X-Google-Smtp-Source: ABdhPJwoPf6zuzMDBvEenJawk18L4W8dUJoEv7LKt3bbcaC8HFnovIVjgwt4eB57Bl7oKGgr9yWlfA==
X-Received: by 2002:a17:90a:5885:: with SMTP id j5mr11885476pji.102.1619017930420;
        Wed, 21 Apr 2021 08:12:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1656:: with SMTP id 22ls1040892pgw.1.gmail; Wed, 21 Apr
 2021 08:12:09 -0700 (PDT)
X-Received: by 2002:a63:1d5d:: with SMTP id d29mr10977675pgm.398.1619017929717;
        Wed, 21 Apr 2021 08:12:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619017929; cv=none;
        d=google.com; s=arc-20160816;
        b=i85WPzq7h3Ijh2E4EH8DarxRpYEsZsRWWg5QG5BkX3PcJ/G5hDLcGJPiQd0QDG4Hgm
         fiACMkA5MMhNbPZoXmqqeL52gfqYDDunGyr/J9ivz81RCAVWzFTcAzNWmwniQBzQpxhK
         YIfYPkWlNGUT24q7192iInS2hVl0PAnIteP0Ev9+xT+ukPH8plE7Nr7atL5mrd9tEXsY
         SSfhiJL14NBYrxNh+cLdCZNRWIBZEbGhdW4LXtCWq2sCg7zQZoZG4hnaqcTaoC6+esmk
         tCjrmzuzJYF9BEsmqiTnUvPcdatCkW5AyMCs7Obq6zkKKGu+nSSXnlOvMcM8icI7mTmL
         Oy6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FEXEAgUao8/U1XoW751IUwiCrSmDVaqLIc6z62zqqMg=;
        b=geSTAOGe5W+vbMu/qbt2yYZWHuPLL7F2Y4j1zwOtN3SFsZFubiQR1T8IE78AFnjpLe
         f09BkIRon1H70LW2TxakG7pV3lx5Pgn2pG7BSGxSfWJSJRgFTFJa05FltzYRF+E/bY3/
         Bq58taMRyQs4VPO68wsKo+bXhjR49ghHIKU5f8GjTTyx/1tLuNbGzl0UosOTJ57fPMh3
         rFgkHDFElLGnc0X6e+Z3r6Ai4waAZZg5kstWZKMo2dFvXsvR3Eds5oJ2GMGlZE/TF34N
         kvdb+8wT6s/BSWDvMobP7oRRJivV6aS/OnXQ5lp67pFB7v/2D64KXls7//e4AcaZaLZf
         47Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vo5glLC6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2c.google.com (mail-oo1-xc2c.google.com. [2607:f8b0:4864:20::c2c])
        by gmr-mx.google.com with ESMTPS id 7si209867pgj.1.2021.04.21.08.12.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 08:12:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) client-ip=2607:f8b0:4864:20::c2c;
Received: by mail-oo1-xc2c.google.com with SMTP id m25-20020a4abc990000b02901ed4500e31dso2296933oop.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 08:12:09 -0700 (PDT)
X-Received: by 2002:a4a:d80e:: with SMTP id f14mr18296328oov.54.1619017928732;
 Wed, 21 Apr 2021 08:12:08 -0700 (PDT)
MIME-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com> <CGME20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8@eucas1p1.samsung.com>
 <20210408103605.1676875-6-elver@google.com> <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
 <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com> <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com> <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
 <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com> <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
In-Reply-To: <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Apr 2021 17:11:57 +0200
Message-ID: <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
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
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-tegra@vger.kernel.org, jonathanh@nvidia.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Vo5glLC6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as
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

+Cc linux-arm-kernel

On Wed, 21 Apr 2021 at 15:19, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>
> Hi Marco,
>
> On 21.04.2021 13:03, Marco Elver wrote:
> > On Wed, 21 Apr 2021 at 12:57, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
> >> On 21.04.2021 11:35, Marek Szyprowski wrote:
> >>> On 21.04.2021 10:11, Marco Elver wrote:
> >>>> On Wed, 21 Apr 2021 at 09:35, Marek Szyprowski
> >>>> <m.szyprowski@samsung.com> wrote:
> >>>>> On 21.04.2021 08:21, Marek Szyprowski wrote:
> >>>>>> On 21.04.2021 00:42, Marco Elver wrote:
> >>>>>>> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski
> >>>>>>> <m.szyprowski@samsung.com> wrote:
> >>>>>>>> On 08.04.2021 12:36, Marco Elver wrote:
> >>>>>>>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
> >>>>>>>>> si_perf. These will be used by the perf event subsystem to send
> >>>>>>>>> signals
> >>>>>>>>> (if requested) to the task where an event occurred.
> >>>>>>>>>
> >>>>>>>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
> >>>>>>>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
> >>>>>>>>> Signed-off-by: Marco Elver <elver@google.com>
> >>>>>>>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
> >>>>>>>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
> >>>>>>>> regression on my test systems (arm 32bit and 64bit). Most systems
> >>>>>>>> fails
> >>>>>>>> to boot in the given time frame. I've observed that there is a
> >>>>>>>> timeout
> >>>>>>>> waiting for udev to populate /dev and then also during the network
> >>>>>>>> interfaces configuration. Reverting this commit, together with
> >>>>>>>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to
> >>>>>>>> let it
> >>>>>>>> compile, on top of next-20210420 fixes the issue.
> >>>>>>> Thanks, this is weird for sure and nothing in particular stands out.
> >>>>>>>
> >>>>>>> I have questions:
> >>>>>>> -- Can you please share your config?
> >>>>>> This happens with standard multi_v7_defconfig (arm) or just defconfig
> >>>>>> for arm64.
> >>>>>>
> >>>>>>> -- Also, can you share how you run this? Can it be reproduced in
> >>>>>>> qemu?
> >>>>>> Nothing special. I just boot my test systems and see that they are
> >>>>>> waiting lots of time during the udev populating /dev and network
> >>>>>> interfaces configuration. I didn't try with qemu yet.
> >>>>>>> -- How did you derive this patch to be at fault? Why not just
> >>>>>>> 97ba62b27867, given you also need to revert it?
> >>>>>> Well, I've just run my boot tests with automated 'git bisect' and that
> >>>>>> was its result. It was a bit late in the evening, so I didn't analyze
> >>>>>> it further, I've just posted a report about the issue I've found. It
> >>>>>> looks that bisecting pointed to a wrong commit somehow.
> >>>>>>> If you are unsure which patch exactly it is, can you try just
> >>>>>>> reverting 97ba62b27867 and see what happens?
> >>>>>> Indeed, this is a real faulty commit. Initially I've decided to revert
> >>>>>> it to let kernel compile (it uses some symbols introduced by this
> >>>>>> commit). Reverting only it on top of linux-next 20210420 also fixes
> >>>>>> the issue. I'm sorry for the noise in this thread. I hope we will find
> >>>>>> what really causes the issue.
> >>>>> This was a premature conclusion. It looks that during the test I've did
> >>>>> while writing that reply, the modules were not deployed properly and a
> >>>>> test board (RPi4) booted without modules. In that case the board booted
> >>>>> fine and there was no udev timeout. After deploying kernel modules, the
> >>>>> udev timeout is back.
> >>>> I'm confused now. Can you confirm that the problem is due to your
> >>>> kernel modules, or do you think it's still due to 97ba62b27867? Or
> >>>> fb6cc127e0b6 (this patch)?
> >>> I don't use any custom kernel modules. I just deploy all modules that
> >>> are being built from the given kernel defconfig (arm
> >>> multi_v7_defconfig or arm64 default) and they are automatically loaded
> >>> during the boot by udev. I've checked again and bisect was right. The
> >>> kernel built from fb6cc127e0b6 suffers from the described issue, while
> >>> the one build from the previous commit (2e498d0a74e5) works fine.
> >> I've managed to reproduce this issue with qemu. I've compiled the kernel
> >> for arm 32bit with multi_v7_defconfig and used some older Debian rootfs
> >> image. The log and qemu parameters are here:
> >> https://protect2.fireeye.com/v1/url?k=7cfc23a2-23671aa9-7cfda8ed-002590f5b904-dab7e2ec39dae1f9&q=1&e=36a5ed13-6ad5-430c-8f44-e95c4f0af5c3&u=https%3A%2F%2Fpaste.debian.net%2F1194526%2F
> >>
> >> Check the timestamp for the 'EXT4-fs (vda): re-mounted' message and
> >> 'done (timeout)' status for the 'Waiting for /dev to be fully populated'
> >> message. This happens only when kernel modules build from the
> >> multi_v7_defconfig are deployed on the rootfs.
> > Still hard to say what is going on and what is at fault. But being
> > able to repro this in qemu helps debug quicker -- would you also be
> > able to share the precise rootfs.img, i.e. upload it somewhere I can
> > fetch it? And just to be sure, please also share your .config, as it
> > might have compiler-version dependent configuration that might help
> > repro (unlikely, but you never know).
>
> I've managed to reproduce this issue with a public Raspberry Pi OS Lite
> rootfs image, even without deploying kernel modules:
>
> https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-03-25/2021-03-04-raspios-buster-armhf-lite.zip
>
> # qemu-system-arm -M virt -smp 2 -m 512 -kernel zImage -append "earlycon
> console=ttyAMA0 root=/dev/vda2 rw rootwait" -serial stdio -display none
> -monitor null -device virtio-blk-device,drive=virtio-blk -drive
> file=/tmp/2021-03-04-raspios-buster-armhf-lite.img,id=virtio-blk,if=none,format=raw
> -netdev user,id=user -device virtio-net-device,netdev=user
>
> The above one doesn't boot if zImage z compiled from commit fb6cc127e0b6
> and boots if compiled from 2e498d0a74e5. In both cases I've used default
> arm/multi_v7_defconfig and
> gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabi toolchain.

Yup, I've narrowed it down to the addition of "__u64 _perf" to
siginfo_t. My guess is the __u64 causes a different alignment for a
bunch of adjacent fields. It seems that x86 and m68k are the only ones
that have compile-time tests for the offsets. Arm should probably add
those -- I have added a bucket of static_assert() in
arch/arm/kernel/signal.c and see that something's off.

I'll hopefully have a fix in a day or so.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq%3DZQt-qxYg%40mail.gmail.com.
