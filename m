Return-Path: <kasan-dev+bncBDV37XP3XYDRB5VK4CJAMGQELILRHSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F0253500DB5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 14:37:10 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id z20-20020a19e214000000b0046d1726edd8sf416961lfg.13
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 05:37:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649939830; cv=pass;
        d=google.com; s=arc-20160816;
        b=yoHgzCentYTSxX0/BuSfd1KCJWqVC2FjC0QdNjHDsStj/KjxrWysZT1njjtBS6zvkb
         NJUGoDr256BdHQ6pF4Pq5u2RY0bwMYLElf7KCMGW9zHYU5zjxyKrVyBnopaa2yPmMsbu
         U9SZK7EoqGk06tg2met/ImeQhSdpDPlCMu6NJPyfxLb05zSSFeEy8DHkJuS/mLR7M6Hm
         T/MC5bffdj8kKBvpBEF4SldXH/tHK4AqG5LcWoBh6fwKbyl+UaKD1Bz6zcb1l0FGzFYL
         rQkq8f8U/53wbf2LAEzr5eRiyjX1uYxo/WGXMAQmtKrn8iApOWUpxnt/Xa9g6MObsFPz
         d+Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N3CwDcj42c7+7TNZiHcb45/6DAOTI5pqGGmiMZ0mH9E=;
        b=mHPXlUfkBamFZb/SUJ7b+Qj5ySvnJWl2Fyns2bhp3UPACQksnEIJXym5LBXGQI/Ra5
         k42bcbdH4nUs+alhcGzd56RsxbS3sGjQASRyQ/NmrPLKhP/1Yg9BUjFgkYxLboU3VjTs
         HqiXJwh6CxqnRa7taVwdDz9pmgdEt2S3UZNzelLwjy7IgDE4oQUCsWFXIusgRsdtv+Cv
         yJleCCakdTXSzDzr49hd7etBJHEOA83wgpnRpivXjG3886ij2MXUDYUd0bTyozKKPX/0
         EOuIPIrUDZ0ijiVSOZkfjYGSM6WpL8h8hrqCfE3L3HBWItI3CnWQ1IYgkBZnduOPRs0F
         s17Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N3CwDcj42c7+7TNZiHcb45/6DAOTI5pqGGmiMZ0mH9E=;
        b=HduKaps4fzAuE6cYDKgtYTZZm5TYAJHquCEqzE+UJ7JxwFEI40NKaULcXlHiBmR185
         zcVbrt3peYsNBkRRoB9KcjaDFD7vEhMk8JVZRn8j+WKpBjX4uXuQRZHPXb2/+Uh7LnLG
         ZoC+W5r8E7vIN23+4kzb0oD5QeiEbeMF+dqkrykOM45usN3l5VYMVrwD9Qx2B7he8QQc
         XwiJjZ5EznX8VnbA3pWbAk/1LdG4d7Rxnj7d+/oJecpOiIiHQhEipzNRh3xLKajCePSC
         y90iTU3cxgiuEId+rKLIJGiFbv1n8cMOiHTvlZk8mjnAOCxXyCcNOnbgCgnfNJTqLLR+
         aCSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=N3CwDcj42c7+7TNZiHcb45/6DAOTI5pqGGmiMZ0mH9E=;
        b=KAwRHiln6HpJw4/wfgw47PTRxasxN+Fi7LR7QhPIdgNTvNQoOnpNL0/wucJnek7AaK
         FcmDWEeerRIPQwpyljnkqzT6s0ED12M99lfppg6hEwcwIMdn+TDhKI36cNEw1oZpLW8O
         JIXqoPP2Mriabh10OuITD5Q32yOFCt1FrJcaVMsX14LmrO48YJ4eRytUnStzz5VANMDy
         2UTZcaFQaO02Gplo5BfY6mmrelurHqI2dhDSdbX62CwwEkUbLg4FS3cX4CA86AA1XG1B
         VhpPhqlM1dp7a/DV17FfdfhrGqE+ZNmZkO9r26z5Zb7b7V6TFaeVxs2rSdXQseS6/R4a
         xC7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530H/fLmX3h10N3syu0ZbbBI6HyKeg9W3G6nKDC6yG7xlfwMadKi
	SrWvkjCch6MTsIQ0brrFPuE=
X-Google-Smtp-Source: ABdhPJy2pMSt5AYc0q5lOt3h4puo+bmeVxY5aTv7Zg66+efdqTK4xATebg8rXBkajH4Au9Dznj6+mw==
X-Received: by 2002:a05:6512:1090:b0:46b:825b:88c6 with SMTP id j16-20020a056512109000b0046b825b88c6mr1803797lfg.363.1649939830344;
        Thu, 14 Apr 2022 05:37:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls4386079lfb.1.gmail; Thu, 14 Apr 2022
 05:37:09 -0700 (PDT)
X-Received: by 2002:a05:6512:3d0a:b0:46d:94f:b0b6 with SMTP id d10-20020a0565123d0a00b0046d094fb0b6mr1828099lfv.486.1649939828922;
        Thu, 14 Apr 2022 05:37:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649939828; cv=none;
        d=google.com; s=arc-20160816;
        b=mQmWABslX5AcQnOliZgBrdIgmaO/o1poYoKZfwhxWTRJ9Vjk544NOOApo1u5KIGDY5
         Cu1DuPozW86hBTXnbM5j3w1ZW/uxpER0NG2/WgHZ+XaeMZosavTMSuuhVP0254ad+qY5
         SI57pLKAStDJ27M0IyjJAOBt2BjDUT9+Z6ncGd1U7P6fj3snEfXiWI+7qleZwQNUgcjQ
         iqclMxgpHNHc68BXZCE20k3JOiNKBJ4X8MbNU6LtJZUVdawHe9o0U/+8hebuyoBtOR6g
         TsPosvFovmSDoVBT7f2h+89pkAF2zVlcOtGVedwVdl6l6nstwyZmkub0aGkATkq3452u
         9ExQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=4EF5Tgb5j0BM7sWKb61MgBi/L5BwSadZvMPwhXzpxlE=;
        b=PMb4G+UNJwGz6g7nC+074F7JLi8X4X4TDc/R4liiLD4W70atN9Uq0qXF+4q9dBP8dt
         X/aZNZQWl4FRBpVPGKLCOhdw8+ICnsKvbfG2Pkco3M++s9PUUNYA5jOumtxnYW5OB0gP
         VGite4YsqlIPbX4n42yQCsky/z8OiieKb1NywhtAV05n8M3D8GQOJBA4P0LSXzb9LAy3
         56KJU1qsWEKnso5bhX4fDthnXKSiayZPD0ANtnSLswQzXtWcQeZglL2rFFtJ3tpeFYDZ
         Yi1MEPvbIfXYKaYRfVTFIcm0wwp1zFqI4gmhcRqceBXZM7jSb6OX7QpoushDhwt4oNsW
         ah8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s27-20020ac2465b000000b0046c9d290537si259899lfo.9.2022.04.14.05.37.08
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Apr 2022 05:37:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7DD25139F;
	Thu, 14 Apr 2022 05:37:07 -0700 (PDT)
Received: from lakrids (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 31D4D3F70D;
	Thu, 14 Apr 2022 05:37:05 -0700 (PDT)
Date: Thu, 14 Apr 2022 13:36:59 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 0/3] kasan, arm64, scs: collect stack traces from
 Shadow Call Stack
Message-ID: <YlgVa+AP0g4IYvzN@lakrids>
References: <cover.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1649877511.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Apr 13, 2022 at 09:26:43PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Currently, when saving alloc and free stack traces, KASAN uses the normal
> stack trace collection routines, which rely on the unwinder.
> 
> Instead of invoking the unwinder, collect the stack trace by copying
> frames from the Shadow Call Stack. This reduces boot time by ~30% for
> all KASAN modes when Shadow Call Stack is enabled. See below for the
> details of how the measurements were performed.
> 
> Stack staces are collected from the Shadow Call Stack via a new
> stack_trace_save_shadow() interface.
> 
> Note that the implementation is best-effort and only works in certain
> contexts. See patch #3 for details.
> 
> ---
> 
> Changes
> =======
> 
> v2->v3:
> - Limit hardirq and drop SDEI support for performance and simplicity.
> - Move stack_trace_save_shadow() implementation back to mm/kasan:
>   it's not mature enough to be used as a system-wide stack trace
>   collection replacement.
> - Clarify -ENOSYS return value from stack_trace_save_shadow().
> - Don't rename nr_entries to size in kasan_save_stack().
> - Check return value of stack_trace_save_shadow() instead of checking
>   CONFIG_HAVE_SHADOW_STACKTRACE in kasan_save_stack().
> 
> v1->v2:
> - Provide a kernel-wide stack_trace_save_shadow() interface for collecting
>   stack traces from shadow stack.
> - Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
> - Get SCS pointer from x18, as per-task value is meant to save the SCS
>   value on CPU switches.
> - Collect stack frames from SDEI and IRQ contexts.
> 
> Perf
> ====
> 
> To measure performance impact, I used QEMU in full system emulation mode
> on an x86-64 host.

Just to be clear: QEMU TCG mode is *in no way* representative of HW
performance, and has drastically different performance characteristics
compared to real HW. Please be very clear when you are quoting
performance figures from QEMU TCG mode.

Previously you said you were trying to optimize this so that some
version of KASAN could be enabled in production builds, and the above is
not a suitable benchmark system for that.

Is that *actually* what you're trying to enable, or are you just trying
to speed up running instances under QEMU (e.g. for arm64 Syzkaller runs
on GCE)?

> As proposed by Mark, I passed no filesystem to QEMU and booted with panic=-1:
> 
> qemu-system-aarch64 \
> 	-machine virt,mte=on -cpu max \
> 	-m 2G -smp 1 -nographic \
> 	-kernel ./xbins/Image \
> 	-append "console=ttyAMA0 earlyprintk=serial panic=-1" \
> 	-no-shutdown -no-reboot
> 
> Just in case, the QEMU version is:
> 
> $ qemu-system-aarch64 --version
> QEMU emulator version 6.2.94 (v5.2.0-rc3-12124-g81c7ed41a1)

Thanks for this information, this makes it *much* easier to see what's
going on here.

As I suspected, you're hitting a known performance oddity with QEMU TCG
mode where pointer authentication is *incredibly* slow when using the
architected QARMA5 algorithm (enabled by default with `-cpu max`).

Practically speaking, when using TCG mode with `-cpu max`, PACIASP and
AUTIASP instructions in function prologues/epilogues take much longer
than they would on real hardware, and this means that those skew
performance with an overhead whcih scales with the number of function
calls. The regular unwinder is hit pretty bad by this because it has a
few function calls (including KASAN instrumentation), and the overhead
of this dominates the cost of the actual unwind logic. Your SCS unwinder
isn't as badly hit by that because it has fewer function calls.

This overhead has nothing to do with the *nature* of the unwinder, and
is an artifact of the *platform* and the *structure* of the code.
There's plenty that can be done to avoid that overhead, including basic
QEMU options which don't require kernel changes.

For example, if you replace:

	-cpu max

With:

	-cpu max,pauth-impdef=true

... QEMU will use an IMPLEMENTATION DEFINED pointer authentication
algorithm which is *much* faster than its implementation of QARMA5 (and
tests below show that make the kernel reach the panic in ~1/6 the time).

Since you're testing with shadow call stack, you could decide to disable
pointer authentication entirely. You can tell QEMU to not provide that
with:

	-cpu max,pauth=false

... which in tests below makes the kernel reach the panic in 1/9 the
time.

You could instead change your config to have
CONFIG_ARM64_PTR_AUTH_KERNEL=n, which would cause the kernel to be built
without the instructions which are causing the slowdown.

For comparisons below, I've built the same version of QEMU as you're
using. The numbering in that version string is a bit confusing, so I've
gone by the git commit ID:

| commit 81c7ed41a1b33031f3e4fe24191a998a492044b8 (HEAD, tag: v7.0.0-rc4, origin/master, origin/HEAD)
| Author:     Peter Maydell <peter.maydell@linaro.org>
| AuthorDate: Tue Apr 12 17:01:34 2022 +0100
| Commit:     Peter Maydell <peter.maydell@linaro.org>
| CommitDate: Tue Apr 12 17:01:34 2022 +0100
| 
|     Update version for v7.0.0-rc4 release
|     
|     Signed-off-by: Peter Maydell <peter.maydell@linaro.org>
| 
| diff --git a/VERSION b/VERSION
| index 80d0afb063..9c57137cdf 100644
| --- a/VERSION
| +++ b/VERSION
| @@ -1 +1 @@
| -6.2.93
| +6.2.94

My host machine is an Intel Xeon E5-2660.

> Copyright (c) 2003-2022 Fabrice Bellard and the QEMU Project developers
> 
> Then, I recorded the timestamp of when the "Kernel panic" line was printed
> to the kernel log.
> 
> The measurements were done on 5 kernel flavors:
> 
> master                 (mainline commit a19944809fe99):
> master-no-stack-traces (stack trace collection commented out)
> master-no-stack-depot  (saving to stack depot commented out)
> up-scs-stacks-v3       (collecting stack traces from SCS)
> up-scs-stacks-v3-noscs (up-scs-stacks-v3 with __noscs marking)
> 
> (The last flavor is included just for the record: it produces an unexpected
>  slowdown. The likely reason is that helper functions stop getting inlined.)

As above, that case is hitting the overhead of QEMU TCG mode's
incredibly slow pointer authentication.

> All the branches can be found here:
> 
> https://github.com/xairy/linux/branches/all
> 
> The measurements were performed for Generic and HW_TAGS KASAN modes.
> 
> The .configs are here (essentially, defconfig + SCS + KASAN):
> 
> Generic KASAN: https://gist.github.com/xairy/d527ad31c0b54898512c92898d62beed
> HW_TAGS KASAN: https://gist.github.com/xairy/390e4ef0140de3f4f9a49efe20708d21
> 
> The results:
> 
> Generic KASAN
> -------------
> 
> master-no-stack-traces: 8.03
> master:                 11.55 (+43.8%)
> master-no-stack-depot:  11.53 (+43.5%)
> up-scs-stacks-v3:       8.31  (+3.4%)
> up-scs-stacks-v3-noscs: 9.11  (+13.4%)

I made the same measurements, reading the timestamp on the panic
message. From my local results, the performance oddity with pointer
authentication dominates everything else, and by changing QEMU options
to minimize or eliminate that overhead the difference in unwinder
overhead becomes far less pronouced and the overall boot time is reduced
to a fraction of the time taken when the incredibly slow imlpementation
of pointer authentication is used:

Generic KASAN w/ `-cpu max`
---------------------------

master-no-stack-traces: 12.66
master:                 18.39 (+45.2%)
master-no-stack-depot:  17.85 (+40.1%)
up-scs-stacks-v3:       13.54 (+7.0%)

Generic KASAN w/ `-cpu max,pauth-impdef=true`
---------------------------------------------

master-no-stack-traces: 2.69
master:                 3.35 (+24.5%)
master-no-stack-depot:  3.54 (+31.5%)
up-scs-stacks-v3:       2.80 (+4.1%)

All results are 5x to 6x faster; the regular unwinder overhead is
reduced by ~20% relative to `-cpu max`.

Generic KASAN w/ `-cpu max,pauth=false`
---------------------------------------

master-no-stack-traces: 1.92
master:                 2.27  (+18.2%)
master-no-stack-depot:  2.22  (+15.6%)
up-scs-stacks-v3:       2.06  (+7.3%)

All results are 6x to 9x faster; the regular unwinder overhead is
reduced by 27% relative to `-cpu max`.

To speed up your QEMU runs, there are a couple of trivial options
available to you which'll improve your runs by ~6x to ~9x, which vastly
outstrips any benefit gained from changing the unwinder. I'd recommend
you at least consider moving to `pauth-impdef=true`.

While the SCS unwinder is still faster, the difference is nowhere near
as pronounced. As I mentioned before, there are changes that we can make
to the regular unwinder to close that gap somewhat, some of which I
intend to make as part of ongoing cleanup/rework in that area.

I haven't bothered testing HW_TAGS, because the performance
characteristics of emulated MTE are also nothing like that of a real HW
implementation.

So, given that and the problems I mentioned before, I don't think
there's a justification for adding a separate SCS unwinder. As before,
I'm still happy to try to make the regular unwinder faster (and I'm
happy to make changes which benefit QEMU TCG mode if those don't harm
the maintainability of the unwinder).

NAK to adding an SCS-specific unwinder, regardless of where in the
source tree that is placed.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlgVa%2BAP0g4IYvzN%40lakrids.
