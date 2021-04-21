Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN63QGCAMGQEHETP2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D2A23367275
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 20:23:52 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id a14-20020a2e7f0e0000b02900b9011db00csf9092485ljd.8
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 11:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619029432; cv=pass;
        d=google.com; s=arc-20160816;
        b=f8fLoj4JKiaw6P7OHjEO57+JLmFJt8bmXuucnbhRToPJUTYzn6He30MQaKFoMVGKGm
         NxcJZrKKUYOEq24VVZ6RgBWR0uXCVuiLsGpcF/jexKRrCKd4kjT5HZdG17oJo4NN3vWm
         aPWfvgAhMQCa3WuCAwFEhSGBhgCBBw2TuwLw7Bx1wLdc37fTMnnfXL81c/k3uRdllgWW
         I05ZZkplttIN6fzwBJ6T0eh4ZQ25589Tj3hsVvFhqma0dc1bYnAyhvieFNIa7Xq6B/7c
         FPOi7a5mJR1pWzG6HGYRKbkC2JUg5YxJfHuZQxJtJnVCv+WVrHJ8sA8E85qz3UQKzKSt
         UmdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2/kTTROlNTLvSO7kPXWpIn2cMxQUnqPoySozYL9szgk=;
        b=AYTzHY4Q2XyAFOnUyAEcF1YRMbIE+0gusNmasSA4F571N9KpOWF7WyFDBmwiA57717
         UCDyzifhD61ovEjamt17ze9gQnA/7eIDivuH2tnZS0ow41y2d9HNZn92ijQDaJ0k7GMv
         HDTHqy6+dx8if8WUaJ6YoZrlyTd4SfDNMZ4YzJOYZUiV+10f08R1wt+JaA9rFJ41QD7t
         0MqQM0GiPg6Bi0HFrU7s2grmUVsooETOUlV3zDxI2j04n4G5MvmCUwsKWpVwGg66bGt1
         bzEOwZJTP0aJiiBptyMz9YlY4G8UbiV416Q8TIG0rUBl6CLOA8carldyfrIPvgDptYJ+
         MsGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Llgaznfb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2/kTTROlNTLvSO7kPXWpIn2cMxQUnqPoySozYL9szgk=;
        b=tV8210NX4Fhaj6yQdqbATfAxLBXWnQpdc80nT2FW/DAdvfIeWEW3QVlKIjVnXsrbIy
         PrLYvwXqdcFi5B64ltmGVsD44OVy9Qyts78bBCbh8KEKizExzbKHUWFWCD3jKFNMPEYD
         wcO6VcghcmISrlCvx3vOhmmgAv9xOGt3EzZCcgN+0h3aFJbAUYQDrBE1ZnMHV1koFDGQ
         Gtbm8JdoNkg+rc/aYt+uertkN2cfeHY1r1pBQFnOyc+bR9RV6ZUMQ42EmzisjHZTx10j
         LMQOswdj8vJ6wJ0kolDdj5wUUXIKC+Glst9iOEJRK08Dx6i/tVZPh7Bw8LlQjc5nYk9N
         phHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2/kTTROlNTLvSO7kPXWpIn2cMxQUnqPoySozYL9szgk=;
        b=ArhadqNDGmERnXrk99QFcXn5wS4b5GkrbY7B2a8/cUa1JT6hxdMh+uOQ2sSIqQUBn+
         SCQX7U4Gx84v2Q8+RUx6fsRZeDcwIc6BHy0LdfzYZXOiZdXPJDDzRdUXFWHgMGZirk2r
         BRrYdRKdSAuuIDw0NUhYW6L3i1Yl9SqZ15tnQ22B27CqgFH8ZDdwdkndCelTjIM30mXi
         EdxWWCEcPHYcMoN0BphPx7aFqkrLLeQq4Q3KIjKLP4z4BwmDFCuvDydDWFXapXV+3c07
         wSDgASgE2gdeLRFjgvE2brouyNa4HimCoMM61dSfEzMJ5dot0vx0QjrpBYRwwdUNkbA9
         luUg==
X-Gm-Message-State: AOAM5319hSfyh/en/E5k+L5g1TOFmaXbRUGJizU+xOx/TA+t0ffZYiT1
	u0AJSgfgGSkUDXN5io2SkDg=
X-Google-Smtp-Source: ABdhPJyhWps/YmL1CqLgEwkckzcHlWulxPPt/Jh7iKxfTgd/Cy5Mlw+YsUDY16fL4DnXtE0igaT0qQ==
X-Received: by 2002:a2e:2a83:: with SMTP id q125mr9376802ljq.370.1619029432383;
        Wed, 21 Apr 2021 11:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls2325891lff.3.gmail; Wed, 21
 Apr 2021 11:23:51 -0700 (PDT)
X-Received: by 2002:a05:6512:3690:: with SMTP id d16mr7792978lfs.494.1619029430990;
        Wed, 21 Apr 2021 11:23:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619029430; cv=none;
        d=google.com; s=arc-20160816;
        b=q+pOcAPi3viW7OmCzdSPodmreliPb+aGfsBeUbfrFxZVKakgaY5jyiHUEA/q9taVKA
         pc+iiRfxZzZvZU6CrtPJ3gokzWy7MOxUyp29uGIF1eYXuTv9AUwowO+iqpyyQxIjfspX
         YOiMNGNx7Tq3Z/F+6oyKr1VOw8y5x2HxHy7Zeso5teGcrwPqvcJP6ef7Zrac6HdmLEgh
         6zyh1Q5Ow3vd9+A1dfG/MWNlJ6XyjUhydwF3oyMprwKl0GxxCsvg6wM3zRGkjG+Xi++e
         9wSTw3iYG2SpYMq/f24BWFJJ1krFUISNkz8nfeq8tg1nI8Al/NMw8if4PUFsd/1LEpGG
         Ozkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tJ7/2ImOqgNsMlFTe/U5S+rQQA/z5wDSOJMIaWnIOgo=;
        b=y7G/JTHl9QKfCSOGzhMgE/P9+bvutiZc7AZFMoYzEjotyFjAHDbSj30OLGiMe+KA1T
         rFuPmU+dcJzmRPjgrcd6NlSbV7lpd4CuKNPMyM1rCZchwlVWzvX+nS7+NrzXzqSOv6R0
         t6BeOx3mmyPqvHUNrVCsBxaHPhW5PxtlvJQvhayTRqqMWsn5/Rnete6KXqk1mkOLAtr8
         xoM3qkA5J5Mo7aTlub/ib8R/hJOupE4HUWeTuqF/4VxTrAiNB9F0IvMZbIoyOp60oRly
         9T31ouh2gN+bltwT1Em2O7j7YWBjTfhHe+Td95XwJadnlF1Zf+O6sJ71gBt9i6Bt0c/D
         Fg6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Llgaznfb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id d25si225400lja.2.2021.04.21.11.23.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 11:23:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id y204so21314337wmg.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 11:23:50 -0700 (PDT)
X-Received: by 2002:a05:600c:20d:: with SMTP id 13mr11054836wmi.29.1619029430262;
        Wed, 21 Apr 2021 11:23:50 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:6273:c89a:6562:e1ba])
        by smtp.gmail.com with ESMTPSA id m11sm232602wri.44.2021.04.21.11.23.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Apr 2021 11:23:49 -0700 (PDT)
Date: Wed, 21 Apr 2021 20:23:43 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Namhyung Kim <namhyung@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
	Christian Brauner <christian@brauner.io>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Ian Rogers <irogers@google.com>, Oleg Nesterov <oleg@redhat.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	linux-tegra@vger.kernel.org, jonathanh@nvidia.com
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
Message-ID: <YIBtr2w/8KhOoiUA@elver.google.com>
References: <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
 <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com>
 <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
 <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
 <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
 <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
 <YIBSg7Vi+U383dT7@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YIBSg7Vi+U383dT7@elver.google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Llgaznfb;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
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

On Wed, Apr 21, 2021 at 06:27PM +0200, Marco Elver wrote:
> On Wed, Apr 21, 2021 at 05:11PM +0200, Marco Elver wrote:
> > +Cc linux-arm-kernel
> > 
> [...]
> > >
> > > I've managed to reproduce this issue with a public Raspberry Pi OS Lite
> > > rootfs image, even without deploying kernel modules:
> > >
> > > https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-03-25/2021-03-04-raspios-buster-armhf-lite.zip
> > >
> > > # qemu-system-arm -M virt -smp 2 -m 512 -kernel zImage -append "earlycon
> > > console=ttyAMA0 root=/dev/vda2 rw rootwait" -serial stdio -display none
> > > -monitor null -device virtio-blk-device,drive=virtio-blk -drive
> > > file=/tmp/2021-03-04-raspios-buster-armhf-lite.img,id=virtio-blk,if=none,format=raw
> > > -netdev user,id=user -device virtio-net-device,netdev=user
> > >
> > > The above one doesn't boot if zImage z compiled from commit fb6cc127e0b6
> > > and boots if compiled from 2e498d0a74e5. In both cases I've used default
> > > arm/multi_v7_defconfig and
> > > gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabi toolchain.
> > 
> > Yup, I've narrowed it down to the addition of "__u64 _perf" to
> > siginfo_t. My guess is the __u64 causes a different alignment for a
> > bunch of adjacent fields. It seems that x86 and m68k are the only ones
> > that have compile-time tests for the offsets. Arm should probably add
> > those -- I have added a bucket of static_assert() in
> > arch/arm/kernel/signal.c and see that something's off.
> > 
> > I'll hopefully have a fix in a day or so.
> 
> Arm and compiler folks: are there some special alignment requirement for
> __u64 on arm 32-bit? (And if there is for arm64, please shout as well.)
> 
> With the static-asserts below, the only thing that I can do to fix it is
> to completely remove the __u64. Padding it before or after with __u32
> just does not work. It seems that the use of __u64 shifts everything
> in __sifields by 4 bytes.
> 
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index d0bb9125c853..b02a4ac55938 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -92,7 +92,10 @@ union __sifields {
>  				__u32 _pkey;
>  			} _addr_pkey;
>  			/* used when si_code=TRAP_PERF */
> -			__u64 _perf;
> +			struct {
> +				__u32 _perf1;
> +				__u32 _perf2;
> +			} _perf;
>  		};
>  	} _sigfault;
> 
> ^^ works, but I'd hate to have to split this into 2 __u32 because it
> makes the whole design worse.
> 
> What alignment trick do we have to do here to fix it for __u64?

So I think we just have to settle on 'unsigned long' here. On many
architectures, like 32-bit Arm, the alignment of a structure is that of
its largest member. This means that there is no portable way to add
64-bit integers to siginfo_t on 32-bit architectures.

In the case of the si_perf field, word size is sufficient since the data
it contains is user-defined. On 32-bit architectures, any excess bits of
perf_event_attr::sig_data will therefore be truncated when copying into
si_perf.

Feel free to test the below if you have time, but the below lets me boot
32-bit arm which previously timed out. It also passes all the
static_asserts() I added (will send those as separate patches).

Once I'm convinced this passes all others tests too, I'll send a patch.

Thanks,
-- Marco


diff --git a/include/linux/compat.h b/include/linux/compat.h
index c8821d966812..f0d2dd35d408 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -237,7 +237,7 @@ typedef struct compat_siginfo {
 					u32 _pkey;
 				} _addr_pkey;
 				/* used when si_code=TRAP_PERF */
-				compat_u64 _perf;
+				compat_ulong_t _perf;
 			};
 		} _sigfault;
 
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index d0bb9125c853..03d6f6d2c1fe 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -92,7 +92,7 @@ union __sifields {
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
-			__u64 _perf;
+			unsigned long _perf;
 		};
 	} _sigfault;
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YIBtr2w/8KhOoiUA%40elver.google.com.
