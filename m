Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5FQGCAMGQEO5RTTTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C212367018
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 18:27:56 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id j6-20020a05651231c6b02901abd14b042csf9049334lfe.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 09:27:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619022475; cv=pass;
        d=google.com; s=arc-20160816;
        b=cP8BOV9DoUiHNOm4Rj8c4ObtfEQkKKHcAMaBW/fKqww0Pz4ocsOEEvIst4L4mJVE28
         mhF/Wemf69V03z91usJG6xy7oe+/eI7U+bjygjOg2KLeFmtu8VyIVoOkMQCOV+lMdjqA
         d2kVuRdUtP4tfha5s65T9TIeCt7J3X5y9iUcOjeBVY4Dmqik2A82eKOh/IvA986dJcnX
         ZySshAbfYLFl7PTOqrN0m6bbdEhfePQgjm4xQbDaibtTn65ohfCqzrFmyES/Crs438Aw
         HcCr+RfCbxzZhcykvQdhbwremxZraVVsEk3tnr8sXCZRqqwNT0Iw3Z2TDjqWv635SfSv
         P45g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OYPig0iNxZuvQc3pzJveVxAcPqkNO1eTbc4H7zg3OLA=;
        b=wmTa8cIqwA3sYvrdBi7zM8uPMG/9mLTDnhMJDUoRgsM+8U9qeLkhLfIQVOpgXVkzuN
         +TK5pp+abVyBnNP3YlwAtmlS7vZdAPINtojuqqa5ztwLyHumUTn4GYFXP9w/SHMcRKxe
         w49b+u+0cP4vHeLUsuVOjG7HdOnTsMAyAEY4h1cszka80jH4devlYLl8ma53qKSRlGEJ
         r8BmFvowfUAEjkDFLBn+8O1DjNSXXcgTKRLR+TQvm2b6c69me34tmkz6mAXx/KBJoJtj
         2NXGCArJmljQ1hrpAI/YUv2yggNXtJge52Cn8cFr64gyDPo1lRqJF1BrJPGUc6ZyPcnH
         0XXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DXNQF6+X;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OYPig0iNxZuvQc3pzJveVxAcPqkNO1eTbc4H7zg3OLA=;
        b=Rmma01Fx9973PqNz/OzLc2OJkMTaMCz7I9flLAykiWkPSVOwGTFZ0ECANwmgll0FHo
         pCSmoHt/tLNeADPIWgEHz9Q9CAeiCPUvXOrLXYnBMH9B7h0YX71EnI0J5cONohIz7UQA
         2DPbrnRbNh+WGOGJoDQzjB9xsjYoOcZakiuzTXY6Rk+t4FGT37WLKKp0I1nDUVql1y+O
         fLmE9NEz8cJmVqfDHnhJXzCoaXwtmOhNlduhvNVMKm2LINRV7Ps5f/jss66aG3dDxAWG
         KSYX/XoozWwe+K4RJNVcpcXoz1L5PUUMYuZbdtXxILHy9JNvNqEJthUzaked4xZoQjfG
         Dqng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OYPig0iNxZuvQc3pzJveVxAcPqkNO1eTbc4H7zg3OLA=;
        b=rnAaPk5ysHPqlxw3zp9Umf7vskCyRPG4rsIc412WxWQE+Pf7BNsQPuBTuylRcVWE+X
         +9z9JAcjEu8gp1ETUdJ8yg0V2MmXkRikAPlHknjWhValp7JCdGxPkRLKusTiW8Hgi8vj
         ULOqDBuFE6+JlBf4E125gqABbzahBjlYd/SY1LqMcHd5cY8eU9hWCQAvi6mn50WbQmVw
         BpLDV/Zrz0ceLfRTYKIynlm8EcxNEDYXh5zkAHPm6MJFTE/fATDthIwc9HKRqHMT1r3r
         RGBc770+u0PIMkqhkKJX8ambvVP9e0wxao8O3TqVfc8TjH8OiHBq1Y12NzOAafg0sJqM
         9SPQ==
X-Gm-Message-State: AOAM533oED0lYHYZg0n0/Pb3uIxCg4fJLqdDsaSYcxqH2OGBU1VwLk2s
	f974ionMYSgLkTCyo9iIh/g=
X-Google-Smtp-Source: ABdhPJy3f0Fm+tzAFjZm7xNAK5DMCO+Qxqrx+CmJsxMHBQFbhfmslByKo/DjW2GnTyIKg5bhflILsg==
X-Received: by 2002:a2e:3c1a:: with SMTP id j26mr19173346lja.297.1619022475776;
        Wed, 21 Apr 2021 09:27:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls2127711lff.3.gmail; Wed, 21
 Apr 2021 09:27:54 -0700 (PDT)
X-Received: by 2002:ac2:54b5:: with SMTP id w21mr20133049lfk.427.1619022474367;
        Wed, 21 Apr 2021 09:27:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619022474; cv=none;
        d=google.com; s=arc-20160816;
        b=IohCmK4JUmwzBYdkxMWI8pWqIvriyBlsVkJRGDtvNQE1gTQs/7pFsV2TGjyztN8AXB
         8BxWqHaLIETIEdUTysgSC7rRxwdF7yiostB7JEhtvjHJCLbBwW+jBOSTgfeLNP3jGMdb
         vu8YHqt/0NTh4DS6hT/hjxpZbi/uCJPsHvsgsq6YctpUuXKVKmk48bf9zWshh5QjJz0j
         74ULEvF4qGB7qIpdAL3LcmqNi+ifg9aKQuWODGJL20C3NYGPE8HETwvrbAkH8qtIFv47
         fsXk9jvszTVrdaoDUCUhz5tZLV7AE2sqjT3CtwtrXK+4umoGiBLIFDINfp9eQoQtKbUk
         7JYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SmfHH6hIJqwyK5X8i5q3Sks3m+nCGH0WqXp+KsNmUL8=;
        b=IIvwowFRkoBvXPOdek0q5qmfpqlgnnA7bHXoOYSy6lZO07c3YUgjsnfutgvpkLWMC1
         jSukdv3Ief7YXpHbdqp8ID4geshegzqIkCDC8l7RLqHB8sjxbe7xXL2Ug/IcBatNEnf7
         9bHyQOeb9jfGOcjy4P4CYdj8VCG/Pbkt49Tv8Bb90DJoIzKY9cWg2T/EkeaYslyfaNJA
         K3VtrtdjcMF7ewjmwWAoPcCCsAXVrjxGPj6UqlDSMaaKKGiY33K47iq5zRto20xWPLhT
         Io8dV9iIK00Vga+dTo2gZKkp8Z5B5vpGC6BkbS6mUiXFGfAhU71lyCy+chcOuHkp8JQX
         Awww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DXNQF6+X;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id l11si193496lfg.13.2021.04.21.09.27.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 09:27:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id o9-20020a1c41090000b029012c8dac9d47so1627832wma.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 09:27:54 -0700 (PDT)
X-Received: by 2002:a1c:7f16:: with SMTP id a22mr10182034wmd.17.1619022473891;
        Wed, 21 Apr 2021 09:27:53 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
        by smtp.gmail.com with ESMTPSA id f23sm2803158wmf.37.2021.04.21.09.27.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Apr 2021 09:27:52 -0700 (PDT)
Date: Wed, 21 Apr 2021 18:27:47 +0200
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
Message-ID: <YIBSg7Vi+U383dT7@elver.google.com>
References: <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
 <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
 <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com>
 <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
 <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
 <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
 <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DXNQF6+X;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Wed, Apr 21, 2021 at 05:11PM +0200, Marco Elver wrote:
> +Cc linux-arm-kernel
> 
[...]
> >
> > I've managed to reproduce this issue with a public Raspberry Pi OS Lite
> > rootfs image, even without deploying kernel modules:
> >
> > https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-03-25/2021-03-04-raspios-buster-armhf-lite.zip
> >
> > # qemu-system-arm -M virt -smp 2 -m 512 -kernel zImage -append "earlycon
> > console=ttyAMA0 root=/dev/vda2 rw rootwait" -serial stdio -display none
> > -monitor null -device virtio-blk-device,drive=virtio-blk -drive
> > file=/tmp/2021-03-04-raspios-buster-armhf-lite.img,id=virtio-blk,if=none,format=raw
> > -netdev user,id=user -device virtio-net-device,netdev=user
> >
> > The above one doesn't boot if zImage z compiled from commit fb6cc127e0b6
> > and boots if compiled from 2e498d0a74e5. In both cases I've used default
> > arm/multi_v7_defconfig and
> > gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabi toolchain.
> 
> Yup, I've narrowed it down to the addition of "__u64 _perf" to
> siginfo_t. My guess is the __u64 causes a different alignment for a
> bunch of adjacent fields. It seems that x86 and m68k are the only ones
> that have compile-time tests for the offsets. Arm should probably add
> those -- I have added a bucket of static_assert() in
> arch/arm/kernel/signal.c and see that something's off.
> 
> I'll hopefully have a fix in a day or so.

Arm and compiler folks: are there some special alignment requirement for
__u64 on arm 32-bit? (And if there is for arm64, please shout as well.)

With the static-asserts below, the only thing that I can do to fix it is
to completely remove the __u64. Padding it before or after with __u32
just does not work. It seems that the use of __u64 shifts everything
in __sifields by 4 bytes.

diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index d0bb9125c853..b02a4ac55938 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -92,7 +92,10 @@ union __sifields {
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
-			__u64 _perf;
+			struct {
+				__u32 _perf1;
+				__u32 _perf2;
+			} _perf;
 		};
 	} _sigfault;

^^ works, but I'd hate to have to split this into 2 __u32 because it
makes the whole design worse.

What alignment trick do we have to do here to fix it for __u64?


------ >8 ------

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index a3a38d0a4c85..6c558dc314c3 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -725,3 +725,41 @@ asmlinkage void do_rseq_syscall(struct pt_regs *regs)
 	rseq_syscall(regs);
 }
 #endif
+
+/*
+ * Compile-time tests for siginfo_t offsets. Changes to NSIG* likely come with
+ * new fields; new fields should be added below.
+ */
+static_assert(NSIGILL	== 11);
+static_assert(NSIGFPE	== 15);
+static_assert(NSIGSEGV	== 9);
+static_assert(NSIGBUS	== 5);
+static_assert(NSIGTRAP	== 6);
+static_assert(NSIGCHLD	== 6);
+static_assert(NSIGSYS	== 2);
+static_assert(offsetof(siginfo_t, si_signo)	== 0x00);
+static_assert(offsetof(siginfo_t, si_errno)	== 0x04);
+static_assert(offsetof(siginfo_t, si_code)	== 0x08);
+static_assert(offsetof(siginfo_t, si_pid)	== 0x0c);
+#if 0
+static_assert(offsetof(siginfo_t, si_uid)	== 0x10);
+static_assert(offsetof(siginfo_t, si_tid)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_overrun)	== 0x10);
+static_assert(offsetof(siginfo_t, si_status)	== 0x14);
+static_assert(offsetof(siginfo_t, si_utime)	== 0x18);
+static_assert(offsetof(siginfo_t, si_stime)	== 0x1c);
+static_assert(offsetof(siginfo_t, si_value)	== 0x14);
+static_assert(offsetof(siginfo_t, si_int)	== 0x14);
+static_assert(offsetof(siginfo_t, si_ptr)	== 0x14);
+static_assert(offsetof(siginfo_t, si_addr)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_addr_lsb)	== 0x10);
+static_assert(offsetof(siginfo_t, si_lower)	== 0x14);
+static_assert(offsetof(siginfo_t, si_upper)	== 0x18);
+static_assert(offsetof(siginfo_t, si_pkey)	== 0x14);
+static_assert(offsetof(siginfo_t, si_perf)	== 0x10);
+static_assert(offsetof(siginfo_t, si_band)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_fd)	== 0x10);
+static_assert(offsetof(siginfo_t, si_call_addr)	== 0x0c);
+static_assert(offsetof(siginfo_t, si_syscall)	== 0x10);
+static_assert(offsetof(siginfo_t, si_arch)	== 0x14);
+#endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YIBSg7Vi%2BU383dT7%40elver.google.com.
