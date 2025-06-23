Return-Path: <kasan-dev+bncBDDL3KWR4EBRBW4B4XBAMGQE2NHVQXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id E3854AE3EB7
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 13:56:12 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-86a50b5f5bdsf284131139f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 04:56:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750679771; cv=pass;
        d=google.com; s=arc-20240605;
        b=RXEEmaKdDz4SAS6lcYGR7Ni1QnzbbKtjJquWDKcrcB6sVuQh/OYrI9EO4BmnwFSCv3
         nVqyNW7sh+EtYCEszYFBIzJfKy3yCG0DAY8YXNMl3mNdQZAk/qnfguhB9JbRolMYsraI
         5FZ/xlpnSJ0CKmvqwmtTxr4koed7TMNX5vcyDYI6OvU9hSYtZE1qxcCwfX63i33hwaOe
         dRSzOVyziIUWw5p9geQx1ZOcdz7HRVKM18KKkmtnKTKyFxcfTJ1z+RQg2JGMEj/O+4MN
         /YgyAHux+MLVYYpmeSuDomCFwIfae6WzPWRNgsXHRq6rylfGMOir+4IRdzkls1m6n7jM
         vQ+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QcDUv6egjRrk3C5AOEmbmQHFPOJOdn3o+Ccw4G3lxT8=;
        fh=9W5hu3+0cwAOQpYWSRCZvKQYp++DQBrYKwhZwUfLE3s=;
        b=Lz5HVe9xf+dEgZyh7/FgjWHKeKJnrOH8c4E1Ah86NWHIgBYF3IBOtaxGSOwAE3HQmQ
         9fTTnwyJs+FWLSTvLlwvQr5V3fCAcunBOGWrTbu5cKqpu9VH9MDhS0zJMLLhWDekP1ba
         CrkQaNoA7aDuXKUQsTIymog1YVipurzCpYrf1wbF2uN8++LM/ArDIBMWR3/GTcMmPycs
         PG2sS/GYbY0pn62kZi0J+YsAwXWuncfZTsGrjzeTdIjr+I4ZPXIYXysJcN8R2M5lhfvc
         OHnH2vd+THLIM5Aidwzi9q7lk+b8WjrpMKfw7sc1roe9JlhfhSDY1bRVVYIauNQCW05N
         lmQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=catalin.marinas@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750679771; x=1751284571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QcDUv6egjRrk3C5AOEmbmQHFPOJOdn3o+Ccw4G3lxT8=;
        b=moHPvPiA/kBIs3LPPzDVm8QxbRvppxtnNWMODvW/R9FSMTHA0GwwhDgW7ce2ybDMx9
         fUlkiV0bp8jM0d882ebhtUxZzxzM+zhQCzUZNOHWbEJgHF8qghX8t8QuKKPcPxWMjU0j
         SJCtp8wT2/1qx4PYYnF4j0jDWLssuMh11i2QcsOmMfC0yXIwPqOsqpah36+JWkZmBv+w
         yrM4v3urmwRS3Hk0wJ079jwDaSmKVyyixYIT+1N8FMZLcUdgYpNsgQXeZyib5uk/HEdb
         RXZiifOIKkCt5TkDc5ucX4FdnVp03mdE92BSYkwhmxx4p/QSHlfnGQ1dxjSNwV7oRS+q
         6OrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750679771; x=1751284571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QcDUv6egjRrk3C5AOEmbmQHFPOJOdn3o+Ccw4G3lxT8=;
        b=APpm2Fp4msxdvxCqV6d7RwU/jPYsyXzLGzFOvBeEL7UPrnuD2niJ0RP4WXse/N6Ovr
         mzBLnxh70Oy43xP8nST9/6wbhktTLsU7UPgCsJWCn4amxW80YMXYYpkKUQqLVGyaGe26
         6M37HgUYsO7ExPg63/TI7ZGeDYiaVC+Awza5vLCFp4eLtR4d/ba11vi/23QMAt3v2M+i
         yWhxpkR6RfbqXJwxLnzXg4sOaWQtygUFkXbaVzqyDuPyaib4p49XtNEnzjakI6shwZ37
         y6/GLP9dvqG3zbM65gCbYR8wuoL6PAmsgyjDji/T1QMWYGrd1BSMha3/MeQqNq2pzszv
         0Rvg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW68CdUD4lmeJdCg2ZomwBI6u1vQAYTahUT67tDM6LnOANEjomaFReWBa5ZdVXjTEFjR8U0zg==@lfdr.de
X-Gm-Message-State: AOJu0YwWmcAnzRvySwVbV9DV2b/Jb4uFS922dvedbbIkl59Yq36ffU3b
	UHcqWiHmlbST3qQ2bxvYHI62bbKo5j0Zg79k2VpUNhR/c5oTFIYWtaGi
X-Google-Smtp-Source: AGHT+IFkgf6gwGieTn8k8XnNT/wuMc2mDszIomLoVE/3t0bEqgIK6z4Zko5lcGNvE7lkvmoocEo12A==
X-Received: by 2002:a05:6e02:32c1:b0:3dc:8b29:30bc with SMTP id e9e14a558f8ab-3de38cc3076mr135216875ab.21.1750679771189;
        Mon, 23 Jun 2025 04:56:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEC2Z7ZmoOxVTAXn8mEtlik482ehNTrXgxERMBX6v/Fg==
Received: by 2002:a05:6e02:460e:b0:3df:1573:75da with SMTP id
 e9e14a558f8ab-3df15737d4fls5379355ab.2.-pod-prod-04-us; Mon, 23 Jun 2025
 04:56:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXo7J7x528iVbbM8S43Oi+xnhuTDPRnwDztgK2KTYIsQ0HS78ulEL5jYVF1H0z73df/XeNy2MEGkw8=@googlegroups.com
X-Received: by 2002:a05:6e02:2217:b0:3dc:7a9a:4529 with SMTP id e9e14a558f8ab-3de38cb10cdmr138984015ab.16.1750679770297;
        Mon, 23 Jun 2025 04:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750679770; cv=none;
        d=google.com; s=arc-20240605;
        b=bfz+0aMoh9NUyn5wai3csrxHwBPczsIpCaLvi1nawrnCJ1BAxWpfLz78nljo7On/R8
         DAWcZWWW2wpQDsdPcm9d4wkpPF6yxxggdGv0SXDJJURg/TjNtBuQaUO0w0pJta7n4xYz
         OL8ynuLu9OqmxxeBru7JQqti0T11dAt0ftyXZEN5gF0K9NPy6flK4/SjcJidallFUT7/
         LAOiBWyaKyCBTlXZrnpSPxN4/p0B5wTQmqfqiUQAR5lDYhJJXsi3BVYGLYunowbp8nO0
         JjVB/VSZpqRC3ddDMv47nmPpKinCfgU5H1sLMKPzv7avaTzpAUKqIpqMY5D74nhftGoR
         ZLcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=64+Kcu62qwNapQJ3CG8fsGya6FkUjObefaU0itBbNEg=;
        fh=6TofbWZukq/bkLoIKidqS7uSkGNT+n8xN1hkmLDFujM=;
        b=Xg/E/MtHpcllk+tY4t0KMGr0r4fKd2hFtSks+EmFnjLxtpjkTvoGOapVaPM7FW59jN
         cg+7VhBxzu3smi30ewIOIxyMsHncLhE56v8X1MJtewjZ4JWz+0nWmQgfI8M1AExZ5w/W
         75jNnXzCkw9W5Hz18l67U83uLK62jtno+nRr9SzbfEDcwq1gBmWVrdQk8eAP1myvGHau
         g9yM6eTf0/vw3XiEx4HH431HN4jWZcZVR7YlijxO1qoWbkdVog+sXzpPAqsGfkndl3Q5
         9R5zcpUZow9W2vO9AN+VznDjtSvHrAAr1r239gahYUORUluieXncRUn7jp6/BNHAMqON
         fBig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=catalin.marinas@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-5019e002239si322275173.4.2025.06.23.04.56.10
        for <kasan-dev@googlegroups.com>;
        Mon, 23 Jun 2025 04:56:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A209D113E;
	Mon, 23 Jun 2025 04:55:51 -0700 (PDT)
Received: from arm.com (usa-sjc-mx-foss1.foss.arm.com [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A21FA3F58B;
	Mon, 23 Jun 2025 04:56:08 -0700 (PDT)
Date: Mon, 23 Jun 2025 12:56:06 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Breno Leitao <leitao@debian.org>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, will@kernel.org,
	song@kernel.org, mark.rutland@arm.com, usamaarif642@gmail.com,
	Ard Biesheuvel <ardb@kernel.org>
Subject: Re: arm64: BUG: KASAN: invalid-access in arch_stack_walk
Message-ID: <aFlA1tXXUEBZP1NH@arm.com>
References: <aFVVEgD0236LdrL6@gmail.com>
 <CA+fCnZfzHOFjVo43UZK8H6h3j=OHjfF13oFJvT0P-SM84Oc4qQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfzHOFjVo43UZK8H6h3j=OHjfF13oFJvT0P-SM84Oc4qQ@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=catalin.marinas@arm.com;       dmarc=pass
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

On Sun, Jun 22, 2025 at 02:57:16PM +0200, Andrey Konovalov wrote:
> On Fri, Jun 20, 2025 at 2:33=E2=80=AFPM Breno Leitao <leitao@debian.org> =
wrote:
> > I'm encountering a KASAN warning during aarch64 boot and I am strugglin=
g
> > to determine the cause. I haven't come across any reports about this on
> > the mailing list so far, so I'm sharing this early in case others are
> > seeing it too.
> >
> > This issue occurs both on Linus's upstream branch and in the 6.15 final
> > release. The stack trace below is from 6.15 final. I haven't started
> > bisecting yet, but that's my next step.
> >
> > Here are a few details about the problem:
> >
> > 1) it happen on my kernel boots on a aarch64 host
> > 2) The lines do not match the code very well, and I am not sure why. It
> >    seems it is offset by two lines. The stack is based on commit
> >    0ff41df1cb26 ("Linux 6.15")
> > 3) My config is at https://pastebin.com/ye46bEK9
> >
> >
> >         [  235.831690] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >         [  235.861238] BUG: KASAN: invalid-access in arch_stack_walk (a=
rch/arm64/kernel/stacktrace.c:346 arch/arm64/kernel/stacktrace.c:387)
> >         [  235.887206] Write of size 96 at addr a5ff80008ae8fb80 by tas=
k kworker/u288:26/3666
> >         [  235.918139] Pointer tag: [a5], memory tag: [00]
> >         [  235.942722] Workqueue: efi_rts_wq efi_call_rts
> >         [  235.942732] Call trace:
> >         [  235.942734] show_stack (arch/arm64/kernel/stacktrace.c:468) =
(C)
> >         [  235.942741] dump_stack_lvl (lib/dump_stack.c:123)
> >         [  235.942748] print_report (mm/kasan/report.c:409 mm/kasan/rep=
ort.c:521)
> >         [  235.942755] kasan_report (mm/kasan/report.c:636)
> >         [  235.942759] kasan_check_range (mm/kasan/sw_tags.c:85)
> >         [  235.942764] memset (mm/kasan/shadow.c:53)
> >         [  235.942769] arch_stack_walk (arch/arm64/kernel/stacktrace.c:=
346 arch/arm64/kernel/stacktrace.c:387)
> >         [  235.942773] return_address (arch/arm64/kernel/return_address=
.c:44)
> >         [  235.942778] trace_hardirqs_off.part.0 (kernel/trace/trace_pr=
eemptirq.c:95)
> >         [  235.942784] trace_hardirqs_off_finish (kernel/trace/trace_pr=
eemptirq.c:98)
> >         [  235.942789] enter_from_kernel_mode (arch/arm64/kernel/entry-=
common.c:62)
> >         [  235.942794] el1_interrupt (arch/arm64/kernel/entry-common.c:=
559 arch/arm64/kernel/entry-common.c:575)
> >         [  235.942799] el1h_64_irq_handler (arch/arm64/kernel/entry-com=
mon.c:581)
> >         [  235.942804] el1h_64_irq (arch/arm64/kernel/entry.S:596)
> >         [  235.942809]  0x3c52ff1ecc (P)
> >         [  235.942825]  0x3c52ff0ed4
> >         [  235.942829]  0x3c52f902d0
> >         [  235.942833]  0x3c52f953e8
> >         [  235.942837] __efi_rt_asm_wrapper (arch/arm64/kernel/efi-rt-w=
rapper.S:49)
> >         [  235.942843] efi_call_rts (drivers/firmware/efi/runtime-wrapp=
ers.c:269)
> >         [  235.942848] process_one_work (./arch/arm64/include/asm/jump_=
label.h:36 ./include/trace/events/workqueue.h:110 kernel/workqueue.c:3243)
> >         [  235.942854] worker_thread (kernel/workqueue.c:3313 kernel/wo=
rkqueue.c:3400)
> >         [  235.942858] kthread (kernel/kthread.c:464)
> >         [  235.942863] ret_from_fork (arch/arm64/kernel/entry.S:863)
> >
> >         [  236.436924] The buggy address belongs to the virtual mapping=
 at
> >         [a5ff80008ae80000, a5ff80008aea0000) created by:
> >         arm64_efi_rt_init (arch/arm64/kernel/efi.c:219)
> >
> >         [  236.506959] The buggy address belongs to the physical page:
> >         [  236.529724] page: refcount:1 mapcount:0 mapping:000000000000=
0000 index:0x0 pfn:0x12682
> >         [  236.562077] flags: 0x17fffd6c0000000(node=3D0|zone=3D2|lastc=
pupid=3D0x1ffff|kasantag=3D0x5b)
> >         [  236.593722] raw: 017fffd6c0000000 0000000000000000 dead00000=
0000122 0000000000000000
> >         [  236.625365] raw: 0000000000000000 0000000000000000 00000001f=
fffffff 0000000000000000
> >         [  236.657004] page dumped because: kasan: bad access detected
> >
> >         [  236.685828] Memory state around the buggy address:
> >         [  236.705390]  ffff80008ae8f900: 00 00 00 00 00 a5 a5 a5 a5 00=
 00 00 00 00 a5 a5
> >         [  236.734899]  ffff80008ae8fa00: a5 a5 a5 00 00 00 00 00 00 a5=
 a5 a5 a5 a5 00 a5
> >         [  236.764409] >ffff80008ae8fb00: 00 a5 a5 a5 00 a5 a5 a5 a5 a5=
 a5 00 a5 a5 a5 00
> >         [  236.793918]                                                 =
    ^
> >         [  236.818810]  ffff80008ae8fc00: a7 a5 a5 a5 a5 a5 a5 a5 a5 00=
 a5 00 a5 a5 a5 a5
> >         [  236.848321]  ffff80008ae8fd00: a5 a5 a5 a5 00 a5 00 a5 a5 a5=
 a5 a5 a5 a5 a5 a5
> >         [  236.877828] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>=20
> Looks like the memory allocated/mapped in arm64_efi_rt_init() is
> tagged by __vmalloc_node(). And this memory then gets used as a
> (irq-related? EFI-related?) stack. And having the SP register tagged
> breaks SW_TAGS instrumentation AFAIR [1], which is likely what
> produces this report.
>=20
> Adding kasan_reset_tag() to arm64_efi_rt_init() should likely fix
> this; similar to what we have in arch_alloc_vmap_stack(). Or should we
> make arm64_efi_rt_init() just call arch_alloc_vmap_stack()?

In theory, we can still disable the vmap stack, so we either fall back
to something else or require that EFI runtime depends on VMAP_STACK.
We can do like init_sdei_stacks(), just bail out if VMAP_STACK is
disabled.

Adding Ard, it's his code.

> [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/co=
mmit/?id=3D51fb34de2a4c8fa0f221246313700bfe3b6c586d

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
FlA1tXXUEBZP1NH%40arm.com.
