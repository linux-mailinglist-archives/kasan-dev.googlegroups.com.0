Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOH6UCQAMGQE73UJ35Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BD87E6B0042
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 08:54:33 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id l5-20020a92d8c5000000b00316f26477d6sf8275282ilo.10
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 23:54:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678262072; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q7wQKdhzh2vk+fflkFf7CTsTmQll2kbZ9kXbRPc8ThIUkBzzE/IYPeiqfMGTwRc5CG
         liwExZRJebUMApOADhM6aL7OoUBlN2E3FnhyA8wNKK9R1fnyARjNgQ+3dNafI1Q9BZtH
         ZAb9hCdZuIqiCZd0Nc9WPJZ7UIXfEmBsiqhdFVYDxreVzCWAYVFSCO87RVShaA5khV7x
         ecAcKPP0Os+1chB6Wc8IqZXIohiTiIJBf7Hkq1UcSa806O0/AoVD1gf5YLa9W3Ts5WZ3
         TDTUT3rnCzH6lLqHi5BsCX5Udnean7BQ+WwgTHtlpTu2o2mmyoD1/w9zzRtvA/sKda9s
         81yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5UorUAIDoFBy3eUc2KujLQhxUQO6mOJgxxvqsi1ifSY=;
        b=kzUwvZO1xHtMSDSE/Ju1UhMXhcfPjnr0WGw0y777/PyYd3qgStYL3s35pioI775HL/
         aAiFMXy8tBfuaaDvWEmhWCclzd6lOJYplIDDVCXYRre3dubUQH59dxBrqlGF7RY6BJL5
         Xz6gh0KJibzTxdQE/XtLoO6oUPJv5c8uYcyea5ZW19el7uHO00u67Bzd6NeTaTg5bGTB
         N654v7SWrn1TWmVMOfB2mlJrCx4XJ2dMQIfgNHNZ5E96lrwvD+GQkM4ppYgNHuYCwOrg
         fPSlwEvAH3M8/zfLoadGhoKLhlysXaBjxhvBvyCnHu6CgQ54Vjqq4cI+40ZKa5Wb2+uq
         VMGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lxu8zAqs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678262072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5UorUAIDoFBy3eUc2KujLQhxUQO6mOJgxxvqsi1ifSY=;
        b=rkyHEpHf4c38WhaVGMsokOzEUwls32ytEiHKUBT8xc3Xc9MmdZ7B7QhpaPnTWAFdxw
         ekdqU/3WyHCFNcXFxDcK4XGbmO1aYGyCTryO3bSYs57bxXPk29dsmMR3mYYwQu+j0FB/
         S6jRe1lBiBtjTWIYeYRTapXALRbymCSnJGomEcPJIzW4qz9qXqYCKIaIuYuqO42Loxrf
         dO86Kx65a6pvgKmits08k5FdzqOqkR3wHs/LdWvQYLX6b0p/gDvg8F5LAVd/yPqo2iFO
         AInctCUlNGgOGxBSU3DsL4S9qw4ItWSEJ0w8MYbialEi1dsVJkQSvPZe6P2cfjHM5wj1
         6QrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678262072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5UorUAIDoFBy3eUc2KujLQhxUQO6mOJgxxvqsi1ifSY=;
        b=eWLRyrOvtroOXreyMYexbKrGD2RX7DhOOYbTilyr9540KQTe4NSMxX6JVXSxJ28aHg
         sFVapTT1NlG3PJ1PCnP1izyaCV2/6RKr6qNNeWnDaZ+wbTVd9oeh1tdZbM3azhOiYqN7
         1sKQoINB4RYZi5DGGKLH1wmuhgJ111ln/wjfiUNT+gVvHsomoSOWhGEIpnW3vldWj1yh
         h0FvvnkIR3RLPcL+HK4IjglyiqInTaBUzCfgYyAYxlAzvzrUiZyEMFeNSunn2ouuw3tW
         hXjOrziflvURqcKCHVvxCvV+YgKacyRLISpkgKn0A67frc3AVJ3A9QcabZZORFm23Kkm
         CeDQ==
X-Gm-Message-State: AO0yUKUpTbfn+qGqddrHAOG5Zs/PkhaVMXRUVVcvBL+wQErQiHVBATdS
	GCh9E7+SyFvXp7YXQLw5PXs=
X-Google-Smtp-Source: AK7set+vZqqk0ueXEl0mshWYpCVOINeg+mzuROuugZPD6zEGp+L41aM6tZk+e02ljN8D7cq2b4BSqw==
X-Received: by 2002:a5d:8605:0:b0:74c:bb62:6763 with SMTP id f5-20020a5d8605000000b0074cbb626763mr8118532iol.1.1678262072613;
        Tue, 07 Mar 2023 23:54:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c002:0:b0:314:10d2:cf32 with SMTP id q2-20020a92c002000000b0031410d2cf32ls4406835ild.7.-pod-prod-gmail;
 Tue, 07 Mar 2023 23:54:32 -0800 (PST)
X-Received: by 2002:a05:6e02:1907:b0:315:4169:c5ac with SMTP id w7-20020a056e02190700b003154169c5acmr15584384ilu.30.1678262071995;
        Tue, 07 Mar 2023 23:54:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678262071; cv=none;
        d=google.com; s=arc-20160816;
        b=lLvLp8U2AfhDJYhWPL4KDiG5LOWwNbxnBBorf+bzDcM36J5FJ0006Jz2dDXRlexcSm
         A3TMLeqReXdi8taZTsuFEZNbu2foD1Vhp52lvuYJw+mvrCdCrPjY1srNCpKkoe0ty0qt
         UB/QlnuiTBT3JgbPehc7+UhousqV+1kh+eFmUmYpGmxcwKslO6+2ieMmrmLiY2yWQxSF
         K+5TrDp2TAac1odK7LV4WAupEussDwfnyC1nv5FU5gS4apPuK8y10Ps92rmT9N5nIRWM
         YUkXCIPZAMNvJC5+rODPVYWkkPzyFbMixh2xLAHLNlX4iUTXy7zl7TxWz7ShgiX1unY8
         ZhbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZROicEC9TU/Yf4zsBSpQ6SvtM6o02kLYOlQBx2ObDKY=;
        b=HqnFq92yKjgDLaeWu9gujTXlWTH6j0ld7vcs/zlFUF4CdwAmjW2TnDJPobf0PcYg1Z
         7lJj5/2UkucXDgGSL/IXY3wuXs0cNUIRM/3Y+cHkCijfT20FGKD28mijW5oBqJuhbt+k
         vg5LbkuZH49YypRvQcFDUi/PwPWKsReOnbssOfOuWjRK0YQoOpI3cLQQE43Zrkt8F406
         vdlAdSmeyuKnLQCsB/k+B4Wp6jRTw+wHkV98OjuaRZfOgbdquKMYNTkldllMSVo0upIw
         +YLm+Zatt7nomKhwmRWMpqJLKpcP/Rb/hULWySVgFvcx7OkjZRic6M5x3koqJ3ef3vL2
         skzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lxu8zAqs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe33.google.com (mail-vs1-xe33.google.com. [2607:f8b0:4864:20::e33])
        by gmr-mx.google.com with ESMTPS id o14-20020a92dace000000b003179767c2b2si644493ilq.0.2023.03.07.23.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Mar 2023 23:54:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) client-ip=2607:f8b0:4864:20::e33;
Received: by mail-vs1-xe33.google.com with SMTP id o32so14614835vsv.12
        for <kasan-dev@googlegroups.com>; Tue, 07 Mar 2023 23:54:31 -0800 (PST)
X-Received: by 2002:a05:6102:e43:b0:412:565:7f7a with SMTP id
 p3-20020a0561020e4300b0041205657f7amr11660339vst.4.1678262071318; Tue, 07 Mar
 2023 23:54:31 -0800 (PST)
MIME-Version: 1.0
References: <20230308022057.151078-1-haibo.li@mediatek.com>
In-Reply-To: <20230308022057.151078-1-haibo.li@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Mar 2023 08:53:55 +0100
Message-ID: <CANpmjNMj3JX6d=HS=CNzxZPZcJZWfz0G5wKmJjfGb_N525NNLw@mail.gmail.com>
Subject: Re: [PATCH] kcsan:fix alignment_fault when read unaligned
 instrumented memory
To: Haibo Li <haibo.li@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, xiaoming.yu@mediatek.com, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Lxu8zAqs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e33 as
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

On Wed, 8 Mar 2023 at 03:21, 'Haibo Li' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> After enable kcsan on arm64+linux-5.15,it reports alignment_fault
> when access unaligned address.

Is this KCSAN's fault or the fault of the code being instrumented?
I.e. if you disable KCSAN, is there still an alignment fault reported?

Because as-is, I don't understand how the instrumentation alone will
cause an alignment fault, because for every normal memory access there
is a corresponding instrumented access - therefore, that'd suggest
that the real access was also unaligned. Note that the compiler
inserts instrumentation _before_ the actual access, so if there's a
problem, that problem will manifest inside KCSAN.

Can you provide more information about what's going on (type of
access, size of access, etc.)?

> Here is the oops log:
> "
> Trying to unpack rootfs image as initramfs.....
> Unable to handle kernel paging request at virtual address
>   ffffff802a0d8d7171
> Mem abort info:o:
>   ESR = 0x9600002121
>   EC = 0x25: DABT (current EL), IL = 32 bitsts
>   SET = 0, FnV = 0 0
>   EA = 0, S1PTW = 0 0
>   FSC = 0x21: alignment fault
> Data abort info:o:
>   ISV = 0, ISS = 0x0000002121
>   CM = 0, WnR = 0 0
> swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000
> [ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,
> pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707
> Internal error: Oops: 96000021 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted
>   5.15.78-android13-8-g63561175bbda-dirty #1
> ...
> pc : kcsan_setup_watchpoint+0x26c/0x6bc
> lr : kcsan_setup_watchpoint+0x88/0x6bc
> sp : ffffffc00ab4b7f0
> x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001
> x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80
> x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71
> x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060
> x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000
> x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0
> x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8
> x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007
> x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70
> x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000
> Call trace:
>  kcsan_setup_watchpoint+0x26c/0x6bc
>  __tsan_read2+0x1f0/0x234
>  inflate_fast+0x498/0x750

^^ is it possible that an access in "inflate_fast" is unaligned?

>  zlib_inflate+0x1304/0x2384
>  __gunzip+0x3a0/0x45c
>  gunzip+0x20/0x30
>  unpack_to_rootfs+0x2a8/0x3fc
>  do_populate_rootfs+0xe8/0x11c
>  async_run_entry_fn+0x58/0x1bc
>  process_one_work+0x3ec/0x738
>  worker_thread+0x4c4/0x838
>  kthread+0x20c/0x258
>  ret_from_fork+0x10/0x20
> Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )
> ---[ end trace 613a943cb0a572b6 ]-----
> "
>
> After checking linux 6.3-rc1 on QEMU arm64,it still has the possibility
> to read unaligned address in read_instrumented_memory(qemu can not
> emulate alignment fault)
>
> To fix alignment fault and read the value of instrumented memory
> more effective,bypass the unaligned access in read_instrumented_memory.
>
> Signed-off-by: Haibo Li <haibo.li@mediatek.com>
> ---
>  kernel/kcsan/core.c | 5 +++++
>  1 file changed, 5 insertions(+)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 54d077e1a2dc..88e75d7d85d2 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -337,6 +337,11 @@ static void delay_access(int type)
>   */
>  static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
>  {
> +       bool aligned_read = (size == 1) || IS_ALIGNED((unsigned long)ptr, size);

(size==1) check is redundant because IS_ALIGNED(.., 1) should always
return true.

And this will also penalize other architectures which can do unaligned
accesses. So this check probably wants to be guarded by
"IS_ENABLED(CONFIG_ARM64)" or something.

> +       if (!aligned_read)
> +               return 0;
> +
>         switch (size) {
>         case 1:  return READ_ONCE(*(const u8 *)ptr);
>         case 2:  return READ_ONCE(*(const u16 *)ptr);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMj3JX6d%3DHS%3DCNzxZPZcJZWfz0G5wKmJjfGb_N525NNLw%40mail.gmail.com.
