Return-Path: <kasan-dev+bncBCMIZB7QWENRBP4C2S3QMGQENMR3M7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C5F99986CA3
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 08:37:52 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-42cb998fd32sf3432515e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 23:37:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727332672; cv=pass;
        d=google.com; s=arc-20240605;
        b=h1uVO1B5RXWHyBMIgWQFmdcL8e/WyacDbZ9yU0/A5+tqEKkXenBC5BFGh/GcSq0OsJ
         d6tF1tkzDtZ1pmxTiM/R1s1A6SldnHMKfJpCQcG5qr9nQmcjvSo3SOQ1e7IFlsnJwcd7
         xAFuSc1wAg9XYNnnIqCcg2E6WR1RMcZ/iSyocIuQBuvCH1f/YC4ZLLl0o+oOxTSZ1hmA
         lDB8YZhKWOMzZLpLCBp5mv46SIki1lpHDSVrmvoDYlcHPjMHiVVcmnRq08IbB3FsNead
         wLkBw91hsXxR9hBHQJ7HTNEi8lWNxIUf0HQMLP3uJqho/KmFnFy127CpP+ftib91iZR3
         GMCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xLae1FgQq2rdaC0k0U4I/5Wv7kozjoy8WTh2oLsurTU=;
        fh=shg//3KQUCtADCmyIpdhNTJEV534uAEMCKUJkRIwhYw=;
        b=ddA6fPCIjdFd34O0c2JkPRnR2mBnI44SrbXTDEddrwLihlktbkPH+fRwI2237pkuLG
         DeXKhJRLyKvw5XB3bQKS8c7zWu1n7aSdWoZZG+7/I2E97aI6CTXybMRCjmAUWXlMhs/C
         Nf5cR0DVJi96tdkzrvQB6eOQp4e0TRwVtqLues8lwQw1nlET00ikd6nzgxsu8G+8YVYF
         WQhm0RapE5auRdVyrJQHnJoebaUPS4Mnj8BjiYDfxgtc6fC4hnkRmSIWT2R0n1+jHUob
         tuoS4bJjISSqWdndBVR24PBLazRi3gAO9zDAxLFENSwHFfBA1MsCG9w4CROkaKGUB3x3
         m2Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VUD1xBYu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727332672; x=1727937472; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xLae1FgQq2rdaC0k0U4I/5Wv7kozjoy8WTh2oLsurTU=;
        b=RSC5sT/lJWoH7GW9VCyLgPbFcQd1i8gZmhp6Jnk82pJvTdtZp2V11a7pp/AGGrZvYm
         3hiKNjjruETMNNaTJfJEZKLDwEKYmKEfQJ6DP4qOJMf44rQRKSymfxSMgdOceAYoshyS
         b/ujhb8CXSVZD82fDBRpTZ9Qufl/K9QoqAWFu1nlWcNWYmeCnMy4syHaz+5NsC52n9dR
         WouAPd1BOYXsJtvcECuVjhHWpihQ0GxSW75ZsPC0ObNYyPm8/bJ1UqDoEfKXDtK2UNiW
         Ok3+sEMZRXDSJAJO+oGFCrDP58Cgc28a4ZC7w0f9uYbSyIvq7Gdbc5mSFVux+gYaXsgk
         DHXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727332672; x=1727937472;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xLae1FgQq2rdaC0k0U4I/5Wv7kozjoy8WTh2oLsurTU=;
        b=xJiQNM5z5P06mSo4kZlNQKqbFamCsf5Ni0P6sC2gKcCdVoc4bz+ljGB7laMWY787V6
         bij5BFAFJ/RENc9sWyjLsKbVjlCYc7OPAyRcSNFClH5IdprRll4f39yjIwFFCjtsclEw
         LOyvlhMOpRyMaY4M43KQKbG/zySZWqOK0sZieUww+GPhzhPrsr/E6Lkum+Sez8bqXvqF
         ebs4J+w6L1hT0o4LlI5opPL8wH8cVdJfU255bWSKOh7OPbdXMr7emKdUuVJdSnf2zIEc
         N3FzBfNhBgsEv1L0a2auCuLur6FdSjmpnO4QV2cQdeTRa9QcA2YnmYprihrUAx6jkOo2
         pjLg==
X-Forwarded-Encrypted: i=2; AJvYcCVslM0R/t2iglgTCDW5zWjjfxArt1uRKqCY52Cc8L/lwJ2/TdSsG1hwkA51lss0J/GXBcqxGg==@lfdr.de
X-Gm-Message-State: AOJu0YyBSNSj+qkyHCpxXzHFQvcROxSXOQVhWWoDM0aucFEKYDVwoH4W
	47ublknuhAKyyqh/2DcKvRNTygUfvOM/v3AB702frgTV5Qc5DgU/
X-Google-Smtp-Source: AGHT+IEleiVd+z3eB/DHkVXo5AhyTaOoPhIvG4CO5KEP4VVq952Cv2AHx4I5NBKh5ilCBZd3vzWsMw==
X-Received: by 2002:a05:600c:1c26:b0:42c:b8c9:16cb with SMTP id 5b1f17b1804b1-42e9610254fmr33403305e9.5.1727332671645;
        Wed, 25 Sep 2024 23:37:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:694e:0:b0:374:c0b6:44bf with SMTP id ffacd0b85a97d-37ccdaee286ls225029f8f.0.-pod-prod-03-eu;
 Wed, 25 Sep 2024 23:37:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFnaTqSdbUWCNdVMWxERHWdrEtB88Ekr2f11xXkyli7C66mXe7x/7YGrb4vJkcr0Yw9PYwvN5CCFU=@googlegroups.com
X-Received: by 2002:adf:f385:0:b0:37c:ccd1:5d55 with SMTP id ffacd0b85a97d-37cccd15d9dmr1706427f8f.25.1727332669589;
        Wed, 25 Sep 2024 23:37:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727332669; cv=none;
        d=google.com; s=arc-20240605;
        b=bE4fnfzhtnBbLxOv2gBwxGcIirXa7JNHWV2Hqh1/4f6LQARP/IpUaX5zCH/DVgPWu4
         29fLobV96fFpQu3/BYSXvhfgvuHsUk30vNMyu1BUqNs/+wZGmbrTDK62efD4703XIMKu
         2mJjHL1Cz4BO9xjQAvWa5tNa4/PT/SVTsid61Aehy5jNKT1jrhya3/fv86jmKSPHZo6J
         L0sQHOi4u9B7KMwg6dtLM3eIHyh3kQ0s0mG4XcVSjEi8hBNIytRLQxqPTCu5YrVG4sID
         nDg9TL1qz0SwgWdxbnfNbL/kxVdJN3MwEhQgUC0cSPZxaLVcii2hAqT8mNuPAlGdfAES
         2orQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RalEU07RSraN17vIQfT7Cy8CVyW/tem5p4MQ3xQOm68=;
        fh=XUrmabq458ucakS2+TFTbrf6jtqML4z+UUGENWoEKh4=;
        b=Cc5agE+Ns9zBV2WonjwVrMsnxGxy6rVePJ2sFR0Wly2bZaBeTWEyaEsW2W1c6YKK/e
         5+2Igq1VUkgmUSZ5IxsPqoIdG7gen48M46gwRh/qVInIhFk2kTjk3sH1wvYMYb4kCoom
         5pXRgTZp6v2jkD/TStHSiB3PJtyDcsPjI0HFjAMVoyYuYIzOw24xXhnmnKo5YnnHkORT
         KTEvxKZbII9FLgTCha6eY/8rN9TqgGUcglFKAjbu5BF1s9pT1uUNTC9/xix7E/O5V8dr
         PZo5ocdvoCL0oI+wzy+CdAT8RFhlj/NwvcWZbtPTKjd4zcvdi6k0jEQaKeL54ckE0cg2
         d/Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VUD1xBYu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e9025c970si4242995e9.0.2024.09.25.23.37.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 23:37:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-2f75c0b78fbso6746781fa.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 23:37:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVB3ZYv0liJGM81JTQOBGN/ULPUZYbxlINyzrIhZ6JtGRYLInFRC8DKu/THwZGYwH7aR+jWxLuLQM=@googlegroups.com
X-Received: by 2002:a05:651c:1543:b0:2f7:4e8c:9c11 with SMTP id
 38308e7fff4ca-2f914cacd98mr30565231fa.1.1727332668509; Wed, 25 Sep 2024
 23:37:48 -0700 (PDT)
MIME-Version: 1.0
References: <202409242144.863b2b22-oliver.sang@intel.com>
In-Reply-To: <202409242144.863b2b22-oliver.sang@intel.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Sep 2024 08:37:32 +0200
Message-ID: <CACT4Y+aLMmCvChrrqO34neheMT3Ntd-n0xw1cDY5_0WWvzJvDw@mail.gmail.com>
Subject: Re: [linus:master] [kcov] 6cd0dd934b: BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, linux-kernel@vger.kernel.org, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VUD1xBYu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 24 Sept 2024 at 15:45, kernel test robot <oliver.sang@intel.com> wrote:
>
> Hello,
>
> kernel test robot noticed "BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)" on:
>
> commit: 6cd0dd934b03d4ee4094ac474108723e2f2ed7d6 ("kcov: Add interrupt handling self test")
> https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master
>
> [test failed on linus/master      de5cb0dcb74c294ec527eddfe5094acfdb21ff21]
> [test failed on linux-next/master ef545bc03a65438cabe87beb1b9a15b0ffcb6ace]
>
> in testcase: trinity
> version: trinity-static-x86_64-x86_64-1c734c75-1_2020-01-06
> with following parameters:
>
>         runtime: 300s
>         group: group-02
>         nr_groups: 5
>
>
>
> compiler: gcc-12
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
>
> +-------------------------------------------------------+------------+------------+
> |                                                       | 477d81a1c4 | 6cd0dd934b |
> +-------------------------------------------------------+------------+------------+
> | BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)   | 0          | 18         |
> | Oops:stack_guard_page:#[##]PREEMPT_KASAN              | 0          | 18         |
> | RIP:error_entry                                       | 0          | 18         |
> +-------------------------------------------------------+------------+------------+
>
>
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202409242144.863b2b22-oliver.sang@intel.com
>
>
> [   16.984454][    C0] BUG: TASK stack guard page was hit at ffffc90000017ff8 (stack is ffffc90000018000..ffffc90000020000)
> [   16.984489][    C0] Oops: stack guard page: 0000 [#1] PREEMPT KASAN
> [   16.984510][    C0] CPU: 0 UID: 0 PID: 1 Comm: swapper Not tainted 6.11.0-rc2-00002-g6cd0dd934b03 #1 4a678012cbfb14407d2e0b76817d9700747886d7
> [   16.984535][    C0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [ 16.984547][ C0] RIP: 0010:error_entry (arch/x86/entry/entry_64.S:1007)
> [ 16.984604][ C0] Code: 0f 01 f8 e9 c2 fe ff ff 0f 1f 40 00 56 48 8b 74 24 08 48 89 7c 24 08 52 51 50 41 50 41 51 41 52 41 53 53 55 41 54 41 55 41 56 <41> 57 56 31 f6 31 d2 31 c9 45 31 c0 45 31 c9 45 31 d2 45 31 db 31
> All code
> ========
>    0:   0f 01 f8                swapgs
>    3:   e9 c2 fe ff ff          jmpq   0xfffffffffffffeca
>    8:   0f 1f 40 00             nopl   0x0(%rax)
>    c:   56                      push   %rsi
>    d:   48 8b 74 24 08          mov    0x8(%rsp),%rsi
>   12:   48 89 7c 24 08          mov    %rdi,0x8(%rsp)
>   17:   52                      push   %rdx
>   18:   51                      push   %rcx
>   19:   50                      push   %rax
>   1a:   41 50                   push   %r8
>   1c:   41 51                   push   %r9
>   1e:   41 52                   push   %r10
>   20:   41 53                   push   %r11
>   22:   53                      push   %rbx
>   23:   55                      push   %rbp
>   24:   41 54                   push   %r12
>   26:   41 55                   push   %r13
>   28:   41 56                   push   %r14
>   2a:*  41 57                   push   %r15             <-- trapping instruction
>   2c:   56                      push   %rsi
>   2d:   31 f6                   xor    %esi,%esi
>   2f:   31 d2                   xor    %edx,%edx
>   31:   31 c9                   xor    %ecx,%ecx
>   33:   45 31 c0                xor    %r8d,%r8d
>   36:   45 31 c9                xor    %r9d,%r9d
>   39:   45 31 d2                xor    %r10d,%r10d
>   3c:   45 31 db                xor    %r11d,%r11d
>   3f:   31                      .byte 0x31
>
> Code starting with the faulting instruction
> ===========================================
>    0:   41 57                   push   %r15
>    2:   56                      push   %rsi
>    3:   31 f6                   xor    %esi,%esi
>    5:   31 d2                   xor    %edx,%edx
>    7:   31 c9                   xor    %ecx,%ecx
>    9:   45 31 c0                xor    %r8d,%r8d
>    c:   45 31 c9                xor    %r9d,%r9d
>    f:   45 31 d2                xor    %r10d,%r10d
>   12:   45 31 db                xor    %r11d,%r11d
>   15:   31                      .byte 0x31
> [   16.984624][    C0] RSP: 0000:ffffc90000018000 EFLAGS: 00010046
> [   16.984642][    C0] RAX: 0000000000000002 RBX: ffffc900000180d8 RCX: 0000000000000000
> [   16.984657][    C0] RDX: 0000000000000000 RSI: ffffffff86400af9 RDI: 0000000000000000
> [   16.984671][    C0] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> [   16.984683][    C0] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> [   16.984697][    C0] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> [   16.984710][    C0] FS:  0000000000000000(0000) GS:ffffffff88355000(0000) knlGS:0000000000000000
> [   16.984733][    C0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [   16.984749][    C0] CR2: ffffc90000017ff8 CR3: 0000000008307000 CR4: 00000000000406b0
> [   16.984765][    C0] Call Trace:
> [   16.984775][    C0]  <#DF>
> [ 16.984785][ C0] ? show_regs (arch/x86/kernel/dumpstack.c:479)
> [ 16.984815][ C0] ? die (arch/x86/kernel/dumpstack.c:421 arch/x86/kernel/dumpstack.c:434 arch/x86/kernel/dumpstack.c:447)
> [ 16.984843][ C0] ? handle_stack_overflow (arch/x86/kernel/traps.c:329)
> [ 16.984865][ C0] ? get_stack_info_noinstr (arch/x86/kernel/dumpstack_64.c:173)
> [ 16.984899][ C0] ? exc_double_fault (arch/x86/kernel/traps.c:380)
> [ 16.984931][ C0] ? asm_exc_double_fault (arch/x86/include/asm/idtentry.h:668)
> [ 16.984955][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.984974][ C0] ? error_entry (arch/x86/entry/entry_64.S:1007)
> [   16.984993][    C0]  </#DF>
> [   16.984999][    C0]  <TASK>
> [ 16.985009][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985040][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985066][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985093][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985136][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985154][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985177][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985196][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985218][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985244][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985264][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985290][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985311][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985336][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985363][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985384][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985409][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985430][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985455][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985484][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985505][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985532][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985555][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985579][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985607][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985628][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985655][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985676][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985701][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985725][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985747][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985772][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985794][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985818][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985847][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985869][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985896][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.985919][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.985944][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.985972][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.985992][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986017][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986038][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986063][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986093][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986116][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986143][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986165][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986188][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986217][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986239][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986265][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986286][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986310][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986338][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986359][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986385][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986408][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986434][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986464][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986486][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986511][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986532][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986557][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986585][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986606][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986631][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986652][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986676][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986704][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986725][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986751][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986772][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986796][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986824][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986846][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986872][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213)
> [ 16.986893][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
> [ 16.986918][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539)
> [ 16.986948][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623)
> [ 16.986968][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58)
>
>
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240924/202409242144.863b2b22-oliver.sang@intel.com

FTR this is being debugged in:
https://lore.kernel.org/all/66eb52dc.050a0220.92ef1.0006.GAE@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaLMmCvChrrqO34neheMT3Ntd-n0xw1cDY5_0WWvzJvDw%40mail.gmail.com.
