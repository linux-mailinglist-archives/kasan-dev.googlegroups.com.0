Return-Path: <kasan-dev+bncBCF5XGNWYQBRB45C4GHQMGQEHEDN2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AFCB4A5137
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 22:15:33 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 127-20020a630585000000b0035de5e88314sf9189222pgf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 13:15:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643663731; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mlb8vhDwNHqpOTJULtnqUdA7ZbV/TDjajHxlZd7LfllU5cQVvXGCqyoHtwlgnMMyCo
         kwa/uj4R4q4Nz+EOCvvfNv7loFYf8Djl6PvPGIhxw6MQx8KwhvP+n9ivTd3w7qFTmoQo
         CWtw6iUdESLGoS608KgNA8N4zZoNbgueho5eKUg6rSlQjU9ag+uza7ff90A8f5JPPlUA
         4h7Vb6lObmJpN2edb5cVk5UxoUvws2HGL5RwNjarOFo68028waZmb8F7GKgqrE91G2Bc
         s+qTiIGCV3YzfnGedUmptZAETbyDwjf0/FGJn+Qrt7qG0uh1e+NA2+fnRQSFYWJHTuMV
         wpuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TZe6f2ZoLsH1ILYMTXVAAmawDBVoP2ypBmT/WgkAWLE=;
        b=V1XFIEQhVacXaG47bE05pmf4ZJ27tS7D8p3AQ0l6mS588kzGZvCjg/Vd6OXXkC0wuL
         JIQmhMOiJXFYz3D9tK3cHQ7748r0I1kJUKNOX49FBnE1e1gD8fF2KwiQNngAtZYsT9h7
         Z7fQIMlK5nLHUkQHJYpbHUvQ0IzXoTAm8cN/lpGje99JA+MN+QX9ZItFEIdSgtigvN/p
         hKYSeJ9CZJ1L/kQd7ym3YFV6dbti+Aj4d8sUstuKSdihkfj4I2j9l5QviARWA1nsgfR5
         Ao9d4mL5yzw8EytVJkx01FVF0adfDNSVa4SEp1qkn0w+hiMBMmdhqXopPCw+HzJ3U217
         cosA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qo7cE3pl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TZe6f2ZoLsH1ILYMTXVAAmawDBVoP2ypBmT/WgkAWLE=;
        b=Nbj44wWXftjXZ1zvekzc9LM8OPI/CFqMdtAI6/Da6qk2XHM4WyqbxV8k0iNBLUw8Hx
         n5m+bGQqIkHDAgANxKU7vW4Ym55haYwfvQbJztdn6CFwqS7sarpmsydSXTH52yMqDo1j
         BigqPMtpCIs3QEX4CO9AgAzhBoCcsXvl6NiQAmOKrPaWtmp0vmWdn417bZy9dxXoNBRA
         6Px6wX8z8QMpK59Ilq1cGWdecxgoAldZfaWeYXPG/D7wmuGC+IRarss3iwGpeNY9wdnB
         EdXUMzl5l2vgjq52skUCvL/nWFrSXJdQULRyyVWiLW1Z1z+UyxJPGSrvdMwVex5JChri
         pPqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TZe6f2ZoLsH1ILYMTXVAAmawDBVoP2ypBmT/WgkAWLE=;
        b=Qh4gfGNq8vc5Dp1uyaBNAs8R4JdWAnifayKWCqRpeB67hlLrEEUqtHes+Om6xfuSfu
         AAEAHtSgUjIsN0z5r3vHgIwR1TtF+RzrDn3EzMb7JJLrAnnoLrUUS/e4e03cTxlfySAZ
         dUtGyNeg+ie+crUudcgbfFnIIrRFCHuPUn7b8WG0Mm+GPB9xZ/M5EGGpkKYUCwAyq/vL
         w0uRT3DFLjvmxxzsYsg0f1EI1nRAACbEiMQLmbwxWqZXwms+YDrvjj/oiNRxVmbZckzG
         fRTywpbfJnUbxI2fGubnJg9M2Axrni1zBb9yTTlSfg8D9RaXwmfhs9+XhQiluydGz72W
         8wsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530v+3NDe5gJvxsx5Ntuu7rZBkZbv2sfjHlSW9zF6ej+VSx/quHE
	o+j47WcA+Ke2q8aovzxO3x4=
X-Google-Smtp-Source: ABdhPJzjhzy2KcUu5XfyEifjzw7htFLIi9tSLDpHHUwKcIG6nQ1oo+LK+7zeNRXLaU+ptq4RL9L8gQ==
X-Received: by 2002:a17:902:6942:: with SMTP id k2mr22093823plt.133.1643663731302;
        Mon, 31 Jan 2022 13:15:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls5913762pgu.2.gmail; Mon, 31 Jan
 2022 13:15:30 -0800 (PST)
X-Received: by 2002:a63:e04a:: with SMTP id n10mr18506983pgj.487.1643663730707;
        Mon, 31 Jan 2022 13:15:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643663730; cv=none;
        d=google.com; s=arc-20160816;
        b=v70L9ilWcxd1z/qbahTOrpEcC0SmAyoImJJArONo/9JmKdLtQSpI/XxVbyNwQ1WSYE
         UrUOfWyau8TjSHkMdulPIXJ70JTGl4gOG+IAlq3Zn8FgyRhMAR2YgCUDY5j7Sg6JObu/
         eQmZWEeAke7tSYSA+iiN+pktMG7omRpsd/GhmWQjIZYomGnWbkvIa+IwliupLYsBg1xx
         fLoKuaTZkSbYxBQUrT5ZAW1QylYmrubd2x3tjYWJtq7t7V5U3biMb+ZPXyzmfHQ3N6/R
         WwRVTd2IZ9UwcIHSaQUb5JCQad3shf6ZbjStErxWfhfw33phkv35aCK1avDJf6pM0BnB
         XQtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cxXm9S9rBUGO+n/qf1n3on2rs5DZHI4UmQ2+ms2iYP4=;
        b=i1JR1cVcbr8z6KhRXuXpg8SDrvc+MmQ7r2nuAt/JOFJu4gAIukIDgCkbCCDDpHSB4L
         rIjr0se8tzcfIqX/4HmZrNh/ons2peQqgTBqQvdhQpZjMnG7a3m0PdJwlc5J9hjGQCTa
         qu/ouJ+jZK3X9bAnvJo+G/bSIPSaRalKcmzLvx2FbefjF4b+xveyytQX1UYcf+vdi7U8
         fVyrz/r9rgzTExuM16CTBDWO7D6hmxR20ORY7qq2xPodBghbLO34j6u5nr/y8wRW0N31
         Wem0BHuBoms/VFl1QGd86WfmNCYZLBGAhehdJpP09EygKDIx6Z+deQIZqfA49V18jLEF
         CfpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qo7cE3pl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id ck20si69805pjb.0.2022.01.31.13.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 13:15:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id h14so13662435plf.1
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 13:15:30 -0800 (PST)
X-Received: by 2002:a17:902:d509:: with SMTP id b9mr22602105plg.3.1643663730410;
        Mon, 31 Jan 2022 13:15:30 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id mi18sm219840pjb.35.2022.01.31.13.15.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Jan 2022 13:15:30 -0800 (PST)
Date: Mon, 31 Jan 2022 13:15:29 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/2] stack: Constrain and fix stack offset
 randomization with Clang builds
Message-ID: <202201311315.B9FDD0A@keescook>
References: <20220131090521.1947110-1-elver@google.com>
 <20220131090521.1947110-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220131090521.1947110-2-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Qo7cE3pl;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Jan 31, 2022 at 10:05:21AM +0100, Marco Elver wrote:
> All supported versions of Clang perform auto-init of __builtin_alloca()
> when stack auto-init is on (CONFIG_INIT_STACK_ALL_{ZERO,PATTERN}).
> 
> add_random_kstack_offset() uses __builtin_alloca() to add a stack
> offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> enabled, add_random_kstack_offset() will auto-init that unused portion
> of the stack used to add an offset.
> 
> There are several problems with this:
> 
> 	1. These offsets can be as large as 1023 bytes. Performing
> 	   memset() on them isn't exactly cheap, and this is done on
> 	   every syscall entry.
> 
> 	2. Architectures adding add_random_kstack_offset() to syscall
> 	   entry implemented in C require them to be 'noinstr' (e.g. see
> 	   x86 and s390). The potential problem here is that a call to
> 	   memset may occur, which is not noinstr.
> 
> A x86_64 defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> 
>  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> 
> Clang 14 (unreleased) will introduce a way to skip alloca initialization
> via __builtin_alloca_uninitialized() (https://reviews.llvm.org/D115440).
> 
> Constrain RANDOMIZE_KSTACK_OFFSET to only be enabled if no stack
> auto-init is enabled, the compiler is GCC, or Clang is version 14+. Use
> __builtin_alloca_uninitialized() if the compiler provides it, as is done
> by Clang 14.
> 
> Link: https://lkml.kernel.org/r/YbHTKUjEejZCLyhX@elver.google.com
> Fixes: 39218ff4c625 ("stack: Optionally randomize kernel stack offset each syscall")
> Signed-off-by: Marco Elver <elver@google.com>

Thanks for the tweaks; this looks good to me now.

Acked-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201311315.B9FDD0A%40keescook.
