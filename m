Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMNGY6GQMGQEWNM72FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id BDF4B46E609
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 10:58:10 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id b14-20020a05651c0b0e00b0021a1a39c481sf1639404ljr.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 01:58:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639043890; cv=pass;
        d=google.com; s=arc-20160816;
        b=YN/FQie5i1gZNkDeW36rC+mVMYDlLv94F/CHtpZKcBOFAdP+6UisbBHhZdXWcfZjYT
         G2LCiIrPLXshSe2bu1Uy1KWw/Kgw60HU6HEVsJOQk7hDCrr/JZ8+BvO2MCoE4Df4jUSe
         75XV41SGn6aOTXvZ8HBbV3njxs+pzGuoV61qo4VPg883ChfSQyJJ4Pp9MkT57KcZ7EUd
         qY2pFf3JNyB2y7XuxCSy8VsRAS2xMk5KtmsAR2F5QWcDeZtRFATJvGQvx8fIJRnJjKwM
         WU+C8cs/T9kaSuCfreBzXtocL1gvOg4WgwOjkw/wqKdMa+SCO9T1DAfi//JW2BEM0awZ
         iccQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=gW/RjWYsP3y886saXyQKscH+nDVnrhuM/juTxl3gLj0=;
        b=dMRG9pWwSFNuA1vvs5MYLCzQyQdLFzNz+uvvt9ppMyTVdvsgJGEziNx9ZOyaP8jrHw
         wBFUhb7vk+shMZRQPf3uNBNCV7iKZ1jb2MiSdl3wFMHxONSKDHBqhCcVai4DTz5KJBk2
         f6cJsHZ1t5Q1t12Obc6DBv0zTC0V89ZM4F+QeceQKTxPI0sWfNwzSmQB/wcHOTi9MtLj
         5TDf/zFCE25iFbnmBIJxG9Cxdz8v5A0ioUtOQYmd7BiGVVA81DhcQis3baEo6y7wiZO/
         xipHMsuwZ0hyyT8c/skLs+zUluZrxwXp1BtyNqCdbxlv3DOiOYzqu8oFDqYI7TBynRZh
         IWCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LGp39Mjf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gW/RjWYsP3y886saXyQKscH+nDVnrhuM/juTxl3gLj0=;
        b=drKScDYVTyKvvLKjlw9+MQTi1WLIPmSkh5GaaV5BWV0q/ID+MTdIxUp2bebPfj/Wia
         Txx1nCdOG5yRjeQx+6zzAYPPxEE0za5UCkCsjeegCPKfYxiNEnh0+pUiEIfwN+lxR/GU
         Cjw1ftENBahSqa4Qs9GIgpLA2chIIN6XEVM3Yik1GVC65h5okIgz6ELI1TcEr0qzdXFH
         8kL3BoVkG1EI01zAjBbyPIISX1rMy6KTWxG9AYnbNGJyqmar0H9FH5RT5ZaYqsca/6Yn
         KK/qhLZw4VD8fZvJ9ES56DO1fuHiogcOUKUOTJH15HrTq+drCttVINii1euRFknEz7Q2
         sQSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gW/RjWYsP3y886saXyQKscH+nDVnrhuM/juTxl3gLj0=;
        b=bEkbJkDIQiDOQke9yPoQI01Q4iI9gPfSOsfhgVqO6sRzOxkT6jXr84FOqWir/iA0yb
         vKB0r3UKDXezLgSeWy8jkx/P+bcEwjZ7EhNsJ2CPQKcptUULashGb29LGUdZb3rigLTD
         5m/60r/nnIfcGt0y8wvzWSSjvqzUofYbrJb0bKxFX81OcRvoenHj84mWVmhcH3fx29/S
         L2rmc45gJpfJZGcYxWs3n+WZBGmy5F8OGqYnDsvHDd1GIATB45e3sqJSs265VA6deWaw
         4XMvOTLyGezL0KJ0SNJ9MtXcMHETtqGGMuZUJhaJXOGliTLJl71r11VZgVB314F6DVPc
         Tm1w==
X-Gm-Message-State: AOAM532igzmB6OnlPeJ4/aPBNZIFIP71U3jNKx5mhRK7tH8DuGLplhYt
	CKJwxayrQlYcdWlOccuQ7Eo=
X-Google-Smtp-Source: ABdhPJwwiOPTk/V3pvTYEo74EEupXX3xwkeb4KxraoBO1ZxWON7yBH8pg3H4JWQUqkDAHZTqvuXArg==
X-Received: by 2002:a05:6512:3216:: with SMTP id d22mr4954663lfe.604.1639043890191;
        Thu, 09 Dec 2021 01:58:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls2971652lfu.0.gmail; Thu,
 09 Dec 2021 01:58:09 -0800 (PST)
X-Received: by 2002:ac2:4d97:: with SMTP id g23mr4964301lfe.200.1639043889081;
        Thu, 09 Dec 2021 01:58:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639043889; cv=none;
        d=google.com; s=arc-20160816;
        b=AUkHI253tzu5qHDbTLUrP2ARHg87+b/V+Y2iWKz7IsoVtFfcMzmVjRPPK2PPcVHylc
         VkdHitiSNp5sGF/JG2vDB2CwSmMUZ4tbLjzd6n8krVHIjGOoRefk5lmXTiZNhtJr7HRT
         Rgr+v6MuM8rV5rVEeN4F+kU05TklkS3ybUCjHPFAAUKJWu9b/CVFglSkpI5HL6L8Aekr
         3lJ0AuP/E7Hrtusc/EvSOuaM51oUxJ5FgfBWpA/2bZKyH5102pjPv55kGkEg1IKBbSXx
         l+9/GRLTqdalWHdRI6I2O6qIi7IFBs3k5PStoZ15+tni/5FIgHkJiWIyhR0jOCoHoTJB
         Cbpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WEDTgzpiltL1NT8/HeGXwilTe74ZNI0f4xOOiwCoVRw=;
        b=jiM+I8kmTveODNu/2L9TA+sJLPMu73XXEBOBqc8QmP6+KLFy4Qyy01RBwEOsi0lKtx
         Fm6QI/+mvkJp/bHKUAkhuoc3qp4MwIYfxQgAsHfwozJX8zoIlPORrCzYhItPmHSY7hj2
         3U6T0VV/fI8V8CyMiAo/vGK0enlmBwCo9F+QePpuadzBp6ZsT1MSjGgTAPdprT+t7Bjb
         GlpEU2UAHtjwzFmIcNMFquuWubzELz6OcRfXCLFOoNsQw02DBUGUkNmMmdeoi9a5uTx5
         vSx1zKLHVDvf/Fnhp8zQmaD8LGm5HKuwaN4Zpeo1+gxJYJ9rR6j8PEg4/UrAFZjJIMNM
         r9SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LGp39Mjf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id v8si367350ljh.8.2021.12.09.01.58.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 01:58:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id i8-20020a7bc948000000b0030db7b70b6bso6108449wml.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 01:58:09 -0800 (PST)
X-Received: by 2002:a7b:c848:: with SMTP id c8mr5903612wml.105.1639043888649;
        Thu, 09 Dec 2021 01:58:08 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:21de:5a72:cfa8:19ce])
        by smtp.gmail.com with ESMTPSA id f15sm6351289wmg.30.2021.12.09.01.58.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Dec 2021 01:58:07 -0800 (PST)
Date: Thu, 9 Dec 2021 10:58:01 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Alexander Potapenko <glider@google.com>,
	Jann Horn <jannh@google.com>, Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Subject: randomize_kstack: To init or not to init?
Message-ID: <YbHTKUjEejZCLyhX@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LGp39Mjf;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
default since dcb7c0b9461c2, which is why this came on my radar. And
Clang also performs auto-init of allocas when auto-init is on
(https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
allocas.

add_random_kstack_offset() uses __builtin_alloca() to add a stack
offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
enabled, add_random_kstack_offset() will auto-init that unused portion
of the stack used to add an offset.

There are several problems with this:

	1. These offsets can be as large as 1023 bytes. Performing
	   memset() on them isn't exactly cheap, and this is done on
	   every syscall entry.

	2. Architectures adding add_random_kstack_offset() to syscall
	   entry implemented in C require them to be 'noinstr' (e.g. see
	   x86 and s390). The potential problem here is that a call to
	   memset may occur, which is not noinstr.

A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:

 | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
 | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section

Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.

To figure out what the right solution is, the first thing to figure out
is, do we actually want that offset portion of the stack to be
auto-init'd?

There are several options:

	A. Make memset (and probably all other mem-transfer functions)
	   noinstr compatible, if that is even possible. This only solves
	   problem #2.

	B. A workaround could be using a VLA with
	   __attribute__((uninitialized)), but requires some restructuring
	   to make sure the VLA remains in scope and other trickery to
	   convince the compiler to not give up that stack space.

	C. Introduce a new __builtin_alloca_uninitialized().

I think #C would be the most robust solution, but means this would
remain as-is for a while.

Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbHTKUjEejZCLyhX%40elver.google.com.
