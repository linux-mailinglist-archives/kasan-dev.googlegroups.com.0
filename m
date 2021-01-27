Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXUMY6AAMGQEVEZB34I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8176D306499
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 21:00:31 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id 68sf1962191pfe.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 12:00:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611777630; cv=pass;
        d=google.com; s=arc-20160816;
        b=iIK+LHgLOjJF3mmeksgXBmw8U3QcV15s/I1yOYoxoT8YlIF16bnmvhhwYBxWQ5JE/E
         0hVHum4NDbRnF1NjunbSfpZu2G5vWtEWcFEXxy8UzVtl5HHDb1pY/HwZqxWliQFh1Sed
         DWEZh1cscQGZELV8pxbKFmeWpHKFe/HIt4RbLgjFTOToYLrt5L/Cuset0bRT0ydkOOm0
         OIkf7yTzrDsFFLbGTeCubpx75XS17SSfPAfvx+zpxE8f8CsS5kufKDmkJ6EJFmhbZvhH
         AhjUvvYksZUgW9n0Bsv1RqDZvRIjj02e1YCPaHJPJ29v3FJa0mhGeFqcIFXGFkTJx0D9
         DOww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=odzdGGacD/F2Ifg+ErJqY9bDRIaUD5jKEKhXgDLMCuA=;
        b=Z9ZTo1ji45USBEk7YKp++SpaoJbl0gAG96kwJd9hi8Zaq3chgkIicBFKsoIx1D+pHS
         HXIF279g7xWEKCgNcj9Tga2WPkZ+iEtmhKn9tDTYnY963FAu1j6Gp50NUQQz671JViI5
         +Ct/c1BI+EfVYpa6QpCzVi8sASALf0tnZD86IZOY0KQo5OXWt2Zhvzzu39q75Uq5chHb
         KvPxtr6JAWlMOLN2/st5s2Iiar8JwMRy29oKK2goDkQC/ySpS33qMbrZltgmblqv1tkL
         BrXDzjrasQeJta+Z/sVpabpF/O7jTfGK6USE5bB/Dk9TnpCzNO0YRv69r2Xwhrb1Kg7v
         Bbgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V8QOj+Q+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odzdGGacD/F2Ifg+ErJqY9bDRIaUD5jKEKhXgDLMCuA=;
        b=B4zkEMGZhrXFwJSmoFGpHJelpZxjsbxsRGdK6S3T1bKbzv/UxbTiaSMOuf8pE+EG5/
         WEXGYV6yZACMncLRQuwtozh18JLI/38WGkMQ8jLqXb3vOO6TlNdbPG+MtbPB/gA29GkO
         aWPO2YUrwXg7h3SaKTPrq8RhWT0nLIMTeJ7hpE+nSllYFtquxl6mlVAgT2GFbfEN2jkO
         p6kdQT1nxAq/1OSWGPuAL9lJhhJ5xdIgJ1WrjUHhoKTlB3QTH4qkDlhoVGUokXtzH27i
         SqZImZ2qUaO/dT0jK22SjVtwtgOdBOnvQc5Q0YnwPUZgOQHVIVKj24HD/htYlhYTY0TN
         k9gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=odzdGGacD/F2Ifg+ErJqY9bDRIaUD5jKEKhXgDLMCuA=;
        b=dTcd/8dDilnP1B/iF95bye3QtSXRpb0K+UyGgF2KAdgQrWE0VL6bgymaEynqWm4jYe
         +eLHQ1y4ouWyT53fJSm1yALEoa6mYIh23eilxJqMv4KpByTg1RNXKsQC6Mxv0AZ3LMUX
         9MmGeyiIMKEf62xxDqqDe1vJtwC/Mc5PC38B8RT4UXBnANjm4JfgF/UUC9ywCA/fWJSo
         cS7HFggtCLq4iKV7amcW7+d0B+/JCu12BozakfnZcPvERUo1DU6D2yJ9EfKKtO1Iyb+p
         I0QFxzUoe7xcHsK9dMZbZ1OSHPxPl23fExfZwmbyaInDVbb+UsRaqGDIyCdcN6aoI7+E
         Ubcg==
X-Gm-Message-State: AOAM531s179P7Rh/5yZKVKSf7CkczbeyXtmEiLns5EIBYM2kZX7KHudf
	Ut66LBIIFvcs0GIPJQOtF4U=
X-Google-Smtp-Source: ABdhPJwQFf7D2zl6T+0VQ5ZOqXDLXIk29KkvLPkFGUH553rZpfkCvrPVlK33FBNLhBRiXPbYNxWjrw==
X-Received: by 2002:a17:90a:f98c:: with SMTP id cq12mr7280980pjb.191.1611777630219;
        Wed, 27 Jan 2021 12:00:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ce54:: with SMTP id r20ls1209683pgi.2.gmail; Wed, 27 Jan
 2021 12:00:29 -0800 (PST)
X-Received: by 2002:a63:5459:: with SMTP id e25mr1991787pgm.403.1611777629555;
        Wed, 27 Jan 2021 12:00:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611777629; cv=none;
        d=google.com; s=arc-20160816;
        b=dTQ2KfxmYV7PlA3eq0roQolGxT3AKumh50rSkVvONrOs4KwfFi9S9qrDwsgCAntqCX
         ZN8ALa3lsOMC5/lVmErwdu6nFZqYo9RUbc5Y+e+/7Fma6DQya40Vu0vVn8QrG4XWWTxH
         KFXxW1X0+CZ5YzXrHjLtjE6LbiO1NDn6mThiM8WaWBPp/LEHyfS5webSDa0PWrocqQUr
         sfMUVyDpdFm7P/ikwxHANbqtc8yLuk/7mH8eJ/4FNNip1u9H34nBTOoYemRcyaCZQ0/k
         C4L2Sk7xWphCrn+/V/EmgOaTjPLwGzB3/CwD+yyKD/SxQG619FZe3uG1/q5IVYk2owsN
         oOew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yBdA7Nf3DvwxZdzX00Eonq9lYvdJAq2LlEJMLWdaFgQ=;
        b=mV5cdZvicVzejYm1E1uotCz3emWa5pfxWN8rP4hd0J3WHuSsAnspdIceAeACON0y++
         AIw1r3ZKaCSklcppqZinxVhRrSWe1HOhKka0qtjx6s19tGT8Vt1zdIk6TBq5QpYzmn+U
         UBdRa+3I9Fgr4xiokvQanzsvTfvNuqJNSWFPE+nHKK00aFzdSkXaywBp//fPR7DHFIVN
         DJwYCHLtBdWV5Q7pt3gDqUxffHPhpNDtBPg5Bxfdktt2o+U5DEmtEKStOjAvKy+zOhl+
         +zi+OqBhjaCLoACNnJvJf20+HjX7tD6H6gQMA4VvHSY2edzeZsQsbWyvGyMzPuGGxn7O
         EgkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V8QOj+Q+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id r142si169448pfr.0.2021.01.27.12.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 12:00:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id s23so1039885pgh.11
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 12:00:29 -0800 (PST)
X-Received: by 2002:a05:6a00:1:b029:1c1:2d5f:dc16 with SMTP id
 h1-20020a056a000001b02901c12d5fdc16mr12176024pfk.55.1611777628828; Wed, 27
 Jan 2021 12:00:28 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210126134603.49759-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 21:00:17 +0100
Message-ID: <CAAeHK+xTWrdJ2as6kBLX+z64iu3e6JEGppOkN-i_jsH74c6xoA@mail.gmail.com>
Subject: Re: [PATCH v9 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V8QOj+Q+;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> This patchset implements the asynchronous mode support for ARMv8.5-A
> Memory Tagging Extension (MTE), which is a debugging feature that allows
> to detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.
>
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> When MTE is enabled and tags are set for ranges of address space of a task,
> the PE will compare the tag related to the physical memory with the tag
> related to the virtual address (tag check operation). Access to the memory
> is granted only if the two tags match. In case of mismatch the PE will raise
> an exception.
>
> The exception can be handled synchronously or asynchronously. When the
> asynchronous mode is enabled:
>   - Upon fault the PE updates the TFSR_EL1 register.
>   - The kernel detects the change during one of the following:
>     - Context switching
>     - Return to user/EL0
>     - Kernel entry from EL1
>     - Kernel exit to EL1
>   - If the register has been updated by the PE the kernel clears it and
>     reports the error.
>
> The series is based on linux-next/akpm.
>
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
>
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm
>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Evgenii Stepanov <eugenis@google.com>
> Cc: Branislav Rankov <Branislav.Rankov@arm.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Tested-by: Andrey Konovalov <andreyknvl@google.com>

> Vincenzo Frascino (4):
>   arm64: mte: Add asynchronous mode support
>   kasan: Add KASAN mode kernel parameter
>   kasan: Add report for async mode
>   arm64: mte: Enable async tag check fault

Andrew, could you pick this up into mm? The whole series will need to
go through mm due to dependencies on the patches that are already
there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxTWrdJ2as6kBLX%2Bz64iu3e6JEGppOkN-i_jsH74c6xoA%40mail.gmail.com.
