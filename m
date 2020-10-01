Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFNU3D5QKGQED2IUCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C0BD28062F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 20:04:06 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 23sf2125209lfy.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 11:04:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575445; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gh8HxGWzPyqpyW5E1MP15ur7hTWgGH5nkBQKAojcuAbnjjLPbFTfRrOocvZ1iWl/Xf
         +CKloJzLyPduO+g8+f82nSe5p/bSgL/i5YlrQ7w21/6+3TVnkdlIwwA6x6BlWaGuzMVA
         xRt5NB55ctit/J3OiJ0KKyqYm6W7veEE+qoYdLZ3A6sM5sN4II3gPIYJUbE+3+1Ml97r
         aQJdG8f8KdlgFfDfox3+pvV3QKjam45GVEUI7Svs3rWM86kiIkEHlV+AHujhwoq0IJ8C
         RGcTUf+1GjSU/C0VZj4QD3PQc/wdWeQsDvOQs6tt/xSwu/+47nC11dMSqPoSmesBr0Ub
         8hWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DVhK/YKr4WElDtuMvAwNSdtB9HEoQDarqvlR9ga/S08=;
        b=AeSaTSPa1Pk9vGIVDQKBX9H2eLhAabuwL9/IS+7Kn8T2kVhzDOX19n60U4rijdILkl
         le8ui74BDZknZIcaYm02etv94z1nKVbGoSHE/97O83K0u4DMSJWsZPJl+8usUNwcjVGZ
         DOuhKgZJ9GrnG4y3CRJWeYyzQxu7yaemV/TTntMS+3fa4NY0z++zHRwlvmVgmZD3vI8b
         tzWCAB+R9Kz6yuRNcxtjNW62KL4B9WIkOJIfuNjcEDBxH8KI/IJKykspMe3O0KuLeAc+
         MLKFT0LmV1VuM1fK917xM8emMPctR6XGhgcpTLms8KnAWIC5Ov+dHSw0eWSPYdOSkxt6
         XPIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dPA+Od53;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DVhK/YKr4WElDtuMvAwNSdtB9HEoQDarqvlR9ga/S08=;
        b=EylX5g5QJT2m2Xp+xd1dzmPj2HOIpmONwOZzzyq7XsTEam4x5WwH8+lQqU+PMdK99X
         i1kZeD1xe8o/PzzgikeHVV2FaZfdlkBpAXjGB+orn4faoBZ4U9ws9a/Nro8uw4Z4u8Tx
         Bx8wwZFAbdUzZ93N3oWwyLkhG4mgQO0NBekt8a//COpOJZqhnO54yWoNpdVMRIMry2ID
         QwNgLOLc4dWYtIeyqSvitQk/MgizVhRBXzSYlCgYxA+7npFBor5Vn1tKoRQ1/A07lKln
         dsOatkCXIIpf3YE9wHMla6oTGTv/Ph7yXzJI7UGqlyJLAo7kV4LqlXki27iaMQ4LuAHM
         e95g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DVhK/YKr4WElDtuMvAwNSdtB9HEoQDarqvlR9ga/S08=;
        b=I1OQ+7ZJCHOR0nQ8MbLzjwgl4sVaPbKDTX0uIUKGo7L+4EwRxnHuMv1UkevmegLh6e
         /78GGUhUwYg6vZgqUxMBYQcOHZqMAo5D68BGDhx1AbeRMjIY5Z1Br3dEDFL+sCosB0fr
         d9DWgsHZCz9A/zEiZDpzkxDQCTzYQ/55SCInQmCU4ImgD53O6XwILYiZPTlYaYsur8T8
         d7gJpfs6AzwODWKpsrIP4hKOfHRL1xkYcE83njgGiA6XvLPORoeB8hovL1iQF1b1wrtV
         hEO6N2/AJ4MqJxlPiWZgvc3yw084Jltb6SMKKEBmseahNt6m+W/cgy3SEppcaQIQsUyD
         Hq7A==
X-Gm-Message-State: AOAM532ytATqrU2nBGCDtAoixXgvnoD3GOI8Kdz7ALL6eBPObAths1EQ
	ACvkQ+p/I0Y75tWt9nwR5FM=
X-Google-Smtp-Source: ABdhPJxrRTfQIVbtstw8cnEElYWYequAtHmtFVO+NYD9IlTMrDu7YB09K1okl9gbENQHqBWMat5VJw==
X-Received: by 2002:a05:6512:214c:: with SMTP id s12mr3327879lfr.578.1601575445745;
        Thu, 01 Oct 2020 11:04:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1743294lff.0.gmail; Thu, 01
 Oct 2020 11:04:04 -0700 (PDT)
X-Received: by 2002:ac2:5315:: with SMTP id c21mr2837228lfh.162.1601575444693;
        Thu, 01 Oct 2020 11:04:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575444; cv=none;
        d=google.com; s=arc-20160816;
        b=tKljMa3GJGqJ63ZKYiyOrOzlnK8lzbM6GbDXgtPeJo9t2EdEidx39TLOuBw6mJj9FY
         nsdDaRAi9mwqZbQWKd3sm3sgTwibPv2RHPJzFom2pqiQmOS81XAQQDsP4cLyPvHx+1hn
         jGZaJehQX5YLKfC+RthvBEnN30CZ77UK3cWUSMIlumVC4Q91hh87mRUrzWc9lASU66Cr
         jNcRiFG056WrAXRw9t0pVZiX4FXA1+OMY86LnD8WdylUjw8MTc1fysDncDgMvSORZRFM
         OixF5KXGyXtiN5SfZPdcbzboAhwqgPD5ujppCf6CtsLF6Rxl5EVWhnQmOjtnf4ix9vnq
         vibg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0OdyXaVNiyIQMSnkmN1U5DBWCyVDZmuQfjlNhLtDrKs=;
        b=Nte2nTBjsNyi4vbDeNs9PCLYlZ7ywUuiIPQYDUQ38tryJxKg/nNFsHQoqx1c/+vR21
         uXPt04fOTXAmPYcCfQNbI9JWoPKwzBZq6hv8ezjvwveqchmSwZa+i9l6v/7gmjZvFGR+
         kU/FcAmn3pO7zIrb4zpvwPWqQDrfjeBVoexKIryfeHciwgyLMHWDpZ98HG3oNblxQBg3
         8bAvNVfiw0oWNlzqyl7oSDs3X9w4/FYTS57wScKtucm1xWQjVkOErFTLQCzco/qhNGex
         pjmkiRIadWm0w++cMEIhzZeX3W09p0XH7xEGnyDOk/dG3nbOoTpIUcUK7a/6DnuXKPjN
         KCxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dPA+Od53;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id d1si170734lfa.11.2020.10.01.11.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 11:04:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id o5so6842707wrn.13
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 11:04:04 -0700 (PDT)
X-Received: by 2002:adf:e4cf:: with SMTP id v15mr10259531wrm.174.1601575443811;
        Thu, 01 Oct 2020 11:04:03 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id k6sm950946wmf.30.2020.10.01.11.04.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 11:04:03 -0700 (PDT)
Date: Thu, 1 Oct 2020 20:03:57 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 39/39] kasan: add documentation for hardware tag-based
 mode
Message-ID: <20201001180357.GW4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <b6edb566f7439224c3e235186305bc07de8d27b9.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b6edb566f7439224c3e235186305bc07de8d27b9.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dPA+Od53;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Add documentation for hardware tag-based KASAN mode and also add some
> clarifications for software tag-based mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
> ---
>  Documentation/dev-tools/kasan.rst | 78 ++++++++++++++++++++++---------
>  1 file changed, 57 insertions(+), 21 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index a3030fc6afe5..d2d47c82a7b9 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -5,12 +5,14 @@ Overview
>  --------
>  
>  KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
> -find out-of-bound and use-after-free bugs. KASAN has two modes: generic KASAN
> -(similar to userspace ASan) and software tag-based KASAN (similar to userspace
> -HWASan).
> +find out-of-bound and use-after-free bugs. KASAN has three modes:
> +1. generic KASAN (similar to userspace ASan),
> +2. software tag-based KASAN (similar to userspace HWASan),
> +3. hardware tag-based KASAN (based on hardware memory tagging).
>  
> -KASAN uses compile-time instrumentation to insert validity checks before every
> -memory access, and therefore requires a compiler version that supports that.
> +Software KASAN modes (1 and 2) use compile-time instrumentation to insert
> +validity checks before every memory access, and therefore require a compiler
> +version that supports that.
>  
>  Generic KASAN is supported in both GCC and Clang. With GCC it requires version
>  8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
> @@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
>  Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
>  
>  Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
> -riscv architectures, and tag-based KASAN is supported only for arm64.
> +riscv architectures, and tag-based KASAN modes are supported only for arm64.
>  
>  Usage
>  -----
> @@ -28,14 +30,16 @@ To enable KASAN configure kernel with::
>  
>  	  CONFIG_KASAN = y
>  
> -and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN) and
> -CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN).
> +and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
> +CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
> +CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
>  
> -You also need to choose between CONFIG_KASAN_OUTLINE and CONFIG_KASAN_INLINE.
> -Outline and inline are compiler instrumentation types. The former produces
> -smaller binary while the latter is 1.1 - 2 times faster.
> +For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
> +CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
> +The former produces smaller binary while the latter is 1.1 - 2 times faster.
>  
> -Both KASAN modes work with both SLUB and SLAB memory allocators.
> +Both software KASAN modes work with both SLUB and SLAB memory allocators,
> +hardware tag-based KASAN currently only support SLUB.
>  For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
>  
>  To augment reports with last allocation and freeing stack of the physical page,
> @@ -196,17 +200,24 @@ and the second to last.
>  Software tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>  
> -Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
> -store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
> -uses shadow memory to store memory tags associated with each 16-byte memory
> +Software tag-based KASAN requires software memory tagging support in the form
> +of HWASan-like compiler instrumentation (see HWASan documentation for details).
> +
> +Software tag-based KASAN is currently only implemented for arm64 architecture.
> +
> +Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
> +to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
> +it uses shadow memory to store memory tags associated with each 16-byte memory
>  cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
>  
> -On each memory allocation tag-based KASAN generates a random tag, tags the
> -allocated memory with this tag, and embeds this tag into the returned pointer.
> +On each memory allocation software tag-based KASAN generates a random tag, tags
> +the allocated memory with this tag, and embeds this tag into the returned
> +pointer.
> +
>  Software tag-based KASAN uses compile-time instrumentation to insert checks
>  before each memory access. These checks make sure that tag of the memory that
>  is being accessed is equal to tag of the pointer that is used to access this
> -memory. In case of a tag mismatch tag-based KASAN prints a bug report.
> +memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
>  
>  Software tag-based KASAN also has two instrumentation modes (outline, that
>  emits callbacks to check memory accesses; and inline, that performs the shadow
> @@ -215,9 +226,34 @@ simply printed from the function that performs the access check. With inline
>  instrumentation a brk instruction is emitted by the compiler, and a dedicated
>  brk handler is used to print bug reports.
>  
> -A potential expansion of this mode is a hardware tag-based mode, which would
> -use hardware memory tagging support instead of compiler instrumentation and
> -manual shadow memory manipulation.
> +Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> +pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
> +reserved to tag freed memory regions.
> +
> +Software tag-based KASAN currently only supports tagging of slab memory.
> +
> +Hardware tag-based KASAN
> +~~~~~~~~~~~~~~~~~~~~~~~~
> +
> +Hardware tag-based KASAN is similar to the software mode in concept, but uses
> +hardware memory tagging support instead of compiler instrumentation and
> +shadow memory.
> +
> +Hardware tag-based KASAN is currently only implemented for arm64 architecture
> +and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
> +Instruction Set Architecture, and Top Byte Ignore (TBI).
> +
> +Special arm64 instructions are used to assign memory tags for each allocation.
> +Same tags are assigned to pointers to those allocations. On every memory
> +access, hardware makes sure that tag of the memory that is being accessed is
> +equal to tag of the pointer that is used to access this memory. In case of a
> +tag mismatch a fault is generated and a report is printed.
> +
> +Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> +pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
> +reserved to tag freed memory regions.
> +
> +Hardware tag-based KASAN currently only supports tagging of slab memory.
>  
>  What memory accesses are sanitised by KASAN?
>  --------------------------------------------
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001180357.GW4162920%40elver.google.com.
