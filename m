Return-Path: <kasan-dev+bncBCMIZB7QWENRBRWVXHBQMGQEMHI277I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 46689AFE9BF
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 15:12:40 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-3139c0001b5sf4873329a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 06:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752066758; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z/3Ag6iMP+bEeUdtfmNYl3hhSZrvbH3oEvSre3hbsOjhDaRKLMuvOimEaYrIDYZHZi
         IkdHo6JksNzzn3S9C/J0gfF0+/3fbR6xweWGDDrYpQQB36Lc3gnolkd95aflShIpGegA
         urxZrUVooqdFOMsbzG8Jcq5uZCb6YLiEF9S+Gxfqqf18cYTR4WztZnqIGxh1H+92Te4L
         N4JnA8lkl1cvM7rO1pPFJ8aqnZv0tQOTzc4fWhjWQ2gPpKNnseozREggifzUsL2Xm3yN
         CVJjGu6ktFViKIQosSmoI1U/txZWaTsXyefVtyjVScSon3NrucgB8+AMIyV9qj8U267o
         39+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x3l1VNBIJNfWAZMhrrVVyJiCusd13hph/2Hq23KHTLQ=;
        fh=GjLgILTIA+w1sFRLH/tFCW1xd3jUZJUIm8VJxJRSkdc=;
        b=cWCD8TpenDcLywfqiy56Kth+pnMAoTox7u6Hmp98YQ7B+T6x1a6X+HtkI+T/33sbMw
         +dVyhSnLLAtQj2cT2F4yrwxAmCZz0EzPrYcbGLuIuLGOxpFYAEzJwXI8UYkO6S9O7tce
         hpzwhvwUk6S155RNVi7yBRtXQaZdiYIJzpZUbPY3xjjgtrJJ/V/0tNTyM/J9ZWkzsTQb
         hrBYcn4HrVLgTEM4ohu9o+mne41TSZUobPgga1uAKGFuFl88g5gLrIWmCZaeeHsDwUz+
         7mnRbS43WiSg4D3wbkdP/E/aCgRiyNIfIUAksZsmtVxPx6FVQzLkZUV3enlOy/xYFLoz
         Oqtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xE94S6pw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752066758; x=1752671558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x3l1VNBIJNfWAZMhrrVVyJiCusd13hph/2Hq23KHTLQ=;
        b=jHQWlA3vLtRDPuZy3NQm20h/CDUrpwpDDPny6Zk/g2ltfIYdzePJSdAu69Ayha1xjU
         zEOwBVhdBHYFW4Jbo5S4DKKH8ypbfIPlT3DKPf9kTUcJI7NGJBXFoH3dqNDT6FWWCc6A
         Wf0vEEcgidGMapaYECY7wuepFMVFpaPuqG3oCi7O89a8etCO6/SncG8aaL+L1apS0Uxa
         KNYftAmR29Eg7czmyk5oV5QPAuHtI85y61siBSAPoHi9/GRKZYwNnMicWgWyGnEY4Ur1
         QhzdcVU376e53gtjDPOCbgfXZC0Uv/SdXxopIZWblbAYmYjb7dp0XtY7+3pZ31eMcfld
         oHkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752066758; x=1752671558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x3l1VNBIJNfWAZMhrrVVyJiCusd13hph/2Hq23KHTLQ=;
        b=cOrOYSY0Z8j8MeBjSsXMvDhS57pZHbBtMZvNEEUof0XNY/KqOQnihzQP7tqxj0/Ek7
         LfECAVDS2Oq2/sNa76CJt90Fbpp28kaTq9DNqYDhVFHguC9MGcT6M+WT1GNZL0y/bfAC
         fiMWvMtlbkv14pnBSWbrD1OWIRpgQlVld1xnh2MsioWGFT4zMLt46TpaGf6WLQIn7N3i
         vSCMbupQtq+S2J51O+EHmH4GnUDYDXix62wZhigQjLnl9Q9qSdK356YKi5HslgJMDOej
         zBQTPQr/Lnc3NUOlQbwaedhqlWHbqXFsXDDcOeDwg3l6h7HsfMuJfWcnkDyxUj6ofG0U
         qzwA==
X-Forwarded-Encrypted: i=2; AJvYcCXUZPdnaWvO/K5NwrXNLWqGMNVNp57vRDSnSfNKwcJDkkmCiZEZLdb9I4i87e8yvSvQm0pS4A==@lfdr.de
X-Gm-Message-State: AOJu0YypBeYQ3EgoKkCwc1Y+HrtSXGK15Y6u60o+0tC0yTLeajXS/+5q
	yYxjiMDADg4lJgx5C9rs9PEEadFZ4TQLxdJ1Erq9u3vOfDlJQvHISjP6
X-Google-Smtp-Source: AGHT+IEsbAGaIrF8sN902v5gA2NnOoHyY4kwdpEu53qZsDxDBhfSSL6CP0ymJ0zYZJTd3X8u8y8s7w==
X-Received: by 2002:a17:90b:3dc4:b0:313:2754:5910 with SMTP id 98e67ed59e1d1-31c2fcf80ffmr4303285a91.15.1752066758400;
        Wed, 09 Jul 2025 06:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc0s47TWazSCVUk5q8NMPvSGiCmrN06dOfNv1zF3ooBOg==
Received: by 2002:a17:90b:50c3:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-31ab03359cfls4750442a91.1.-pod-prod-05-us; Wed, 09 Jul 2025
 06:12:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj1bdu7WrmWfaJRr9nSEqsjZfwsGAA34We6sV+syJSbgkZEnEWxh8hiLaA9IujXX9giLDmCP//YT0=@googlegroups.com
X-Received: by 2002:a17:90b:4f8c:b0:311:b0ec:135f with SMTP id 98e67ed59e1d1-31c2fdff74fmr3795996a91.30.1752066757131;
        Wed, 09 Jul 2025 06:12:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752066757; cv=none;
        d=google.com; s=arc-20240605;
        b=S6jJvd7Kmd5oTUvqqb7CO5At7gmWSdquesh/wH7FtFR9ReFOYqCdVKt8PpEy4BkBqL
         zgwyRXRrMc29lh/O3hH7/aGcAM4+TpizwVMpFmtW48wgtxdFrzEkCG0tVvV44LWfZJz+
         32/im7+qzTzGg2KjnGXN/A6lzyun5sh1ZRNuv+sVOtJ7JnYVHyLgZ81vzG3RWiZjpWTw
         EElm3RBjfOJzTfHbCkGngpMs773tRlSeZWDGSrqe0vGV7ft3pTRf+2I+l42WrD/ULh9s
         hPDL3+EURN8V3OxgvJcwKY3UtlSOtu7e3PusjHC/rB72yG4O4PRqhin0rvekQqVx4alX
         vcRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fL+pY6fWp85rYXFbZMcl5dcJ/9fsmg9O8nAr0THFasw=;
        fh=SrdHPjEK8DxbTXu1NHxb0uzX156e8dU+OxNhHkKxDDs=;
        b=Ew80ZKGuro4prcHQ5EG49dOmk9zbSzR9fSWtUwzJa1gyJh7tysqaaACZ/zMWmLXAiP
         8QkRlmSUGkq83Lm+R0mUtcPDwGzPNiKU0xT5hd9sKXxXBEdPJ9EQZypHjP07sfJdr1N/
         Km9IFtkPPgI0QtRaSx3tZ4UHRQH2lFd4X5wYCoCRAllHJUN+KI07vKfp/LIcWgC26TVc
         rHHZFlyyFKjTiTd3M6wu9pa0/70bZ62wTneLoLMZpW6wErLif0Xi704MRhwrTrQkRXRt
         05SeK3ME8fHcBmLAAdbJlMYA2wif+j41xKohbU6vGJASXH/l0UfRLmCzHLROneWjijQA
         O5Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xE94S6pw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c2feddc8csi71083a91.0.2025.07.09.06.12.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 06:12:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id ca18e2360f4ac-86d013c5e79so445414639f.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 06:12:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgFwdxoATCZJXRrnb7appga1d2hex7vsMGzTatVBDBm4ou0BxYZQ9UYOwwGehWelw5JVGt2zuEYA0=@googlegroups.com
X-Gm-Gg: ASbGncu123MckdG115pGrdWiUQ41K6/DytQ0a+26rAWrbHNGOp1i1aEUPo6yzWPYCa8
	q6Wfq0T172dNFOSoElktw1wis4bnnSRf6MFCIcKp53XTpDF4ouSWvveRipJUge+AFk1hpev8Qfl
	8groVbm2sWh7Bhm9HjwTK1aggPyZcs3rv1gJG2ue/Ehoo9MVPA/aweKdTtxYokF33GahSt6wrIu
	FOG1snWp5pobtE=
X-Received: by 2002:a05:6602:4a0e:b0:861:d8ca:3587 with SMTP id
 ca18e2360f4ac-8795b0fa8d5mr306086339f.4.1752066756235; Wed, 09 Jul 2025
 06:12:36 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-4-glider@google.com>
In-Reply-To: <20250626134158.3385080-4-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 15:12:22 +0200
X-Gm-Features: Ac12FXz8IWecUDpLj5NTCC5KnNHKtX0iPWuNoUP_LzOkkm3xhcQGIGzEOXtSrOI
Message-ID: <CACT4Y+Z=G0PBvMk=5MgLAC3LjKOHvCpMqtnw6PLey3SxeUa5gQ@mail.gmail.com>
Subject: Re: [PATCH v2 03/11] kcov: elaborate on using the shared buffer
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xE94S6pw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d33
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
>
> Add a paragraph about the shared buffer usage to kcov.rst.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: Ia47ef7c3fcc74789fe57a6e1d93e29a42dbc0a97
> ---
>  Documentation/dev-tools/kcov.rst | 55 ++++++++++++++++++++++++++++++++
>  1 file changed, 55 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6611434e2dd24..abf3ad2e784e8 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -137,6 +137,61 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
>  processes only need to enable coverage (it gets disabled automatically when
>  a thread exits).
>
> +Shared buffer for coverage collection
> +-------------------------------------
> +KCOV employs a shared memory buffer as a central mechanism for efficient and
> +direct transfer of code coverage information between the kernel and userspace
> +applications.
> +
> +Calling ``ioctl(fd, KCOV_INIT_TRACE, size)`` initializes coverage collection for
> +the current thread associated with the file descriptor ``fd``. The buffer
> +allocated will hold ``size`` unsigned long values, as interpreted by the kernel.
> +Notably, even in a 32-bit userspace program on a 64-bit kernel, each entry will
> +occupy 64 bits.
> +
> +Following initialization, the actual shared memory buffer is created using::
> +
> +    mmap(NULL, size * sizeof(unsigned long), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
> +
> +The size of this memory mapping, calculated as ``size * sizeof(unsigned long)``,
> +must be a multiple of ``PAGE_SIZE``.
> +
> +This buffer is then shared between the kernel and the userspace. The first
> +element of the buffer contains the number of PCs stored in it.
> +Both the userspace and the kernel may write to the shared buffer, so to avoid
> +race conditions each userspace thread should only update its own buffer.
> +
> +Normally the shared buffer is used as follows::
> +
> +              Userspace                                         Kernel
> +    -----------------------------------------+-------------------------------------------
> +    ioctl(fd, KCOV_INIT_TRACE, size)         |
> +                                             |    Initialize coverage for current thread
> +    mmap(..., MAP_SHARED, fd, 0)             |
> +                                             |    Allocate the buffer, initialize it
> +                                             |    with zeroes
> +    ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)    |
> +                                             |    Enable PC collection for current thread
> +                                             |    starting at buffer[1] (KCOV_ENABLE will
> +                                             |    already write some coverage)
> +    Atomically write 0 to buffer[0] to       |
> +    reset the coverage                       |
> +                                             |
> +    Execute some syscall(s)                  |
> +                                             |    Write new coverage starting at
> +                                             |    buffer[1]
> +    Atomically read buffer[0] to get the     |
> +    total coverage size at this point in     |
> +    time                                     |
> +                                             |
> +    ioctl(fd, KCOV_DISABLE, 0)               |
> +                                             |    Write some more coverage for ioctl(),
> +                                             |    then disable PC collection for current
> +                                             |    thread
> +    Safely read and process the coverage     |
> +    up to the buffer[0] value saved above    |
> +
> +
>  Comparison operands collection
>  ------------------------------

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%3DG0PBvMk%3D5MgLAC3LjKOHvCpMqtnw6PLey3SxeUa5gQ%40mail.gmail.com.
