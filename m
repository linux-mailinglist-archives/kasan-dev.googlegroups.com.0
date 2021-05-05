Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFKZOCAMGQEDHZOIAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id B09DE374375
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:25:29 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id k9-20020a63d1090000b029021091ebb84csf1111777pgg.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:25:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235528; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBKAytR/WEEsIA0iGtd1NaPGE0zPyTKGJTTqkGpUfL4O2y7TM6I1VkZuHhnYLvJ/fX
         ggUZ0H1Y7MOVYRKLA0OY6oVTzy4kHdbdfvFMVUEkRz/byhD6zYcWPhE/UPU0uPIbrBSl
         xpGrl8wvSY2FBhbCVHe3kU0jW4GM0M6OkGdTBiw+wTYh4vzaT3fn3+kZOCVZ7KX2IMc8
         GoDDGlkOTE/J0qdalatA2x1h+RInzMe6emBj1UmFknPAEOoh2Zt5ciGOvBJuncKpvtnP
         cnGGZquGcK4/NpGwIM2Se4H3j7zBv7lvz0frd7dE7/3VMUEMuZvLkbkFAWRirwKmNXwb
         siEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yM6llnubxAU+4u6YKbQQjB5y/02l0gutHy3VGgT1JyU=;
        b=s41xVsze7zliggttS2rF0BjqL1WQB8Je7CJ31YidACpRhPy6/7VZTMOl3KV3Hr4sz+
         sxIlL+ZmkyIqviBx3IlgcVjf9M4gQWW0pfKO/gBXb0lR/pAwDFpFX8IUbhES/El4NF+v
         jMumE+1GgOVMNpw2Ir8Bd6CW/yKlBL5nZPSwO3nIG+kPE2Q6ia6tUVPBTACDU0GfP0QC
         weqQH68tlbUusRGBN6D/hdLmASmEBAdmIPjMX7tnO81uMYDahANjqVOPXuAN9HGXZWsp
         xTaovD7CUnuJRzoOcqk0OoITzG9DD+JEELp2SzZ4dVd7FWF6nSJYBOl9xyOO1tDN/4Lp
         UiOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=liHtDy4G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yM6llnubxAU+4u6YKbQQjB5y/02l0gutHy3VGgT1JyU=;
        b=BgorBXHguPk4y69rki26AxXuzhL/CmTPu1Q/z/qlumJktF1JC0NOa9DSHshF4M20GO
         berEKvG4qn4a1adthrnZMiruBxINNGf5Ok1Qz+G8mlp53d5xqXlQaaqm7TAqOir5qbLv
         wXQcn/AO8A7So1GYNHqH3nJNa65P/9Np2eQ9QgO/QBj1EV4Umpldbn/kdKlfdYtXIdlh
         Xqh0dRIdjScfQKinSbIlocXV5tmaNM8rdKVAeg4w46jiCIQnUh/iYArVDVzvUOdfJv+V
         wmSCSgQRR/cndFEXeWocmV5jkJvPH8efGeIOQyW40bAGp4Z9hO9R5J7XaM854HrYamR8
         vjEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yM6llnubxAU+4u6YKbQQjB5y/02l0gutHy3VGgT1JyU=;
        b=jlZCdn5eA4qz0QP0L0Ek4n9YSONP34ckTk78PmBUP7yn6zY1YAKhUFPPUrQfv33dC7
         TxkaY806hfLxn5GwpB6kse6BqC1vuKyTxepbZuSpdOOJsk6afs/cM/1rmLh8ZpmXaZ1I
         84Za/R7RkFfjvnAM1fS027o9WX+bKRNYxEJuOY9L3Yjv4+CbrXMtNoWDdHrEDtjCWI0g
         pQfVVR4sqceIdI48uIcHpu3iz+X525Y7npWL+5ZIi0ct9hKvkHL/UmzwFCNSDTXlM7Bu
         ce0G++pcVrsIa6SYlk+IspUr953fYw9TF6fzi12+HBXsIve9ritHBUpgP4wX9EPCr3kJ
         jFHQ==
X-Gm-Message-State: AOAM5319MMhwQCf0yyfHaZM0IEVSRiRPTATLe2ZGKatAVuXoasO29/Ba
	0rX1qtwFvGqqw0otfNti0G8=
X-Google-Smtp-Source: ABdhPJxd/6AHwf7K+rJr9ceKo1r+Ny8LzgNNZQkNCUzIVJGVRDFTRsj5U5GAgp60otAG6TwGkYC6IA==
X-Received: by 2002:a17:90a:6385:: with SMTP id f5mr12597195pjj.212.1620235528374;
        Wed, 05 May 2021 10:25:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9255:: with SMTP id 21ls8259151pfp.2.gmail; Wed, 05 May
 2021 10:25:27 -0700 (PDT)
X-Received: by 2002:a63:34c:: with SMTP id 73mr29385728pgd.431.1620235527769;
        Wed, 05 May 2021 10:25:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235527; cv=none;
        d=google.com; s=arc-20160816;
        b=I78PgMYnt/6Qbla7goHJeIHxGEeGKm0Azr6L6yZJpiKjV6nGEshvfi9jIbSsVqj7fc
         0rJizxQ4+BSqhixKm6LoJ6ilSFB1AoetqEO4a/CX9J6kBr7lFSl9uVLGl/k0u6Yhdp7W
         UEoZxPJ8LfbFSf19+MxjOrV6HlGtRmZ0pAhzT/8qDQilagFU1/dFZM8r2af3hZnvoqdn
         +PdFse/hPrl8xxAtzAjzuHnFqorZfQl9YDhU12505L68pts+BtyrsZJ19ot3UXDjPGH1
         JgvnLfCipn8GEDcbkX4TbGjaj71VrLweD1ERnN/WSgH3dZbg66vFgZFllX0tLPRDq5pT
         a6kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sVTxixNEQgaMU45bwkqw/v+zgKxhFXtlznyvyelbh00=;
        b=k/V/2QfV8a10BZ7AuLsPGQF/h2fc9V1x/jmsdEBsdmASFHlGdsWEdph3N8LsZ8Mdmf
         YdsTxdyZTsgdzb79iOKWqd182qmYYvee7PpA0f7/1R6U9pclxqn9LQRdKgM8xpgwrRlS
         rtERP4x7HFQU2PIshqCVJ3y3P6AvEjB/bj5jwDhB5wJHq9bUWprXNOy9bz/wHZlzO8bS
         mGw471GiZ/kiJudpIWMa/m90PxH9PteUCiMx/rWtwTw93F/0VRrnxrUnURlxJC8kj7Nb
         NTAShrCe1cU7CemIuJINwjsVmXEax5thUMYlSUQETNppCLlvPagDGsMr3mLLusm9Qm+z
         +LcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=liHtDy4G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id md7si751425pjb.3.2021.05.05.10.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:25:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id v24so2862924oiv.9
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:25:27 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr22157199oif.121.1620235527302;
 Wed, 05 May 2021 10:25:27 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-8-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-8-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:25:00 +0200
Message-ID: <CANpmjNMhMvKePmEutfd6U0wnd-bvktEQwR-=O6efxe6RM9A_4w@mail.gmail.com>
Subject: Re: [PATCH v3 08/12] signal: Remove __ARCH_SI_TRAPNO
To: "Eric W. Beiderman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=liHtDy4G;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Now that this define is no longer used remove it from the kernel.
>
> v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>



> ---
>  arch/alpha/include/uapi/asm/siginfo.h | 2 --
>  arch/mips/include/uapi/asm/siginfo.h  | 2 --
>  arch/sparc/include/uapi/asm/siginfo.h | 3 ---
>  3 files changed, 7 deletions(-)
>
> diff --git a/arch/alpha/include/uapi/asm/siginfo.h b/arch/alpha/include/uapi/asm/siginfo.h
> index 6e1a2af2f962..e08eae88182b 100644
> --- a/arch/alpha/include/uapi/asm/siginfo.h
> +++ b/arch/alpha/include/uapi/asm/siginfo.h
> @@ -2,8 +2,6 @@
>  #ifndef _ALPHA_SIGINFO_H
>  #define _ALPHA_SIGINFO_H
>
> -#define __ARCH_SI_TRAPNO
> -
>  #include <asm-generic/siginfo.h>
>
>  #endif
> diff --git a/arch/mips/include/uapi/asm/siginfo.h b/arch/mips/include/uapi/asm/siginfo.h
> index c34c7eef0a1c..8cb8bd061a68 100644
> --- a/arch/mips/include/uapi/asm/siginfo.h
> +++ b/arch/mips/include/uapi/asm/siginfo.h
> @@ -10,9 +10,7 @@
>  #ifndef _UAPI_ASM_SIGINFO_H
>  #define _UAPI_ASM_SIGINFO_H
>
> -
>  #define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(long) + 2*sizeof(int))
> -#undef __ARCH_SI_TRAPNO /* exception code needs to fill this ...  */
>
>  #define __ARCH_HAS_SWAPPED_SIGINFO
>
> diff --git a/arch/sparc/include/uapi/asm/siginfo.h b/arch/sparc/include/uapi/asm/siginfo.h
> index 68bdde4c2a2e..0e7c27522aed 100644
> --- a/arch/sparc/include/uapi/asm/siginfo.h
> +++ b/arch/sparc/include/uapi/asm/siginfo.h
> @@ -8,9 +8,6 @@
>
>  #endif /* defined(__sparc__) && defined(__arch64__) */
>
> -
> -#define __ARCH_SI_TRAPNO
> -
>  #include <asm-generic/siginfo.h>
>
>
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMhMvKePmEutfd6U0wnd-bvktEQwR-%3DO6efxe6RM9A_4w%40mail.gmail.com.
