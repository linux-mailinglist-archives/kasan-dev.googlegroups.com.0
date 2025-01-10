Return-Path: <kasan-dev+bncBCMIZB7QWENRBKM7QS6AMGQEOQTEBUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 611B8A09015
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 13:16:43 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43628594d34sf10969065e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 04:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736511403; cv=pass;
        d=google.com; s=arc-20240605;
        b=GovnfTMJ1VuteKh1BzOWiW1hQ9dV2G2NlCym8Xk9bF/20sC36BteD1RfTLLzJclfDB
         Oy0LF1PZVM046eZA7bkBUmprzgM+hSoKw2reDyYist+5X6pC/fvQIPVvOfrAH8f/dCTW
         ezHBU1QgLDMTGZW0UxjPBxnPWo5F6qiXXNBPjknFmNJQiruRfcd8jp8Qnip6BxWhKZal
         bmJysZw68O5f+NU0t3EzeWRAJBi4xz03NVRHtQ3cviqIIRKVootqBlrjX5evUPLwxpMg
         9BDC5f/act2Up0tzhvFsZh3Lz3u242c0y/nyMrQFDX/JdbDO9U5/s1CB68bqBVofd1Xi
         Mpqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7xxKUQq+YcwHZrJ65VZ93FJ2nWeN+XaX18tykd//CI4=;
        fh=hfDHsPUIrMTbBZxpA/SvxZKc7fDZ+qMZRchryHu4Wpg=;
        b=c/qlOvYnDJPiqEiQ/1llKVXYAt3ahKwId1ewrk656YduQ3JPs3soGPqNi1LeQumyP/
         hZ1sdF9904Xj6Y5Rjq7/32jzRdY1TDEo0fMMmKAfK/lTICRSOlO48xYaQNSvaiegO39o
         WrxU9mqLUKjvwpSFPcUp22GMpRrRKAMBBqyHOO1NE4dJwaQJDl8+qPB5iZQdKYjLwRq+
         GGWrB9+cbADgZixyGxFXP2k50IZ35O9owsHLQfxLzFXVO+10VNudpjaTrYfkkI0DHEFW
         JgWOlFZZJxtr1pYo2ljOaKjVXDuG6GcTbYHqDe+O8L9T+hdtegN/ZJqeileL9TFrmEkP
         1cIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zlkHu5kU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736511403; x=1737116203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7xxKUQq+YcwHZrJ65VZ93FJ2nWeN+XaX18tykd//CI4=;
        b=YCZJ5WtJSUAtMJPGFm6baDB20nm8hfUBHAMCCq59UK+2nPBhbAvNa1Mcn8OAfEnTcr
         n+g8diRK4GiiyCM8tLpSeAgUXcpXr+pNmOF0vJh59LF+OUQgO6dQtYwW/QYgbVBZPjsC
         9QkAoyRL4S91VdZDoiuLNXyB7bogc2wwXgRiFsjnWiYM7jX7B+J2kvFEaRSedeRsaRLw
         hMctk0Q/oSeoPiCz+LMAUnaSytI5gB8Z0yu0NzfhQOZwbibhoHznTE+sSVuDUWRRUlyp
         QA+SzTEaa8iUOhmqVNapEL3az/18vZURbVrctP7JJDCruV7GqET0xbZvzjoHoCmcqgnj
         5VFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736511403; x=1737116203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7xxKUQq+YcwHZrJ65VZ93FJ2nWeN+XaX18tykd//CI4=;
        b=CWmUDGmB1iBmR5xqF1ttFJ1LOe5tcjbxutF2QygVyNNgBZ49Cg3tPTs5E+/yuuRaO7
         Yv1BfatrQ3In/apA+/MwMjprL69qiu22k5NzEzaYqeR8MeHGaRyUxrajQ/3eEE5JA20g
         b73t2JRkok0/64aK+cPUlr0svvPXCXL40c32YEmNuDvsRJAJTDkzy47owKUcaridKpEm
         M8KqS4RDgDWdh71kro1Y+McA46UNZXGxGeHQXqQ+jXZnL38MrlD9FGVldyfzELOARTaN
         ntkL5/z2wKgOkrLpjVkyhVdjVQKfSGtWbX7BTokaru+npTDuiGqpPNqHWcJST1YUNDJS
         rzPw==
X-Forwarded-Encrypted: i=2; AJvYcCV9/EBY9dbr+typIKfud8fDx+ZDeKpephEEAUYZTIoJccydsPTUt1UmiCV4omsi+783Vw+7SA==@lfdr.de
X-Gm-Message-State: AOJu0YwZrBVL0QKuO/mH/CnifxdyDNmRgZFOAecrqFsEt/FuQq78KQTn
	uVh6w1LS02J2e+aFWuAt2LqSTyqnSjWNvNsubr79YJxElEIZIdvG
X-Google-Smtp-Source: AGHT+IF5LTTtEeAEV3pGgmTn+KlweJvrxJNsTWMTg0Qujqzv4hm2AAbSDnXvqBauyw7l5ByBM6gN6g==
X-Received: by 2002:a05:600c:808:b0:436:488f:4f3 with SMTP id 5b1f17b1804b1-436e26a1b3dmr103319655e9.17.1736511401716;
        Fri, 10 Jan 2025 04:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fcd:b0:434:aa6f:2428 with SMTP id
 5b1f17b1804b1-436e87eccd4ls10711785e9.0.-pod-prod-04-eu; Fri, 10 Jan 2025
 04:16:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUn9Ni/E2gzru8wntRff/GtYY9bzAl4hi1kI8yOjXb0NfJmKpH5rbpwCsF1hIaOKHOgMmFV+XHM7ZU=@googlegroups.com
X-Received: by 2002:a05:600c:3aca:b0:434:f335:855 with SMTP id 5b1f17b1804b1-436e26eb428mr77498355e9.28.1736511399388;
        Fri, 10 Jan 2025 04:16:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736511399; cv=none;
        d=google.com; s=arc-20240605;
        b=aYZ+9aWDZ3n9r+m3nvVpThfij0b2HfT+1M83zUxNGy1DeCECcTw7HB3b/ehHMngDRi
         TYX0idZIf7Ylpjui7OhKSXix68l4xWw7Ipsg0RJP8T1nyvLQDiaEuIVgDMPo0nXJ8Kll
         uN+vvjiRc1wZXLOE20mU+5b1OHKih1PDDv1scDs3A3wgpIciYWW0ivjDub+fupZ50v31
         jkBXt3BPtjaCgc5WVgWLKHdempGj132gWQ0ACWpFKfX8LNvADOiyqjNgTz8t6snOMdf0
         lQjOJldmH9ITB2sGtZIoSab/D8/1VtB71H8Az2MUUZyasikKGbP/l5hWvNGJMQry0Umi
         11+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dx6LfbWoOZVo4WZlNr29Yr02kRZ3p+X0xl0ciBlTxio=;
        fh=PF9zNWnoDOY77ySnzXfGNdXDN4sN3isdJonWP2gJGA8=;
        b=erpT+UkRKPtHAArwxEu5wsvNFSr+XCrvGh7oxaltFm7AW3QfzR0w32IsECVj0ZGzql
         kilHEh2y7hv1vsiMOUIRIXHrKFTPLGwVAVV0Qob5al+sNWg9o4dsi8+U6IAdTNvUP//2
         m9gt8mz3ZTvMQ5EdITl2ARbP84Otdkm7kq0cK+9dDwX+PSlalL7MRUzLbwDKCCVSHJu4
         trQ3mPMW209V+95PExLeD2Ips3j3kzEIhkipKAHcvNwcj5+nYQtDM2rUgfP5aN2IcaqE
         Dh7q/ceq3wGa3B6xq5BqAqc5DSWEJsEPUEJ7h1x4telZBIzIqj/HE0Ra62pzYkRwU1IM
         d01w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zlkHu5kU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-436dd15bc91si3802475e9.1.2025.01.10.04.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2025 04:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-3022c6155edso15625461fa.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2025 04:16:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVCgBzcrJ1hMJRjRXUXZYJFOowM9XEblQ2+jD1gbcvNETqznVSxWgW0w9g2SUkWRTfatP4nNOy3mEM=@googlegroups.com
X-Gm-Gg: ASbGncvnMMQV3m/UpHrL11ZFPfU3zhuu8BoU4nfOF0E8o4TXAUYv7MhJ0GGEp/ubVh+
	WIsjEfR4aXBFIlLMIWDFfIBXIKEAcGd2zZLg65t4QHztJHrBy9E/TmpfAPKKU++nDaBw5rx8=
X-Received: by 2002:a05:651c:19a6:b0:300:2464:c0c2 with SMTP id
 38308e7fff4ca-305f453158amr29422851fa.8.1736511398361; Fri, 10 Jan 2025
 04:16:38 -0800 (PST)
MIME-Version: 1.0
References: <20250110073056.2594638-1-quic_jiangenj@quicinc.com> <CANpmjNOg9=WbFpJQFQBOo1z_KuV7DKQTZB7=GfiYyvoam5Dm=w@mail.gmail.com>
In-Reply-To: <CANpmjNOg9=WbFpJQFQBOo1z_KuV7DKQTZB7=GfiYyvoam5Dm=w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jan 2025 13:16:27 +0100
X-Gm-Features: AbW1kvYg6Yj75R_YQTMDFKYPIK4IFfqRlUkZXLVrw7rnxTU_BdbrBR450FQtMuY
Message-ID: <CACT4Y+Zm5Vz1LL7m_BubwV=bMPgVjOVNpp12nDZRi5oesH47WA@mail.gmail.com>
Subject: Re: [PATCH] kcov: add unique cover, edge, and cmp modes
To: Marco Elver <elver@google.com>
Cc: Joey Jiao <quic_jiangenj@quicinc.com>, andreyknvl@gmail.com, corbet@lwn.net, 
	akpm@linux-foundation.org, gregkh@linuxfoundation.org, nogikh@google.com, 
	pierre.gondois@arm.com, cmllamas@google.com, quic_zijuhu@quicinc.com, 
	richard.weiyang@gmail.com, tglx@linutronix.de, arnd@arndb.de, 
	catalin.marinas@arm.com, will@kernel.org, dennis@kernel.org, tj@kernel.org, 
	cl@linux.com, ruanjinjie@huawei.com, colyli@suse.de, 
	andriy.shevchenko@linux.intel.com, kernel@quicinc.com, 
	quic_likaid@quicinc.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zlkHu5kU;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c
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

On Fri, 10 Jan 2025 at 10:23, Marco Elver <elver@google.com> wrote:
> > From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
> >
> > The current design of KCOV risks frequent buffer overflows. To mitigate
> > this, new modes are introduced: KCOV_TRACE_UNIQ_PC, KCOV_TRACE_UNIQ_EDGE,
> > and KCOV_TRACE_UNIQ_CMP. These modes allow for the recording of unique
> > PCs, edges, and comparison operands (CMP).
>
> There ought to be a cover letter explaining the motivation for this,
> and explaining why the new modes would help. Ultimately, what are you
> using KCOV for where you encountered this problem?
>
> > Key changes include:
> > - KCOV_TRACE_UNIQ_[PC|EDGE] can be used together to replace KCOV_TRACE_PC.
> > - KCOV_TRACE_UNIQ_CMP can be used to replace KCOV_TRACE_CMP mode.
> > - Introduction of hashmaps to store unique coverage data.
> > - Pre-allocated entries in kcov_map_init during KCOV_INIT_TRACE to avoid
> >   performance issues with kmalloc.
> > - New structs and functions for managing memory and unique coverage data.
> > - Example program demonstrating the usage of the new modes.
>
> This should be a patch series, carefully splitting each change into a
> separate patch.
> https://docs.kernel.org/process/submitting-patches.html#split-changes
>
> > With the new hashmap and pre-alloced memory pool added, cover size can't
> > be set to higher value like 1MB in KCOV_TRACE_PC or KCOV_TRACE_CMP modes
> > in 2GB device with 8 procs, otherwise it causes frequent oom.
> >
> > For KCOV_TRACE_UNIQ_[PC|EDGE|CMP] modes, smaller cover size like 8KB can
> > be used.
> >
> > Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
>
> As-is it's hard to review, and the motivation is unclear. A lot of
> code was moved and changed, and reviewers need to understand why that
> was done besides your brief explanation above.
>
> Generally, KCOV has very tricky constraints, due to being callable
> from any context, including NMI. This means adding new dependencies
> need to be carefully reviewed. For one, we can see this in genalloc's
> header:
>
> > * The lockless operation only works if there is enough memory
> > * available.  If new memory is added to the pool a lock has to be
> > * still taken.  So any user relying on locklessness has to ensure
> > * that sufficient memory is preallocated.
> > *
> > * The basic atomic operation of this allocator is cmpxchg on long.
> > * On architectures that don't have NMI-safe cmpxchg implementation,
> > * the allocator can NOT be used in NMI handler.  So code uses the
> > * allocator in NMI handler should depend on
> > * CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
>
> And you are calling gen_pool_alloc() from __sanitizer_cov_trace_pc.
> Which means this implementation is likely broken on
> !CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG architectures (do we have
> architectures like that, that support KCOV?).
>
> There are probably other sharp corners due to the contexts KCOV can
> run in, but would simply ask you to carefully reason about why each
> new dependency is safe.

I am also concerned about the performance effect. Does it add a stack
frame to __sanitizer_cov_trace_pc()? Please show disassm of the
function before/after.

Also, I have concerns about interrupts and reentrancy. We are still
getting some reentrant calls from interrupts (not all of them are
filtered by in_task() check). I am afraid these complex hashmaps will
corrupt.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZm5Vz1LL7m_BubwV%3DbMPgVjOVNpp12nDZRi5oesH47WA%40mail.gmail.com.
