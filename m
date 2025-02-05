Return-Path: <kasan-dev+bncBAABBXXPR26QMGQE27OLDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 511E4A299D2
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2025 20:11:29 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2f9f42d98e3sf110032a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 11:11:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738782687; cv=pass;
        d=google.com; s=arc-20240605;
        b=ilCDVoEixHQMW7dllKgloy5v2uXBppLUF8Xgh0zuh+5OMGLnk/GAc+C5ztwqNQjiHf
         a4EiwKv1VkpI3G2jZ8yBkRAzXj6H/5hZPavhRyNyRJIx7AMn+jaVicspQfsdGG2TY0ML
         LG+d/dQIe/ZdYKL50m6vu6I4P/u3K2KoQ0uhq8iB2xhrA5HsOu1sTt5RnCIZRiBEtADz
         7BV5P6PeNrriTSSiTwk0qhHsOwMAHPeAEB1O0yAmCCp6AH9Ceoxepi8yYQpCNV+/LO20
         0EiJjz2O2Pc9Cq4W+8t/D4SnPhAWowr7220XlC0e/B5YS9IbcO00Kh9I2fxGkru0uToo
         uQSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=RZaVbC8j5+Bwi7f7QuQLhWpFqCTBGvv5kKY6m7JFNOY=;
        fh=ke2F1DdkOu3dBPkTe7FwwefC3c7W1EySxVcQOqcOXlg=;
        b=K9FCaVPvHCW1KjZNgnu1+9i3aVWmKcfwTrfMtdgRD4lWPJSznpiPcNk2H5kBZ0uAvq
         uVtLrnu7vYxnbpKCuzfmKMthSCSNrcIwbZRx5ky0sviaArWxDo0YOu14BX/0pcSEaQh/
         /Ex41fxsrZpZ8Z035ALDa5r659SUTk/jeSrx/E12nzNxA3MWwB0WdhTnhXy9I8MhpxlY
         jTcxN/b5y2HRK/ix2/Jao72Zalxb5JXC4lAq6PHMe+AYxJf1JViN+nMRgTqBeWHR2JDf
         vzPkQvzqkvUgCYz1GqcT5YEimwd23RIfUFqFR1Uw+gAtGfDQyogq7LqdImT1FCYmgeFa
         orqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=mzVxLSJN;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738782687; x=1739387487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RZaVbC8j5+Bwi7f7QuQLhWpFqCTBGvv5kKY6m7JFNOY=;
        b=O871c1JL1HCX5iE65QuBot9jco8Y75PP79++cEeRWZ/56iijWJ5yxWLoQxe9qxsPUR
         0DKR0WTBuXHXMUc4WPTcYYw5hB0Z21JGfqvVby77B+zVHHtrA0Pr4UfgrpDpOl1geWns
         D8LTkRZsmBcJ7iYXqWFuilKJnIUl/xM1fDgzCX7afwOGne4w33sGBe710skTW9LM6kBB
         koewHwwtm1YJzv7TbMgBCdIUN8B2so6yVewqGz/Z+u5n8Vr8Eiz8EESXazM+RJ7lBd6h
         +75M64LVRsv/o07J6FkzNZ078I/wZoyCReaxRKAkucBjtgR4tut1gEmWJPCh2hkyKOuE
         2DsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738782687; x=1739387487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RZaVbC8j5+Bwi7f7QuQLhWpFqCTBGvv5kKY6m7JFNOY=;
        b=N00CQJT7WmWHwUL72NZcXsc3TWOfbE6W1WmOWKakai/TnEC5HsPfz6Qo5yKEzEXESc
         4sfUhsshbD1gGOV8HAkKHHUT8CwMoSi9p96sbKm+q2IrrECLLbDFIGFsZepr95N5UyzA
         3f5L5BfvNts+g7+yk1/cTfbFpECus/OBYzxJb34HH2TOxts7CKP1hpSdhihS57G4pODo
         rRP2c3NO3hwU9GvfksMuI0rEjvUbRHPgEv8xyDzOp58zdakR9CwxZ2a97Eaks/7lYMqZ
         ewQ4F8kdLMG4kqd6Yrs/9z8iInX2w0t3l+SDV++XvJu9GkzPOGjn9/8wUgHKylBr3E76
         VMhA==
X-Forwarded-Encrypted: i=2; AJvYcCVPHPjgknv9rCVBzOVisIuOqkBvyHQD7HHZGO6GXKaKPuotY7JnTkJsI9w/OwGKNNZGwAVZZg==@lfdr.de
X-Gm-Message-State: AOJu0YxAjNgyi0dFRjG6R2cvDHH7RDz0QiVv969LoXyRO7dd+ioVzRQx
	XU1V6UHwwTlGe6PKoYg46OXH42Rqvz2vzNi7gYToBTZisugcAP4D
X-Google-Smtp-Source: AGHT+IHXRc4390b1fmHryIUtTxdVdqp9BrKJ5bZhsEhIRWEU7iXiMjEvXGRdIuPi2h8TvEtChFS02A==
X-Received: by 2002:a05:6a00:4651:b0:728:e906:e45a with SMTP id d2e1a72fcca58-7303520d375mr6831482b3a.24.1738782687196;
        Wed, 05 Feb 2025 11:11:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:35c9:b0:725:c8f1:7030 with SMTP id
 d2e1a72fcca58-7304401d681ls34627b3a.2.-pod-prod-01-us; Wed, 05 Feb 2025
 11:11:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6ywrTCmqZKENDX4SeXb+giOB4OHE8lLDc6YdJahDS2stbGrrW6+Y+sDt45z4BDZLGVV9in95Mtec=@googlegroups.com
X-Received: by 2002:a05:6a20:d49a:b0:1e1:ac71:2b6a with SMTP id adf61e73a8af0-1ede88b2342mr7601424637.28.1738782685727;
        Wed, 05 Feb 2025 11:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738782685; cv=none;
        d=google.com; s=arc-20240605;
        b=Zuo5FcgMsVuV1H1WvCS9ar1ZmXI8LhBWUPHtnOeNGOqBwpClvnIlKnmlszDo16jWAp
         Lu0CPQOfCMG193yJwC7v5rLo4tr09oRSWwvLq3q/RLgDsE9uDA2f/a+r2uJAY2V5JlbM
         DcN+uXgHvFYaVShYiFvgkQTwdB+7SO/m7sEWXgVGWnc2HsYBmExeLrokUpH/8vvKGXjz
         9zmFkKovwtYmgxLaszUejLdCjf110BwN68QNxcjAcNjEU8CPBWPOHR1jxFBmVF+dZ29T
         PUx3MbyAltbpzRnp1yK5ssIZ7TsDD48yukLX09636noo5/rSEJjuaakUl2INZHsqs4lx
         gazw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=SYRJ92XRnRT/x5NskeDXbjb8HVyYz50Z7VSg1zqM4Ew=;
        fh=lsozXqhRZKy4C4fp/71ggWGS2/6gwE7co7jutiVIO/U=;
        b=TTU7hfkKFspV5vUJN8uKBHGxCc5EeUwIQsJ9Wx6f9/nnkT2uYn6do/H2t34BdCQdzk
         dOHUXD7ZemzDCu9BCP6m37VF34VAmUTu7dG/8yIhKfaUhnAH4Den0vaEijkL4GxfPp+j
         LdmeCaehmAj/tNLTZbRLK9005GagQKy0ouoH3Qiy5KkeHhqo1xjveULJKXVyltmzSd6H
         zZPm8Xm/XteRRVWti4Nkpe0DGQBICamnb5+yCzw1OiryxRDiTe0vt0W/m5XyNUknrIAd
         3WUnQHt+d9rci07rtavz32iQaXqzo9rBb8GCLcMtCIMdxEHfZC0tF4C15vgwmiwpGbCD
         Osfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=mzVxLSJN;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72fe6967ba5si668864b3a.5.2025.02.05.11.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Feb 2025 11:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id E015240285; Wed,  5 Feb 2025 10:59:10 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id DDBFA401E1;
	Wed,  5 Feb 2025 10:59:10 -0800 (PST)
Date: Wed, 5 Feb 2025 10:59:10 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@intel.com>
cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org, 
    xin@zytor.com, kirill.shutemov@linux.intel.com, palmer@dabbelt.com, 
    tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, ardb@kernel.org, 
    dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
    akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, 
    dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com, 
    tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
    paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
    jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, 
    jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com, 
    rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com, 
    catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org, 
    ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de, 
    kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com, 
    julian.stecklina@cyberus-technology.de, peterz@infradead.org, 
    kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org, 
    linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
    linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
    linux-doc@vger.kernel.org
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
In-Reply-To: <fb30574a-d238-424c-a464-0f7a5707c46a@intel.com>
Message-ID: <3dcf7631-d839-7235-10c7-30f80d7f796a@gentwo.org>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org> <fb30574a-d238-424c-a464-0f7a5707c46a@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b=mzVxLSJN;       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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

On Tue, 4 Feb 2025, Dave Hansen wrote:

> > Could we get support for that? This would allow us to enable tag checking
> > in production systems without performance penalty and no memory overhead.
>
> At least on the Intel side, there's no trajectory for doing something
> like the MTE architecture for memory tagging. The DRAM "ECC" area is in
> very high demand and if anything things are moving away from using ECC
> "bits" for anything other than actual ECC. Even the MKTME+integrity
> (used for TDX) metadata is probably going to find a new home at some point.
>
> This shouldn't be a surprise to anyone on cc here. If it is, you should
> probably be reaching out to Intel over your normal channels.

Intel was a competitor for our company and AFAICT has issues all over
the place with performance given its conservative stands on technology. But
we do not test against Intel anymore. Can someone from AMD say something?

MTE tagging is part of the processor standard for ARM64 and Linux will
need to support the 16 byte tagging feature one way or another even if
Intel does not like it. And AFAICT hardware tagging support is a critical
security feature for the future.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3dcf7631-d839-7235-10c7-30f80d7f796a%40gentwo.org.
