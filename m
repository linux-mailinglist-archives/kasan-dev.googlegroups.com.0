Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGPXY7EAMGQECY5IR6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C974C4756A
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 15:50:03 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-297dad9959fsf3563425ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 06:50:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762786202; cv=pass;
        d=google.com; s=arc-20240605;
        b=knXcO8Ay7Q/6kglLLhP13ioVJQhkJ0OqkVppwssOTSGkW3l1uzJb7YiCQsQbF6X6X7
         s65AUFqVeoAUxc9EWobiL0QD3Tle00Gd4mc0Kd9cmv8cASNrGFl5HFgm75j58pvg5u1V
         hl7WTaLJpukcOo05ukI0LDhPWwM1a/RAgZ7Gx6hmZNVtj1mRZt04AWooGF6weZ3fv5hd
         p5SL7ttxXVUh+anhWAn6kj0TkbtfOME9o+PAjhyQystcWhmCs1vV1qCzE3mQjp7tlCJ/
         Wsr0iz/f6q/45GewECUzPrAdWEPasUrdvdRtQYQyMKifEPb89u1PqVp8CNKkpmAlaJCH
         w9jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mabIQoo9WaKLLMdVK0trYesZrLyLRVmexkC4njUmfEI=;
        fh=xmiGuFXPp1PGXu8U1JgEmfLwm46IOjI9vKIn4T/v3Z0=;
        b=MIglqS8Yh7ipglSpBE1MjsPo9wUiMDRXPSCzX8bK4WN/vjShXqRAr0tMfcMoJ7hnNO
         wXlW1/yMVSQfD0mLL0Aixql3D16Fo96lP0j5UkOl2Xl21nK8zXRdDk8IiV8ARqxI2HB/
         TYbEvA1hjG7WIoKYHhNfsutbgmTuhkUt7klWVID1mJ/Fi+hIx/iqTExah2rXtY1BgZD+
         OtzviMHmjJhj+JmrIhYsAxoASwWTxNvtB9vBrKjzzNWLcgcMUH5yD7fbtfqflQEzZNdH
         hKyRztCyp4J8/Tnb/GcNHZFI8rqt2lAnuYjqOpT6kgxBRGZcIWD8TZ8QaAB7E+1Sqe87
         GN5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L1YhNvt8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762786202; x=1763391002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mabIQoo9WaKLLMdVK0trYesZrLyLRVmexkC4njUmfEI=;
        b=NrBMardGVUZiewu5lvKaShM+A2uLZBp+0ekoQSnuOBlWRRbJUkJoFtFDfdP0TkNcgd
         Dyiv9yPZGvGy0V7qdzmjAegS24oN6yb8e0U3Qtl6Y3jPenXegtu7mncnlEBrEucCiiNQ
         vLntWJM3eP4uDvFnUc1nLN++8RwaePShIVPlBBvt4Vc0koVHaChrzKhQETuHxt7Cl7OU
         RH8A5W8BiGDtoUg6Fyn/bRX1vJWu+2yhNVa5NmLv7f9/zsmYhEUT/Qm3CSzS3HWC28eb
         nK+qI6rCaRpu2SCvRB+o2syzUNvKvw4Ko0MJVCwZm/LMezzEFmxUcLWyQSQFqpoP+UjC
         fXYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762786202; x=1763391002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mabIQoo9WaKLLMdVK0trYesZrLyLRVmexkC4njUmfEI=;
        b=Kqohf/tJrlO5JSnGozb7lOfvPMfQ7Y03/LSZOQadu1Eq0dIY0uSzyRTo6ADUxtGSd9
         3EP5AMvazc9Uuq2psTYSOIlMO79tosnzhc30sy9AVFhU2GiuxPbxIau+DCMZhrzkbcX6
         itPx0wKSIRvr4Q/pBrGtHFg+XSYSJzAwECuMfXQ4AmtkWoljDGUfSkA1EaDsk0a631aP
         LuDoworm5zTCSCp0GE/aXtbT2c5gh095ioFrPb8kS+i6yVrj+Z7Y2p/TS1ZPSibEnIHh
         dHAhyh1AkYdn2f7IRpvDt+GYfVzfwl6ZDe0HLyDOLljK6XwzRX3PHo9xOGpvZyUFkYye
         GPTA==
X-Forwarded-Encrypted: i=2; AJvYcCVj97q0h1Cx6VbA2czhPwhbWQ0opZl53A6tvTbaPh0y9OD5ZO2RCpvdhPXv8c/jH1q4lEt+sA==@lfdr.de
X-Gm-Message-State: AOJu0YyaEoJtOJXQ+xVpirU0X154OmCLX6WPy+ZICywMs3gVdVfl1sny
	O3/8Hp1DsJU8Mq+//xvsJKF2y/QXuBJj+IdBqQWZjARYVU7m1w97W9ba
X-Google-Smtp-Source: AGHT+IGqzUPSw7ssHLDw4CrqFlfi+AUnO/qYxJm7ObztEMre9stzzUJALNToD9dUrpKemW/ol/Tv1A==
X-Received: by 2002:a17:902:c94b:b0:295:745a:800a with SMTP id d9443c01a7336-297e5415471mr59541815ad.2.1762786201775;
        Mon, 10 Nov 2025 06:50:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a1J4z0CIw/cYcdZSZTKy57rlndqzL9hBVPNCYuUynkaA=="
Received: by 2002:a17:903:41d1:b0:298:f12:862a with SMTP id
 d9443c01a7336-2980f128932ls14508295ad.0.-pod-prod-03-us; Mon, 10 Nov 2025
 06:50:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWYWV5tnCOCrRZ0QbSy1YsjfWZrbYQyu7Z5cSzgIIc+p5Esx1wsSzGKTzGLnTKf1P4dK4JMwMJTWYE=@googlegroups.com
X-Received: by 2002:a17:902:f908:b0:295:70b1:edc8 with SMTP id d9443c01a7336-297e53e7d36mr85500095ad.2.1762786199964;
        Mon, 10 Nov 2025 06:49:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762786199; cv=none;
        d=google.com; s=arc-20240605;
        b=WnIu8U4WJnjt/WIMpn/1+/Odtv13+DFc3wh8JgZiMBr6cBQ38mGSX/trAeiHIy4TTn
         kL2hCB8QzHeerg4z0GhXU8tt75InEl+t3nJ+mxzmZPBL+PFJDC0Y7KRJZ62ZidIA5neL
         +NNQ8SUbnxOfXq6PwS02SbkmcyzsQS+7i/EVDf17+WliK+RA/nufkY08F8JHPNKpx0Pe
         xvvLCcNw8eAS4oOlddx3OWfv2YIFFolaUuBl0oZQw8LS8T/ssCvPIQ8yq1Dnr7s23cLW
         H1/H5PVbo9floKj3DnlyO32eMaQFVpBMG1X8phuL0N0nYZbqajEDpC/1JTIeMy3GDitd
         e7Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yuV15cVIkOZ3osUBoMrFPeh8PgM7VFfcDiPWWGwwe8E=;
        fh=p6KhTIy+aw3E0DeFnTZyH02z5RFa/poVgEA0N/qu+Co=;
        b=TtGyBiBUNFSxIY7qYvHl9FfjNUj0frKW+Em2Cx7PUg0AULbQKsaF6sSswrV/AH5EJY
         WqrLBGBuIgbH7uTw6jsG/jzc0dPxYCpYGDN/x8GR4KRFTPkBuaer5yfM1QxpbbWadeSq
         2WDKiQsRiVkO5e4mVrTUlntpau0VXaZNEqLfIgLnywFeCXwwBKyWhWDlZjSKmsUs8FM+
         UGReq3kNrPkBp4YPVsu+0UoLC6hxm8iB2ZbQ4NcYqbRrQRSg4aIHmWq0ctfSZXKQyFK3
         xwczdoLt+y5IRNadAeqF//6PdwBjUY3ZP/3cm8EJLmonGFXCGT/BXj51pYi7Q9cVmsGM
         HByQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L1YhNvt8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2965096e394si1646055ad.2.2025.11.10.06.49.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 06:49:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-7aab061e7cbso3723205b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 06:49:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/Wv635ze5EHr401dNawqksj1wNnUzmOdrh3wm0/N54K1yjLJDY7bxxtvn2TYdlYme/uj83P2wVi8=@googlegroups.com
X-Gm-Gg: ASbGncvaQpRdgP4enG/aefJftyNnEBTko2Z0lula9dTUMomzlykiw/MpA6Geklg9bfB
	Q951CWr34nXjJhtcSJkAYpv4NjZXvfmI0e5T3dBytookgi+tYaN/jC9+fdkUHm9lID9OOtkFMCU
	mTGhjbexA1dqkJQCFBpeOA/CZpxxeGwC0VEPfy15t3R6UCTP3dVxg5WUx7KZWd/uxCDWslU+T1A
	aQkpbyGs55IgMLdT/ZYdffq4fUxEjVBvkyT4ihxIgoQ5ORS1yt5lWKlgu8zCO4ik8a2mvGj5vtV
	U3xjT1G82H4sUYwvJS5Y+SRZnNE=
X-Received: by 2002:a17:903:2f88:b0:295:24c3:8b49 with SMTP id
 d9443c01a7336-297e56cf5bemr117461485ad.46.1762786198920; Mon, 10 Nov 2025
 06:49:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <81848c9df2dc22e9d9104c8276879e6e849a5087.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <81848c9df2dc22e9d9104c8276879e6e849a5087.1761763681.git.m.wieczorretman@pm.me>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 15:49:22 +0100
X-Gm-Features: AWmQ_bltIHaW2m2Y_rXOjdB0rjwB0avPjx0FCrIDnvZhp3yD5E0mxdw5HHzg9_w
Message-ID: <CANpmjNM+ot5A-pRLhV6Esn=QvCeCStd9fG_pgwrVA=6pxD8aqw@mail.gmail.com>
Subject: Re: [PATCH v6 17/18] x86/kasan: Logical bit shift for kasan_mem_to_shadow
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, pankaj.gupta@amd.com, glider@google.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=L1YhNvt8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 29 Oct 2025 at 21:11, Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> While generally tag-based KASAN adopts an arithemitc bit shift to
> convert a memory address to a shadow memory address, it doesn't work for
> all cases on x86. Testing different shadow memory offsets proved that
> either 4 or 5 level paging didn't work correctly or inline mode ran into
> issues. Thus the best working scheme is the logical bit shift and
> non-canonical shadow offset that x86 uses for generic KASAN, of course
> adjusted for the increased granularity from 8 to 16 bytes.
>
> Add an arch specific implementation of kasan_mem_to_shadow() that uses
> the logical bit shift.
>
> The non-canonical hook tries to calculate whether an address came from
> kasan_mem_to_shadow(). First it checks whether this address fits into
> the legal set of values possible to output from the mem to shadow
> function.
>
> Tie both generic and tag-based x86 KASAN modes to the address range
> check associated with generic KASAN.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Add this patch to the series.
>
>  arch/x86/include/asm/kasan.h | 7 +++++++
>  mm/kasan/report.c            | 5 +++--
>  2 files changed, 10 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 375651d9b114..2372397bc3e5 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -49,6 +49,13 @@
>  #include <linux/bits.h>
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> +static inline void *__kasan_mem_to_shadow(const void *addr)
> +{
> +       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> +               + KASAN_SHADOW_OFFSET;
> +}

You're effectively undoing "kasan: sw_tags: Use arithmetic shift for
shadow computation" for x86 - why?
This function needs a comment explaining this.

Also, the commit message just says "it doesn't work for all cases" - why?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%2Bot5A-pRLhV6Esn%3DQvCeCStd9fG_pgwrVA%3D6pxD8aqw%40mail.gmail.com.
