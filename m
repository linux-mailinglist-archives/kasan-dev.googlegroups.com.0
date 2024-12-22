Return-Path: <kasan-dev+bncBDZ2VWGKUYCBBF6ZT25QMGQERDQFGUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 42B0A9FA434
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 07:07:21 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-467a409b8ddsf65051171cf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 22:07:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734847640; cv=pass;
        d=google.com; s=arc-20240605;
        b=CW7uMqP/d450LFHD7YC2cgXm32Nn68HHEaj4H4TbYQG5d1cFRmEcTOzobSNYuYB6OY
         KBLxqvGFDGcalkNDeRd48wvSEBy3w8qhOPjzxY1zdYj/OQl9dsjHFuhlRvf1TBhfio5t
         rBrCb9pPV6UtrcAwUcg7OklcKA43ZznjA3cKrdyRVKDTRWu293X5IAm6XRfT/AcnRJqa
         77+SZxrsAy21vMdgrKERiTd1BONvZwc8avlcIIXCpzo+104Z3FOn+RMug7i+WZguohtH
         gyCA3WNVn3uATFjiA+Ha5dk2Av8oTTrsz5+IoQ/mZqSonymOuwsNRKisokkfI5yT4yf3
         rjjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=3842bKq+icasMoQR7aE2xYOpbApALHjO4uEkUGnSzXg=;
        fh=i8vACkZJTxeh622jfqMIltVFLZ+7pHKQ/Fysg5Jy/ug=;
        b=XcPqE7BNBU4qiP4Wn12Y9zdQ9yG0aM7inOgZ7ejc8RDOPh/ZpY5GvJ2mr6c06KVOrU
         11UFLHY+S4QQVsTD6Zci332aFUjvzSlt4S5p/++mHGGvJeNpsITv50yFGluuFQL5LYY0
         CSIMO5qLTs1vjYsI/MJGvvlD0uiaR7o48qVs8hvB2EFCTA+H3qtwQ29S3i5urYiNoXuE
         iQQYawtR/sRmbrojKq/MPKIndihJDL+zsFKR0RDQScLMTL0DwGddOPOyN7QM9LDKMrtC
         lWMxHrKDNjjfKtRTdJXcoaFPiX88deqpl78f3YAZwQbaasj98Vgfgr+Khede4u+7hPBX
         FKhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I3fcrnqv;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734847640; x=1735452440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3842bKq+icasMoQR7aE2xYOpbApALHjO4uEkUGnSzXg=;
        b=uwf9wiZw+8y8ENzmj0Ceeord0XFXmNdoqiD2V6gEH7a87hGeO0K/xXrnrqtYdsUVba
         ZXVIQByKMcSVMqRX9DI/ipPYQWGGVdukxq/pz5xCGS8XXjhQqxfPXlrqQ88eNYZZ6TaD
         Cbs2VdM6s07ROCuQ/vC3skE0eOVb35HEFOAasJfXBbMl2S/o0oW1V1hchXegr1sxNQun
         +ksEfK3E6xkjFCR3ZuBJDZCzFqcc6Pqj/fm0jCVqdNkpvUR1ghh7IaHxiF0TjGmy0wkr
         +Gvfzoxa5DnhQz014Lp9DXjxG1bYkBKL77vI4d+Xt414qogK0bShObwhL7GT/1sPG1QD
         iRWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734847640; x=1735452440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=3842bKq+icasMoQR7aE2xYOpbApALHjO4uEkUGnSzXg=;
        b=HHtSLoYabhZfMB2CxfiVU9GTQdqpInXUjXXrhrowsBuN7oqtqoh/nEBI/SPbzXl1l7
         mKrYmjHCDN1OlbUJT6wp9YGlv3FsvaJk/raOGCA5Ot69U5H5cFxISPlpgl1HTLs1hNkJ
         00YJ+2lAapneu5a1hJcZcebnd3l2VNqVwtJgRB30AbJ5gVeTIqtUuezWOsvdsd5kTLaZ
         HJMwNTs/nEgFX9KSk7HJIRoQvp6RPSE9/RtazdjW/MijVDZTK0a6RfEv/YN386FI1uH5
         QCwo8M8Br9yRar6RlbBfHn1rSJteJ50p6b1eWq2JJbSCc55jd7WH37wyM2E8XorFmQFH
         TOOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734847640; x=1735452440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3842bKq+icasMoQR7aE2xYOpbApALHjO4uEkUGnSzXg=;
        b=TLMtGBA7Nz+EwlfsY3VjWRSytOYZGexj0/aGmuEQsRhcx1Ul/ULYFx6JNy6icY8VR5
         sNlmhd4jA0U5Yskzk/b7/wW1pkpTTA7Mj90obZFgrjmeJwV6UTPWoozVEdly9oDMn3aR
         44c5bvrVRpGRALlLmt0HIDMZ14l0Z/JhSR1Icl3Z93dQfloWjSzfuaI8X9m4R66Mw1wG
         xCMLMyzrs8ul75LGY5x3AcvZgqlBigQ7/n94Wucz1vLQtwU5NQhi28tjZB7+YkoIcpDV
         1/uHwyZUL1cyYUhYZPCBGZOK7j4tUf4QIA1h3T/G9rPudwo4cqGYb2SRMf8Q/UuRQ4J8
         RG1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWT5EWWZPrr1yfaebmVyu5mnBD8Yj0NnhFOLCX9o7Hd0W4HWDt+KbLIkXbgu03GGPVu8XuaIQ==@lfdr.de
X-Gm-Message-State: AOJu0Yytanpl3KVKi8Lh8Ttpm5jmLu8M5kBGn3QWi+R5nlxteuMeLP6X
	Lda08R2q5EPMZ3E9y8TGd2cG+WdRkIM5uycdFe8blAiQ7bQ259Ps
X-Google-Smtp-Source: AGHT+IH5dq8ojWXsmwFdn/73+EkHTK7HZNLGZHwgnbhmkxtH8D5KcHMTxDAWx11NsJOvtFFVPu0Raw==
X-Received: by 2002:ac8:7c4c:0:b0:467:64eb:f2f2 with SMTP id d75a77b69052e-46a4b1120famr152405871cf.9.1734847639930;
        Sat, 21 Dec 2024 22:07:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:420b:b0:469:63f:ce07 with SMTP id
 d75a77b69052e-46a3b07bc3cls10154601cf.0.-pod-prod-00-us; Sat, 21 Dec 2024
 22:07:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoe3F8xpt2bHbtO4ccl97AMYpW4YO3E7krTiLY1mkS3JB22le1/v5dVsB+8hadzdgxwMLbY48pbzk=@googlegroups.com
X-Received: by 2002:a05:622a:1a1e:b0:466:9f00:e766 with SMTP id d75a77b69052e-46a4b1a75bamr122992471cf.24.1734847639187;
        Sat, 21 Dec 2024 22:07:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734847639; cv=none;
        d=google.com; s=arc-20240605;
        b=Mt3v2mUJAZ5PYBK0R21AApA8MFzBT76EFQb3cSzuUfd7+mvjgi0KF/VV0X8RnqmpFy
         wJdvdKJDB9hKBgaubuyJdFQfyl2Cj+fRoaPTSZC68sS9iHmRvqoc9mZMoCx/95gPqupH
         ZVmYAIkTO4P3aYxFyY4VU9mcBgeEtz2uIHFDmiaco7cBGdns2ydo9ahzcrTpkY5bpKNE
         pZji4E0Xh5zYXrWcOIdG+/bXyp3jhkQ6NNnoixJxB0yKM3SAQxfLuI8r6qDPP1Y656OJ
         F57zmQDLO47P4ybyjeFJf6Jw9Me4CvfDvwsIrsdbywRUVM18XWF8WeZg+70Z3Yrf9aBL
         q5mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=htlpToW+3tDMXYk9LHSjN7kEjprwT0u1X/m/1Vl/oro=;
        fh=S/8bsVcBH9jQQRmdlVa/ew/4d01+x5AwQ8Snq0Xg0/o=;
        b=W3OS2GtRd9ScZqXgPOpLFlRxcwgzn4PZLbq+NO3nqFHLW0Jdy9xZOGL45/c8/Nh9Ee
         XELtAG4ZWKfNN/iFiLd8UX+nvMoRDxLCR0HJLKgToetAxuRZl3SAfaspFLJ6/c89qEmo
         q1JX72/1S60/R2zTG7V4TqdS2iS0sCQBPIszVLu5SLniraeFUB2S1ePcEUfdlaNF4ABz
         05seVvjRQ2xFO2xITAI1OkFTYYCVbNq/T/UfCE5cAHzFbsKYnKMwLT1bKF9epT0b4Fj+
         zd5AUPTq/6DDS7VjeBFQhy75uqO4XnzlcL+LdgK5ZoU41AhOkIL7By+gHk4P7CaC6hbB
         eMOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I3fcrnqv;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46a3eb77451si3134691cf.4.2024.12.21.22.07.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Dec 2024 22:07:19 -0800 (PST)
Received-SPF: pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-e4a6b978283so3421851276.0
        for <kasan-dev@googlegroups.com>; Sat, 21 Dec 2024 22:07:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU2N+YVB0r+kH9FrRxvIvhuFt3UA4Cws4DlJzr5Nx4ltInpFMg8JtYQvSRhrDPZ4f9a/969DxywmL8=@googlegroups.com
X-Gm-Gg: ASbGncscda5nj1xS+OfWI4ux5QVJ1ZkKHcNdhUj2ii79niRgSRiPIyTKCy05UQyOhww
	WbalIg0ygf3oOywvgtwImSFY7Ni/hmutQYNHMgaA=
X-Received: by 2002:a05:690c:6908:b0:664:74cd:5548 with SMTP id
 00721157ae682-6f3e2a65668mr105552167b3.1.1734847638651; Sat, 21 Dec 2024
 22:07:18 -0800 (PST)
MIME-Version: 1.0
References: <20241222054331.2705948-1-guoweikang.kernel@gmail.com> <02d042a6590ddb1fadb9f98d95de169c4683b9e7.camel@xry111.site>
In-Reply-To: <02d042a6590ddb1fadb9f98d95de169c4683b9e7.camel@xry111.site>
From: Weikang Guo <guoweikang.kernel@gmail.com>
Date: Sun, 22 Dec 2024 14:07:09 +0800
Message-ID: <CAOm6qnk0KYJXuCLU=7Y10wjMjWnUQ+n_RDsJZv5rAqBmq9bkug@mail.gmail.com>
Subject: Re: [PATCH v6] mm/memblock: Add memblock_alloc_or_panic interface
To: Xi Ruoyao <xry111@xry111.site>
Cc: Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Christoph Lameter <cl@linux.com>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Oreoluwa Babatunde <quic_obabatun@quicinc.com>, 
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>, 
	Hanjun Guo <guohanjun@huawei.com>, Easwar Hariharan <eahariha@linux.microsoft.com>, 
	Johannes Berg <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, 
	Dave Hansen <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, 
	KP Singh <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>, 
	Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>, 
	WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>, 
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne <shorne@gmail.com>, 
	Helge Deller <deller@gmx.de>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao <naveen@kernel.org>, 
	Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff Levand <geoff@infradead.org>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Yoshinori Sato <ysato@users.sourceforge.jp>, 
	Rich Felker <dalias@libc.org>, John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, 
	Andreas Larsson <andreas@gaisler.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-alpha@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, 
	linux-mips@vger.kernel.org, linux-openrisc@vger.kernel.org, 
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, 
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-acpi@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-omap@vger.kernel.org, linux-clk@vger.kernel.org, 
	devicetree@vger.kernel.org, linux-mm@kvack.org, linux-pm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoweikang.kernel@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=I3fcrnqv;       spf=pass
 (google.com: domain of guoweikang.kernel@gmail.com designates
 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Xi Ruoyao <xry111@xry111.site> wrote on Sunday, 22 December 2024 13:51:
>
> On Sun, 2024-12-22 at 13:43 +0800, Guo Weikang wrote:
> > Before SLUB initialization, various subsystems used memblock_alloc to
> > allocate memory. In most cases, when memory allocation fails, an immediate
> > panic is required. To simplify this behavior and reduce repetitive checks,
> > introduce `memblock_alloc_or_panic`. This function ensures that memory
> > allocation failures result in a panic automatically, improving code
> > readability and consistency across subsystems that require this behavior.
> >
> > Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> > ---
>
>
> Please try to avoid bumping the patch revision number so quickly.
>
you are right,  I'll pay more attention to this in the future.
> And if you must do it, you should embed a ChangeLog of your patch (below
> this "---" line) so people can know what has been changed.
>
The update was indeed due to my problem. CI prompted me that there
were some compilation warnings that needed to be dealt with, so this
update was to fix the CI warnings. Refer to this:
- https://lore.kernel.org/oe-kbuild-all/202412221259.JuGNAUCq-lkp@intel.com/

> --
> Xi Ruoyao <xry111@xry111.site>
> School of Aerospace Science and Technology, Xidian University

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAOm6qnk0KYJXuCLU%3D7Y10wjMjWnUQ%2Bn_RDsJZv5rAqBmq9bkug%40mail.gmail.com.
