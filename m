Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTOR2WBQMGQEW6SAIUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D10F035DB8F
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 11:47:58 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id x10-20020a1709029a4ab02900e71f0256besf4790526plv.8
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 02:47:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618307277; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhZVLWGvgD5ydgv5ogae+ieUxMeWym7urlgUWeAmgruDQGHxxmvnKqXPTT88oA+nH+
         4Ao+RT6DB3Pm0sEw/zZLg3hnvUSNXOwV6Y5mfgcN/BV4so91j+NDhZ4Ig19iVeaocZNE
         tlLIvC7s92AKPgdB/g8/nitu1ITKY0gXcYdFmVY/o0zz/jr9DqmFm8+G3heDQMKKSC7j
         zTYeTXCQrFM5/ZWRw/o0GSA7KbyDuSwiSuJAbgy1aqDQsJeQJxoxv7vnUz8NgZDzPXRv
         MTEsavAV2gNArqH15fOI92Qu7lJwGf3/eCtoTcVkfWKrdknfEeph1mjwwcQO5U/8dQtE
         MubA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uS4hib42DZdmEGR4WJCuD4yURWCL4j7yCN8fcSGMioI=;
        b=yjaevx1oSgvTokC8WMlCTJVtZj53Hxgi4fYpAy2+fBhHaNedGsY+dikEPmlPOVRiMr
         xi639+d5Pme9Gpc2kgi+cttD9US6t8ko/U8RbZh4a8ns7pKGVROlvfrwVaDOeFrd8Oro
         sP/c+0/QeDHjdcUskup1EVIEXbLwyUjALdeBKrs/fhqGLIBDwsMP2Flqrha8KItv1Zlm
         1DuN3cgHBPqZOxycMLeCwj+qKaGRbuR15+ByyqDbV3A7faR2VrQWxKRpZWkGJtWeXDw0
         5MlMxwlqUQtguA82iJAxrReUSVDnMnZo3outouiTlpfbVsC51vbjsXA/54ZmAz5TKQaM
         sdgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uS4hib42DZdmEGR4WJCuD4yURWCL4j7yCN8fcSGMioI=;
        b=b805EgS6kv8d9yFPJTZo/EBu4E4hZWP4HGrPFv0DGHyTofUl/FxjR56l4iX7fKlwB9
         bYYwRqkmDsAOswtVb9s7o89cQrHaPNORWTqBUW1QzLMF2I2Ie0gaOBNlbkiFi9skYthL
         5Hew1BPKQhiMXzNg7rj+1rHLownxZdJPz38zWNhS4qjhaddvfAQDfTE13FObOFtZw963
         mexkBcj2s4aQey4N2INRhHCA4EI0hjyk8mNQSlShW/qkBCSK2RbdIj/c+A7B1ESJDR8+
         cV0PtTBzd+h20I26T03wkJcvjJhHUyS587+y2kMmy7LNBTdtk/r2ScTVKz+y4wrGRkXE
         agwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uS4hib42DZdmEGR4WJCuD4yURWCL4j7yCN8fcSGMioI=;
        b=rFyCwwjdF2U88Tg5yUwYAyu3jSChrdopUnZ7soKLUoGJY5GrULwfVeWFV4eRs05jvk
         PfrFG1gERCiqyrukE0cffVuWGDj/Y65FyaJ796goEl5Iv42YqL/vqNlYCis3c5uik9BR
         WDf1nKmJXp3TzNIFNygYAZyjbjdBqFinT6LB9mrIhkaNbOlAXtS0XJ+0nJD/m29s8KJZ
         rNC4DTe32QgPv3N1qNGhPLxmROlLPwH56AaibXofTbDFADG1StZzOT5H8QygidcQ+432
         eIal/p42XDMEgbVezFvPM9c5a2t8NmOAiWCCcibZoH/srsGPoDlevL9eAgJcxC+4PFIw
         dmsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PK2UvkeavuhP2UWiBEHnMTKKuHuYu7qf4FqMgfp7Mzm9zh7zi
	5I5tkSlcmiRnohb49Qpe/oA=
X-Google-Smtp-Source: ABdhPJyWL/wOoBh5bYj7VemGZWPdIdH/Et2/C2JqgbBN6UmF5tDXKw23ImV8kpnTUUuUqaaVlB7kUA==
X-Received: by 2002:a17:902:e851:b029:eb:1fd0:fa8e with SMTP id t17-20020a170902e851b02900eb1fd0fa8emr4711715plg.38.1618307277629;
        Tue, 13 Apr 2021 02:47:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d385:: with SMTP id e5ls2630345pld.10.gmail; Tue, 13
 Apr 2021 02:47:57 -0700 (PDT)
X-Received: by 2002:a17:90a:7566:: with SMTP id q93mr3865765pjk.103.1618307276961;
        Tue, 13 Apr 2021 02:47:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618307276; cv=none;
        d=google.com; s=arc-20160816;
        b=hxEVKvWasEBkbdcJUhxDeaX9sHgV1rkcndj6zE1KM3K1JZpohBeIn1megfAb12kM30
         qwpzwnxYEqZPjdm6lf0VuUSElP5oYxNzaeTd5er98URfkN4QYB7d06vaJi6E43stNYfH
         DNDJ/85ck14T7Yu0+4z0X+OfU/2uucNXGL4mQwJvKw60TEvUxU9PCW9jD9vDdRIBd0FZ
         5OYQM8VFBMxJZxujx1a3kd8yXSkviRl0eVFfHxBOnLnnzOQgJE96FSPDaNbceTPRIiUp
         eGmVcfachRfDczymEi0bXA1hSoHVSF7+/dIqhruVvsJ3IP+ITPU2FhPTCqot9yQoXyBI
         HHPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=5NhlKdvdU4gZsFuL4UnbYWWpvySftnX31YPOlTkai78=;
        b=TLc5I73mvxn3SMW3Re7VROOMZcVSlM/SIICrryrKt2dRY+6/tpWtF0RdUP7Ju+2KGD
         aA+tv0p2nODSalTrSuYkghWDUajsGzznguGt8sVsP1ubxbg5hkiVu7aWdM4IBeG0Np3Y
         LuWNH8kcTXOomk+FYcuvOn1mMsd9BHlJjZ3/zTFQUuuaN923qOy33JANASYHbAe9ASXO
         C5cRkJ7vHsxWU8ZbT5WTiCH7woinzgu2qisfuJ35TuXyfr9p6t6qlZqguM7GXYKV+xXP
         Xt9DbIbHBgp/GpXzMD2ibTUwpCQksKue/sCWjzOG2LgPneYJUFH+SOcRajDUIvmrkFu4
         G/gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g23si1385208pfu.3.2021.04.13.02.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Apr 2021 02:47:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 572C0613B6;
	Tue, 13 Apr 2021 09:47:54 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org
Cc: Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>
Subject: Re: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Tue, 13 Apr 2021 10:47:37 +0100
Message-Id: <161830715687.1113.4436583872879811764.b4-ty@arm.com>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, 15 Mar 2021 13:20:10 +0000, Vincenzo Frascino wrote:
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
> [...]

Applied to arm64 (for-next/mte-async-kernel-mode) but with a note that
I'll drop them if Andrew prefers to take the patches via the mm tree.
Thanks!

[1/9] arm64: mte: Add asynchronous mode support
      https://git.kernel.org/arm64/c/f3b7deef8dca
[2/9] kasan: Add KASAN mode kernel parameter
      https://git.kernel.org/arm64/c/2603f8a78dfb
[3/9] arm64: mte: Drop arch_enable_tagging()
      https://git.kernel.org/arm64/c/c137c6145b11
[4/9] kasan: Add report for async mode
      https://git.kernel.org/arm64/c/8f7b5054755e
[5/9] arm64: mte: Enable TCO in functions that can read beyond buffer limits
      https://git.kernel.org/arm64/c/e60beb95c08b
[6/9] arm64: mte: Conditionally compile mte_enable_kernel_*()
      https://git.kernel.org/arm64/c/d8969752cc4e
[7/9] arm64: mte: Enable async tag check fault
      https://git.kernel.org/arm64/c/65812c6921cc
[8/9] arm64: mte: Report async tag faults before suspend
      https://git.kernel.org/arm64/c/eab0e6e17d87
[9/9] kasan, arm64: tests supports for HW_TAGS async mode
      https://git.kernel.org/arm64/c/e80a76aa1a91

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161830715687.1113.4436583872879811764.b4-ty%40arm.com.
