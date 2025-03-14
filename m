Return-Path: <kasan-dev+bncBDDL3KWR4EBRB6XO2G7AMGQENJN3U5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F12DA6199D
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 19:37:47 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e63458181eesf3741457276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 11:37:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741977466; cv=pass;
        d=google.com; s=arc-20240605;
        b=JAj9TzORITzOO/iR7mJ+RmxLTsxlxyBwiTye58+DFcKIus40yLOFq+N7hvSWH3rRfX
         QG2GW5eTG5BP5dAAZbuiwr9gb1scKW3EhD7zxf3kKdsjDCr9gvwOQwxUByEqxLBgd4FB
         fi7OGPcVdE6Sbw+ajMnUzl2G0BS8zIjYfGYKM8Gd5z0YaxYVU4nOsrOpUf1igRRP+dYr
         SabhHAH5dfj0j4j6CE4d9L+Wql9Tsck2Niy0qv13Pbqi4OE4nij7ZC/03qA+f7guSHWV
         NOxOUq+VIq6hpFvLIqAGOPzBYSdiIk5/dkGwZN826aQKzecJU4zQp82abWp1YzXhyHYa
         0Opw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UTZPZeLAkbVICyUr005cK7lwXpcGJxqu87Mg0snNZX4=;
        fh=m8IR78dt6Ld79CquByVRajWC/Xt3QA8G1402BAFs1/U=;
        b=axgbhGaKzjA63NDm7OQV5BVvHcZIvSnyXQHbKR/etIAFVrqawvvvMEyrLvVNN7DGHo
         rk2pzMjcjgvNGy4k1T4ibPtrbDeKEmWVsCOmr2otWQ+MIDfIkqjxxybVXUy6KAAEZxDI
         pm68u6QnZWBKYPQbMr4+oE80AYvMrKBVxS93T5K2nREf/i88XVu6qR9PCavm1smURham
         ohOYMP3cB7ZOLEvj23w00UWkEPRnxHoF2MhpT/bqWss4gaS5YNDP6U9zTWSbsJ0rUC5s
         Yrx89yVHAKqth6tRp6yjbwJ19McgSXLp5s1BBoYDHSLUhAH/qctqmk2TyD2pLnq3lkpK
         BKdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741977466; x=1742582266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UTZPZeLAkbVICyUr005cK7lwXpcGJxqu87Mg0snNZX4=;
        b=hWYKKz1U695e3U5gK/ANVJcu/24DM7Wh8sJwd5FFHkhRfO570DwibWaBlr8bZKszZt
         JAO4BjEaaa+oiJppqwYWqNCEZ9mlPKEEjRgYqdLWw2zKC2T3Sq9ISvK71nwOIZfe22wB
         WCb+j6E9rOiLZo5LlBilCWX8ANg9jhAHHBIJnyhMwHGAI8bup/rqPiQXWglrTbKLgvB8
         G/aVRsrkIJdkaZvjM7p751pGgNHwy3wEnRp4F5pgaHWeDCW2L6PTTTUv9frtlcFcR2ew
         qS1ah8YLV5e65pRH/VxHKY4tj1v6hSSwuKPHXQ92vGF0Io66tiT+UzOXcDQ4Bv3pSIkI
         D4eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741977466; x=1742582266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UTZPZeLAkbVICyUr005cK7lwXpcGJxqu87Mg0snNZX4=;
        b=M24lns2H2FcWazuhvIvW/oeZoQ+Jxw0USzQXlDNnHZyYFI0gCAjemOnGgyekdYvcU8
         3mo9Nyul8fp6sTaWW+b7+0o7T/XH/+gITCOr+uZyAKOEmrkREKnL8GaZYRSTQjUsDucw
         yNXLsk+zjmilVES4ufFDilzIGIfB2Clt07mGB4J6Yr1VeGkjREyneR6qRIPMtfzGCAuv
         5kxDhNU+yo4+142ExF0Ujnf8VpYDPFileZ8/XZKhbb8VrGEB6A1uAO/brcBgyw/k9fX9
         AX9fSaIIFclddQ/Fp4fykiLlsOAv2Qs25TLRsCDLau9Glxt0qRVe8Gq+k2uMyHKxXpV9
         CzOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWDufKbssZv/Wp6tN6LODrwwlYKeZt+FHCDAYGnnAZ3iGvUqk9moJlQjF0hmkPlCwQqZLYgJg==@lfdr.de
X-Gm-Message-State: AOJu0Yxuo14REEFqBeerrge7sYzL9VhaJjUcV4DrMfTMBzxa97uu6njQ
	4zvkDb08Z+5QusmAtGR9u4jufTW05n/FEs+54Pw5hmNoTzCcfRue
X-Google-Smtp-Source: AGHT+IEbx7YXjGt6z3PN4LMu/T2EwB4Znff390Lkj2lFH+3LsyaGDpIMCfLSThXGVEF8BA6SOfjkdg==
X-Received: by 2002:a05:6902:2602:b0:e60:9c2e:8966 with SMTP id 3f1490d57ef6-e63f65a820amr4432226276.32.1741977466296;
        Fri, 14 Mar 2025 11:37:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIQwy8J4Ti7iGZ3h7AcdjPsPGfKnARsQvtC9IvB5rHQRA==
Received: by 2002:a25:2608:0:b0:e63:f487:7ca0 with SMTP id 3f1490d57ef6-e63f4877d6fls132498276.0.-pod-prod-07-us;
 Fri, 14 Mar 2025 11:37:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyDklo3Ov+68MFJdY46+dlEU83ZM5B5i9hOoP9UhpbV3SdvP0/q5FLhFSRMXmcpltYgXNrjNPyHZs=@googlegroups.com
X-Received: by 2002:a05:690c:4b12:b0:6fd:3743:1e31 with SMTP id 00721157ae682-6ff45fb4252mr49736867b3.18.1741977465158;
        Fri, 14 Mar 2025 11:37:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741977465; cv=none;
        d=google.com; s=arc-20240605;
        b=c3kGCNVEjldAJfq7I8guTztEEq5QoVaIg6+VnseTb99gzXJkSwTGz214qJ9Xslne77
         V7ls9Y+/McSXvjUi8AnE7iz0l8+1/XZwEGpbOdAK7Zf1m4sphG58aV7RxGQJK/OV8u9b
         ujX4z0bKyO2r3pU0nCgXKcMcc7jmGDFChpZhdFL9oKWMFH19bCwgWki9GW96J7pvj5Fq
         M5xI3QLzM3JKhp0+RDAAeLnqqVbvAJQ4iN4TKlmA/zv5YLPv/RG5gRd7tnDuxwYJEK8P
         MlOcFPg3OvwM2fmUXjVsyDbClk3fgqQW975JA2JDDsXnk2/Yf6yAZa4ltsnTfHpPdZR+
         lJTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=FQPymT7DNMnjyCVx21Yl46BqrLZSkSJWkjcpXnWXL4k=;
        fh=gjUlMowKwhXNxIZ5ohgCRwmM+qTic5ziJJygvXa3b7M=;
        b=A8gFe3gJnUl/2RF4WWCqbGNqYaz/XRy/XwoJBgl4DypuDDx3tIiQNkbX+oP/QDdeLd
         Q/rWId+subNDRx4+kjgxO4GiplIaaMerxCJOITMrB4figGSwjVEeNrAwSu4DQy+TGbxO
         0EPs5SuB767Sybvaxf7gtRoGddSA3gUDhyMf3BzbwjUg47hMbVSDESxkHziOropyzZVx
         KtAkz/6FZl6znhjSqn6CMtppX9339FlmrQkhv01mCYglrJ4f1+/Jr7qmzxVFujXd4EtI
         iJY6eOZbfDFlN6EXEcUUk5apRPLS5jwp3uTd1DYwI7nQMeLkZpBVDmGHpzvQsqI4Q5DT
         L8vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6ff49d483d2si1091647b3.4.2025.03.14.11.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Mar 2025 11:37:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E3ABFA4884D;
	Fri, 14 Mar 2025 18:32:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2B0F7C4CEE3;
	Fri, 14 Mar 2025 18:37:42 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	Anshuman Khandual <anshuman.khandual@arm.com>
Cc: Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Ryan Roberts <ryan.roberts@arm.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH V3] arm64/mm: Define PTDESC_ORDER
Date: Fri, 14 Mar 2025 18:37:39 +0000
Message-Id: <174197745246.735540.15365076503205188211.b4-ty@arm.com>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250311045710.550625-1-anshuman.khandual@arm.com>
References: <20250311045710.550625-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 147.75.193.91 as
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

On Tue, 11 Mar 2025 10:27:10 +0530, Anshuman Khandual wrote:
> Address bytes shifted with a single 64 bit page table entry (any page table
> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
> is not very readable or easy to reason about. Besides it is going to change
> with D128, where each 128 bit page table entry will shift address bytes by
> 4 (aka 2^4 = 16) instead.
> 
> Let's just formalise this address bytes shift value into a new macro called
> PTDESC_ORDER establishing a logical abstraction, thus improving readability
> as well. While here re-organize EARLY_LEVEL macro along with its dependents
> for better clarity. This does not cause any functional change. Also replace
> all (PAGE_SHIFT - PTDESC_ORDER) instances with PTDESC_TABLE_SHIFT.
> 
> [...]

Applied to arm64 (for-next/pgtable-cleanups), thanks!

[1/1] arm64/mm: Define PTDESC_ORDER
      https://git.kernel.org/arm64/c/51ecb29f7a65

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/174197745246.735540.15365076503205188211.b4-ty%40arm.com.
