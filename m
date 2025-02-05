Return-Path: <kasan-dev+bncBCU4TIPXUUFRBAG5R66QMGQEICGHF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id E870EA29D20
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:04:34 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-216311faa51sf5233275ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:04:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738796673; cv=pass;
        d=google.com; s=arc-20240605;
        b=alUMygMKnPHMUXNI7S8EcRKb5rsP/XXlpU5FcX9lo6VEOIKPiimO4I8qwXnV+cHI28
         CiflyXI8eertpr5O1paN8SNTL5IN6AbOlnY00J3UZn4ibPG556HwO6m3yfg8O/H6g/g2
         SjvJxflWDZ3UUr8FNUw71oGmmH41OhWftU1xapvwVxZYXjvtVbxN5gQt7vJwKSYhvj/2
         OfiURsKZB+s4OW4UrcNzEHWTqAsXN850VvdXK3zoD2bCiff0RKm7giy7eO61m7MBvYLv
         Snx1m1Tp1OZupgpjf6hL40hLL5IFbq1YGBbkM8MBLoTP4uOYduE/V7P40IJBkxVWIB3v
         TYYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NxHXkRAMhKJ8Estx0a564z+y5xdswjQnexnY9Moat9A=;
        fh=iPj+nqTIOMeqjcIbKjz1VEIP2WDQby6MXA+of/WbhTk=;
        b=KKwm7luA70Mg0zozauY1LDCTPP1ga43uEz0z366MBIgkzPr4nwiKR7pX9/zoS3ZsCw
         SqLb9Y8wJ789+o8szDqjgzOTg6YCpEvkYyURzO7hOhfi/RSthbZJlagVPDnhbjWU8gLZ
         sUjS1SaR+qJ+PzTpd6DK1l8rU8Tjc5UOXY4jk+FfVmDMPOwxHKFR2TdNlD9KkVtM2By1
         yK1fQ4IDkgMIPpvaxG5TPWQz9eTgxb9TBjyDwjaofJCv9jrj6wa04eluZlsmg4Z2xVlj
         7D4p881SgPjmjNWMwhXI3bWmskVUAs1ynZC4cosQ+OipuWdmmtSR2Wa6s4pT00EBHE7d
         q+zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="gxyO/DkI";
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738796673; x=1739401473; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NxHXkRAMhKJ8Estx0a564z+y5xdswjQnexnY9Moat9A=;
        b=bzIDwZdHDuWGvNMB6qMdV2zjn2qK4UUnjRuSQdzYyOIGPxh406yeWBQ9pLgPMF7hE4
         e6OlcEexfXifddhHu77U5GipUAp4jB+qHcqDyjlnWMUDVQW5Tr7Vua7B/mR2USyIwJzE
         WfrUNYWLxpdb97QkQPwSoVg76TgRCeRQxuFAJ5IgjVtjTMd6O+PN+Yt6jO3cPJ7OJXUl
         K+YBXxTFDOhNR80/h6pOhn5qwmecNJmS2dAT8BNAlplradJuKYE9PzySnHP4LuwWPget
         EOk4LBJXpecJN/u2/pRJs8xETcrbVHshQ5dSBPZl9sgr/9+0R77/ByO/oZKBMYuOn5+y
         5Bcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738796673; x=1739401473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NxHXkRAMhKJ8Estx0a564z+y5xdswjQnexnY9Moat9A=;
        b=MPVUdy7nFa7F/9dQhzC8DgeHH7tKJtcZwPVcORGujJJ73xaHSfs9vPDiZEDD0vX7EQ
         z4sNa5hN4RCvt3vtO4Y+hltrnzmftgG0ol0e5eO2zdidYLS+DsiqQ46KE+NKh4mq7K0o
         RZrjfvThqqa69BqTjNg7S9Fww1bwX4qMfZReEBZ2Ds728XpjRyjPra/MqayhhWhXfMEL
         DQGXLhrkewxaMSjS9gzEXEPPRu0Gr7vGXkk4oir0dlggqnJ20cAcBj/9YVKYECm5Jr4T
         K3LHR7JG0xtMIGU/gYFu4RqclhOKdqb+88Xhhpqd4T6x/aRqIqCzrCK8X7NLFpCxv/9Y
         4xkg==
X-Forwarded-Encrypted: i=2; AJvYcCXdiuGsywWZoDjtNYmWlY46ft8I4iOyCV4pPjUuhs2lV/8KDDQb7Y5SMvbzolwbSJokaCSllg==@lfdr.de
X-Gm-Message-State: AOJu0YyHE4H4bT9YHulypVcYLTwytT6RfA6I4gmn+BDhFDWCjzXwO/4f
	d55uHVNenXDvJRw1tPkY4eeD0D5WuHOIcvjNnLjLHXrv2oL/T+Gb
X-Google-Smtp-Source: AGHT+IEQr45Wx8dxhrfYq+ZM/U0Z73Y1OM78Shpyf7OWiMK17XqWYUdpehcUcLN7n54VAEt//1Upkw==
X-Received: by 2002:a17:903:2406:b0:216:4b6f:dde5 with SMTP id d9443c01a7336-21f2f19b5a0mr20071245ad.13.1738796672962;
        Wed, 05 Feb 2025 15:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:38f:b0:2f1:2e10:8152 with SMTP id
 98e67ed59e1d1-2f9fde3573fls212081a91.2.-pod-prod-00-us; Wed, 05 Feb 2025
 15:04:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbsMtulJnKsy1PJE1freUy+fwa6WNNeI2fGb10UI7HQo0z6eS0pL/9IXvzsHtXUTwTB1fQmnDG/lw=@googlegroups.com
X-Received: by 2002:a17:90a:12c8:b0:2ee:7504:bb3d with SMTP id 98e67ed59e1d1-2f9fec60463mr2109971a91.0.1738796671586;
        Wed, 05 Feb 2025 15:04:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738796671; cv=none;
        d=google.com; s=arc-20240605;
        b=IiPZ1iHUURKB20FQvzqkMpLVTNUNt2tZZOV1FpOcZ4kFa7Ue+NhFGWPTH2fUMWqeIG
         04SQV+N5rlWDw4chJmAEmDffia3fkecg/oJXOROxsJD1rsvxKVW1rRyzCgsoBD2zo1Ai
         OGTxG7wsk7PuOw2A1JMVqIoY4uqfHUjKZdAXDVSf+aLyqKe1r9KQ/XM1JF2X2kZXl+b9
         WxFDvV+uKzaVaS64ljzjIq25rd2xrQa88K0BGx6FrjFfuKBcDPfVo7h7KI8ivEaocVRh
         8Ld/cCV0AD5NA6RD/gSNGzPSqg/4RBAbmRZWbxbBAZAh/8TJegJkAdJrqwcPugJaG5AO
         i5+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S72eIFvgqEoxbQM8qfvjvrlejM+2TfjiaT1i5lkDoBg=;
        fh=wMcgh+yKPiAN/1xRCV20sgyM3gfD/z681sP+goFmuss=;
        b=ZyEZJV7IOZEAROr47vsX6M4MHqWw5QxcFdcgAWrF30pM2bOL4TuSt8aI26g05g2znh
         wAqznIRKXeHVyHYrFYnEG5FK5LctJGE1+f7vt5Yc3tqGXPFmIy0NpCpxBy2YmBu9TpUk
         CtfDcxBOwKPC2/DQG5g1gXKMZSLktr2GjbnraOUw77YRyISIKm2UvCnP2JE5C4WzYDEa
         iyjIYpJeMgMdI4iIvoWanCqzpWw2vVvf6K9cOx/lJDREaT/hitVs91zN7Of2kQGyXDgu
         NrPpxKW4nzjHGnKGEUYI+/7gzM2cEvkpvazEZj13jFCRov0a5uY93bCZsj1daBY/LnG6
         wplw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="gxyO/DkI";
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21efe2d206bsi2522855ad.7.2025.02.05.15.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Feb 2025 15:04:31 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 28E055C69F4
	for <kasan-dev@googlegroups.com>; Wed,  5 Feb 2025 23:03:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 33A4BC4CEF1
	for <kasan-dev@googlegroups.com>; Wed,  5 Feb 2025 23:04:30 +0000 (UTC)
Received: by mail-lj1-f174.google.com with SMTP id 38308e7fff4ca-30225b2586cso13535871fa.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:04:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXLk/1ET5N5LYTxn2OtGNEgEUDfrBm1AuAdi6avUf1zLx1VDZhRu323AGSjxiUAqUFl3av3TGo6a3U=@googlegroups.com
X-Received: by 2002:a2e:2c12:0:b0:302:41f6:2352 with SMTP id
 38308e7fff4ca-307da5ae80amr3376651fa.16.1738796668357; Wed, 05 Feb 2025
 15:04:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org> <fb30574a-d238-424c-a464-0f7a5707c46a@intel.com>
 <3dcf7631-d839-7235-10c7-30f80d7f796a@gentwo.org>
In-Reply-To: <3dcf7631-d839-7235-10c7-30f80d7f796a@gentwo.org>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2025 00:04:17 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHktLC2F=suQoNF80-ZQ93-3pxWz20_L76_6morUGPaNQ@mail.gmail.com>
X-Gm-Features: AWEUYZnX90yX3IKaA52q5S_M7G8eGfUWUp3XkEiKOjpcZPLHNrjrrMHxTq0wSUs
Message-ID: <CAMj1kXHktLC2F=suQoNF80-ZQ93-3pxWz20_L76_6morUGPaNQ@mail.gmail.com>
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for x86
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Cc: Dave Hansen <dave.hansen@intel.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org, xin@zytor.com, 
	kirill.shutemov@linux.intel.com, palmer@dabbelt.com, tj@kernel.org, 
	andreyknvl@gmail.com, brgerst@gmail.com, dave.hansen@linux.intel.com, 
	jgross@suse.com, will@kernel.org, akpm@linux-foundation.org, arnd@arndb.de, 
	corbet@lwn.net, dvyukov@google.com, richard.weiyang@gmail.com, 
	ytcoode@gmail.com, tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
	paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
	jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, jannh@google.com, 
	bhe@redhat.com, vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, kees@kernel.org, kasan-dev@googlegroups.com, 
	x86@kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="gxyO/DkI";       spf=pass
 (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Wed, 5 Feb 2025 at 20:31, Christoph Lameter (Ampere) <cl@gentwo.org> wrote:
>
> MTE tagging is part of the processor standard for ARM64 and Linux will
> need to support the 16 byte tagging feature one way or another even if
> Intel does not like it. And AFAICT hardware tagging support is a critical
> security feature for the future.
>

Can you explain what you feel is lacking in the existing MTE support
in KAsan (enabled when selecting CONFIG_KASAN_HW_TAGS)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHktLC2F%3DsuQoNF80-ZQ93-3pxWz20_L76_6morUGPaNQ%40mail.gmail.com.
