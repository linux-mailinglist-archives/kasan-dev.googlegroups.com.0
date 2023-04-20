Return-Path: <kasan-dev+bncBCZM5DHZUQCBBLXQQWRAMGQENXQ2Y4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E8A16E9AE2
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Apr 2023 19:36:48 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-246627022c7sf746122a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Apr 2023 10:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682012206; cv=pass;
        d=google.com; s=arc-20160816;
        b=xGyLegNW3IlgfqEM2gClHXYuMN/usScdi/NRVCZtiE9wmGysOu53TF7wNSpU+1IBaw
         zI/LPMWQQrqkwIDkxW/BN7MwTdD/yL9iSUqx00DOjcIz2S3u5HMhvJZf7qbcBTudAyvU
         2wSgTvIE5N48/gbsm9F1eu4b3BFFi5f/+A+JyFqIXfE6Edza0FqEHJQ4aP0C0eJTZoZ1
         PzeODjJImwunOKkfH/J42B2U4SdoJdXDUvTrTWYamKY3ro/tv6+wyalBmQLRxIOQ+YCt
         RjgEaV9YEs4JexfUnB+ppyRrkNT8YoXlTPL7hQqzvDQV+q1AAqVfNwpYBGUnTsD8u93N
         rEzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:mime-version:date
         :message-id:subject:references:in-reply-to:sender:dkim-signature;
        bh=nC3jSakO2LBXztksZooQiK/rll34R3T64sdBBsRle50=;
        b=ILTGC3oP335jD1ml+HB3mWkXUw1kh9R6bBq8yXoi7bh4/Zh9ZXkLKvtaU4f3DSUvnR
         dsbQghak6qWUYXE0i2rnhvqDkv6L4aGy6sEyoGpoTBPObmZcHBO0Jr2HguItCGpKoqsa
         QuFvVRGB10fXg5v/sIJ56Cy5aDPnTgwDS9RKC0+2bu04NT1/DKeJRcGU0HIHDyT5JX0Z
         QiKjA9266qMfX+0BEnTsDA33S7TIm3YvFo54lIp5lh0oNX/q3tHooezBjXZ6smYAK9H+
         l61omoH/dgBdvHCT4fkzF4rzdORHLYjDnuS9iD65OXJQZf7j2hEk/IBbw9lzA7BJDZon
         htTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=R65bYw0u;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682012206; x=1684604206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:mime-version:date:message-id:subject
         :references:in-reply-to:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nC3jSakO2LBXztksZooQiK/rll34R3T64sdBBsRle50=;
        b=m+AaIPNhViwGo4DFrs/nLwF5zTDgogeOgJxuda6gbS8NezZ7xSCMOk6MU1Bo96TdOd
         tIjA9pqIaauf1urJ6vGOIFlwTKXfuhXk/PIEHOl4uMrQIJVREypzgM+Rhuh+PPN472HQ
         vNcovAvS4gJVMLpwFxAdqlDxWB4fd4timar9zMSHTUZjHLzQQJDWtJSZCverHMZA5kGJ
         UfULi2kRkhc5dS+rGrypS0c2xF9vxiLfEfmwCCKckFY6IwSWhXxtaaIVPekUP8zWnPbD
         yEsFCnrALCfVwhQSmVDpTsNodVQJFUdwmG+FaMJ3LDTkptt/8SDA/OXR31ukzlO5hejl
         CDXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682012206; x=1684604206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from
         :mime-version:date:message-id:subject:references:in-reply-to
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nC3jSakO2LBXztksZooQiK/rll34R3T64sdBBsRle50=;
        b=Lg8xvGdvTn16SN+wMFYNw2hvIOuG5W7BTY6pqpAAGafzNC7VVxsIYnsba1IQit6ADS
         8KaF42NtJvH7dD0qFF6BQfNmtAzI6rEk4QBjfJGfGJ+d0NI2Mia2nwWYH/HNh28AISRc
         88XHNK5AaNUCQ5f2uKUDzrQQsE8TgDN+RVTPmouee5x4mlpAeX9mHkc2Di1t7UDC7eFF
         GzF+ZkXZiWB9xEsDn0KiZ8oioNrsPk9B8vmqkx1/fVjBKaHy70Npj6uXdq8Xcg+a14cJ
         S8Feny5W94T/QgkLaACJwIxVJPjx3aVqOqKgSFfloyNzNxMjSBIsbB8kwx1oYIXgBfRB
         oetw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dWB1q/255nnq6Y6fuJ6MxHUQUReBa4Iz2R2Eah/10ha07CkQK9
	twszpiweBWvesZjJ7z+HMsY=
X-Google-Smtp-Source: AKy350Y+ZQck0O8FVQLhUFPVcKoX4dG1nBJZHXIRFDP9M5W+C7gpByKOcqbr6H1d59PRvHne2ZVNJQ==
X-Received: by 2002:a17:90a:4ec7:b0:246:f535:3132 with SMTP id v7-20020a17090a4ec700b00246f5353132mr643210pjl.7.1682012206572;
        Thu, 20 Apr 2023 10:36:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4282:b0:23c:1f9b:df20 with SMTP id
 p2-20020a17090a428200b0023c1f9bdf20ls2717088pjg.1.-pod-control-gmail; Thu, 20
 Apr 2023 10:36:45 -0700 (PDT)
X-Received: by 2002:a17:903:188:b0:19f:3797:d8de with SMTP id z8-20020a170903018800b0019f3797d8demr2878163plg.9.1682012205794;
        Thu, 20 Apr 2023 10:36:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682012205; cv=none;
        d=google.com; s=arc-20160816;
        b=LvqJcbGDTMeJRsEjEcDSjl9CBd+104DabedHTK6Mhks4HM3oIdFSMgI/oXl44Z13Ha
         4dJXnCiEgtcP86SPkhpq5seDH1hBVucgq+/1i8jyKK1oO7irh1EfjGPYHpadJTZEJkbE
         ts4iK4I/3O6WxR4KyZbl96QeUDiqSGIgZc9uLRTtTQlxj0AMoN7gxIj6NsQD5upKjtqK
         yK2zE6BLf9yGz1m7Tf80rp9+LRo4nCd3GyK+lCmQoO83HUjgxKVOZNlp4wSJq7zf4Cm0
         QNqdW8x4KrCPTytRvvC9sWlqL3dNi8CgvTzubwCosoAuhU+VqG91EiLlytnWMUQoU05m
         yQag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:content-transfer-encoding:mime-version:date:message-id
         :subject:references:in-reply-to:dkim-signature;
        bh=JnRCEEUMbL4VHxSaKuZGWLgXCAjCR6wrwzaIjE1iCNc=;
        b=a/+pGLuYpyZpYU9Rq25ps027dUPgU2m3eZ/9QHaMujrs2WC5x3lockgA1kXueVBkq1
         LKa7/xFYkrvIAwCQzCW31vhTW2Y6riNYdysmjv7ggNZfryEmdfMJDO9yXPcrM+cdlzyd
         WLSaDJAZPl6ZxPTPCtOU3+7rr2/biYbNyHKMdRCNmHJwVvqib+MQUOcNAEPe+0pT0BrW
         sV1IfGcoJ2PJ6smXo8T0Ee6Ve408f2fgG2Y4J5qp8ADiJ68m6fW4+m8OKgaYejhB/XZb
         27iiyZRV7XwZ7UhI1SdQX81zHrVOsAFraAlDt4cHiYH7kaj5/3890riGZyo4MQwHyNow
         RgLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=R65bYw0u;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id oc7-20020a17090b1c0700b0024705d6c0e5si93508pjb.2.2023.04.20.10.36.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Apr 2023 10:36:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-63b35789313so1029066b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Apr 2023 10:36:45 -0700 (PDT)
X-Received: by 2002:a05:6a00:1144:b0:63f:120a:1d96 with SMTP id b4-20020a056a00114400b0063f120a1d96mr1084389pfm.11.1682012205312;
        Thu, 20 Apr 2023 10:36:45 -0700 (PDT)
Received: from localhost ([50.221.140.188])
        by smtp.gmail.com with ESMTPSA id j16-20020aa783d0000000b0063efe2f3ecdsm1489431pfn.204.2023.04.20.10.36.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Apr 2023 10:36:44 -0700 (PDT)
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 0/6] RISC-V kasan rework
Message-Id: <168201218500.13763.4099213624397858271.b4-ty@rivosinc.com>
Date: Thu, 20 Apr 2023 10:36:25 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.13-dev-901c5
From: Palmer Dabbelt <palmer@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
  Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
  Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
  Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, Conor Dooley <conor@kernel.org>,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
  linux-efi@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>
X-Original-Sender: palmer@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208
 header.b=R65bYw0u;       spf=pass (google.com: domain of palmer@rivosinc.com
 designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
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


On Fri, 03 Feb 2023 08:52:26 +0100, Alexandre Ghiti wrote:
> As described in patch 2, our current kasan implementation is intricate,
> so I tried to simplify the implementation and mimic what arm64/x86 are
> doing.
> 
> In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
> instrumentation: all kasan configurations were tested on a large ubuntu
> kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.
> 
> [...]

Applied, thanks!

[1/6] riscv: Split early and final KASAN population functions
      https://git.kernel.org/palmer/c/cd0334e1c091
[2/6] riscv: Rework kasan population functions
      https://git.kernel.org/palmer/c/96f9d4daf745
[3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
      https://git.kernel.org/palmer/c/401e84488800
[4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
      https://git.kernel.org/palmer/c/617955ca6e27
[5/6] riscv: Fix ptdump when KASAN is enabled
      https://git.kernel.org/palmer/c/ecd7ebaf0b5a
[6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
      https://git.kernel.org/palmer/c/864046c512c2

Best regards,
-- 
Palmer Dabbelt <palmer@rivosinc.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168201218500.13763.4099213624397858271.b4-ty%40rivosinc.com.
