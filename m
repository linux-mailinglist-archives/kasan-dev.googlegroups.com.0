Return-Path: <kasan-dev+bncBCZM5DHZUQCBBJGAQ6SAMGQE2FBGWEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0770F72822B
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Jun 2023 16:05:27 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-259a3c7fda7sf610287a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jun 2023 07:05:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686233125; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4ZQYygJgq21pG+JWe4O2e3Dlt5vc6GOOwGVScSepUwHMIQiRXs+v3ta9IzficVvoY
         RjAgwUC4xUJ/Dpdw9Gv7t6o8Fbzius5Iki0Sf+Zx0zrFWOcobl0rv/tisk+OfEBGKJic
         u3E8ZQYxhjPO1NAhf5AjKayRQCeayhNifyIBbflWtMBKLD6uo3c6QmTKyiUhd35bjDmY
         hYzgfRwes1P1PsoXAWB9jy/NgluHPOXagjzNbvWbV3APAB/D0t2oUvtGdjshmMEpQNJh
         CaUG3PwwVadkoH9ogonwDpLb0JVzRIxZPwWINJ6+Pi7Hp5HXrVFGj5EN0Xi9Fys7S3aC
         xypw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:cc:mime-version:date
         :message-id:subject:references:in-reply-to:sender:dkim-signature;
        bh=aC9hjS+v1tEL5T6pfoMjAabjrgY1exAPx3519q5OaSM=;
        b=CFwAFxcvjpgfRltlHn5bLI/SjF7yi4vtsBJYywxt8FkxA5GoQJBO5zV80pmVHCHapA
         KhIxGKo4RqXU+7i6/VEI1b4hKDzoWQKKnm01NwEbnfZvZn1s5ofzxtZcvhFtfqx8XsHc
         m3pAfDjMqnblzRqyOhEiNldBgordbVhMv9BK3qUtE+TKIf+FbDtk0SFJTZazGokK6et8
         McooHMFMCipskec5EGcT2hGpZSWn9Zx+KXjD4zlcB+rzrDgCn2IJjOCJKga5SNzbCQ0l
         PcrbQMWH10NTsaOSZvFdlzXj4wwXK0A24lbDeznuDJjEuNn1ZpM6D4oK/qXR8iOgp95b
         zsBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=dWFaFLnb;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686233125; x=1688825125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:cc:mime-version:date:message-id:subject
         :references:in-reply-to:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aC9hjS+v1tEL5T6pfoMjAabjrgY1exAPx3519q5OaSM=;
        b=YKv9sUiz2+GwiZBxyXNBekB/8sXpc3HuMKGkdA/MIUos8HU3hl6jk4AoTzuojanJLV
         cwVAAfqA7XYrwR+x+aT2iXGbTHGLWCDAT1oOMVYhuecqTHDEq9AhBlyaZSKcUKYYOgZM
         u6kmOgQLJlJpeLp7kApS+Km65o/ZcCZHFaETOO6f3r3rAbkXhQZm2fFGYFEYJbK9impl
         mml7mEwibsHNJM26w3SOMWDPwcG3tfwkbV0+vTfBcJAzw6CNgaNrexJ/Hc0oi4zipoq3
         D7e/OeOPe+OvxiGjugM8RbYAmHZae7iG6JV5Di+jfxTxOaaMvqbvRPIlVfjrK+ItIWOB
         aVWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686233125; x=1688825125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:cc
         :mime-version:date:message-id:subject:references:in-reply-to
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aC9hjS+v1tEL5T6pfoMjAabjrgY1exAPx3519q5OaSM=;
        b=kJc4DsP82l1Y3Th6r8nFGLDv9etmU+6nGA5DtoZP+FLzCtp95qBKVmL13AmceHY4RQ
         sDpm6/kWw0V0FPZKnxhQ1SyAz/rlhyV0+hmp3wAgvEExPIhNbV85UJZBn0V2onYtEh3R
         AWn8vFXySXZThWINekXfopbA25SdqjgJ2EA9ZddOhQljtpdlVMzZ+0Mr7DPUdvI8Cdhg
         RNLGnofEACBQwg+zvCYdwUj+aNooRytcpBGmsq++oODrV3oWR70pgfowLZDRSzLQOK20
         VAtU2QlN7yFjHvbI4bKA+WWIpsavlRJwOkxs3i/27b328xVRLAUu+hzVNsI3nNbrrOql
         njBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwaKmqdeZBVMEh1Tb3PbQFKlZiOSTTyGcdjy/1O+9bgrCFp+06s
	AxMzxcok6JaN98Ibdx1a0r8=
X-Google-Smtp-Source: ACHHUZ6ibM9uoWXp7AqYcfZ2y7hSxNe3wGLNhcL9M7splJNO+q5BoRV6MwUII3dmI2tVlUH1HICOaw==
X-Received: by 2002:a17:90a:3d04:b0:259:b504:5840 with SMTP id h4-20020a17090a3d0400b00259b5045840mr5819109pjc.0.1686233124805;
        Thu, 08 Jun 2023 07:05:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3890:b0:250:1af8:3324 with SMTP id
 mu16-20020a17090b389000b002501af83324ls1125967pjb.0.-pod-prod-08-us; Thu, 08
 Jun 2023 07:05:24 -0700 (PDT)
X-Received: by 2002:a05:6a20:429f:b0:10b:6e18:b694 with SMTP id o31-20020a056a20429f00b0010b6e18b694mr7462020pzj.55.1686233124020;
        Thu, 08 Jun 2023 07:05:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686233124; cv=none;
        d=google.com; s=arc-20160816;
        b=NumfeMTdCbs4+wKaMp3XW6KIswLA6Z+rpfZNGZM4bRD01Knv/QfAGnRww5AeWN2qLu
         nKtE9zM0KerQIaYT6DOWywodPUfHPUMQeOaeEjJCnD9zHfE3XOZJTSeiOO/v461XpE9G
         fSnXSjuE6dk7tSl5B3frzG9k6hyWwaG0Xc+iQTjw825s74NnOFt0vyaeCcUqacl1H6TF
         XbZlfNIhMMx1UyhaFhe5eSZZUgnWDMEQrJp3ODs6pDGaORruljJDPqBFl6owljblNhaT
         v21M6C9agkoJve7PsvrQKhwhM0zNMGwRQ3FB35jLx/PoQiNfcFMRIe6YJp1Fz9n1cwwS
         +62w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:cc:content-transfer-encoding:mime-version:date:message-id
         :subject:references:in-reply-to:dkim-signature;
        bh=iiTCui1w+W8sNchnu7jhDwLSkHbv4+LC8J3CAsZCpJw=;
        b=wQxpSTaZTUey9/z3BU2bXlOBRirynbEu8n9WhgM7MUEfgerGcpSdGA87ofRFCMl+Op
         8KzZ7M6vzevy+dAYJ8EcsRTJZvJ9Mcw1V22bZOjyV0X8js86hX38sh+T1SI3MKk5MZRb
         2yknUR8bsElvv4hTA534WmHG/z1zRhholSrhjt7/Y9tiHtFFHK+JCclebByWdDH+fnW/
         gmnY+FXb7TXUI6j4wQKv0dy6ZWA8730COl0vBQwGY/hWBsHjTHr0OPi7DqDJmKpR5pCw
         iwRvSY2k6TJKSGxfTUcdRal3N2HmpoNhkT1CL2YuawwPbeVdnM7Wlc4zJQKlFCIHPQBU
         ijOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=dWFaFLnb;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id q4-20020a63e944000000b0053f352e1980si98637pgj.4.2023.06.08.07.05.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Jun 2023 07:05:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1b04706c974so4614295ad.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Jun 2023 07:05:23 -0700 (PDT)
X-Received: by 2002:a17:902:c411:b0:1ac:5717:fd5 with SMTP id k17-20020a170902c41100b001ac57170fd5mr11654586plk.60.1686233123522;
        Thu, 08 Jun 2023 07:05:23 -0700 (PDT)
Received: from localhost ([135.180.227.0])
        by smtp.gmail.com with ESMTPSA id f10-20020a170902860a00b00192aa53a7d5sm1502362plo.8.2023.06.08.07.05.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Jun 2023 07:05:22 -0700 (PDT)
In-Reply-To: <20230606130444.25090-1-alexghiti@rivosinc.com>
References: <20230606130444.25090-1-alexghiti@rivosinc.com>
Subject: Re: [PATCH] riscv: Fix kfence now that the linear mapping can be
 backed by PUD/P4D/PGD
Message-Id: <168623309503.19530.6891077660786418703.b4-ty@rivosinc.com>
Date: Thu, 08 Jun 2023 07:04:55 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.13-dev-901c5
Cc: syzbot+a74d57bddabbedd75135@syzkaller.appspotmail.com
From: Palmer Dabbelt <palmer@rivosinc.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
  Dmitry Vyukov <dvyukov@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
  Albert Ou <aou@eecs.berkeley.edu>, Rob Herring <robh@kernel.org>, Anup Patel <anup@brainfault.org>,
  Andrew Jones <ajones@ventanamicro.com>, kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>
X-Original-Sender: palmer@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208
 header.b=dWFaFLnb;       spf=pass (google.com: domain of palmer@rivosinc.com
 designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
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


On Tue, 06 Jun 2023 15:04:44 +0200, Alexandre Ghiti wrote:
> RISC-V Kfence implementation used to rely on the fact the linear mapping
> was backed by at most PMD hugepages, which is not true anymore since
> commit 3335068f8721 ("riscv: Use PUD/P4D/PGD pages for the linear
> mapping").
> 
> Instead of splitting PUD/P4D/PGD mappings afterwards, directly map the
> kfence pool region using PTE mappings by allocating this region before
> setup_vm_final().
> 
> [...]

Applied, thanks!

[1/1] riscv: Fix kfence now that the linear mapping can be backed by PUD/P4D/PGD
      https://git.kernel.org/palmer/c/25abe0db9243

Best regards,
-- 
Palmer Dabbelt <palmer@rivosinc.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168623309503.19530.6891077660786418703.b4-ty%40rivosinc.com.
