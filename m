Return-Path: <kasan-dev+bncBCZM5DHZUQCBBDF2RORAMGQEE66E47I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B9536EB1EA
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 20:59:26 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-32b42b751bcsf15569705ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 11:59:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682103565; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qr66aQrMoumRYStRgjEokegRbNbLVbjFXNKibIQ3migOE4wCP05VZbwLe7buzMSsBb
         M6YRYAWBaFRg/qfqBNu+SiD2EPZT8ju6iRYzb15ehwgpxq3+e4XHrYjN7UBxF7bAbcmM
         pBRViFHCT9iiiRZjrrOUmaOx9aA5bThVBiFdE1YNBiPV53ooUx4AUU8oRpSyPzMbxpbm
         gx4qJB3JlP8x7I3KIJYY6uJQufwwFNlMWq4AOBZWz9nX2NEF9K+rPqEFO3ZymdqKIbrr
         YH7ZXSwAiuBVMHzMSGazZM7rbw+u4QyzFW+PpJ6Da5BDP4KGZGgQSI8A0tlYsC6QTlql
         5KhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:mime-version:date
         :message-id:subject:references:in-reply-to:sender:dkim-signature;
        bh=x9/ayrAj141S1dVRmrq0cx7R2icQ/vRcoH9+7m6VWb8=;
        b=s6HcCD8rnv8G1Nv2wXIorftdyi5EWkzQDtnyAKIyeaFa5xMTuX9qjV1SxTCfdCSZnu
         9SIm6mNPMyvZbsI72J3qS3HH19KKsWl88k71JOIOzrDKIQTg/I5GvUtC3NU6F7yBs/2Q
         cfrod7w7xn7Vd+1f7zP7zplsiAj5bX2yKN7dv4evf2FPIF1QMrtgKImv6Db87qVKnyAl
         N7P4Zj/R4fZbLhbUYIRQPjx0pO1ECufahKRTdx/25GQ/nWx5u30ZHzat/OOq73bh4Slh
         66scLfkar207clTyazvjnTapT+Py9e9YD9mjpGpm5BmnH3c51oULU8yQjcJ7OjduxGCD
         MG5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=1eyKirCq;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682103565; x=1684695565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:mime-version:date:message-id:subject
         :references:in-reply-to:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x9/ayrAj141S1dVRmrq0cx7R2icQ/vRcoH9+7m6VWb8=;
        b=GRIKVgz5tr81ObQ56idtvWKaL8D1FFQEjGY+zjILN5xpqp3qfyXahQa7dWQXGkJXeb
         KUJ7W0SOuoign0jJANcwE70NSkF84Tj0RuS/ghCd7AUgtyC8+QKKlgpbR441P7AH5XVd
         AsF844P83r0G9CYR0EV4hpsRB4AGF9P0EVfQu6S7BIo1klOFCshmqZ9Y/EqhUOvMwsRx
         qUPg8Y/Riojrlw+xfNYSkZyEvUW9USdWRQGctJPvhEgUedE5IC0MV81ooQPIkchmUB5+
         5CkhauuQS77avnSncKR7XPRnbvjBF4fovdfQH0HPtG7JW8k/UbbCCg+ClFf6R2VQOaZU
         2qOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682103565; x=1684695565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from
         :mime-version:date:message-id:subject:references:in-reply-to
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x9/ayrAj141S1dVRmrq0cx7R2icQ/vRcoH9+7m6VWb8=;
        b=OO8WTGm2f8o3qA1C8xepmv/GKd7gNBRhl8qoz4z58nU/7+vnpVCGO1Q2TaL9/L6KIs
         hIBiTdHZeelp3yeRE3DyN8ze+evt3r5Bl5HwPY01PVWBwJ+EjjjRE72fYL6UaoLFeIIP
         WSaeXIYxlbNUSGUWMco/lSDqxoq94JOMZhkh7MlmjrBEeHnxotTBIYYUKzeM/H6EgO8E
         hOJTWCA2smdREBkyTieyj0oq6toBef6EP1ij6VXC3pT6yxN53XifIsDGQOYZpcYRMG7j
         sUQ53UVR2z5HdxyinUjWTI69wU7btKye6bp6X/PIzJwiPnvu8LwvtTNDO6EWLuJBshwq
         SkaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9enU6Htr71XQx/UUZdPYMp9acni7C7A6isHg8Dl0cfAcFQ8r6z1
	mRooRE4vQrU6v0LxsDbUIsKP2A==
X-Google-Smtp-Source: AKy350bzpALgDJ/h1grISos/cXFnKcukY/veO+GcyoXobre6iwSWgYYNq39M3keZnwtUJ1vZkqcTxw==
X-Received: by 2002:a92:c0c2:0:b0:32b:8bf:4d77 with SMTP id t2-20020a92c0c2000000b0032b08bf4d77mr3356175ilf.1.1682103564773;
        Fri, 21 Apr 2023 11:59:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1201:b0:328:fee0:eb77 with SMTP id
 a1-20020a056e02120100b00328fee0eb77ls1989764ilq.5.-pod-prod-gmail; Fri, 21
 Apr 2023 11:59:24 -0700 (PDT)
X-Received: by 2002:a92:dc82:0:b0:328:6e2d:5a2d with SMTP id c2-20020a92dc82000000b003286e2d5a2dmr3699732iln.6.1682103564230;
        Fri, 21 Apr 2023 11:59:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682103564; cv=none;
        d=google.com; s=arc-20160816;
        b=jd0Ufg9Iop3AYE45+GtzQrKP/HgnXcuQUMFLPyO9NBNV/a0CNqIjU94WXHpGjRvCJp
         0yU3EasPNaMflN6pHBZ5UF8tQbKDhx8Thr5jPTTg5/H/1GxCf1FnlLWD3rK5UlQMzmTl
         K78gWXmYGt2Q/8hvK1PbelLkPIy9GzQN3/QBwcM86LoWNDXnj3N0MpH0sl2GmucbYi3h
         CVAhaBHJzxDcB34Cx+jYvP4MUFK0ACcU3QrSig3Xg6pG1DukVRSwajdxOPq1Pj4gGPUc
         sOfWa6uOZCQ6reJrfhPOR5/6Z2Rlb5Jvh7BPgCNaxBraWiOUEjuHq3/MWPGCY++mWfSY
         GeDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:content-transfer-encoding:mime-version:date:message-id
         :subject:references:in-reply-to:dkim-signature;
        bh=JnRCEEUMbL4VHxSaKuZGWLgXCAjCR6wrwzaIjE1iCNc=;
        b=OvRELIVEGrgr8SS5KyrKXXu/cejRHLjwaqe4An7tEJbysTNgqkv14vp9SZop2GeIqW
         r0McxMFd3LIcjWGcAUsg9oWdGNVaa/mJF7/3ROTcUtAagFLK5G7c/LnQA15JYZlJ6j8X
         PWbis7BMw/S7JRAbcYcL6qES2rMJoG529AF8C1jYAtUH+Js57UEkWfBe69mkg09V6fTF
         t5/4S3dRJ0H/lQ7Idy4CkRc0CgaVsSDtAcwzxSoc4C3DX1g88B0npCm9DHXrr0JYeCkS
         WBDofbNtIiqQSJV7tSEQSyrgc1gb4Wn6mESWbqeZC2WTPpKTccB6dn/uPHHBiM0+kU9/
         oJYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20221208.gappssmtp.com header.s=20221208 header.b=1eyKirCq;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@rivosinc.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id x8-20020a927c08000000b0032616e0cb6asi150541ilc.2.2023.04.21.11.59.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Apr 2023 11:59:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1a68f2345c5so22030635ad.2
        for <kasan-dev@googlegroups.com>; Fri, 21 Apr 2023 11:59:24 -0700 (PDT)
X-Received: by 2002:a17:903:41d1:b0:1a6:492c:df22 with SMTP id u17-20020a17090341d100b001a6492cdf22mr7006809ple.17.1682103563482;
        Fri, 21 Apr 2023 11:59:23 -0700 (PDT)
Received: from localhost ([135.180.227.0])
        by smtp.gmail.com with ESMTPSA id k9-20020a170902ba8900b001a0742b0806sm3055707pls.108.2023.04.21.11.59.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Apr 2023 11:59:22 -0700 (PDT)
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 0/6] RISC-V kasan rework
Message-Id: <168191616322.7488.11200893464689398522.b4-ty@rivosinc.com>
Date: Wed, 19 Apr 2023 07:56:03 -0700
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
 header.b=1eyKirCq;       spf=pass (google.com: domain of palmer@rivosinc.com
 designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168191616322.7488.11200893464689398522.b4-ty%40rivosinc.com.
