Return-Path: <kasan-dev+bncBDA5JVXUX4ERBHV677EQMGQEEM6ZRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id CD518CBD52F
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 11:12:47 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-6496f5da246sf2830058a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 02:12:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765793567; cv=pass;
        d=google.com; s=arc-20240605;
        b=igsutUvtOHZp2mAvNKpVUGGDcGM+8j//cs7MgLAZvwLyImB67SH7jDbfJ32DZ/BK3s
         S8ejrdA+vObARmAYDA2naGtX9YOchQBhZ36fmdxdH5j5qhVClFhdgF3y3VLckYbxOI6d
         bhnMiR4UKHbHNJOuXCZu8iE/slznJhr63H+9jLMmHC7fNxWnovwi4aOddD+aZu8cGgYJ
         AxxCbBvUpfu8fprFA4PmQpfsnq1dOYMsoyIxPNV65x4ZKA5Phuj+f/qumdNmgsY8Ddwg
         +VQNKfgNbM14bVhpILL05+8dv0B3LTlUDZaCX4/9F/NRy//9YAVLdxRVmHmik6iLDTXw
         tKdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=bdmS/fcXlRegDYjzscHwoktq3NgJAHvDtQCDxdCrWe8=;
        fh=fYuStXsjPAWOSH1A6mscfg7zsXujzgKrNiTHj2Iz+yQ=;
        b=i93cp1tVxCHJvglXNJeoCCrekTKaLAxUjrJDat6B4SvB9leYPH0SUFxXd4uaEVKXAk
         L9VQvmmwASLRwMXJ4qMfADYsghtLlY0gtKgRoO5/nHTPrHfltkyN4rfEQbRPcM4tWTqR
         ADVSkPUCMHDJ0F9oNht3V+y05pMKya+cdAGXdFvC4oGOzq2vZ/AfrJIaaUJgszd15ZRQ
         ERdweKK0JBKugyFbK/uPSXDLdQRKiIvUWnl+kj0eQRla7c1EMZg52tgrm5z3HQvBlJUW
         WmBiXc1AKg0gPIhwUlWyqa6gdBrGQRaTEMnpMvg51ZCb3aEwyach+prP4f8GeuJqyxL8
         DKvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V3NVI3VX;
       spf=pass (google.com: domain of 3g98_aqgkcsopgiqsgthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3G98_aQgKCSoPGIQSGTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765793567; x=1766398367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bdmS/fcXlRegDYjzscHwoktq3NgJAHvDtQCDxdCrWe8=;
        b=V4+p1+AK3W3rnavOHTWYyKiIIe3rrRLmrDJ9LluvknfD1yyAHEX+IkTQ/vLZ345f6H
         QqUWjYLxfgQnaVn0SG6jTxohninvXO5Y2J1QUh4K80OeHCywlWBrREEwmR0+NrtoWd6B
         jdIbqtpEqE2meIc/SQMNTAnzQ39w5BSv/bEZ6vl19Lx0e4HhqRBOq+uVJWJUqgYMeIjD
         ZmPdwDPrv0RpOANTtZv8EBiCXroZGGcvOClYkpXL0SqFMAG3WXzJR9jznl2QgzKTIFN7
         fJs6Gjt9s2FahhHza2WQq4j1bJyHE1hdUKbHIw1W/U60cd9y6JQZ8R1630x9b9C3hVOH
         i45Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765793567; x=1766398367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bdmS/fcXlRegDYjzscHwoktq3NgJAHvDtQCDxdCrWe8=;
        b=LrC01mYKu2TParTk8BVE7ISW7iyQlBehWtsMpRHNfnPpZ8tblWbMnbR3EhGpxd6wIn
         N8RFM/lIL9S+mmO8bUGNJ6Mz9InpgiEnFZCvuTHzBlRlr8O2zQdE/UqcTjJyMAcTxdYP
         r+MoLZusHpPxypQuGAcKgczcQ12H880OMsnKfml7yTBMSBVJx/6dieiOaivHUa95MByd
         YaWNX8hBsbX//dyTgXAu7gKoQTmT6/xJCfEsUHsXhGgvLk2zFMINW5Bv6bcTJYVZR9vv
         BJWP04ZZOdIvetG9VypeZmI1a3qwxmRmAQXxDu3qSZJD+Keu+i9LIW9oUOp5TDf+VW+M
         Odkw==
X-Forwarded-Encrypted: i=2; AJvYcCUQYIsQkx22XZpzYnM93n2vKlkGZub+IpljaV4ZX5maFaZ4lCwl9M719ufqLIgBjfUcIHgcyg==@lfdr.de
X-Gm-Message-State: AOJu0Yz6UVSIOpUv/mXdb8E1FqXDdxux8EYhRUn986/n8udqbGcn4K2o
	g/wNioV3mQh16N2J8vSejIO64Kn2Gyj1pK/evpTEVhSWVCTLaFMHzTnP
X-Google-Smtp-Source: AGHT+IHppBTXAiHq9wgn5n86SBpyk0azplltyEB1h0K9818abuuRLf+oJ2ZxSrFSpYsj5hcx7OMy7g==
X-Received: by 2002:a05:6402:2812:b0:649:838b:61fc with SMTP id 4fb4d7f45d1cf-6499b1b87d4mr10059684a12.22.1765793566847;
        Mon, 15 Dec 2025 02:12:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWasIPmYuH+2OCOy5Ox7yJhu9fdmq06ME+VfmGxhrpe6GA=="
Received: by 2002:a05:6402:4610:20b0:649:784c:cac1 with SMTP id
 4fb4d7f45d1cf-6499a433fe7ls2127602a12.2.-pod-prod-09-eu; Mon, 15 Dec 2025
 02:12:44 -0800 (PST)
X-Received: by 2002:a17:906:cc45:b0:b7d:406f:2d4c with SMTP id a640c23a62f3a-b7d406f4273mr477050466b.53.1765793564101;
        Mon, 15 Dec 2025 02:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765793564; cv=none;
        d=google.com; s=arc-20240605;
        b=CjGPAAx7HVVVXfvqaE2A5I94yY+c0F4Fdt9pxBLzeyn1F070bfrsAzPc/kpHlAcgCN
         fGXV2X/aqrw0kMOtSvOGxkvpmiOjzigeSULA+5LobXoTopeR+hX78+QTfX2U6pBtEIrY
         BaqnS5yz0P4KTSTaKl9qYuV8nIvg/3wmzd+pn+DQMlave86yA5yOcppgdkxN6YFPBAyu
         mBIlk//ZVm7lcwGCJTa+krj60CrOOwggmX1KCGm7xJh6Qul8HoVOyZaxbg+u9mvI37tg
         jqodPsC+G7YXDVehCocIQMY/h4/4O52zGQ1B/81BFK1vRI72GL3nW7GpSXxAeJjAH+A5
         /uTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=VN0V1tPgvY8SofsZQUsWAMHh5jjoUhKRWaN4QsOByNk=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=fPE1gX+E9HChSfl1AJ4aMJEhf4xnK1bjkHw1mgp1cIKjhSQuwOVhIbCRZdPmv20joQ
         BxdAN5d1smdfXidyjfgQNGC81UFkoGQ1X1e1NE4D4pNRAds1xz2yfhb8a9zJ4iq/tiWY
         4nSMfkWhoIYQd29tFEdHLNgcjNup7Vtse88e425SIROe+HURv537B6ZkEMtHIWalGCX4
         ngHmcGaIGx7/DQHARjGuhkG0Tb4k1T22Z+QKfwcCIrYIDLEprwvLc18wDRyfFxshu92o
         kUln4uL9aLDVpyDi9mKPj+vhWiqWDOz6E3dNXAWtVP13YBr1+gHOwBpDsKV0AaYpBSGQ
         XsCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V3NVI3VX;
       spf=pass (google.com: domain of 3g98_aqgkcsopgiqsgthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3G98_aQgKCSoPGIQSGTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-649820df1acsi241632a12.5.2025.12.15.02.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 02:12:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3g98_aqgkcsopgiqsgthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779d8fd4ecso16280125e9.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 02:12:44 -0800 (PST)
X-Received: from wmbgx1.prod.google.com ([2002:a05:600c:8581:b0:477:9856:8f53])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:4d98:b0:477:5639:ff66 with SMTP id 5b1f17b1804b1-47a89ed5c1emr93875665e9.13.1765793563729;
 Mon, 15 Dec 2025 02:12:43 -0800 (PST)
Date: Mon, 15 Dec 2025 10:12:38 +0000
Mime-Version: 1.0
X-B4-Tracking: v=1; b=H4sIABbfP2kC/32NQQrCMBBFr1Jm7UgSEy2uvId0UeI0HagZSUpQS
 u5u7AFcvgf//Q0yJaYM126DRIUzS2xgDh34eYyBkB+NwSjjtFE9Bi8FOS4cCaNwzGtC7ZzyE5G 1zkNbvhJN/N6r96HxzHmV9NlPiv7Z/72iUeHZnLzt/egu2t6CSFjo6OUJQ631C/aMKNW3AAAA
X-Change-Id: 20251208-gcov-inline-noinstr-1550cfee445c
X-Mailer: b4 0.14.2
Message-ID: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
Subject: [PATCH v2 0/3] Noinstr fixes for K[CA]SAN with GCOV
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=V3NVI3VX;       spf=pass
 (google.com: domain of 3g98_aqgkcsopgiqsgthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3G98_aQgKCSoPGIQSGTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

Details:

 - =E2=9D=AF=E2=9D=AF  clang --version
   Debian clang version 19.1.7 (3+build5)
   Target: x86_64-pc-linux-gnu
   Thread model: posix
   InstalledDir: /usr/lib/llvm-19/bin

 - Kernel config:

   https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f053=
7e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt

Note I also get this error:

vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR: =
machine_kexec_prepare+0x810

That one's a total mystery to me. I guess it's better to "fix" the SEV
one independently rather than waiting until I know how to fix them both.

Note I also mentioned other similar errors in [0]. Those errors don't
exist in Linus' master and I didn't note down where I saw them. Either
they have since been fixed, or I observed them in Google's internal
codebase where they were instroduced downstream.

As discussed in [2], the GCOV+*SAN issue is attacked from two angles:
both adding __always_inline to the instrumentation helpers AND disabling
GCOV for noinstr.c. Only one or the other of these things is needed to
make the build error go away, but they both make sense in their own
right and both may serve to prevent other similar errors from cropping
up in future.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
Changes in v2:
- Also disable GCOV for noinstr.c (i.e. squash in [0]).
- Link to v1: [2]=20

[0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
[1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7790d5=
4df@google.com/
[2] https://lore.kernel.org/r/20251208-gcov-inline-noinstr-v1-0-623c48ca571=
4@google.com

---
Brendan Jackman (3):
      kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
      kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
      x86/sev: Disable GCOV on noinstr object

 arch/x86/coco/sev/Makefile   | 2 ++
 include/linux/kasan-checks.h | 4 ++--
 include/linux/kcsan-checks.h | 2 +-
 3 files changed, 5 insertions(+), 3 deletions(-)
---
base-commit: 8f0b4cce4481fb22653697cced8d0d04027cb1e8
change-id: 20251208-gcov-inline-noinstr-1550cfee445c

Best regards,
--=20
Brendan Jackman <jackmanb@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251215-gcov-inline-noinstr-v2-0-6f100b94fa99%40google.com.
