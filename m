Return-Path: <kasan-dev+bncBDB3VRFH7QKRBON3ZPDAMGQEARCFCKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 504E8B971A4
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:47 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4d6fc3d74a2sf9403321cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649786; cv=pass;
        d=google.com; s=arc-20240605;
        b=lSUr3LrtYITWFL2t2StS466L6J34EybBGzMeGVVT5dj1t2d/VjK6DyJjYrMZMewN6q
         6MGxyIeSa55wi7ztlwrZUbUzYWKRhGyb2xMP5Bty2TJ7fUfYx5qTfCBvxANEOhe/C1ky
         5iyzaGIGe0+qgZrlsDPvBs4WiZ48jSJp5npE2glXPxjjwht6INrkFUOuvHI3i/cEbvCZ
         Z8hpJuTuPgBb1LvvjkVjLK+kalRAUk/xXZHJAwYVHYBDkqbOuuRUZYIEeN63UEFyfrxZ
         7gNOVT4rnL4W0/tROVjiL/QN2H+V2mRTFjG+fxjwrm7G943fhp3v32XAV2frdYsbbgnG
         iZxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1GfkXeL3+GdsB/vC520TtNIDdIT4EmrZUX03Y78L9/c=;
        fh=lB4FYg/HUsz8+Zd8ARiLBCFdTXWcTP4U9uC9HYHR/rY=;
        b=CfnBZtv1AkB5+ZDa8gNb/xvbBJtSWVjF5vVVMnzZLMCJ1v9JX7VjbjQIxnVK8hETNO
         YaIUnDbf/S7Dd6qnmlh1+9UUC4i4uU9hq6G+g+SVZWUsypOHsa2UW7n66dZZXHJ0spAx
         nYUCuKkArNRwVAcQzqRcSSgTt9DQNgS7i62JNVi/o/H7Fz1q5M+NEQEYETjAAK+DGnR/
         k3UFaGFxw+gd9NNL3Sp7m/zihDmlQjwS2iuMdHua+rHxwGUnam1EvOiyh+s0kpOtIH6p
         NJFDm1cLwNOJZHpT4YreNIe3gbsMeAcfwRUvwnYYQWa/ESJNrPuw7QQuazp0KV29Dh0+
         s0sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649786; x=1759254586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1GfkXeL3+GdsB/vC520TtNIDdIT4EmrZUX03Y78L9/c=;
        b=TdPz5o9dT/gSOXWV3b4t6xfwKWan9NNhvg6819x8v8nppAg6lW66k40IOGRF4M/xNC
         r5g7K2Y/aLfGGjMzJyh4UL/jPpUa99CSMFDvWfBpMxPvQxZUoO+dZVqjCKfa2+DgQ8Wc
         iZ5ZcbmkX66sXCIjM6YofAPRcZUim7X56IVwIK25yFa/fZGRO1+IjL61kLG/hlc4sItN
         4HVR9pRg0IYl2Lb3xE6BW8tKKry0UjqiMmXMKH8G9nbwlIJkWF67JhRsCuEWQdTv6GPt
         ghU/l+YuCNGCBaHYo86uqYRx3izguEusyT4/NN7v2La3cjvEu54jn2XniwHOvRdr0jbg
         2a9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649786; x=1759254586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1GfkXeL3+GdsB/vC520TtNIDdIT4EmrZUX03Y78L9/c=;
        b=h3Jfdw4WyTDbidBt/kzKSvZ1jF24X405+KoH/axW3n6F4f8zCuV7DQRbjb0hGeeTjT
         EJ2EsMKClOBjQKFtt9qATiFlKzXbItjOvCIAKnWhSA28YeRpmrS4wr4Gre7VCRlIUl+C
         rsKSOPrZXUI++oO9I+4D5ioerYrFf2BZeoRDjeYPprMC00rjATvFP5c7WSBLGeRgCNf7
         xr3TQksPFTa+iX3mr/96yqdTi+B/6R8s14dAc+gp8jvu76Tb880RN6THz9RV0Tbopr3r
         4w0Kc/i4dJs5uTqTV4qK9vhjBC3gXhViPC0vPB7eg3M7WHxG6hccld9HWKqVjn+/aPvi
         KfwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgi9ckvYsVba1BPLiMaJzKfC9Lq+SzMdz+ENTN6GomofyNFSQ6YtVd7lAebAGfAlhV4e2Cqw==@lfdr.de
X-Gm-Message-State: AOJu0YymohdUvjcHlCY2UuaeDJz0XM+rTeTGBknVmKQzETXNWLpY9Exm
	X3oQiRviEFjqQfHSYZIWdY5ZhaQHvek9YulldXOUus5JDlC0WNQ3wOwn
X-Google-Smtp-Source: AGHT+IGCnrVGAk41pQbtmIOYg+YPqvG8+q4g8pwp9FG7HVWnj16sDQRbJ5+ANaVTakSfSFraA84RhA==
X-Received: by 2002:a05:622a:5e0e:b0:4d4:d7d5:f579 with SMTP id d75a77b69052e-4d4d7d5f6a3mr18740311cf.52.1758649786025;
        Tue, 23 Sep 2025 10:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6T+GT6wAZnj/PYRuhmdTGZGcoDAKCpjJjpqiI/OEUxAg==
Received: by 2002:a05:622a:246:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4cf64288f9bls29356281cf.2.-pod-prod-04-us; Tue, 23 Sep 2025
 10:49:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdk2HSUg8uoIDN0t2bL1T7HzVHI/GKcuwemsiJXXeU20gSQOLgKby543Lf1vM0w4RmDln6izyXWIM=@googlegroups.com
X-Received: by 2002:a05:620a:319b:b0:84a:568:b7d3 with SMTP id af79cd13be357-8517370024bmr364788385a.74.1758649784332;
        Tue, 23 Sep 2025 10:49:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649784; cv=none;
        d=google.com; s=arc-20240605;
        b=KZZtzSUDTOZhtnilEuPdoECFveYEHEnowKRmkePHw1tVSuyA3ONSzSyBfWhGv2MYus
         h/jBk3K4s8vUyWinaYtlSxnEafXzs2pA4+bM/T3hzJT0DIWP7pdju1NQt9sbesl991rG
         AEtLNPEPxBYlI896ESF6GJQdI3B1IsCGYRN/tJPKR/h9g2J+MYKHtI1YYow9pj0WADDm
         hC3oyw6HCGdJ523zMacOf/kCF668s5gRvOkgl5Vf1gmXkpc56f2hn/AMwzgn0EXG+JGx
         zILIFjE1L/hpFpT1cqrEXt16EpAVlTdq4n6jSdO/S+3FMHl+GUEH331cbAfeXePrKOJn
         k9Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3TEt5FVs7bAByY4KAampM0rCdgggPH1dRWAiWsS8XiU=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=hPSj6A1xV8Y92akeOTgZm/kx7RpeKB5GVw6XI2hVCMSp1EMr9+zkxo5rRXxkPkRfgo
         5m8/xg3VK0vKS7WNuTH4iRndOlc1j1D6ZmAlJHnTMD2Gv3fqAWnPHd8D7jYb0VGFs5qI
         8/Onaso4QSU7DBBafrMFk/67ffSwH61hu1dqeGUVy6WcQarn0xxWqxk1Wz/kd+WZBsnV
         e9vppLjEAVa4lH1Pb611M9Js3sX/I31tUyAruf3woWYVpZLq9KfeA/u7R1XTfdBQ5zT8
         lmdpl4bXAymqCN2HFeikSA3MIrB8ztatZej3Kfs01iTS5CA29Kx4/+x7FynEmA7fvjkI
         WkrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8363066c299si30922585a.6.2025.09.23.10.49.44
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B63E425E0;
	Tue, 23 Sep 2025 10:49:35 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id E078E3F5A1;
	Tue, 23 Sep 2025 10:49:39 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 07/16] arm64/proton-pack: make alternative callbacks safe
Date: Tue, 23 Sep 2025 18:48:54 +0100
Message-ID: <20250923174903.76283-8-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

Alternative callback functions are regular functions, which means they
or any function they call could get patched or instrumented
by alternatives or other parts of the kernel.
Given that applying alternatives does not guarantee a consistent state
while patching, only once done, and handles cache maintenance manually,
it could lead to nasty corruptions and execution of bogus code.

Make the Spectre mitigations alternative callbacks safe by marking them
`noinstr` when they are not.
This is possible thanks to previous commits making `aarch64_insn_...`
functions used in the callbacks safe to inline.

`spectre_bhb_patch_clearbhb()` is already marked as `__init`,
which has its own text section conflicting with the `noinstr` one.
Instead, use `__no_instr_section(".noinstr.text")` to add
all the function attributes added by `noinstr`, without the section
conflict.
This can be an issue, as kprobes seems to only block the text sections,
not based on function attributes.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
This is missing `spectre_bhb_patch_wa3()` and
`spectre_v4_patch_fw_mitigation_enable()` callbacks, which would need
some more work :
- `spectre_bhb_patch_wa3()` uses `WARN` which is instrumented, and
  I am not sure if it is safe to remove. It feels like something else
  should be done there ?
- `spectre_v4_patch_fw_mitigation_enable()` calls into
  `spectre_v4_mitigations_off()` which calls `pr_info_once()` to notice
  the disabling of the mitigations on the command line, which is
  instrumentable but feels important to keep. I am not sure if there
  would be a better place to generate that message ?
  Interestingly, this was brought up recently[0].
  It also calls `cpu_mitigations_off()` which checks a static variable
  against a static enum, in a common code C file, and is instrumentable.
  This one feels like it could be `__always_inline`'d, but given it is
  common code and the static nature of operands in the check, maybe
  marking it `noinstr` would be acceptable ?

[0]: https://lore.kernel.org/all/aNF0gb1iZndz0-be@J2N7QTR9R3/
---
 arch/arm64/kernel/proton-pack.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/kernel/proton-pack.c b/arch/arm64/kernel/proton-pack.c
index edf1783ffc81..4ba8d24bf7ef 100644
--- a/arch/arm64/kernel/proton-pack.c
+++ b/arch/arm64/kernel/proton-pack.c
@@ -1174,6 +1174,7 @@ void noinstr spectre_bhb_patch_wa3(struct alt_instr *alt,
 }
 
 /* Patched to NOP when not supported */
+__noinstr_section(".init.text")
 void __init spectre_bhb_patch_clearbhb(struct alt_instr *alt,
 				   __le32 *origptr, __le32 *updptr, int nr_inst)
 {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-8-ada.coupriediaz%40arm.com.
