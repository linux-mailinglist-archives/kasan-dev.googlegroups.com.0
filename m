Return-Path: <kasan-dev+bncBD4NDKWHQYDRBU4L66WAMGQE22Y24BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C0E828F83
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:16:53 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-429b125d60fsf127131cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:16:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838612; cv=pass;
        d=google.com; s=arc-20160816;
        b=svayur+X8fDV4GGH158flkd3l6/nje+e37X8hBEtoPM0OzqAXkb3lQ5ZffceU1fPZH
         WYFxO/17Nt27o3eSDjk9g/pr8lMeLd/y54r0oe2A5Ldzp/ubj+6zuZoG76t82Ijtk2Ub
         uxDuMEDAWLyvsVS0FPo+1rqPnpKo8+PKAv32rb0g7CdNgRzBCiQi7sMAbp2v6Avu0UhR
         D8RUMqVLtvurN/Y41bP7O4CKyhlbXtfEwbB0T3s+3w/Rs/qBk0mpzARd+a1dVzlWKRTY
         ERRD5ByHaIOPtZ3kZ0CHCZp1y98QzXOyowClPDgwga+JR7SbvXtH8sg/dtVWmjR4io31
         2Z1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=eeNZxPisIJ4DkrWMeeQlDuqW+r+ixlkt6FYZ9SJRdp4=;
        fh=dTe6zL5Ivivq2KoKBIkxib/65Ipl1ye2APy+yz2cYE8=;
        b=Vx0VGbKdm7yoGADwi0z767OrRpBWg7tif3x/Ee5Zcblox9Vk6ln0NQlWZPBBPU8Epe
         RibOcakjYpFq/CjzJTSs6XV32EZTelbz6C1EzDBOTUrlprrFvlTzSr58AcpTlnwky58Z
         Ch7/HMzaOthjs+6wb2uREt/eRnBfeqyLTmzkzwaEeqK6kdKrjPsHDH4tTRAVl1TMNE/k
         rb4Ebi9q6jFJPGpNdsFh1dL7v4aClpbupJ1df1t0K1Pv6bXo5DOfkrMrzYYdoj7ecTPF
         brzvyHX5c4l4EzkbebtG+XRiWKNHekUzteXLOZXXMegeMkB27fbMWUoVcXHTF0L2t/Ef
         /8lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qB46A5Sp;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838612; x=1705443412; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eeNZxPisIJ4DkrWMeeQlDuqW+r+ixlkt6FYZ9SJRdp4=;
        b=syLG2S/TuCYdn3AiIJIeVO7/OEaw8o8NkPWMvBUme3tmZSnFWnxMT9odW+E105RUuv
         SexoSdQXOvunkjpZRGZFjK2WhxcssM8vcZNcfKL1sJvNFAh/alIDmXJT7xjtyboPqd51
         +j2LCIfUIu6OLCPY0PKSgaOvyknMB2/k5iJ/5IiWKlKuiQiTVpA1kUNWhGZsOUUN8/yt
         j1xKXv4FKGx2Oufn0tWfs3Qj6Yz7lg+o/YT0qa62FNyHUIv4dk1OioFe48Q0xffyKcmj
         YEhTtAJlM1cw16geyN1gFHeOCYAd1ZO/zyIrs8uDESbPSfYlwpJi7LfYSzGK614OMDZC
         Yziw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838612; x=1705443412;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eeNZxPisIJ4DkrWMeeQlDuqW+r+ixlkt6FYZ9SJRdp4=;
        b=uRm/dGu9o85eaWWVRznUwokqE4ln5PPbLS/3zJ+AjMkXS6GnXPdzkvo+PGQUrXJY0n
         5J/kUhVJwiq5zLXsVfLbZFwrdgJcsCtxgtPIfPcGtRGbu6w4P36ssUiRj/3m2B9ryYUz
         jRI10SPJeexrWlTF026JSbh1m1nWOpCnyhLVeGawX40NDyRnQe3sG00qcl85X2srBgyo
         PVFME/JReDnz9I+KtL5AnKFCsyA6AreyqLDShtbWebObO26zzjMBMqVfUgLcRb8FLW7E
         H3ioqb0kwRsAvVjxz5X2PfsyoAz3V+U7Yfjan++JyGEVFl/fu1TlizoPoZ5rLbWQ8B4l
         NuXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzY34bxyzdbndVIbXEFwBq47jgrHCdKJhBjzkkh5SckrON6BcM8
	4h52S/XarN8ZdvFPq0Kt9hU=
X-Google-Smtp-Source: AGHT+IFVY5SPhsNCooc4hSSsWSgPo02shFXWb3c7dVnLIlR4YMpNUQ9KNJCgTbrxCO6quFC/wo+tMg==
X-Received: by 2002:ac8:5746:0:b0:429:9ac2:46d with SMTP id 6-20020ac85746000000b004299ac2046dmr156275qtx.26.1704838611879;
        Tue, 09 Jan 2024 14:16:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c49:0:b0:67f:6bd0:4930 with SMTP id a9-20020ad45c49000000b0067f6bd04930ls2624099qva.1.-pod-prod-02-us;
 Tue, 09 Jan 2024 14:16:51 -0800 (PST)
X-Received: by 2002:a05:6102:54a0:b0:467:7a68:3c7 with SMTP id bk32-20020a05610254a000b004677a6803c7mr1961vsb.58.1704838611162;
        Tue, 09 Jan 2024 14:16:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838611; cv=none;
        d=google.com; s=arc-20160816;
        b=pHCMzU396NWWcNCicN1n6hdniT6Z6db/RLkw180j6/qjRCsy84dKI4pO2aRHfAB8mU
         vBSPF9+GJ9iWMzaZZThh8Du/YYSwWeOFOdB5DvFPRgh9ErpdMpBV9K7nijzhWKN+6c2w
         aktdJ0IywGYCLrZImQzzRypg5ZxYklGdrjepgIrA0cY/uQN1TOz3zVvPCQr5aKDa5IOH
         JKFaCKUiM1SH7C2POjuGNmdHreelzBRHE/K3Br/6L46Cv3Lncvm3acyLLncaqI4mlU/C
         +jo0zxa2XmKDOPe7LSequqdO7akk1x3ud0Vy4I8AE5E21mnVTwSR9x0x8IcVZ3qraIZl
         07Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=JwzkgqiYvhBptnhcxqKlM+k3Yyi9aMUpjlUtUDzBhTI=;
        fh=dTe6zL5Ivivq2KoKBIkxib/65Ipl1ye2APy+yz2cYE8=;
        b=onK2R4JYyDPxWAhGVQOSuHIugA/Ifh8Z0319j4br2sA0s2qcHMMNpGmx9liPHL7Oc/
         FsdeVD823s0641mbV+pPJ7A16aGUWN1GO4aNruXwZGsy5fI1Tu2NNzuff1XOtfcgaOsb
         9OSAJ8yRBrbONKsQPT6MEbznzaV3UsEGyYeZlMi+GGb72vIK5Wvsojt1HDDad58oubGs
         Hz2ohVbEbV3/RB/nUniS9MMuXg4+7Lm3jqpx3hk7c3VTOoVw1+45mcca6TslIgsloeiX
         8E9w1OU+z7x3Ld1pihQhvXNHdhAHGYNKsbWMSq6MNdsAq32YQ8JhaPkHHKyTzrhgphB8
         vWeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qB46A5Sp;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x2-20020ab07802000000b007cc759f7d1dsi196884uaq.2.2024.01.09.14.16.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 14:16:51 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 902D461578;
	Tue,  9 Jan 2024 22:16:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA61FC433F1;
	Tue,  9 Jan 2024 22:16:48 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
Subject: [PATCH 0/3] Update LLVM Phabricator and Bugzilla links
Date: Tue, 09 Jan 2024 15:16:28 -0700
Message-Id: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIALzFnWUC/x3MQQqAIBBA0avErBtQi8CuEi0kpxoyCy0JwrsnL
 d/i/xciBaYIffVCoMSRD18g6wqm1fiFkG0xKKFaIYXG+7TmInQu7ejYbxGtaGZtu1aTJCjdGWj
 m538OY84fszs+Z2MAAAA=
To: akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, patches@lists.linux.dev, 
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linuxppc-dev@lists.ozlabs.org, kvm@vger.kernel.org, 
 linux-riscv@lists.infradead.org, linux-trace-kernel@vger.kernel.org, 
 linux-s390@vger.kernel.org, linux-pm@vger.kernel.org, 
 linux-crypto@vger.kernel.org, linux-efi@vger.kernel.org, 
 amd-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
 linux-media@vger.kernel.org, linux-arch@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, bridge@lists.linux.dev, 
 netdev@vger.kernel.org, linux-security-module@vger.kernel.org, 
 linux-kselftest@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
 ast@kernel.org, daniel@iogearbox.net, andrii@kernel.org, mykolal@fb.com, 
 bpf@vger.kernel.org
X-Mailer: b4 0.13-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=2460; i=nathan@kernel.org;
 h=from:subject:message-id; bh=EHvco0VkqOSJGuxdue1TEtXAL00jI8VZrVZxCAuX2+E=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDKlzj17YHOFbeqmmzSTv+Yl3Dvc2pO2+wn2gftPWtOlmz
 ZFzErc87ShlYRDjYpAVU2Spfqx63NBwzlnGG6cmwcxhZQIZwsDFKQATcYlj+J+VsOtwv+FtLr6v
 L2ptJLoTJ1xwvPM+afI7W55fz9vnRocyMsxLsi56rXP33S6VMzNvVJ4tXR/xeu4ma9Zvvc8ruWO
 PdPIDAA==
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qB46A5Sp;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

This series updates all instances of LLVM Phabricator and Bugzilla links
to point to GitHub commits directly and LLVM's Bugzilla to GitHub issue
shortlinks respectively.

I split up the Phabricator patch into BPF selftests and the rest of the
kernel in case the BPF folks want to take it separately from the rest of
the series, there are obviously no dependency issues in that case. The
Bugzilla change was mechanical enough and should have no conflicts.

I am aiming this at Andrew and CC'ing other lists, in case maintainers
want to chime in, but I think this is pretty uncontroversial (famous
last words...).

---
Nathan Chancellor (3):
      selftests/bpf: Update LLVM Phabricator links
      arch and include: Update LLVM Phabricator links
      treewide: Update LLVM Bugzilla links

 arch/arm64/Kconfig                                 |  4 +--
 arch/powerpc/Makefile                              |  4 +--
 arch/powerpc/kvm/book3s_hv_nested.c                |  2 +-
 arch/riscv/Kconfig                                 |  2 +-
 arch/riscv/include/asm/ftrace.h                    |  2 +-
 arch/s390/include/asm/ftrace.h                     |  2 +-
 arch/x86/power/Makefile                            |  2 +-
 crypto/blake2b_generic.c                           |  2 +-
 drivers/firmware/efi/libstub/Makefile              |  2 +-
 drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c           |  2 +-
 drivers/media/test-drivers/vicodec/codec-fwht.c    |  2 +-
 drivers/regulator/Kconfig                          |  2 +-
 include/asm-generic/vmlinux.lds.h                  |  2 +-
 include/linux/compiler-clang.h                     |  2 +-
 lib/Kconfig.kasan                                  |  2 +-
 lib/raid6/Makefile                                 |  2 +-
 lib/stackinit_kunit.c                              |  2 +-
 mm/slab_common.c                                   |  2 +-
 net/bridge/br_multicast.c                          |  2 +-
 security/Kconfig                                   |  2 +-
 tools/testing/selftests/bpf/README.rst             | 32 +++++++++++-----------
 tools/testing/selftests/bpf/prog_tests/xdpwall.c   |  2 +-
 .../selftests/bpf/progs/test_core_reloc_type_id.c  |  2 +-
 23 files changed, 40 insertions(+), 40 deletions(-)
---
base-commit: 0dd3ee31125508cd67f7e7172247f05b7fd1753a
change-id: 20240109-update-llvm-links-d03f9d649e1e

Best regards,
-- 
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240109-update-llvm-links-v1-0-eb09b59db071%40kernel.org.
