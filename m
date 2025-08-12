Return-Path: <kasan-dev+bncBCMMDDFSWYCBBP4D5XCAMGQEQ5PUHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B802B22870
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:29:37 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-7098e7cb2dcsf97616336d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:29:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005376; cv=pass;
        d=google.com; s=arc-20240605;
        b=VkZJj+ohMvDSCnnmIxZINeyvEx2nJAi6CV90Eqf1B1DSXLfACl7BvlhdKbrU/m+D7y
         hkwyosp1393aZ+hnlFf2A09R/9jlTmqyHzbBwCUulyc4EWQNIC0p6XjwOcACHnrXTqOx
         5UhebnZccvA2GUEwyWJ6yMqfe69gqn17X2Dj5XtybtSXuAqvpZUIL6ognxEGLaF94o/X
         k4Z0Ovi3zn0z33KCu5OOKsgjKNR6o85C8pPMb47LReqcpAxTZMsFI7i3jVIBKeJWRoUs
         jpguMb6323Y878uRwk48hxrq7pmmyZ5YNTu9v3JgYNhuKSYPyMGTnIL7Q1/DC7X2pV7E
         mCrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SuMZM6tIYCq+whyN33FFk9UO0USIHwmfMUZxhY9PJHA=;
        fh=kdQFIwwPp1yWUhCwwBOxulDEghDf/n1i4LlDaEKDk40=;
        b=byVvwxvKrMCJXYyvlLyrDwb48D7Bf+YQsHA6jmByVLSwM0c0WiSKKYIa8xAS+ofEuR
         GZZWTzMntvMtELWfZ/SJzW1jGgunpmCII/UcfSHiqkoXKjb1gBhrOJVOT9DTQMjcjZV2
         23Ck/orNrZl3DR/9UQoB3kAVdwHInnijB9JBFLEiIsQVCso+mR+LfRM0XZW+BfjlofBM
         gTSEIe/+jrK2MGUWJsr4rc9zo1JlkZZ0y7bkLpDILvKXDL2+K2lon6Tg5TscM2yMlvkB
         DGQQnGkjxLFu/HnihcF9gcF9BLm2PXAXJf0Xsqh4EopIQADoedTFh8y39rreR7ckEwTb
         MWiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dxXQMyrK;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005376; x=1755610176; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SuMZM6tIYCq+whyN33FFk9UO0USIHwmfMUZxhY9PJHA=;
        b=oLrMPWXDIPCwSW0Hh6kD6jya5u2ZMO2UsiqX47wUKJdxW0zVsH94JVU6lCzwmHuxNZ
         O/iT9iVbZEj572B6WJvtx0d8vFp+MxpdLOMeO4F58l3erqRL05EYSdM5VUYzo6IIEZdI
         X1jdNGQLhJG2Ep8m7C9cmGlQcLE+ej4GupABxAQz0kRbz1xJuaK17Y7t+UosffRUQbGl
         O4vHvzh/INNgmtSF6bXD7xnMwZniebpDiYKoDzVYtd8zcOF1wE53ZBcd1cYin0WkYbTW
         ckUUUkKVl8BoO0FahSbyNAFdiaVv/AKLrgpCDW7CsMybN2mRV1HGTqxeZAzaXfq12OoS
         8mlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005376; x=1755610176;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SuMZM6tIYCq+whyN33FFk9UO0USIHwmfMUZxhY9PJHA=;
        b=wE9cFxZ6vkuvobnVBp6V3toMQy+r1RyTKo2SOJdWLYUoRudk/2MNj+WuLQzqLkMhKW
         bHoXm5BCz/KUAfI/Z5D5e2JT56M6vLBTLpDQNsuBYoI2ZBUSAypEA78RgOwveGbu99KZ
         sdYjT4zWCLhQP3t/iVm2R3rXPQBMJZ1z/oYV/tIP9meO9gHKtujoW9PiHOS3jLfLlgnj
         VU7fLgf9PUKc0C25tOWHkOIXrfh0kfSDGHFN8t2P3RCemhplAwiLoyDqMRrDnJZv6q8F
         LgUCTMB5cQUHqn/dUJE40VTAhU1reysyxv7EZq3XwJEpTMbWuhJAJ5SEUmaadAjVeEEK
         co2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbus2dmT0hDrKLB9EuGEXHSD10rU1K1RlVg+IFnqjJw6gJ3z0XDeEzHg5qyrtZmVNhruq32g==@lfdr.de
X-Gm-Message-State: AOJu0YyJJwZpKyBjoZuBVEYll2OS1vVZEA2P8GW9Jt+goQY6ahKEsTrT
	luDUnXEdc/IaBcgJxRJOaFKn+Byfj1/SUmETbx8nURaGMUZkNAFZtryd
X-Google-Smtp-Source: AGHT+IFFXM5fSq12vFT9XnY+twtxD8BT7+YbBDIjK5NFIsAGkP9Ci/4bL7YhBFV6kx6GO/mdOMsO6Q==
X-Received: by 2002:a05:6214:48f:b0:707:76b4:2d36 with SMTP id 6a1803df08f44-709d681c590mr43563796d6.6.1755005375834;
        Tue, 12 Aug 2025 06:29:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLwknb+fFCH9fa9OzsvzsCaEf/t1HKEIafII7e90WCsQ==
Received: by 2002:a05:6214:4e8f:b0:707:18b0:de30 with SMTP id
 6a1803df08f44-70978bb2475ls40635576d6.1.-pod-prod-00-us-canary; Tue, 12 Aug
 2025 06:29:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfKoOffd+KgVl5K2Uz3FYT4SYbJmg++Kt1PlNTADi4NeaHrzZkvJagTrsJJYJY4hyg2J/LX6JCNqE=@googlegroups.com
X-Received: by 2002:a05:6122:919:b0:535:ed79:2aed with SMTP id 71dfb90a1353d-53afa027e30mr1736354e0c.2.1755005374925;
        Tue, 12 Aug 2025 06:29:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005374; cv=none;
        d=google.com; s=arc-20240605;
        b=IkrOz4TdqlzQEubrTFbZwZhVP/CDyxEsS1Ra2hKsU5Tc8FA3j6S7WI4KLVVgS6jvTe
         9rO5M9MiZAgfAEx8K6RiWNZDIi6H3dKsZm0bh2VKwZJw7mSizP2WdCLe/xLP88WRuXap
         mEH8L8wCccu9aJOsBfcJFevM2cfWdWdJtT52aDZ4rJoc5e2BPi/fA/4eMgodVjtErccJ
         b3BVTqKxnoLTsqWWwKtR7oS9Omn8yhqCnEImi+QCiGxL1Mv67mKS6Pc1e+ZkknwPRhvK
         gMdj4aEO46jmzyrXusHEy6s9JuOsD9v9M1LpjwFAO9c3tUDUw3ySshC/jOBse6pafiRi
         0YqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ex520mDAAluSLXFdiYJ04d7IrdUaRDN9zWUBH2TlPCk=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=RqG0hYNfQDW70PS7g+i2Cx7PWPCSGrAetvAy9sfJF/ujVW6JvxEfH2sFSKhm/epaS0
         VyPKZgo7pjD71YAywidZxFbv2Ljao/kpOw4gZMcGNHc7LMhDi4ESAGmL3Pxe6Jm8ZKLp
         7ivriWZS41XnpGAo3vgnAqBqOQUSQoxkTHofGRzDOBKioT18OZ1mxeeYOy0XFaBnyIqG
         M9PkqHVOopIgUeNQNle2gukSg73ICD914thagR16TqIt8bFfWRY6sHdjgVK03zp0YGI1
         UsxKU6vvwQJq4b8z+avTnCpz8wCuP5hFXfXi6m+IAvuVbhhNtjyTRaGBdk/6mhgkiuCY
         Bqqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dxXQMyrK;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b02e6ad6si548125e0c.5.2025.08.12.06.29.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:29:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: 61AuiICSRUWIntkS+J+AzQ==
X-CSE-MsgGUID: TmuoafYnQ7S9IVJZU/bjrQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903787"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903787"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:34 -0700
X-CSE-ConnectionGUID: t6kjFU4oRZiLZmMpMij85g==
X-CSE-MsgGUID: TDLcIyj9Qy+UaemOVoZKVg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831582"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:12 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 12/18] x86: Minimal SLAB alignment
Date: Tue, 12 Aug 2025 15:23:48 +0200
Message-ID: <a765e38bdeae15193215bb8fd713df9350048edc.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dxXQMyrK;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

8 byte minimal SLAB alignment interferes with KASAN's granularity of 16
bytes. It causes a lot of out-of-bounds errors for unaligned 8 byte
allocations.

Compared to a kernel with KASAN disabled, the memory footprint increases
because all kmalloc-8 allocations now are realized as kmalloc-16, which
has twice the object size. But more meaningfully, when compared to a
kernel with generic KASAN enabled, there is no difference. Because of
redzones in generic KASAN, kmalloc-8' and kmalloc-16' object size is the
same (48 bytes). So changing the minimal SLAB alignment of the tag-based
mode doesn't have any negative impact when compared to the other
software KASAN mode.

Adjust x86 minimal SLAB alignment to match KASAN granularity size.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Extend the patch message with some more context and impact
  information.

Changelog v3:
- Fix typo in patch message 4 -> 16.
- Change define location to arch/x86/include/asm/cache.c.

 arch/x86/include/asm/cache.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
index 69404eae9983..3232583b5487 100644
--- a/arch/x86/include/asm/cache.h
+++ b/arch/x86/include/asm/cache.h
@@ -21,4 +21,8 @@
 #endif
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#endif
+
 #endif /* _ASM_X86_CACHE_H */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a765e38bdeae15193215bb8fd713df9350048edc.1755004923.git.maciej.wieczor-retman%40intel.com.
