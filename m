Return-Path: <kasan-dev+bncBDAOJ6534YNBB56P6XBAMGQEX7P4LIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67457AEA28E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:11 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-32b30ead2fbsf5092061fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951928; cv=pass;
        d=google.com; s=arc-20240605;
        b=WzTPp8g2Sld+RsODhdQ7ydsJbwUMbVySX4PQucidElNNWCu5dOg7lUnuvDgFor/Ibd
         7oO/vyORvZIp6FkMcZKImKVTzQykS4H9Zu1L/JVHav0HUxtxs+qYD72OylsQlqwysjqG
         8jmeh5MDxywuQpGcBLuA4EEV1kj6sskYoDI6CXxgCgKyN9Vd5ZF/2KWOV0bB91pcETBh
         CFe2gXEfpkzkQ+qQ60S+Nr2dPMFK6vQFzdnvcGfJUi5LTCZwNFNfilj2px5Fa6EMUG/8
         zUgVjbOft1Wgsda03Jqbm6hUxmbDIoW+3+ukayiRdINZbtucLI59xl9xK5SKeImDVWcq
         PtTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=50/tWcIDNkcd/snte6Y148ui/wxbsWTsC+SYdTQDuIU=;
        fh=lj3ZDUjrWfPJlvnLFHNDk0e55j+4m8p1a+vsp22wTq8=;
        b=RiOwlTdFZmE+zkfw6mH4IIQqDplpCYDVN4DJUZVtEK3Awfpra301PjaEHgJ/BAEpoQ
         2z6K8pqdYy8wgO85OAiwUQ+c+UlEjj5X99NLIJdajI3uC3/HLfxjOIiqBiv0yl+zqeLx
         /6NrSBoOAQpBegFoX+9qazwbEMq99+PLQYaJZCRnBEqaUwu/z5D0BGeZlA0o5bbOqcHo
         3Ur1hM/GYuIJKAA1yT+86EAVFMYpUijvV8mskcq7lLNqenCH4hjCrQV6HDfI34ZN9mHS
         X/hS3TMPQBZ5MPdp3QsIht+3TgxdTzcLEYtvgfhTVUkFoXgvNonrG5s/uZ5n4jp4wAuC
         bZhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TEzHGnkr;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951928; x=1751556728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=50/tWcIDNkcd/snte6Y148ui/wxbsWTsC+SYdTQDuIU=;
        b=elGxV52OTSUrmHF575MWCLZF6mKsE3QuRcJPQ7siZEmRvyUJFQRrSuf5iEiBbHtqRA
         6F0AVplvPibCwktVnTwPbnT3Ur13/Lbo70PiLLRFcjd5p6fvWEy4FMqRyx2/fZjl9iof
         95BW8lvQYHByr0fsmPCMtOSW+YOpIZbvTvROFTkKs/+QVbZsqXD+sI9lS0yJqJmEUA1Z
         T8fw5QILP+W3gKsCSZ6fwYmR8DW1bdWdBuGaGtiku6nScDLUxzh1btQM4HAh6JlFu980
         Qx98PRJcoxEoE7yMXPzg/Dk5ajzfz8Hl+8d4B1piSJ/ox3rJMs4CQjs1jILnT0mSD7H2
         gg1g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951928; x=1751556728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=50/tWcIDNkcd/snte6Y148ui/wxbsWTsC+SYdTQDuIU=;
        b=Jh+Ya4byPPl9IF2djMNnA0IgeSNATsTcUPT/m6znIwGlff3+RiidEkUr8fih5IdjJr
         NVadBn31KLiuRXC6Z/fnpudfktkfayZbEoUfCNJxbURiuBActXa54n4TkxWWy6rPHv6p
         I81dbOBVJBz1ex/kOztA54kECLUnreHymmMzWa4Am5t6PXqyq4RB5D9WVtzJkaeK5Jlf
         SajFoSZPA7fhRtSoVJ/zSIecBq0zPK2bv8rA4itniIblELOoW9qxxk8+wehz76txreDU
         xVmstMwcdvKNlr0TkPFRp3BrQFRTJPOXyvU+hFGbtTjQGxqAEkixNU6Db82kEzUeRUBt
         /fGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951928; x=1751556728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=50/tWcIDNkcd/snte6Y148ui/wxbsWTsC+SYdTQDuIU=;
        b=iD5JD2bRPOB3Jtvsi5hyKL3s2ULX5ki1YHtMx5CfvXCTMEJzscrnMtT47M9dKP/fzh
         YZTmmq3fS9PXOvud/kJB7TyzlByKekflqNMpBRvF49OF+Tuj/akPfUfuNGtJcdGJ+0H1
         paoiIYuSNQ2innCvnR2MMvesSZ6Rp0PUk651VAmfPduo2GnHWRjuk+4FFYpkk2UmeWOf
         QApX/6QJR+FU5NG82UD8GGvki3Mxd7rf98ZAPxCup7/oB1pKTF5yvSZokGzs4sxoBKJ9
         BXFclrxaOztXJLaRGX1pETxOYIiQCLZXrMrx62CGhboga7BIKNAG5ll8STWyqxPzh2Iz
         DmyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHfp68mwy57hEAWkJMUAAMP5T5LG350EwPveGZYyQ7K9leFbC3oMFxldpIhnsm17Rr/Nog3g==@lfdr.de
X-Gm-Message-State: AOJu0YzwoahMveLDtO41//dfp+Ke7M2fdb0unM1tegKr1Q46pe9BR894
	3uEU/a0bkgZOtxSeWAyxFNXFyrt0H+WFTRzxByCsnFVHOzzo485zvZKq
X-Google-Smtp-Source: AGHT+IFEx4tSJrCt1a/xauxmBBfymweTMh4dyQ30Oc+sxwVFGEQeJDPvwiMx8DX0kYh1XRSWqqsW2g==
X-Received: by 2002:ac2:4f10:0:b0:553:2812:cf01 with SMTP id 2adb3069b0e04-554fde57942mr2782797e87.54.1750951928090;
        Thu, 26 Jun 2025 08:32:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfGd0HrnUZOtc+paBhOX1Jqv8Qzmmzo2BRAxpcRGfpkRQ==
Received: by 2002:a19:e041:0:b0:553:d911:31f7 with SMTP id 2adb3069b0e04-55502e074e4ls287546e87.1.-pod-prod-08-eu;
 Thu, 26 Jun 2025 08:32:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrLbgnNvK60ZWrUs/wAA7Q87tA2jhuxjdqBsDil8vJc5auNOEuntA0XFElCOwDtQ+UUck7gBghkaM=@googlegroups.com
X-Received: by 2002:a05:6512:3c87:b0:553:2375:c6d9 with SMTP id 2adb3069b0e04-554fde5eb9cmr2466848e87.55.1750951925350;
        Thu, 26 Jun 2025 08:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951925; cv=none;
        d=google.com; s=arc-20240605;
        b=gJGIIrqlJlrm2XuqnGc+vI93AfZLnOBI5h9VjS1fDEuiBN8p9KXvX4gjCY+pMx1zld
         79UvSseUwETlD1+3jCX7pO1jM4Y4jurS3EpPP7DfsXtY+h87ghDA9t4QVoFwV2G9Qp4w
         PmsZurp/OhmmvVuZZ4/wy4NdLkeZLItvW1OSSMm8E+cRQs8oKtGXw9hZSp9B7KdfyTH1
         fLNDylMYM+nwv4Eohkaq5b7QD72O4ja7YqvC0xQiDq8TSIC4TtAjwMYeJGUHi1KPkem5
         2YQER2rN8GRMeep27PMfhyhHKuSebOcoLhAtoo0dhfkXYLppwOvXEWne5HQfNJpuRb8T
         X45g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YMfAvEP2mtW3abNAfjIslAPajM3CO1XTnrCn/94UwT0=;
        fh=za6Hj9FiddCnYqgHv2LzeSGBL2w0zQQE9ZilW18ijGA=;
        b=KAHoPhoeb25XFKis3qRlhiChfBZdUbGX+D5XjvBPBgFXO1AGL+GYEQ61S9AvnaBtca
         ObrpXiPZJZ22EDZTPvORTXk+Pl/cRDUvYrS/nCSLSItFXtJot0Gfqc0DA0I7c+oiLk2Q
         UuPVUExch8bSP5qfgG84StRvoTcSO8tF6s3EiCJV4UHqk58RW+nIcW6FTXj0PdUzdZG5
         DepXsx4T1LfVGeRXV638Lt6eC7HP2eUH26KgGsywuzAb4GP7YbNPsdg6QcSPcB5HYZ1h
         U5pEMpHtie7mp4K1mNZFuXG1FiPN8vL22gIQJXGqhD5ZfiJGkG7sgVaddWfI0K6BA8fy
         pjuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TEzHGnkr;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b23ad3bsi6643e87.1.2025.06.26.08.32.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-32b2f5d91c8so10271221fa.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVot5YvK85PoW8/XM0HqYxWdkY1k10FkTuHb9ztjdaAoNPvTKoZ2EeXl/SirlxQkWletJJ0MC9xkyU=@googlegroups.com
X-Gm-Gg: ASbGncvOwPYCU4DzcKFOuuYR5eZKoHEaPq+8M6B4KsSZS2BKR4AUa0O6A/24COZ8/By
	nES2hWSZ33/17GSwMsUrU1fWka6KBqmpdfkTbfdo7zbLKDO749Q9p35mkKJAnPLfBPHhl3lSn42
	zIMy7lBan0T1djZX41Zu8W/7H3ShqVTUjJs3hH9tFqV+ejCTcEdMwJWYHR+yBU04kSRniLhl+m/
	Ti8DHAoodCSUkvPO+MkRTd848Ymwp6kuSPgfQ8CHGoY1JI1okaoWNNY4Uf5VWwz6ukTm9GgMPMl
	ZxTIlAcmbUa9lTnwBAe5SJ6t99jZuhW8kJISvebsJGSojzip3x54NHRHQxpvBs+gPkPfwK9imBf
	ZaWkAKzXoaWSjwbRMPpEVPal+efPfM8vlVzIxe+wE
X-Received: by 2002:a05:6512:1589:b0:554:f76a:baba with SMTP id 2adb3069b0e04-554fdcbb935mr2999055e87.3.1750951924452;
        Thu, 26 Jun 2025 08:32:04 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.31.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:03 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with kasan_enabled
Date: Thu, 26 Jun 2025 20:31:36 +0500
Message-Id: <20250626153147.145312-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TEzHGnkr;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This patch series unifies the kasan_arch_is_ready() and kasan_enabled()
interfaces by extending the existing kasan_enabled() infrastructure to
work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).

Currently, kasan_enabled() only works for HW_TAGS mode using a static key,
while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-time
constant) or rely on architecture-specific kasan_arch_is_ready()
implementations with custom static keys and global variables.

This leads to:
- Code duplication across architectures  
- Inconsistent runtime behavior between KASAN modes
- Architecture-specific readiness tracking

After this series:
- All KASAN modes use the same kasan_flag_enabled static key
- Consistent runtime enable/disable behavior across modes
- Simplified architecture code with unified kasan_init_generic() calls
- Elimination of arch specific kasan_arch_is_ready() implementations
- Unified vmalloc integration using kasan_enabled() checks

This addresses the bugzilla issue [1] about making
kasan_flag_enabled and kasan_enabled() work for Generic mode,
and extends it to provide true unification across all modes.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=217049

=== Current mainline KUnit status

To see if there is any regression, I've tested first on the following
commit 739a6c93cc75 ("Merge tag 'nfsd-6.16-1' of
git://git.kernel.org/pub/scm/linux/kernel/git/cel/linux").

Tested via compiling a kernel with CONFIG_KASAN_KUNIT_TEST and running
QEMU VM. There are failing tests in SW_TAGS and GENERIC modes in arm64:

arm64 CONFIG_KASAN_HW_TAGS:
	# kasan: pass:62 fail:0 skip:13 total:75
	# Totals: pass:62 fail:0 skip:13 total:75
	ok 1 kasan

arm64 CONFIG_KASAN_SW_TAGS=y:
	# kasan: pass:65 fail:1 skip:9 total:75
	# Totals: pass:65 fail:1 skip:9 total:75
	not ok 1 kasan
	# kasan_strings: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:1598
	KASAN failure expected in "strscpy(ptr, src + KASAN_GRANULE_SIZE, KASAN_GRANULE_SIZE)", but none occurred

arm64 CONFIG_KASAN_GENERIC=y, CONFIG_KASAN_OUTLINE=y:
	# kasan: pass:61 fail:1 skip:13 total:75
	# Totals: pass:61 fail:1 skip:13 total:75
	not ok 1 kasan
	# same failure as above

x86_64 CONFIG_KASAN_GENERIC=y:
	# kasan: pass:58 fail:0 skip:17 total:75
	# Totals: pass:58 fail:0 skip:17 total:75
	ok 1 kasan

=== Testing with patches

Testing in v2:

- Compiled every affected arch with no errors:

$ make CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm STRIP=llvm-strip \
	OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf \
	HOSTCC=clang HOSTCXX=clang++ HOSTAR=llvm-ar HOSTLD=ld.lld \
	ARCH=$ARCH

$ clang --version
ClangBuiltLinux clang version 19.1.4
Target: x86_64-unknown-linux-gnu
Thread model: posix

- make ARCH=um produces the warning during compiling:
	MODPOST Module.symvers
	WARNING: modpost: vmlinux: section mismatch in reference: \
		kasan_init+0x43 (section: .ltext) -> \
		kasan_init_generic (section: .init.text)

AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
is placed in own section ".kasan_init", which calls kasan_init_generic()
which is marked with "__init".

- Booting via qemu-system- and running KUnit tests:

* arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results.
* x86_64 (GENERIC): no regression, no errors

=== NB

I haven't tested the kernel boot on the following arch. due to the absence
of qemu-system- support on those arch on my machine, so I defer this to
relevant arch people to test KASAN initialization:
- loongarch
- s390
- um
- xtensa
- powerpc
- riscv

Code changes in v2:
- Replace the order of patches. Move "kasan: replace kasan_arch_is_ready
	with kasan_enabled" at the end to keep the compatibility.
- arch/arm, arch/riscv: add 2 arch. missed in v1
- arch/powerpc: add kasan_init_generic() in other kasan_init() calls:
	arch/powerpc/mm/kasan/init_32.c
	arch/powerpc/mm/kasan/init_book3e_64.c
- arch/um: add the proper header `#include <linux/kasan.h>`. Tested
	via compiling with no errors. In the v1 arch/um changes were acked-by
	Johannes Berg, though I don't include it due to the changed code in v2.
- arch/powerpc: add back `#ifdef CONFIG_KASAN` deleted in v1 and tested
	the compilation.
- arch/loongarch: update git commit message about non-standard flow of
	calling kasan_init_generic()

Sabyrzhan Tasbolatov (11):
  kasan: unify static kasan_flag_enabled across modes
  kasan/arm64: call kasan_init_generic in kasan_init
  kasan/arm: call kasan_init_generic in kasan_init
  kasan/xtensa: call kasan_init_generic in kasan_init
  kasan/loongarch: call kasan_init_generic in kasan_init
  kasan/um: call kasan_init_generic in kasan_init
  kasan/x86: call kasan_init_generic in kasan_init
  kasan/s390: call kasan_init_generic in kasan_init
  kasan/powerpc: call kasan_init_generic in kasan_init
  kasan/riscv: call kasan_init_generic in kasan_init
  kasan: replace kasan_arch_is_ready with kasan_enabled

 arch/arm/mm/kasan_init.c               |  2 +-
 arch/arm64/mm/kasan_init.c             |  4 +---
 arch/loongarch/include/asm/kasan.h     |  7 -------
 arch/loongarch/mm/kasan_init.c         |  7 ++-----
 arch/powerpc/include/asm/kasan.h       | 13 -------------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 arch/riscv/mm/kasan_init.c             |  1 +
 arch/s390/kernel/early.c               |  3 ++-
 arch/um/include/asm/kasan.h            |  5 -----
 arch/um/kernel/mem.c                   |  4 ++--
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 22 ++++++++++++++++------
 include/linux/kasan.h                  |  6 ++++++
 mm/kasan/common.c                      | 15 +++++++++++----
 mm/kasan/generic.c                     | 17 ++++++++++++++---
 mm/kasan/hw_tags.c                     |  7 -------
 mm/kasan/kasan.h                       |  6 ------
 mm/kasan/shadow.c                      | 15 +++------------
 mm/kasan/sw_tags.c                     |  2 ++
 22 files changed, 66 insertions(+), 84 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-1-snovitoll%40gmail.com.
