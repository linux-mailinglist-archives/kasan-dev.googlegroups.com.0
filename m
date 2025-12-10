Return-Path: <kasan-dev+bncBAABB56U43EQMGQE46JHMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 23A94CB3919
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:14:33 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-37bab6de7f8sf24201041fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:14:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765386872; cv=pass;
        d=google.com; s=arc-20240605;
        b=YI0MrbzClsVGqmfzTUNQZZp4TpKFfmIMn9JuCBpuwevUHoHWb2iV0aZ3bA+IEbUW9u
         9rtP3SR1l1t+QBg+EDqGyLe50XeY4jDxKPUieIn8doBpwXmRHUOMrnHwdlsT4J/ihwh/
         1rnHrMZUwQIuMgQGXLQ5cAKKwsjIdwaW7qfmEHdOSi7Xgh+KaIw9BYzzb7gsUykRI5mj
         j6DhqkgZOuKCidaY1KzR4Oy620m+N/9MpQ1LWHfUsRMnVnGpUFre4ETWY888pqBJ5EKa
         M5PIdIj7IM6/uL1Dsyqpqe0z1O5EOkLDsXrO2jzNnUwvlmoFO27i4WdeMT9LcfR+GAHY
         Z62w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=Uoow9e3J/TQnsqrE8zKI6Kt7tLWgqnPwdSs6aqsrteE=;
        fh=FYjNpycY1MNj4ixvehG3/r7SLO34eZTcCMGUYfNfQgE=;
        b=FRPMh5OaCuRS/KbwugaezOB6qJis2jU+pqDozceLsc9azSw4Vww0sA4RBJ1wmTblAK
         djzyMJV1iFGccTlHaPl0w6nzo9TLpDKruEF6pQutuUIj4xsvpFMeaCO3b++QQG6QqHDm
         iN3cjF3gwNTtMWD7DcCm/Nn160Snzje8Qk6EPAEeiSQNHmwb72J7pzBJfe+FS4C/AApH
         nNpUvWI4rXTGCvF4bnlvZypS3WnBP9qbbFtuFbKa329dRQcS163TR9MRgt3uzT+Lq9IN
         M4YZDWgkMZg9zKCQqG5MJqsIdn3miwBj9bbS8/17w5fQaH3LEkqRYhjNkbXgB5czHv+8
         6FGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="e/uy32js";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765386872; x=1765991672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Uoow9e3J/TQnsqrE8zKI6Kt7tLWgqnPwdSs6aqsrteE=;
        b=ge3iNtnUV0FofUTVuo+3hRR+VKUDRwHhwu3LWaRX2Ji5wdn417zhZlXIqJ4bSUE3yB
         eEScIGVEmuM6Q8gaFjUiDJuailL/jw6nD8MaP/a9F8GQ5ho6Va+3hAfDRqdFJXRSjNA2
         vRfVm+M8aVMPtz8vgcr+aXeSTRo24Ttmz7khyPh6LPMsRKVUd8D0vece7BP3OZnV98KR
         0wJuqJvTFAcb98RbEjBaV7yErRamY92kAExF1Fn3mLW6fMRh3jp8oj7gpSJb8kiIdXga
         jONe+Y82Sx+PPbrjNa24Tky57fDtzNinLOOjJUfegRAUtguEOko1w7eW7r9JW5VNxRqT
         e/WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765386872; x=1765991672;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Uoow9e3J/TQnsqrE8zKI6Kt7tLWgqnPwdSs6aqsrteE=;
        b=dU6n6R6UHbvRMtHVWpA4PZ7TXLPexRLJcKQha7w2b+cX8j+PnJd+UkTY52J9Qq4c1W
         yrTkzrPLb8PLZwAxlQUGOjYMwyk5WiauCxnhfrmxOfPEezHe2/icSOTW0wm75k8+eW87
         8apuqlON6OOUosRrDGRHrUpLV3cUjsGP52WmU5bIiG0S/KlX++VWE0/QlJfNUlLkk+rF
         lot05xmXQimWcECI+POBPhLIk1jKyTf5DPf6YT+Br09NXNYHGf5DfJt2omj/GEmmf8RZ
         oQLN6Ju8wQOIMcf2skQufmba7U4jO+be9Dy3/mEYSFAwFguW1gar85xhzUoqppi/iNx6
         2VCA==
X-Forwarded-Encrypted: i=2; AJvYcCWmlrohLW5dB5QlY9g3ZErgBCOxODka4Gr1KJhCXQrkLpTsNeDarOpTa6qQ6V5rFDddnm64aw==@lfdr.de
X-Gm-Message-State: AOJu0Yxw/6Ff8fg547LRuEP4b4nFDiHSemI7nwKxxBI8ZJEu8T+HEJ5o
	PAkbfgQLPHmJzZVVIUSY6VTw34JN1J3hoU56A8h8guZ794uqUin9W+ND
X-Google-Smtp-Source: AGHT+IFgp4anD7xKACG9mmwjIVCsrnGB3pNcqS9u7079IM4S5bwUibU/NMxzQVGnxuDDOG4icDqyHg==
X-Received: by 2002:a05:651c:41cf:b0:37b:ad8b:7680 with SMTP id 38308e7fff4ca-37fb1febae1mr8693981fa.9.1765386871940;
        Wed, 10 Dec 2025 09:14:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZpjLQRfLfghvsOQ3oomvRoKv7JYoE/u9OOuPGy66MkGQ=="
Received: by 2002:a2e:a17a:0:b0:377:735b:7cbf with SMTP id 38308e7fff4ca-37fbc80a7e1ls70371fa.0.-pod-prod-08-eu;
 Wed, 10 Dec 2025 09:14:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnO9Ae3nnV316lnROdKYgxz5bJQ4/yz2LxBiSp4wcYVuf95I16fr0GgyBOxmYih2/Vuc6yC8peIAg=@googlegroups.com
X-Received: by 2002:a2e:a78a:0:b0:37b:9d7e:2295 with SMTP id 38308e7fff4ca-37fb213f317mr9781211fa.41.1765386869719;
        Wed, 10 Dec 2025 09:14:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765386869; cv=none;
        d=google.com; s=arc-20240605;
        b=hV+tGgY6KDT6f0CtHwwrGrb5COf52yohvg+gB8A0SVmAhI7tTx28+IfmcLGcE+N8q0
         qljmJPqqjnyB5Oyp8TnDQNGnJ3NIDuMEgh0irOzI0Lt42aJ1Bm5eEBaYpx1WuJf2zLew
         yxf9L8ddCFns3odvssYCaWktSocF1ke+/PBASwzMiFDUK105m+OgGVF0EON8B3vUExIO
         Gfy2MTzLsxU+soeMzH7Nt78A4ELG4dw726BO6EVjOqBZFH62GvPbs0DXNRHs8Yb2Yt3l
         EdhlpyCUPVkPT6z+QGiXom3Cyt/O6/3i7YpEjeEk+43YHZYcjRPzQrxADdgKbvSn3xCi
         M2PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=tQBUlk5fifS6yOJJqQb8R9OP8yHw0CO86r6/5oBtm8g=;
        fh=4440H8l2G/7tr5rtwFy+ZNgTp3J69jiVIuSlXpW1/fg=;
        b=b7xBESKlLwXPXLFGYbyJv97DpEfU/qCNrJ80o1ZAeVOIQM4pr1W5reRqERzHh+EJqp
         fAH6hEXL+9XHshUerBlY3sfWUs/QnCpRol0jFXQfyXyH12yLktTas1pRQQd3BclR4rR1
         DA2Ayrv5gzQtFgXDggsQuqRK7rPLgXHwtdL6BwVpr4PjxTaoIUrYl1PQ7TONAWw8+Pkr
         EuKpqCO5uSBCmx0N/PaJYjmDtF3fStijy4xW/XEWcPKdCXMtTNY4Y/qTMRjB34N59mtq
         JVDo0zw+ZpUk1ZCshg0L600ZtnsOVIsVeqGuVwgDzhntxpovI3JH7ocaVGaVdzfaAsvZ
         2fww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="e/uy32js";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fbc9a81d4si3341fa.2.2025.12.10.09.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:14:29 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Wed, 10 Dec 2025 17:14:14 +0000
To: weixugc@google.com, kas@kernel.org, lorenzo.stoakes@oracle.com, nicolas.schier@linux.dev, nathan@kernel.org, kbingham@kernel.org, bigeasy@linutronix.de, jackmanb@google.com, jeremy.linton@arm.com, andreyknvl@gmail.com, surenb@google.com, glider@google.com, kaleshsingh@google.com, dave.hansen@linux.intel.com, will@kernel.org, thuth@redhat.com, kees@kernel.org, fujita.tomonori@gmail.com, tglx@linutronix.de, jpoimboe@kernel.org, samuel.holland@sifive.com, maciej.wieczor-retman@intel.com, luto@kernel.org, vbabka@suse.cz, ardb@kernel.org, justinstitt@google.com, mhocko@suse.com, axelrasmussen@google.com, maz@kernel.org, xin@zytor.com, akpm@linux-foundation.org, rppt@kernel.org, brgerst@gmail.com, urezki@gmail.com, nick.desaulniers+lkml@gmail.com, leitao@debian.org, samitolvanen@google.com, trintaeoitogc@gmail.com, morbo@google.com, yeoreum.yun@arm.com, smostafa@google.com, dvyukov@google.com, corbet@lwn.net, peterz@infradead.org, jan.kiszka@siemens.com, yuanchu@google.com,
	ada.coupriediaz@arm.com, Liam.Howlett@oracle.com, hpa@zytor.com, mingo@redhat.com, mark.rutland@arm.com, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, ubizjak@gmail.com, catalin.marinas@arm.com, david@redhat.com, bp@alien8.de
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, linux-kbuild@vger.kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org, m.wieczorretman@pm.me
Subject: [PATCH v7 00/15] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 50301002b2cc10e908f03a29606438935e19d835
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="e/uy32js";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

======= Introduction
The patchset aims to add a KASAN tag-based mode for the x86 architecture
with the help of the new CPU feature called Linear Address Masking
(LAM). Main improvement introduced by the series is 2x lower memory
usage compared to KASAN's generic mode, the only currently available
mode on x86. The tag based mode may also find errors that the generic
mode couldn't because of differences in how these modes operate.

======= How does KASAN' tag-based mode work?
When enabled, memory accesses and allocations are augmented by the
compiler during kernel compilation. Instrumentation functions are added
to each memory allocation and each pointer dereference.

The allocation related functions generate a random tag and save it in
two places: in shadow memory that maps to the allocated memory, and in
the top bits of the pointer that points to the allocated memory. Storing
the tag in the top of the pointer is possible because of Top-Byte Ignore
(TBI) on arm64 architecture and LAM on x86.

The access related functions are performing a comparison between the tag
stored in the pointer and the one stored in shadow memory. If the tags
don't match an out of bounds error must have occurred and so an error
report is generated.

The general idea for the tag-based mode is very well explained in the
series with the original implementation [1].

[1] https://lore.kernel.org/all/cover.1544099024.git.andreyknvl@google.com/

======= Differences summary compared to the arm64 tag-based mode
- Tag width:
	- Tag width influences the chance of a tag mismatch due to two
	  tags from different allocations having the same value. The
	  bigger the possible range of tag values the lower the chance
	  of that happening.
	- Shortening the tag width from 8 bits to 4, while it can help
	  with memory usage, it also increases the chance of not
	  reporting an error. 4 bit tags have a ~7% chance of a tag
	  mismatch.

- Address masking mechanism
	- TBI in arm64 allows for storing metadata in the top 8 bits of
	  the virtual address.
	- LAM in x86 allows storing tags in bits [62:57] of the pointer.
	  To maximize memory savings the tag width is reduced to bits
	  [60:57].

- Inline mode mismatch reporting
	- Arm64 inserts a BRK instruction to pass metadata about a tag
	  mismatch to the KASAN report.
	- Right now on x86 the INT3 instruction is used for the same
	  purpose. This series attempts to move it over to use UD1 in
	  the future so it's consistent with UBSan. Also using INT3 in
	  on the kernel side causes other issues that need to be patched
	  over.

======= Testing
Checked all the kunits for both software tags and generic KASAN after
making changes.

In generic mode (both with these patches and without) the results were:

kasan: pass:61 fail:1 skip:14 total:76
Totals: pass:61 fail:1 skip:14 total:76
not ok 1 kasan

and for software tags:

kasan: pass:65 fail:1 skip:10 total:76
Totals: pass:65 fail:1 skip:10 total:76
not ok 1 kasan

At the time of testing the one failing case is also present on generic
mode without this patchset applied. This seems to point to something
else being at fault for the one case not passing. The test case in
question concerns strscpy() out of bounds error not getting caught.

======= Benchmarks [1]
All tests were ran on a Sierra Forest server platform. The only
differences between the tests were kernel options:
	- CONFIG_KASAN
	- CONFIG_KASAN_GENERIC
	- CONFIG_KASAN_SW_TAGS
	- CONFIG_KASAN_INLINE [1]
	- CONFIG_KASAN_OUTLINE

Boot time (until login prompt):
* 02:55 for clean kernel
* 05:42 / 06:32 for generic KASAN (inline/outline)
* 05:58 for tag-based KASAN (outline) [2]

Total memory usage (512GB present on the system - MemAvailable just
after boot):
* 12.56 GB for clean kernel
* 81.74 GB for generic KASAN
* 44.39 GB for tag-based KASAN

Kernel size:
* 14 MB for clean kernel
* 24.7 MB / 19.5 MB for generic KASAN (inline/outline)
* 27.1 MB / 18.1 MB for tag-based KASAN (inline/outline)

Work under load time comparison (compiling the mainline kernel) (200 cores):
*  62s for clean kernel
* 171s / 125s for generic KASAN (outline/inline)
* 145s for tag-based KASAN (outline) [2]

[1] Currently inline mode doesn't work on x86 due to things missing in
the compiler. I have written a patch for clang that seems to fix the
inline mode and I was able to boot and check that all patches regarding
the inline mode work as expected. My hope is to post the patch to LLVM
once this series is completed, and then make inline mode available in
the kernel config.

[2] While I was able to boot the inline tag-based kernel with my
compiler changes in a simulated environment, due to toolchain
difficulties I couldn't get it to boot on the machine I had access to.
Also boot time results from the simulation seem too good to be true, and
they're much too worse for the generic case to be believable. Therefore
I'm posting only results from the physical server platform.

======= Compilation
Clang was used to compile the series (make LLVM=1) since gcc doesn't
seem to have support for KASAN tag-based compiler instrumentation on
x86.

======= Dependencies
The series is based on this series [1] by Peter Zijlstra. Also for the
series to work on bigger systems (with more than 1 NUMA node and more
than 128 cores from my experience) the vmalloc fix patchset [2] is
needed. If you don't want vmalloc support it should run without it.

[1] https://lore.kernel.org/all/20251110114633.202485143@infradead.org/
[2] https://lore.kernel.org/all/cover.1764945396.git.m.wieczorretman@pm.me/

======= Previous versions
v6: https://lore.kernel.org/all/cover.1761763681.git.m.wieczorretman@pm.me/
v5: https://lore.kernel.org/all/cover.1756151769.git.maciej.wieczor-retman@intel.com/
v4: https://lore.kernel.org/all/cover.1755004923.git.maciej.wieczor-retman@intel.com/
v3: https://lore.kernel.org/all/cover.1743772053.git.maciej.wieczor-retman@intel.com/
v2: https://lore.kernel.org/all/cover.1739866028.git.maciej.wieczor-retman@intel.com/
v1: https://lore.kernel.org/all/cover.1738686764.git.maciej.wieczor-retman@intel.com/

=== (two fixes patches were split off after v6) (merged into mm-unstable)
v1: https://lore.kernel.org/all/cover.1762267022.git.m.wieczorretman@pm.me/
v2: https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman@pm.me/
v3: https://lore.kernel.org/all/cover.1764874575.git.m.wieczorretman@pm.me/
v4: https://lore.kernel.org/all/cover.1764945396.git.m.wieczorretman@pm.me/

Changes v7:
- Rebased the series onto Peter Zijlstra's "WARN() hackery" v2 patchset.
- Fix flipped memset arguments in "x86/kasan: KASAN raw shadow memory
  PTE init".
- Reorder tag width defines on arm64 to avoid redefinition warnings.
- Split off the pcpu unpoison patches into a separate fix oriented
  series.
- Redid the canonicality checks so it works for KVM too (didn't change
  the __canonical_address() function previously).
- A lot of fixes pointed out by Alexander in his great review:
	- Fixed "x86/mm: Physical address comparisons in fill_p*d/pte"
	- Merged "Support tag widths less than 8 bits" and "Make special
	  tags arch specific".
	- Added comments and extended patch messages for patches
	  "x86/kasan: Make software tag-based kasan available" and
	  "mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic",
	- Fixed KASAN_TAG_MASK definition order so all patches compile
	  individually.
	- Renamed kasan_inline.c to kasan_sw_tags.c.

Changes v6:
- Initialize sw-tags only when LAM is available.
- Move inline mode to use UD1 instead of INT3
- Remove inline multishot patch.
- Fix the canonical check to work for user addresses too.
- Revise patch names and messages to align to tip tree rules.
- Fix vdso compilation issue.

Changes v5:
- Fix a bunch of arm64 compilation errors I didn't catch earlier.
  Thank You Ada for testing the series!
- Simplify the usage of the tag handling x86 functions (virt_to_page,
  phys_addr etc.).
- Remove within() and within_range() from the EXECMEM_ROX patch.

Changes v4:
- Revert x86 kasan_mem_to_shadow() scheme to the same on used in generic
  KASAN. Keep the arithmetic shift idea for the KASAN in general since
  it makes more sense for arm64 and in risc-v.
- Fix inline mode but leave it unavailable until a complementary
  compiler patch can be merged.
- Apply Dave Hansen's comments on series formatting, patch style and
  code simplifications.

Changes v3:
- Remove the runtime_const patch and setup a unified offset for both 5
  and 4 paging levels.
- Add a fix for inline mode on x86 tag-based KASAN. Add a handler for
  int3 that is generated on inline tag mismatches.
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion.
- Remove patches 2 and 3 since they related to risc-v and this series
  adds only x86 related things.
- Reorder __tag_*() functions so they're before arch_kasan_*(). Remove
  CONFIG_KASAN condition from __tag_set().

Changes v2:
- Split the series into one adding KASAN tag-based mode (this one) and
  another one that adds the dense mode to KASAN (will post later).
- Removed exporting kasan_poison() and used a wrapper instead in
  kasan_init_64.c
- Prepended series with 4 patches from the risc-v series and applied
  review comments to the first patch as the rest already are reviewed.

Maciej Wieczor-Retman (13):
  kasan: Fix inline mode for x86 tag-based mode
  x86/kasan: Add arch specific kasan functions
  x86/mm: Reset tag for virtual to physical address conversions
  mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
  x86/mm: Physical address comparisons in fill_p*d/pte
  x86/kasan: KASAN raw shadow memory PTE init
  x86/mm: LAM compatible non-canonical definition
  x86/mm: LAM initialization
  x86: Minimal SLAB alignment
  x86/kasan: Handle UD1 for inline KASAN reports
  arm64: Unify software tag-based KASAN inline recovery path
  x86/kasan: Logical bit shift for kasan_mem_to_shadow
  x86/kasan: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: arm64: x86: Make special tags arch specific

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      |  6 +-
 MAINTAINERS                               |  4 +-
 arch/arm64/Kconfig                        | 10 +--
 arch/arm64/include/asm/kasan-tags.h       | 14 ++++
 arch/arm64/include/asm/kasan.h            |  2 -
 arch/arm64/include/asm/memory.h           | 14 +++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/kernel/traps.c                 | 17 +----
 arch/arm64/mm/kasan_init.c                |  7 +-
 arch/x86/Kconfig                          |  4 ++
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/bug.h                |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 81 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               | 23 ++++++-
 arch/x86/include/asm/page_64.h            |  1 +
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/kernel/traps.c                   | 13 +++-
 arch/x86/mm/Makefile                      |  2 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 +--
 arch/x86/mm/kasan_init_64.c               | 25 ++++++-
 arch/x86/mm/kasan_sw_tags.c               | 19 ++++++
 arch/x86/mm/physaddr.c                    |  2 +
 include/linux/kasan-tags.h                | 21 ++++--
 include/linux/kasan.h                     | 36 ++++++++--
 include/linux/mm.h                        |  6 +-
 include/linux/mmzone.h                    |  2 +-
 include/linux/page-flags-layout.h         |  9 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  9 ++-
 mm/kasan/report.c                         | 37 +++++++++--
 mm/vmalloc.c                              |  7 +-
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 38 files changed, 354 insertions(+), 74 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h
 create mode 100644 arch/x86/mm/kasan_sw_tags.c

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1765386422.git.m.wieczorretman%40pm.me.
