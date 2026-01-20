Return-Path: <kasan-dev+bncBAABBDFIX3FQMGQEU75I2MA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MGg0ECClb2lIDwAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBDFIX3FQMGQEU75I2MA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:54:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D0AC946CE7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:54:07 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59b6d9aafc4sf694892e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:54:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768924447; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dlh11qORYPbmqBlvTlFZ0bu6e8iG/Zucc1gwR+/iA/9ahXcu7jDbmJmMKIrOi3eqf3
         2DlexA0KPZXY+9W1pL6hrcMGtn+hX8iPOs1KyR3+nqBvHhV3ZcCq28hYiyuuWgCTSmRZ
         /ndQJhGMHZ+kT9DLqNyTILtLYf+qy/+2zJqYb5Ha3oATXzwe8uCFDY320D1LqHfnXKYL
         z5Iw8JPg/4jma2bZG+a9oRMHrNMVCZcj7fvEcTUvbGkaAg9ZYvdrAQIDDlbo3oMuxPjQ
         MR/kFLgmOQzqzq3riTjsZhrq0790eRQYa3uTQhI3nFnRWu0mnCvxNC7Ci74/phjvI6xb
         cwRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=guIvC+ZdNWyY5YVqwqfDBPHNA3HZqJ8KMll8Zoe1hNw=;
        fh=SYIcIMTJbqbqsIU7wBw3JtyEpK8aK/YHMAKBI9Ztldg=;
        b=RLZMyQyg3EhVru4jRlY+kjb8PAr8lCWWy/BBdKFRtr+1A99dxEk7yOGEBK83LHguSF
         dWNdxAtKWXkAPfRK5OZ5FszMCZNsHMnSInyXiFD4xLTkdlUKlf8ZDyqVMfKmwcrwDF14
         7/iedvGEM1D6SCX/7f1moGVoFDssVtORV6aDYvfdfsGvFJeuxEbL4en1Ye9FbnoPfZy4
         AzphELX6b0eH8WOfn3J7nA6VKTt8p6PLaDG1xemKC+B0RZBAj9U3aO5o76UBkWiAeGz+
         9OU2x2AnjGhdZGJehGv6JGZGm74fop/XW0QMD0NXko+HjwMsYkP0qCEC0qpsPaO4My0s
         tusA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=VMYppwYN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924447; x=1769529247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=guIvC+ZdNWyY5YVqwqfDBPHNA3HZqJ8KMll8Zoe1hNw=;
        b=RoKyybqzHTWNh0DiEb4rWmVPHOldLMqVt5kJ2E2m4Qm3Y9HOHOOQPX2vqWXwSs9nd4
         IswQX/jgoL4TiEC5nJrvCvWjHouvrBHVllCSC6xCagr+LbEwLXfdmDdhs7Tmwhei4HeG
         5A13rGjUK3mGEKLOBlcrLPfh7MNJC9+xWRDphJgEzmDXGFI79pKUHyMsh6wA1bMlnuCR
         D6BoDlLbjKZgLsqZYrSNyv+egNG63lgk8P/YVfdXT4RLE8Oy7LfVee4WSTYWuLcLd8dK
         +2dgkp9z/C2L9MJQUL/HlYyN46suqfRZ+7y6NzASiTxmrdh8UwiWjGnbQ7azq/CwtWLW
         HRpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924447; x=1769529247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=guIvC+ZdNWyY5YVqwqfDBPHNA3HZqJ8KMll8Zoe1hNw=;
        b=rVRYdZ0xCtWC57pRva0cl2lTwTsStThy/9HBdKHb8B8OTgOUE93re5b8smxhkQgLK6
         XuiWQythtRpXGoHgxpnc6LRtbCbK0LgowjSv1QOBlw+wy9u3AR3q0P3GY0lLs5O/6spT
         fLV8zTWbdxi+mGDFKd4WS+mrg/Hjvdp9pZoc3OLhf8+/L28AJU6FHbUdTLFNzmNyVPMD
         y3/mpWz3xV6wPzwSzD0WedAhOAS0dCrPByPgi25Mr8iYHNe2uGuFRsE/b+jEDP4PsGSn
         xyEU5qT1jHt4w5Llf/VbvSIUZNWAiC0KcFMIcvAUdVlrPbuZ6FrX286BkePtk3mxIooT
         Jjnw==
X-Forwarded-Encrypted: i=2; AJvYcCVXRXF8NPzARQ6SjZqguVAQB1rctikBvbn6Ex8xzmnk1RCKzaw4+Wa0EmnvcjF3hiCL05BNZg==@lfdr.de
X-Gm-Message-State: AOJu0YxTcZfoZaAZuFnIV1TWXwKQOzo47aDNMGTkKB7EK2e4Cb6grFWW
	Iou9Ymclgek9gvZSGmbeXQNONl3LSjrhUEZmgWkcFZBgFKm7rZ3hpGSu
X-Received: by 2002:a05:6512:6187:b0:59d:cdd2:13a2 with SMTP id 2adb3069b0e04-59dcdd21a42mr57403e87.4.1768920076757;
        Tue, 20 Jan 2026 06:41:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+En3FVsRCPUoK72Gntmc+ZSnb9ib8G/zyg9z4dLF6qpmw=="
Received: by 2002:a05:6512:b26:b0:59b:6d6d:e with SMTP id 2adb3069b0e04-59badf258f0ls2398059e87.2.-pod-prod-04-eu;
 Tue, 20 Jan 2026 06:41:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUaabylMnmYCHo1++boM0Cxn/bzLawsMVi4rEhBnGJA20Uj6BFsG/hmkpudiuYZn9cEKNYDKLU040Q=@googlegroups.com
X-Received: by 2002:a05:6512:2347:b0:59b:b259:a00 with SMTP id 2adb3069b0e04-59bb2590b81mr5009450e87.49.1768920074548;
        Tue, 20 Jan 2026 06:41:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920074; cv=none;
        d=google.com; s=arc-20240605;
        b=FfhfDxGM1VkhVrm2Eis89kq7QenSyLVI22QNnY7MLg2+d8hlBREUG6YjXArnCyvItn
         oBvDWYoMAL605+d2XP7vLgRQx34CskPEa8C27xUCIZLQ2NuK8zeY0BCryETzdeJ6/2zF
         JfirkH/uJT5ybWxSMNDFD7J9ydBEM+pcGEPUypsmbnPUgYvCpO3mfDxWjikreILcHOyM
         segnE8EaJ3nH9c9yq6a4lom8Xr55SR/ksqRtwD/gTUrwJKiVobmR5UfAA+O3qA62/yzc
         s8vUwjvw5iQsVGM5IG46g2synYe2iqpvH58yxALg8h1GsTVgMybFEbKE27fjud9EL77Z
         NERw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=1+HljzJAxHOBFeIXuMPiGuXCQ1Tna/1pc36MTk3CcdE=;
        fh=cnqandUeFaFr13ovu1fylENTYAQWu7WkMuJGMPV4oJc=;
        b=Q4Wun9Zix0Fodve3TLYMma8ukbIONMhrAyN1omFW8XoB4fMj/4YhXoEKvZJAjFlx+u
         BFCjrzMSNlzLkFnQ8ChsHcUBTvQlSSSIo9jSbzRFlkGHYvTDftR1kvDpL8CzsB8Zw4qz
         4ykV1S12v8rMUFERuxrsHK3TSBAYQ6j3dRg09+VeX3t36ohBMzoq6uVh0dDOpFwUhWax
         Ux6bTvZK+GIgqxGqq+/z3zIa3oHtbn7m2ChoCiBWWdejR7pTG3b+PE/5IyAlx1LyKeyU
         t1/Oj+CUN5/Ljn8XOEkRk9KU77MGRSMkjeMqrn/913ftNggLtljH4CG6qv7/QG9oL6n8
         kwxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=VMYppwYN;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf341ef5si301481e87.1.2026.01.20.06.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:41:14 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Tue, 20 Jan 2026 14:41:08 +0000
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, llvm@lists.linux.dev
Subject: [PATCH v9 01/13] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <eb5ed91489b648fcb0f7cbe3fe4347ba4e636b65.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0488e01fae9adc69c76456c169a4b2174e5e4018
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=VMYppwYN;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[arm.com,kernel.org,lwn.net,gmail.com,google.com,linux-foundation.org,siemens.com];
	RCPT_COUNT_TWELVE(0.00)[24];
	TAGGED_FROM(0.00)[bncBAABBDFIX3FQMGQEU75I2MA];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,sifive.com:email,pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x140.google.com:rdns,mail-lf1-x140.google.com:helo]
X-Rspamd-Queue-Id: D0AC946CE7
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

From: Samuel Holland <samuel.holland@sifive.com>

Currently, kasan_mem_to_shadow() uses a logical right shift, which turns
canonical kernel addresses into non-canonical addresses by clearing the
high KASAN_SHADOW_SCALE_SHIFT bits. The value of KASAN_SHADOW_OFFSET is
then chosen so that the addition results in a canonical address for the
shadow memory.

For KASAN_GENERIC, this shift/add combination is ABI with the compiler,
because KASAN_SHADOW_OFFSET is used in compiler-generated inline tag
checks[1], which must only attempt to dereference canonical addresses.

However, for KASAN_SW_TAGS there is some freedom to change the algorithm
without breaking the ABI. Because TBI is enabled for kernel addresses,
the top bits of shadow memory addresses computed during tag checks are
irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
This is demonstrated by the fact that LLVM uses a logical right shift in
the tag check fast path[2] but a sbfx (signed bitfield extract)
instruction in the slow path[3] without causing any issues.

Use an arithmetic shift in kasan_mem_to_shadow() as it provides a number
of benefits:

1) The memory layout doesn't change but is easier to understand.
KASAN_SHADOW_OFFSET becomes a canonical memory address, and the shifted
pointer becomes a negative offset, so KASAN_SHADOW_OFFSET ==
KASAN_SHADOW_END regardless of the shift amount or the size of the
virtual address space.

2) KASAN_SHADOW_OFFSET becomes a simpler constant, requiring only one
instruction to load instead of two. Since it must be loaded in each
function with a tag check, this decreases kernel text size by 0.5%.

3) This shift and the sign extension from kasan_reset_tag() can be
combined into a single sbfx instruction. When this same algorithm change
is applied to the compiler, it removes an instruction from each inline
tag check, further reducing kernel text size by an additional 4.6%.

These benefits extend to other architectures as well. On RISC-V, where
the baseline ISA does not shifted addition or have an equivalent to the
sbfx instruction, loading KASAN_SHADOW_OFFSET is reduced from 3 to 2
instructions, and kasan_mem_to_shadow(kasan_reset_tag(addr)) similarly
combines two consecutive right shifts.

Add the arch_kasan_non_canonical_hook() to group the arch specific code
in the relevant arch directories.

Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v9: (Maciej)
- Take out the arm64 related code from mm/kasan/report.c and put it in
  the arch specific directory in a new file so the kasan_mem_to_shadow()
  function can be included.
- Reset addr tag bits in arm64's arch_kasan_non_canonical_hook() so the
  inline mode can also work with that function (Andrey Ryabinin).
- Fix incorrect number of zeros in a comment in mm/kasan/report.c.
- Remove Catalin's acked-by since changes were made.

Changelog v7: (Maciej)
- Change UL to ULL in report.c to fix some compilation warnings.

Changelog v6: (Maciej)
- Add Catalin's acked-by.
- Move x86 gdb snippet here from the last patch.

Changelog v5: (Maciej)
- (u64) -> (unsigned long) in report.c

Changelog v4: (Maciej)
- Revert x86 to signed mem_to_shadow mapping.
- Remove last two paragraphs since they were just poorer duplication of
  the comments in kasan_non_canonical_hook().

Changelog v3: (Maciej)
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion. Settled on overflow on both ranges and separate checks for
  x86 and arm.

Changelog v2: (Maciej)
- Correct address range that's checked in kasan_non_canonical_hook().
  Adjust the comment inside.
- Remove part of comment from arch/arm64/include/asm/memory.h.
- Append patch message paragraph about the overflow in
  kasan_non_canonical_hook().

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++++--
 MAINTAINERS                               |  2 +-
 arch/arm64/Kconfig                        | 10 +++----
 arch/arm64/include/asm/kasan.h            |  5 ++++
 arch/arm64/include/asm/memory.h           | 14 ++++++++-
 arch/arm64/mm/Makefile                    |  2 ++
 arch/arm64/mm/kasan_init.c                |  7 +++--
 arch/arm64/mm/kasan_sw_tags.c             | 35 +++++++++++++++++++++++
 include/linux/kasan.h                     | 10 +++++--
 mm/kasan/kasan.h                          |  7 +++++
 mm/kasan/report.c                         | 15 ++++++++--
 scripts/gdb/linux/kasan.py                |  5 +++-
 scripts/gdb/linux/mm.py                   |  5 ++--
 13 files changed, 106 insertions(+), 19 deletions(-)
 create mode 100644 arch/arm64/mm/kasan_sw_tags.c

diff --git a/Documentation/arch/arm64/kasan-offsets.sh b/Documentation/arch/arm64/kasan-offsets.sh
index 2dc5f9e18039..ce777c7c7804 100644
--- a/Documentation/arch/arm64/kasan-offsets.sh
+++ b/Documentation/arch/arm64/kasan-offsets.sh
@@ -5,8 +5,12 @@
 
 print_kasan_offset () {
 	printf "%02d\t" $1
-	printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) \
-			- (1 << (64 - 32 - $2)) ))
+	if [[ $2 -ne 4 ]] then
+		printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) \
+				- (1 << (64 - 32 - $2)) ))
+	else
+		printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) ))
+	fi
 }
 
 echo KASAN_SHADOW_SCALE_SHIFT = 3
diff --git a/MAINTAINERS b/MAINTAINERS
index da9dbc1a4019..8e0e776b66a7 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13585,7 +13585,7 @@ S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
 F:	arch/*/include/asm/*kasan.h
-F:	arch/*/mm/kasan_init*
+F:	arch/*/mm/kasan*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 93173f0a09c7..c1b7261cdb96 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -434,11 +434,11 @@ config KASAN_SHADOW_OFFSET
 	default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
 	default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
 	default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
-	default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
-	default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
-	default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
-	default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
-	default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
+	default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
+	default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
+	default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
+	default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
+	default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
 	default 0xffffffffffffffff
 
 config UNWIND_TABLES
diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b167e9d3da91..42d8e3092835 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -22,5 +22,10 @@ void kasan_init(void);
 static inline void kasan_init(void) { }
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+bool __arch_kasan_non_canonical_hook(unsigned long addr);
+#define arch_kasan_non_canonical_hook(addr) __arch_kasan_non_canonical_hook(addr)
+#endif
+
 #endif
 #endif
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 9d54b2ea49d6..f127fbf691ac 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -89,7 +89,15 @@
  *
  * KASAN_SHADOW_END is defined first as the shadow address that corresponds to
  * the upper bound of possible virtual kernel memory addresses UL(1) << 64
- * according to the mapping formula.
+ * according to the mapping formula. For Generic KASAN, the address in the
+ * mapping formula is treated as unsigned (part of the compiler's ABI), so the
+ * end of the shadow memory region is at a large positive offset from
+ * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
+ * formula is treated as signed. Since all kernel addresses are negative, they
+ * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_OFFSET
+ * itself the end of the shadow memory region. (User pointers are positive and
+ * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memory is
+ * not allocated for them.)
  *
  * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The shadow
  * memory start must map to the lowest possible kernel virtual memory address
@@ -100,7 +108,11 @@
  */
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_KASAN_GENERIC
 #define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) + KASAN_SHADOW_OFFSET)
+#else
+#define KASAN_SHADOW_END	KASAN_SHADOW_OFFSET
+#endif
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (UL(1) << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START	_KASAN_SHADOW_START(vabits_actual)
 #define PAGE_END		KASAN_SHADOW_START
diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
index c26489cf96cd..4658d59b7ea6 100644
--- a/arch/arm64/mm/Makefile
+++ b/arch/arm64/mm/Makefile
@@ -15,4 +15,6 @@ obj-$(CONFIG_ARM64_GCS)		+= gcs.o
 KASAN_SANITIZE_physaddr.o	+= n
 
 obj-$(CONFIG_KASAN)		+= kasan_init.o
+obj-$(CONFIG_KASAN_SW_TAGS)	+= kasan_sw_tags.o
 KASAN_SANITIZE_kasan_init.o	:= n
+KASAN_SANITIZE_kasan_sw_tags.o	:= n
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index abeb81bf6ebd..937f6eb8115b 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
 /* The early shadow maps everything to a single page of zeroes */
 asmlinkage void __init kasan_early_init(void)
 {
-	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
-		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+			KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	else
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALIGN));
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW_ALIGN));
 	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
diff --git a/arch/arm64/mm/kasan_sw_tags.c b/arch/arm64/mm/kasan_sw_tags.c
new file mode 100644
index 000000000000..d509db7bdc7e
--- /dev/null
+++ b/arch/arm64/mm/kasan_sw_tags.c
@@ -0,0 +1,35 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * This file contains ARM64 specific KASAN sw_tags code.
+ */
+
+#include <linux/kasan.h>
+
+bool __arch_kasan_non_canonical_hook(unsigned long addr)
+{
+	/*
+	 * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
+	 * arithmetic shift. Normally, this would make checking for a possible
+	 * shadow address complicated, as the shadow address computation
+	 * operation would overflow only for some memory addresses. However, due
+	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
+	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
+	 * the overflow always happens.
+	 *
+	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
+	 * possible shadow addresses belong to a region that is the result of
+	 * kasan_mem_to_shadow() applied to the memory range
+	 * [0xFF00000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, the
+	 * resulting possible shadow region is contiguous, as the overflow
+	 * happens for both 0xFF00000000000000 and 0xFFFFFFFFFFFFFFFF.
+	 *
+	 * Reset the addr's tag bits so the inline mode which still uses
+	 * the logical shift can work correctly. Otherwise it would
+	 * always return because of the 'smaller than' comparison below.
+	 */
+	addr |= (0xFFULL << 56);
+	if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)) ||
+	    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+		return true;
+	return false;
+}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9c6ac4b62eb9..0f65e88cc3f6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -62,8 +62,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
 #ifndef kasan_mem_to_shadow
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
-	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
-		+ KASAN_SHADOW_OFFSET;
+	void *scaled;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+	else
+		scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+
+	return KASAN_SHADOW_OFFSET + scaled;
 }
 #endif
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fc9169a54766..02574e53d980 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -558,6 +558,13 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 #error kasan_arch_is_ready only works in KASAN generic outline mode!
 #endif
 
+#ifndef arch_kasan_non_canonical_hook
+static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
+{
+	return false;
+}
+#endif
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_kunit_test_suite_start(void);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 62c01b4527eb..53152d148deb 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -642,10 +642,19 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * All addresses that came as a result of the memory-to-shadow mapping
-	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
+	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values. Thus,
+	 * the possible shadow addresses (even for bogus pointers) belong to a
+	 * single contiguous region that is the result of kasan_mem_to_shadow()
+	 * applied to the whole address space.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+			return;
+	}
+
+	if (arch_kasan_non_canonical_hook(addr))
 		return;
 
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
index 56730b3fde0b..4b86202b155f 100644
--- a/scripts/gdb/linux/kasan.py
+++ b/scripts/gdb/linux/kasan.py
@@ -7,7 +7,8 @@
 #
 
 import gdb
-from linux import constants, mm
+from linux import constants, utils, mm
+from ctypes import c_int64 as s64
 
 def help():
     t = """Usage: lx-kasan_mem_to_shadow [Hex memory addr]
@@ -39,6 +40,8 @@ class KasanMemToShadow(gdb.Command):
         else:
             help()
     def kasan_mem_to_shadow(self, addr):
+        if constants.CONFIG_KASAN_SW_TAGS and not utils.is_target_arch('x86'):
+            addr = s64(addr)
         return (addr >> self.p_ops.KASAN_SHADOW_SCALE_SHIFT) + self.p_ops.KASAN_SHADOW_OFFSET
 
 KasanMemToShadow()
diff --git a/scripts/gdb/linux/mm.py b/scripts/gdb/linux/mm.py
index 7571aebbe650..2e63f3dedd53 100644
--- a/scripts/gdb/linux/mm.py
+++ b/scripts/gdb/linux/mm.py
@@ -110,12 +110,13 @@ class aarch64_page_ops():
         self.KERNEL_END = gdb.parse_and_eval("_end")
 
         if constants.LX_CONFIG_KASAN_GENERIC or constants.LX_CONFIG_KASAN_SW_TAGS:
+            self.KASAN_SHADOW_OFFSET = constants.LX_CONFIG_KASAN_SHADOW_OFFSET
             if constants.LX_CONFIG_KASAN_GENERIC:
                 self.KASAN_SHADOW_SCALE_SHIFT = 3
+                self.KASAN_SHADOW_END = (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
             else:
                 self.KASAN_SHADOW_SCALE_SHIFT = 4
-            self.KASAN_SHADOW_OFFSET = constants.LX_CONFIG_KASAN_SHADOW_OFFSET
-            self.KASAN_SHADOW_END = (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
+                self.KASAN_SHADOW_END = self.KASAN_SHADOW_OFFSET
             self.PAGE_END = self.KASAN_SHADOW_END - (1 << (self.vabits_actual - self.KASAN_SHADOW_SCALE_SHIFT))
         else:
             self.PAGE_END = self._PAGE_END(self.VA_BITS_MIN)
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/eb5ed91489b648fcb0f7cbe3fe4347ba4e636b65.1768845098.git.m.wieczorretman%40pm.me.
