Return-Path: <kasan-dev+bncBAABBXNHX3FQMGQEPUERBTY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CFLiBLKhb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBXNHX3FQMGQEPUERBTY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:39:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C1D44654E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:39:29 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-81e7fd70908sf9802442b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:39:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923568; cv=pass;
        d=google.com; s=arc-20240605;
        b=KST3EKmZi89/WYxSxMfVK1k2WVp3eluUNeSsQDhEnyas0RlWDurVHhQn2WKUwy7lqt
         IILvlGA/u+TEN3JmTsnFQ/WKxlr0ETTrRBTQ0N8QMR7YLGtNs+DbgaarqIizOr/C/y+l
         oxhKpqlVDWQFO9SfMzcmEWb5AZJ+uohMRcKpZnp+Q1Hjt/UIWOoZaWlFXHt1jUYxHM1R
         A246Peh0TfJ3L7GSNDJnzkt1HFndKyeRS6dEyDiPgJLVZobZq/KTGx4ezZ/Wclju0pAy
         EoBdKRCd/2tyg2lpaIKhKRX6rBnaF+dh2E5zI188QPVoEyX1uidTU/QyWnh1wQ6cJmVC
         G1lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=5c4XDZ0gtx0dF85pHsjV57m6r1gtV1H6UfmVbAbNZNo=;
        fh=4K2fnTLlESDPwcdFx4WYwxDARzsWUN3U3xRINsi8ILI=;
        b=LRnIinYLu9s4GhPD2e1mxZQF+T+NiElkhU2sBlTPCSBfszPGs2kAvHPMuXaIiMulhj
         LmNZsu04+H6+y7VJcguU3EXY344FtaJvUBuqYaSdbU+NAe5/rrugmWLXUOvGrT3g9IpM
         svA+TZNLDiWfzcYdZ6iOI6VbFqbVm5Uw9Ggu7uQSvkjnnXpdO+oFClI2bwbAj8/SEVhW
         KPjf2GbhiRo0wkoFcW24XNIqfRWIFNyNgtilcoB+VRptxXqwje8gFiMI2LS0oAF0+hkQ
         ap7XHVIBj7FfD6piSgHaZyuBrhqEab6Ifo9AJqdkDax5MZnP3txhdY4LhEeDHQKg4JZ4
         nu2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GyWAu6jQ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923568; x=1769528368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=5c4XDZ0gtx0dF85pHsjV57m6r1gtV1H6UfmVbAbNZNo=;
        b=LVrDoy0bDcDVTwSkOZEt2f8TQ6Cy79jdxKtLtB0mKxVrZinKQ5namKdxnljTeX2Mkv
         JmIv4wlxdxmT4KAGquXdTq2RdNfqCVf5KW+iMfEUqolgE5Esm7++ePTelkDZnRXIFhjK
         S8yFLJrD0BN3qpDfSFbxhd0iOe69H0lQUiwoVYYUO+WaYI//gfY+sVPckgku9ARE5qH8
         GS2vnlKYi6guO6KxBvJKEcIB/G/cdhUWoYT1AucFjPnkweljXSwOKuZMB/O0LhidG5TZ
         vwEyh7qM9+GRfaJ8gRrTEbYFlmjro4mXiU9SSeFJs+TnvuXV4zhfZgXYpttYnPA5Q0V1
         367Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923568; x=1769528368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5c4XDZ0gtx0dF85pHsjV57m6r1gtV1H6UfmVbAbNZNo=;
        b=bSq/HpbcRh1bZD/uzeHnP7vaAQNreU8VPWJIjQ9WWhex66A8T6OzHUzQz3gHu10sHR
         wktoo38babQJHYl46hhgAQNnC8MKgiRyiL1i2ovQY/Nmkk/Rwlo44B5rLigThHsouXzX
         PIEIc7TMiqk6Cv4Bq4w+uUZOYFTvDAbJbimfyPhrNzsa6tQosYvUbl67z16f9wLv5K5B
         Djf/NLou4ZnP4GnJLQIgQY6jb7UDyqgmgFqFwfdDEpelSNXi27DGRLH7gj07CT3XDkC1
         RMtgF4eHtNzYWvilHSEKfe7NgD2CGQtJoMoNGqYattcaj5029ztI78Me0Zg1kWs9XSU1
         /+xA==
X-Forwarded-Encrypted: i=2; AJvYcCVKkyYCFu5CmFa7DmBiQCx9qVNmK/OotqpN2H3u9wh1KdUAYsi4h0aJ+4mvPKb8zZQu9dk+1g==@lfdr.de
X-Gm-Message-State: AOJu0Yz66M1uLTSrKAFkxdhHCLpG5KKQcCgrT7PzGruvz8Jnib6GBO1A
	zJ3/TcoAM9MtSCdzjq8Rrd5FakGcI42nAPgQWtEA9GnIC6iUnSlTMYI7
X-Received: by 2002:a05:7022:438d:b0:11b:9386:a381 with SMTP id a92af1059eb24-1244a79367dmr10274595c88.48.1768920030339;
        Tue, 20 Jan 2026 06:40:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hylu1aDOrg7eA4A0bJaSA4er1XeznbM+O1JL13Jg+o0g=="
Received: by 2002:a05:7022:3888:b0:11b:519:fc3e with SMTP id
 a92af1059eb24-1233e1d1040ls2522073c88.0.-pod-prod-03-us; Tue, 20 Jan 2026
 06:40:29 -0800 (PST)
X-Received: by 2002:a05:7301:e06:b0:2b0:5342:e00a with SMTP id 5a478bee46e88-2b6b3f2a334mr9124164eec.15.1768920028851;
        Tue, 20 Jan 2026 06:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920028; cv=none;
        d=google.com; s=arc-20240605;
        b=hACmhyfuNQ9OmTaoqG5+auxdpLyHY1RqVe9kPJ2t6w1PzsMsKyNhoCWKHz0Gjmit4i
         EYFExPT8/pVyFpSMhfXrQpzsikVJUAaPcda+Mz3e+kwHEIfFHI2UMaRodiEokEGJbUiR
         col+YFp9oujq4/thNLJqDBO/RyR8Qzea3rKqFsbJkqwKzXcqNodMXGgmzIMjZQSISEtv
         gJpHuX8YSQrW9hV/GESI0l4WrSIXDY8OW/oFYswwNMh8aEycNt11Pj7w/viu2dlgJ2mO
         r3FV947pPddbo0YpiY4SbMdC2aILrVDhdvO1wAU1RJdI7MJhWGRFll7rWfTEXV9oDvrH
         71Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=SYwR7mzcRNmkDkZFtWt3FaqD6GeRNp89lD+pp3qVLF0=;
        fh=0JQnp5GyzOkS+lZUaKBotFveEKraiEBcE8LaAkI09JY=;
        b=c6/AgPp+CONve2s5NaDmZb/zMmWwnfOfIlRHtYMsj855P0rw9wID/fZTRk7ATRzNxU
         8X2GupIsqIHT5f90AOzhAXndJrUbNWQX44GGv5/KNljLXKej4lnmMmaUJ5ZNJO4CSHiK
         2h6fswBRvXo0Ct/+wkx6SKWQVszk9AXMM5rEsTwt2RN1kAeDpR3mXbbT7ia1FKu5ps0M
         Q7nnOwcDKPy2mUVDr+dtknv3HivfbDpBFNV+AwDnr8MOHifQdxS/LpGH0o9ehY6aJeiV
         whcNJLCxdWnKQfuw+q72Ih0Lb/Egyc8uz/4wLK0cv4zVh5CStg/gE1Q2xxgo+wBZnz2R
         IhJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GyWAu6jQ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b6b3643bc8si402486eec.3.2026.01.20.06.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Tue, 20 Jan 2026 14:40:15 +0000
To: chleroy@kernel.org, surenb@google.com, justinstitt@google.com, nsc@kernel.org, jan.kiszka@siemens.com, trintaeoitogc@gmail.com, dave.hansen@linux.intel.com, ryabinin.a.a@gmail.com, kees@kernel.org, maciej.wieczor-retman@intel.com, urezki@gmail.com, will@kernel.org, nick.desaulniers+lkml@gmail.com, brgerst@gmail.com, ubizjak@gmail.com, rppt@kernel.org, samitolvanen@google.com, thuth@redhat.com, mhocko@suse.com, nathan@kernel.org, osandov@fb.com, thomas.lendacky@amd.com, yeoreum.yun@arm.com, akpm@linux-foundation.org, catalin.marinas@arm.com, morbo@google.com, andreyknvl@gmail.com, jackmanb@google.com, mingo@redhat.com, jpoimboe@kernel.org, vbabka@suse.cz, corbet@lwn.net, lorenzo.stoakes@oracle.com, vincenzo.frascino@arm.com, luto@kernel.org, glider@google.com, weixugc@google.com, axelrasmussen@google.com, samuel.holland@sifive.com, kbingham@kernel.org, jeremy.linton@arm.com, kas@kernel.org, tglx@kernel.org, ardb@kernel.org, peterz@infradead.org, hpa@zytor.com, dvyukov@google.com,
	yuanchu@google.com, leitao@debian.org, david@kernel.org, anshuman.khandual@arm.com, bp@alien8.de, Liam.Howlett@oracle.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, m.wieczorretman@pm.me
Subject: [PATCH v9 00/13] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 73a30de0b93895cc80a2f788f03a5bd41b564548
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=GyWAu6jQ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBXNHX3FQMGQEPUERBTY];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[3];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FREEMAIL_TO(0.00)[kernel.org,google.com,siemens.com,gmail.com,linux.intel.com,intel.com,redhat.com,suse.com,fb.com,amd.com,arm.com,linux-foundation.org,suse.cz,lwn.net,oracle.com,sifive.com,infradead.org,zytor.com,debian.org,alien8.de];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCPT_COUNT_GT_50(0.00)[62];
	TO_DN_NONE(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,pm.me:mid,pm.me:replyto]
X-Rspamd-Queue-Id: 7C1D44654E
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

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
	  purpose. The attempt to move it over to use UD1 is already
	  implemented and tested but relies on another series that needs
	  merging first. Therefore this patch will be posted separately
	  once the dependency is satisfied by being merged upstream.

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
x86. Patchset does seem to compile with gcc without an issue but doesn't
boot afterwards.

======= Dependencies
The series is based on 6.19-rc6.

======= Previous versions
v8: https://lore.kernel.org/all/cover.1768233085.git.m.wieczorretman@pm.me/
v7: https://lore.kernel.org/all/cover.1765386422.git.m.wieczorretman@pm.me/
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

Changes v9:
- Lock HAVE_ARCH_KASAN_SW_TAGS behind CC_IS_CLANG due to gcc not working
  in practice.
- Remove pr_info() from KASAN initialization.
- Add paragraph to mm.rst explaining the alternative KASAN memory
  ranges.
- Move out arch based code from kasan_non_canonical_hook() into arch
  subdirectories. arm64 and non-arch changes in patch 1, x86 changes in
  patch 12.
- Reset tag bits on arm64's non-canonical hook to allow inline mode to
  work.
- Revert modifying __is_canonical_address() since it can break KVM. Just
  untag address in copy_from_kernel_no_fault_allowed().
- Add a bunch of reviewed-by tags.

Changes v8:
- Detached the UD1/INT3 inline patch from the series so the whole
  patchset can be merged without waiting on other dependency series. For
  now with lack of compiler support for the inline mode that patch
  didn't work anyway so this delay is not an issue.
- Rebased patches onto 6.19-rc5.
- Added acked-by tag to "kasan: arm64: x86: Make special tags arch
  specific".

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

Maciej Wieczor-Retman (11):
  kasan: Fix inline mode for x86 tag-based mode
  x86/kasan: Add arch specific kasan functions
  x86/mm: Reset tag for virtual to physical address conversions
  mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
  x86/mm: Use physical address comparisons in fill_p*d/pte
  x86/kasan: Initialize KASAN raw shadow memory
  x86/mm: Reset tags in a canonical address helper call
  x86/mm: Initialize LAM_SUP
  x86: Increase minimal SLAB alignment for KASAN
  x86/kasan: Use a logical bit shift for kasan_mem_to_shadow
  x86/kasan: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: arm64: x86: Make special tags arch specific

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      | 10 ++-
 MAINTAINERS                               |  4 +-
 arch/arm64/Kconfig                        | 10 +--
 arch/arm64/include/asm/kasan-tags.h       | 14 ++++
 arch/arm64/include/asm/kasan.h            |  7 +-
 arch/arm64/include/asm/memory.h           | 14 +++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/mm/Makefile                    |  2 +
 arch/arm64/mm/kasan_init.c                |  7 +-
 arch/arm64/mm/kasan_sw_tags.c             | 35 ++++++++++
 arch/x86/Kconfig                          |  4 ++
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 79 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               |  8 +++
 arch/x86/include/asm/page_64.h            |  1 +
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 24 ++++++-
 arch/x86/mm/maccess.c                     |  2 +-
 arch/x86/mm/physaddr.c                    |  2 +
 include/linux/kasan-tags.h                | 21 ++++--
 include/linux/kasan.h                     | 13 ++--
 include/linux/mm.h                        |  6 +-
 include/linux/mmzone.h                    |  2 +-
 include/linux/page-flags-layout.h         |  9 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  9 ++-
 mm/kasan/kasan.h                          |  7 ++
 mm/kasan/report.c                         | 15 ++++-
 mm/vmalloc.c                              |  7 +-
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 37 files changed, 312 insertions(+), 56 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/arm64/mm/kasan_sw_tags.c
 create mode 100644 arch/x86/include/asm/kasan-tags.h

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1768845098.git.m.wieczorretman%40pm.me.
