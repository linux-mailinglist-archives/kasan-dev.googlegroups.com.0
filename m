Return-Path: <kasan-dev+bncBD4NDKWHQYDRBV4L66WAMGQEOWMO7YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E52F4828F86
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:16:56 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35f49926297sf44779935ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:16:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838615; cv=pass;
        d=google.com; s=arc-20160816;
        b=pQo9e1WQKeulAntx6Ae8Oy3slMQTeLivz2/H1u1IIyxHSwCbydzapqXbjHgM2d+vO8
         Xm7TWnYrZzIoT9YnmlokR/boj1IUoV8cfYJlezDlP7/YA1F0oDQq0oQgFfyhKvT1rT3E
         bywkKElXERYCwKo3JWMQS+IPre1z6Fwr1HG1nRXl02NsZvNX5wRvieqhvhA0G72soe88
         TUSCF6nJwgO6ZqUpFayX1TUA4rWBcjBnB+Si3Y2J8m/xsurYYi8cnm+aSLMpfjbUKUyw
         B5cnF5r0h9vwnmP7GvHHA57o5xDr2cT04wsQUCZcgrzkDx5mcAjJPOqXewMjFzr+R+Vd
         VoDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=TEn01WZeKctdtrMDt4JRfe0fcmOOV4gceKF+zkMOgNc=;
        fh=dTe6zL5Ivivq2KoKBIkxib/65Ipl1ye2APy+yz2cYE8=;
        b=fcVEfEn8C8ikf8GsUoCAXKoew/P+f0kwR9n0aMpArBzdaWEWmqHyD9aZHq1wJ1xPM3
         rEwXSECITfv2AZ+QPf90p0zbfsyAucTG2YTHCPq4F6scCiQ5gNTqX97m6rFHOajDTGZO
         fiYt4ssOwnXL36co1B4zkqKZrkDLmqUJL+1WwBweCbyTMCLdpFoR91gAMBfj8FJPhhyq
         +m7L54syLpKWFuyM2ZtJeCH6tVLPvYkTvvthEPGWz4QKHzhIix8x7IkdZlCQAUFYOHSQ
         gwJyQAIRB1rg4iZgJS/94Qj7x+rvRMO3GMQW9smSms+uZcOw8Xhbiaw5pt9ZiG+TtWYQ
         /HjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nwd91x1d;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838615; x=1705443415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TEn01WZeKctdtrMDt4JRfe0fcmOOV4gceKF+zkMOgNc=;
        b=AKGfEvd4SEJa3/D+A+UwbZQCi9180pED1vUPZ3PY0+1h73JFDWz8AOQYpgJbejBmkp
         Y+pfJc4oIJ5Q0CGflXbb9HRALrRyBAGjTETPZizS/nEODgYu5vK/ZUEV6MTMDMXOJVo0
         +tuI4rj4X+14pwCKMDwP+z8a7n6f7ooGI1X3swU/qvQyz6npiqN1wCzGdkJJLHZBn3Bm
         ucEO8A698qZ43dfyVpM4Hzzu24/tkCNK0iKNzaDfdbFgXuvErWk5WsJt1Xhv4eKIAoSX
         gzvF30f3VosEgL3e+vOtjyJAALFNI7mMbNSpai4fEEIfR/RuXxMoRfD+/8syNDhSVgsg
         R6Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838615; x=1705443415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TEn01WZeKctdtrMDt4JRfe0fcmOOV4gceKF+zkMOgNc=;
        b=uKfglAMhejMkjUjTDyww4FRwgxPS/Thi3Vs/ZME1ImPp6UuM2HQWsedD96a82SkEyk
         YUlt4HxVdPN+Hy3HJhzyh1H/kB/6gcqWzoHACNzcE9ggZ6lABebz322w8RjmTLDs/zgT
         EqGIuumh8XUoGpEK+RwTjvw/YTkjQYeD+wWK8CxyNGJ3CtjGwiJeup5l1zlGpAPMrNWa
         wfjxjgXMirL4cB0MWTD4sPhene7nfGmzlyZjllJ3iBsFpqlZoatDngJcYTDeWT2vg8W2
         l1HknuW0mkUKZQ5R0+1Y5jNtMDi7JT4HbT/HxWUpTqwzu17Ow/MPY6pnPH9bUyTYt+jr
         Q+/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxMuxqSwbdgRQTUEQjLouWw6dA2pxd8TJLQBgbI3jG/ugp4voTO
	UV8SdW2ogSd2XcTVyr8bCAI=
X-Google-Smtp-Source: AGHT+IGGRIVknVmsIW0Bss5tC3lQkORqP2HAcAtAX4seJkADcRp5q7AVvAV0EwuscYJK4ayU3eqTFA==
X-Received: by 2002:a92:ca0f:0:b0:360:615d:5612 with SMTP id j15-20020a92ca0f000000b00360615d5612mr136843ils.57.1704838615410;
        Tue, 09 Jan 2024 14:16:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:50d:b0:360:16bb:ff94 with SMTP id
 d13-20020a056e02050d00b0036016bbff94ls753553ils.0.-pod-prod-02-us; Tue, 09
 Jan 2024 14:16:54 -0800 (PST)
X-Received: by 2002:a6b:e60f:0:b0:7bb:dd2f:477a with SMTP id g15-20020a6be60f000000b007bbdd2f477amr142297ioh.13.1704838613726;
        Tue, 09 Jan 2024 14:16:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838613; cv=none;
        d=google.com; s=arc-20160816;
        b=gKW1hBBu120OxY2Ir+KQorJX365+CBiPNkQ4q47PnF2QPvB7+jRMY/7cLFMjIzCsl8
         o7D6T7khxBsphduZRmtjS65FEuedWK0vnAMZWTfp8W+51WsQ7pY7A7ZQT1fpntNWjka6
         txEPiyBAOJVmO05uDy/obp7LgKx5NXgVVK2w2UKsyMDXDFnybpXr09ETrlMt/czH1/Jl
         GtG4dsgzyOL+0D05Ke61L71enaNbbiqc3/Gy8/2UbiLe0ME4u8e68QAa8Cj55GlqEMh9
         zGWdp1SHp38Qk4HKXgOYhtDzmVlKoBhwNn3AGw7PeIsyG0JG9XIX9hgFZ53S2O6kf+1m
         4JjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=A/YH3B9yUYFhZKC27yo0w0Zww0sg09I4AJ3N1zIXhqc=;
        fh=dTe6zL5Ivivq2KoKBIkxib/65Ipl1ye2APy+yz2cYE8=;
        b=lJWu9qFNJEkg+uhBSd44H7J3lAx07MvsAhGfsvgB0to92wKlJUhr1sT6u8rXnbmKzh
         2qBuWwBs5Qo4pYLh9zT2Nk41k1EyT/auLVrQ0aaWWBwqgD0LgWkc9DK54xP6OGj2sE9J
         crI4pgy7MsSsqHBOZkt4twUn/CBGhwIrJN6s7+jFUoaSzaf0m7b9jVgPuwl8mBOQU8Jw
         ibVliTcrqY7FV9WMtaK0cIftHFTciCQ7m+kxc3ViI3gcnxnfEm5p+4Vl1FkXu6mJFy2G
         lpTVC2hXIFM3PSAE6WWsdYw9YAEUB54Dkj1pu7rHetkB6tpZolxjUDS7ZeEw1eoNmzp3
         K9+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nwd91x1d;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id v26-20020a6b611a000000b007bef30e05ebsi45033iob.4.2024.01.09.14.16.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 14:16:53 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3FC2461595;
	Tue,  9 Jan 2024 22:16:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65911C43390;
	Tue,  9 Jan 2024 22:16:50 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
Date: Tue, 09 Jan 2024 15:16:29 -0700
Subject: [PATCH 1/3] selftests/bpf: Update LLVM Phabricator links
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
In-Reply-To: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
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
X-Developer-Signature: v=1; a=openpgp-sha256; l=7587; i=nathan@kernel.org;
 h=from:subject:message-id; bh=eFscEoCIAi+UJQp3abWYRAO4Lvaf4O8cRgQlKNDdBDE=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDKlzj15IUNPmFinNmNO40TyB+eHTwFMf6kVvPC5Rrjn6Z
 JdC/PJtHaUsDGJcDLJiiizVj1WPGxrOOct449QkmDmsTCBDGLg4BWAiwu8YGVbUeWkdrFi1UUdq
 4sron76zUsq4BZg2/XauNjb4rF67R4iR4W11UIPnynvJDpfc96myPrzLNvclj2HuZymRz+4ctQ5
 n2AA=
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nwd91x1d;       spf=pass
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

reviews.llvm.org was LLVM's Phabricator instances for code review. It
has been abandoned in favor of GitHub pull requests. While the majority
of links in the kernel sources still work because of the work Fangrui
has done turning the dynamic Phabricator instance into a static archive,
there are some issues with that work, so preemptively convert all the
links in the kernel sources to point to the commit on GitHub.

Most of the commits have the corresponding differential review link in
the commit message itself so there should not be any loss of fidelity in
the relevant information.

Additionally, fix a typo in the xdpwall.c print ("LLMV" -> "LLVM") while
in the area.

Link: https://discourse.llvm.org/t/update-on-github-pull-requests/71540/172
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
Cc: ast@kernel.org
Cc: daniel@iogearbox.net
Cc: andrii@kernel.org
Cc: mykolal@fb.com
Cc: bpf@vger.kernel.org
Cc: linux-kselftest@vger.kernel.org
---
 tools/testing/selftests/bpf/README.rst             | 32 +++++++++++-----------
 tools/testing/selftests/bpf/prog_tests/xdpwall.c   |  2 +-
 .../selftests/bpf/progs/test_core_reloc_type_id.c  |  2 +-
 3 files changed, 18 insertions(+), 18 deletions(-)

diff --git a/tools/testing/selftests/bpf/README.rst b/tools/testing/selftests/bpf/README.rst
index cb9b95702ac6..b9a493f66557 100644
--- a/tools/testing/selftests/bpf/README.rst
+++ b/tools/testing/selftests/bpf/README.rst
@@ -115,7 +115,7 @@ the insn 20 undoes map_value addition. It is currently impossible for the
 verifier to understand such speculative pointer arithmetic.
 Hence `this patch`__ addresses it on the compiler side. It was committed on llvm 12.
 
-__ https://reviews.llvm.org/D85570
+__ https://github.com/llvm/llvm-project/commit/ddf1864ace484035e3cde5e83b3a31ac81e059c6
 
 The corresponding C code
 
@@ -165,7 +165,7 @@ This is due to a llvm BPF backend bug. `The fix`__
 has been pushed to llvm 10.x release branch and will be
 available in 10.0.1. The patch is available in llvm 11.0.0 trunk.
 
-__  https://reviews.llvm.org/D78466
+__  https://github.com/llvm/llvm-project/commit/3cb7e7bf959dcd3b8080986c62e10a75c7af43f0
 
 bpf_verif_scale/loop6.bpf.o test failure with Clang 12
 ======================================================
@@ -204,7 +204,7 @@ r5(w5) is eventually saved on stack at insn #24 for later use.
 This cause later verifier failure. The bug has been `fixed`__ in
 Clang 13.
 
-__  https://reviews.llvm.org/D97479
+__  https://github.com/llvm/llvm-project/commit/1959ead525b8830cc8a345f45e1c3ef9902d3229
 
 BPF CO-RE-based tests and Clang version
 =======================================
@@ -221,11 +221,11 @@ failures:
 - __builtin_btf_type_id() [0_, 1_, 2_];
 - __builtin_preserve_type_info(), __builtin_preserve_enum_value() [3_, 4_].
 
-.. _0: https://reviews.llvm.org/D74572
-.. _1: https://reviews.llvm.org/D74668
-.. _2: https://reviews.llvm.org/D85174
-.. _3: https://reviews.llvm.org/D83878
-.. _4: https://reviews.llvm.org/D83242
+.. _0: https://github.com/llvm/llvm-project/commit/6b01b465388b204d543da3cf49efd6080db094a9
+.. _1: https://github.com/llvm/llvm-project/commit/072cde03aaa13a2c57acf62d79876bf79aa1919f
+.. _2: https://github.com/llvm/llvm-project/commit/00602ee7ef0bf6c68d690a2bd729c12b95c95c99
+.. _3: https://github.com/llvm/llvm-project/commit/6d218b4adb093ff2e9764febbbc89f429412006c
+.. _4: https://github.com/llvm/llvm-project/commit/6d6750696400e7ce988d66a1a00e1d0cb32815f8
 
 Floating-point tests and Clang version
 ======================================
@@ -234,7 +234,7 @@ Certain selftests, e.g. core_reloc, require support for the floating-point
 types, which was introduced in `Clang 13`__. The older Clang versions will
 either crash when compiling these tests, or generate an incorrect BTF.
 
-__  https://reviews.llvm.org/D83289
+__  https://github.com/llvm/llvm-project/commit/a7137b238a07d9399d3ae96c0b461571bd5aa8b2
 
 Kernel function call test and Clang version
 ===========================================
@@ -248,7 +248,7 @@ Without it, the error from compiling bpf selftests looks like:
 
   libbpf: failed to find BTF for extern 'tcp_slow_start' [25] section: -2
 
-__ https://reviews.llvm.org/D93563
+__ https://github.com/llvm/llvm-project/commit/886f9ff53155075bd5f1e994f17b85d1e1b7470c
 
 btf_tag test and Clang version
 ==============================
@@ -264,8 +264,8 @@ Without them, the btf_tag selftest will be skipped and you will observe:
 
   #<test_num> btf_tag:SKIP
 
-.. _0: https://reviews.llvm.org/D111588
-.. _1: https://reviews.llvm.org/D111199
+.. _0: https://github.com/llvm/llvm-project/commit/a162b67c98066218d0d00aa13b99afb95d9bb5e6
+.. _1: https://github.com/llvm/llvm-project/commit/3466e00716e12e32fdb100e3fcfca5c2b3e8d784
 
 Clang dependencies for static linking tests
 ===========================================
@@ -274,7 +274,7 @@ linked_vars, linked_maps, and linked_funcs tests depend on `Clang fix`__ to
 generate valid BTF information for weak variables. Please make sure you use
 Clang that contains the fix.
 
-__ https://reviews.llvm.org/D100362
+__ https://github.com/llvm/llvm-project/commit/968292cb93198442138128d850fd54dc7edc0035
 
 Clang relocation changes
 ========================
@@ -292,7 +292,7 @@ Here, ``type 2`` refers to new relocation type ``R_BPF_64_ABS64``.
 To fix this issue, user newer libbpf.
 
 .. Links
-.. _clang reloc patch: https://reviews.llvm.org/D102712
+.. _clang reloc patch: https://github.com/llvm/llvm-project/commit/6a2ea84600ba4bd3b2733bd8f08f5115eb32164b
 .. _kernel llvm reloc: /Documentation/bpf/llvm_reloc.rst
 
 Clang dependencies for the u32 spill test (xdpwall)
@@ -304,6 +304,6 @@ from running test_progs will look like:
 
 .. code-block:: console
 
-  test_xdpwall:FAIL:Does LLVM have https://reviews.llvm.org/D109073? unexpected error: -4007
+  test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -4007
 
-__ https://reviews.llvm.org/D109073
+__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d
diff --git a/tools/testing/selftests/bpf/prog_tests/xdpwall.c b/tools/testing/selftests/bpf/prog_tests/xdpwall.c
index f3927829a55a..4599154c8e9b 100644
--- a/tools/testing/selftests/bpf/prog_tests/xdpwall.c
+++ b/tools/testing/selftests/bpf/prog_tests/xdpwall.c
@@ -9,7 +9,7 @@ void test_xdpwall(void)
 	struct xdpwall *skel;
 
 	skel = xdpwall__open_and_load();
-	ASSERT_OK_PTR(skel, "Does LLMV have https://reviews.llvm.org/D109073?");
+	ASSERT_OK_PTR(skel, "Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5?");
 
 	xdpwall__destroy(skel);
 }
diff --git a/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c b/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
index 22aba3f6e344..6fc8b9d66e34 100644
--- a/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
+++ b/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
@@ -80,7 +80,7 @@ int test_core_type_id(void *ctx)
 	 * to detect whether this test has to be executed, however strange
 	 * that might look like.
 	 *
-	 *   [0] https://reviews.llvm.org/D85174
+	 *   [0] https://github.com/llvm/llvm-project/commit/00602ee7ef0bf6c68d690a2bd729c12b95c95c99
 	 */
 #if __has_builtin(__builtin_preserve_type_info)
 	struct core_reloc_type_id_output *out = (void *)&data.out;

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240109-update-llvm-links-v1-1-eb09b59db071%40kernel.org.
