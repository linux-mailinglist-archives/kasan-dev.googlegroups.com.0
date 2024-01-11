Return-Path: <kasan-dev+bncBDWYV74TWAEBBIGS7WWAMGQET4MFAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2530582A6B8
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 05:05:59 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2cd0804c5e6sf40875621fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 20:05:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704945953; cv=pass;
        d=google.com; s=arc-20160816;
        b=wS6/Vn0gEa6spkxN8OCBrlX+hhOqoBnLfT90TQq2kWRn0ClVeVhsLskKlgGPnveRTw
         EGBruflcxquvN2a3z6EyqAx7Yzo49HhwEvgLIot+84jYHAIhT+Be2dCK66WyAiW62Rtp
         fOMhxkWj3wocc7YNP0Ip3K31UuMmxl8pFxrubmzueHYFj+TwYg4dKq0yahS5MTsLYXnX
         0p7pe/wtG/i3eQ85j/R88XkyY5hE6PzbmkvQNw+p9i8jBvhP5jVoxGi7gecw5IJ0sQ7C
         43zl7jHlWKmAxFJ4W9suU8F7SN22TnmkVGQDtjUNUfKn9UUviWqby3cndbLkAQfomT2F
         5aHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=vcxMWWLIjhkX1rwRrHcB/KAkiYkSF5LsI8urLHVO5xA=;
        fh=VwW8+mhp6AdbToJNpN49j4VtbFvk0EJL+lV4swZIG/A=;
        b=XDFxv1XNo9xwGtokn8fstHxg/nd9pwVv1Vydg+5V9mxn6AlxI7BLN1xw4XAxlehxpR
         bIlRmD7g2riYmf3JH3r8H9/UKQ7P+GcaFhHWIenMn72UNVXYc3L9sdNhXJhvvTCLBSKC
         kdwaa8w/dr05Nq1OKQnnISvzv54i8IuJByj3dPK5RDxaUwYsPB7ZYz+RWbE3+xm0QHkl
         EYYW3iakIvpdYs1UytQIucmtZfuAP0FcooZUO0SOTzl52qLLTs2R0PrnxWYCvhrMdeh6
         PKsFrabDz6Vya6eoXB61mk9gekMZ4AApfkm4PvSCm6nSKekiM48qnMdbG+0Rcm9VTWSq
         Ohkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=q90eKb7K;
       spf=pass (google.com: domain of yonghong.song@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=yonghong.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704945953; x=1705550753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=vcxMWWLIjhkX1rwRrHcB/KAkiYkSF5LsI8urLHVO5xA=;
        b=Gu4p2tcan5Q9U3oEVH+tgyPksRzvHKqsgpBA8a9PwZzGH75szoHwjK5zabhkc4F9Uf
         UhzPS8INhMteZNNm1Go5GUxHEYt0MxHQfjoSxoV1eFgx7s97/h7FHTzHO9vRsysMdhDp
         rZynG+2qsJfhGBXOTsh+54bfX6uUy7NyMP/omRmgJotmDfeXMO4gScCeAH6SXhxbA210
         IkP+YtrNeHDR542IbIrToHebCsudKX8knanX/3jtG1+tPxEwJ4yroM+yAQ0PCYquH5Ne
         KoiA3bLYp9nIZuzy32XjucH+KtiSg1IXBQkmff76gGUTVGQyndd0FEUJ41PYjSSQEKGk
         j74w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704945953; x=1705550753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vcxMWWLIjhkX1rwRrHcB/KAkiYkSF5LsI8urLHVO5xA=;
        b=X31WGqkuFXMf9F5U10ukbC76NxI1HfsP3TdVq2twrduMVPhkcVT8pm3bJJPIpe+faJ
         zfNf0LGWuWqRT+p66htn/vFAgCeJmVQCLkQ3OlMdYM/Bl8putwp4ntEH02mGCCSIXoH2
         a0m6ZXK8uSPGw0Av8rcWqMvo8c225V3BsAj/hlM18FRzzeyo5ymviDSwZXXujjhkpDnj
         WS5/ADUdwOBvKIap1ECvhRYICEhfa8epSV70851yTOQS7RCc8BDZoXj6BfzsvqAGrS6N
         al0lGoeXUun6ONP1XLd2C6mGc3cYULskeU6Y2y3VOaF54CqQ+BZQruSFO49E9oRimVtG
         4iUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YympvaVtGPsBxhwwUU0rnfQBS3+SNUvNTopEvQ/4XrvNfDIpxS4
	2TvjEYDRXIPfVLdbZhOYUrA=
X-Google-Smtp-Source: AGHT+IGphddDrddgoJRYEok6BMj1C/Mf5Qhdb33kS9MuFpZUzQVar1zheMflmYJ0gUrww938MUU7Wg==
X-Received: by 2002:a2e:81ca:0:b0:2cd:7039:e28b with SMTP id s10-20020a2e81ca000000b002cd7039e28bmr28441ljg.17.1704945952928;
        Wed, 10 Jan 2024 20:05:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a11:b0:2cc:ea42:1d66 with SMTP id
 by17-20020a05651c1a1100b002ccea421d66ls32605ljb.1.-pod-prod-05-eu; Wed, 10
 Jan 2024 20:05:51 -0800 (PST)
X-Received: by 2002:a2e:b1d3:0:b0:2cc:eeea:9e8f with SMTP id e19-20020a2eb1d3000000b002cceeea9e8fmr30205lja.13.1704945950695;
        Wed, 10 Jan 2024 20:05:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704945950; cv=none;
        d=google.com; s=arc-20160816;
        b=o2hjsspMOpBMgghZ7wT/A0+pv3fINNA1gW2KyyylFzVZr4NUWNVYaTqz3Kt26xSkLg
         RV9kYcb+hDil51Oo0OU8qILFjba4+UZrSl4E1YtqPgEIVxK87mMOlOmx+eCGkxVPH/NF
         38NOStXtHtWlbCiggbiZfzL12tFg99W++hcyVdSl92mVn4X6iDdPxs+BNyhe8sTS2SuQ
         w0OrC5IlaWeVCcjP4jzqwlRA7V10s9IiPXeEdeZzPrPFdgd2ksZ6Xv/IgxhfJWRWtWHX
         UtHIfxzxC9VAGNJkx5gBKC1Yq4kNj3TLBg17niSwxMR6ZYxDmGxLCQ6PtyuSd0aCBYsA
         8roA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=oe8y6rx2nxJCVb5v6A3KEWIfmf39eOlQDxZDCZDQpSs=;
        fh=VwW8+mhp6AdbToJNpN49j4VtbFvk0EJL+lV4swZIG/A=;
        b=FCskWG5Yzk+7Hc0hXByYILAKspQweGmE0cFaUuRZqh/sla0Y27Vk1oUYnyHh5XGnYh
         aM4/K5udxidvwHsVn3k+6hJypNg1zJ2VsRMFS64rO+x2ffW8/tdWYARleedr3B4+3OEl
         oRsJDUmhK0pWxwXcNCNRODsxtzsfcG8Nn7yJUfIgQsy19CaWaigu5YHzj3O/c9B9pbZT
         Sl7wrw5nELjYuAvnce2QfVEDikVJBI/LY7Eub+3BFLPLA17+qs/OvSVrwN+kJhPVB+m+
         O+6WMagCrAGSOFwBl9LfA+UkkHnyNbCF3dTyG6DRwCZD3yOzO3aNkWCwOz6bC7j8BySR
         NNfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=q90eKb7K;
       spf=pass (google.com: domain of yonghong.song@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=yonghong.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [2001:41d0:203:375::bc])
        by gmr-mx.google.com with ESMTPS id f25-20020a2e9199000000b002ccc27fab8csi8077ljg.7.2024.01.10.20.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jan 2024 20:05:50 -0800 (PST)
Received-SPF: pass (google.com: domain of yonghong.song@linux.dev designates 2001:41d0:203:375::bc as permitted sender) client-ip=2001:41d0:203:375::bc;
Message-ID: <6a655e9f-9878-4292-9d16-f988c4bdfc73@linux.dev>
Date: Wed, 10 Jan 2024 20:05:36 -0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/3] selftests/bpf: Update LLVM Phabricator links
Content-Language: en-GB
To: Nathan Chancellor <nathan@kernel.org>, akpm@linux-foundation.org
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
 linux-kselftest@vger.kernel.org, ast@kernel.org, daniel@iogearbox.net,
 andrii@kernel.org, mykolal@fb.com, bpf@vger.kernel.org
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
 <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yonghong Song <yonghong.song@linux.dev>
In-Reply-To: <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yonghong.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=q90eKb7K;       spf=pass
 (google.com: domain of yonghong.song@linux.dev designates 2001:41d0:203:375::bc
 as permitted sender) smtp.mailfrom=yonghong.song@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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


On 1/9/24 2:16 PM, Nathan Chancellor wrote:
> reviews.llvm.org was LLVM's Phabricator instances for code review. It
> has been abandoned in favor of GitHub pull requests. While the majority
> of links in the kernel sources still work because of the work Fangrui
> has done turning the dynamic Phabricator instance into a static archive,
> there are some issues with that work, so preemptively convert all the
> links in the kernel sources to point to the commit on GitHub.
>
> Most of the commits have the corresponding differential review link in
> the commit message itself so there should not be any loss of fidelity in
> the relevant information.
>
> Additionally, fix a typo in the xdpwall.c print ("LLMV" -> "LLVM") while
> in the area.
>
> Link: https://discourse.llvm.org/t/update-on-github-pull-requests/71540/172
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Ack with one nit below.

Acked-by: Yonghong Song <yonghong.song@linux.dev>

> ---
> Cc: ast@kernel.org
> Cc: daniel@iogearbox.net
> Cc: andrii@kernel.org
> Cc: mykolal@fb.com
> Cc: bpf@vger.kernel.org
> Cc: linux-kselftest@vger.kernel.org
> ---
>   tools/testing/selftests/bpf/README.rst             | 32 +++++++++++-----------
>   tools/testing/selftests/bpf/prog_tests/xdpwall.c   |  2 +-
>   .../selftests/bpf/progs/test_core_reloc_type_id.c  |  2 +-
>   3 files changed, 18 insertions(+), 18 deletions(-)
>
> diff --git a/tools/testing/selftests/bpf/README.rst b/tools/testing/selftests/bpf/README.rst
> index cb9b95702ac6..b9a493f66557 100644
> --- a/tools/testing/selftests/bpf/README.rst
> +++ b/tools/testing/selftests/bpf/README.rst
> @@ -115,7 +115,7 @@ the insn 20 undoes map_value addition. It is currently impossible for the
>   verifier to understand such speculative pointer arithmetic.
>   Hence `this patch`__ addresses it on the compiler side. It was committed on llvm 12.
>   
> -__ https://reviews.llvm.org/D85570
> +__ https://github.com/llvm/llvm-project/commit/ddf1864ace484035e3cde5e83b3a31ac81e059c6
>   
>   The corresponding C code
>   
> @@ -165,7 +165,7 @@ This is due to a llvm BPF backend bug. `The fix`__
>   has been pushed to llvm 10.x release branch and will be
>   available in 10.0.1. The patch is available in llvm 11.0.0 trunk.
>   
> -__  https://reviews.llvm.org/D78466
> +__  https://github.com/llvm/llvm-project/commit/3cb7e7bf959dcd3b8080986c62e10a75c7af43f0
>   
>   bpf_verif_scale/loop6.bpf.o test failure with Clang 12
>   ======================================================
> @@ -204,7 +204,7 @@ r5(w5) is eventually saved on stack at insn #24 for later use.
>   This cause later verifier failure. The bug has been `fixed`__ in
>   Clang 13.
>   
> -__  https://reviews.llvm.org/D97479
> +__  https://github.com/llvm/llvm-project/commit/1959ead525b8830cc8a345f45e1c3ef9902d3229
>   
>   BPF CO-RE-based tests and Clang version
>   =======================================
> @@ -221,11 +221,11 @@ failures:
>   - __builtin_btf_type_id() [0_, 1_, 2_];
>   - __builtin_preserve_type_info(), __builtin_preserve_enum_value() [3_, 4_].
>   
> -.. _0: https://reviews.llvm.org/D74572
> -.. _1: https://reviews.llvm.org/D74668
> -.. _2: https://reviews.llvm.org/D85174
> -.. _3: https://reviews.llvm.org/D83878
> -.. _4: https://reviews.llvm.org/D83242
> +.. _0: https://github.com/llvm/llvm-project/commit/6b01b465388b204d543da3cf49efd6080db094a9
> +.. _1: https://github.com/llvm/llvm-project/commit/072cde03aaa13a2c57acf62d79876bf79aa1919f
> +.. _2: https://github.com/llvm/llvm-project/commit/00602ee7ef0bf6c68d690a2bd729c12b95c95c99
> +.. _3: https://github.com/llvm/llvm-project/commit/6d218b4adb093ff2e9764febbbc89f429412006c
> +.. _4: https://github.com/llvm/llvm-project/commit/6d6750696400e7ce988d66a1a00e1d0cb32815f8
>   
>   Floating-point tests and Clang version
>   ======================================
> @@ -234,7 +234,7 @@ Certain selftests, e.g. core_reloc, require support for the floating-point
>   types, which was introduced in `Clang 13`__. The older Clang versions will
>   either crash when compiling these tests, or generate an incorrect BTF.
>   
> -__  https://reviews.llvm.org/D83289
> +__  https://github.com/llvm/llvm-project/commit/a7137b238a07d9399d3ae96c0b461571bd5aa8b2
>   
>   Kernel function call test and Clang version
>   ===========================================
> @@ -248,7 +248,7 @@ Without it, the error from compiling bpf selftests looks like:
>   
>     libbpf: failed to find BTF for extern 'tcp_slow_start' [25] section: -2
>   
> -__ https://reviews.llvm.org/D93563
> +__ https://github.com/llvm/llvm-project/commit/886f9ff53155075bd5f1e994f17b85d1e1b7470c
>   
>   btf_tag test and Clang version
>   ==============================
> @@ -264,8 +264,8 @@ Without them, the btf_tag selftest will be skipped and you will observe:
>   
>     #<test_num> btf_tag:SKIP
>   
> -.. _0: https://reviews.llvm.org/D111588
> -.. _1: https://reviews.llvm.org/D111199
> +.. _0: https://github.com/llvm/llvm-project/commit/a162b67c98066218d0d00aa13b99afb95d9bb5e6
> +.. _1: https://github.com/llvm/llvm-project/commit/3466e00716e12e32fdb100e3fcfca5c2b3e8d784
>   
>   Clang dependencies for static linking tests
>   ===========================================
> @@ -274,7 +274,7 @@ linked_vars, linked_maps, and linked_funcs tests depend on `Clang fix`__ to
>   generate valid BTF information for weak variables. Please make sure you use
>   Clang that contains the fix.
>   
> -__ https://reviews.llvm.org/D100362
> +__ https://github.com/llvm/llvm-project/commit/968292cb93198442138128d850fd54dc7edc0035
>   
>   Clang relocation changes
>   ========================
> @@ -292,7 +292,7 @@ Here, ``type 2`` refers to new relocation type ``R_BPF_64_ABS64``.
>   To fix this issue, user newer libbpf.
>   
>   .. Links
> -.. _clang reloc patch: https://reviews.llvm.org/D102712
> +.. _clang reloc patch: https://github.com/llvm/llvm-project/commit/6a2ea84600ba4bd3b2733bd8f08f5115eb32164b
>   .. _kernel llvm reloc: /Documentation/bpf/llvm_reloc.rst
>   
>   Clang dependencies for the u32 spill test (xdpwall)
> @@ -304,6 +304,6 @@ from running test_progs will look like:
>   
>   .. code-block:: console
>   
> -  test_xdpwall:FAIL:Does LLVM have https://reviews.llvm.org/D109073? unexpected error: -4007
> +  test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -4007
>   
> -__ https://reviews.llvm.org/D109073
> +__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d

To be consistent with other links, could you add the missing last alnum '5' to the above link?

> diff --git a/tools/testing/selftests/bpf/prog_tests/xdpwall.c b/tools/testing/selftests/bpf/prog_tests/xdpwall.c
> index f3927829a55a..4599154c8e9b 100644
> --- a/tools/testing/selftests/bpf/prog_tests/xdpwall.c
> +++ b/tools/testing/selftests/bpf/prog_tests/xdpwall.c
> @@ -9,7 +9,7 @@ void test_xdpwall(void)
>   	struct xdpwall *skel;
>   
>   	skel = xdpwall__open_and_load();
> -	ASSERT_OK_PTR(skel, "Does LLMV have https://reviews.llvm.org/D109073?");
> +	ASSERT_OK_PTR(skel, "Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5?");
>   
>   	xdpwall__destroy(skel);
>   }
> diff --git a/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c b/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
> index 22aba3f6e344..6fc8b9d66e34 100644
> --- a/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
> +++ b/tools/testing/selftests/bpf/progs/test_core_reloc_type_id.c
> @@ -80,7 +80,7 @@ int test_core_type_id(void *ctx)
>   	 * to detect whether this test has to be executed, however strange
>   	 * that might look like.
>   	 *
> -	 *   [0] https://reviews.llvm.org/D85174
> +	 *   [0] https://github.com/llvm/llvm-project/commit/00602ee7ef0bf6c68d690a2bd729c12b95c95c99
>   	 */
>   #if __has_builtin(__builtin_preserve_type_info)
>   	struct core_reloc_type_id_output *out = (void *)&data.out;
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a655e9f-9878-4292-9d16-f988c4bdfc73%40linux.dev.
