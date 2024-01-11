Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUHU7SWAMGQEVLG26JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B883582A54E
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 01:46:10 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6d9b8ff5643sf2769813b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 16:46:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704933969; cv=pass;
        d=google.com; s=arc-20160816;
        b=V+gk7IfdvnG7rvHCPNzpqYJViuEmnprVjag6J5Ns4+xIXwbKofi3xNmdbz3hv2O7lY
         vcnR1KN14958xIzVhRZceuQD9/WtoncrBizGx/z2B1xI8jOw16ZlAC7TLioKggRYD1Qn
         OBOn5fXSt3y2Ph53TRopHzUOuADuhxrVo21Jynik5acv3AUp62AN9tebl/oa5PTrhPj8
         PmnMCrDF4jP4z8RE1D1FyGxnmbu/aPGAukfiMbGnBvdT24J74A89Yce18Ab4cD0J+vUD
         OhX9ocuEei218W/ZPgMVXrXjKTwdRplZ2QannFoPBUAXImg8zIOBFzc/IuMwI/25fWvk
         NeMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SG2moKwOz26TTsXiB9hmaV34PaJ77cF0KCY42q+5C7M=;
        fh=TK0zhiT7VdPxEkTzRdfdYSBqaJW6TPp2BWXCAOxVxNk=;
        b=OMaSJzMQ8sN3EvFW1IgRRU0eyc603SaGi3sWTDZAP1bPW66HbBMFb15cl82bsIsTTz
         j6JWa8q73/Xs/4AbKVH4dEtGmqrMys//ip21iUhLnhP4GH64GOKFDCb6YXYN9ZekOxMQ
         g/T8NGkUvjpD0q2/jW/WBc1Mou2z0K06mLHSf9sWTMDpvD1J7DJOoDIzq/iITSz7olsc
         7/vpyIml+tDptgheMJxoQlJmvB1rhmBlWT+C9DHYXbK3jSXMHli41FLDpSGiLtQsZHqe
         TDWOjQR9Mr7J73IJ+fQAOhbRlDCd1iWX5KsQhpSfJCE+6W84YKdkW+8pT0mbWs1FwFOz
         d3tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Txa6wmhe;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704933969; x=1705538769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SG2moKwOz26TTsXiB9hmaV34PaJ77cF0KCY42q+5C7M=;
        b=kK+w8jPRKkbqiEsiZtfl163qbEctfDDwL78xH8isSG7jxXCJvHdYj1esmbWjNKVFU/
         Ff0tDFRoQlkd3BLgBjOAWXBqckKA+P79xNyxZBPwe1Km7BO3RLcDMEPZO6To0jBYYhHK
         +0rRv2UV1RMjwyFWHYYFdI0C9aTH4W9FzcPebzD2bBQRyadHf1nsYqT5yWNqNPMKaHui
         BCz8auiUvqHJuWybC0E+idWXhR1fqSbcXvv9/gpCeAcoXL298wcB9bn/WGB9hIAOjxAA
         HSL9aI3zKaursMbJvowvMnsXVYhbRU9JhDhWeGdGFw9mS1b1mzzni9VwEwP+zFnWBU0m
         8PqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704933969; x=1705538769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SG2moKwOz26TTsXiB9hmaV34PaJ77cF0KCY42q+5C7M=;
        b=hbauC6izqAlzBZguTQhyzOroiW23+4wu2hSiMoMcPZ6YvSIyTAvSIAILKzbaQVSka2
         3FxJybpve+YnUnU+naoLYQgKxWOlY04ER9UkKk7QAPXiPzhR58uOK4wLiUDMFqfmP6FH
         MfnQCOycB7+fI6AZOZqxpm9jfB57lPV7XpxUVulpuYDrTwT2sV+BURnJXHIRF0FQ6CxJ
         Wa6nyIzn44CifjCEDDbdyGa+/jzkLKJVeRglGjuccrwOyhOs0K8en24yWhH+Lnaw5ZHU
         qzlW42uBWxVD0YMUDsN+CmPU7a1DiHYxfm4OBZdQ08mPFRm1WPAsLg1tDYvREoDSd32Y
         eQbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzaFnw8KzxVb0bzU6kT7zYZMFhaN3qpumGPcaIlCM71OT/2sJfX
	a9UbedALFg+sXrgjun+0PZ0=
X-Google-Smtp-Source: AGHT+IHHMZ29AfoE0yabvMk2qnv07fXsREsS4cveXwVif5QsBKtkvOj2NREcj1S1XxdusNRe0PHzqw==
X-Received: by 2002:a05:6a00:1884:b0:6d9:9003:e2cd with SMTP id x4-20020a056a00188400b006d99003e2cdmr565888pfh.41.1704933969014;
        Wed, 10 Jan 2024 16:46:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8d0:b0:6da:83a2:1e56 with SMTP id
 s16-20020a056a0008d000b006da83a21e56ls1395783pfu.0.-pod-prod-09-us; Wed, 10
 Jan 2024 16:46:08 -0800 (PST)
X-Received: by 2002:a05:6a00:2e18:b0:6da:a31b:3f9c with SMTP id fc24-20020a056a002e1800b006daa31b3f9cmr692994pfb.53.1704933967896;
        Wed, 10 Jan 2024 16:46:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704933967; cv=none;
        d=google.com; s=arc-20160816;
        b=pvC/McZIHcmk0IBsHBnu/c8m8FZZ4oCQgXNaoiHLNk5W9SAaIPyj12FQkgjaX+kEhb
         qh9kklTmMIcy5aNMEI3y1llh9oK3xoE7yEO1yjoCfMSa4W4hsvFe8FhR5v+A+YsL9oOz
         tXDVy0q14iWfhg8JfqCrdcrHMMLmFwk2YB10kPBaniy+J8SLciCXaQhkc0JdtI0Ngseg
         9r7hT3bAMQLPNkuFxo++EdIYuhZu4Az78be+vezmzrj53DkefnGLeVovMqhP2/nfht0U
         UMtEjq7IUBSlGsDRzVw2r0d3P3Prud9V0Zi86buojznDGMFzFExMUY0Vma9OXqYuOJR9
         kmzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gueNhZrbsNiJzCN2gb4yLrjECQBWf6cwwXnoTcfXIT4=;
        fh=TK0zhiT7VdPxEkTzRdfdYSBqaJW6TPp2BWXCAOxVxNk=;
        b=0Lk0r6kQWA90m5FjW9PZKbaQma0RuQ81jNu+0F/OvqMceUUjbEMeG5b3rCm45FQdvQ
         mvnaPwCWtMI0o4mjwlJJg/pocpphECqe9rtddSnYxzpr7K2csaId6BGCzhfFtnyvYg3m
         mOZuJrbUJU3kdHsW1lh0hHcJhcyEpZgbzg5s0cKo9veVXqh9ZPAw164tW6riSRNhCQVs
         M5Xn5+5SG/eWzF/mRl+GaVeIIZPj8QfY9vwVQxas03JI56mT/FVM87zI6dxG1BfztMkZ
         865/LkUkS8iQm9Wo3Hu1xwIUMzdMvHFVg5WHqbKCIrXVpnTNJ4kYzhSP6HbLneOZ7sAX
         kPSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Txa6wmhe;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id gc3-20020a056a0062c300b006d9bbac9a93si355167pfb.6.2024.01.10.16.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jan 2024 16:46:07 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6d9cb95ddd1so2179116b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 16:46:07 -0800 (PST)
X-Received: by 2002:aa7:90d3:0:b0:6d9:a64c:c5d1 with SMTP id k19-20020aa790d3000000b006d9a64cc5d1mr504196pfk.26.1704933967538;
        Wed, 10 Jan 2024 16:46:07 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id y2-20020a62b502000000b006dac91d6da5sm4071344pfe.68.2024.01.10.16.46.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jan 2024 16:46:06 -0800 (PST)
Date: Wed, 10 Jan 2024 16:46:06 -0800
From: Kees Cook <keescook@chromium.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: akpm@linux-foundation.org, llvm@lists.linux.dev,
	patches@lists.linux.dev, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	kvm@vger.kernel.org, linux-riscv@lists.infradead.org,
	linux-trace-kernel@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-crypto@vger.kernel.org,
	linux-efi@vger.kernel.org, amd-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, linux-media@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, bridge@lists.linux.dev, netdev@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, ast@kernel.org,
	daniel@iogearbox.net, andrii@kernel.org, mykolal@fb.com,
	bpf@vger.kernel.org
Subject: Re: [PATCH 0/3] Update LLVM Phabricator and Bugzilla links
Message-ID: <202401101645.ED161519BA@keescook>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Txa6wmhe;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Jan 09, 2024 at 03:16:28PM -0700, Nathan Chancellor wrote:
> This series updates all instances of LLVM Phabricator and Bugzilla links
> to point to GitHub commits directly and LLVM's Bugzilla to GitHub issue
> shortlinks respectively.
> 
> I split up the Phabricator patch into BPF selftests and the rest of the
> kernel in case the BPF folks want to take it separately from the rest of
> the series, there are obviously no dependency issues in that case. The
> Bugzilla change was mechanical enough and should have no conflicts.
> 
> I am aiming this at Andrew and CC'ing other lists, in case maintainers
> want to chime in, but I think this is pretty uncontroversial (famous
> last words...).
> 
> ---
> Nathan Chancellor (3):
>       selftests/bpf: Update LLVM Phabricator links
>       arch and include: Update LLVM Phabricator links
>       treewide: Update LLVM Bugzilla links
> 
>  arch/arm64/Kconfig                                 |  4 +--
>  arch/powerpc/Makefile                              |  4 +--
>  arch/powerpc/kvm/book3s_hv_nested.c                |  2 +-
>  arch/riscv/Kconfig                                 |  2 +-
>  arch/riscv/include/asm/ftrace.h                    |  2 +-
>  arch/s390/include/asm/ftrace.h                     |  2 +-
>  arch/x86/power/Makefile                            |  2 +-
>  crypto/blake2b_generic.c                           |  2 +-
>  drivers/firmware/efi/libstub/Makefile              |  2 +-
>  drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c           |  2 +-
>  drivers/media/test-drivers/vicodec/codec-fwht.c    |  2 +-
>  drivers/regulator/Kconfig                          |  2 +-
>  include/asm-generic/vmlinux.lds.h                  |  2 +-
>  include/linux/compiler-clang.h                     |  2 +-
>  lib/Kconfig.kasan                                  |  2 +-
>  lib/raid6/Makefile                                 |  2 +-
>  lib/stackinit_kunit.c                              |  2 +-
>  mm/slab_common.c                                   |  2 +-
>  net/bridge/br_multicast.c                          |  2 +-
>  security/Kconfig                                   |  2 +-
>  tools/testing/selftests/bpf/README.rst             | 32 +++++++++++-----------
>  tools/testing/selftests/bpf/prog_tests/xdpwall.c   |  2 +-
>  .../selftests/bpf/progs/test_core_reloc_type_id.c  |  2 +-
>  23 files changed, 40 insertions(+), 40 deletions(-)
> ---
> base-commit: 0dd3ee31125508cd67f7e7172247f05b7fd1753a
> change-id: 20240109-update-llvm-links-d03f9d649e1e
> 
> Best regards,
> -- 
> Nathan Chancellor <nathan@kernel.org>
> 

Excellent! Thanks for doing this. I spot checked a handful I was
familiar with and everything looks good to me.

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202401101645.ED161519BA%40keescook.
