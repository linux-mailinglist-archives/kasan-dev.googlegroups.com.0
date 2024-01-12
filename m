Return-Path: <kasan-dev+bncBDPZFQ463EFRBMNEQWWQMGQEWOKLBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id BA61782C228
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jan 2024 15:52:34 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3bd4ba35a60sf4478162b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jan 2024 06:52:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705071153; cv=pass;
        d=google.com; s=arc-20160816;
        b=fnlGz7Pt9uIMgPADYuHpc3+V2fo0uelSqRY1j3fvBurxOhD8/luQisv0mrvptlEiab
         +7hl7l9gAkmi0PL08iKXueKboAiW0SmNSJdcsvjnZYGoK0qKLIrgQzw1KOfEukh7Fwe6
         aNZT1qzxDnhm9xFOEhIoBHQTO8lg4BEXsHd7Tyd4TPUiEAh2uNkT8ytsp5/3posKaNbz
         i4NaSaYY7JraA7dit4qYWcVODcr/yl0ytBz1hIVxDkx6PFtjrYXZSwHqP+2utX5L5mTt
         saaH5PxjY6VWEhPDDS0YE9aZDOiJNgzunKXeMt5Rfp4KhmRbAFJckDeRQ/kqWUnQHKKo
         WCWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Xvn3HbYEs5o9ceVQPr7Yx4+az9J7ZqfHhKYvHO3je+o=;
        fh=rLavxYPgCGm9kRPwRtonSpcipfezctx1aIgcmBosUuk=;
        b=MxaLSPraWqLnjoIFqwXEbuoG1vTBPZBmCAr9rxq8Qrv48xGWL++UXTpz3v6icnm1aO
         iuVp/jLlYUxVCrB0VyecsXe4g3+ZPb5MNei13S6Y5e+NZ+cY3nc61HTVt8tdpxVf33kA
         H4TcwOVyu4wB+9WeH5VEt9jj+/GxP4aglphXqKOgGD+3CTBqPKYzCcF+DqYHypoT99ww
         JVM0wTo8mdCAAvBJ89FSKJSYE8ltLXjslHWsURcYSBlPxITqL940k8V4hWoHVjkUuEeM
         Ym4ueOEtWKBcsJuHK0d1kVku1B5c94OAPBwCvw17EG5UyLCcYWGc8omNS5IEqS9rOFVK
         z9UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EHkE2HqN;
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705071153; x=1705675953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Xvn3HbYEs5o9ceVQPr7Yx4+az9J7ZqfHhKYvHO3je+o=;
        b=VaOiqOVJQU0LxjkI/X94ZLTrl1xyZ9bFJUKLuuzJLYYK7SKXs1z24WKSS9yZc9DhBY
         TNwDsKBMTVoq6AogeHJar0vzNsQXhWGteGT9nVZZRo3qwCJwnhNRWQCE7/L4Ozg9ofke
         PLS07XFiimgu2sIb/HHGWrEn+vo/1A9nEP1N2WoNP1mrgHk199piHv0zyUYh7qSCNl64
         Zk8odNHAa3duQA4judEZ7xG16IdKX+CJwIJezJ55I3nzxNmVCtkXAHkQKRXtOlycrusk
         v6sCgighJbw7R5MHkhJwqPEbhR1S+MJq4C23lZxZNg0K6LM1vAMuNoLAW48282is5dfn
         UN6g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1705071153; x=1705675953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Xvn3HbYEs5o9ceVQPr7Yx4+az9J7ZqfHhKYvHO3je+o=;
        b=aXvTIPWZCAq8VhSFlyMif1lOoD6t4PfPjmy/7HyR4cBV0sgmsMAEmYaO/8WWg/xvd6
         N1dkSOPNtXadFgmvzV5MZw2+gTmPna/dbWQJ7zgQxonSg9+Vphcw3my0OiD1+oZ1zui4
         KMWULdVWs5qBVHmc8O3aL3QmO+pm0RNt5tiRwEq5WEimU1/Dt7pngViUwiXRfldDKciP
         4BFle6a1K/4CEuOtHMmQEBrsAGVyJCZmSKbQ/v+kVaOHqjtXZvInAUu7S2a6N+jzG8oR
         4O5yXJPr96MbxpCchZaYXwTJ0Mf+6FIoNSlXvulfhET9iPSnL6ZC7IzpKWTUR9kffoW0
         Rqfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705071153; x=1705675953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Xvn3HbYEs5o9ceVQPr7Yx4+az9J7ZqfHhKYvHO3je+o=;
        b=KWaMJ+RGu6TeAPQWA4l+zoZwcpPEINi4v7wWDLt3TXFWyNAPxK5rkPSCEs6w7aXvvT
         /I/5lpbOv3HmVmC7QuiQtDwf1tTw3qYXciRa1rvYOYtKpN3+A9ifd4UhUkp7spb4TDpT
         Hr82ylwU324dQKN2Gs8QJWnugbV67K3WuIYqfAomHaN8nxhf9NfgBEiEqWzZMYukU5aF
         x4etOt5SNzRL1ge8iEfj9uy1PU8dyAXzai3/+XV/5gvOejHz8+yfdtkmeW/3PxH0pOmK
         8Z9Yi5iugOVX9FB8EPJNINn2RZsD1H/KZ97AG2nYhmVXvceZDxmnfBkBhFQsyFTI2dhV
         ZmEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx6C6H3dxuRYcSmm3yQ0cqH33x0gjrph0xTV8nNfoc9u6Kr3wII
	ccA9pM4wLS8bJbwv8joLufA=
X-Google-Smtp-Source: AGHT+IG5txmNqY0tjmMadn/7tAOctYvs+uAXjRemb0HDleLRdul/uCCq+bNv/He/yman4P3Uhzps1w==
X-Received: by 2002:a05:6808:1826:b0:3bd:4640:37aa with SMTP id bh38-20020a056808182600b003bd464037aamr1394776oib.91.1705071153246;
        Fri, 12 Jan 2024 06:52:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2423:b0:67a:1a58:78fc with SMTP id
 gy3-20020a056214242300b0067a1a5878fcls3720564qvb.1.-pod-prod-07-us; Fri, 12
 Jan 2024 06:52:30 -0800 (PST)
X-Received: by 2002:a05:6122:2805:b0:4b6:ba78:7029 with SMTP id en5-20020a056122280500b004b6ba787029mr1045419vkb.32.1705071150473;
        Fri, 12 Jan 2024 06:52:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705071150; cv=none;
        d=google.com; s=arc-20160816;
        b=zGE+tNPKunu/FqdVqJRcgyTqDFsEDISaDDI7iIp/6SjmC+RyOpa/O6b56hFILEGP+v
         LWqDgDxKxh3hjoOzIl6V5VLlrTXGyO+oRDGGiG8F3fHsEnBsoxZf6zInf9n16uVKjuiF
         coiY7hbqmYJlIPWKm2OAOfhL2IMh1lKHrSJ6FruzoDWne1QAM/BjiffQt09N6JScw/RO
         evu4cCgdsjckKnni4vH/gNDWLQOmERDRLJs8xaF9a/4lExPsoGrW1gm0mrXHck38onXg
         IXE818ix3aRzGiX6lkO5PKrA/sMp2+9X9L74A/TgyhQgPTBpVh1GG+p/oXTv2tvIMrtS
         eCsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZO45YkzCWML/dfVASjM1WgREcSCHVv4YlKgRi2In5SM=;
        fh=rLavxYPgCGm9kRPwRtonSpcipfezctx1aIgcmBosUuk=;
        b=KKB6nLeQvfxxNqin4XyA+3Zk0tvCgCbXDCmXNhbuOiF4kp8Nng5YTBpvh+HqX2EsGT
         LTZLtacYLyN8un0TLNVVBFFT+BLYd9WhJleH+r6ysTi1SZ/QYJIfLkhdRxOG5oMx5Cg2
         SeSciHmuTpZXc5PJbNrbS6x2/dlr+Xjyqrl8bAsId01rEX75EUo4DpTVseOrcJbtAJxI
         jNyiBlGez2zvDWbO+id1sdFixObV9ptYub6J8WQ1SQP0H/aci2wW9s+mzxlX5rypP24m
         ACOCrooD3+gVSlnUGIDYgfvjhdWBa0pHNjSSrEawlPkNa5hLvDyoMWTxMuHd0Vk58SYc
         +rFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EHkE2HqN;
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::32 as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x32.google.com (mail-oa1-x32.google.com. [2001:4860:4864:20::32])
        by gmr-mx.google.com with ESMTPS id n64-20020a1fd643000000b004b2e6e4330asi374670vkg.1.2024.01.12.06.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jan 2024 06:52:30 -0800 (PST)
Received-SPF: pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::32 as permitted sender) client-ip=2001:4860:4864:20::32;
Received: by mail-oa1-x32.google.com with SMTP id 586e51a60fabf-20503dc09adso4051259fac.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Jan 2024 06:52:30 -0800 (PST)
X-Received: by 2002:a05:6871:452:b0:206:8691:cc78 with SMTP id
 e18-20020a056871045200b002068691cc78mr1680164oag.34.1705071149757; Fri, 12
 Jan 2024 06:52:29 -0800 (PST)
MIME-Version: 1.0
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
In-Reply-To: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
From: Alex Deucher <alexdeucher@gmail.com>
Date: Fri, 12 Jan 2024 09:52:17 -0500
Message-ID: <CADnq5_MVDDR-EvgSEhiw_qPkUDPnV25tjUN0SNYq45Q29BN4EQ@mail.gmail.com>
Subject: Re: [PATCH 0/3] Update LLVM Phabricator and Bugzilla links
To: Nathan Chancellor <nathan@kernel.org>
Cc: akpm@linux-foundation.org, linux-efi@vger.kernel.org, kvm@vger.kernel.org, 
	llvm@lists.linux.dev, ast@kernel.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-riscv@lists.infradead.org, 
	linux-arch@vger.kernel.org, linux-s390@vger.kernel.org, mykolal@fb.com, 
	daniel@iogearbox.net, andrii@kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-media@vger.kernel.org, linux-pm@vger.kernel.org, bridge@lists.linux.dev, 
	linux-arm-kernel@lists.infradead.org, netdev@vger.kernel.org, 
	patches@lists.linux.dev, linux-security-module@vger.kernel.org, 
	linux-crypto@vger.kernel.org, bpf@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexdeucher@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EHkE2HqN;       spf=pass
 (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::32
 as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 9, 2024 at 5:26=E2=80=AFPM Nathan Chancellor <nathan@kernel.org=
> wrote:
>
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

Acked-by: Alex Deucher <alexander.deucher@amd.com>

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
>  tools/testing/selftests/bpf/README.rst             | 32 +++++++++++-----=
------
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADnq5_MVDDR-EvgSEhiw_qPkUDPnV25tjUN0SNYq45Q29BN4EQ%40mail.gmail.=
com.
