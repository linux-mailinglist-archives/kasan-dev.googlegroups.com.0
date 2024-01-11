Return-Path: <kasan-dev+bncBCS7XUWOUULBBV5BQGWQMGQEM2P6FCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C18482B5FC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 21:34:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50e4aa3f7eesf3697723e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 12:34:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705005272; cv=pass;
        d=google.com; s=arc-20160816;
        b=DzGXpNLTtgCFpHzou8p+bOm2dGvNnssOOWO/kbJ/PZhYAFzltA96Lzqn9DyU1YL+F7
         SvkK5ep7GmB3XghVNFxacc+o5wAna1gHHntjBNOsd+hgD+2+PHI8/6yb9cojq0E+tmOm
         BrDNJCT53WqGXizeL6wAk4ci1zEBGkWHfqDbryj/BvBlcHhhxGxsIBCmO0Z8g+wCFSeB
         QYv9OhUOosyygv8VClWKkA13EESonpynNpidNU5JVDmZXbLbpIu8toSZ6vB4652tWIpu
         1HOxg2wkW2J3g6/jqo9XrgAWfWZGKmrsDAwoQNdaNR9lvv2ua6Kx8Zi05p8TH+g9R+TE
         EB8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5KvRmhl298gKSlhrnl+ZwYXghMk2h4J4TL3w5xyMwzY=;
        fh=nvNHyY7qFsg89wC5tsDZx3vFnPNJvMWaCjfJUNu8ivY=;
        b=eN05UzxpxvHdBhM465F9qnCMgCvrfjshUVNtxkIuZvLxtDnh3rN0U3nNpZ1sjULHYG
         0h9llP4rzTHhPbg6HAimjz2x6Lk8+OuJpGkSJP3S+TUkryA4J+y0cMLRGh9a/H+i5l87
         akyw7M1x0ITz88v6LOkz846n3f73CVcdM6tRs7k5WFi5snDWZfE/nq2eGnvCKzY/KZ9p
         NwZ6FunbN3ZVKGKbslb/Qw+GqQ5HVIJHD1tLrlvo0Hu7bpzoiD9m/cZKB+21MS6/t/Hp
         gEtYBjYTStrwqXdXIuiu/28MtG8Q0kiPrmWjOsPlg3VNVZMSFb3ofHTnrRJQ+f/j1xvM
         I4qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z2jkN2WT;
       spf=pass (google.com: domain of maskray@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705005272; x=1705610072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5KvRmhl298gKSlhrnl+ZwYXghMk2h4J4TL3w5xyMwzY=;
        b=NFv45MLUcYv2xtJdqwAfci/M8FOR1UsXLSMItvbLkkpbVbzP4P6IBzkOd1EgtVAGii
         UNyfvLD4PnjQaGl1HWCBkdD/67uvvy22yXFSThuFAM/rapOWOql82hY5KEbodcbTobpp
         r9NU9AAdTkyyjMZ7AFFLtS8e1DzDX+Tfmqg20ZIuxL/xZvq2y8BWmwDHPO9Dec/0QmNI
         kcXDf2Nhehd9NqfQQDBP9LiK8jL4hjOfevuuYzdKEIakJSclLMBFOsADvz8H0w0h6J4c
         CgC60FpiuTPe3nDUzNB4+AIA6eHt58+0FW1wi7cLVy0ch/c0ERRH05YZL9idw/5Cz/0/
         5Kww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705005272; x=1705610072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5KvRmhl298gKSlhrnl+ZwYXghMk2h4J4TL3w5xyMwzY=;
        b=w6qeMdPmfmje5Qz8PWkEljavOmBSTPAeJ+muaUuurI/t8EW3LpxBUl6NSxFBY/7CHU
         /TNS3mWgNBQm4ZA/T3/ma/5chYYMTLrVTphLaQr0XaW855xZXQWam/R9t0t5ZJNAR+x1
         45G133KcljhwI7x5IoA1aQy6mux268c3LmkwD+8/56pm8IUPW5QRbLWIHPoEpNmpANVT
         yc3TDfzwEM0ljtoZxhFbvWfGs7K6gD1nHWZfHDp2Qtg4Ntfq5SjpkMor2nEjMQhJDH4u
         P2yP0V9myqkSoc4+QkDQQ5+iW+UFoh+iMsV6dc/HANoOr7jH94TzPheIdz1vc4+mK5BE
         /f0w==
X-Gm-Message-State: AOJu0YyvdVK1k5YBYrI6rOdFhyZY7g/+4e0nSPR4SmxDJ3MBDc2xFlNs
	2+sFhilaGZwBO8BLkD1XZPw=
X-Google-Smtp-Source: AGHT+IGTgJD3za4AIqG/wUMotzIrH/am3VnFlwdi9m/QqTdFlvwJBx3Ar3+Npxsm1oaN/kHwbk5Nvw==
X-Received: by 2002:a05:6512:2252:b0:50e:a15c:6b58 with SMTP id i18-20020a056512225200b0050ea15c6b58mr292592lfu.4.1705005271408;
        Thu, 11 Jan 2024 12:34:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2803:b0:50e:7281:9f03 with SMTP id
 cf3-20020a056512280300b0050e72819f03ls1162082lfb.1.-pod-prod-00-eu; Thu, 11
 Jan 2024 12:34:30 -0800 (PST)
X-Received: by 2002:a19:4f17:0:b0:50e:caa9:f801 with SMTP id d23-20020a194f17000000b0050ecaa9f801mr858611lfb.29.1705005269627;
        Thu, 11 Jan 2024 12:34:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705005269; cv=none;
        d=google.com; s=arc-20160816;
        b=MBFw4F+velNfcn0eJhNGVNHWV+X3JbgrGmF0lLWwfXNIp7Md0cjXLgqmmjtdf7tFhy
         M3eFkGh3oAHtgigiLP6poQn18yxXUCfOrcVr03jyt9lqxawxe5GyyQyJUl+zSU8wY/R/
         FSzI20bqfFy13CVFwCfX54zgP/JthSkm18Y7qQUr8ifHHykKZE6DbB5ttc9EO9KNGAgC
         WxUXiBKxIU4pwZ5RMsFLa1YFJyfsYIuuvXgvQPgteNaCC+3NLBzPnLK4wPttOMzGw9lY
         KwC5ggRC5vpRj/ecToSDKbyKu/ZlRoh2mV3/m7BhIH8SVhkQD8mzSlsUTmeeFtTWEk4M
         wTog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZhucuI11iLm9jZSo5DyrLuQREbxS6U88O/YNonTCxz8=;
        fh=nvNHyY7qFsg89wC5tsDZx3vFnPNJvMWaCjfJUNu8ivY=;
        b=zY7GlAQTM7Dg5IV37rJEdSZbn0bc+BhohlUlnAnmlkDLd/HoneaQmAcETaeHzQ3Z2e
         Qvy2BTMaXaCYTms67qNbFsJQQJLUtRBe7s6VQnGkqWZsCPSLYenbHOdmphPYnkUE2YYH
         9AWQ/1U0s96SURT5qYcW9+vfTuPsq0wSUh6CzCHgy9TwpHNnVCI4e+zwdCXcSVEfZoOQ
         2tcAx75t8e9zxbeifN0BlI7ZE4x/WTtQvtCTF4aNIcl2B/WfBQLOL0NvKWLzssdbdbx8
         xlQhtJy8sd32lqat819xPLFbKD6e7XOhaMCWv1Ta8guonOR0VrssmeYU44JfJkTkG3jp
         FCJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z2jkN2WT;
       spf=pass (google.com: domain of maskray@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id p6-20020a056512234600b0050e6b19b855si65707lfu.11.2024.01.11.12.34.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 12:34:29 -0800 (PST)
Received-SPF: pass (google.com: domain of maskray@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-40e62043a5cso675e9.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 12:34:29 -0800 (PST)
X-Received: by 2002:a05:600c:1d1f:b0:40e:61cf:af91 with SMTP id
 l31-20020a05600c1d1f00b0040e61cfaf91mr127026wms.7.1705005268801; Thu, 11 Jan
 2024 12:34:28 -0800 (PST)
MIME-Version: 1.0
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org> <202401101645.ED161519BA@keescook>
In-Reply-To: <202401101645.ED161519BA@keescook>
From: "'Fangrui Song' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Jan 2024 12:34:17 -0800
Message-ID: <CAFP8O3+947djoRjnVPuPhHUHbHv_9CugufuXQ+c=N03yLsaEcA@mail.gmail.com>
Subject: Re: [PATCH 0/3] Update LLVM Phabricator and Bugzilla links
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, akpm@linux-foundation.org, llvm@lists.linux.dev, 
	patches@lists.linux.dev, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	kvm@vger.kernel.org, linux-riscv@lists.infradead.org, 
	linux-trace-kernel@vger.kernel.org, linux-s390@vger.kernel.org, 
	linux-pm@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-efi@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-media@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	bridge@lists.linux.dev, netdev@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	ast@kernel.org, daniel@iogearbox.net, andrii@kernel.org, mykolal@fb.com, 
	bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maskray@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Z2jkN2WT;       spf=pass
 (google.com: domain of maskray@google.com designates 2a00:1450:4864:20::32f
 as permitted sender) smtp.mailfrom=maskray@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Fangrui Song <maskray@google.com>
Reply-To: Fangrui Song <maskray@google.com>
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

On Wed, Jan 10, 2024 at 4:46=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Tue, Jan 09, 2024 at 03:16:28PM -0700, Nathan Chancellor wrote:
> > This series updates all instances of LLVM Phabricator and Bugzilla link=
s
> > to point to GitHub commits directly and LLVM's Bugzilla to GitHub issue
> > shortlinks respectively.
> >
> > I split up the Phabricator patch into BPF selftests and the rest of the
> > kernel in case the BPF folks want to take it separately from the rest o=
f
> > the series, there are obviously no dependency issues in that case. The
> > Bugzilla change was mechanical enough and should have no conflicts.
> >
> > I am aiming this at Andrew and CC'ing other lists, in case maintainers
> > want to chime in, but I think this is pretty uncontroversial (famous
> > last words...).
> >
> > ---
> > Nathan Chancellor (3):
> >       selftests/bpf: Update LLVM Phabricator links
> >       arch and include: Update LLVM Phabricator links
> >       treewide: Update LLVM Bugzilla links
> >
> >  arch/arm64/Kconfig                                 |  4 +--
> >  arch/powerpc/Makefile                              |  4 +--
> >  arch/powerpc/kvm/book3s_hv_nested.c                |  2 +-
> >  arch/riscv/Kconfig                                 |  2 +-
> >  arch/riscv/include/asm/ftrace.h                    |  2 +-
> >  arch/s390/include/asm/ftrace.h                     |  2 +-
> >  arch/x86/power/Makefile                            |  2 +-
> >  crypto/blake2b_generic.c                           |  2 +-
> >  drivers/firmware/efi/libstub/Makefile              |  2 +-
> >  drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c           |  2 +-
> >  drivers/media/test-drivers/vicodec/codec-fwht.c    |  2 +-
> >  drivers/regulator/Kconfig                          |  2 +-
> >  include/asm-generic/vmlinux.lds.h                  |  2 +-
> >  include/linux/compiler-clang.h                     |  2 +-
> >  lib/Kconfig.kasan                                  |  2 +-
> >  lib/raid6/Makefile                                 |  2 +-
> >  lib/stackinit_kunit.c                              |  2 +-
> >  mm/slab_common.c                                   |  2 +-
> >  net/bridge/br_multicast.c                          |  2 +-
> >  security/Kconfig                                   |  2 +-
> >  tools/testing/selftests/bpf/README.rst             | 32 +++++++++++---=
--------
> >  tools/testing/selftests/bpf/prog_tests/xdpwall.c   |  2 +-
> >  .../selftests/bpf/progs/test_core_reloc_type_id.c  |  2 +-
> >  23 files changed, 40 insertions(+), 40 deletions(-)
> > ---
> > base-commit: 0dd3ee31125508cd67f7e7172247f05b7fd1753a
> > change-id: 20240109-update-llvm-links-d03f9d649e1e
> >
> > Best regards,
> > --
> > Nathan Chancellor <nathan@kernel.org>
> >
>
> Excellent! Thanks for doing this. I spot checked a handful I was
> familiar with and everything looks good to me.
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
>
> --
> Kees Cook
>

These reviews.llvm.org links would definitely be kept like
https://lists.llvm.org/pipermail/llvm-dev/ or cfe-dev links
(discussions have been migrated to Discourse).
However, I agree that the github repo link looks more official. I have
clicked a few links and they look good.

Since I maintain reviews.llvm.org and created the static archive [1],

Acked-by: Fangrui Song <maskray@google.com>

[1]: https://discourse.llvm.org/t/llvm-phabricator-turndown/76137

--=20
=E5=AE=8B=E6=96=B9=E7=9D=BF

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFP8O3%2B947djoRjnVPuPhHUHbHv_9CugufuXQ%2Bc%3DN03yLsaEcA%40mail.=
gmail.com.
