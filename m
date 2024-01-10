Return-Path: <kasan-dev+bncBDCLJAGETYJBBL6A7KWAMGQE54CPN7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2000A829BA5
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 14:48:33 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2cd5686ec93sf29639411fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 05:48:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704894512; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNpJVfW8sqFJcWdTHAoC1PfQwlu9duQ6ojsBrrJJD/EFdEkRzexcfyMebUGxjm9165
         7DAFsf75DhCwgvT/5UejUGXbc27iKiAzezf83GOSaI6pzm80BL2gfGOhH5cGZTNJjBbc
         8Yxo3LVHXE4vZggNBuoBZ6Ouug0PhjkgaH2IZaiBB9zuORS0XSmzumzHQ+9mUnIkLcZq
         FCCXwtb3jBneIzX654o+F6EVnjW2/ZsQ8xs31Xer3i4rBi2O6X3DEMfHdvht6DCpFEGn
         WWzfSRxOk1iB0fx5NooCPVJ5xlibJrF08sfrWihn10yO3/n4vP1tRkNEHBgwRJQl7eOs
         ntRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Gber3JGPov3A2/3JBWiatDKdb6znLoyhsMcSHzMRKnQ=;
        fh=vDAGxAs+f3E2hgP5g3RHsSD+2g8NWKNyjWL+ui601Mk=;
        b=TD1VgedmqwUvcWWO6lVJAHGSrANs8WqV7ieTVJlr3A0Yyz+MaAfGcWWn+pKcoQ1bcn
         r192JqfGGbJ0gilQaC47UcAL+FZEn1Qe2lC0HAsNbaPfoMeDbTKm9+nsXs0pd0Bi2o3e
         Ha3+8Sh+HzrEOe6TlBUNALrb2+srAsw8MzpMPtwlXnGqb1EjKLS0ptsd3Rz1OuEVvpux
         tZh4sLyZB2pptUHgkh1ocaLbwIXq4Ma4sQs+qjgSoO8bl2FN2CmVexlRCJ6aN8P7wjh2
         8bMHP64yaseomMk1VtkoT/dDdXdC/L3YJ9rwLomZ66qsGxD9UNVGJY5IHic6sNT557Ms
         +6tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1jPPPfb;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704894512; x=1705499312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gber3JGPov3A2/3JBWiatDKdb6znLoyhsMcSHzMRKnQ=;
        b=no1cmHNbdrx6ASjQKiU2xW5Isj/aths0QkaWTS8bLkPcmlLNO+EOqDyXwf7yNb5Ai0
         RP8pvpHnOMMy2TWjfUvo7Qsoxn2E8FNjcOtKrgKiVJlVQ8ykBbiRT6KbgEjW/NiWxZxp
         LUgLUSSE7MAjPq/fSiHsCadjqmnd2Z8amJhPDGrzSEj/iUPlU/TiO6a4Rh4baZ/KIrHg
         kJLeZDeliXHY4+vFl6PtCdhWC/O8WRSy3F1qxQfd38oGgg7744732UDpnCxSYWYYpuJm
         uoX1/rTf+Ke6VQVp1Yisfi6LJ6FlS8CqgmgARhkUzWDGOfFr63LQMAzph3gDi57z0SeA
         DBtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704894512; x=1705499312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gber3JGPov3A2/3JBWiatDKdb6znLoyhsMcSHzMRKnQ=;
        b=UTNdJ/pSJnvHEhxvbvLQoowMLy9uEdijNVbcmxuUgDkE3J/qF/Ea26p0nCJxriA1Rf
         454OA5eTCkeq4xR0ZEfvO1KsQ9bbXJf4jYfheHsTcthBYDoDLrMesYANxvSuutHGOvGI
         94Schbxl+f9U5AAKh9KoL3947l8BdHfP3xKMxg26p9pGJ/1ujvxzArvbIHXnZ0y5850Q
         ATy+2T7IYu1Zu+SunMdZBLX7nvOtad0oLemFJkpsu4HfsAse10+YZg4pIL4jGJrb8np/
         88LjiZVw9Y8xcyhToqQspahfetPdPJIhVFnaG4d4G3RmEgfvCZ37aPEzv72gyzQEuBeW
         3nbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxVsvE3/3n9kN2SDnHXrHUOqve3Pn5J4t+3pvOYinvgH/nDDYt5
	cUyzBR+8WcBfoPbCHBaC35I=
X-Google-Smtp-Source: AGHT+IGt+Hj9cKWsMjB6iFoq8/3YJ5Yf3g0yKbHeX1lAJmy0BwTO7MRra6CUkxxJ6uN/QaBa9qIXaA==
X-Received: by 2002:a05:651c:10cc:b0:2cc:cbbd:c63d with SMTP id l12-20020a05651c10cc00b002cccbbdc63dmr678238ljn.0.1704894511247;
        Wed, 10 Jan 2024 05:48:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc22:0:b0:2cd:d0c:af0e with SMTP id b34-20020a2ebc22000000b002cd0d0caf0els153731ljf.2.-pod-prod-09-eu;
 Wed, 10 Jan 2024 05:48:29 -0800 (PST)
X-Received: by 2002:a2e:80c1:0:b0:2cc:8dda:c96d with SMTP id r1-20020a2e80c1000000b002cc8ddac96dmr599191ljg.28.1704894508821;
        Wed, 10 Jan 2024 05:48:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704894508; cv=none;
        d=google.com; s=arc-20160816;
        b=eyC2DfqhlvkxPh/qozgnYDryoskBExvAJfppBd1PgYz3g0X4uzovLYrZRkrDrbWmWB
         Se6x+LiTOP2AqXzcq1VOu91jL7l1bQk+qCV921E1XMGOIKqVqw2H83PLCSVFx9BPDncq
         iloEQBrBs0u7Xy1N38Ajeoee72AUmNUSYQwRfX97NVmvaD4o9EAQa0Ol8cnrXc6tmapg
         dC4aY+YMW8J5sopajaRWD4l7WBjVdEKWWH+/gR1/DuahaLdxm+W9qFZDUWhw69V62RWt
         24xt52ZEYS1Pnrq1DoZ9Z1dlXjph2Jx8Nu/7+8Ye+08KqRqrMEERTRp8xvYKPLxiunBk
         SyXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z1KQESlU7A8PxqGeTfhu/hJ0I/Wt3cQhfAbhcPoveeg=;
        fh=vDAGxAs+f3E2hgP5g3RHsSD+2g8NWKNyjWL+ui601Mk=;
        b=OIjb51dwwxH6+Cctia8epgPPA/8Ub04GfqKTc13cZrlJXIKQCvwy2/x11f++l1wyJK
         NkC71jtKnLJ2zi1jPWNlNNh4WEp3/kQ4ks3BruSuGIx2IzurtxUwlXyuz1dfgbXL2zWL
         AYKjl0U8hFOy+WewxVhk3VtRpJ3ghPtuv6/R70YSekDweAkIqgjDaSZBIe8WtED0omv/
         oDKkjICP0PPcTamGhuWca8OJmjcAlLrUXIpqQM2DkFE6sPFo81LwfVhn+GgcIfyiVzXr
         OY49nIAjy4go9jB9+M7g1LX+z5icUr8yJCpSHEJtXDYii5E+eWxRV4iDKzxZYt3oCB98
         xuPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1jPPPfb;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id o16-20020a2e9450000000b002ccfe00c6e8si135956ljh.3.2024.01.10.05.48.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jan 2024 05:48:28 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 2A253B81D6A;
	Wed, 10 Jan 2024 13:48:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 14496C433C7;
	Wed, 10 Jan 2024 13:48:22 +0000 (UTC)
Date: Wed, 10 Jan 2024 13:48:20 +0000
From: Conor Dooley <conor@kernel.org>
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
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH 2/3] arch and include: Update LLVM Phabricator links
Message-ID: <20240110-apostle-trident-533d4c2c9c97@spud>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
 <20240109-update-llvm-links-v1-2-eb09b59db071@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="p6SYI+U6gP5vpK1M"
Content-Disposition: inline
In-Reply-To: <20240109-update-llvm-links-v1-2-eb09b59db071@kernel.org>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V1jPPPfb;       spf=pass
 (google.com: domain of conor@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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


--p6SYI+U6gP5vpK1M
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Jan 09, 2024 at 03:16:30PM -0700, Nathan Chancellor wrote:
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
> Link: https://discourse.llvm.org/t/update-on-github-pull-requests/71540/172
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---

>  arch/riscv/Kconfig              | 2 +-
>  arch/riscv/include/asm/ftrace.h | 2 +-

Reviewed-by: Conor Dooley <conor.dooley@microchip.com>

Cheers,
Conor.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240110-apostle-trident-533d4c2c9c97%40spud.

--p6SYI+U6gP5vpK1M
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZZ6gJAAKCRB4tDGHoIJi
0mIlAQCj5ZP6QEhEswWYjX38obn/p3pF8mt+Ve+vlBnVEhAW8QD8ClRvKxDiajR5
Zp8ES/FLDyH/QJ5QjGuYLP5PATLeFAY=
=SqXc
-----END PGP SIGNATURE-----

--p6SYI+U6gP5vpK1M--
