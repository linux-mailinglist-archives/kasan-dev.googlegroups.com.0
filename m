Return-Path: <kasan-dev+bncBDCLJAGETYJBBRNHSOOQMGQEDVARSGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1046B654820
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Dec 2022 23:01:43 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-14c6a6ff8d8sf1577431fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Dec 2022 14:01:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671746501; cv=pass;
        d=google.com; s=arc-20160816;
        b=G41FwP+w7eU6IX92avb5NbBlHUDsaPbxZI4pj7pMMKW0fnwW6JjC24EQnO+gR31Nxq
         BEuI0Yq18IsKuoqQ258bHHbxeIafLJCsVk3xjalnJnF/GNqQkdS2k6UpbJLC4hdE8G2G
         Lgi72uCwO41ZJ0Ebnulaq0Omxm+X3PJu/Wplc+i7JbehgzyRFr8wCxxyHcz1feDwfx5f
         szynpKnPmlKQE6QX6Zj16e3ZfFCl0RwPGgh31JcP2W4EDLWLZjytVQfyE/wUI3IQ34Dt
         sV28ZBO6xVLwZpLkWGpvcvQEn0aAIgQmzzdvOD8uJYH2QQixdSt7b2q1VyY4Zmodw6NP
         SNQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zMTH4P3HxgPnmgEWYQpZIBSyqcFbant78iiw/MHZpAw=;
        b=q5tJm2M/KcHj8iGdeLzBhUw7YZmCa1sXuopmgVIloVUAbVNW8d9GH6dDuEgx2pcT8N
         jriQhVr7ss1F+CeLMHjk4Sy43Tjq/547kV94hpveGYEIknVkyMJ8kuhIWJvgO/TDOJ1l
         Jkm6R5rk1FGUwvI0IXgReCRzH8dFb26vuaeAijufvwzyhFnJprck1ed40nbwn9qXmshy
         z/S4kVO6b6JOU7rXuGXujbgnNTwuS034DPhqcLtDfRXmqL3w0Hdnv2XvWEPS7lxfFbFn
         d2LAkn5K9g8QJTHa0QbYKXOAfb7Nd/XLXoZyjTV7/r7RQyLh8h4gqAkTaTsTu/u3bMCk
         kdrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EkelR5Yf;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zMTH4P3HxgPnmgEWYQpZIBSyqcFbant78iiw/MHZpAw=;
        b=KKseTUVHKID1s0kseTYBAeZ54lSC1/w9CQOEvhaHN8IiSdoyyNOJJabfxFQOcxFdcz
         keayPbbnRL6ubGeV83IG0fpJn2yopjVQS3Ih386fqZ/AgQn5DUIs40jOsq+ThtQQoNKo
         IAFlSKHOxHtBzIR5dKgV72JCQAIFxqE321Q9bq7YrDi8cJRxbs2eXSdNOPH0348yS+Pd
         7bytPvqAZvo1OEKRgf6/3NRP9f2Pxh4obm++lwrDLJGPSdH8V++tJnp9p6Du7u71JFsc
         xisUGBkXKzvzvScC0LgGsIOqz+KdJ9Vsm3sn/f7zSVfDlztIf3dQWhZoqzPrn0/OQGBH
         KS0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zMTH4P3HxgPnmgEWYQpZIBSyqcFbant78iiw/MHZpAw=;
        b=5Wh96f6IW6SZCudLRu6F82txjdjr6i31k6ztyp6+GMBIbxZLr+X6Pq5/vCwEJC7EZ/
         XJZrYtnh0ECfCbBEpOYAsRAxf59KtppWXgerh9p9DCD2K0YxNSIERGUQmk8jn9qJU0Uc
         5ndoQ4h9teoO4Ohprfc18l/YVo6AZ3I3SoveySHIcnXDc49OADBVMyseKAEGZjylPhhy
         U0wVJnHgkoitoPxIxAkyXJE55a8z4sVXhnjzBv4Jkmx3EZP0rpYk/ccir03jmalgPxZR
         DYENEeyklct4r5tr0vPIM6+BGH+kNO8hMRS52phGkUF4uUVaZe/tWNWzRnjDPumz3wHw
         YpKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpcYKLpY13kSObe4oEpwhfuMTWYvlDCDerg+ayw3bkVEUl0IWO5
	jQ1zTgqiDM3NbSqUreAWfF4=
X-Google-Smtp-Source: AMrXdXtfY/1GCmItKV1I9ZS+DSIEJ2/Bz8mA4Xn2Wzmnu7YKnqr/5z/BxnslvrTNITzndBUyM75zhQ==
X-Received: by 2002:a05:6870:e8e:b0:144:e3d9:1839 with SMTP id mm14-20020a0568700e8e00b00144e3d91839mr466373oab.98.1671746501172;
        Thu, 22 Dec 2022 14:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d2aa:b0:13d:3bac:62b8 with SMTP id
 d42-20020a056870d2aa00b0013d3bac62b8ls1109235oae.5.-pod-prod-gmail; Thu, 22
 Dec 2022 14:01:40 -0800 (PST)
X-Received: by 2002:a05:6870:c7b2:b0:13b:d630:e411 with SMTP id dy50-20020a056870c7b200b0013bd630e411mr2896466oab.6.1671746500467;
        Thu, 22 Dec 2022 14:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671746500; cv=none;
        d=google.com; s=arc-20160816;
        b=hfnR/uKVWiU0PeKLB0AWjS6A8//vVkj+hqjggUNGggEaCfgTUa+we6bhYfBjIWvjAe
         wjTw0m5BcLPyQ7wlyKZbh2u6kcIdsgK3cpySW374oAoN0Gz6GqfRAVtMClXmL7n6YZ2q
         b+wy9TiNnCCdMbgzgFoxgITw7ZlLSMqQH6GqSQ8sBHWVZOpFou/SRNONw4JB9FXRXix+
         Urn4h5gDTihEyZhq4qpYheZ/tq3OlZN+iE19uQabUszgO3zghGY1XiBYFmoTaO6VM2Xq
         tGryff66Bms8zc4ZG3fZdrrSAnzZpNeLypI5F84WQy1ZG+nrxDdZGYCf3KhbBNgKfniN
         iNcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Iv0obKM4vJwFG2VrxJSRSgdvXJaX2M5OTpYKgXCxvf8=;
        b=i5NhtFWkZ330av1qp+pKpfHHFeODx2iRA1E/g/3nIRkivWq2bhf1FcbHgXLM+VlupF
         SGdUQYU2kckIU8dw05SQzKFDqowI3crAa0NGLsGajuSkdFbKkm+OOXyV6modF1tPGfWt
         RssV6Luw8ZXoPZNNyJD8KEYj2Wzbo2kaO1WPgnW6mxFAS8yKGvikziqumElFjcTGZWgM
         J9BtcEbbhcvByXY49AOuJCGSx43I4x9A36wKEg8oNsL68oMQdrUQnUdsKYDzgrEVvvt/
         3ZW5jDWWEYHPEohaYMbtyvXMhvj74SZ0rGSST7uE0FxBdIzJJbWDEL84gXBIiDuF47RO
         UbRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EkelR5Yf;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id w8-20020a056871060800b001371e49ab90si190505oan.3.2022.12.22.14.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Dec 2022 14:01:40 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3583461D62;
	Thu, 22 Dec 2022 22:01:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DA0F5C433EF;
	Thu, 22 Dec 2022 22:01:36 +0000 (UTC)
Date: Thu, 22 Dec 2022 22:01:34 +0000
From: Conor Dooley <conor@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Subject: Re: [PATCH 0/6] RISC-V kasan rework
Message-ID: <Y6TTvku/yuSjm42j@spud>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="TCn4u6SoH/sj16af"
Content-Disposition: inline
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EkelR5Yf;       spf=pass
 (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE
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


--TCn4u6SoH/sj16af
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hey Alex!

On Fri, Dec 16, 2022 at 05:21:35PM +0100, Alexandre Ghiti wrote:
> As described in patch 2, our current kasan implementation is intricate,
> so I tried to simplify the implementation and mimic what arm64/x86 are
> doing.

I'm not sure that I am going to have much to contribute for this series,
but I did notice some difficulty actually applying it. At whatever point
you sent it, the pwbot did actually give it a shakedown - but it doesn't
apply any of the "usual suspects" tree wise.
It looks like multiple patches interact with commit 9f2ac64d6ca6 ("riscv:
mm: add missing memcpy in kasan_init"), which caused me some difficulty
that was not just a trivial resolution.
A rebase on top of v6.2-rc1 is (I would imagine) a good idea for this
series?

For the future, perhaps using the base-commit arg would be useful for
stuff like this :)

> In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
> instrumentation: all kasan configurations were tested on a large ubuntu
> kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.
> 
> inline ubuntu config + uefi:
>  sv39: OK
>  sv48: OK
>  sv57: OK
> 
> outline ubuntu config + uefi:
>  sv39: OK
>  sv48: OK
>  sv57: OK
> 
> Actually 1 test always fails with KASAN_KUNIT_TEST that I have to check:
> # kasan_bitops_generic: EXPECTATION FAILED at mm/kasan/kasan__test.c:1020
> KASAN failure expected in "set_bit(nr, addr)", but none occurrred
> 
> Note that Palmer recently proposed to remove COMMAND_LINE_SIZE from the
> userspace abi
> https://lore.kernel.org/lkml/20221211061358.28035-1-palmer@rivosinc.com/T/
> so that we can finally increase the command line to fit all kasan kernel
> parameters.
> 
> All of this should hopefully fix the syzkaller riscv build that has been
> failing for a few months now, any test is appreciated and if I can help
> in any way, please ask.
> 
> Alexandre Ghiti (6):
>   riscv: Split early and final KASAN population functions
>   riscv: Rework kasan population functions
>   riscv: Move DTB_EARLY_BASE_VA to the kernel address space
>   riscv: Fix EFI stub usage of KASAN instrumented string functions
>   riscv: Fix ptdump when KASAN is enabled
>   riscv: Unconditionnally select KASAN_VMALLOC if KASAN
> 
>  arch/riscv/Kconfig                    |   1 +
>  arch/riscv/kernel/image-vars.h        |   8 -
>  arch/riscv/mm/init.c                  |   2 +-
>  arch/riscv/mm/kasan_init.c            | 511 ++++++++++++++------------
>  arch/riscv/mm/ptdump.c                |  24 +-
>  drivers/firmware/efi/libstub/Makefile |   7 +-
>  drivers/firmware/efi/libstub/string.c | 133 +++++++
>  7 files changed, 435 insertions(+), 251 deletions(-)
> 
> -- 
> 2.37.2
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y6TTvku/yuSjm42j%40spud.

--TCn4u6SoH/sj16af
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCY6TTvgAKCRB4tDGHoIJi
0orbAP9JIVPQo+hgzKfF1ShcT+6Ln7xErm9HazmhbtqIG0D61gEA5NgEVxpsOv3f
J9oJpI8UCyLrfCOHSx5LFudR2RhlJgs=
=WKhG
-----END PGP SIGNATURE-----

--TCn4u6SoH/sj16af--
