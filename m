Return-Path: <kasan-dev+bncBDCLJAGETYJBBCFW5SXQMGQECWVIGXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id DF4AF881672
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 18:21:13 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-430c3b3b4dfsf21801cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 10:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710955272; cv=pass;
        d=google.com; s=arc-20160816;
        b=I64od0KTvDVRvwBeD6Vw9+KyuDh2FuUTK+eSMawuu5uyijllawd7ZdwrqDlZRw+zIw
         VPeMruzvZQXKEebhZ6YFayqsWx7zZ4RDEhR8uCAcWfp7vAsf98I6hPXNIb0a9vVGmDS7
         VdRXmuWw6u4XCOUicF8skw3d0OPp+QPfdQgAFH7ArSyr/lC0rDoMPn4SVix1+HP8Lak7
         v/tw+EyKmbLk8II5gRTufY/4ov4VUFRWCM3iPJfbvMXXa0B7UjVNm7Gb6C9ooyDGrRFo
         pUQd6aYg2ACHjz6WMqnOS9xSPoz2dBjHvs9IHxV4Z4UY3PCNB0OvCjASXa7e9nP0x6Ob
         AOVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z83wUnJopBJHVKoESpB+VZgSZDg1nN6gf0Tju/m4Vas=;
        fh=eqBhspgX3gNMl050Nom1RCkg9z+hdEZiAl/TZ7T2CXc=;
        b=uiz4KR2DTYnscKoJo0L584EvMz6B7SDRPltIhli3yvvianyOlmxLx5f2JnyTGmrojp
         65slSCoSByipd/q/T/CcO4x3mAf96ObZM7obDdmqBm0yDklxbB+CIn740XO4MkjOA1oQ
         zJc+ZUG0ef1PSo1gYtA4YSkNrU3I8KL5mUlkQudOnY7N6boGC64yhIbqTkvMtKuawe8J
         Pq35uGiWZF/Z5fStMsfAM/1iFt9ZAwJLeWjgOzdwt+fBNjsLGyUEyGL7Ik3O8gCX6QYq
         qy+U8clUXpK7yqfjuSS+QrzCa8Rdb/M9urFtA4JJRQv8Ws/JwSbQplJcNFx+tc58cJw8
         9cDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sSGqzDQR;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710955272; x=1711560072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z83wUnJopBJHVKoESpB+VZgSZDg1nN6gf0Tju/m4Vas=;
        b=CrwmSAlHU6TXxss9vkhwreXcfmJ2k+WqcfISmqH0KVe1MP4FAb+9jBUJ0CGg0YzyAC
         4367E5xfd1XY3Wnj3oHoAOIaTis5X2vmeUpPxkkRZ0KY9LFFg4KUym/39mcD/dZNZqed
         ll3ZMXng8C4U0s1ITvZN1UiXwyJ5jvvkJ8PGVUZrLsBqYEIgKqs2wkmNvOrFexxmSlED
         J5FRCOw4ERmCA0rgqkJOQrCRd165mSPV61WGUZwxw9doQfFjzq/2UV7GX7TF621iVuJZ
         6DzRJSVVRmafRsvrjtZMwUVqGoAdwRcDcey9FPedv7C4gT6jRbjCOpfGYiUZFg7oNJIg
         XOMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710955272; x=1711560072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z83wUnJopBJHVKoESpB+VZgSZDg1nN6gf0Tju/m4Vas=;
        b=pLoyEkucFz2CSHu84Aj/YrqhWxWw8b8C9fxkVpmYCjEbgx5i9yK4R6/FnTpghn9EbS
         IB4+g+1L56vEkB5ZlV57mK9fxh1R0lnHKqxrR1mI0dnPd05neav2qLPdvty94BK9vgDi
         3jmKHvKDa4EHhWUKMpNfRbFfjqj+4HbDKWEF6DwgwMT/rFOO9Uwycga2ygiCwJQEeHCj
         PIouYOIWY9ViGFUuoxWNL/+QTn+H15R8tTtfysdNOMzm5W9sBeNzLRBxHfR5S3vwMBNp
         G2YOvriEJ0zoNFZAml+JHULYpgzcSmIwOGjSCB09OzRNESayJUTsYJpnoouzPMfzqpwf
         Cmcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfKVWhx5xrKC2RLMRqCPca8pBi3knKbd2+BZJHpVtPnMlc/1LaSsy82u/XFs/iwQQZei1KSbCVt9ZJQJv3SfnGzsWC9z4p6g==
X-Gm-Message-State: AOJu0Yy+dy8T9ZHO6/hNzIQwERiCoZANTpP6bX0FQiTSmHV3qUfDKqXg
	qK01Splo9NxpQmKfvCn0IcwEFu8JvGZUggPFVvtb5HbQW3IZINbe
X-Google-Smtp-Source: AGHT+IGJgcNdMZKys2FYQ4mNKCbsG119sCUve1LwVq1xiWLr090sTTInNVZI15fbuTYs+haYonHPdA==
X-Received: by 2002:a05:622a:199b:b0:431:1d88:ce55 with SMTP id u27-20020a05622a199b00b004311d88ce55mr36503qtc.22.1710955272480;
        Wed, 20 Mar 2024 10:21:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1011:b0:430:edac:58f4 with SMTP id
 d17-20020a05622a101100b00430edac58f4ls305062qte.0.-pod-prod-01-us; Wed, 20
 Mar 2024 10:21:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxKBZh87IOEKVgQGfEOsIJOn6nMmMVK6utnDHj6+o+VsskkqzOdhC2P7wXG5T8Ventu9zYAo8YykEaTPTMR6fIBCDyKoNuPmMeXQ==
X-Received: by 2002:a05:620a:57d3:b0:789:dd63:5f7e with SMTP id wl19-20020a05620a57d300b00789dd635f7emr20247002qkn.53.1710955271317;
        Wed, 20 Mar 2024 10:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710955271; cv=none;
        d=google.com; s=arc-20160816;
        b=tmvS5PVYsiTB+CiH6zIfg2nbtlQTrSxdz8A5fW0ADvYTTp3b1Cqm9XgLfwCR+xxGs8
         IJcSffZquUnOvEF39zE1Pkd4ROQSu1jo+Cvinr9oQoYWPqYC+1APJWpekaF4NdDdHCow
         ABPd6gujzSyIeQ0JrUgHJaBhKU7N5cspVE2ECQGw7D/uhrlSTHmwbPpWbEi/pOvwKHWY
         +P6E3RxbezWX8CMncemAA4uFL6d1NDcShLlYqViCEft8+7Qefc5Danpz8CA204z3zSbH
         MuaAPJS4uD4OJiCk7bj/LHexcXBDBDVdnTcEGH7m/w9UR9+L9kUaeup+nPUtouQgteiw
         eARw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vdI7cSVCBpoArr6cQUeOr1FMIVOf2v9pxUfka7+o4ps=;
        fh=j7WGryLOYUwZ7dNBayE9j9e32gq8BxhSy5AlWNjlMr8=;
        b=clN8L1BaeTzvIqHFKU3JJuVL8hO3ZuhqD1spmBoEXNOLJDgSLeJmaWTKTYLfdixSfz
         fpPO0yDz7aNYK+ougtzvHqX/bEpeDCI5My4pD6glp8elO45wQV6o57VhDRnzdhSZgC1d
         jb402+Yj17py7SvmGa6hubyrmRQIj2iDSIMY64ubTBiiTpboVNbWkDidOezVJTVUEK0f
         Ri3nG3xnJleG8h2Ka6NoWBM170TYWTGKS53f0MM9s/7uORiLxjV4CGAhiCSq4GfkNFwn
         wn1IJgqi3e0WZuqap2mfFSRCBlBeg/t7tUNA9S1fbbJYNHkwuVDeV7EUoFGgj4haxBeX
         9nvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sSGqzDQR;
       spf=pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a13-20020a05620a102d00b00789d43b16b3si1149687qkk.6.2024.03.20.10.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Mar 2024 10:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D110C61041;
	Wed, 20 Mar 2024 17:21:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DDF59C433F1;
	Wed, 20 Mar 2024 17:21:07 +0000 (UTC)
Date: Wed, 20 Mar 2024 17:21:05 +0000
From: Conor Dooley <conor@kernel.org>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org,
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>, Albert Ou <aou@eecs.berkeley.edu>,
	Shuah Khan <shuah@kernel.org>
Subject: Re: [RFC PATCH 9/9] selftests: riscv: Add a pointer masking test
Message-ID: <20240320-handpick-freight-ec8027baa4d1@spud>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-10-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="2lLUjXGQgSitrjkh"
Content-Disposition: inline
In-Reply-To: <20240319215915.832127-10-samuel.holland@sifive.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sSGqzDQR;       spf=pass
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


--2lLUjXGQgSitrjkh
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Mar 19, 2024 at 02:58:35PM -0700, Samuel Holland wrote:
> This test covers the behavior of the PR_SET_TAGGED_ADDR_CTRL and
> PR_GET_TAGGED_ADDR_CTRL prctl() operations, their effects on the
> userspace ABI, and their effects on the system call ABI.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
> 
>  tools/testing/selftests/riscv/Makefile        |   2 +-
>  tools/testing/selftests/riscv/tags/Makefile   |  10 +
>  .../selftests/riscv/tags/pointer_masking.c    | 307 ++++++++++++++++++

I dunno much about selftests, but this patch seems to produce some
warnings about gitignores with allmodconfig:
tools/testing/selftests/riscv/tags/Makefile: warning: ignored by one of the .gitignore files
tools/testing/selftests/riscv/tags/pointer_masking.c: warning: ignored by one of the .gitignore files

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240320-handpick-freight-ec8027baa4d1%40spud.

--2lLUjXGQgSitrjkh
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZfsbAQAKCRB4tDGHoIJi
0pbyAP4rgHPD5OEauv47v5LeZ6gpBL/+0Gj9XCgAwfpJ1XiI/AEA6/mJhAh0XHlI
JCwPgAQGsM0OU/X+IRCzl56WkN8M1QA=
=mhnd
-----END PGP SIGNATURE-----

--2lLUjXGQgSitrjkh--
