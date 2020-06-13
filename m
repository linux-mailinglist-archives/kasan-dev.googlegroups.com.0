Return-Path: <kasan-dev+bncBDL2VT427MERBTHNSP3QKGQERXPB5UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id ADF601F8409
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 17:54:52 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id r10sf1835583lfc.6
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 08:54:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592063692; cv=pass;
        d=google.com; s=arc-20160816;
        b=sy8/anjhQFpX6l2wxF3vsRkmenDeSfEclwsTXSPnyv3kr0EHrnR4qLsjRoIVBat1vQ
         zwqKtD0gKN5Y0wBgfeSfd9ecufLIduqQgsGZBtUXl+Z/UGGCH4nB4clnlfDvlZ4Hax9G
         nz+Z2i55r1JGTH4raIn2B2mGaD9vwZsPNxCwpuA01qyTU1kQiFFJtqiihwF75xl9m2Wl
         3jBUB9fYovjFp0B17PnHGyjrd2S5pDWNPVvMWATVN61yDMBJiAA4NMMyv+5OAX0PiR3O
         RCDoq7lYtO9c33N273qG0eQXcLKi8KUX/OFV3vylqXsSv7Ih3HtKUp6+Xz2R5xLE7Vb8
         i8/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=HIZhaHfO3pwKcFEsBApEbFzMneLHjW8GAXVPyzR1HEs=;
        b=DIboOEUulrrfQQ4VXGBW9OtibUt25bqKoW4t+minAXUUbPwxyGgmEt3QeVAgKhTeNv
         EW07qiQUJuxA6/00x/JAY7Ij94GEcHKfxQakOP/6pxUrLPIkoRoCu/f7VrLXHUosr/37
         Xxt1cIOPsIo6j7WLtaqbRib4P2JlMKVBiG+1WFjjJ5l2k567nb+ZcEpSuIqPx3xgAAlW
         QAdlRCpqR90WuYm/oQ9IQRpfhbtVWK95IrJoDHMFmBU2CfrXGLnzonOlnlqQcynB1GqR
         HFngj9wmspgmt1kigvxDwH/XXMAWuFZyeqDCYalTXsov/PpzH5HjM1muuI3vwXtxP5EX
         YoGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HIZhaHfO3pwKcFEsBApEbFzMneLHjW8GAXVPyzR1HEs=;
        b=l4AtJswih5jBthjCt1TiB4TnLHN3fyS8y8YCWWCjIS4TAW7KcJhdco1qMdl3kZ0Y9K
         28KT5scDnWYdJ1TInxbeb4mPKshZz7CcLqiqkY6xMING1qBjRbV78o+UslWmHy/4Puqq
         +j4kgq09mnqJka8dsY6DhunrvbMy/nLf4Z/P6CmE1bADM2WKvr4aIoguvB6iXHt+Tc5t
         ApE5ZIj+5zQxVhJFaJmnq5Qz3NN5oXsj+so8wfxTJJV7br6mX8t1GthAML49ks4geku5
         cU7srMWEUVxssATrdiICe73jv5zwFEd8jOx0OdZx2fhVXXE5x4hxLO0wJKKn4E/jM9wg
         L7AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HIZhaHfO3pwKcFEsBApEbFzMneLHjW8GAXVPyzR1HEs=;
        b=Ld6mRo7/bJHjk1bt3NM3kvW9KpwLY1Pk+1pU/Fk9GHaV1t4G3Tv1AQcnYeuLEnih37
         /YzdgnsUNhUj8oTsm25YwXgUk658Wpv2KB+Nntyv0cd/OrnzjjKPcFHfLvI6aOqjgIhS
         9ctp8arRhRRbYL+7BiUIUCuZ4UwV2lVvaO9tePBwrGwYEUnBy0bePNusQTaUwKZe7Im6
         fhnpQwWy3ezoLS9tP/6TyqRg/QE4zN0Z0yVf6F67vsrsw3tk6zWSNSdVQG/4o5kk9NYE
         Y8S7cM/LJFQO+NM04ZNYKKjFrageuzxsQ8+v/xdPW2+AQjVdzUXU3Q+XtFASVa+XmGBB
         JJOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wwS870Yxh3x4+nxQQGPu5MXN7taiGZ5/i2p8GqFWRqLO94csb
	/IMNuKJsZES2B3xD4ydzBMQ=
X-Google-Smtp-Source: ABdhPJyUyLcCsXji3So7Ff/itWXlAfQVTSFipXgNYbx3fJDw5gptrFHRu54R8B3Ch325DuVdfIchjQ==
X-Received: by 2002:a2e:8e27:: with SMTP id r7mr8988634ljk.382.1592063692195;
        Sat, 13 Jun 2020 08:54:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:30c:: with SMTP id a12ls1735840ljp.9.gmail; Sat, 13
 Jun 2020 08:54:51 -0700 (PDT)
X-Received: by 2002:a2e:9e87:: with SMTP id f7mr9861871ljk.44.1592063691791;
        Sat, 13 Jun 2020 08:54:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592063691; cv=none;
        d=google.com; s=arc-20160816;
        b=w9xWtmqCNIn3S0w8pXyF49TEVDPQYBrZPRbEAevJwoB+V40Me3ClMEHhZCjiLw8FLC
         owjlVKcZtsxu7U7+pIXdsj3U5a6+OrrjYBmFlZUNOCgY9UzoZGKoK5/cSljzzvt5AApP
         npWdZppBhY9lq8NpSq1mVJzbcTQ18YinnZc3KfB303dqQEZ3nfJck+JBFGZaZM2Wl+1G
         sunBSOubmSlCtYY+EyaS9tW2hvybl2hU319CuL/aXfubFHeVMPXkXPGd4Si6+M/7CVeb
         PpZFUnbstluLFaDzxjiwoRJb65CNGly1utEoWZy+q2RFi8Lfyc5dqs8usslecTerlcvs
         7pDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=L11aPAgfuQ6rfO/04YpICoQpKfv2/gzciCyYcX7Ltok=;
        b=XkThWt6GwsljCFEE21+wQM25KX/JDrHM6AoGeORegp5TixT3gTL8iOyedCKi/1+uCd
         rwO5whldSHdZeL57380vLFcojiAFlIWZAUFzZQqeL66p+dAGO1uJL1adVRZMxEiQv1p/
         5ORjK5YbmBl8iPcI3i9PBWhqg4n1kb3Q4siBHsx9Vh31POnr6Qrnc0x4pu2LIXGDZTBp
         KbhRyJByMZIjoOTCso+y34QHsOe99BlR7G8w7yYxXc3iUu4Hlvo+9rw7AQnR4jqWTRK+
         xAY6PIhMrLM/wpzgvWJmWj+2srKMg4lx14qzC5jBvTvUG2biU0lSelW33A2Ac73v8ySa
         xT/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id f16si730451lfm.0.2020.06.13.08.54.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 13 Jun 2020 08:54:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 8A9DDAB76;
	Sat, 13 Jun 2020 15:54:54 +0000 (UTC)
Date: Sat, 13 Jun 2020 17:54:49 +0200
From: Borislav Petkov <bp@suse.de>
To: Qian Cai <cai@lca.pw>
Cc: thomas.lendacky@amd.com, brijesh.singh@amd.com, tglx@linutronix.de,
	glider@google.com, peterz@infradead.org, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: AMD SME + KASAN = doom
Message-ID: <20200613155449.GB3090@zn.tnic>
References: <20200613152408.GB992@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200613152408.GB992@lca.pw>
X-Original-Sender: bp@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=bp@suse.de
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

On Sat, Jun 13, 2020 at 11:24:08AM -0400, Qian Cai wrote:
> CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT=3Dy + KASAN (inline) will reset
> the host right away after those lines on linux-next (the mainline has
> the same problem when I tested a while back, so it seems never work),

$ head arch/x86/mm/Makefile
# SPDX-License-Identifier: GPL-2.0
# Kernel does not boot with instrumentation of tlb.c and mem_encrypt*.c
KCOV_INSTRUMENT_tlb.o                   :=3D n
KCOV_INSTRUMENT_mem_encrypt.o           :=3D n
KCOV_INSTRUMENT_mem_encrypt_identity.o  :=3D n

KASAN_SANITIZE_mem_encrypt.o            :=3D n
KASAN_SANITIZE_mem_encrypt_identity.o   :=3D n

so something else needs to be de-KASAN-ed too.

For now flip your Subject: AMD SME - KASAN =3D boot.

--=20
Regards/Gruss,
    Boris.

SUSE Software Solutions Germany GmbH, GF: Felix Imend=C3=B6rffer, HRB 36809=
, AG N=C3=BCrnberg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200613155449.GB3090%40zn.tnic.
