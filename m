Return-Path: <kasan-dev+bncBDLKPY4HVQKBB47DVODAMGQEHQ6OCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDD273AACC7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:55:47 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id mh17-20020a170906eb91b0290477da799023sf1083474ejb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912947; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0iboh0z04pOspgEZTQ9wrZQkOJMWm6N85hQwM48+7LQ/c+ejXwLOOxP7IGjBsvrom
         5qfxRHV5gcD38BPuNFMJgVrKWyZJ9Y+LhS8IWWP+PXOiYgIklJc/VfShzIG1Y+7KoRBW
         rBd279Dq8Bzya8XN8SodHQVxel7ztbstiP53TCsiJSL/FPno2X/nlwQTPlBtQBwjQhu5
         3bIuIwCrCdn+p9X43eKjESgalE8xB6ocbLaoUpTk/ONW8YCF6i5n5F2jELRgNXM3vXeb
         stw47kJNcZKV2e4mvZXdg8+RcsLdWScGe+Zj7mKv0c60uetFZ11XrgTMobBLcvVY7+CF
         xb5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ii4oaxW1vCx4ZZeM6WStZZJ967UuQ36x8QLvTg/kmFc=;
        b=ourmVY1cptCqEyapY4APuu6fnxaOK3JPbs4ogclNWclgGvoYTSyxG+W6p+hL1Fg//6
         YcYp6M1SEQlMxtkWyoF1h3P2C/oVIcF6NmW7PGHahrHgt7IaSDq/+Qe+t3h3gMxHjMvB
         DfgvdyXLdGuenIR/QQPoxVjVAnu/9huvii1MTAzAwaKN2IKJ3rDjwsjOMfrGDQzrQLAq
         NIdQzlKHx4aY3nCNd9ABCHSZSulLwuqWR+DF+MhMGv0PwGpdzmmYhW/XOINdA5A0QoGO
         YQu7xxBhhirhGGNDgd8pcTvu07icRDWgE8eFwPnYfjxVc9YlzuQRctG3WIlq2YKhPfGj
         KF8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ii4oaxW1vCx4ZZeM6WStZZJ967UuQ36x8QLvTg/kmFc=;
        b=j1ysfKSlFTgos7YF+KGFEJZA6UlJNNbLtcc2cP9VPQsD163uMOdj8kQpoOsOkzlbUM
         MaYP1yOLd6XRsfgBSCPsoZ1ByMsqxTNUkwWKFlEy8IabdnG/MtSp1Di6zT7cz8piO9mJ
         pjk40EUNIKMaqMr6VNA02GW9ikVlDABxyKV1rCkZ4k4yPFrs+81G0STtt/unglmfRHCI
         ICCL5guy9eR15YwEihiMcX1jLGEBXpqNU3WV0BcQnFMlB3TfQj0FGmiWwPOiIfLB9FLe
         LSmccpJKFgoi2y4xRuqpWaOaA+EoNNDlsYQCietR7igTeLn+uLE5Sw8v48AoF8sLfRhY
         3qIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ii4oaxW1vCx4ZZeM6WStZZJ967UuQ36x8QLvTg/kmFc=;
        b=JquZgGYR+yMzpRoTNyafLwFYSJYgpzbiSixSXmaaOIuBxhMpczqO+7WOZ2p36HUzv4
         1mAkK9mywf38x3/4OdKUh2cGkIWHbqPSGPggea68xFABuDnO2AH6bqbXEmuMh2FEHRkR
         3oye2Usa2tOAdk4KeN29LMCevCVxN/C9im2MGJ6Jb20xQVSYT2Srp14kMjD3u/ehsdPa
         D8oMXJ0qQy0mS4wBhMAebmN74/Sp5toNnvsXlVIQDBVNHgV//IN6AdMrvS3F36YySsXX
         X6XoDP1uFwioSyPFu4yF/tkd00f/VEhgfhEDdkT4eTrUdcBSAsmRhykCbZ40rqdLVIx+
         pzwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AQ8GTOvZx8oVS47Si5zGpmIBou9ZAvqOP25yt89fYAgVGJ1Sp
	r3A0/XfL+FpKr8LY7FA/PqI=
X-Google-Smtp-Source: ABdhPJzrfRiJ6AUkNqAhCUmPtrrKoS7OR4RB9VvMvx2u14IucGGK4Ew6G4VmR7CR3iaWxqkeNiPGrw==
X-Received: by 2002:a17:906:128e:: with SMTP id k14mr3573363ejb.485.1623912947467;
        Wed, 16 Jun 2021 23:55:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1c97:: with SMTP id cy23ls1957247edb.0.gmail; Wed,
 16 Jun 2021 23:55:46 -0700 (PDT)
X-Received: by 2002:a05:6402:10d7:: with SMTP id p23mr4543006edu.74.1623912946649;
        Wed, 16 Jun 2021 23:55:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912946; cv=none;
        d=google.com; s=arc-20160816;
        b=yl5w6VJzttV7Bb45qh0Rz6HwoJ8x7NmwcEq3kzW6XulRE5iSx0HShDKBqI4VGUo91/
         7BrAbezWsccelx49gXPqp9zod8+qobpdLosW6E7t5PnR9b2ooJwhY2dYK5Y/sZtslPp2
         ZwKauHNfkL90QwHYUthBFjK1U69Zv0q14AWWTH1BjFI53WLY+oQgmJg3piad2I+3CbhB
         Z1pxFbGDxLXIE23TNNeGrWtR96JCUWSLG+DyVMQbczwS3ZWaiD1LYCY1Wis6zANtADU/
         ML0FlKqR76lFi/gG+ppfdBjykbB1WMo0fFQFXAtrB5ti6gAti3uDRN/xBMwriIV7ELL8
         3Jaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5FZ4SLwJJwY6UvU874TbLYcadVpAshknkx58czx3zrc=;
        b=YE43n6zNP4noZ5KjKOwy1ELfu4xEPI7gCQ26v6F9RTtEH4IajX7Wn7DCfa8rmx5ZjG
         2hR8sj62Je5jvLbQDa0HhTX4FKe9VjYcWXgrOQ74qzhq7Gc8u26fUzMrLbWYTuiDbj9x
         ehp0U1ogCsXCpZhxMis+8SYTDAnRZNPBylU3ftL0oR87KgWtjUXcITW9IF2oK6GSHTI6
         9ziZ2Kj7gts/EQr35FIXiElqjWGrxxfKsimOvI6Kt/RLoW/C78fgj2+y5WOI5yPYHGD/
         XygLgI8ZYTKbr6KlLXwNBDljqKTk2gMwbQ0X1J39kUbBh8eSlQEyX98abHKA9Zjbx6wD
         oFgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o12si86752edc.0.2021.06.16.23.55.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:55:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4G5CW62V8YzBDt2;
	Thu, 17 Jun 2021 08:55:46 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id dKW6sfhlMRMC; Thu, 17 Jun 2021 08:55:46 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4G5CW61XjmzBDLt;
	Thu, 17 Jun 2021 08:55:46 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 176178B804;
	Thu, 17 Jun 2021 08:55:46 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 3xwBsrTEU-ED; Thu, 17 Jun 2021 08:55:46 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3D8EB8B801;
	Thu, 17 Jun 2021 08:55:45 +0200 (CEST)
Subject: Re: [PATCH v14 2/4] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, elver@google.com,
 akpm@linux-foundation.org, andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com, "Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
References: <20210617063956.94061-1-dja@axtens.net>
 <20210617063956.94061-3-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <853a39a4-5ec3-08a9-87d0-d599e8828e8b@csgroup.eu>
Date: Thu, 17 Jun 2021 08:55:40 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210617063956.94061-3-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 17/06/2021 =C3=A0 08:39, Daniel Axtens a =C3=A9crit=C2=A0:
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>=20
> This will only work in outline mode, so an arch must specify
> ARCH_DISABLE_KASAN_INLINE if it requires this.
>=20
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> --
>=20
> Both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>   - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>   - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
>=20
> I haven't been able to exercise the arch hook error for !GENERIC as I
> don't have a particularly modern aarch64 toolchain or a lot of experience
> cross-compiling with clang. But it does fire for GENERIC + INLINE on x86.

Modern toolchains are available here https://mirrors.edge.kernel.org/pub/to=
ols/crosstool/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/853a39a4-5ec3-08a9-87d0-d599e8828e8b%40csgroup.eu.
