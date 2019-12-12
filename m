Return-Path: <kasan-dev+bncBCXLBLOA7IGBBYOFZHXQKGQEMP7PWGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BFBC11D189
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 16:55:14 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id n18sf1704452edo.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 07:55:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576166113; cv=pass;
        d=google.com; s=arc-20160816;
        b=p6j3awtPX0KcA32oxlcSA7OyRouBUPC4C2SczGLsu9uIIx0DHEUVXSkFpuIcqT4e3l
         6nIVGPSCY1I0mo6iMuBvWeYPRbKGUjPbVBDbtk+S4PT5H6436VSw1OZdrZ95t4wJ/dtL
         krpgJqWliI6QHy6mvIhMikq1n2Qhc0tJhzcv1XkeY8XVOI4DqKKdv9ZigQEj1ZnpTk/R
         t8XXN4CjJDwaeEu+P0ToK0UBUdQu6p3cXNVLn7QSFgn8q6NZ6hjmrsEmg8y131tiGcXq
         4JXmSeSw6DRhZ9GbESULeINaqLiZdLERIdeqlwxzC5LwOGCyaoSs70TloIyrq0vKAOQu
         rzbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=2JealDnyhBWsXjSq6cLqTCev65z618kg233blFEBRMk=;
        b=h5dt39pgCSld1VZmaahb+uiHpeJmh79rh/0fhgny7yhjVr8YAYJC0DZe1+KXL6thCQ
         ple6ZQN7Zx8iahSrUHA2236BiYsdNNrTw+YhkFOkO3oJbwmaEnQi20RhI8lIq9azw1T5
         VYvaKwYxk5xP7hJ4RaBg3+VwCNTSOqJpa70AilYF886yRugQCoOcSNL5NiKFPrg8c1cV
         LFe6Orib5HLI5MEO11C6PWHT5FYRw85rvMbuQrxANwDGVqQwyg1EAqVNrlMkniq1F+RH
         Z5NrxoumkW73X80cK0AG2uT5n+dqyExjcU31z0fRNXyjf2pXALZHPIru5WrPy+0kQN6/
         EcDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=EfCot0cP;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2JealDnyhBWsXjSq6cLqTCev65z618kg233blFEBRMk=;
        b=cIOcSkiyjwWGJzhXMKDMJiEF6C26zMuRy7837tOkmD8LrJ4xHqsrnT6dk0UGc+AwWp
         PkwGnsT5ZqO63x7Onn8BcHF9NYJEer2tn4iwJagC7bavgccFTak3fJe5G4rHsBjEN08+
         vNHEX7jZWBEcigypk2VM1N4OgINrFuuHc+40r6AdwCW3KHlLSAEh6qFF727A9DiUh8/A
         0OLb5AqkvDlhMP2rPLuL5J/SA3+MXLI1Ay3z+K3kXWUUuZTWee0pMTQHvKXbryiCuH34
         Xv6AbEDYoOI0nzOC8H5vB8rEPEU0kgQcXelWtU0+BQb85Fm6mvVLPl1pjtjpRsfAxSVn
         iy0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2JealDnyhBWsXjSq6cLqTCev65z618kg233blFEBRMk=;
        b=hnMUChkS8sCWB9m0/uaqRRG+5TSccEg6wKo6lDoyP3KFtXNlz4uCFCuSIEKG6eBmxE
         wwfDih7nPcx9xjRCLt7ILAOcYvmobJw8NFv+E46rN6slhnKXbSpAxgNwlYIUfZmveOGK
         5OlKoBQ/xUzpyaBEmTK5SYucDml1Nww4CDboqMtk+wHFzhqaVo5KWZ4f6yC+sWs9UbAh
         6z1dnHs5EFgWofDATQiMjYR2I1zRGazOjvJ54rlIdmsqXc3gKlmDe3joIVwYgJYjWSi9
         4zY/lAUaPSpA8Af9bvOiR06UY45UtJW5wEWRk+QRd7z+JZl+ptfTzibxa2VCtMrsRqMK
         q8tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQj9zSMAPXw3l5XxxmHME7mVaettGWrDcXWj/200COnAjlnja8
	qr+QP2qkG28RtxXw3bm/rNs=
X-Google-Smtp-Source: APXvYqxULDyZxcpg1pmUODBymCteN2IHya6C11uGDJixm9h02nvlsXbhlu2cdcaFwdYEyewPIZqOHQ==
X-Received: by 2002:aa7:cccf:: with SMTP id y15mr10256585edt.108.1576166113853;
        Thu, 12 Dec 2019 07:55:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f2c6:: with SMTP id gz6ls1616464ejb.3.gmail; Thu, 12
 Dec 2019 07:55:13 -0800 (PST)
X-Received: by 2002:a17:906:d8b2:: with SMTP id qc18mr10406812ejb.162.1576166113304;
        Thu, 12 Dec 2019 07:55:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576166113; cv=none;
        d=google.com; s=arc-20160816;
        b=T2dzYIf2JaDbv2SXr1XJvpzuo9/unauS297j5fsTqDWzgq340fyjrvnOs8WPG4ou6d
         uIfQr7fydyxVlf+TgLXfPaaI6cmGNXyK81jhRvsETXLWPskNkhvIsIN3rHwAPkkDYNAD
         KZ+DAfzb9mVT4jGf1Ed6Ih6IXfl441DnRpcwuIGss/bqjApp4KAGIds/uLdKCBXzg2N/
         nkpX0Z4x0wyPLY6HSXvJSGoU4cCxtFcQ5atn7IDQN/sxRUzKsiiD/F8B7scqu59+VglU
         2WTO14kvLAEWusFgFjN9WFv+Rs1qLUuGNFb59ARzKTsCEzKzaMj+hUMI1jT0K9NI3qrZ
         0kzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=PJztFoqZeZST1HMzqILi2xyKFqgX3RxPFx1/4+TG/tk=;
        b=gwZlY4W/2yVThv3giw37TIc10Pl2+QGWFxlzCYtpQFHigDZy5xOsvH0rF338Gy0kXa
         Lj+pdRfsgi1Z5ngGGxpVelojmMCuNK2IwiPBBKTHm3rbZY2mb/wfw/KaEnXJHTLJ3eCi
         +hzQpJIKcCRTyyXgZ3knE1/kZg4gm63R+sURMVPXZHNKYSRQ8LDZC6Qv8sptlN3XUkqU
         2AjUl4q740SfjoQXED02sOzD4r2paTqfKaG6liHRUFZit8BOD0Eoz8EQVS6WLVlOXZF5
         q/LagV7N1H2CZfFAqrSbI4KSudw/R00Uwjc3zhCF4RtO2D4TuQKiscbkyqQgwOfj9eec
         N++A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=EfCot0cP;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id h11si205253edv.1.2019.12.12.07.55.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Dec 2019 07:55:13 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47Ydfl2H6MzB09ZV;
	Thu, 12 Dec 2019 16:55:11 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id D9rWWWTshkIZ; Thu, 12 Dec 2019 16:55:11 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47Ydfl1CmQzB09ZT;
	Thu, 12 Dec 2019 16:55:11 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B10348B872;
	Thu, 12 Dec 2019 16:55:12 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 9AsI8caOxSn5; Thu, 12 Dec 2019 16:55:12 +0100 (CET)
Received: from [172.25.230.112] (po15451.idsi0.si.c-s.fr [172.25.230.112])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 935D68B860;
	Thu, 12 Dec 2019 16:55:12 +0100 (CET)
Subject: Re: [PATCH v3 1/3] kasan: define and use MAX_PTRS_PER_* for early
 shadow tables
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191212151656.26151-1-dja@axtens.net>
 <20191212151656.26151-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <65a52c58-4409-de89-6f5d-8797d0ebca74@c-s.fr>
Date: Thu, 12 Dec 2019 16:55:12 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191212151656.26151-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=EfCot0cP;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 12/12/2019 =C3=A0 16:16, Daniel Axtens a =C3=A9crit=C2=A0:
> powerpc has a variable number of PTRS_PER_*, set at runtime based
> on the MMU that the kernel is booted under.
>=20
> This means the PTRS_PER_* are no longer constants, and therefore
> breaks the build.
>=20
> Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
> As KASAN is the only user at the moment, just define them in the kasan
> header, and have them default to PTRS_PER_* unless overridden in arch
> code.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Suggested-by: Balbir Singh <bsingharora@gmail.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

> ---
>   include/linux/kasan.h | 18 +++++++++++++++---
>   mm/kasan/init.c       |  6 +++---
>   2 files changed, 18 insertions(+), 6 deletions(-)
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/65a52c58-4409-de89-6f5d-8797d0ebca74%40c-s.fr.
