Return-Path: <kasan-dev+bncBDLKPY4HVQKBBGGV4KBAMGQE543WIJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C2C6344740
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 15:32:57 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id cq11sf27452693edb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 07:32:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616423577; cv=pass;
        d=google.com; s=arc-20160816;
        b=I+7L0f118wXU1GO1PQimFHsy9/5UX5vlaiKFJg0jqXF8gySMqb3yMIm8/JtWchR5U9
         fQKqJl+KZsY09VOV2Pdo6Ru5w4ttNfQocSGYu3Opxc6CnPtEXef84WSF33A2lXnuknao
         DtvUinMfDGJGfJEuq9v9lMuYLEeAY+YZCOOC53wO63yTcTeXuWVOVYAQzzxkjJ7C5vXU
         foUPgXZQ6/k2xRXAao+dZQISr8ihjkUfDBSitltlj6t4QgBQAfddSd5DogApmru7F9PX
         PeYh2ad+dRLcEnc/Fux+L6NKsyanWK/jQUSnnQziOtqQIbfevB++jQ33h+Edu9fGJkdX
         Xiag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=ZvlUhCXEOLkilmyVFENkWskEUOfrc+u9jYvjlOJCSY0=;
        b=r76lcUeWrfQp28VZP4N5bhoZtxmfjYowXdFJz64QT1oePqGKG3aYsfzuEuuGVqPJks
         D24bxjK8vlPjlO6LCfl/xrfQz6DMblY0h3STOZDt4pXV30HHE6AYdINMRl71/tyy6X+k
         RriRTWX/wmrSpEumPvGlILoVY92c5PCHOYbLnYV6cp6EqUT106Urvhn/z1zq/UumfUox
         Cig2RZumIUxb+hPzHs69RQraTWb9USDc0xN6kPt5if5RZ8HPWqFezabcrUOIWCELrM4m
         SrLTY1rYOKiEMJjPR6e0z7UgW1o+VJOykCUazOZzBxSfEdsLwGAeIlRffc91i0Jg1wWD
         R9+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZvlUhCXEOLkilmyVFENkWskEUOfrc+u9jYvjlOJCSY0=;
        b=HRvf5q+qbNGKVwmFMRAaQB/Lh8jok/FMh9aNrGbgIfHwEOhntsrXT/UUtutsRKzmjN
         Eg8xLq+4XaG98dHiTJ5QEmuPCqSYQYV/zH/cluv78xLfmvSkmRy/OfvtkoqUmqj7FHdL
         MIRj3VAh9u5MWkR7Sma8M78Q0nsTvrMSJjZ1eY4yCVxWvWGUGGvk1I3ORxJy5gZfpyhd
         i017IciwI77RAZdrSrC5LQfRbxhhBNn601CTzXAISs2TxYaffL2aTxlE1WI0mijQyvJC
         EkNV/ipWOnTfSwwXv1W3kDrvA120xXbtpq8qmOKo+D+J9rub29VDL437sXM2EhAvCeeq
         fi/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZvlUhCXEOLkilmyVFENkWskEUOfrc+u9jYvjlOJCSY0=;
        b=oX/qb1iITYjlvJvedY+FzQQhWFjHcV0IPrHJ8ipOgHoG8G8hsFs/s8KTPmh1Fbp9oC
         bmn8FQUikD/p940OqAj1pqWN4B0rQDefB2wbSM99cQS3f8lh+sfUwn/TKHVtEJZXKFZc
         5r0x2R4WYoK6R8/UiFNSjmvaUsvctkZggi6+Ae+j60VyTvjY9NgkPyOpqZGWvash3Bl8
         2RPNWlz496ARCUrvMIGqPXLlhx4EUgHVctH9xfQMF3/a7tRN1hg0jA10vdgdZD5qlUvE
         uwCl1A8ErQaBPvykOz6rJgq9AIZGLLlhex+C6uk4XVWnOUpklfC9TFHujVDP8gBVJbgN
         Pwbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U/k/UKmx9zived3zXutOHtQZQbBzdkpGYVdUpk4mXjd8qvZZ9
	qIeBeRmzge4f44B+Rw65Xzo=
X-Google-Smtp-Source: ABdhPJxTvqDhlJk/QH1Q22P+x9rRc+PgZiwggsH1DxZZUiVaxr+tXWSKuVnYVmMIOJx8mDDXMMxzSg==
X-Received: by 2002:a17:907:75c7:: with SMTP id jl7mr11801ejc.191.1616423577033;
        Mon, 22 Mar 2021 07:32:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d788:: with SMTP id s8ls1842703edq.1.gmail; Mon, 22 Mar
 2021 07:32:56 -0700 (PDT)
X-Received: by 2002:aa7:c450:: with SMTP id n16mr25240642edr.16.1616423576191;
        Mon, 22 Mar 2021 07:32:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616423576; cv=none;
        d=google.com; s=arc-20160816;
        b=ZwEe7wYw1mOiSqj10mzR0tk4hFwt7pp0xc/OF9LsG+UDiwwWT115eYZDH8uAOVcG9D
         1SRezVLDMU99nbNMmg9TfT48Ox2PVZv8V9zH08l9f9ENprULaRJbgTeHoKAXPssfq8x1
         yQMpLTI8MzsIRfXp2kyVFwlCtB2B5FIp5aq3w5kyQMGxdqfO9mbu6LkbSXNIXKycPEkE
         aiMVVAhZn6qXyZ7PPXhhw7tU1yOVJ3ScghIYqKRLUmrWm3wpNOYDK25ET3DI5vgsL/Nm
         WfQbhrU4WAmjvTS9FRMflRxUq65mko66xwNvIt9P4ddO2fg61Any+wGmkcly5jpdBJl+
         Jfeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=PpTDbCL0EuvA3mwDaMpXO945wftA/o53owxJrhQOIOA=;
        b=adS1dJ1a35YMT+xIqM0iPRWZcs+RKM5+22+yV6hCIahnAmqPITZtmdd5Nw1kGvRfh+
         dkwmn1aCxeYJKX5nQrWBJXijKQQjvn4sGT6HYoJthq02Itt8c6YaRGatz+87kZKGc00S
         +00mMK95I2jVzYtiAU50hehY1Pugm6iRTYjPAETwogUiE1fRnSOuYtVPmtaWuyBIRZMU
         xCCe1hnKrPQB5XeQya7K5pi44JDLmkmyM45TOSo7KRbEfJEciPbg9zFM8Ko0WuVGStBB
         Ndrmuu/d9qfF72FLJUqVAoF9rsxL3kK/dfIPqHGfMy3d05AJbHRXZHbrp/838yC0hXTU
         fwjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id df17si643673edb.3.2021.03.22.07.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Mar 2021 07:32:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F3xmf1Jcpz9tyhT;
	Mon, 22 Mar 2021 15:32:50 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id Ddg49OyYyGfy; Mon, 22 Mar 2021 15:32:50 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F3xmd5qZNz9tyhR;
	Mon, 22 Mar 2021 15:32:49 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1785C8B79F;
	Mon, 22 Mar 2021 15:32:55 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 6Tx7BT7WTY9N; Mon, 22 Mar 2021 15:32:54 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3E4318B79C;
	Mon, 22 Mar 2021 15:32:54 +0100 (CET)
Subject: Re: [PATCH v11 0/6] KASAN for powerpc64 radix
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20210319144058.772525-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <5a3b5952-b31f-42bf-eaf4-ea24444f8df6@csgroup.eu>
Date: Mon, 22 Mar 2021 15:32:50 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
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



Le 19/03/2021 =C3=A0 15:40, Daniel Axtens a =C3=A9crit=C2=A0:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>=20
> v11 applies to next-20210317. I had hoped to have it apply to
> powerpc/next but once again there are changes in the kasan core that
> clash. Also, thanks to mpe for fixing a build break with KASAN off.
>=20
> I'm not sure how best to progress this towards actually being merged
> when it has impacts across subsystems. I'd appreciate any input. Maybe
> the first four patches could go in via the kasan tree, that should
> make things easier for powerpc in a future cycle?
>=20
> v10 rebases on top of next-20210125, fixing things up to work on top
> of the latest changes, and fixing some review comments from
> Christophe. I have tested host and guest with 64k pages for this spin.
>=20
> There is now only 1 failing KUnit test: kasan_global_oob - gcc puts
> the ASAN init code in a section called '.init_array'. Powerpc64 module
> loading code goes through and _renames_ any section beginning with
> '.init' to begin with '_init' in order to avoid some complexities
> around our 24-bit indirect jumps. This means it renames '.init_array'
> to '_init_array', and the generic module loading code then fails to
> recognise the section as a constructor and thus doesn't run it. This
> hack dates back to 2003 and so I'm not going to try to unpick it in
> this series. (I suspect this may have previously worked if the code
> ended up in .ctors rather than .init_array but I don't keep my old
> binaries around so I have no real way of checking.)
>=20
> (The previously failing stack tests are now skipped due to more
> accurate configuration settings.)
>=20
> Details from v9: This is a significant reworking of the previous
> versions. Instead of the previous approach which supported inline
> instrumentation, this series provides only outline instrumentation.
>=20
> To get around the problem of accessing the shadow region inside code we r=
un
> with translations off (in 'real mode'), we we restrict checking to when
> translations are enabled. This is done via a new hook in the kasan core a=
nd
> by excluding larger quantites of arch code from instrumentation. The upsi=
de
> is that we no longer require that you be able to specify the amount of
> physically contiguous memory on the system at compile time. Hopefully thi=
s
> is a better trade-off. More details in patch 6.
>=20
> kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
> nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
> fragile - if any real mode code paths call out to instrumented code, thin=
gs
> will go boom.
>=20

In the discussion we had long time ago,=20
https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20190806233827.1645=
4-5-dja@axtens.net/#2321067=20
, I challenged you on why it was not possible to implement things the same =
way as other=20
architectures, in extenso with an early mapping.

Your first answer was that too many things were done in real mode at startu=
p. After some discussion=20
you said that finally there was not that much things at startup but the iss=
ue was KVM.

Now you say that instrumentation on KVM is fully disabled.

So my question is, if KVM is not a problem anymore, why not go the standard=
 way with an early shadow=20
? Then you could also support inline instrumentation.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5a3b5952-b31f-42bf-eaf4-ea24444f8df6%40csgroup.eu.
