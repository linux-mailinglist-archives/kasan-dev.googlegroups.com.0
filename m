Return-Path: <kasan-dev+bncBCXLBLOA7IGBBYG7V7TAKGQEPCANRAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C813128FA
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 09:38:08 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id d23sf4299609wrc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 00:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556869088; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iu5BnIGpRPO9u8UP1E+yCaMZ5UJ9flNalG4EPg1zsyE0vRBwKHwjMSafBUwa4czjtD
         N8FVFDYGH3e0ZFvL9reI5q+Bckh/FyJ0S7ZCkS8B7+w4I3DT+jpBnWKj9BrGmY/usM5l
         7F/OLTYyI9eXDIO9YlYz2a8HyGQINWxty21LgV/jP+vHMyZ6s65LP4hmS69/lEEq0KVQ
         LwEtVaJ7gbWeT0zL9NKbWAVNKOCsUlb6Moh7S9QZX9AfDogPKMZmzovD4G5LCmff7S1g
         XvvzCev56KUHZzkugNQHIVWSh8IJYQDYePx5VlzRCVjgjjRyl1ZE9ldZHzTboFIdPxXZ
         akLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=8FkvcbLJhAa7flQDye6RaivPQLGSlY13FnSB997bWbs=;
        b=Swu2xa3iWuv7v7Prp0jj+m5P7o0RKrHGDSs5s7oUMDoBwyEiPM+Rtt1bjXCXhgVIuG
         luHP+9k/Skg10iaXywVWx2Cwbl94E9Qq8ZL8A2ojfXehorey6O6iW2NMC9/PjZYXQvEy
         7cl+oT2g50uGDBeutbVa4fCpjIvFD/v//DS0ggepS7d5c49fJ2al9oVLb8hUOqBf7XM6
         6TvbQpWIhoiKpcVXj9243vHRRPQgSxpYOiDrUQ49uhK1vg4kPSrYkwwufFgYGkbFn9Iu
         0qkHfw5yYwdr85WRrHLwvbqV3MB23Cgdq9rs09Npf2gqSpLKk6AQNSBqNN3clb4Lwp9a
         cq5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=g6fjTQ0J;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8FkvcbLJhAa7flQDye6RaivPQLGSlY13FnSB997bWbs=;
        b=NbG8uJ3QOfVZDNLHthOTMt+KkkopP4hSMYIHMstvytvoxYYfSBY84UXu35AO3i/m1z
         mtjtkD36tlLcph9a2WWqEEiPy2KoPiRXlkpGfg4uG1EEAO0WK53xWb32fb7QwoQlBXyh
         T6Qev6bNJ1hG7Cx9BcJquo9QKcax+q2Xw8vXi4uLil/xs6SP42x1d4iBWJklrzxEytWt
         Ija5j75zJW2g2qkPvEbRL1p/A9VZE0OPoJIMxMQHYrh2SY+8RLn3R8qGxQNWqhO+qOdp
         LHd07PDli/qSGUyapCWeBD/5FfxrHbhvjBWmrul7OeGIFr+6b+Uh6cAnLcy3JxVP0TCl
         L8DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8FkvcbLJhAa7flQDye6RaivPQLGSlY13FnSB997bWbs=;
        b=JORb098vNZeAjJ8L99PQhKBYQ2KJl+UaI8IHdam3pm2N6dpNYAKYcbMPMuNr1ewD9I
         nB6UJABKJoretghn+Ax/KOy2WXO4fAhJDvJ7amCg7KyDHXkFW2KLRqKgApTvCWGrNRDl
         PlfjSbr7ghAzwryaHNDBL6MmJznfKycm5m+FFHifZrS+8Bi18Rh0GL79yHbs9d80DIKP
         WBTo+j5ypoO3gu9SjMfQmlaEIcr5Dm1chEKx0BBsNP6SdQW2WteZoXp9yzUPI8cdv97J
         QBouZeK+ddQ83i7wZm6le97nkCg88CFYyHErxDZ5Bg3lJAkYTEAqvZlZ8fxdNuw4I3KM
         TpDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU5Y/2k4+MihtuX4LLOgwdXwLTlBBjMpdiEJqvKNBKRxGfp/Sz1
	VHIWFnqqKLd0X5nl228ijqQ=
X-Google-Smtp-Source: APXvYqy1zD0Aaftob1o8t3vqpvPrhrM7ZdFrUzDa0WM73cgXRwPOgVvkTuryKCd4DHXd84yMdnGlYA==
X-Received: by 2002:a1c:1b08:: with SMTP id b8mr5385622wmb.35.1556869088372;
        Fri, 03 May 2019 00:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5051:: with SMTP id h17ls1111504wrt.2.gmail; Fri, 03 May
 2019 00:38:07 -0700 (PDT)
X-Received: by 2002:adf:9e86:: with SMTP id a6mr6193601wrf.178.1556869087918;
        Fri, 03 May 2019 00:38:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556869087; cv=none;
        d=google.com; s=arc-20160816;
        b=a7bbHBaJNP/ABnvqsWfVaTSJ4MdNZiK2UhEURfcaXzNpG1Aiaw/rSfyh8yLU3kfJOJ
         pkTO5LJNpM72QU9ecBRJvNiDfyqVdaKd8ApAupPUqiz6y9m8LNbMxxQW9Smkc/w65tqr
         0EYzZ73XptY39Wo6yqwrYjXBuzp7naZADU8/cYN/2t1YNSVtFgI7PEhiUYvYM8nUBCfF
         sPWciblqyORS+sdnnY8uXObLdiL0kYE+KpuLplSYw8va5TlhIUD1IYr7DUQa8G0wZV6g
         FbJzNqvIyXa2RBYT2OkfuLGHio26WDYBZ15cJtoHMKjSXBbXyPNs5YivwOhFLUYPsh1C
         1EUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject
         :dkim-signature;
        bh=22Xq3HEvd6Yru88xMDUMXzEqbO1waVFeR8bEmAMWSqI=;
        b=zFnuzmzy2lnMwchvM5QuZ9aX7aGcp5uBMdEigLN3jkI+xS/qIq2gU271dpEuIqF90w
         QvSfDoXUDmh1BUdYZrh4npCsE7VTammtvAyrO3y2YW55cT2eF0SGivChGZSLYo41wplx
         vtJ+OQwYI09HpTh9k3Qbab8dW39vjHia7DyfNyMK0A3WK/mPgw93cTwBblCaby9oKPOI
         CVOhbTLL7DzKpnZOtRVmjDKj1gzqGU1QvnwPQkvMOwS/9huJ9HxEi7Vl9FVgus571U7t
         Hqva1VR5OhkbSOupW9S/ab1xmdwEJqQ3fX6VvIB/rAd9xUIcyITprI3KlymC1KnI/axb
         2fHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=g6fjTQ0J;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 61si33931wra.0.2019.05.03.00.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 00:38:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 44wPB63Wcfz9vFVp;
	Fri,  3 May 2019 09:38:06 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id Q6TCMmlYgt_T; Fri,  3 May 2019 09:38:06 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 44wPB62PVJz9vFVk;
	Fri,  3 May 2019 09:38:06 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 556958B888;
	Fri,  3 May 2019 09:38:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ppmZKOEr5jsr; Fri,  3 May 2019 09:38:07 +0200 (CEST)
Received: from PO15451 (po15451.idsi0.si.c-s.fr [172.25.231.6])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0CA268B853;
	Fri,  3 May 2019 09:38:07 +0200 (CEST)
Subject: Re: [PATCH v11 09/13] powerpc: disable KASAN instrumentation on
 early/critical files.
From: Christophe Leroy <christophe.leroy@c-s.fr>
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Nicholas Piggin <npiggin@gmail.com>,
 "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Daniel Axtens <dja@axtens.net>
Cc: linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <cover.1556295459.git.christophe.leroy@c-s.fr>
 <867c149e77f80e855a9310a490fb15ca03ffd63d.1556295461.git.christophe.leroy@c-s.fr>
Message-ID: <5cff9551-e0ce-a2a4-989c-6b55825fa171@c-s.fr>
Date: Fri, 3 May 2019 09:38:06 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <867c149e77f80e855a9310a490fb15ca03ffd63d.1556295461.git.christophe.leroy@c-s.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=g6fjTQ0J;       spf=pass (google.com:
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



Le 26/04/2019 =C3=A0 18:23, Christophe Leroy a =C3=A9crit=C2=A0:
> All files containing functions run before kasan_early_init() is called
> must have KASAN instrumentation disabled.
>=20
> For those file, branch profiling also have to be disabled otherwise
> each if () generates a call to ftrace_likely_update().
>=20
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
> ---
>   arch/powerpc/kernel/Makefile             | 12 ++++++++++++
>   arch/powerpc/lib/Makefile                |  8 ++++++++
>   arch/powerpc/mm/Makefile                 |  6 ++++++
>   arch/powerpc/platforms/powermac/Makefile |  6 ++++++
>   arch/powerpc/purgatory/Makefile          |  3 +++
>   arch/powerpc/xmon/Makefile               |  1 +
>   6 files changed, 36 insertions(+)
>=20

[...]

> diff --git a/arch/powerpc/mm/Makefile b/arch/powerpc/mm/Makefile
> index 3c1bd9fa23cd..dd945ca869b2 100644
> --- a/arch/powerpc/mm/Makefile
> +++ b/arch/powerpc/mm/Makefile
> @@ -7,6 +7,12 @@ ccflags-$(CONFIG_PPC64)	:=3D $(NO_MINIMAL_TOC)
>  =20
>   CFLAGS_REMOVE_slb.o =3D $(CC_FLAGS_FTRACE)
>  =20
> +KASAN_SANITIZE_ppc_mmu_32.o :=3D n
> +
> +ifdef CONFIG_KASAN
> +CFLAGS_ppc_mmu_32.o  		+=3D -DDISABLE_BRANCH_PROFILING
> +endif
> +

The above is missing in powerpc/next (should now be in=20
arch/powerpc/mm/book3s32/Makefile )

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5cff9551-e0ce-a2a4-989c-6b55825fa171%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
