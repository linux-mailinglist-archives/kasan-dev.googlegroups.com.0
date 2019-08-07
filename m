Return-Path: <kasan-dev+bncBCXLBLOA7IGBBI7EVPVAKGQEMLQDCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6129E8502D
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 17:45:39 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id y130sf92906wmg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 08:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565192739; cv=pass;
        d=google.com; s=arc-20160816;
        b=oP7WKWmf2QQpMwwYyzk4rqKes9DrWkXG09ucTonFj8e3GqrFdhLBmUKrrVnOeqLgpF
         p6gHXeZsmgnr1EMCli5rtZ0a1AhZeiMsM/KhI8OmnJCzkmwsq6T5rSd5zyJ110lc5zfJ
         r+CV1wjwsCJcm3PU75KOxUQX+3hfT5UjbFM/uZQaORY843bvxY+tR5qvHv0kmjs2GmMa
         XOMQh5xesGLurAotp5g6epv4I6Uz5cUpoiA5tlFb93BgPNSF+7EYN3BperkModt0Josr
         340becWdADzecoh9s246cAiOD9LXfWXgZ0IV6ixazqHvNIlGGVaZfTeAPS11exx1L83X
         vwQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=hkO+yLtdk/qu3hnfBmlhb9iuzYJwzKbG9uxPQPrMJAQ=;
        b=mlRb4SHWlfS+efqrx6XGvrEoUF8B8kCVAuB6Iz7zpEqFGj7VcudBVvAZUyplvQhrpg
         3QuuvVAb/l0WIcOWbB170BwdpXzKTzqQ0Gpg4E03OVe08sm19w7+xNoh6gFECL/BYfit
         Q1Tni9+JCLIBN59IBogdUrYuVLJu9ccnce8BQSWRDqYqQEPi0Nw+S/+Hb12zCPJ+RhV+
         w38WncvDnMhLednJxv1v4TJk6TlmixERVmgp8K2mePU5NB4MElBJ7g3xUlq1MQYldDtQ
         WD+P7MWigPDWyfxTnv5Egc6Qev8tPNSOY4JuoLtbDTi3E6IjOTrk1Ek83wtsS/ok7/qu
         zlAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=CZnBhtCc;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hkO+yLtdk/qu3hnfBmlhb9iuzYJwzKbG9uxPQPrMJAQ=;
        b=MSbJ2/iMaO3J5gHUZXvWHsd6/2a8e9R2HUc5qVhxNo1QhqHQjlMFtAjYDrAstnUjBB
         lWYFAMXTRm6rHEICFLqJgFGn/3cR3EnW14aPfXDmwa1EOXKEwGDKrPTlTNtznd9uzG3r
         gLSgisb2BVmcS0UFHoO9cjJRvV3iFvT5a6m4lzAzTuP21a/Mw6X+zQQdMBAj48aDvnue
         Y+GiK60IjcdkIecWYLTDs0xid3fcdefdn0jw3SEgt/ssOQ77eaziCzSEgu0zxUfxPLyI
         4iiK0ugsob73V+0UpKicgQVqdscBbV7lsaLSlyv+7I312csKweFF/h431152PAdfeyoC
         udFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hkO+yLtdk/qu3hnfBmlhb9iuzYJwzKbG9uxPQPrMJAQ=;
        b=D5RZsHD4Lvt1rGWpRe1uBRXqemuwJXfo3TdcKzG6pvuinTcy2b00s91kNe6rvo4cl+
         LqM8lasUxxbRGy7IZ5BqDRYCOuKlTE6K2SKvrp3ZRXJSQ+w5gPiTp+2t8D92vzuHP2rH
         8HfjVNTNwaI9UE4in0tMoEXwzsQBq7zRDdZJeYGKHUpIfCUapUoZ3g4crpBOMswFrOVv
         Jj9JyVycjGlGZjKwBIi6hF/ir3C3gN0XciJ8luvDhBi1x9rfNn6Fq8tDYV/4lN6tSh9D
         DYptQifOFr+XEehjIsm4r/sqrnGJgmQ2R6Juf/GwjOZaVAKDE1YqdwD29Ut6s2V8EjBg
         +EtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU6s0MiPTe+f5oXf7c4VCbKQP/C4eyLoWom1/PiQdjK1OUROZ35
	rBEUNkPoODi818Ez1pRVDOU=
X-Google-Smtp-Source: APXvYqwwlBi51CFgWxjqxBqBA7hKtplL/UzK29SA9XhvmPUehJMzrisr/E4fwkBZ4ApSXoAh6U/vPg==
X-Received: by 2002:a05:600c:206:: with SMTP id 6mr548740wmi.91.1565192739072;
        Wed, 07 Aug 2019 08:45:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f78b:: with SMTP id q11ls17538828wrp.10.gmail; Wed, 07
 Aug 2019 08:45:38 -0700 (PDT)
X-Received: by 2002:a5d:4e90:: with SMTP id e16mr11531005wru.339.1565192738705;
        Wed, 07 Aug 2019 08:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565192738; cv=none;
        d=google.com; s=arc-20160816;
        b=iCSH75OTkeRiIQyuaMjo3K86B1pJtOBQw/swQEIvg5uEq8oF18BmBemRXh2SfI76FZ
         nVA7yfk65gKjtzHo02o+Y2DjLMm9u4kHwg5rMd5N/j/PWj8qikT1rmaw5Jy8UHoLG/Mb
         IzkufH4VhnrTNfqgmNuOWQe+OmzYp8kL2BYwvxp4JCQ5r6rZRy+AnxAWz51+uBRsnYdF
         JfDSEb76EZc92pO5ZmnriSdpCPa2Jj/oD3j0+KEyamPiDVA238HFcyauRKYEFxQq14+A
         asgLCT4FUg9vqPsW4hH4LjX5cuhXyEtj3Slm9d4wK11OLMfo76g/WvvfD2Si5X0IQp/z
         nfOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=2zAbkzyFY7Pds8cbijyFQH7Lyb8kWT7NvvPvhHUU+ho=;
        b=02Fu9EgheR7Y07AZo9dQ4JcQutEhHQE3lGMBckBkMMOaFZ4HtTzNqmrJSG3Fr4pdz+
         5EZNmbgUeEYIccRK5s/V4nI+XmAiOnmTJ5A8c21yDzX4fy0d9RBcpy5x2xci+Jgxw5WL
         0r2GfE0/1vtRe1NxAYaZqTJSxZbeyLfAUWmGad6XOtz1hc4TM39E1YqkyPyeiREV/YsJ
         vHgiMDFSpSF9F7zAiYr0nDZxbW8UDr97tLfLRu0soKHEQiGXik0+kEFKgrV4xD5eOHyG
         aO2gMlW/+GtN0iVWXR6NQ7wyv4sWU8WWqaDlYy+JDnXhsBxESYtne2ZUAhYu0nJcFvO4
         jxRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=CZnBhtCc;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o4si1335861wrp.4.2019.08.07.08.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 08:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 463bSJ4YGsz9v1rf;
	Wed,  7 Aug 2019 17:45:36 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id LYvJ3l9XWudI; Wed,  7 Aug 2019 17:45:36 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 463bSJ3Q5Tz9v1rd;
	Wed,  7 Aug 2019 17:45:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C62258B835;
	Wed,  7 Aug 2019 17:45:37 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id FlmSyZb7ox5o; Wed,  7 Aug 2019 17:45:37 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3ABB58B832;
	Wed,  7 Aug 2019 17:45:37 +0200 (CEST)
Subject: Re: [PATCH 0/4] powerpc: KASAN for 64-bit Book3S on Radix
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190806233827.16454-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <fe758b6c-93ec-7069-5151-a395c8666844@c-s.fr>
Date: Wed, 7 Aug 2019 17:45:37 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190806233827.16454-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=CZnBhtCc;       spf=pass (google.com:
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



Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>=20
> It builds on top Christophe's work on 32bit. It also builds on my
> generic KASAN_VMALLOC series, available at:
> https://patchwork.kernel.org/project/linux-mm/list/?series=3D153209

Would be good to send that one to the powerpc list as well.

>=20
> This provides full inline instrumentation on radix, but does require
> that you be able to specify the amount of memory on the system at
> compile time. More details in patch 4.
>=20
> Notable changes from the RFC:
>=20
>   - I've dropped Book3E 64-bit for now.
>=20
>   - Now instead of hacking into the KASAN core to disable module
>     allocations, we use KASAN_VMALLOC.
>=20
>   - More testing, including on real hardware. This revealed that
>     discontiguous memory is a bit of a headache, at the moment we
>     must disable memory not contiguous from 0.
>    =20
>   - Update to deal with kasan bitops instrumentation that landed
>     between RFC and now.

This is rather independant and also applies to PPC32. Could it be a=20
separate series that Michael could apply earlier ?

Christophe

>=20
>   - Documentation!
>=20
>   - Various cleanups and tweaks.
>=20
> I am getting occasional problems on boot of real hardware where it
> seems vmalloc space mappings don't get installed in time. (We get a
> BUG that memory is not accessible, but by the time we hit xmon the
> memory then is accessible!) It happens once every few boots. I haven't
> yet been able to figure out what is happening and why. I'm going to
> look in to it, but I think the patches are in good enough shape to
> review while I work on it.
>=20
> Regards,
> Daniel
>=20
> Daniel Axtens (4):
>    kasan: allow arches to provide their own early shadow setup
>    kasan: support instrumented bitops with generic non-atomic bitops
>    powerpc: support KASAN instrumentation of bitops
>    powerpc: Book3S 64-bit "heavyweight" KASAN support
>=20
>   Documentation/dev-tools/kasan.rst            |   7 +-
>   Documentation/powerpc/kasan.txt              | 111 ++++++++++++++
>   arch/powerpc/Kconfig                         |   4 +
>   arch/powerpc/Kconfig.debug                   |  21 +++
>   arch/powerpc/Makefile                        |   7 +
>   arch/powerpc/include/asm/bitops.h            |  25 ++--
>   arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>   arch/powerpc/include/asm/kasan.h             |  35 ++++-
>   arch/powerpc/kernel/process.c                |   8 ++
>   arch/powerpc/kernel/prom.c                   |  57 +++++++-
>   arch/powerpc/mm/kasan/Makefile               |   1 +
>   arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  76 ++++++++++
>   include/asm-generic/bitops-instrumented.h    | 144 ++++++++++---------
>   include/linux/kasan.h                        |   2 +
>   lib/Kconfig.kasan                            |   3 +
>   mm/kasan/init.c                              |  10 ++
>   16 files changed, 431 insertions(+), 85 deletions(-)
>   create mode 100644 Documentation/powerpc/kasan.txt
>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fe758b6c-93ec-7069-5151-a395c8666844%40c-s.fr.
