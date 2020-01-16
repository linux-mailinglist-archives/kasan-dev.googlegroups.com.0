Return-Path: <kasan-dev+bncBCXLBLOA7IGBBD64QDYQKGQEGJ6BQHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D9E4F13D6E9
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:34:07 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id k18sf9096501wrw.9
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 01:34:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579167247; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nxs4v7lwvvAFeczS8OSChCnQqNuRoxL8Jab6QNiIRW2+U9oaU+okk3CLgMyCMIv1y2
         gZxLmz3B3QW0c/N0x5Lrro6iCMD1SweO+M1v8QNfA+iEt2YfqgO0DpF4hBK7en1R0+af
         07DeMhJqi9Vx5UZAQcWk7neUuu/DQxr7+JILWmKbJm7PF1ig82+0iVVgh3LvjZljikG9
         ipX07CoKFJRYl0dnTJBTAhgJxnPdof1AtBopyR5SjuleYpZiYixvIeNua8gC08AypcQT
         Wvj29be/YcjEbocmIyN+C2QeBKirjv6LEXvGxoEsFdOyrMFCOFmuv2HSsbBnWlzXmfov
         ZfKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=zg023AYHVuG9B7A7x5DrehCNYKLxRMql5wq5kpuRkm0=;
        b=UbstKge9FB8OP7YQJpBJFeFLxnw7LJFWO0s4Z7vohkVGV6Y9BLRfEn9xnagSbnhPOu
         48zGxMLDtmmK45JSd/HRo9ysnD1fTGno/s6ATfWt4r7SQjBJY9uD+NsbzPVfXjkOgX53
         NfsyZ+5u0dk0RTiMQI8hKoWB8EkIeIVhUczzF97xz79a53m8C2f79Td8K1ynsc+ygcVs
         MkgyUyoTf8PaAAikZ+cpfCpgnV+eo7Z63W7fXXu2Ng2ATpNQ05GABbzqbtP32EYY0tJX
         228d8V0sjBp0GWnkANs5D1W5fKJ1HB+OM2qkHZl0OM8Zr4vaI/joJUreeWUlQ04Ld+TT
         2aYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=bdDCDEzJ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zg023AYHVuG9B7A7x5DrehCNYKLxRMql5wq5kpuRkm0=;
        b=XlZ2OJQS+CWz/g5gPDmeYxBV0TJictfAb3uBtfRPleUdFW3OwynWxnPouD6WEpZU4+
         oJkeKyXSIs0x7yeeFVxSrPVsbD11AxKgFu9LPBJFaCJqPfh5pYtHsKXzeS+L2XVMhxRB
         Y/8dtsX/nGt++qP3Oe+eTeCfppwTwS21TSyxu8w/FAoZqv2EhlY6MsMmJ9gMOceTOLTl
         oqNqPquonNQQaIcOwYvusnxL7B+CGwwOB7vUe1R1+w/7CxMKBqqTlOnCzH9W6l0IFMUj
         XokPHgWABTG6iR67MgZsFdaW99M1mUgBxK9bgho9I9395/XZS0HdXmOcyU81aC1XpxAS
         nWHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zg023AYHVuG9B7A7x5DrehCNYKLxRMql5wq5kpuRkm0=;
        b=LNPtj1JRuHLM6H47/zJbZetePqzA3tljLjx7KXgFlmszxITkhJ8bGij+5Awo5B+7Q4
         o2CRRc7Pn6rxxcJj1MLD/aM4+UtwNVGbcsv0OWdHRHK2/6r9lGNIIeucisb5xbZOhLJP
         c2VQ0/wMu1M9Pn+frOt1rHxlbMdEe9qNLPpanWQYWLmkqQxcSaqUS8SD8EIGZgKo/aRL
         0PcWt1Zil4Ow/8mjoL0vJCZezlGSIvzc36s7hnO5tt7xU67kZ7efsKwRQSw/EONjbDrB
         Cqho3rP6IArhhWs8Cgi9a7uXM83/2ttRvteaxhus+cn4/vVlRcUPbGQajuD9EHXfjYQK
         fFCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVyNCKk1q0Jbci0t1CAoZaXLFRPP3x9KvzXIpIH5e4o/qgXjuX
	RztKSSK4xDWK2HJoXwcVrlY=
X-Google-Smtp-Source: APXvYqyEO4hn8I+MIs62AnJGoFG7ft6JCStcU/pd7YGyBwxVoC6x2H38Zc3nB2G50xacKlDQnQvpwg==
X-Received: by 2002:a5d:5267:: with SMTP id l7mr2431594wrc.84.1579167247554;
        Thu, 16 Jan 2020 01:34:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9808:: with SMTP id a8ls963215wme.0.gmail; Thu, 16 Jan
 2020 01:34:07 -0800 (PST)
X-Received: by 2002:a1c:81ce:: with SMTP id c197mr5152595wmd.96.1579167246976;
        Thu, 16 Jan 2020 01:34:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579167246; cv=none;
        d=google.com; s=arc-20160816;
        b=FNszWwPNItoEYvEYH5SdkhSgB14/L5wR86LZrjA79mI6209L8Gqh5hfOf/nMOnYY6x
         c8tD2NuM7uEMeaZCEucBcV1fnbZdJXUltMvAM+5EI9VVygrS/7dMNt9ZlcbuLnoXjtfp
         EkYLXrDz4lkBUZtHSmGl0MIH1VTYAfutUKPJFWq0a/V7WQOrab3ndV5MI8XtYHJEeSAK
         cOakQuFKbSSWTwmM1z9CEPkQttlcKlSG5+91njtbq0uLSfkEHUgQycgPuJGj03gk+s1H
         IgYzRcdDSKRj+4hqZTkxZ+UYkYpsEg8SHYzSUSb+dWi8/s7DyVu1Vx/qXM6QPHWEYpsL
         Bj/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=IEAXhb+SjJPqUD1Zb1vn+3GKKBJH4VCJ7C1isv48Ggo=;
        b=FnHmSsGkei+6qbk1oWliIQw0kSDEY4tFi4qxurhyKcJ+69oZYngdqGNCWZQGBZEzZn
         Wdxye2jAY7s9ZoyPZtbD4gjSRFsPAEGn8PNZNMEaJqj3n/JmnwKadF9WVid+2B6c6FDk
         1FgWYhodxy46bYM0wLM1Kk9PCO8bxdBtrWeGLyggC0yqts+kmCZe5kMfwzUHG73PXibZ
         8qCOCLu+RNbGNYMPyI3817ZehrgnuyXi8Oe6wLQ1T8lN7ctqDif+REkzsoMdnuJAG263
         xBhkbzcbE6kDLSNc0BNmjqFuhXG0ExyYv+vL134EJ+tP7G6DP6aEBYgK3HDk6C8qwunH
         Df+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=bdDCDEzJ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y185si260631wmg.0.2020.01.16.01.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Jan 2020 01:34:06 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 47yzXs45Nbz9tyQL;
	Thu, 16 Jan 2020 10:34:05 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id U8nIyqefG5v1; Thu, 16 Jan 2020 10:34:05 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47yzXs32ysz9tyQK;
	Thu, 16 Jan 2020 10:34:05 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 7E9CC8B812;
	Thu, 16 Jan 2020 10:34:06 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id CZ-uRnBuwtrT; Thu, 16 Jan 2020 10:34:06 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E40738B810;
	Thu, 16 Jan 2020 10:34:05 +0100 (CET)
Subject: Re: [PATCH v5 0/4] KASAN for powerpc64 radix
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20200109070811.31169-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <8a1b7f4b-de14-90fe-2efa-789882d28702@c-s.fr>
Date: Thu, 16 Jan 2020 10:34:05 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20200109070811.31169-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=bdDCDEzJ;       spf=pass (google.com:
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



Le 09/01/2020 =C3=A0 08:08, Daniel Axtens a =C3=A9crit=C2=A0:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>=20
> This provides full inline instrumentation on radix, but does require
> that you be able to specify the amount of physically contiguous memory
> on the system at compile time. More details in patch 4.

This might be a stupid idea as I don't know ppc64 much. IIUC, PPC64=20
kernel can be relocated, there is no requirement to have it at address=20
0. Therefore, would it be possible to put the KASAN shadow mem at the=20
begining of the physical memory, instead of putting it at the end ?
That way, you wouldn't need to know the amount of memory at compile time=20
because KASAN shadow mem would always be at address 0.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8a1b7f4b-de14-90fe-2efa-789882d28702%40c-s.fr.
