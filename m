Return-Path: <kasan-dev+bncBDEKVJM7XAHRBPWP7XYAKGQELEE24GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9063913CD12
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 20:27:58 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id be8sf12100340edb.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 11:27:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579116478; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uj/wd9LlwqxYn5AuEi9tSKb1rJtcacmpougJFasgzsXc8hRrL+yaNf+y8Vwee3DJbX
         kymw4efYzj7rIAdbFvl6PdrN4JrAAoT0Zgl+BV+DFmP+3YEm6gxWMdsLVicJ5wLTeIWI
         P+USVND7i8dy1A70wo+7a+WeVkoPzxXFD1ueUkwJp65NuyHvZgftYw8DtEykjIaprP5G
         ZZcx3oq/JpsHGUscImb4GzNCTuMaagKMdRjuk2u1gDnqrtrEj7Dt1LT/Gq6HwW9rlX3T
         GNLu5YdGhY1BONHej1CY+Whe0ED8dxx2le6AVpdopkdMvr18jsTCbWCTQ4RNcYpwqGmt
         gYkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bd2bOkzGxSwm0Y3mT1GXjXCyDRLKMu1CrYIgqPqyHRg=;
        b=FFWldHcFhHT1Zy/PhpC+OeK6d4eJjFTE4NmM973e8At/QGfDpVo4h0eZpDhJH0s5mK
         Gslgshm3By1Zd8M8HvInw/YiSuPCiBxAvV8VcEmoQPkFJLnvLn5RhRNc4/Zzizmc08ud
         zfs6yi1FhjrTQnGtlwCrm+g83FyfswEAuS2hnx9pH4Xlgu8bdvC57t0ypQb8NWHx68Q8
         6w7uPlJb6fvxO0cn59X/Qdt47oE8JfU2vFQfpw7QwKyLMsd4+pI0xF0BRy6VwV6R+tLr
         JQhdYchONJGRlq33cKKbZR7ps3i8MpUakRw73v4mKFahWBPrnGC8k17HiJNXk50m+97u
         NN9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bd2bOkzGxSwm0Y3mT1GXjXCyDRLKMu1CrYIgqPqyHRg=;
        b=EyvCBrYzGTwYTvi68f0Q77lh78kQonhwAmE6p5Ow3tJxYB0lvijA1tJhlHmFg9KjkM
         OI3+wl3wXV+tC+hgVOF7ksynDxrr471dodtEvCJH1josFeGWN7EWD3dgc38XB6ZQ61js
         qbSionWRawFHOQVH1D9meij62Y0aETwmd9eGj5eUozrBNT25bdUQlC6X9/o6Xqd5LycE
         KJ23NURjS9mzbxQ6beit25PeIvPORARyNh1ZmrjbCbEU6ZNyHcxNHH3wvUPPeXCnisxe
         HirCgfmtDakro5VG6KZyqCfvAo80otlgVXBBPc0iHK+Gxt5rI63qo5Ybuyz98hPDZmUR
         FruA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bd2bOkzGxSwm0Y3mT1GXjXCyDRLKMu1CrYIgqPqyHRg=;
        b=X+FBkJ52U5vvX7sCCLTjLcrMHKPZGu08sAyAGAvNbr6ESz9twCtFAqId29iMcjmFby
         ppggeNZqGbW2RMWDhr0s04TvKk9xp8m8diRhy+s813f6L9cAtL0ADaF4KYcuBObu5m7e
         VVS2RNBtWXP0hg2qmsuCl48+clVwDgDIM5Fhw7ulHjhGrBmupklXS+rCQm4JMtF6qpyA
         TKKj16p3XOfeu85JQQChxXy3t6ONrbvBIuGdB/yzJOUm2AC7r566d+ISSKcLoRt4fJwW
         zjs457jXmJyf4RHc88UIUPwXfHd4bRUZyHxZ/Qrr1i++paiZmhHqyusTfLN4/YUJiWzD
         TKqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUq3D1I6gK9b8Q2gY7N+HrQhXnwNhJffrJdMvflFcqYCRlSu2Xb
	rLZaIyfe6qCzii7jcoWa0SQ=
X-Google-Smtp-Source: APXvYqy9mdvswy8rGqxao94WuUx2eSOu42VDiZ3Uqv9UD2jJ9V00UN6LZWA589BXZNHoC8bjBaO/4g==
X-Received: by 2002:a05:6402:1cbb:: with SMTP id cz27mr32138073edb.227.1579116478220;
        Wed, 15 Jan 2020 11:27:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:f01d:: with SMTP id r29ls4485104edl.6.gmail; Wed, 15 Jan
 2020 11:27:57 -0800 (PST)
X-Received: by 2002:aa7:d145:: with SMTP id r5mr27849243edo.337.1579116477765;
        Wed, 15 Jan 2020 11:27:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579116477; cv=none;
        d=google.com; s=arc-20160816;
        b=oDC0ALhOrRFnRnYCt2ATpcV9WuWlkCkqDsqCTYUa3MP+f7Su/AOtf7C9qcqGtC8mtI
         +hdvEgsdsedNJq5LKbuvQdHHNhmAtH3n1LUtH4F0+NqYmBraqjH9+Hlig04Xc4Q0yxNt
         2EUCjp5emDjxrHFk7HO51xYe1Mx6ZgSz+We0JWNQdsVMHu1otX7bcQeQguolyTtllq3J
         qGnWog/Re3Bs6ktxgDOkv91h7kQw5PVRSLlqkH5O0lnmC52Fk73rCWUCxPTgoXjYrHxu
         DqcBJ4CnOLyf3TOQcgLAUNUxT6OEUngHYaKzCUhkXNESOAdVdLWhfIDllEKGy00azR4k
         bzWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=VH1H5lLIV/Al2+yxk7HIqoJUzIpfeRi268eijxl8GqE=;
        b=zqY7VXUGn4my6cfcQNrJNR5C4Bh8aTSmf47eqP6KWMC2a8ntxKKfa9W0HRcVepVfCn
         D57ZNPE8gx1B68ciiazKW0WK8+dNzpF9h2f3aRcIIVGpcMV2gZcY0zx8pRPbMhN7L5Qt
         KWw7aB9cwTLsvGJOx1LshXtzL/1f33qtxy3bmmqQg1lEzrLmYPKEcuOVKNtp1cwvBr58
         HPhvIYlGIRS7crpj4oQs5R/u5JFZhiWDfgtTQGxucMRiqcmB+9KuDpOJageK0x0U+/q/
         7tlrTBVMV26LNhiGu1twudUkuHvnPKgrIKRQT+ORoFr4VZIHdvk31uC4ALl/8z6gU+hH
         kQ+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id w19si876407edr.1.2020.01.15.11.27.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 11:27:57 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from mail-qt1-f170.google.com ([209.85.160.170]) by
 mrelayeu.kundenserver.de (mreue011 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1Mf0Ru-1jK1Gp0Wny-00gVME for <kasan-dev@googlegroups.com>; Wed, 15 Jan
 2020 20:27:57 +0100
Received: by mail-qt1-f170.google.com with SMTP id c24so6011671qtp.5
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 11:27:56 -0800 (PST)
X-Received: by 2002:ac8:3a27:: with SMTP id w36mr186613qte.204.1579116476026;
 Wed, 15 Jan 2020 11:27:56 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com>
In-Reply-To: <20200115165749.145649-1-elver@google.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 15 Jan 2020 20:27:39 +0100
X-Gmail-Original-Message-ID: <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
Message-ID: <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:JRrYfKS6lt0p+IeFZ+JsHQTKknIYFbwuKiNYNeDL8qMoXu+j7/e
 a0OQhEFle0DWnrvseaGeIBcczxCznAe52OUWmcgHbBwLkQYnAvq0YmYTSyfqrtbPQ5Jzn3e
 YA1VB53/rIB421IfuqHnKbFHBSdWmyd5MmkiAYNwRSC8Bzj5TPVt4vM6+N69fMYEPt0QB6/
 1/66tkUuHVco/YY/G0wmw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:8ldYAdu9ZJ4=:CdvveY+BV5BU7OPQaSuCoo
 KVKYq/jOUmk03z4A9TcLZcqc9nwdpVt/Cb7rfxjZP2EvSNknM6y/T5NQusEPRLKgEg980J7jf
 xl/8OOVusp5FKh5KMz3Ji3rz82pxNl3119e4X2F/QTmLWvuo/NWMMIVPvuRkp2dDmfB81Q6Ae
 V8htUFUGRHDIfHnqL6pFJ2QrnmlE7QINNri4R6qN9euU2m/rxHsl01ohUDZfTChMvtyB8c7+1
 V8dQqjzYSj2TLqaeYYBEtNUpmTSPrQAHgpv9oGuSqBq2E4PJWia8syk4bV2g7nCGW8tB3JJ5q
 HuL1+O04Pi8+C1rUPnW3/F16IXY1w/6nEOG6xvvUPhyJwkVgBCgCskISWTuW7fM8uCd86RsYN
 mlQVqxaRNKV/abMxGgOhRjSIGgMKNZwn2//uS4WBa3NidATbDEgg/Vnz1O/RrbNmhiUaqu3nc
 fZmTvojyfVPDb6nbdN4Gn4OKxL3WaL+Kk+FNAv6EIyi/8K9kOfQSTotzaDOW9yauA2hVr4NnH
 GJe0r2LscmYEJq7lpHTm7p0yFOoog09ouc6QRvvAamtU6F32j7bIKNHDrhd0aNt+cOadS4XUu
 C7iBAtUw4JfFz8qRa6CNLrW/9CiKVBky2iAm2w6VGoE3/fr+kgi6QjWglspY+zSnawTMUNohV
 y/uG6ZJ6Jy+FDgJlq0uF/sxMWY0nC7/HTE5ghq0jvQBFxqC89aLv8GvDDW5ny+wGgRwizv+dy
 qJSkmNS+bcAXdA7Ky8n8+9BI0GHpRDnPVwfu5OSr+MNQgECCB89xGr6KS9iFYONAYUp2rbthf
 B4X3Gvb33sRNCwhDHr7k4X7vUhqiPbG+WnYLeaLRw18UH/sxpXeRF7ZX1/6cUtHW7PDDG/Jq/
 kkDsC9zFcfx7sPNX0XKw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, Jan 15, 2020 at 5:58 PM Marco Elver <elver@google.com> wrote:
>   * set_bit - Atomically set a bit in memory
> @@ -26,6 +27,7 @@
>  static inline void set_bit(long nr, volatile unsigned long *addr)
>  {
>         kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> +       kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
>         arch_set_bit(nr, addr);
>  }

It looks like you add a kcsan_check_atomic_write or kcsan_check_write directly
next to almost any instance of kasan_check_write().

Are there any cases where we actually just need one of the two but not the
other? If not, maybe it's better to rename the macro and have it do both things
as needed?

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3b%3DSviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-%2BJiQ%40mail.gmail.com.
