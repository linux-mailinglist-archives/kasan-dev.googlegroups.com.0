Return-Path: <kasan-dev+bncBDLKPY4HVQKBBDFC57BAMGQELZCKITI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B287AE7F92
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 12:36:00 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-32add2506absf31847641fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 03:36:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750847757; cv=pass;
        d=google.com; s=arc-20240605;
        b=kAn5oUop5O9g1VOUJbC+VRuFn3qcPxBZEQX7WSe5NVQQUZcQcLMB23NcJuSCRZQVCe
         wmQAKOnCdXXsWw9xviisbjg/E8ZRHH23n7jXjz0Uu9pvXdj/dKbKykTGu9U+lw9DNhlw
         Qx0WmxhM2Nrt/oqhW1U2Vex/HsRmSzuqhyLPGF7UhWOzhyQZytOfZ+6RUO1sJb5pjrOh
         nnU4qAI9Bnoo0AC0vCGKABug0U/SaCofz2UeQBhYn5cRk9fXGMXTxp4lydvUyu+lABSR
         7GYhaS4KMMXSDkNuBGBejI5C68AJZfncUshWV7/KK/n+nTwxRbP49r6cWhsxYhdOPfIH
         1Q1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=bJKQOhJbVyrt3gGtwlqwYlzd3dNILhuCAHPHjzmfFp0=;
        fh=9H/HB342fzZ3W0ST51xOgFgu7lRWPKMfsrJV4c/4Vm4=;
        b=W9VW8OjD7EJS1NR5EIwNai2Als1Re4YTPt91Sn7XDdzgHaEPHqtL0FbxU9LsJadf4P
         yqB8LLW1J/6X5NiwNARQJNR4fnXB7B93gwgiBr/evZPhdecys/P6WyzH/DzARROYibM1
         E8Ped025D8G0mqNjzkyBhjR1M4SNEFTMr+Fon0fmhWoLmISO8S9vKPqS/3yb84C1hq7h
         F7kxKOvuJO1p55XniT4IDioq9yyom2cFwHVClOEx55AjolOZGyFBibUdmzdQ9h0HRUQk
         wrIVYpLcsNEa0v4HJtL+9KHJwz3+B9VTdPP1W2nTlS2bBKlNt17tOWhGzxYCLetokurR
         Ysgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750847757; x=1751452557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bJKQOhJbVyrt3gGtwlqwYlzd3dNILhuCAHPHjzmfFp0=;
        b=jx6UWpdK1ZKSTX8kwj0Dd4sDXge2y7CefR2fiiOto3hcVIT9PP7dxWtRG5GccNEnDR
         E4brUaW9GGyTYJs/PCHjGijpvTYF6VaU3dYLFIN1ZzqriYUuCDPldVO+Q4/Ys/RJb66I
         eVoU8W/Odz47FI5+2V4sxA5RzdOCkMic8gyLLIyY/mG+be0450JQIUlPvpuP5DkzpNc1
         EOHN/EkYSvVW1RE5t15Otz+Cpej3tKJZ1hLwOAqnZLOQYDldVbrLGTQvPsO3+ahAlGRF
         Umms92nOahii5dpsQDZYvOj+Bv2QdsOyrHC0xUJs9ItVVWixI/koiY+B4ksTH7foiSs0
         ClMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750847757; x=1751452557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bJKQOhJbVyrt3gGtwlqwYlzd3dNILhuCAHPHjzmfFp0=;
        b=o+xUKW9PP3ynyMgXq+S/KTlqrd25QNR18CISCVOi2xiNEZOVDzNdz/iBW9RC2sIgWn
         6j6CP5kKo/ntSyWr8b1KAw74lVAz4r7RMLJxOZ5ERW4ynIYvL8/tJkJa9086TOA9jVbV
         J0uvZzQR4NyQc9l5qpwFBMY0sqJLGrhLvTWkE33/8uiEjMcONw5GVUA0UNudGrtuwtV1
         X1JZeQ9Ok9y9pZHtueSi5UdBwZQd/sv5LGMPDjtwwr6s1Ap0zVnKE/cNd2EDQUXlN7O5
         g/WgIrtAye3A6vuR6jjepZH+UrTt5gC6NLZ4qrqaeq3InKukmwVUKBc+s20qUarXEsop
         w49g==
X-Forwarded-Encrypted: i=2; AJvYcCW6/hfHwJT1rxGeaFmbecStDNI8XBvAeOwrD2AfhmVEgEZJ4/4S7d3tasqnEz6/FEgiTq5bVg==@lfdr.de
X-Gm-Message-State: AOJu0YzMzooez9B3X4ZV8YsgEigGnyRVRnFvjAPO4DRsn1kLJ0tbzyoy
	P3t9exBtOwVM1TJvDRjr8rn62iuXDpuDeGZi3eLspqOMkxmyuwqzV2kg
X-Google-Smtp-Source: AGHT+IFlXtW3Zg/CVAEVxrFPSw3yB7neDNDsGExexCzKJQzFRkynkQ8u3rcRdmJHc3zLGj2GQJvN2A==
X-Received: by 2002:a2e:7806:0:b0:32c:a709:80ee with SMTP id 38308e7fff4ca-32cc6582a2emr4392751fa.39.1750847756793;
        Wed, 25 Jun 2025 03:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmcxgri+JaGBtSgRllnQ/cAY7N5Ihx1QYI7p7yfRbV9A==
Received: by 2002:a05:651c:2106:b0:32b:7db5:4bf9 with SMTP id
 38308e7fff4ca-32b89863cd7ls18324061fa.2.-pod-prod-06-eu; Wed, 25 Jun 2025
 03:35:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUv37tXMA1kgie1n5xc/VDF7oQM9ndyYTbMNeT4lZVv0VuCJD75eC1kSem8VAyiSgAJezK6KIVZdNY=@googlegroups.com
X-Received: by 2002:a2e:8846:0:b0:30b:ba06:b6f9 with SMTP id 38308e7fff4ca-32cc6522b7bmr7152391fa.26.1750847754282;
        Wed, 25 Jun 2025 03:35:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750847754; cv=none;
        d=google.com; s=arc-20240605;
        b=DQXNzO4SHbd/F/RRlIUkw1BvGPA309+1qTyTBLgzKtGp3XE9vJc8p5BFeNW0yVEi89
         2cm9bHWRoyeJygTqruSsoT56pGj2EkAhTmrB84IBYY7ts1lPb+UqokMkTxMbnC1Kciud
         B9EgO33RrBxMcGpoNwZGXl8MtEFvvRexknDibbrSc1/OEdJJNmunzi48q+ZpJrcmhVPn
         JCFHsCT5Qd10FG5zUVXpGcpkOSF4lKRR+qiwireFsMZjn6RElMFumKatQMk/BHWuFh0U
         ZdBESzyJuTIoAxd+i5K2qzoz0thMPm9gDzaPtSMhFRwpddDVmffiDvMDvk1L4ptQDPUc
         jZvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=3a4sekYOIoKPTcsxrLRc+zk+wxz53oyg/zv9+AP4v48=;
        fh=SFdHZR8zxg6TEbE6MgAXQj1yZoKJ36rM9pB/hubh7sU=;
        b=YuxZFjQkSKOeWxQgJ10uHzJY6gAoiYfis1LPbTj+PoaKo54PM2VQ2V5RVp2zTORR3n
         WubfNnb1oOUgjBMK5Bz9Gm/COAcrc9h7gV81aq5AysdyKZvrnz9Xp5ipp4O1+ipzNi1h
         /PylzGH8FPUIWNsIjOggwMGWR1OOKiJZykrEEKovsEX1Ket1tMt6pBu83qsMWcMRLlx7
         ZquPZwZMcFFjcKtVodnRNb227GFAnr7CNIN4+nU9ONxC1RP3SVCaLu80YQ5CYdg2dk5j
         v8YNfgraoszla/BQJrIMn97Dmt/pH1IqUI5QjMD5A3939bFL0en0DpVpMizFjZF0VaLs
         RBNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b97dd0a25si2888771fa.0.2025.06.25.03.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 03:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bRys55D17z9vDH;
	Wed, 25 Jun 2025 12:35:53 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id E-qPa8r-zWGB; Wed, 25 Jun 2025 12:35:53 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bRys54JGWz9vDF;
	Wed, 25 Jun 2025 12:35:53 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 87F7D8B7B7;
	Wed, 25 Jun 2025 12:35:53 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Tp4ps0JWzqlx; Wed, 25 Jun 2025 12:35:53 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 942C38B7A7;
	Wed, 25 Jun 2025 12:35:51 +0200 (CEST)
Message-ID: <db30beb6-a331-46b7-92a3-1ee7782e317a@csgroup.eu>
Date: Wed, 25 Jun 2025 12:35:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/9] kasan: unify static kasan_flag_enabled across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, catalin.marinas@arm.com, will@kernel.org,
 chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org,
 tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 kevin.brodsky@arm.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250625095224.118679-1-snovitoll@gmail.com>
 <20250625095224.118679-2-snovitoll@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250625095224.118679-2-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Historically the fast-path static key `kasan_flag_enabled` existed
> only for `CONFIG_KASAN_HW_TAGS`. Generic and SW_TAGS either relied on
> `kasan_arch_is_ready()` or evaluated KASAN checks unconditionally.
> As a result every architecture had to toggle a private flag
> in its `kasan_init()`.
>=20
> This patch turns the flag into a single global runtime predicate that
> is built for every `CONFIG_KASAN` mode and adds a helper that flips
> the key once KASAN is ready.

Shouldn't kasan_init_generic() also perform the following line to reduce=20
even more code duplication between architectures ?

	init_task.kasan_depth =3D 0;

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
b30beb6-a331-46b7-92a3-1ee7782e317a%40csgroup.eu.
