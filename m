Return-Path: <kasan-dev+bncBDLKPY4HVQKBBV7FVODAMGQEVAZXR6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BED33AACDA
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:59:36 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id p20-20020a1709064994b02903cd421d7803sf1752863eju.22
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:59:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913175; cv=pass;
        d=google.com; s=arc-20160816;
        b=SuXnE6oY9tW8dCvWwO+BlNQ0w9c4drwU5R4R9p3+uFJip57KrJdqVyOk/PHDGRcP5J
         TEW1MbctFXXNnaHSB3iuzLyjaKNWnwrzwbKLNAJznYYkOAiH5RMEMmvobpT/pj5mzzH3
         N49sYjQ2z47bhLfC9Bu118c5uDzH/N3ce6NGQnu2/AZn42UKr/Sq5w4vLAAnCmIDBwR6
         pR7fHqqY4kW2PxFUnZndlVX3TlSKc6xgXBJCPPoaUq00In16DyzNKwsuU1LZLmJ7rh0I
         HcB1kr0R4FuQ9XVyPvRQTTvRtcIoVDTF3/lgmSjZnWXHQG4CatukYqqIHjs/ADX3aZhU
         l6cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=RJZn+/hwKL9E9y8OL0d6W+cufhMqgFZDz/HM89CIyIA=;
        b=hOSkFoA05vJHltHFgTNlCqlU+1F6Y7IYT/SiL/mNht95Y90kDsSXlZucQf+YdH6oDM
         /G1SO2kqJs//flqT+oXRLJZbwNvYQJCicFG89eAjyBnpnxLqRWq1yJ7ZZSmbZ195IKXa
         cLtE5pdx6+l8ejWpMWq5ngo9ChwhVdntC81YmwBH1SOXEYmLpASdfsNYNjUnUPEQkO3v
         BFZAldIGsS47CmYl/1d3hAPBq+pOijzNDQY+A5sG52vXX3b6Z9bfwcLDqk8IeJfjU1c/
         eapjzewcbtY9EkRtia+MLWzm/cC73hkf30+IHdXtzclTAOIUI0fNH+VmFcA1qaKhE+2V
         dyRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RJZn+/hwKL9E9y8OL0d6W+cufhMqgFZDz/HM89CIyIA=;
        b=iAlltXAkt1D2d2KqabFE7BG7aUIBr4VUcLGW1iMior7mKPut+LpT+LUuw7ydFnbMw7
         iFUZaTiCTOvMHlOpcC9zCfSn7xj9Cv5GUhA9nRAirEE1QAVnXiRQl83ClhkWcqR+cYPr
         /YjVc1NvkCMa6yctc2fw5z+Aih0TM0HoExPWKIzGk8wiM9C8qikajBDET74iOJaBEJs6
         z1um6Yew743+Rt/VaQYzHpTd0Rrt4Wy90rAkPgXwCHmxtq0hrIEzGDcrS/TMYt4JoQDv
         N4oOklF8+Ss3szLW5IoXw3CldXQtgEtX25xCZt5cbIjwyZJY9FK8V4Ok3KRcyNgw5wn2
         6oog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RJZn+/hwKL9E9y8OL0d6W+cufhMqgFZDz/HM89CIyIA=;
        b=LYbJOCDXxOaENjbPGDmgOlSl2y4hiSxF2gNVqN9i3RfJ7wEhDOLENdT8LeZyBKHSQJ
         yx6gW+pt/5vJJNMlrTfodzh2dIWYyXHTN2dBhmA8eLIV787WfUWUnihBqlKWTdkPebHn
         xAIAnJ4oi/HIVtIIOWZS3s+NH8rvgpar7xtD9MD6VE/NFvsMjvekO6nQ6EPONYoQzOHA
         C84EMaS2A9etFFiY+pj7aO6TeAGE0ZTVokPBA2Y6ZeP0cVYnX4THDw1bte6QGsUXZgdt
         PGWXAzpVMijbtaAaQliJILe9htzJbqcYfCEmkQ2d1Rkgxf9s2EOIVg655GiovRdizMne
         VudA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530pbByG/FYQ6cbPk+nGsb78Ocwnj8vGDzmTimH7BR2WJ99Vrrxo
	lv1Q5p2VVG1VCdpK1G5bC94=
X-Google-Smtp-Source: ABdhPJwej0H1M/wF/CCDVA1XL4pXNfLgM0oKf/CIyJLXrsNPKHL5/FpFVn9f9wPEG1ugZxxFeQZQUg==
X-Received: by 2002:a05:6402:35d1:: with SMTP id z17mr4558147edc.159.1623913175825;
        Wed, 16 Jun 2021 23:59:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4404:: with SMTP id y4ls1967028eda.1.gmail; Wed, 16
 Jun 2021 23:59:35 -0700 (PDT)
X-Received: by 2002:a05:6402:35d3:: with SMTP id z19mr4510737edc.324.1623913174978;
        Wed, 16 Jun 2021 23:59:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913174; cv=none;
        d=google.com; s=arc-20160816;
        b=SXwV0Shp3BeSNekqA3s4iuNpkyG5bdRjA+T2P4qvLMDxf+aACjz4aEGq7NWTDxjqzm
         wNloEdLnHl9i1OLl5VxPlfmzsYjFDqRt3CCebjwHyVqe9ljk7tF4r44Ed5DSNh2OiuO1
         yn/XEwhuhD6wF3t4fSLIdMoiEw8kYhKdjYykl46wSGRfqkezjfSzp+G2srXm8DeGZXAS
         9aaOMS7O7Y6+7pvftBYYX9VX75+1EcucKnnYvaixRwNmSK7YeCrrtP947AHDibXJCO39
         o+k5O0pLT5Lq+5lfQQltuWTHRePCsBNvWhRHa54rZY8zN9YoMj4LRXs24J7pTCnqb1x0
         upJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xGKpZoUiCg+4J1O0HFNDsJ5YrKRqa+OSBm6eVgOZY8g=;
        b=W2iTM/zg1yC3K2NSuijbzbM0A9xCJ2RDhEnDRRRBnRPPF7A93iRgwMtPXXE9VFz1d4
         KAScSL91ztDBNmWbi5G3HeB03YSM4k1qi93FfiKksQmIJR6ejdkBvK1+PLbtkZk/FC/T
         pDpq+dFOVJ9ryh+zvsl5tS+XBn8v6ld11J1R7cz2VJxM6RpcnbhtvLDEQ5vHe97qo9zy
         rFwAj1K40XP0EDFqgGkYNPWwxt0HErZTuI5ErtGCIZihDKdz1qAK3Si/A4q9m09HThBK
         w8urx8/imf5BQfSkVkr3U966f5LkpzWYgpt7G+ZYss+F/XOesBm0xquqSpke0MToGGdX
         EgwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id s9si226625edw.4.2021.06.16.23.59.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:59:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4G5CbV4X8kzBDx3;
	Thu, 17 Jun 2021 08:59:34 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id LWQ9nsdPA2gf; Thu, 17 Jun 2021 08:59:34 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4G5CbV3ZxXzBDwb;
	Thu, 17 Jun 2021 08:59:34 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6E9478B803;
	Thu, 17 Jun 2021 08:59:34 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 2IndrkMHscKX; Thu, 17 Jun 2021 08:59:34 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 93D628B801;
	Thu, 17 Jun 2021 08:59:33 +0200 (CEST)
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
Message-ID: <1a8960b7-fcaa-3649-1e8f-01911112209c@csgroup.eu>
Date: Thu, 17 Jun 2021 08:59:30 +0200
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
> ---
>   mm/kasan/common.c  | 4 ++++
>   mm/kasan/generic.c | 3 +++
>   mm/kasan/kasan.h   | 8 ++++++++
>   mm/kasan/shadow.c  | 8 ++++++++
>   4 files changed, 23 insertions(+)
>=20
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..b18abaf8c78e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,14 @@ static inline void kasan_poison_last_granule(const v=
oid *address, size_t size) {
>  =20
>   #endif /* CONFIG_KASAN_GENERIC */
>  =20
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)	{ return true; }
> +#else
> +#if !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
> +#error kasan_arch_is_ready only works in KASAN generic outline mode!
> +#endif
> +#endif

Would be cleaner and more readable as

+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
+#error kasan_arch_is_ready only works in KASAN generic outline mode!
+#endif

> +
>   /*
>    * Exported functions for interfaces called from assembly or from gener=
ated
>    * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 082ee5b6d9a1..3c7f7efe6f68 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 va=
lue, bool init)
>   {
>   	void *shadow_start, *shadow_end;
>  =20
> +	/* Don't touch the shadow memory if arch isn't ready */
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>   	/*
>   	 * Perform shadow offset calculation based on untagged address, as
>   	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
> @@ -99,6 +103,10 @@ EXPORT_SYMBOL(kasan_poison);
>   #ifdef CONFIG_KASAN_GENERIC
>   void kasan_poison_last_granule(const void *addr, size_t size)
>   {
> +	/* Don't touch the shadow memory if arch isn't ready */
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>   	if (size & KASAN_GRANULE_MASK) {
>   		u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr + size);
>   		*shadow =3D size & KASAN_GRANULE_MASK;
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1a8960b7-fcaa-3649-1e8f-01911112209c%40csgroup.eu.
