Return-Path: <kasan-dev+bncBAABB7HJTH7AKGQE3GAEBIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A40422CA8C1
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:53:17 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 64sf1375566lfk.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:53:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841597; cv=pass;
        d=google.com; s=arc-20160816;
        b=IyTi5ldJhK/T8UA0AWPlJggFxTCN7L3yy9547o/z3g+IwR80AtEt8xstcHvgp9ELql
         Ej/qR3bcH+dZex+upYltIJPNZ1FitK+2aTprlo7JNeseTyxQyHO6/+Fnsx2Yyhx4DYqx
         v9EGYd+FLn8w9vzsHBxfEHuZywTtGugLZ34PUHNMEmOLP37tpzzxXIyxHtgqVJibsyE9
         bxvQty5yW/cdiZTLJe1rPVIywGgXxSg26SIFcVA8s++zys4Vvz1iLYjVjjke9Dg2V3XG
         /inoN5caZX5CMAKDpTmNjaYyrQS902xlVdaWHp2NgRe6WHU/1TMInJj9rUmESYu8gRVs
         i2Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=PdF/kFLPD4xgARBd39wPcF997Kmn3Wcw3ClAwbiUeW0=;
        b=RTt2ThiFySnb3k3M5oAD42cz5/SZZhMMeTY1BCTZE2zwV8kZGNRo4g+ltUQXQooBrT
         ufYLb+EZJjg0X3uQ6AZWPKgNhoH8NT51ZbLDawwJ2BCYa5cJBG6IHs8j9FAsa4iaaZs1
         03XTumOV2WyMlXgUWLzm0ecIoPDjlMxAO8ETU6NF9PcKLeqrbvLfAXja74WF+0MxmmAG
         cTNgJqyGXBUZ5sL2OVyWACIb/ox56rbqijavq4OXVsfLIuqe8iJy7fZ9DDvgct4+bxWG
         maoocIsw8i0eFP77at0oNvyIZG5/TJu7Qi2K5JrgOZfj5y0cSwOczI9LjNYIchx77YoQ
         K7dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PdF/kFLPD4xgARBd39wPcF997Kmn3Wcw3ClAwbiUeW0=;
        b=lgV0xk6gI4Ti4oLhKEE6Ni7yknFVRActjVnkPWa2HMn0dQdP/FpM52UJAyt4HC4mLU
         Ni4vi/QOa34pUWNQOpzrDRQKzm/UXKHz9DjRFV1Zau1pfZ3QHwa7a1bDrfwSzvlryWWs
         3IPKXMETlAW9pvEb4k+Juxr90OA8tkoRCyNSmS63behIXR0QITJgi2+xUUHfAS+QFFw7
         qECij7Fxgv/zAPZm40MITHWlRW3dtABstB6I966BkJHudmhL3KNhk8/eQ/7wlruL3jGL
         Ri2fTwrv9IAm7cCqnEIofz1/yL4/jM+UxVLhMuC7GKhlU18N/OQ9xYtk6PHet8Vu8lpA
         /ouw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PdF/kFLPD4xgARBd39wPcF997Kmn3Wcw3ClAwbiUeW0=;
        b=DNEpnNTYmpQPnobYsTsfztVL2VhsIjlycolU/fhHK4IIPzj52MoPO801mroDwVgFVz
         odSKvs/YSbHibdrN20W6pZO6ejgPlRutdaYYh2WAh/vI/5Cs22HlStAv2UGvX8ZPi6f3
         CXoAqxxondNYMZaV7Emt5Fx3/V+54d9AorSKmTtr0r9JKzAHGPTr0x2kJwp0TepOWDO7
         aMyJpb2GTJ9G/d/Yb/Xl91GND8bqbcTpetkdOG6Jutj4vmMFFMVY/dM18WZfvXt7rWL5
         +sWYfUQWRSNXxKqyBCaQkQ1mXeh2HvKZz9Nkn/OOem/x+thuN5RvPts5/5SHU7Tzs91R
         7Vrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fp3SqhnybW+uTZ8/jNEruXPhGvMn5xcB/UDake30leitavk6i
	+m7r2Mpdk7h5xcTRPCuiqD8=
X-Google-Smtp-Source: ABdhPJy4HmaZRQ5ZgdOuXVbuPYCCAnTuZ+WwK4JON3NEohofjLWoB+h4lpMmzKpgVFrYAkSaRrs+qg==
X-Received: by 2002:a19:e58:: with SMTP id 85mr1735632lfo.395.1606841597172;
        Tue, 01 Dec 2020 08:53:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9848:: with SMTP id e8ls539215ljj.4.gmail; Tue, 01 Dec
 2020 08:53:16 -0800 (PST)
X-Received: by 2002:a05:651c:1199:: with SMTP id w25mr1795395ljo.165.1606841596264;
        Tue, 01 Dec 2020 08:53:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841596; cv=none;
        d=google.com; s=arc-20160816;
        b=kpkST3kYH7d86yurNIoyWV8Bhq8sFk3Emf669khuqCD6y8wt61TWgePO7+FQJlQR9k
         HIk4OAMs7N6nFHYe86AuFMD5xbbb5gu2bH/668nQrAZcKniXlCgNmEPlHwHUn6l+jNNh
         NDqCROeXgnYU2HBlZ+XADxguJPxPTBzcC8/1Kfs2fBwkTLzsgcPoo3cw2Y8peTHwn2qP
         p55/BePjxf5F8G/MV/iU2nL5wOinEBtj/D6gwfM8OWq07RVsZDXs6BSNK+bYrycNqzeG
         M3kN8yiq2UHFb+hVAAYSU45RmP4MLN619un6/i8Fk2V1Y6vB5LbWBZVTUhTwSkrKbyUB
         Np9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Aufl0/bkFQ0vrrpx/WzaPhAcQ3cfWkRTo5lb9McL+lk=;
        b=R+vBdgFJvHvvmvg5uyezbb4wVhqGuklyB12bJyRepzfyvHYgROiOiSISunixDQWjQu
         EIBgY6VGbbHzNHgDC1MwZ1mSCRHTjfH69Ysdpn/Fb3m5Vxe2rSk1umvz+tpZ8RGRCEuv
         JUGQinuKOHwSLfNNom0R39zeW+qAifoUiBA812Wo5CMU+2CoMuoG+qSDksrNs5/Tkin7
         AzaIO1t3CplOQaLH/+ry6XrqaKpejz9iqAe5qSmtTMVdEcuF4GnrnooTWSdTJVGKp+wM
         J9/xxVgZj1vPWHlGLF9/0KSFlik1jMKrWForp6MpDKn4I65sMMivBkoY3AUF1yiqgR6e
         1SFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id b26si8441lfc.12.2020.12.01.08.53.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:53:16 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Clp7s63DZz9v400;
	Tue,  1 Dec 2020 17:53:13 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id wq3KDCIGPUsp; Tue,  1 Dec 2020 17:53:13 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Clp7s52ZQz9v3yy;
	Tue,  1 Dec 2020 17:53:13 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 161398B7BD;
	Tue,  1 Dec 2020 17:53:15 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 7Dn2a6jQZQ1y; Tue,  1 Dec 2020 17:53:14 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A77558B7B7;
	Tue,  1 Dec 2020 17:53:08 +0100 (CET)
Subject: Re: [PATCH v9 2/6] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: "Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-3-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <bc92b30f-f087-ced6-cf00-a62370eae733@csgroup.eu>
Date: Tue, 1 Dec 2020 17:53:02 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-3-dja@axtens.net>
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



Le 01/12/2020 =C3=A0 17:16, Daniel Axtens a =C3=A9crit=C2=A0:
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>=20
> This will only work in outline mode, so an arch must specify
> HAVE_ARCH_NO_KASAN_INLINE if it requires this.
>=20
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>

Did I signed that off one day ? I can't remember.

Please update my email address, and maybe change it to a Suggested-by: ? I =
think the first=20
Signed-off-by: has to be the author of the patch.

> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> --
>=20
> I discuss the justfication for this later in the series. Also,
> both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>   - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>   - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
> ---
>   include/linux/kasan.h |  4 ++++
>   mm/kasan/common.c     | 10 ++++++++++
>   mm/kasan/generic.c    |  3 +++
>   3 files changed, 17 insertions(+)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 30d343b4a40a..3df66fdf6662 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -20,6 +20,10 @@ struct kunit_kasan_expectation {
>   	bool report_found;
>   };
>  =20
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)	{ return true; }
> +#endif
> +
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>   extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 950fd372a07e..ba7744d3e319 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -117,6 +117,9 @@ void kasan_poison_shadow(const void *address, size_t =
size, u8 value)
>   {
>   	void *shadow_start, *shadow_end;
>  =20
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>   	/*
>   	 * Perform shadow offset calculation based on untagged address, as
>   	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
> @@ -134,6 +137,9 @@ void kasan_unpoison_shadow(const void *address, size_=
t size)
>   {
>   	u8 tag =3D get_tag(address);
>  =20
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>   	/*
>   	 * Perform shadow offset calculation based on untagged address, as
>   	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
> @@ -406,6 +412,10 @@ static bool __kasan_slab_free(struct kmem_cache *cac=
he, void *object,
>   	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>   		return false;
>  =20
> +	/* We can't read the shadow byte if the arch isn't ready */
> +	if (!kasan_arch_is_ready())
> +		return false;
> +
>   	shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
>   	if (shadow_invalid(tag, shadow_byte)) {
>   		kasan_report_invalid_free(tagged_object, ip);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 248264b9cb76..e87404026b2b 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -169,6 +169,9 @@ static __always_inline bool check_memory_region_inlin=
e(unsigned long addr,
>   						size_t size, bool write,
>   						unsigned long ret_ip)
>   {
> +	if (!kasan_arch_is_ready())
> +		return true;
> +
>   	if (unlikely(size =3D=3D 0))
>   		return true;
>  =20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bc92b30f-f087-ced6-cf00-a62370eae733%40csgroup.eu.
