Return-Path: <kasan-dev+bncBAABBMWKU7GQMGQEXFYTYLI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2Lv/NDTlqWl+HQEAu9opvQ
	(envelope-from <kasan-dev+bncBAABBMWKU7GQMGQEXFYTYLI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 21:19:00 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E13A218186
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 21:19:00 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5a1378c8adfsf249414e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 12:19:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772741939; cv=pass;
        d=google.com; s=arc-20240605;
        b=dBS8xZhSot4dfHJ+vIMFXyNBiwylr5qYQBHYOQC8bUvWMblBgJ8jpQWdckMA+Pf0nl
         0aTmEMxHMjuiFbWHibnTM1snWkPyhARlMBxAvXx9h5WAKBjjkn1Ho3YOrNxHIcS1PjKr
         mWR0+w/NcECJrZ3SCi71Xi3SRKOkNxc1LFp1URHGhnRrDv8UpVC5vryjmmmV0D31xsDG
         kkQ77UVs8vXuBBQ8g3kmeZo2RpzrWIHUSwDI7TcT1tAhso4NogCCwAhgIoj1XoRJefwN
         54ucVpJm91WhKVAxfhJULy/q+MtoCAqrtpJy20hkg74WiUkK00hNgxRPK+lGhSVBzXIi
         qziw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=vs3leTrIPxKLt3gTndaLpZfb+qjvin09yy5l4NxBm78=;
        fh=TTtlpPYm1+vd3NCDnrDfG07sqCHOzICGseW3Dk1QBek=;
        b=NCk5U7m1fAW/p72g/uWNjU7JZIq41uxDkTUjlWsoIIiOtgKv7IXBLWt9T1UV9BEMfS
         1Gl8jgw8fHMr8KvNp+cfCogOoSLVKgMLGmd2pbkRFOROBSLW9mz27dtxluwj+pxz4zMd
         B8RVquYIvDl7D83itCXDogDd2nOx1iEqTWGNJmv99R75H9gaO9BtpoAsoO5wzvw04kaA
         agRsthhKiGqogRuonx9yFhfs0PBdkX7LoPJikgZ5iu7ifOWwtLC4VKUJNiWrDcOq+DHl
         UzK7qBYWcxGDP0LeYZphPNMn1ELCoLW39DrLxpYyxo3EkeyVqnWKaFwWtU6SfucWOpbV
         tmEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=dNz8L5X6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772741939; x=1773346739; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vs3leTrIPxKLt3gTndaLpZfb+qjvin09yy5l4NxBm78=;
        b=KL3sxWiEkMGWAZbXWpP7Ywi8BzeFtndvrasqDOD7S0uNe6oIkQWoBHZd7UX1e9Sbxy
         dhfNk4sZkZxOeDspryo3IYxkEXYqfdLvAlRpqxmBj2G0sV5EqC0foPwkEuVKDlBPo/PX
         XhO+cCmzipRtJajXbWAjLNQvAfULMxbArs8SrGlSKnVXlXV1v4KTA8MImmKiZE5TxFWT
         X63JwliDb9d36Ih3H4U9v4dfLpAOJfPmKYl4cjtyLLUzEBWRkEeWvuLJ1NofZKKeS9K2
         8cvTw65fz3nuOlvgsoKMiea3UgeWsRYSS1jx8vAN+LA9WpXx5x/JbpDYFqwXZYfGqB1r
         kSFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772741939; x=1773346739;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vs3leTrIPxKLt3gTndaLpZfb+qjvin09yy5l4NxBm78=;
        b=jylWfGIMyV5fZeQE98JpASVTx6MpiJI9jgH4ijF9QwR6bROevXxx4F14nYJkt68Cn5
         YK8jyUHWWLw/mgkOhbh54TXmJq5H4v4XlX9dP3JudRGX25YUkFxRXSVLnmAtp+iRtxOc
         4ndj3kH+jqYBWh4/u4ilqev+7OLX4sDhLE2RjJABEou7vhnsUaFb+DnOlfpUNwRpWLDm
         UqtiKCcqNyS/otkeq7UEs74fmBxVLiJrnJ3Mzffwxo2CuaJ6wfed4IaM/W1ETh1XtV4X
         9kdJDyHyn3q1fUwE7EYNHbKuWfsE2PEtRtq3qbYFocSUNrY0CTTj/CpdjdoqRwKEvwzU
         NGCQ==
X-Forwarded-Encrypted: i=2; AJvYcCVK73K8lRNjKqtKc7s0MRYmsdZIdTOQ6zUvf7hCim9F3aR8mnSmpTbnoOgrt2/H/o3shdQn+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzXJWt5f5/avSPYg8iaDWGdlkQhS//9cfkZq36oksKZEDCdJYjg
	tUWhnfHyq4AUgtpT/IUaIHEqM9YUi0pB5FnPrS9WAMuQQWp2+EZDhxTT
X-Received: by 2002:a05:6512:3184:b0:5a1:27a8:be28 with SMTP id 2adb3069b0e04-5a12c2f2273mr1308328e87.11.1772741938983;
        Thu, 05 Mar 2026 12:18:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HNNNFiFO39AUGP85u+OGWuZKnrtsGzHYA0YsKU16eROw=="
Received: by 2002:a05:6512:39c3:b0:5a1:2c19:aeac with SMTP id
 2adb3069b0e04-5a12fc447dals266516e87.1.-pod-prod-06-eu; Thu, 05 Mar 2026
 12:18:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWKgBYmYOvRJhss2dOY+hvG7+j01y0+6Rs82tzDyFgTQjUJOEle61n+gDLlbMCcN3S+Xr7VmCe1iKM=@googlegroups.com
X-Received: by 2002:a05:6512:3ba8:b0:5a1:1d47:76e1 with SMTP id 2adb3069b0e04-5a12c2eaefbmr1435233e87.3.1772741936849;
        Thu, 05 Mar 2026 12:18:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772741936; cv=none;
        d=google.com; s=arc-20240605;
        b=AJVrHxnlJo6DG7ZAqRBr3OhdduPejCo7A5ug/oN8a/7ntXmn6MBauPwPMrVUxITgr0
         VCL5wg3RjG5mpv3xEfMhR40i+oS6v7pP7mQtqZVJKSX/VQy7hcKpHPVuU8WfH06oCLFh
         st2kUnusDBjp2e8MjSfDHUMunAgRoiwzlITgUSPaEbEJMy+GMZz+93IAx6QJDZmPhUnM
         672lu8nRQcPlphxsIPusxcVnN4t4++wZeoVYmev57SWGTeoCLRBYq2dTeptCROsrvDyi
         qfKmOvCms4aHKIE0J9geuI4nNJRS7DzP6Z0/QY+76d6xT6dQ1yl4hz4z/zCprhP8FCbP
         nHUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=cjzFn4m2KpajID2eW6dWgmxkcxpNABzXQGduS9dF8ns=;
        fh=rQoAgTABpoxH/VIG/SflDEM6gsnZB6YF5HWTrcKIoVg=;
        b=D/vQUjVJsci8bPldc6XdrL3Hqw8QtAz2dCLZG/CxGA1YbfKMqv+bHpDX1h66eDWWRR
         yFtqM73+u1h2u26WIYTYlXqtjDexEvo9yT2V7zBAusd4jEu2gMxcDxfJ8ZmZtUklYJgB
         eRZm7AgHHgBsv2mu6BJog3xCSXqLnI61BHBr5/OSPDej91OC7lX6sNqsuooZMHOWsorU
         G37auVa8sALbmVu/3eywl6HO0bEkIuPuZvNK7aQvrenV5N3JDHLT/WL/HdMsAOB8+QGH
         BPnaKAYyxNDRdGwfN8ocE/5Vy0pVf3sJwBVWPXDxmr67Ll2tubSzU104VP0PF9m8m22x
         r9Fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=dNz8L5X6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5a115b5c424si310127e87.0.2026.03.05.12.18.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 12:18:56 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Thu, 05 Mar 2026 20:18:49 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, workflows@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v10 01/13] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <aanievpHCv0Sz3Bf@wieczorr-mobl1.localdomain>
In-Reply-To: <CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA@mail.gmail.com>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <bd935d83b2fe3ddfedff052323a2b84e85061042.1770232424.git.m.wieczorretman@pm.me> <CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5b2989690457c011b9b0d41c90461138ce83d507
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=dNz8L5X6;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Queue-Id: 5E13A218186
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBMWKU7GQMGQEXFYTYLI];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[24];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[arm.com,kernel.org,lwn.net,google.com,gmail.com,linux-foundation.org,siemens.com,sifive.com,intel.com,lists.infradead.org,vger.kernel.org,googlegroups.com,kvack.org,lists.linux.dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,wieczorr-mobl1.localdomain:mid]
X-Rspamd-Action: no action

Thanks, that looks really neat! I should've thought of that instead of maki=
ng
separate arch versions :)

Do you want me to attach the code you posted here to this patchset or do yo=
u
intend to post it yourself? I'm working out Dave's comments on the x86 part=
s and
I wanted to post v11 sometime next week.

Kind regards
Maciej Wiecz=C3=B3r-Retman

On 2026-03-05 at 13:05:48 -0600, Andrey Ryabinin wrote:
>Maciej Wieczor-Retman <m.wieczorretman@pm.me> writes:
>
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -558,6 +558,13 @@ static inline bool kasan_arch_is_ready(void)	{ retu=
rn true; }
>>  #error kasan_arch_is_ready only works in KASAN generic outline mode!
>>  #endif
>>
>> +#ifndef arch_kasan_non_canonical_hook
>> +static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
>> +{
>> +	return false;
>> +}
>> +#endif
>> +
>>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>>
>>  void kasan_kunit_test_suite_start(void);
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 62c01b4527eb..53152d148deb 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -642,10 +642,19 @@ void kasan_non_canonical_hook(unsigned long addr)
>>  	const char *bug_type;
>>
>>  	/*
>> -	 * All addresses that came as a result of the memory-to-shadow mapping
>> -	 * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
>> +	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shi=
ft
>> +	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values. Thu=
s,
>> +	 * the possible shadow addresses (even for bogus pointers) belong to a
>> +	 * single contiguous region that is the result of kasan_mem_to_shadow(=
)
>> +	 * applied to the whole address space.
>>  	 */
>> -	if (addr < KASAN_SHADOW_OFFSET)
>> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
>> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
>> +			return;
>> +	}
>> +
>> +	if (arch_kasan_non_canonical_hook(addr))
>>  		return;
>>
>
>I've noticed that we currently classify bugs incorrectly in SW_TAGS
>mode. I've sent the fix for it [1] :
> [1] https://lkml.kernel.org/r/20260305185659.20807-1-ryabinin.a.a@gmail.c=
om
>
>While at it, I was thinking whether we can make the logic above more
>arch/mode agnotstic and without per-arch hooks, so I've ended up with
>the following patch (it is on top of [1] fix).
>I think it should work with any arch or mode and both with signed or
>unsigned shifting.
>
>diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>index e804b1e1f886..1e4521b5ef14 100644
>--- a/mm/kasan/report.c
>+++ b/mm/kasan/report.c
>@@ -640,12 +640,20 @@ void kasan_non_canonical_hook(unsigned long addr)
> {
> 	unsigned long orig_addr, user_orig_addr;
> 	const char *bug_type;
>+	void *tagged_null =3D set_tag(NULL, KASAN_TAG_KERNEL);
>+	void *tagged_addr =3D set_tag((void *)addr, KASAN_TAG_KERNEL);
>
> 	/*
>-	 * All addresses that came as a result of the memory-to-shadow mapping
>-	 * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
>+	 * Filter out addresses that cannot be shadow memory accesses generated
>+	 * by the compiler.
>+	 *
>+	 * In SW_TAGS mode, when computing a shadow address, the compiler always
>+	 * sets the kernel tag (some top bits) on the pointer *before* computing
>+	 * the memory-to-shadow mapping. As a result, valid shadow addresses
>+	 * are derived from tagged kernel pointers.
> 	 */
>-	if (addr < KASAN_SHADOW_OFFSET)
>+	if (tagged_addr < kasan_mem_to_shadow(tagged_null) ||
>+	    tagged_addr > kasan_mem_to_shadow((void *)(~0ULL)))
> 		return;
>
> 	orig_addr =3D (unsigned long)kasan_shadow_to_mem((void *)addr);
>@@ -670,7 +678,7 @@ void kasan_non_canonical_hook(unsigned long addr)
> 	} else if (user_orig_addr < TASK_SIZE) {
> 		bug_type =3D "probably user-memory-access";
> 		orig_addr =3D user_orig_addr;
>-	} else if (addr_in_shadow((void *)addr))
>+	} else if (addr_in_shadow(tagged_addr))
> 		bug_type =3D "probably wild-memory-access";
> 	else
> 		bug_type =3D "maybe wild-memory-access";
>--
>2.52.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
anievpHCv0Sz3Bf%40wieczorr-mobl1.localdomain.
