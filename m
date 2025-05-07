Return-Path: <kasan-dev+bncBDE45GUIXYNRB27O5TAAMGQEPS6OCEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B469AADC91
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 12:35:25 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7401179b06fsf5388377b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 03:35:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746614124; cv=pass;
        d=google.com; s=arc-20240605;
        b=i/z1eWlVPEYJ6YmBRC9VU8sIJSStYOnrZgbPPKZQKwvwflzEfppMLneD4HkeTkuATU
         7odD12FhR7QvzxJ0SwoZslkeq/oL1oLbvR6lBqhsxmmHE9XBggEK4ff2gPmDVbvAocsL
         3sNz7tJWeXL/GlhO1NU6eVkwnDZoIXfzv/GBhgAcETrt7+71+6pThePXnBm7I2XQchl0
         TVduEeqnUxyOTFQSLP3QTpf/bu1Y6k8eAqKf8FTENbVrsFsKGTVL494IGPbNYRTpZg7b
         O2faHi5pFYBYYtVYoGURpICpQq0+b1m6kkTYr/Pb/g7R3EqZsCWqOwWcePrzSdfW5SqX
         bpcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=fICeGF/Q+gja2DhQZL1QQiRHW9Mz+tcoggOjE6nJ/VI=;
        fh=SygMVEQwDrv4CvhZQQb7lKBbK2P3UhC/Sq7bJ0JhpyY=;
        b=O4aLNoJ0UWZcfggtWJ2F+vjAbeW2L3rTNnWQqsEQ6gV2CFsH+rPP1pH2n7jtlHBDIl
         YyAKd30HoXROp/Ddj0rybkjr3EY/L/yYSf4pH8An2O4LG/R0tv6Acsff67yIKeEslUIv
         Nx7YM6SDrHWUkP1h44G0vGyBvwEtESBC6qOYwBXWglEwj+RAjQ275bER277cvHtDQfUC
         czKaaAzOofUB57M9Sd3OQpIYtHrgytCNm3P78DmvnSd/Y7irFd6TsgfF8LWvDcX9mcxp
         I47ck6pCFKrMu5VG4ZjIHt4k7S2NxQQuPVjY9ID5iDM9ErYs1m3Doh6XXteh5w9xFFIX
         1RVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=quH70Q9F;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746614124; x=1747218924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fICeGF/Q+gja2DhQZL1QQiRHW9Mz+tcoggOjE6nJ/VI=;
        b=lhe+Rxc911ynGKLjiA5VCS+7RT7Y6TyQ1IgFjoBkmaxH/SXeVs6OITsRfEnQZ18ZlO
         U1U2khKBQJS1a2AlWW8jUuTwo7PlA1dTIB3OFmdHNwgpChgphmfjZVSwXnDHDrF453s5
         nV/2cg7UZDG+0UbNXfIE9UapxFjDfsos5Io9Hvke35WBpZKuuxQ2U998RamHZ3nX7wwZ
         mibiofR1tiYV3g498pTP54CUd5zGYvPf7Zn++tSHAxyeBGgT9nmNDy6hlVyzGot+D2+q
         uenkD+SzJLZYyXklgojiYtZFipC8jMOurSMHuFwv7fx90WjBPdE4yEuypg+9CWIRH9/0
         +4Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746614124; x=1747218924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fICeGF/Q+gja2DhQZL1QQiRHW9Mz+tcoggOjE6nJ/VI=;
        b=j8GT7AJhnftKpKR16p1kt4WqXQ5CV7eDIkWlFWQ7+EGxQT+xwE6OVpfUvBQquEZu+E
         8ncwz987VSnODA74AK5lSw3G+BEf+MjQdcxBRDv5Ec+2tBhrUJgiHg/lruh+ou3U6NOY
         /KLHZXFnZiIVrnIQL91pshGy7RlHw+DjIKeGlih2JsK+gsRPMf7/mAKgHt+ym7L2xWQF
         o1yan4NYvkpbr3NvgO4L7nHDRsoDwOGZEj3yhm3OVLsDbLvGWsZo7tpTRz+yfD/4UgyA
         pa7W5DXqxjXlGzbat4a3uhxUZWJzAGJJ8OJK2li2CAJjJdk0BmvcfPrc4iDToe/g3jwU
         QREg==
X-Forwarded-Encrypted: i=2; AJvYcCUSb90BN6KQdNFZ0B461+C3frr9DFOIb52DN0Lbk7M88yZf7T1kSV4MvJX9pebqxCkLQNJ0jA==@lfdr.de
X-Gm-Message-State: AOJu0YwCt/UV044tbRbwECsklzREldLgWzjvd+WVf1/YJMmAA7/48TnA
	OoD+bmjSsyblcDypYOiwLBDf4Coko24WqbViRsNKhaKIhiW6vXtj
X-Google-Smtp-Source: AGHT+IGqVxrfnwNdRt2QSMVBRmkB6KGp5pmuJrhEa32iT4OJo+PMNwo1F3KHVGRWjFdudfn0eFTqow==
X-Received: by 2002:a05:6a00:3314:b0:736:7270:4d18 with SMTP id d2e1a72fcca58-7409cf1b4d9mr3840117b3a.14.1746614123683;
        Wed, 07 May 2025 03:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEm2flHvGNwMUW5eKvhUy0e/XjPWpEfxzfxV3K6aYTd7A==
Received: by 2002:a05:6a00:10cd:b0:736:9f2e:6b1b with SMTP id
 d2e1a72fcca58-740459cf0a7ls6867922b3a.2.-pod-prod-01-us; Wed, 07 May 2025
 03:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXj4n5ujifJ5RsR09wv1+14GxW8E5DoL+iWmfQUWps6aom91BgrZVNqO7vnp6qw7NjQpaEl1QcFnas=@googlegroups.com
X-Received: by 2002:a05:6a00:298d:b0:736:ab1d:83c4 with SMTP id d2e1a72fcca58-7409cbf336bmr4139441b3a.0.1746614122203;
        Wed, 07 May 2025 03:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746614122; cv=none;
        d=google.com; s=arc-20240605;
        b=gwG9Twpxs/KVJ++f7ktI9bMOhju35Qbdn7iXSSFIJFLiFMcJYv2hIwOCuxcywik6oq
         IklHa1i9w3WKrO+8paW8OvIeggdvreTr2ZhSVax0IDVtRNjhxyFYyMnllnM1f8/KfM2D
         NnqNIwgrb3XtPbrTtalrjalXS6kSd4fUvfFSKUCBtjIR2ScvRL8VrHm8eX23kweCVIu6
         7ExikF+GFzJXJEZp0oV9UEgXCJxp1XeTnMVi1YrRkrGAhHiEsCXeEGhk4x3rdYdc7dJO
         C0kZ3AlncrfgvAnljkW1Y46mqltclXNwX3vjFJt2gtgfKNF6DIqg51T4R+PLhIMWPnZQ
         ZXfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5GWMgj/3amqdpBVWxSIsX0UzGsUbfcmm/WdWzaOR5mM=;
        fh=2z/1RxSQWcW0oXsRdcGt5bUJLgK7CsN9NPg1VTD1AXc=;
        b=fshHUtQpIv4hGyHimP0VKUrchXNlmcCpnd6wN6kOCOXovhiZZuln0fiheKPLmQHytb
         l5Ck0h7UqLvLEh4yfPNCzDUu1OQ7a7LIMBZLz0CanAxbtnGXrkZTK2b+gp0gx4FDN4Jy
         GJPOw9wPqvIwSgfQ9rfWa8p9HvFGq/GeWdUIl7jEuULgomaAR8xSbad9knTB9gu1FdAz
         KAAp02Z7nKVxTekHBELM7tqD+LTlrEu5ykU1OkRHUPFU7GnpCFAshU5/Zza8cbcQqQra
         BwZdqPD5fWbcgIvIPUTCYU86NmVYBQOuLLBJlF7nvGBU4z24MR+DVipkgcMAe0BAq5Of
         fkyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=quH70Q9F;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74058d76e55si483664b3a.1.2025.05.07.03.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 03:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DF80743768;
	Wed,  7 May 2025 10:35:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B2307C4CEE7;
	Wed,  7 May 2025 10:35:21 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=valley-girl.lan)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.95)
	(envelope-from <maz@kernel.org>)
	id 1uCc7T-00CZoF-93;
	Wed, 07 May 2025 11:35:19 +0100
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	Mostafa Saleh <smostafa@google.com>
Cc: will@kernel.org,
	oliver.upton@linux.dev,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	hpa@zytor.com,
	kees@kernel.org,
	elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	yuzenghui@huawei.com,
	suzuki.poulose@arm.com,
	joey.gouly@arm.com,
	masahiroy@kernel.org,
	nathan@kernel.org,
	nicolas.schier@linux.dev
Subject: Re: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
Date: Wed,  7 May 2025 11:35:13 +0100
Message-Id: <174661410588.354102.12581614598575589637.b4-ty@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
References: <20250430162713.1997569-1-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, smostafa@google.com, will@kernel.org, oliver.upton@linux.dev, broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, nathan@kernel.org, nicolas.schier@linux.dev
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=quH70Q9F;       spf=pass
 (google.com: domain of maz@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

On Wed, 30 Apr 2025 16:27:07 +0000, Mostafa Saleh wrote:
> Many of the sanitizers the kernel supports are disabled when running
> in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> (and makes more sense) to integrate than others.
> Last year, kCFI support was added in [1]
>=20
> This patchset adds support for UBSAN in EL2.
> UBSAN can run in 2 modes:
>   1) =E2=80=9CNormal=E2=80=9D (CONFIG_UBSAN_TRAP=3Dn): In this mode the c=
ompiler will
>   do the UBSAN checks and insert some function calls in case of
>   failures, it can provide more information(ex: what is the value of
>   the out of bound) about the failures through those function arguments,
>   and those functions(implemented in lib/ubsan.c) will print a report wit=
h
>   such errors.
>=20
> [...]

Applied to next, thanks!

[1/4] arm64: Introduce esr_is_ubsan_brk()
      commit: dc1fd37a7f501731e488c1c6f86b2f591632a4ad
[2/4] ubsan: Remove regs from report_ubsan_failure()
      commit: d683a8561889c1813fe2ad6082769c91e3cb71b3
[3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
      commit: 61b38f7591fb434fce326c1d686a9793c7f418bc
[4/4] KVM: arm64: Handle UBSAN faults
      commit: 446692759b0732ef2d9a93b7e6730aa762ccf0ab

Cheers,

	M.
--=20
Without deviation from the norm, progress is not possible.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
74661410588.354102.12581614598575589637.b4-ty%40kernel.org.
