Return-Path: <kasan-dev+bncBCLL3W4IUEDRBUWX4KUQMGQEN2SEQHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A19D97D6147
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 07:47:00 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5079fd9754csf5275712e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 22:47:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698212820; cv=pass;
        d=google.com; s=arc-20160816;
        b=wiBNcgMl81mkdrFQOEn1gx79pO7k457KP7F+4A1BLIdm6qBe87LwfFhGJGVWYEGrzI
         T8sHEisv70QIgx+Pi+Ow1Cviwr36wvfJtPZIjtgIl1aW5hCmmX1+d5jZFyWDHelZphcp
         qGUhiV18SbXSVsZmt8UAVbp7xcnEx1nfyHKylqvvgLplfWSFyuKKNBXa/lu8wnPw5+Q5
         CGDmHmHVCl0le580Uv0iQhvhfmqP1naaFb3boldtZXh8gCAm2BG5i7CFg4c0V5wde0Jd
         XtpwJxEFDy2cY8YmKIb88NxdBokXY7fOlwkQHHPBsQ821m+eo3+O78NoWADETL1AwpXN
         GVAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=dn+GiE9WTBMR3PGsEAbmJ+lNuklLgas8VIR79onqKm0=;
        fh=njOM5Z0AmjjssjsCwVLk+UhSJkgF9hqohHI5y28hjHs=;
        b=rUByaqFdNrZDFBLan8YnBGbCsa6HEVuy0aNIIcURoBK98GplcEQSFZAap2iFlThVxQ
         gYQ1EWtCYi96BIvI43EXLnDWcLrImoGVPln7VQP8EHkCTF+xjlrZIsrC+/xnIvhY2x6w
         bjgcZ9UJciXsFITTFpLbrSNfBNLMWf6lKItEkAGBOFXwtQpQrkRKCrCE+bfYg14IbU9m
         +5p2FZczXOctQgWhjcib3VbphFR2z71fjtmjvpFsOFFu6/A6gl50owGPqN22tr6U/C3p
         rUogDWWBGaC8871F+e+l7e10gnSBRAsU0LgIsC84dWBjvjZ9qBTnOoa+pIsOF0ttp5jM
         dd1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=CtP3+TzS;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698212820; x=1698817620; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dn+GiE9WTBMR3PGsEAbmJ+lNuklLgas8VIR79onqKm0=;
        b=jK1O8NnkPNwWDoOK0tKmY8HQ/h3hVV4HWtKAaeJaIEcVmuM+/6kwnpHOPUvi/aezK2
         mADxmKqbx6zbRhh/WQyrTBXijIK2HJ/RvtdKnUewBYEcOd4kH4c1LFdXR2fjSv7Bh4Nf
         uSjqebnXvz5kQhRL0iXekNMAgpd4ukOVaVnCyKLfms+7thjaYmewVHskPM1NJB/wqegP
         M18ArFga9Mue+26ybuzd/5csHs57Eso6yVrhi6FHEitvrGsc8eDqBPj8V55nhfIXppRI
         DYH3iKCbXbfF/tnz7XEoenDkGJyWTth5AR+JUpQlzg9dreOrQ578omyqjzyi+5mviKBd
         tRUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698212820; x=1698817620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dn+GiE9WTBMR3PGsEAbmJ+lNuklLgas8VIR79onqKm0=;
        b=jGOnDq5RpUMkewCcteAG7mWL9OEMWtjgstPO1RagyLiQKWLn+vbeoUjQRY5AhtyTGI
         KFWgFu/qibSjn5S9WhUjryBpv2aKCg7kJ8kROw4sMIYMz6OHOUa/LgJSz9kZUdr4tk53
         aVnEI9UF75RNc8jL8Y4UOBMV/YwcdO5IiGuP8WZ1mxi3uieYpLn9GG5s1rU3hqQBrk5k
         rE73tL2oM+QCxtp1ZDvlecStUK39ha9yWCk/mz4y58zRXE0fFUIVWxZGxeZq7r1Q7OIf
         5jTAxa7DTDF79h6X4ALwLrZMpeDlBLFGaI7NiuXqqag33T9zIC2EC62Jr4BUILU6Nxq9
         iwTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy3oNyRd4xKXFUb3XTDekvxIzxHw52JdLDb/xboDDy5y4M/Ncl9
	ve5/6VPgRuxiVPGwSP7+bls=
X-Google-Smtp-Source: AGHT+IGI2uJuzXZyiIWUvaCp29EFsCc5yww124ASbXmd+HRoGmQiLTctpTZnXLqXVMOdiPKo1TCwtg==
X-Received: by 2002:a05:6512:3c8f:b0:507:cd39:a005 with SMTP id h15-20020a0565123c8f00b00507cd39a005mr12198013lfv.39.1698212818541;
        Tue, 24 Oct 2023 22:46:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e0e:b0:507:cf9c:aa7e with SMTP id
 i14-20020a0565123e0e00b00507cf9caa7els654886lfv.1.-pod-prod-07-eu; Tue, 24
 Oct 2023 22:46:56 -0700 (PDT)
X-Received: by 2002:a2e:b048:0:b0:2c0:122a:322b with SMTP id d8-20020a2eb048000000b002c0122a322bmr9099858ljl.48.1698212816564;
        Tue, 24 Oct 2023 22:46:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698212816; cv=none;
        d=google.com; s=arc-20160816;
        b=tYQM+NF/Wy9Hn5GYQ6OlimSPkFy3rQcdauIF2wOfDyOKaLDS82FexQoCyvrOCuKxev
         3Ypa0CGq/YyCeXp26kqkwsbXoJv/hBmZ89zWVJN+9any0f0TXBgw+hI5AO8T86olNN3I
         eWyTUsWjLhq/7sMIrwEnSk7jLGiYy+vg+DKlXET0uFwnfXpkJkhUbt6rr9aZabnQsUzY
         2AwG3CG60er/hmjxxTz3WqRpFjolMJvfzyu7DWt0by52nPtoPTHTqkJIt/CMYWkecmT2
         gbSuGmycXnG0wcu0jMf9hFLLIuFVxVukajrGB8poZtmY2EdjPeCZO+Hvk/9+GFopiP44
         IZ5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UqqJ79dloiHVNU0KwhCyPc6dgqQibRHVqcGY18Lj9uQ=;
        fh=njOM5Z0AmjjssjsCwVLk+UhSJkgF9hqohHI5y28hjHs=;
        b=tSX9QtM+RfO/ghJoPfaRh4lNdadsIcbTXq1KdCeOv87h0PK6MZQlKTo1QD3n8bjit7
         Rc78GKyPZ/1dA/tvld6KA5MubwRAk6qX1Dh+10asCmpbRrjFDvEz+zraZag/55PTdygX
         oKn7/nFDhZ3KHDWmRTs+fuZPOtH1pv2ODeEWQcMSfikhZA1n9QF1/c3Ukb7qrBMq0940
         ry0TykbMFzWXQRsIrcOgbHXvzOv2rkchvvCk8hQaBgvftxc4U7gV/9iCcxagPyW74cn9
         F7mje1oQBakYiud3xloZwkMYPm4JvR1H7aeX+Y3TTzrIAAUlvk1S9dTawVFu3Jiul/NR
         CVlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=CtP3+TzS;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id d13-20020a05651c01cd00b002c17e2e5fb9si452162ljn.5.2023.10.24.22.46.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 22:46:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id A2366176EDE;
	Wed, 25 Oct 2023 07:46:53 +0200 (CEST)
Date: Wed, 25 Oct 2023 07:46:52 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>, Neil Brown <neilb@suse.de>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v2 06/39] mm: enumerate all gfp flags
Message-ID: <20231025074652.44bc0eb4@meshulam.tesarici.cz>
In-Reply-To: <20231024134637.3120277-7-surenb@google.com>
References: <20231024134637.3120277-1-surenb@google.com>
	<20231024134637.3120277-7-surenb@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.38; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=CtP3+TzS;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Tue, 24 Oct 2023 06:46:03 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> Introduce GFP bits enumeration to let compiler track the number of used
> bits (which depends on the config options) instead of hardcoding them.
> That simplifies __GFP_BITS_SHIFT calculation.
> Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
>  1 file changed, 62 insertions(+), 28 deletions(-)
>=20
> diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> index 6583a58670c5..3fbe624763d9 100644
> --- a/include/linux/gfp_types.h
> +++ b/include/linux/gfp_types.h
> @@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
>   * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
>   */
> =20
> +enum {
> +	___GFP_DMA_BIT,
> +	___GFP_HIGHMEM_BIT,
> +	___GFP_DMA32_BIT,
> +	___GFP_MOVABLE_BIT,
> +	___GFP_RECLAIMABLE_BIT,
> +	___GFP_HIGH_BIT,
> +	___GFP_IO_BIT,
> +	___GFP_FS_BIT,
> +	___GFP_ZERO_BIT,
> +	___GFP_UNUSED_BIT,	/* 0x200u unused */
> +	___GFP_DIRECT_RECLAIM_BIT,
> +	___GFP_KSWAPD_RECLAIM_BIT,
> +	___GFP_WRITE_BIT,
> +	___GFP_NOWARN_BIT,
> +	___GFP_RETRY_MAYFAIL_BIT,
> +	___GFP_NOFAIL_BIT,
> +	___GFP_NORETRY_BIT,
> +	___GFP_MEMALLOC_BIT,
> +	___GFP_COMP_BIT,
> +	___GFP_NOMEMALLOC_BIT,
> +	___GFP_HARDWALL_BIT,
> +	___GFP_THISNODE_BIT,
> +	___GFP_ACCOUNT_BIT,
> +	___GFP_ZEROTAGS_BIT,
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	___GFP_SKIP_ZERO_BIT,
> +	___GFP_SKIP_KASAN_BIT,
> +#endif
> +#ifdef CONFIG_LOCKDEP
> +	___GFP_NOLOCKDEP_BIT,
> +#endif
> +	___GFP_LAST_BIT
> +};
> +
>  /* Plain integer GFP bitmasks. Do not use this directly. */
> -#define ___GFP_DMA		0x01u
> -#define ___GFP_HIGHMEM		0x02u
> -#define ___GFP_DMA32		0x04u
> -#define ___GFP_MOVABLE		0x08u
> -#define ___GFP_RECLAIMABLE	0x10u
> -#define ___GFP_HIGH		0x20u
> -#define ___GFP_IO		0x40u
> -#define ___GFP_FS		0x80u
> -#define ___GFP_ZERO		0x100u
> +#define ___GFP_DMA		BIT(___GFP_DMA_BIT)
> +#define ___GFP_HIGHMEM		BIT(___GFP_HIGHMEM_BIT)
> +#define ___GFP_DMA32		BIT(___GFP_DMA32_BIT)
> +#define ___GFP_MOVABLE		BIT(___GFP_MOVABLE_BIT)
> +#define ___GFP_RECLAIMABLE	BIT(___GFP_RECLAIMABLE_BIT)
> +#define ___GFP_HIGH		BIT(___GFP_HIGH_BIT)
> +#define ___GFP_IO		BIT(___GFP_IO_BIT)
> +#define ___GFP_FS		BIT(___GFP_FS_BIT)
> +#define ___GFP_ZERO		BIT(___GFP_ZERO_BIT)
>  /* 0x200u unused */

This comment can be also removed here, because it is already stated
above with the definition of ___GFP_UNUSED_BIT.

Then again, I think that the GFP bits have never been compacted after
Neil Brown removed __GFP_ATOMIC with commit 2973d8229b78 simply because
that would mean changing definitions of all subsequent GFP flags. FWIW
I am not aware of any code that would depend on the numeric value of
___GFP_* macros, so this patch seems like a good opportunity to change
the numbering and get rid of this unused 0x200u altogether.

@Neil: I have added you to the conversation in case you want to correct
my understanding of the unused bit.

Other than that LGTM.

Petr T

> -#define ___GFP_DIRECT_RECLAIM	0x400u
> -#define ___GFP_KSWAPD_RECLAIM	0x800u
> -#define ___GFP_WRITE		0x1000u
> -#define ___GFP_NOWARN		0x2000u
> -#define ___GFP_RETRY_MAYFAIL	0x4000u
> -#define ___GFP_NOFAIL		0x8000u
> -#define ___GFP_NORETRY		0x10000u
> -#define ___GFP_MEMALLOC		0x20000u
> -#define ___GFP_COMP		0x40000u
> -#define ___GFP_NOMEMALLOC	0x80000u
> -#define ___GFP_HARDWALL		0x100000u
> -#define ___GFP_THISNODE		0x200000u
> -#define ___GFP_ACCOUNT		0x400000u
> -#define ___GFP_ZEROTAGS		0x800000u
> +#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
> +#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
> +#define ___GFP_WRITE		BIT(___GFP_WRITE_BIT)
> +#define ___GFP_NOWARN		BIT(___GFP_NOWARN_BIT)
> +#define ___GFP_RETRY_MAYFAIL	BIT(___GFP_RETRY_MAYFAIL_BIT)
> +#define ___GFP_NOFAIL		BIT(___GFP_NOFAIL_BIT)
> +#define ___GFP_NORETRY		BIT(___GFP_NORETRY_BIT)
> +#define ___GFP_MEMALLOC		BIT(___GFP_MEMALLOC_BIT)
> +#define ___GFP_COMP		BIT(___GFP_COMP_BIT)
> +#define ___GFP_NOMEMALLOC	BIT(___GFP_NOMEMALLOC_BIT)
> +#define ___GFP_HARDWALL		BIT(___GFP_HARDWALL_BIT)
> +#define ___GFP_THISNODE		BIT(___GFP_THISNODE_BIT)
> +#define ___GFP_ACCOUNT		BIT(___GFP_ACCOUNT_BIT)
> +#define ___GFP_ZEROTAGS		BIT(___GFP_ZEROTAGS_BIT)
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define ___GFP_SKIP_ZERO	0x1000000u
> -#define ___GFP_SKIP_KASAN	0x2000000u
> +#define ___GFP_SKIP_ZERO	BIT(___GFP_SKIP_ZERO_BIT)
> +#define ___GFP_SKIP_KASAN	BIT(___GFP_SKIP_KASAN_BIT)
>  #else
>  #define ___GFP_SKIP_ZERO	0
>  #define ___GFP_SKIP_KASAN	0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP	0x4000000u
> +#define ___GFP_NOLOCKDEP	BIT(___GFP_NOLOCKDEP_BIT)
>  #else
>  #define ___GFP_NOLOCKDEP	0
>  #endif
> -/* If the above are modified, __GFP_BITS_SHIFT may need updating */
> =20
>  /*
>   * Physical address zone modifiers (see linux/mmzone.h - low four bits)
> @@ -249,7 +283,7 @@ typedef unsigned int __bitwise gfp_t;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> =20
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT ___GFP_LAST_BIT
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
> =20
>  /**

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231025074652.44bc0eb4%40meshulam.tesarici.cz.
