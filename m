Return-Path: <kasan-dev+bncBCF5XGNWYQBRBVHQVKXAMGQE7ZIB7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 158BF8523AD
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:31:18 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1d93f4aad50sf222735ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:31:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707784276; cv=pass;
        d=google.com; s=arc-20160816;
        b=ttYkjHx5kQXSAUdUPzNTiX2lJYFCKdVCumqnribD8P9ycodbihK2Il2oi0mn1r/1R7
         +rDwM3gwA10sLwb7Xwqe8jnKYmh8zi+bYwTdRxW1BdM82b58YbKQdWn9P9mMu+elMuP/
         we7b0Zh32haZ1IsvcIPnPOvI1Zn4wWd6q2gaSZTFzB9HAV2ejTSvR232AlNOas/gsi2K
         eRC7ZW9RYxZy5eEML7chGZQgewJFVJQyd6b9k0pgjUwMoZqPREx2TELY0Qtl74WLNpq/
         jdpAtUX0RzgHFr+S0hv26SEMmSEDAsLPni/t24CmJdMPl1ey0eirTn/Hj2f4Vnqv1mvu
         ZUXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eMeK00QFx7x7PywS8GiqhFLlJQz4NIEzjRSufC5CEYI=;
        fh=lEEb4hESU+NMv4d6aV1Zp79zpMw20pTPUY+m8S2p54M=;
        b=kKlEcU0iLkG49lcgHaZNyn6O74fR9eN82/mpRk1hgrPrFYM+SKrNH0pNSnirqXiLFG
         Bnz9oj1HfWblrlIqTh6BFCJFoEa/vR/kJB1ahRYnn3U5gCmUEt7bV4uByTsSKQKzClmW
         D84ioVg9ENQgk2R/nTWY8S6R/9dWFhun8qLw4tiedgJWZQ5WwpSoc5MdPy1P4H5B85QE
         fG8nEHITP/4/LBQpBzsfPsy6b9aKQtY05Amoj+Hev8bjip1ves3RKIZD04Bac6HevcCe
         inWKlCw50TE/oOj9bNc03spqHCxAgfPxl6mptLTFzjemphhkD85KQRQ2K+ipNcIpjIgH
         1XgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BDBGmrPm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707784276; x=1708389076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eMeK00QFx7x7PywS8GiqhFLlJQz4NIEzjRSufC5CEYI=;
        b=vhMeqrqxb+nMYPOX1uc/rfCYQESEWSL9UErCIyOPNX2QjOkBGGwB3Qht2jUwBN0SZ1
         +yLNJj97WinrO+w5pvFgBClcmKJnCuMaWQ/Vue3umWvXURk4O6Lp1W4WaCMvNPtJgev8
         wgm459s95oZrjMosZwz6jVSUZXEuDEKwOzLTKMeGF9xdQ+UBH8zxY3eBvol0Zlql7mHR
         cEeXSLL/aE5uhL6gFi8GEEl9AqjoFm8aeWseAJE0fQq/RO9/7Rp8Dd+s2T3j0aPwCRBb
         14BlmUjukmwd5HQmpIkkl2pnhchC4nEl10A0xOwm3E9T/lpOnCH/+UTMIanbpj2x15RI
         /11Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707784276; x=1708389076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eMeK00QFx7x7PywS8GiqhFLlJQz4NIEzjRSufC5CEYI=;
        b=JbpmmLBo89JkGBDtOYU7zh8Ol/51OGIii+U6uXChBD3T0MdPIxkdVIYrRyLYHpBsuw
         NzDqKJ+jQw5jFbymYUyMKbaYSymtDtk4c/lzfZZKUa3jF1QMHsaYzFs8EqRXzkGLQan0
         /R6iWyd/VlffKxPbeehw/DzY7NxRkA3vR/6bkq2tJXpzYkJ/fPEcLMUFuI4Mrdh9aJnc
         SF/aroqn6mc8d5TXPwMOjcoMIVHeyrizChFI/M85PK/dcdCPw6ijuRetQyBZkgzVdo/b
         fE9M9iZ6vHIr5cKfQO5j+qHPwHE5kARklqcFwJINFxVzIFRzsTLoIiontpJehPVJ5lYg
         tqsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3FWM0Ck+tLRJUcVfOx+2Mhpc5wtVBCMCMBDXZByT1xiAOhOVjcbtQM4bNlRxB+taOuS7jiUX2tRXbekDhHCyGKJGHP1oH4w==
X-Gm-Message-State: AOJu0YwHK9TCoAQZg0j3ZuERJTO/MOXeqUQiIqlvjn/Junk7MWG/ukr2
	UOstcFWRlBW7P3CeApOjFfA1BfLOJlhylz2NkPJ+sp8mV6OQ4AFO
X-Google-Smtp-Source: AGHT+IFsWceJHRkPXdxbvj/ZDv2TyVluns/5ZWU6NfkTEslSCZTGSm++uvqdufRabC+gqOTx9adtvg==
X-Received: by 2002:a17:902:ab97:b0:1da:292b:cf94 with SMTP id f23-20020a170902ab9700b001da292bcf94mr68189plr.4.1707784276727;
        Mon, 12 Feb 2024 16:31:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c0d2:b0:21a:216d:5a20 with SMTP id
 e18-20020a056870c0d200b0021a216d5a20ls1161658oad.2.-pod-prod-08-us; Mon, 12
 Feb 2024 16:31:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVs5D7Nw0DmS9g0Ud+PQ1ptEp0ORHHfNCzCytRllRulGxJmeqWjDiO2ihW9yBezMbT/Zb53EptCTnBHLi50aTiXDVeVJuvhKFj9Ig==
X-Received: by 2002:a05:6808:148b:b0:3c0:3653:aa55 with SMTP id e11-20020a056808148b00b003c03653aa55mr5656086oiw.7.1707784275960;
        Mon, 12 Feb 2024 16:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707784275; cv=none;
        d=google.com; s=arc-20160816;
        b=kVwRiLDn0xWGCBhGWbYar1tcCl73DNEYftXaT2E2pNia5utqWs/DTC7xSFrRd53pha
         8APJyTpmCev090faeSaEjN4PMKGOBpCdmYq5lUvmst18ucHEgT0/hV8Q5bv2m755l0P5
         QKx+zaJ0I8y+oWDP9OdcFRpdG3jMa3SVBJ3lK1yLKDWyb/CyZuf51VL6bSzkv0THWapd
         0ABWoal4XaHMK6leXkntsaaKXx6/yutSMKSnKvIiFPQuU6RtXlSUikS5RqF4sKQlyT/2
         tjBg0+fvhAawRO0SjSxJBiner0IqViSuTsobscJf960f13i8eCrnMchUD/xwfTB1yIW1
         5Xkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=flZnqd6/OOEmgqviJI0+73E/bOCz1vKp47Qn2/+ubUU=;
        fh=upSeLit9FDNf4bwPrejC9sC6JFeeD6EbWUt6jOuLPuc=;
        b=HcLqbjATIULUMqugh3jDE/RHmwKDCtEPX9Q+w0GNgietprjAMfkwSe5cp8wH56/MtY
         rDtZAERrllhEFdL8j0DZr3Z5N0J/3+yFenJVJgV3j3CCBgN4Z6aU2R/5ekAFDhVfmVQA
         PxS5/h1w7oEkNvkqdXYdKtfr/1+W7vXPbMf8KOshFVGVuzuFfMclJVxGHYcL3p5ZIBGN
         D0B80ZmWBGi5r3nn/ge0fflUfTivBxJTXVXD1X8cgA1nS/3+sszqFLjFgnA6w7S1QsJR
         YeXwcipl1lvZn0jLzE39jSbwunJ6BA/1U16MUhfmxZFX9Y6THsSCpxlqw9xVnAYB0Dcw
         xrew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BDBGmrPm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWa4Zo+ufBIWTFSpE2ZOUhYOBcfOLrGT8wdfjzuG7LkGSCezyft9FQpTR2ha9uD28jqvsO/rtE62eCuLcmHLocKm3GxO0ft8zH6DA==
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id s15-20020a05680810cf00b003bff43c21dbsi157367ois.2.2024.02.12.16.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:31:15 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-1d76671e5a4so31329115ad.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:31:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXR6lYSGERXJo6XqqtncSt9lg3rYtko50a0KAqbaiffAgQqg9twyrsvOF55KYYsCBtHXKjtjcQV59XpaonrYNfPOs0FMw9uOW0A2A==
X-Received: by 2002:a17:903:228b:b0:1d9:bbc2:87e7 with SMTP id b11-20020a170903228b00b001d9bbc287e7mr11716581plh.36.1707784275245;
        Mon, 12 Feb 2024 16:31:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXP5RZAw1oi53o/gxKC4lO2ca7b/Hnqmpu8kg53cb7pw3QU44jF2cY5+OJBO6UbtPdy3/ScqJ+yf7mzB1hCYHjxvomlODDl0HkKLCMv6E8skXfvujDWmni/YcNWO4nMXhGrOxeccbAmX0B72Uhdj7z1F5wnbrmaXvP4ia+UngYKrTfi6zBvPXGEMidOrtC//iBWuwimaSSwoLAh48OoaqZ0YF1ANYUBQHmL2TutBWkpjIGS2TqAYs27TCeERgQwfZbIsk/DHhYmWHL6p0EVZwjG8KAvifMOUVVcXuNh1Sa6TZ5Y3gTH6ughhPUYB2LKprUpqD6i1Yz7tVX7fjGBIcttAAT1kuCW4DlKJbcvzbxu16bupxscwO3CZc6mcJtOQC5DZZZmP3f1D6uGeMaeyaJbEsWEk7AFmtq9u58uiyHBRALuJh62/GZXPJ2r1F0nOMklbBoF4iW9CYBCQtgHoFD0uyUAt8KSb+R4XjOMTQwrYL+IS9RM2lDNbNcOzOlvf+6JvYioco20iLyMrCWmC0+E4YuJKUqNJ8vVWQdsf98PnP/hEU3orVBxYPh5gtfPTRDTl4moSJd6XjdbNBjbbLzcrTLEl62Zy3WKE7PzvY0WHqAIVNOP+c190IQbrg/bVQ7AocPN5UrCC00c1njxdtRP6joT2g2496knPxnT1ET9xMrrP9OsLeKPtpfk35zb/iv8WgnHojmXpiLLth0P0BUzWN8X6lkI5KR2laOddod5KZTJVKomMvDvD7HL+USR5kLcH8zXQ/A806PO/AtJmJus0fbK3dJyVEPGmyM76zJXGfwHe5jZqO7MaWE3KHHyFeghxm3nQG+1YYaiym3hNfKgvV0KtiyTHS/FQMXcaOhDobBRiPLI+ACHtnugOFWPepL/5sB6MN/0TBNeiJdi3GZtVopPhwVAr3wc2le/ryrc9EWHVaNFML1m6i3+xpTTL210VR
 jtMSem7iKf9pLwlD1xOKe32gXxOwoZenfWojO9rGAgoL5/f8DL3n7m3f7O76PQ5HJmm8cMn8G8T0tmdyg6kXdXbH7zAvineHF5nWDbpiSc+p7Qzl9LSvoTFweZ031yvdC9H/13LxKteGYjgBszsOQbPAlZNIlAhFKtZ719A4IjJPj8Sa4f+5PnB3hQQ7EFcJZMXPgR8Ab73qaXggizB7rMhTpr7b0oX/nHZMi7JjTL3cM8z1K9sinOvKJbRKrk6hORHp7RfvhJS2L7wtdbAxv+NJmc8Ke+Q2MHUQ/lnbWbrqyBLDNaEAqR+qaDtj5gZBiHL3YUL3kSUGjMIffjdpfL9hOTSOhrRGDt3NkqEHX7V/l3kCpd8TzpITAIhtblcZFvE5WOXduAoVGVN65Y3EfuvzkLUBDIyViEtttLHJi1WHEA4WZ7gMX/6rDR5a0=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id d10-20020a170903208a00b001d92a58330csm894702plc.145.2024.02.12.16.31.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 16:31:14 -0800 (PST)
Date: Mon, 12 Feb 2024 16:31:14 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
Subject: Re: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
Message-ID: <202402121631.5954CFB@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-24-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-24-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BDBGmrPm;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:09PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> It seems we need to be more forceful with the compiler on this one.

Sure, but why?

> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121631.5954CFB%40keescook.
