Return-Path: <kasan-dev+bncBDCPL7WX3MKBB353XTBQMGQENLIM3AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B12AFF686
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 03:57:06 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-235089528a0sf13676185ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 18:57:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752112624; cv=pass;
        d=google.com; s=arc-20240605;
        b=kijQNxl8RbPKgNYOaXaEbAR+FgEa/XAcFN24HfBwHZkywgHptBDUBKv3xr3MyxJPWk
         WEelgjaEVWvQVHgmoJJ/b02/6r1ORmF7oacXPWNmbcKVRVzwelvl9CWMzBJw+pHKBSNO
         wHIDdCEeESohYTpQ01LNijuN3NG88fET7/70FSTvpTW9zjXN98PA0d6EnixKFYtAsPCF
         jC7uXXmzXMgomHRwxLZ9x+MEkrubcKUgOt9nJi00ilqZL4sLF7Y7IFpdfHssCNgBvbgr
         uvWFzi1v6qd+mauLM6gIJa3G1C79DgKJhrc6Zp/IvGuAEMV0oyD1CcLM3xlABhJg4nYQ
         oVpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OfC1cEN8ZjZGYERJtpQdVx70BEkaPXDvOT69MnMvkvo=;
        fh=lSbsEXbogOnsRiPtDHQvUuIn3r6djYLZ0GRRGbv+SB0=;
        b=b5kNXz9V8uHGWZs+RfAuSGOIo3PxghfV1UHbLIwPEAIpJBs+L9GADWTBRhxOyNIm/p
         FdFsWP3LeqHy7TOY34BwFuJww+f2zc1H3/1JlSwJJ8jMYkUBaycWZ6IG7/axkKqy21/4
         gLWhwqHDFp8wYtUzFj6Xu6F2M3WKvTZA0mjU+DDZWQuowP/YLlH52rsNrZ+H9J9ZAf/P
         Ele8uwU3utjFx77DMr9doT3XsEV2aYqtOKRa6O2UcjW79GKV+JYV61ejSBtbetrh4Rql
         2oPG5E2smzuBcwBw/qwK1qemhgMtXS9c4J8KNmDHFRVTZww1yj33A8Wnh1DVVtLteehr
         aZIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s36gQ67r;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752112624; x=1752717424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OfC1cEN8ZjZGYERJtpQdVx70BEkaPXDvOT69MnMvkvo=;
        b=TDt4K40cOrTGSHgGETBAt69c2I65kFCWNAZszeFClIRshGS7MFO1++pSmSTMtaCzvm
         GJTQesnBBQAE0xJucJXoYjoCCHeZw3kkh+r6K++YoXnzaXzf3PUVKdJoqPYi38Lp2BEc
         HSLxgEskIaiQQT5HplxRNPFrc5U6PQVWRNZMci1yPXYoaEdrqUKaUheA9AD9RkQq1utB
         SeZLnZUXoTMmUPvxLQ5awdsI9f6PCREKXmmHIKUvpvhZFijxV76CEtbAP/fQ6LlccKmm
         K4zUflmkynSqNYwjvyGBe/Argzbkd2FFIIo7XnC4wrCvC1LfIQ79BTduFIkMe26yiUkT
         q0ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752112624; x=1752717424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OfC1cEN8ZjZGYERJtpQdVx70BEkaPXDvOT69MnMvkvo=;
        b=M3WMX+19y6yhdcB9aALJKEKC9uPS1Q1ekwvbdYbbubSKq5nDuKhlzfdgk0cuq4yu5d
         P7CNwMVAfxRYZF6aiaZ3Emh+kirKR8xRa8JBzXxmtygfEKggbUpG0F2GmskMlSio9woJ
         vFPKGQBhXj/mZJumKDVf8Cd+Kfe7jxB6LJbYaQGATo+bjZdRat0QTiUjwvhf7hMTvlFo
         E124wbSWrUKAuwSARJNHfznW8ttx5Ks1963efmXno9tGnXUy6JQZ23ON8MyhwEnygu55
         9CV0Bbf6iBfYdq/oT6s+D7WGizUU8rGbHcrG7S667ts3yv/ReAsFjBsufs3mJOXOQ2XH
         HghA==
X-Forwarded-Encrypted: i=2; AJvYcCUe/KkGtzZ8Hl1abuhttOTlt51kAhlebarO4aoFEVh2URCviX4A2MaVIb5RkrZl5us7iZAj+g==@lfdr.de
X-Gm-Message-State: AOJu0YxYEqr5pw65/RssWFrYfwmz7AtMzMMjs/86BtQFodLPhIN6R1CQ
	pC31348RI5uBrbOdD1L1fdPL3Vv4ENHZbn2p01d/vbvhDTP58LtbFAxL
X-Google-Smtp-Source: AGHT+IGe0lssmlfvRt5NHdoC8tqx0/UZMQcfJIhTT3jTF2CkZDq/XlEEYvJy6lemgIvp4NCo7nqHvA==
X-Received: by 2002:a17:903:4b2f:b0:236:15b7:62e3 with SMTP id d9443c01a7336-23de2f52462mr27030305ad.9.1752112624158;
        Wed, 09 Jul 2025 18:57:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZct2niJXqE6alz8FWEM06KQ4r79I/DtoPXMk4mVXs44CA==
Received: by 2002:a17:903:2f83:b0:236:6e4f:f30d with SMTP id
 d9443c01a7336-23de2d2ae20ls3656995ad.0.-pod-prod-00-us; Wed, 09 Jul 2025
 18:57:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYO7ujCzQK6dkV6qosJT8oJBrkS3SDT27KfjJ/8nRpwMqnfVa9ImKTxKJHqlSZEqjl7EWGK5Vdg9M=@googlegroups.com
X-Received: by 2002:a17:903:32c3:b0:23d:d290:705 with SMTP id d9443c01a7336-23de2f44349mr25164915ad.3.1752112622454;
        Wed, 09 Jul 2025 18:57:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752112622; cv=none;
        d=google.com; s=arc-20240605;
        b=PjVg3g/8ZpnwW928DkomqIlD6K2Yg0sMDlU/5WPC+E7UfsJWa+aTAXtmx82/Le3YPN
         bZ9RgFopURTViaridJYUY0kYCzVhxQFHp1SYDTzREpn4JidtxYYtCYCRzMgX8adIo1OV
         ujeUv4RGDdTnXdPLlHjRB8nwumSroB90KRC5JJkwq51h7Eods59XkVuyXZ4F5oIrpxVU
         cpC74rtado3Pb61pIKpa1ggjILxVUHgtA5rlAtQPwhyYqDK3JE3H3NCVv1gWffmyASU+
         k/K2/GMVCumtalz/eWQdvDACubRNsJlcA9JS55OHiAQMfJP9r6ErXfbqsRT8RaGKa3Ty
         zP/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DDObvEJ/jIdbBg5ZxcRmtzlW2/cKEzrqP8L22Qd6WsY=;
        fh=i7bVn5v9w+7goYASDRxSCsmO9K5U1rdcjQefYit2SPw=;
        b=QYrtR0H0DPep0RClPLug7FG6rL/PAmnPSPn+KCuDZF7+trdLmUq/mDC24ciFILCpgj
         GyK0qsWNSFrC92Kd5zUYz5H1+n8lxqFEC8+OKn+i+qZlZrzNyvp/NEYzo8jkFv7FJJTO
         P97NkuSxR8IzdaBoKSaR8N4zk2Jo3Co2bO2MVzzIaRVNcv2y2/xDkl1Svi7kxbXsDMwo
         z2NGxvjiSG45jNt9gTyyF87ledVSEkKHqOlp+Dz/aL7uQo35kVctO38pSiPatpKu6Pix
         l7ho4c7NWyz050E+nQLdXdj/k/WXge0EDo4sgCTZNOtvUd8oKDcnq/j8+b5lIV5bBeaj
         VnIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s36gQ67r;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de42a5613si210125ad.4.2025.07.09.18.57.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 18:57:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 9CBA65C6B8A;
	Thu, 10 Jul 2025 01:57:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B5A6C4CEEF;
	Thu, 10 Jul 2025 01:57:01 +0000 (UTC)
Date: Wed, 9 Jul 2025 18:57:00 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ritesh Harjani <ritesh.list@gmail.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Naveen N Rao <naveen@kernel.org>,
	"Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linuxppc-dev@lists.ozlabs.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v2 08/14] powerpc: Handle KCOV __init vs inline mismatches
Message-ID: <202507091856.C6510D809A@keescook>
References: <20250523043251.it.550-kees@kernel.org>
 <20250523043935.2009972-8-kees@kernel.org>
 <87jz662ssp.fsf@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87jz662ssp.fsf@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s36gQ67r;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Sat, May 24, 2025 at 04:13:02PM +0530, Ritesh Harjani wrote:
> Kees Cook <kees@kernel.org> writes:
> 
> > When KCOV is enabled all functions get instrumented, unless
> > the __no_sanitize_coverage attribute is used. To prepare for
> > __no_sanitize_coverage being applied to __init functions, we have to
> > handle differences in how GCC's inline optimizations get resolved. For
> > s390 this requires forcing a couple functions to be inline with
> > __always_inline.
> >
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> > Cc: Michael Ellerman <mpe@ellerman.id.au>
> > Cc: Nicholas Piggin <npiggin@gmail.com>
> > Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> > Cc: Naveen N Rao <naveen@kernel.org>
> > Cc: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
> > Cc: "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: <linuxppc-dev@lists.ozlabs.org>
> > ---
> >  arch/powerpc/mm/book3s64/hash_utils.c    | 2 +-
> >  arch/powerpc/mm/book3s64/radix_pgtable.c | 2 +-
> >  2 files changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
> > index 5158aefe4873..93f1e1eb5ea6 100644
> > --- a/arch/powerpc/mm/book3s64/hash_utils.c
> > +++ b/arch/powerpc/mm/book3s64/hash_utils.c
> > @@ -409,7 +409,7 @@ static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
> >  
> >  static phys_addr_t kfence_pool;
> >  
> > -static inline void hash_kfence_alloc_pool(void)
> > +static __always_inline void hash_kfence_alloc_pool(void)
> >  {
> >  	if (!kfence_early_init_enabled())
> >  		goto err;
> > diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
> > index 9f764bc42b8c..3238e9ed46b5 100644
> > --- a/arch/powerpc/mm/book3s64/radix_pgtable.c
> > +++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
> > @@ -363,7 +363,7 @@ static int __meminit create_physical_mapping(unsigned long start,
> >  }
> >  
> >  #ifdef CONFIG_KFENCE
> > -static inline phys_addr_t alloc_kfence_pool(void)
> > +static __always_inline phys_addr_t alloc_kfence_pool(void)
> >  {
> >  	phys_addr_t kfence_pool;
> >  
> 
> I remember seeing a warning msg around .init.text section. Let me dig
> that...
> 
> ... Here it is: https://lore.kernel.org/oe-kbuild-all/202504190552.mnFGs5sj-lkp@intel.com/
> 
> I am not sure why it only complains for hash_debug_pagealloc_alloc_slots().
> I believe there should me more functions to mark with __init here.
> Anyways, here is the patch of what I had in mind.. I am not a compiler expert,
> so please let me know your thoughts on this.

Yeah, this looks good. I'll snag your patch and drop mine. :)

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507091856.C6510D809A%40keescook.
