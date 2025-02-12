Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZ5PWO6QMGQE4C7DBKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 23B48A32D38
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 18:18:33 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2fa34df4995sf126214a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 09:18:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739380712; cv=pass;
        d=google.com; s=arc-20240605;
        b=LHxPUmIputOUqCy2XteyCnIipU3wS0/e6g016nfjZNvgRuRTRFE7sn7roeE7XEQDyH
         TJO3bg9PvGEBs+4CqP6TZbqignftH5J8qA7+/6WUayLDEgm4tcqEVZQrLa60r8CWcosh
         pZKpNF+HDSnVHuhzPKopO4sOdG4qTwhUz3n7XvgyUDljCmejy3anCQaA4WNqHVLSPcpY
         LyPEf+YFb8CZZPZjathOHdzATY5BaeoIUUeUb7nANxRpZIFho7feUrBQvyCLPB9CpnQL
         8Zl8iB64m/NkhFS1rxRwNAEKCkSXxYzj7/kT3IYYNNlqXZmXoskx0uFXDzFTWkIt2g0d
         BVRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZOEr0pcph9ijzUkxnR3tDCWZv1GyHmr/ImU/TmHtSQc=;
        fh=MYp6X5RiT2+1h6DWXAC+JH9m8x9hZR3pXs+5sKM23r8=;
        b=kw3SXX+negUrS+0hlKYCk6KndiX47jHR9MI2mWvmrOEibAE1M3zJUeTuU8B7CEn86I
         3Xa0my62UJqU7us7kVglLs3+raVCfaKKfTBVyTIKrRmN/PbGbqDu74qr21mayvBqhYFE
         VlxtuX6aNxi1tCCoWLPW7pVxBqUo+N5ZL/TrfryfCwk5nyS0qsMvktxjzqusO5cLps77
         pIoKwe2X/jQ22q46SFcao0RpTALPKUePL5zP15yBJW1okYf17BKVPHBhKaRO7+Yqv3Em
         OsLBorvpBA6V2iZi9ua/NNAymRE0TWR/WzZvdSAGg/mOKayl4EJ8MvNjv0Lxm6khen71
         RA4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739380711; x=1739985511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZOEr0pcph9ijzUkxnR3tDCWZv1GyHmr/ImU/TmHtSQc=;
        b=xAEp442VdKKYx+lkMYH/IHWtRyFfNbN6mHNCQE1r2m43t0P/wlt8KqHiRgVi/vPHeW
         mOlODuMqiKA4mcknUZK72IXtu2iLsPuSH9bOUS4eJgCis8ROVCVfMJWFAgM3AX1J8hCe
         yHGILZnmkEmgFIwTeZHWk6rdzAATbd+RTai6e7jIKfuH1lBZz74E+k32Sy2snyzSbzBt
         fhxAo9/RiorjQdHXvT9/aLrFayApnMCnHZ/ipVeGVHSnyhDczgbgedM9kGD6rGXPxKdd
         UKeGu6mgOuL5Em/S4h+SXus0Tbe+CLxFRlTEz4DSRVhYEzwmjIuHTwFwxmRWpJEZ1bTe
         v8PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739380711; x=1739985511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZOEr0pcph9ijzUkxnR3tDCWZv1GyHmr/ImU/TmHtSQc=;
        b=Q463WP8jP8vDXmJ4BUYKDG+BhWLxpauxD3WvsF6fABWZe99oti8dzC5XblWl5Fatc5
         JIsH6U7Sgm8G0zpomesaIa2xkb+2pWEJE8tI4A+JiEEozSeceZUcroW3xvJllaHfGdzZ
         5EPBR0XJVWE1gSMxuqg5WHDDwahRK8x9RM6mkNz1p+97Xb8vtu0cmWtw9jdk3hYB54rz
         zs/P1uKEWdhGNXxU6mbw0ovY7/26alXdD8CY1bsQ46wjZHwZ6swa2n3JedWjPu7MX60l
         ZktIeYXwgN3jmFy8AcQcvaAJa6ZK790AL+i4XqSVFAvVXIwj307h0YxK3WybdarbVNCQ
         OsNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2k3R3WQKYkqKETh1/3rFsSwWM2EQJ98ZzhkMvSLm2g69PY9zsBXC/zsy278Np27iQ1mvUwg==@lfdr.de
X-Gm-Message-State: AOJu0YyvaXifNf3fikI0GgkleCUr1aq3+3poDYvABs/er1BGXIuj0nCM
	0bErh/sA31VeH+qUc6tveeiIvjoIelwmNWv1XPtsz6O8PvHBiD14
X-Google-Smtp-Source: AGHT+IFx7ZgBPyDuTEbgVapPImpL1xgeY79NGHeUb7MmDrg3TJU53u1+I1OdH0BVuKvlhpMsgBpFZQ==
X-Received: by 2002:a05:6a00:1c8d:b0:730:9860:1240 with SMTP id d2e1a72fcca58-7322c39c33bmr6043048b3a.13.1739380711596;
        Wed, 12 Feb 2025 09:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9397:0:b0:725:e2f6:f34c with SMTP id d2e1a72fcca58-7322b1f2cdcls1191148b3a.1.-pod-prod-08-us;
 Wed, 12 Feb 2025 09:18:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWIUptOyjYTF5cCj+0IDbjfmjcR/hMH9SvF+CnO61OQYOJ8hA22OrfurG6x3OrftxuKUpt1pk3ZoQU=@googlegroups.com
X-Received: by 2002:a05:6a00:4fd0:b0:732:23ed:9457 with SMTP id d2e1a72fcca58-7322c39b70amr6125429b3a.12.1739380709934;
        Wed, 12 Feb 2025 09:18:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739380709; cv=none;
        d=google.com; s=arc-20240605;
        b=Uo5rJBk3Y3kyTOkCLIiHx2y3qdGzBV0l1VavEExOIgTWjQAzlYv/yqqAsWSGayYg/D
         cQzCo+UMTEgMRnO3YXsdpmQx1P+PbxCqMN5uZ3KAnUYV68JHutDORJ9tvrCrJ9cxvJi4
         xuUpuoeHdBeVkH30BZKoXeRrbi5PKk1wknQt4DvrvCvw3IuxmCIq1pT1K4rRIWeSPL8q
         KPJ9Cx9T72jODmL6h6cnUBKszfKSbv1R0yaIYGwZfh2dm1GlPPbIV26j9MFsoZmvpxkr
         PKIm900/5yZbaxznlqK6At/v+IAKiXX2fr2rzhAGRgy4erQffy//f/sDQ2v8JFXiCmNL
         jfsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Rlgz5seG82Ux+fkG2i/legtN8SP4dQp1hc1HwNMZJ+Y=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=GqgjFVRqJmYgEB9w5TlnyhtWIm9KM2MJoSFl6sshmCDyq/0DIgByFeCWWcT8HYWwdE
         2GgcVIlCMdd02FOvzY8TKsVJPknvpMwppCFT5fEDr+VHBJ33sBowysQZ6r0E0BrDs9IG
         IGWODXg7X3MgjGbG60mqJCTnm772NkSSJ28MOKsZ55ABOkCsmv7X+0mj959cF//P4fgu
         MsmWRwUoOPoeZshePAei5BUIioaEFxYib577/LrbPHAglKtVu6ZCAA5eAEHCwOCOI4Pl
         dNSFJAbXQ0vR7aXuMSOxHIUy7VIQlx4dMsI4OWO7v0RTi4UcZLwpLf3ENTXfMxerWq6H
         W2fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-ad543e61375si498583a12.4.2025.02.12.09.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 09:18:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A6A1D5C5FFC;
	Wed, 12 Feb 2025 17:17:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D15C2C4CEDF;
	Wed, 12 Feb 2025 17:18:23 +0000 (UTC)
Date: Wed, 12 Feb 2025 17:18:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v13 5/5] arm64: introduce copy_mc_to_kernel()
 implementation
Message-ID: <Z6zX3Ro60sMH7C13@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-6-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241209024257.3618492-6-tongtiangen@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 09, 2024 at 10:42:57AM +0800, Tong Tiangen wrote:
> The copy_mc_to_kernel() helper is memory copy implementation that handles
> source exceptions. It can be used in memory copy scenarios that tolerate
> hardware memory errors(e.g: pmem_read/dax_copy_to_iter).
> 
> Currently, only x86 and ppc support this helper, Add this for ARM64 as
> well, if ARCH_HAS_COPY_MC is defined, by implementing copy_mc_to_kernel()
> and memcpy_mc() functions.
> 
> Because there is no caller-saved GPR is available for saving "bytes not
> copied" in memcpy(), the memcpy_mc() is referenced to the implementation
> of copy_from_user(). In addition, the fixup of MOPS insn is not considered
> at present.

Same question as on the previous patch, can we not avoid the memcpy()
duplication if the only difference is entries in the exception table?
IIUC in patch 2 fixup_exception() even ignores the new type. The error
must come on the do_sea() path.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z6zX3Ro60sMH7C13%40arm.com.
