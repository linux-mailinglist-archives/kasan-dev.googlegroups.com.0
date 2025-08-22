Return-Path: <kasan-dev+bncBDZMFEH3WYFBBRERULCQMGQEPZ6VHWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 31DA0B31DB2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:12:07 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2eac3650sf5524816b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755875525; cv=pass;
        d=google.com; s=arc-20240605;
        b=HzNMfUg0kfFu7YsDEXGZzYR62RfZOyQeEjCQqGIQEl6F6pTy4AQX0Fd16AEB8EJvSu
         uLVj8ZHN7NaEmzOwAhRjqRiVSGxS1T54cTF4sC3SPDDxPY6puAa/DNesjcIg92uDRdw0
         vPG7Qua0hQ9kU++Zm+po/b6j7D3IHcI/ZptMWeTXbGnfqMDN5pNXvaENPxNE+Ip2bfsN
         EbM9+vpsSHZb3KPRQsuD+JIUHKRRcRo5bRjO9NWy0LMjzafryG+4UfWkLvNHc7FYeTW3
         5wsZVbjUnIyvqY0mHsow1p3DnowczNMcWe6APgx9SHyCoz6qXud35dc+XJxuQmB3ZIUO
         6ydA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2RoQDoJEXQBR3KAS5ZRkYa96O+WgxhXjpDXd8UAgyWg=;
        fh=hRo8XR3ekOtIBopLqTLUapPBqUxDSfboTdn3jyrm6BY=;
        b=d71uHMhZL4XrPiOwjnIUP5woZmCD0W4kqmIr7/t/bFezThH7CXNXgzyJ4HgVbgbjfW
         erRi0L2sAnU+SgiYtjqBk7LE+LxDZoaV5Lx/hR+eytGFSD968ANJYKFWfHwLaZLU6yJ/
         hcrST60zBewxA76Me7NcN+uMoJJEBgLRqVOrP4aanORClkY6zOO55cwtrV+WbBjxlDz1
         uBofGTrbbcqRdMf0Nsc4l3BzEeglEOxEfUQRfySlPEzEV57wX9bHWpZPQfWqcQqAHKDH
         Md5EIWolpYgv8TltkS6W2rj0ZnWLuOiKQw3+F+BESmamiUML4F1Lx3jvhKjkQqsqk2Zz
         VrNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gi25p9sE;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755875525; x=1756480325; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2RoQDoJEXQBR3KAS5ZRkYa96O+WgxhXjpDXd8UAgyWg=;
        b=AxFgFaAj7SOfHIRUV6Qyi7o7B3sZsOIO0gXL5iSuYk00B5Q/GH9peVXummfp+uPA+w
         V0TdEd9QpVvGE+Oxmdj1ASVlVhn0Y5U76IisEXl6syJAVn58cguiu/BnFSJsr8yzmNE3
         VpGYsfeNdYSV5HfPPjjJa51OxvSxTQvwFDK25jMFSK50SKBjHVxk01zrupifuuHn5ufI
         yxLGHda3tcG/wRrgliRuB4NtpeMWAQeiqdVm9QvAuQ3lmzpYecAtZcHcvbsdeSF/+7Xb
         glD+TWmEKhKyK1XfmbYD6SIrfvi/a8cS+uH0kSOiuuJxyKkb2Mvtdo6oe8VeK37+upot
         JqMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755875525; x=1756480325;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2RoQDoJEXQBR3KAS5ZRkYa96O+WgxhXjpDXd8UAgyWg=;
        b=JVDBBDXzgnvcmb0MBpfI2Lq4nsnlvBuLS9RFq6fDfZYWsuxQqpPy9hasfoSpi+kRYh
         QR47Phi+WPXHPa0dL1RwqGx6yOLnp5wJ8tUbDdPoZf8QdpJSU3wNX73WwG8W63cJVyEp
         Iet93LgnajSp5wvt+/AJoeUskw2fw87/6XFSCjsX0GBB7bi+oq1qpOx0KZvW05OWv/CB
         U6cyahaCcbLLc+Ei2J6rQfSuYntNNfXVcUQ1GvuTpJSWB14LyLQUlCBX1FyYF4IYFBg7
         gqPujxlTTR35wTVh//mscToj/bdTgrvYk45XUieJeJHDOM3dIJcNG8zVLvaDZUS7ZUSR
         smvQ==
X-Forwarded-Encrypted: i=2; AJvYcCWibw+476eingBUoTXtH9dOYtXCSFVLa05RveZTeLLBKr26y0iM1ScZN0i3MfrwCg0Vr/uMTQ==@lfdr.de
X-Gm-Message-State: AOJu0YxnN70fBkwEV0yalj/lVHsqYqtyzSbT17t7dIlUi6/wPVSVHf6s
	Xxio6xcFtnELhdD4UO+EQPwsct8zhCg20c89xJrrQWKMl/vxmy4obmJ2
X-Google-Smtp-Source: AGHT+IEp+cgRKBMvsI8mWYLOnEjPt5Gg3ZR+2XyCO+HYmmXwZPaZpovGuWW1lss+kPofLiBw/FZx6A==
X-Received: by 2002:a05:6a00:4f83:b0:76e:885a:c1cc with SMTP id d2e1a72fcca58-7702fc32896mr4013057b3a.30.1755875525160;
        Fri, 22 Aug 2025 08:12:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcSlcbnrZsT8XLep84TSevSb3MLIZcOMiGZTDLt3Us54w==
Received: by 2002:a05:6a00:3252:b0:730:762a:e8a with SMTP id
 d2e1a72fcca58-76ea02f54b2ls1882636b3a.2.-pod-prod-03-us; Fri, 22 Aug 2025
 08:12:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvdrV9iKEGwltj4L7XnTwbk/BF2yiBlyLFWKH6koOD8I5ZsK1vQNQD8aIeOeI6jPykNTFwbiS4H2o=@googlegroups.com
X-Received: by 2002:a05:6a00:2d8f:b0:76b:de63:4341 with SMTP id d2e1a72fcca58-7702fc02a46mr4175159b3a.23.1755875523704;
        Fri, 22 Aug 2025 08:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755875523; cv=none;
        d=google.com; s=arc-20240605;
        b=SIOSM2z4AyfJ1vmExfmCf64B1QrDWLCTyBIt25DKdcOuxSEAW2YEwcif4L86EFrBo8
         tnSYGEG6VPZcFIeNdBijOXh8BoVqNxKaEMrPyeoMFUiAac/z1alqK3E51Ofgt/UB3Fy3
         ES+WlMpSyeHR3xGMJ9qm1YlQbDwv2ltyrkbb9UQ2B+ayG9hLdj1vNPHSUaEZE+v05lxd
         tzrsm5IHLxreK6D9Hd/wqad1hMwuMD5YZAc8DhF1eWTaQrIDDZby9MzYY5tl04vnaC3m
         a/yKYX/LKOKDMYSVAoYL3zt2TJzCl4KN0mg69ikEklpIefJwI346jAOVC2Pj4b9KYJWM
         eyRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y1caK4/CeBqmFZVqvqUPKKf/tNhYxSNSju7u+8j5swI=;
        fh=WO8HiRo2V0p1zuPfqY5wl1Q95GTWlWmPMz0IsqRV34U=;
        b=Pl9pkagcw+VHwaVMboKyDONZdmu67Zo0YCM5+x0qkejGDR5Ma39RcpYW3pzmXX246U
         NuB50A+FoCOGcNTTSjXw6UlTRepGiKyK0u/Tl0sv7OwXv266+J0Owm/UI0OFz/PFLdne
         PP2UzXqIC1tRaTp/Xc1unqAOLFPq3W3EjWVeuoajKKBm9tbkrE+vAvbf6Sqp7dg5xAPR
         X7s5ThacgNWBEcWpYzQCNxCVoaXpkvawsi6O7wY3mVt8pllGNU4HpF1Mm7mMsGTt+0ge
         5nlDDlsfC1I13x+NJVyXvYmaNkm752iM0039y1csbQtQOCku6c6uwDncJl6b+B9NvrzP
         AS4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gi25p9sE;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7704027ff19si6800b3a.6.2025.08.22.08.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8512544470;
	Fri, 22 Aug 2025 15:12:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 164C3C113CF;
	Fri, 22 Aug 2025 15:11:47 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:11:44 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 04/35] x86/Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <aKiIsF8mpeUy-8zt@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-5-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-5-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gi25p9sE;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Aug 21, 2025 at 10:06:30PM +0200, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.
> 
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Dave Hansen <dave.hansen@linux.intel.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  arch/x86/Kconfig | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 58d890fe2100e..e431d1c06fecd 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -1552,7 +1552,6 @@ config ARCH_SPARSEMEM_ENABLE
>  	def_bool y
>  	select SPARSEMEM_STATIC if X86_32
>  	select SPARSEMEM_VMEMMAP_ENABLE if X86_64
> -	select SPARSEMEM_VMEMMAP if X86_64
>  
>  config ARCH_SPARSEMEM_DEFAULT
>  	def_bool X86_64 || (NUMA && X86_32)
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiIsF8mpeUy-8zt%40kernel.org.
