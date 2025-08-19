Return-Path: <kasan-dev+bncBD56ZXUYQUBRB34CSPCQMGQEJVW2CUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E7E7DB2CBD8
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 20:24:48 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b10946ab41sf4695221cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 11:24:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755627888; cv=pass;
        d=google.com; s=arc-20240605;
        b=hjFhD8bJHjZk2bBzZLzclPGhRV+x8HuumjbzqO4yT9lp4Tkm5ho+UlpLo+6YsvqqWP
         LBDpmBYU2TENDqmdBWFAcuFBB0Ieh+jX4I0VwzSCLs1fwv5caeMLlItMr/QpSr9JCIEv
         ZrdNyibowxK11qqfHl/typ0ugq2AaSaCaT0tlnFaXxweGCPDst4PHomd5ahCaN61drur
         v2680ODpwNe/D/ZXMsLZr7KzGvZanUrJIdNf4D62Y283m6jq0gLvbzcaYaZP88/HGaPr
         bbnt9uIOgotpB2MkYEO5dcUV8/K3XZbdi3PAyWYPTEo8BvjaoUI6VHgn648EozmUyU0V
         3J1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=v7bR4p/WxUb81eShZdVz8QXz2x/DxYr87tUb9Yv9E5g=;
        fh=GvONR/qjnMV8/+ZFybT746rJgG0MrVN5+V9dIC6W+ZI=;
        b=FOOwgWqzPu/3cIO6DdThf06e7l3e/acr0HBgNMAyQ65P+6+PaijkbZ5gj25tfBsFVX
         UAZZcUIXKhr6IxWy/nmhfBsenLpqi6RF0QXG0mUIaH5tDpsVB5/nWlw06LtwVR3YMYiV
         whHwGfKD/s9IBpBGN0XSdG2pftp4DfFxa9R/vhHyYZjImZOC8Ae2tJOWrYMhAEpyc0Cs
         ykYWB74lKhq3DrAYgvqs2uqGiF/HxjVLCzzSX5vzrOBLpJ4T9XSAn7l1Sc5gfHP8HoK9
         k2HzFFKwcgFNtlUiupLqHrFDVlDKRXOH+P8xblH5m2SILapnOquAISC7pK79sNTmsk+y
         nbGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EwzZComd;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755627888; x=1756232688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=v7bR4p/WxUb81eShZdVz8QXz2x/DxYr87tUb9Yv9E5g=;
        b=j5D59J/4Y/NuuQva/O92rbihTR7sJRM0VOP3TlgRJNyDoaUMEzyugHLFsRaH094cOO
         LbdedSF8LAYUS60YyFjyw1L/Lqec4zN/8RMa0+EA3ppliLzaPudlh/XQBOH/N18ekgjx
         k2lfbj8u60qRq/xqSigNCRTf8lpQ4uJwpBPTd1O0YinRYLDfaRI15p4Mc2H+Jq6p9aK2
         HRZmT73KK4ShohhFj6AvITqGM3q4V0qJ3BrroJENVLgfb/IcKgp9ejFjbXpXESmmmqay
         5f/Sc0UltjoMm7GR9+xVzh4g6e+6Jgr0t6pFiewO5mIYmAcQz/FG1LozSEuvxThOc7Lt
         Kfkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755627888; x=1756232688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v7bR4p/WxUb81eShZdVz8QXz2x/DxYr87tUb9Yv9E5g=;
        b=M6jOqGXV66D0DsflMpBDlDv1ho7uI1f0DoyCUAhb8mMgND1mIdF/Rt0apQ8L+rNGit
         BGCgCWm4Cq6YkTD+6F0CdwRNHoZn8PNbKhyD7H1t/I84emI/j2CzvRUDyO3vyEYgLZGx
         i4mmaRekOj7L+cfeopXX+VpxJePmLoGQTgMHIFRd9QVpnIPLHZlMqR4RHNzGscfhz0JT
         fSudPCZ4lTIYFrDj7+PZbmDnGiwM4X3Hol1WfBV4F8sfPeEW05fojn+79YusyZQ7Q93z
         xnrgytfN3G2b23s1/5n6rT0auNY2WNClUmFM6vR2QDsIufszSYK6e+Kkwj1Vns2bEty5
         amRw==
X-Forwarded-Encrypted: i=2; AJvYcCWdHMjqzTR5BRdK9S18VEy5LmU+rAihNlPrS7ws1sAqwMUaHcHwEpEMm4yWRF1hqoOUd3u0+g==@lfdr.de
X-Gm-Message-State: AOJu0Yy5aI99ldaEi8rHbUOeFa/dABdUqMyZJZNJ3dM33yfmkULc4KtF
	y60QdUD76yrlLLgX9cR4hWsQGtuMyNrIDw/MLNL8D6dJkza2pHrIz4H5
X-Google-Smtp-Source: AGHT+IG7l457NvAYQXocQqK9bjxVkivBsoU3/ZR9zqREud4Gb9bbdd3AJDUIlGaJh3pt6Kn8rME3Lw==
X-Received: by 2002:a05:622a:198a:b0:4ab:5d26:db8a with SMTP id d75a77b69052e-4b2911c9b8cmr4310171cf.18.1755627887640;
        Tue, 19 Aug 2025 11:24:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCC298asLWgYdd2k9gV4eyzKVuRhKWtITlBOP9UYYLjQ==
Received: by 2002:a05:622a:98a:b0:4aa:fbf6:4242 with SMTP id
 d75a77b69052e-4b290e14bcbls1444111cf.1.-pod-prod-00-us-canary; Tue, 19 Aug
 2025 11:24:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnwfr/nd9BanXbyXuS2jRmQ4euD0RkfMZtrE4NvPOHp7PCCi2ePgxFtR8ygVlG+lk2Znr9bO1RMrc=@googlegroups.com
X-Received: by 2002:a05:620a:40cd:b0:7e8:454:ab8f with SMTP id af79cd13be357-7e9fc7e1332mr42401385a.21.1755627886681;
        Tue, 19 Aug 2025 11:24:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755627886; cv=none;
        d=google.com; s=arc-20240605;
        b=MT6IlrCLyS511chEtFK74ye3EGV4fGtJT8MXirDygmvJGUBtjX6VH6/Rjn/Df/mpzl
         g/KDBLG/EJBbRcVJ16PDzyuoa8SZU7AX87uqRSI1D4PZ9TMTW+4DM7MyTnr8h4FtuBgH
         bEOpFotuDNnWOsKuR6kkQF/hx4gZekJiVCxQnQ9+EdiZFXvOpnT6XubKJ8CwgzSCICuP
         jUmL68spsyXoh/dpJPkaW/x3YC94qdYnTFFP7miW/fExKL6cHOCNJim2SklRQkSAZj6Y
         fCmHxj5Oqaa6o4djgky/Clt+Gaom8Kq0HyX5yq9ynrTpO8JjpYMUh7lp0vGTa+4BYPRU
         qndA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0Jymx+EA6KESZceDiO0ZcOJChcO4ShLkCuHB0UCXkIw=;
        fh=j6sgmjYfcl3NT0NcHnADy1HyK+NYf98K9zJ9uHWD/qk=;
        b=ZP+GEV0FawiPTIQqnFT1xVlP0BfzVVyRiOKb3TsbaetB6Z6LR3BsYMRZRfwyl9R0Xb
         aZTMH1hh1OybMD+vSK9ShKaLdIdi+2OV8ITVtt3PdLMOD36w980f8NJlqpKn2TZ8S3mq
         w7RlQIhya+q9meV/6sz2uIB76Rqr/tQ35aNbybkw4HgGfEjCkOt3VCtlC6rtlMKB5/xA
         pYKfUw+9Mo+oflw0su/83nSAe2H1hLa37I7CEbPYIlcuVeisazDSGn6MVGIraoIIA44T
         m0s7P0N7qCn6Ke6R94Yo4b6g1lyXUGTdGyumVebAleDaGhvYG+FTzpU7trbSafsOdddY
         HWYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EwzZComd;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70d70191d92si600886d6.2.2025.08.19.11.24.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 11:24:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 340915C655A;
	Tue, 19 Aug 2025 18:24:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53727C4CEF1;
	Tue, 19 Aug 2025 18:24:44 +0000 (UTC)
Date: Tue, 19 Aug 2025 12:24:42 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <aKTBariwz1_XsRv0@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EwzZComd;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Tue, Aug 19, 2025 at 08:36:59PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Make sure that CPU is not synced and IOMMU is configured to take
> MMIO path by providing newly introduced DMA_ATTR_MMIO attribute.

We may have a minor patch conflict here with my unmerged dma metadata
series, but not a big deal.

Looks good.

Reviewed-by: Keith Busch <kbusch@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKTBariwz1_XsRv0%40kbusch-mbp.
