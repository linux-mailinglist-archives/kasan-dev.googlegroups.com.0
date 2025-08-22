Return-Path: <kasan-dev+bncBDJNPU5KREFBBAM6T7CQMGQEPQKUXCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 14004B30B25
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 03:59:32 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-323266b700csf3282180a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 18:59:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755827970; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHPmnZ6GlqoSVsi3yKtAD341kQXQWt/XLSU/G9wZTO7EXN0x1mh627cHJpv+kPnCwK
         IpmHEofrTkW8caeIkfSWANE58Yav7qWuzWRImSr32sCxn/faYi3F5MjQe6whCMLNtq5Z
         SHZX80w12WUxg27Yb5f3EhQqM38vuk4EuoLJ87xGbYQzI74fYySlK1T82xuYRc8sBjtv
         lkwxz6/5yGHsVVfTo8eWKQpQ3Kb8kooZhNSSbf9cnPIH1XIJNAQyMPgaV+U7MsNKATCK
         k9cavVwfox3bdCpetBKZssKF1+1tnysmotm/mdo0mUSy32NMiadJ4VY999vDYCulCk0X
         LcQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:organization
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=79GQQ0cFYyzqroi5K3YYgMjHveNptlNDvmRDmJWfUZE=;
        fh=jfQADy0Ul463fYUy34CF8DHdw32czI2xScKKQScbNT0=;
        b=Rzx75GsZ11rlDg89OghUdi9nvs8zTsRhQHOO/8ireKIwz4zuqOWXX6Yqqt//05a2Qe
         nYrRGlYFyh299eiCgMqu3PGhCtHNeOrKgtj8lx1TKKCDESY/0PWIOhwClXrlj4LVzx++
         MDp0IWthviLoIDaPzdpAo4vE892HoFheRvLcn/6QgjYht41Jc64PkwTorKXyQSNHuYyC
         0Jbq+E5R4VV+fEFZDdRlZ4v0T65eWnRqXdcviIflmQoZlM4Aflm6FjxPQ7bov0n1bXqt
         JsydWTyCSh2YhxZFfttFFa4vxKOygm3W8TWOLjAwuaLpdxXQxX588A1VKyazXdWIfg0s
         APNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="fwCb0/jz";
       spf=pass (google.com: domain of dlemoal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755827970; x=1756432770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=79GQQ0cFYyzqroi5K3YYgMjHveNptlNDvmRDmJWfUZE=;
        b=RgP9q/mylqTMFB7tcHfRJh2H8HWwJ90Xzg9lu1nxRiGFLw52FOoY60WVEz4ojaBC59
         8YCZr+1WMdAIRtCtRd42RUkYqEIrYzexpsTgsLhDyeMZhnGQLsNLBx2yvFESa+1d+PFT
         kzSi5yHIcCyQYahN/OuNY4I5JYIVfCoB5tnGgJcPXpx6+0dQgSU7S59qh9O2QuuhTXaS
         vm55Ickl6SP1hJjOx6tdfTuNJh7p6IvHx/uHIB5IxOfDuQLWvw9ITnoKhra/vsRPMJmQ
         rjmlwnp8aXlV1joHBd2RlVZp883tMxP4f3YlXSi8rtWnhDMiM77yajXIAqADCj3M+A0P
         ueBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755827970; x=1756432770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=79GQQ0cFYyzqroi5K3YYgMjHveNptlNDvmRDmJWfUZE=;
        b=ExMbuRz9dKYVimUGV1GcSX1pYZPhtc+6GgpjojI4/XWMDAZ1Lx+9n3936xpU0kMo83
         eSE88Oi2C1d7oF4sCzvBNmgRRPHlXZ4OY83Iyok/wxohpaVCh/8SBscoqg7yqB1w0iqT
         CYJbofAHkrGM/S9/elXhEd4LEPBFhBABPh8RJTXhee+FF9HNKolizj407+Hv6NCKKpj6
         KOT2L4xB/gRiSZEZYeRA/eyaDRW5oFd9F8EG5EsGEJRE3YIhvFES1bWAmQ2PjaDpHMpd
         On9EIJGW281OtdeDAvVxPoLyQjQYnPCnKC8RvvTrA1uyaeQE9fzBKt2clOZfenyXd/Q8
         L48A==
X-Forwarded-Encrypted: i=2; AJvYcCWv/9xqml+zLqoVSw9hat+ykIJdDdEl4jCi8Ug61Se6L21OFsumvME1CcBoy3spSgHYsQDXog==@lfdr.de
X-Gm-Message-State: AOJu0Yx0Mya0F2HVUxWMEa6DKBQiz/Z/JK3YuA85NqzrScD8UobsiOYP
	xtFSg+31uGGey65KLGOKJuKU9t/oj4p7TPVbXH7t+Dbkuq5KNosuXKQu
X-Google-Smtp-Source: AGHT+IFEaV66MktJNPGJujd02Hm6pM24czkMwJ+J1v2VC5En+o+Hg+aTEAhGXJZmxljU+ZvEVjAlTg==
X-Received: by 2002:a17:90b:815:b0:323:2607:f5a5 with SMTP id 98e67ed59e1d1-32515ec659fmr1581066a91.26.1755827970190;
        Thu, 21 Aug 2025 18:59:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmKC2A7yg5fs2+MiNhBD5pPOawWS/XGV2eaKdMYWhhkA==
Received: by 2002:a17:90b:3bc6:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-324eb7e8cf2ls1982713a91.1.-pod-prod-03-us; Thu, 21 Aug 2025
 18:59:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAXDNCwn6ienwYdV9TKLq/pWIGzZURbKyDsqJTTtORQKcM+ibZh3JXEiKVFf3A2FagpEztTmMjYDg=@googlegroups.com
X-Received: by 2002:a17:90b:1d06:b0:321:2f06:d3ab with SMTP id 98e67ed59e1d1-32515eab619mr2078572a91.21.1755827968564;
        Thu, 21 Aug 2025 18:59:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755827968; cv=none;
        d=google.com; s=arc-20240605;
        b=d31Llk4w/OlZ8AczVoveSrx6qrKRBxSsCyW/yyZo8hp7sBvJzAwXGtpYhqcD/pw88w
         An5d6kCCKpji1nt9Qt9VOuPfFkyKogfVv5adaBBSZrUk/7WiWEAj6r/bi+UHWhvXleC7
         uG4ExxycKRQTvL6OiDjuVhDF83JvGVQPDYnfEae0lSNMRTg3LjMfg0wpXMPmOfDsY6LT
         ne0adsly1qKfvyRtV/qPTSyG49r4Bn4xEmS3/dlKjgxQw0PpahMkdBVUjC9oCJ9MVlpO
         TPNPr+oXUXdphJVeH4SuNP6lgx5QT2o6v5EVBSokjWfXtiJ6qS4A6EbHRk/QNe3AB3HE
         26VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=TYwcfR40TeWsfT3bxGe5ccvVRM+x9ilYYyOeQE763K8=;
        fh=5d33eUqZhnjKuOEMCh02bLvMmuDu/YvoDMUZh+hQz0s=;
        b=I6YEIg/NvnooCVw9RacJX3G2ErhcrbRuuSb7kRzIjtiPqorf9RenEcx680Kf1370e9
         d1kvPfhACC4mDSpVvmupoEuUc9610xLlz8clVQlD36IxBW3Cq4oL/Oj4bV1qQmlJPwF0
         j0IwfQiLHmvUzG6qhXWxtSM5doLdYQPGvQ2DlG+7CNSiHYsyjSj0t99Xv6lqzbJuyvxO
         e+YdQYaO5kTKmZjO9IK2EEyyVxarh1cl5wp20BhFnpbdxWDPwKw5wX62Ym/qk+N9/JcB
         l5SgfYNUUUvpFj2ZmHgo1EO4075aIt3jOQHQSFIzdZI6o2oT9DnZk+QWty61VRWUXr/n
         vVVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="fwCb0/jz";
       spf=pass (google.com: domain of dlemoal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f80d9c15si107974a91.1.2025.08.21.18.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 18:59:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlemoal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BB83A5C6103;
	Fri, 22 Aug 2025 01:59:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0940C4CEEB;
	Fri, 22 Aug 2025 01:59:16 +0000 (UTC)
Message-ID: <3812ed9e-2a47-4c1c-bd69-f37768e62ad3@kernel.org>
Date: Fri, 22 Aug 2025 10:59:15 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 24/35] ata: libata-eh: drop nth_page() usage within SG
 entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Niklas Cassel <cassel@kernel.org>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-25-david@redhat.com>
Content-Language: en-US
From: "'Damien Le Moal' via kasan-dev" <kasan-dev@googlegroups.com>
Organization: Western Digital Research
In-Reply-To: <20250821200701.1329277-25-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlemoal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="fwCb0/jz";       spf=pass
 (google.com: domain of dlemoal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=dlemoal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Damien Le Moal <dlemoal@kernel.org>
Reply-To: Damien Le Moal <dlemoal@kernel.org>
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

On 8/22/25 05:06, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Cc: Damien Le Moal <dlemoal@kernel.org>
> Cc: Niklas Cassel <cassel@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  drivers/ata/libata-sff.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
> index 7fc407255eb46..9f5d0f9f6d686 100644
> --- a/drivers/ata/libata-sff.c
> +++ b/drivers/ata/libata-sff.c
> @@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
>  	offset = qc->cursg->offset + qc->cursg_ofs;
>  
>  	/* get the current page and offset */
> -	page = nth_page(page, (offset >> PAGE_SHIFT));
> +	page += offset / PAGE_SHIFT;

Shouldn't this be "offset >> PAGE_SHIFT" ?

>  	offset %= PAGE_SIZE;
>  
>  	/* don't overrun current sg */
> @@ -631,7 +631,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
>  		unsigned int split_len = PAGE_SIZE - offset;
>  
>  		ata_pio_xfer(qc, page, offset, split_len);
> -		ata_pio_xfer(qc, nth_page(page, 1), 0, count - split_len);
> +		ata_pio_xfer(qc, page + 1, 0, count - split_len);
>  	} else {
>  		ata_pio_xfer(qc, page, offset, count);
>  	}
> @@ -751,7 +751,7 @@ static int __atapi_pio_bytes(struct ata_queued_cmd *qc, unsigned int bytes)
>  	offset = sg->offset + qc->cursg_ofs;
>  
>  	/* get the current page and offset */
> -	page = nth_page(page, (offset >> PAGE_SHIFT));
> +	page += offset / PAGE_SIZE;

Same here, though this seems correct too.

>  	offset %= PAGE_SIZE;
>  
>  	/* don't overrun current sg */


-- 
Damien Le Moal
Western Digital Research

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3812ed9e-2a47-4c1c-bd69-f37768e62ad3%40kernel.org.
