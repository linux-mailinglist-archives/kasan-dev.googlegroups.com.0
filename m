Return-Path: <kasan-dev+bncBDAZZCVNSYPBBS6X66RQMGQEXUN5B2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89CB272282A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jun 2023 16:06:05 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2562b26cfafsf1647193a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jun 2023 07:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685973964; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3Bc+xW3NGojRDMUM3FZn6IiWHYxE7G+qYzRv/NtPqUXMw/Qb44qmH3FCvchNLTvYC
         kmI02YrWZqLVzs+xzhIGhvNbeV+v2PxlBpT2iwJX5j01jFymz48sbAv26/Lkit41b5Vi
         dSHR5TPqVrr+jQ9dvRfA0qck5gfA4s4jXh2SObhvdJaspuRR+CRy4Qgew4AxaiFC/Phk
         LMBPy+Os1dO7l0C0LP7ELOE2x27TcwOF3qiKVTIQOTYj4knHIj/QBRf1hLASlxWDJgVE
         qiRf4gG+8wUFb3d9DJuDm3LyakCcqXjyuvhPUjB+i9hkd48kTxe+u6OLMyZPnbRW9c6Q
         758A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pGg2dhVsAzAS1w/vbSP+k56tUWHtnDos3s6IBpq8s6o=;
        b=0cHsvaNcfviKjrSLSmp3lqcgX+sg9yc8Z7kf8RL06LCgnFdTALV/HnC6nWZwoPFWU7
         ibuZTEPccXuxDNiaUOrsVBf7yI+KNYWiTPALlLlePDXu1swB+vKDXhswzWc0nAV5o75P
         Ks8hACJ6QnUcac0wGG+RjvolaosHSR5IxBhK4Rk2IvFw+ZkqPl6KwFFohKah4sqBGDNB
         6KT7/knOq6ywvxZnrvpR9AF3FJ6UGME20OZJeeLs8E2ksZzbbbuIvUvrh/DpXu07KL5K
         2Ok3yAtURQeEbvUxy6Cq+2jZ+dTo85WJsylYR8fUcOjiWznAC/MxgriyLEZvXxFBD1TV
         XBsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P8rvPmfM;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685973964; x=1688565964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pGg2dhVsAzAS1w/vbSP+k56tUWHtnDos3s6IBpq8s6o=;
        b=q4aC/3WiiKwYaU8wgPcinF4ssO0+0UqOk7IypVpYV8UQv7zVrxYp59k1sSiguiNXB8
         Ar5juKnBc6tgyUQ/F55jWksaBZW+oeiDM4aLYD2saj5I8qbCT8ecZCUNl/EiiLfQbclY
         cZi32c6CG8uiMEvIM0uOxES9OC6JKDLhJG2Yjea8RnqYd9XYUb068k3uL2hXe3NxP5bB
         Tp3G3MH8RdvRAZhcLxRyYG0b2L+XRxjm6qLWWex2cPJ7MC1jQ2+9ec+G1WYNf07c7eD9
         eC9Iln3DszOVsgaav2EDX816cPWVjUw/IAToOvUXVkckmI+niSOzMAI+0RmN6P2FbO44
         zieA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685973964; x=1688565964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pGg2dhVsAzAS1w/vbSP+k56tUWHtnDos3s6IBpq8s6o=;
        b=gzxWbY1kVUfJ8vSBQwAaHkvnEaOcUDGK2MKf9d71VHTchuSjZH6NOYOACsAZrRr3di
         2R5Jet/AS77TSTNDCd3HxxeSKm5sc9NPaQKEun48pTPuZ+1mCeXdEti8frus2psCMIFO
         KXUaVqtGSRpX7K25E49UaPPzEkIlgPAPJME2mol9QmCp7LmU5H8LAC+HWLY/ic4gNSgR
         Z2oqA1VJbEasF3cGVvZmXploXjIypDxDvmtKGXJ86YRJvudEoRSwRGH7Lt73dG12OsbS
         5fyf+AR0FiOOcxk0Uw4t7tvRkaClycG35EhHvBom9M7uiCoiyNg+vu0ponuRA87BwBaV
         gUQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzM0HGpDk3rsR+tqH7kNTkDcPNfdBqbRFDcdpRGLevcd4GQsOao
	D1JJd7zKdf5aDMGR5kkQ664=
X-Google-Smtp-Source: ACHHUZ6qtFrE4udbQu2qnZoxSje0Lt9CFyLy9a/1cIUVjxVRdfmVJ+JtL+geGQ/VLZVd/teMK1++ZA==
X-Received: by 2002:a17:90a:fb52:b0:255:54ce:c3a9 with SMTP id iq18-20020a17090afb5200b0025554cec3a9mr3607555pjb.24.1685973963538;
        Mon, 05 Jun 2023 07:06:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c90d:b0:253:7088:517b with SMTP id
 v13-20020a17090ac90d00b002537088517bls2223157pjt.0.-pod-prod-04-us; Mon, 05
 Jun 2023 07:06:02 -0700 (PDT)
X-Received: by 2002:a17:90a:2f46:b0:255:63e0:1248 with SMTP id s64-20020a17090a2f4600b0025563e01248mr3939998pjd.0.1685973962764;
        Mon, 05 Jun 2023 07:06:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685973962; cv=none;
        d=google.com; s=arc-20160816;
        b=PcHMor3/l+auXyy/RBOZiV65H8lVIyBKZLk+tg2QP9ghapaeGzPprmuLUgGOcau7up
         vWpJYIY+Py7suzHV5YTOHuhbSJLL59O0CRdyY7Y7RBzvB0bgfiHAj5LZ5JFbeTUTlX4x
         ey4jrDMlW+ShZ0BhstnJMIHUq708PV5ciiuysUpV852IxGtiNbfn/XNaR6VjDCfhlOlh
         jf6hdSQwqnlRpOYZEPchr7SUUA+66R8xeGD6i7i324wmOLvg/b6ztnRZKoyWSqDAb+k2
         Y7wbg5E4h9VE+QTPAloDOaiWQ/E8OqMi+h0ggvfQOWtsgVDoGDbRUknl9eRlIS2uhqGR
         NcAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SEbMdkTYQd1XGwIQ1d9jIUEnt/7HRRl3aea4595yQQQ=;
        b=HWyKQPLE2DfwROiVHfPelWH/ez0k9w1RUvM/yxQlqgmV4Kw7zCBtdHh98DL+5ycW0M
         FDJ597fK4kCuBYBAAbJKEFZQicA4GYnPs2Egy0bE83Nm6NJP8Os7q3JUhWrbjXHXKGrL
         oTc3fYc1yB9iXoOo8p1YJ8EYG3VmTqMXqNHj/3R+7n5Xo70auavYLe2XSUUgjsdfkru9
         zk+3hiirWs07Afzz9Zk2FNSkTUsFhu43DgkCxsk91OCeH7Io1Seaw6cnE2nLi3BBVCf/
         +dvMbb+jDzc9Ol0HUKdsNdkp1+DzNj+J7bkFC3YK61eDBDzd7bz7rq0WrkMqiFmit5by
         yRuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P8rvPmfM;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id pw15-20020a17090b278f00b00256bc6ccb6csi1071620pjb.3.2023.06.05.07.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jun 2023 07:06:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0E4E4614A6;
	Mon,  5 Jun 2023 14:06:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43F84C433D2;
	Mon,  5 Jun 2023 14:05:58 +0000 (UTC)
Date: Mon, 5 Jun 2023 15:05:54 +0100
From: Will Deacon <will@kernel.org>
To: Peter Collingbourne <pcc@google.com>, akpm@linux-foundation.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, eugenis@google.com,
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
Message-ID: <20230605140554.GC21212@willie-the-truck>
References: <20230523004312.1807357-1-pcc@google.com>
 <20230523004312.1807357-2-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230523004312.1807357-2-pcc@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P8rvPmfM;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi Peter,

On Mon, May 22, 2023 at 05:43:08PM -0700, Peter Collingbourne wrote:
> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> the call to swap_free() before the call to set_pte_at(), which meant that
> the MTE tags could end up being freed before set_pte_at() had a chance
> to restore them. Fix it by adding a call to the arch_swap_restore() hook
> before the call to swap_free().
>=20
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c=
61020c510678965
> Cc: <stable@vger.kernel.org> # 6.1
> Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@media=
tek.com>
> Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d=
434.camel@mediatek.com/
> Acked-by: David Hildenbrand <david@redhat.com>
> Acked-by: "Huang, Ying" <ying.huang@intel.com>
> Reviewed-by: Steven Price <steven.price@arm.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> v2:
> - Call arch_swap_restore() directly instead of via arch_do_swap_page()
>=20
>  mm/memory.c | 7 +++++++
>  1 file changed, 7 insertions(+)
>=20
> diff --git a/mm/memory.c b/mm/memory.c
> index f69fbc251198..fc25764016b3 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>  		}
>  	}
> =20
> +	/*
> +	 * Some architectures may have to restore extra metadata to the page
> +	 * when reading from swap. This metadata may be indexed by swap entry
> +	 * so this must be called before swap_free().
> +	 */
> +	arch_swap_restore(entry, folio);
> +
>  	/*
>  	 * Remove the swap entry and conditionally try to free up the swapcache=
.
>  	 * We're already holding a reference on the page but haven't mapped it

It looks like the intention is for this patch to land in 6.4, whereas the
other two in the series could go in later, right? If so, I was expecting
Andrew to pick this one up but he's not actually on CC. I've added him now,
but you may want to send this as a separate fix so it's obvious what needs
picking up for this cycle.

Cheers,

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230605140554.GC21212%40willie-the-truck.
