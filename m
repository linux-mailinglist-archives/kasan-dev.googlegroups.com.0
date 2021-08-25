Return-Path: <kasan-dev+bncBDDL3KWR4EBRBH4KTKEQMGQER54UIGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B0E63F7BEE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 20:00:05 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id d17-20020a9287510000b0290223c9088c96sf261078ilm.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:00:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629914399; cv=pass;
        d=google.com; s=arc-20160816;
        b=K1pDiJ8xTH73I1t4YHDaPB/Mcn+7Etk1wC1XK7kKY/2lFM9zLHSpb3XfFuhjkh7ZjU
         UplQEhyQCOd40FSSN33qOYm7ZhhUhSso9azynO9E/3701XknK4xKMi8HexMK0gTza97A
         gNjWYViuQ0CdSs74r36zwk1zK8pSiSHsui4OdL1mcyJcQSRPDYjhRvyajfow5bsr6vCO
         739F52+YEQ2DALCNOlgxfjMc3PxLKPZwglyxg1wJWI9U6Ossl4cQ+y1aOGs3bpMHea80
         IXYQMNIJyNBdgG68bl4JIp06mME2ZCWXYSjqoRfeBobz32RQvX4CXC5+1alVuDMRkiUB
         TSFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FuqTtS/n3vb/nIyG0oyom39CsRx5H7tjzkpKmEULSZQ=;
        b=mnY/D9v2QJ3vdYwwkg6s7JpoEe12eX4heG1jQLiD7wgOQMa+8OQsSScG1euIFXE38G
         DItjfDnBGRHLhVsvXbzluVYGkGb+9A0dsuUhq2DMmc/d7+3y+n//sSaWbSBU7ByHh5gZ
         a+WEDWltJ/KKRX+FxGMiu8kTT87k/0OjRuI6w9njeZUWgrTtbp5FSKCQtPrX0DZrtz35
         kAse1fd6lguR/ZDUXPZKdyjSPHUUod0JmBJstNRCRZ1/aXXxGrQkMMI5Nvl3L4K+gZNq
         ieuXh7936FwOPlySsPZCrMWr+8ICkc7uI6plmlwOAkpVX/y8W5HH3p0aQ24tLKiOBvmK
         vAzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FuqTtS/n3vb/nIyG0oyom39CsRx5H7tjzkpKmEULSZQ=;
        b=biqUArG+nZTIGOrTlL43kFkBYPHVDxpxFoka6SqsAAPsUj3Kqqr8czFNM4Q+/qDvuQ
         hC8nKK4iy0/+ImXr2jLWghqKlb9ZIsAQ3J3fwz8wZd0rQ7WnKQ6pVO/ESFvtew7VnOX7
         gg45EaA9lNCJBg+1P5EIizXi7ETJ8+VBJW0a5Uu3qioce+feQ2n8et/mpMrH0JIRcHIY
         gTDZtTputOD4mlAiP6ieD7NrwDvXatCzLVvgaD9QnzlW6p31u7DyG0tiQ2h2ouZIB00G
         pG28FleXKrGWFGtjQJecAzAWzXf2cP78hV+NxkrOsMdnKeOO+XfxpHd2UUMoyIT10pig
         Z8pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FuqTtS/n3vb/nIyG0oyom39CsRx5H7tjzkpKmEULSZQ=;
        b=APCOiTmCBL0y/ClSADJDxiTe1viOKfepFxtzrA0rwf74xD/TI5RdWWV4gxgqN/BzPH
         EN8qhW2+7JpamjO2NQSooxHREiyv5qSpXj57AAKZF5Jg9V1c/4J+iOcXWj5X+PU3zyfY
         ElhMjYWRskkTg3SXRl4qRLXHHDLd5D6NcC/SHqygZ9J5i9jWhWiWyRruYTtx67kJuM8W
         ysw9rYtvODN43Oa7niQQ9yM8X0bnbYGEe25JaEWaGvHB7susRNuZqU2QJ18Ofc+zm3zc
         aX11Zc4HnIBxBaIUVb2noxiwBcCEdrdoHP74e9SAC9MkBOjAAzaxGW+xrNGn8OR4xJxL
         rgNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ihrHQTrErXWWV8u07BhZfKabuzwrLvQ0v9wW71/Dez3Slvs+M
	WaWUTdi2ZjnA4FwzfcKX7EY=
X-Google-Smtp-Source: ABdhPJw1u2lkoBzbgiFkSlGebCTrYCer2qf4p1oUmDxaiCPmHDwZlaOacoGP+IR9+0CWoA4R9T72ew==
X-Received: by 2002:a02:c502:: with SMTP id s2mr41025542jam.135.1629914399244;
        Wed, 25 Aug 2021 10:59:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2714:: with SMTP id m20ls436717jav.6.gmail; Wed, 25
 Aug 2021 10:59:58 -0700 (PDT)
X-Received: by 2002:a05:6638:168f:: with SMTP id f15mr40704976jat.85.1629914398862;
        Wed, 25 Aug 2021 10:59:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629914398; cv=none;
        d=google.com; s=arc-20160816;
        b=jL272u9gxV8iNIlhE25UcMWWnz/GpA9GQea4jCX34NoG60Mef4JOGAslpLp1Ep15Ce
         EAtu80ScMC+tbx7YvHLQoR1OHeFYlh+KRouABNM23oUwbvTzdALhXIAQpOabJz6TAChW
         5cvErY7kwDuAKozi2LSl8XfMOrlS0biAyessJKtS+oxHk2MdfZOYpGXrBnnAkAxcBJSo
         ow6c8arxuAUo/M9CZT3VktA+2JnHt1Le883eZTNgDD/9exseXU0X5r9WetHyUB3peoy1
         NbeT7HWmB2EaztygqG8lFKQtZ+UlWzzs6SH9pMEWXpSu4zEVWOseQg/+mkwXPk9QF6RY
         ue2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=mh/slETS+1gAiRqlNVjAItPzjl9UllY6HORnVFaYjYA=;
        b=FyBwrMM0gqnTyvfx7UhLca5f5tG3QKYU0OdJd1McoJI0shYRsPiB56oGebGWcmZXmK
         krD5nG+W3AnCFhg3X86RZ8sDcYgcb5fCbwiWwvPeOU6opxa2qShdopxR6B6iVwNx20tv
         3oDR3ApP77Q/73aEL0dIdz1+1hFtNRSCHVMqGq9s2B0dl+ZH+IHxlDfM6dsbtZ3l9CM7
         LFHMQBQl++UGpE6HeDsV3kB70ynheGEMctswtVjvXioLhPVN6QcdVtrL/Ai1PvSyf2Kl
         ykU3GNjc+2krXBZAxfJSOyAxoql9W9zhmml6CQbktpnu81HYAUn4i/pZfkmGmcPmIxWY
         Skcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l68si93503iof.1.2021.08.25.10.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 10:59:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7F4EF60F35;
	Wed, 25 Aug 2021 17:59:56 +0000 (UTC)
Date: Wed, 25 Aug 2021 18:59:53 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, elver@google.com
Subject: Re: [PATCH v3 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
Message-ID: <20210825175953.GI3420@arm.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-2-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210809093750.131091-2-wangkefeng.wang@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Mon, Aug 09, 2021 at 05:37:48PM +0800, Kefeng Wang wrote:
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d5cd52805149..1e8fe08725b8 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2238,11 +2238,17 @@ void __init vm_area_add_early(struct vm_struct *vm)
>   */
>  void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>  {
> -	static size_t vm_init_off __initdata;
> -	unsigned long addr;
> -
> -	addr = ALIGN(VMALLOC_START + vm_init_off, align);
> -	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
> +	struct vm_struct *head = vmlist, *curr, *next;
> +	unsigned long addr = ALIGN(VMALLOC_START, align);
> +
> +	while (head != NULL) {

Nitpick: I'd use the same pattern as in vm_area_add_early(), i.e. a
'for' loop. You might as well insert it directly than calling the add
function and going through the loop again. Not a strong preference
either way.

> +		next = head->next;
> +		curr = head;
> +		head = next;
> +		addr = ALIGN((unsigned long)curr->addr + curr->size, align);
> +		if (next && (unsigned long)next->addr - addr > vm->size)

Is greater or equal sufficient?

> +			break;
> +	}
>  
>  	vm->addr = (void *)addr;

Another nitpick: it's very unlikely on a 64-bit architecture but not
impossible on 32-bit to hit VMALLOC_END here. Maybe some BUG_ON.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825175953.GI3420%40arm.com.
