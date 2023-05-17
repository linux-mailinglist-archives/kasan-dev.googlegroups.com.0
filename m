Return-Path: <kasan-dev+bncBCJ4XP7WSYHRBBGXSORQMGQERHSP5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 92EE1706BDD
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 16:58:13 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-4edc7406cbasf574111e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 07:58:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684335493; cv=pass;
        d=google.com; s=arc-20160816;
        b=lml+88ea8qJqMhiMVCzpFmEX0bv4zA4As3JHl7BCh+rZCEASKiBaNP1BpYXY82Puaj
         jBNm9solbjA7p3pXmvK/Vi3/uSFNMhLA3B6qLnAGUMgukiWPOsmviXmAvB2cAWMLtxBe
         R4C0rQEjwLpn93JnvP8ENiyPK/h8Qto+oyxyNxco99QK5bEKys63mcxLVNxUNFX/BV+p
         E1hhDAUc/q7MCp1fdIu+iOp04ZisvK0cUxtps4I4nu+Dl3gkcy/9lhQtxgxjem9/mcVB
         iI9d7ch6HHiKWNqzaHiK9ZF3ob8pA6/LoXCRJG2bXHSRl9GZGkEUOEOjDbIzlRRrAusZ
         YCpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=JiPcRrJbHGSY8WiU15gcBhBFehhI4NDqctMs06QbbfA=;
        b=wvXV4xBp2X0yBepC71WhbLOBPdZwTlFQl9jiui+d/kBHkhqMIP71b3+a/+mg/YK8Z/
         w+Mtn8zNfVu2sxW+HuRueQe8h40/U1juMhweoVSEzj7I6bJ/HHIyIml/60OKoYoAGazl
         DDmjthnrsN7Cg60MrybrmUMjbzwCxVqw4kte9tk4rZjV2CN6Nx5fHTjKpnaiRR0Q2V1p
         TK2HhBK3vW9UXNMHHhdTER5XJm7gIFCv72Tl/uL6RAG8rAB6bCLz2ajb4j678kx1ReXz
         +jJ6PucavCwtdfH7Tv6YXCamgjG/Y1mqhOnSBat+jSTzorYjYYPtKdqB3XxhkWd7pNf7
         oylQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684335493; x=1686927493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JiPcRrJbHGSY8WiU15gcBhBFehhI4NDqctMs06QbbfA=;
        b=IWhNC3Mg6Jr9sCArw/koGtqs2mpppM9pPbhQXmvc5SL6PjMIZrY0hmkmuTEiFaMwqa
         T/Ps2fzhnPTsjFxJmi4g+K04tXZHWSA7aM9U7wjttskrpudYT9GywxDvBSKZTfN6l8fG
         UYEsPrqDtteXj8g18KT8IdoaZ27p+nh8WcqudxHrqjxgD7KjT++ksRRMOo31Zr/h+Nfj
         ktKEpuDYmRhYowjvegiRQp38l3aWI4waHQ+s4TA/UlDhKy2A+7xt9oNvurP5eTIfAoD9
         uLcYocDJLuscvQPq1l+6wNsfroRtSHZSYfv3TGb4ozIB3NGjroi1oSJkws98+gKKZx0x
         j4Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684335493; x=1686927493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JiPcRrJbHGSY8WiU15gcBhBFehhI4NDqctMs06QbbfA=;
        b=Pfb0j1evL8K5g5PUwZy9VcJLjvIxnGr7p8gI4cP8GC8qoVA7wOSqIBM5yH3IK3/sNE
         QhKNXhZXDURedOBbCptOaDxVyiZ+rTe+/KT2PImc8dM8QXsopIn2DHw/L3TfusB1mFW+
         bgp+atcyvjwK1ZnheKbNQrhyRFY+PPReLluAfUlnxlMZ2sOsLoidWsKhhzRTuoSJOz8O
         e7MhC9lAdiegNs+84I7KM6g4J3AdoJfkMAhgcudUNIbTwqXAh9zIDCyHRX+eacpzrPJW
         Lxiye9YWIUv8YslqWA4yYrBnWnqyr45WXyhqIo6lfLVcOB1MausZkCtiIhGJa7fJtPd1
         Vq1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzM4vJTchVL5hm7gM9vQ7JSDznMnHjOLmvtNa2QeL5u0qrvv01r
	8tSy2BQEBJhV/q3f0sQqwB8=
X-Google-Smtp-Source: ACHHUZ6u6U+c7pW8Q5HPFrgf2NGzbL9jzWpjFnQ2rlfyXSLFQaF1RGNbxlUcOQmLG8SoKOQyso5a2w==
X-Received: by 2002:ac2:48b1:0:b0:4d5:ca32:7bc5 with SMTP id u17-20020ac248b1000000b004d5ca327bc5mr231066lfg.12.1684335492525;
        Wed, 17 May 2023 07:58:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9945:0:b0:2ad:a1e5:c894 with SMTP id r5-20020a2e9945000000b002ada1e5c894ls162656ljj.1.-pod-prod-06-eu;
 Wed, 17 May 2023 07:58:10 -0700 (PDT)
X-Received: by 2002:a2e:900f:0:b0:298:a840:ec65 with SMTP id h15-20020a2e900f000000b00298a840ec65mr10506288ljg.36.1684335490590;
        Wed, 17 May 2023 07:58:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684335490; cv=none;
        d=google.com; s=arc-20160816;
        b=gLad1amPybehWVkb2LYNyyQjDN2TKRx0r6RGbXh1IkK1BvLM3HZx6aRaiVmjB7KvDa
         /G0kCb5wVr3XYerlS8vBemAXLvzoFkhaJoJgo9SD+N/LAyGbHY+FIbKE+rUOm3b3ecu4
         4PxEsjCXX/LLJK5I6wEhMnOtmcP607F25e5ImqCnEuCBOqVy8G0hXOX7/XZRrPypD6fq
         Nsg3s2QQNj8NKwV/M12aeXTlNCgdV/+rRE52Nyr8KF65Q7Rm84g0UTjVWyaFL8To0Qvs
         0UYDy2UKm2ZTFI1tca/YVLCl96AqName/G+xuAEYz2yz6YgnjAlhx1uXDfPHfXGHSkCN
         d2dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=td9MkxkNf87qbPdhiiQuWtIT/WbGO8lv0aeODdr9VrU=;
        b=sk+lPefU1OsTy39xLlOqzMu4gk+V7+a1J8UY4E1TG4MBN/XWv0dRx1ekkIl7QSFEk8
         jpAjl0wl+NpEvQGwApJAyhusjJHhQ+T8CoaH93OTLJxP210W7ZfXjorSv2+58bmV7x6p
         Tifcznq/u02zrYMXFrT++3vTgeEgaIhiielTv4vr+O9pRFnWlD2PJBpCo9zhumpdBn4y
         ZEf1cUQXzjvANc2V8TrdsERZkayXxlgbh0YjDApgdJYjoGQJi9rRORsskGFwx+sfDxRy
         Z1ra7bxj5Cj6MVLQYhW59LSAXgoOQR5sUk36hWObxub/AHg3I8+GopJ5yLmdXCJbhN6D
         qsGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bx43-20020a05651c19ab00b002ac75541fd4si1949525ljb.0.2023.05.17.07.58.10
        for <kasan-dev@googlegroups.com>;
        Wed, 17 May 2023 07:58:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2B29E2F4;
	Wed, 17 May 2023 07:58:54 -0700 (PDT)
Received: from [10.57.58.217] (unknown [10.57.58.217])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2FEA93F73F;
	Wed, 17 May 2023 07:58:06 -0700 (PDT)
Message-ID: <59cb3075-3747-7478-58e2-534b00b5daec@arm.com>
Date: Wed, 17 May 2023 15:58:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH v3 2/3] mm: Call arch_swap_restore() from unuse_pte()
Content-Language: en-GB
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 "david@redhat.com" <david@redhat.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-3-pcc@google.com>
From: Steven Price <steven.price@arm.com>
In-Reply-To: <20230517022115.3033604-3-pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: steven.price@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of steven.price@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=steven.price@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 17/05/2023 03:21, Peter Collingbourne wrote:
> We would like to move away from requiring architectures to restore
> metadata from swap in the set_pte_at() implementation, as this is not only
> error-prone but adds complexity to the arch-specific code. This requires
> us to call arch_swap_restore() before calling swap_free() whenever pages
> are restored from swap. We are currently doing so everywhere except in
> unuse_pte(); do so there as well.
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a99ae05d6bbc4f

Reviewed-by: Steven Price <steven.price@arm.com>

> ---
>  mm/swapfile.c | 7 +++++++
>  1 file changed, 7 insertions(+)
> 
> diff --git a/mm/swapfile.c b/mm/swapfile.c
> index 274bbf797480..e9843fadecd6 100644
> --- a/mm/swapfile.c
> +++ b/mm/swapfile.c
> @@ -1794,6 +1794,13 @@ static int unuse_pte(struct vm_area_struct *vma, pmd_t *pmd,
>  		goto setpte;
>  	}
>  
> +	/*
> +	 * Some architectures may have to restore extra metadata to the page
> +	 * when reading from swap. This metadata may be indexed by swap entry
> +	 * so this must be called before swap_free().
> +	 */
> +	arch_swap_restore(entry, page_folio(page));
> +
>  	/* See do_swap_page() */
>  	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
>  	BUG_ON(PageAnon(page) && PageAnonExclusive(page));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59cb3075-3747-7478-58e2-534b00b5daec%40arm.com.
