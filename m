Return-Path: <kasan-dev+bncBCJ4XP7WSYHRB3WWSORQMGQE6S4XP4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B7832706BD8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 16:57:51 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ac8393dd5esf3986041fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 07:57:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684335471; cv=pass;
        d=google.com; s=arc-20160816;
        b=BmqfeE+fc9ACOwmpW/PyrbbchduARVPAY5zwrX0K2/n7MgQW+lDLOXGxgw6QFwWl2j
         TiS3OmegVNrk6aGMvwvRr/ZsCLyRkDN3VQHRqXlF0fSae+ZL+lem4HY9jFyiVZujI60V
         V9zC9PufBfGepw82eqHrQYqDbEYU4iYYwkvLCh5hkncKGNAKxOtyY1JVTcojCG2y3KCM
         2xehElkdEGGcM7fUyLk38p5UZz6lDVqzVSCXwBacgixLfgw2SKhHIVS29h8/F0i3X1Xz
         KS2yMq5vnftLXrnlzHg1oBsTxdoWwcuHMqAGWcmQ1VRA9HyjeSFCqRs7OvNB6+Z+CF9B
         fwUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=HgadWGWRBMXDVbST7Z2FIHm89AcufN/tcX2JWUy1MRo=;
        b=gvUsuWsmjBn9In2H/qzPlYKUPBuA25i9bhBPewkrlR6TOqc9TxsGwWxNebf/rItc4g
         6CXLr92DnYUzoTH7PWU6jyvmIGb0lIk3YrVlgRjkOy0yEJ6psHM5rKYvuvLqeY9Q+IBi
         84+pBsoTtfxUQHemoJQQgrwi40gu2px8b/la519VdopkfsUWDuBTlBSndfoxlB6OVjgb
         3mdz6I9UvGpahxzvoUAY5hjnFGzftozeO7/1di5hr0mfUuWa7KrdagGfp3FyFpsX7TpJ
         O+5KEXytnFLSffZ2poOaIxIWRwTK0S9nY8Xtitdh1v3P38tc7+ejfy0YdTmIesGkku6C
         34xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684335471; x=1686927471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HgadWGWRBMXDVbST7Z2FIHm89AcufN/tcX2JWUy1MRo=;
        b=eZQZ2filCStzemjDJjNWABzvkYBTQMvS9nn+fyL7suMpcx/sklBhldFcawM23lFDQo
         +GuuLagpQ3/bFLiZsP7lxFNh7lPQiyj6S5AEwUcAiOYszQ+ckSn01ut+LeqTmr7kaHJo
         rYPfd4zwhk/DPmb8B7IfIBhNu1xOc+ky9xJlQ3SNwzfgrP/O6T1K4I7/GdJIXMTWGgcC
         eLZddEW5VPrzsRsRu3J0ZtTscxOT9E9f3NE4NdVh7gviEnDcPvM2PqSuomQ0Mstw3D6t
         kJOCeo5MBfkHrQLDoqzVlZsIoYUgGJO81QkdHVSJaEd/vW91x0V+x/nrl9zC4HeyiGuT
         ycYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684335471; x=1686927471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HgadWGWRBMXDVbST7Z2FIHm89AcufN/tcX2JWUy1MRo=;
        b=BC3jljr2cYVzxylqjVh2vk9EsLza5pKqvJ4QmYQLG2HgQRSmXkK6cFGiAoLQXP0BTJ
         P4tN0CjVWQd9clZONWqNW+qiqbFevcEdwkCQB5Eb8llnTVoKv3vdXFkgrGlqNDY1Hdpg
         QRLZ+L/Mz7SBOEDt4A8UiY6a0XQPVrEHGRiFoTsKyvB7ARD1IQKrOgl2ZDILeTQz7PyD
         8lHM8TRC2ATvhtaHO4kL/Nu4ch+z8/LoY5LzhsEhHSej2LvEjGHBhEfuiGXYy9bW7edw
         9ba+da/IduofWOJxMyaShbRqxdLiKoMT8x6xFXist8Ghi4xIeME3xndN4fcNwcGBAvZv
         BWyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwf05y9zEUT5Ku7k9hs7rvlZCs8tnWGRluSjFsbZWoHPHVtPcmk
	5b1hDZ3QPmS6Nx57kF4Z01c=
X-Google-Smtp-Source: ACHHUZ71MkbnHVQG7Ji8pPhXhzP6VW/LRZ4aZE9+qeG6/BwCQ4OZhtNRa0npQj0wgFn4wEg3WNw5eA==
X-Received: by 2002:a2e:88ce:0:b0:2ad:990f:de57 with SMTP id a14-20020a2e88ce000000b002ad990fde57mr7603967ljk.7.1684335470803;
        Wed, 17 May 2023 07:57:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a10:b0:2a7:7ca6:a43b with SMTP id
 by16-20020a05651c1a1000b002a77ca6a43bls786602ljb.1.-pod-prod-03-eu; Wed, 17
 May 2023 07:57:49 -0700 (PDT)
X-Received: by 2002:a05:6512:4db:b0:4ee:e0c7:434d with SMTP id w27-20020a05651204db00b004eee0c7434dmr330083lfq.51.1684335469076;
        Wed, 17 May 2023 07:57:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684335469; cv=none;
        d=google.com; s=arc-20160816;
        b=KLSwDKu83gh/0hcHU6Kz/m5CUT1LoWZSjAt+/H1NvoV4jwRSdY6LXmpeyZSaLifqMy
         Ez4cZHb8oujb9uph3Plsw5wtheJbrK2X6ggVlY+8eD1zLgJIXHwM5mcWrICF+DPZa2Zm
         ZidCEC/yowK27Hb+uF/zNe7cY04yt6CSxGEYC5Aq/w66s+3LS48vjyaYaWnGvRuXLIWS
         h3kawllgN39BdMHebluMr7qaWX77aohX8ika5nWo+GruCjhdkw7dsrr6vockZJNEE2IQ
         e87JQJpfv63nMrYneOHrWaDrMcJRgz+oB7cbvKQLukBfAurOPNp7Bcg3NLVQ8Fcfxubp
         Q1vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=+Zwx//lOdg6V9D63MW28GsqyK5yhFT+5Pyw49IqDxGo=;
        b=fYH0jQM7gf9LoRuuLwXCvT1XxZ7Vyx7MDnGAh+l8JOa9z1rFPNh3NlHY3c+FmUljUj
         91DB0my+wQ4B5KlGYkoZef9v5fbcLbmPK+iQL6MD2tF+JIwAyP09HOQvpW2ipWMWUIgG
         W4lZQvJiAJK0fFdej1w2HYeSiDWz0e1FdMxmVazfEyZJyuzM9LFEZj0lO7eWgJMja1gA
         X5QSlkIGqWcl8rBFzBH86YzNMnCNfTOF7Q1cQqXAU14aUFpY6XW01y4Tit9Wj972TFam
         SKAJCqpywD6BBNFYa0SOMziMNkMZxWz1pghaPxc3UxBTCFfXYWBu450NC5FgBdR/DuLB
         IwBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h7-20020a0565123c8700b004f24cc1c786si1548194lfv.7.2023.05.17.07.57.48
        for <kasan-dev@googlegroups.com>;
        Wed, 17 May 2023 07:57:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 620641FB;
	Wed, 17 May 2023 07:58:32 -0700 (PDT)
Received: from [10.57.58.217] (unknown [10.57.58.217])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 66E9D3F73F;
	Wed, 17 May 2023 07:57:44 -0700 (PDT)
Message-ID: <9b9e7fbd-6166-09ce-9aeb-be28e51eaf10@arm.com>
Date: Wed, 17 May 2023 15:57:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH v3 1/3] mm: Call arch_swap_restore() from do_swap_page()
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
 will@kernel.org, eugenis@google.com, stable@vger.kernel.org
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-2-pcc@google.com>
From: Steven Price <steven.price@arm.com>
In-Reply-To: <20230517022115.3033604-2-pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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

Reviewed-by: Steven Price <steven.price@arm.com>

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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9b9e7fbd-6166-09ce-9aeb-be28e51eaf10%40arm.com.
