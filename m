Return-Path: <kasan-dev+bncBCN73WFGVYJRBHE2SGRQMGQEIYBNBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 92044705E36
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 05:42:21 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-4f3923306d0sf211706e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 20:42:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684294941; cv=pass;
        d=google.com; s=arc-20160816;
        b=LnY5cAQml3VGTe06Kt2QdDu0wSrXYrbpI9T48dKRAlIEDNG1N7DnATZk1xT7tr/Z8z
         qyl1KZxqBhuV2vk5XLuXywwdIKDqy3SCFdsZe8txmpJ60fGPXnGrbdaG/VRPg/DCxZIE
         oKsw4Jk/qCgTUwJodCY6EClJ+jfl2V5UpGRTz9JwC6ZQKu1EGIfc/Qap6UH9RQj+qOai
         ViUi612mkH5IdPYDiEDrWezVJC4SXSrUOcxsYPkvpjkoyLHYTzaJAjfJGcGyDTI4GKeO
         dKyfsBv7ShFZCV2sVzlnMhpGq+fjKnbIzmSureXAGvGwDf8BejYzBTm8ID/1ux09Nv4T
         Mepg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:sender:dkim-signature;
        bh=3noJyKWd2TPJjjcSkksGLcSSVf6L1Sn/a64yzTneEqk=;
        b=XEQpNs7QzI1kWOVdl6OXPGOlwsQvlx9vdjJ2Q4S3ey9kZzOseKQq3XZ5d1sBVbM7YR
         VQNJ8DQmtoWPuvM81GxKRFPVNS5lvakAK8xHv5HyL9rEwr5YoJmLBJXub0CEu0XPOp+V
         c8gcEtTCqPMw5Il0Bki+jXfOZYkAwgT+lPQVRYGMWynYpRtxJyhKRgZ+WHluqR3jP5Eb
         BmXzK1e+D2LDbZ7hoEmQl6rVMTeB0i0uEimlKxBSTaE8LoejZDEztoM690cckEb5rqpN
         wjD/ah5lYRL6xvGnxeDMROPEq4iAPnlT1TzPDQUxJV6S3BjaS+4fiHTni//JNN7HKgQ0
         dVig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nWRRvi1o;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684294941; x=1686886941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:user-agent
         :message-id:in-reply-to:date:references:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3noJyKWd2TPJjjcSkksGLcSSVf6L1Sn/a64yzTneEqk=;
        b=m9vISpzKtVvbfSZOAfw3WBn8nhKGwbgtBYTX/KA2IeefXu8THBKhigjXplAJc5TJsk
         eICssApxFpLCdo6TZKYrSGnyw41VBkJLVIsRiISn/rHbWPZNPUK1Kw4wABu1o7iCIupt
         EYU2vrGCACgLDWZGPttw7bCtbsmuGk/xREE2kVNLOkN7qNgMMA/o2mdNZKgbLmcUDRLa
         aiekCfqRXMvH/xINOcK+mrRc2Zkos3tOVT1ZZLd9lza7mn4zNWKTMeBBJ7KPiMtJaIuj
         fjXB1VLULjASo8AMyBF7h0NtkM/Nwv3cfgbZMElewveE/cb61qJnCJ4sDYNHt+SVx1cJ
         orYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684294941; x=1686886941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3noJyKWd2TPJjjcSkksGLcSSVf6L1Sn/a64yzTneEqk=;
        b=YH2jIs+fa5pYXSNfRCeWgvHpH0D/AncLHTWSO8s0euiOLD3JZdk3pcuAZNXdKNFEmn
         IpOyw+hg+jaAtJxWtOUF6rGMH5m6u9NvGDsPf/X2V1R7CNzK097duVCU25g4hIOQ6+lw
         rdbSU1rprP7SOo0BdkFLzok/TNq/Ovi1/qCBah11AYorFVvvESfBGInYbq2KYAeuERz/
         z0N7o6bAJybBDVyDx/GMRYMWMLiXq+cwfZQ6a8V1DOWQOa/K65ZrV43UsIn+FEGNwbAp
         sAFU4yu7z0NEVu0S8JIesSLYpiVfroVeyezSZ4FLGh9xCdWVDWDUS1E2lTg8QBZofjwD
         dqGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyNRc+qBZ7GWg17kvrQ1uO9BBAwN80j92y7K03WJZeFpDM6569T
	L0ALJjhC+mOIfPx+GXbGfwY=
X-Google-Smtp-Source: ACHHUZ5/8H7AUbJbl/zPzEoBt3rjynXH9BRjT4rTIlQtOk5skBbL3lZ8gHHuR2p2IXa/ZzkjhGiGtA==
X-Received: by 2002:ac2:4836:0:b0:4f3:7ae1:c6a1 with SMTP id 22-20020ac24836000000b004f37ae1c6a1mr2635689lft.4.1684294940534;
        Tue, 16 May 2023 20:42:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:54b:b0:2af:5db:ad4d with SMTP id
 q11-20020a05651c054b00b002af05dbad4dls310206ljp.1.-pod-prod-00-eu; Tue, 16
 May 2023 20:42:18 -0700 (PDT)
X-Received: by 2002:a2e:7a1a:0:b0:2ad:16d1:eaad with SMTP id v26-20020a2e7a1a000000b002ad16d1eaadmr230124ljc.12.1684294938610;
        Tue, 16 May 2023 20:42:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684294938; cv=none;
        d=google.com; s=arc-20160816;
        b=gwwlOJ1RWHwBiVG7FsW/hQiVt9l8jBxPgDUuhvbpKNbu6FUmfr+ezWhYdUaSwSgHdT
         XpB60w4FPMKUU/8/ToHzsyyfheXkicJyU1ijoGGsWlv+EP2ovqybsT9Z74O2D9hQH7Y+
         FZ7lTPSC+dGXAOBaTrRv27BoQJqGWVk4V9ZT1HqkvQVS7GKSI0GHu/OsvLwZ/BUbIJKA
         M+Ya5qbmHl6C1t4/DZmIeZPIXKkn5ZMSms+Hb2LKDXR8yZTGOgwkNAc0CEbI7xFGqQKr
         reAovwSE44DK68U2PNT0qBwiWlGrFVwCWURR1H4itOKg9lG2j8PmrjjSpGKI4IoigqZS
         Icog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:dkim-signature;
        bh=hdlcW41rB/yh+usMP/g3GGVgQlKjKQ6/xZXXMkuGzdg=;
        b=kTrQr49+SL+wqPCrg/5glpcALfby0HqY6DTVKlwt5pIM8L8YwNWERix08B5uSYgYSA
         UU8nM1mArCyOAY+EdKHWH+07y1d6H9XhXkqJYZ9D5goj1t6qCNa5z8jx04cV7h83i7Kd
         DRJQ9hNrBnfd08h0xfAbkjEkcOm7GDs3bRThcyJo9aB6tj2SdKJIQoc7atEsUmO51KaN
         LWl4bNg8j00FNEfmflXAwWQTxaFAJZD5clM6wrl372JiySdQVgkR/RpFRXXrgcJkCEKX
         UZu5Z0gNpQGbuajCkW89i0Sn9sTar7tBxhDUPqaxxYN0Uob7u7RwIvzABGZ31aXipeM9
         cBVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nWRRvi1o;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id bz16-20020a05651c0c9000b002a8b2891ba7si1961910ljb.1.2023.05.16.20.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 May 2023 20:42:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6600,9927,10712"; a="379842593"
X-IronPort-AV: E=Sophos;i="5.99,280,1677571200"; 
   d="scan'208";a="379842593"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 May 2023 20:42:15 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10712"; a="948103305"
X-IronPort-AV: E=Sophos;i="5.99,280,1677571200"; 
   d="scan'208";a="948103305"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by fmsmga006-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 May 2023 20:42:11 -0700
From: "Huang, Ying" <ying.huang@intel.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,  =?utf-8?B?UXVuLXdlaSBMaW4g?=
 =?utf-8?B?KOael+e+pOW0tCk=?=
 <Qun-wei.Lin@mediatek.com>,  linux-arm-kernel@lists.infradead.org,
  linux-mm@kvack.org,  linux-kernel@vger.kernel.org,  "surenb@google.com"
 <surenb@google.com>,  "david@redhat.com" <david@redhat.com>,  =?utf-8?Q?C?=
 =?utf-8?Q?hinwen_Chang_=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=
 <chinwen.chang@mediatek.com>,  "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>,  =?utf-8?Q?Kuan-Ying_Lee_=28=E6=9D=8E?=
 =?utf-8?Q?=E5=86=A0=E7=A9=8E=29?=
 <Kuan-Ying.Lee@mediatek.com>,  =?utf-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
  "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
  vincenzo.frascino@arm.com,  Alexandru Elisei <alexandru.elisei@arm.com>,
  will@kernel.org,  eugenis@google.com,  Steven Price
 <steven.price@arm.com>,  stable@vger.kernel.org
Subject: Re: [PATCH v3 1/3] mm: Call arch_swap_restore() from do_swap_page()
References: <20230517022115.3033604-1-pcc@google.com>
	<20230517022115.3033604-2-pcc@google.com>
Date: Wed, 17 May 2023 11:40:58 +0800
In-Reply-To: <20230517022115.3033604-2-pcc@google.com> (Peter Collingbourne's
	message of "Tue, 16 May 2023 19:21:11 -0700")
Message-ID: <87353v7hh1.fsf@yhuang6-desk2.ccr.corp.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=nWRRvi1o;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 192.55.52.88 as
 permitted sender) smtp.mailfrom=ying.huang@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Peter Collingbourne <pcc@google.com> writes:

> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> the call to swap_free() before the call to set_pte_at(), which meant that
> the MTE tags could end up being freed before set_pte_at() had a chance
> to restore them. Fix it by adding a call to the arch_swap_restore() hook
> before the call to swap_free().
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c=
61020c510678965
> Cc: <stable@vger.kernel.org> # 6.1
> Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@media=
tek.com>
> Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d=
434.camel@mediatek.com/
> ---
> v2:
> - Call arch_swap_restore() directly instead of via arch_do_swap_page()
>
>  mm/memory.c | 7 +++++++
>  1 file changed, 7 insertions(+)
>
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

Should you add

Suggested-by: David Hildenbrand <david@redhat.com>

for 1/3 and 2/3.

It looks good for me for swap code related part.  Feel free to add

Acked-by: "Huang, Ying" <ying.huang@intel.com>

to 1/3 and 2/3.

Best Regards,
Huang, Ying

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87353v7hh1.fsf%40yhuang6-desk2.ccr.corp.intel.com.
