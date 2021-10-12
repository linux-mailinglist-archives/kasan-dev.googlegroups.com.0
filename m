Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJ5ES6FQMGQELJO3TJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D498242ABCA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 20:21:30 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id l18-20020aca1912000000b00298b655b0a1sf151752oii.21
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 11:21:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634062889; cv=pass;
        d=google.com; s=arc-20160816;
        b=hAsEmP+tD4Y8GzeOEgDCyGUpjsML5fcfIaZ++duy8Uf9ZYN2SseFmIQ5nXnpFBI1sn
         S9n+ortn2E+hTx0pPAP3DoY5x694COqj4m4QUrXFAiYQJ6Ztq0Lo9FQHQsHcFla08omG
         L1/HmdCErpV6y1FPYFcyXgDAlJwT0iCBbX/PHBU4Oyx2d5djVn5QHAfktYuYPmjUUplw
         iJj+VY60e4WNCXl23XS79Z+HNk3GqUb6NdFUg8v0Ky84TtdfYwOa+VJZLGGNxyreudZI
         Y1xglBfri1fsfN55BSg9px7Bbg/FfC2S48ypmt6m0tnM1vbvRfR3jeKK3yrMs5wiH5fs
         O96Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BGnvtojaGlFhbkkNa6xhARt7UFPAM2Ad8DMT2EDxf4E=;
        b=PAqo/MRgq5riCK43tRrkWwDjTcXnGe7PGFFugiF6oAZJDStHTj0vi4avPzrQ7DDtnd
         CURL7h3NomyOZEpYoeY1RnsrtIjxVNucESJ9JdT5yU1FC6gAZe2VShKmxqKXLkLIpdI8
         1Jr0wsWH+1J/PsgRMLZrKzrrQ8p4gy4/2PptDOj51sW0qwpPS0PrsCvX312DWU5lSjf6
         Hs/O38eaCPgYQw8DNscWCkQlZPklz+z9FIb2f+7H+3BawYOm+id/hSvT3W+gdDD03gYj
         qHCi0esHpp66fv8guNC5mFEUA+XSAsnX73rrJXRDdC0sg8Yxd+eATMHXvPRG8y57YWKH
         mJpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BGnvtojaGlFhbkkNa6xhARt7UFPAM2Ad8DMT2EDxf4E=;
        b=m9lEp3d2Cxtzvnb32HdaoL9DlFEBJsWPCmHvOrrpGxfviiDc/+uZIwZ3crs1YxQyba
         glgOY8372OX8HJy7CcJZUvzYW5TkL3MSZ4xO7iteivLG6dujYxnFAUqLDuwtl5LX5w/j
         vEu+ZGtUUDQp0msLxRxTm2syBUqljNgFK1GMBPfmE1cW33kqXka+iDl+IfL6ODcOKB0r
         JRCzf+Wy9icPJzxZN8GPvnsa2EWD6fFbks0TV8AY+jOS0NJBWyvsq+vaHMdSKfdkwKN0
         CWMh5M8SDVg5vUmVDO5PCegLdzKYGQhzAJPuv1NedwkCx9hJ1psPAP/JTX9gTQej+/sN
         uaqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BGnvtojaGlFhbkkNa6xhARt7UFPAM2Ad8DMT2EDxf4E=;
        b=4SwtguC/JobzFURcLisT9I9RpdAciWCFlGtODgDAH714RdK7IKY5/wL2ES3mrqGgLj
         SaxawhOeGuGjJzIA71EC27nyD8i+nAtbpk2A1ExVkCLG0/qO1snihdSTvg8PskkjmeEr
         nGlf0PtbHm8oWl7oCXXE4Em8aRP9sGP8hTwE6cayRs3ZG9O0EjqzWh+4CYNGwLSoWG34
         BW/7GGg2d2h0eTqR4FXrslOUlK8G5amFjf/78R4V8kpEr5amZzUdEwhRuBmLWOAcmmiJ
         BwNteWzJSWqTeATB7TaXFGXBsxqUvu9fKn5vVAAtR5ZrBDrRCWwWYIhLMdwnY6myMfur
         7Zgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330DqNFN8BNeO3R0n8eke9H8A8JtOO0K/MUgMaxlRS9kFuSqHZY
	JFZ56LLlpLQR/ko2jzSnO0s=
X-Google-Smtp-Source: ABdhPJwXk9VCtdHixW3QtXO2qXd/B+k+RB3DW1ghzhmXNxIZG7kiLSd1zTrKEpGCqU2HkQYMfUEOcw==
X-Received: by 2002:a9d:60d9:: with SMTP id b25mr9921961otk.378.1634062887456;
        Tue, 12 Oct 2021 11:21:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9b99:: with SMTP id x25ls1018850ooj.9.gmail; Tue, 12 Oct
 2021 11:21:26 -0700 (PDT)
X-Received: by 2002:a4a:3859:: with SMTP id o25mr20265178oof.10.1634062886856;
        Tue, 12 Oct 2021 11:21:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634062886; cv=none;
        d=google.com; s=arc-20160816;
        b=fb780PCX1/86nkvc4tcgysDWT/JhPZ56R4SplrM1mnBkz87pfiVYEP8aB5K4VkL17q
         ox4CSZbLiYZ8jWQsNHwjABCSmD+/Gk/FAUh7b/RY1NciJ8aodYXyfNZXSar0uQWqfKEA
         SRylNBTw8WfWFSnL93KTB7F9lAEc9nGafH0GVb6CHAJ3z03dS7cIxDUyx/g675PMZIl1
         1DSCNJUChRei9CnN9Vi85owayeeGxxL1ZgN7o0QJWRYrgwKtC3415vDj+2WegixcKneO
         yiYfFZegNn89ysM2rtBW2ffO6gvbkPrpYL8z0g+neyIX1Xg5C87sPbN417BSLxaUTAaW
         /slQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=VHGR8xQvclPIBDBUYzM3/UKk9BfHFGQ2A4BtEKHwUFI=;
        b=HeBiedwUUgk+R5lNKtQVhokwIaaYGwLGQD5jJFbdbRnfN5OC2jAZyi/7N9rzeyIA6y
         rndZfgo1qEWlLRaOXdpFiqkPbL2pu98BjSnCqAuwOwsn4B1drpfkxer95emT51GNIt75
         fgzfIHzosFrPwzugL7hfoew5qTf4uX/2mpmzR7pIyuv73UqndPEDm+uA2oT0571H5+G9
         J8UkISomPrLUPE3xASzpgb8e+xS7CtbNwhWgnlvAM3N+YwPAshKjyaNgDyYOhHeM1jtP
         OyJCPt3Ek4bZ3jG5vF9tX5T8hBPiP/XEJfVXNArvUglg2tke7OT0o9DXsizvUAudcd9F
         VJQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m3si1245056oif.3.2021.10.12.11.21.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Oct 2021 11:21:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 37ACB60D07;
	Tue, 12 Oct 2021 18:21:24 +0000 (UTC)
Date: Tue, 12 Oct 2021 19:21:20 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com,
	akpm@linux-foundation.org, gregkh@linuxfoundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
Message-ID: <YWXSIOm0u58vBfJ6@arm.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-2-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210910053354.26721-2-wangkefeng.wang@huawei.com>
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

On Fri, Sep 10, 2021 at 01:33:52PM +0800, Kefeng Wang wrote:
> There are some fixed locations in the vmalloc area be reserved
> in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
> pcpu_page_first_chunk(), it calls vm_area_register_early() and
> choose VMALLOC_START as the start address of vmap area which
> could be conflicted with above address, then could trigger a
> BUG_ON in vm_area_add_early().
> 
> Let's choose a suit start address by traversing the vmlist.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWXSIOm0u58vBfJ6%40arm.com.
