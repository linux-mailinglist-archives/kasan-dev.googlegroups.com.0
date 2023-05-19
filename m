Return-Path: <kasan-dev+bncBDDL3KWR4EBRBOWMT2RQMGQEXPPJ2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B465709C8E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 18:39:24 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-39632bdfd2csf2685022b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 09:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684514362; cv=pass;
        d=google.com; s=arc-20160816;
        b=iJJhvjku88qq4Jfrk/8LWOv+BA1fEvhMIUgHAwD7ubRTp103JfemNzhqw+wMWVXAic
         v2X78D8++1kB6trWaQm2EFRBxZP0NkJB1DdR9RVx2mk+yMCbJiCU0zUK9wZIXtJsuLod
         8FXuV4vvfJIhdwH433TATWaKxmWLGTA400BozedNsvxX4S/sGlJPfJ5gZZtExKHj2Vhc
         YZGIBnCfYoE4on5wdONHvM+NrRDF18lpoxn1lxXBW62+E6xuWDTdlUVgm9up5NKJBIf3
         DwI2dm52AfJpd6mcBSP87r1lstnpz7YSfWkAHExQW24KgL8wqZBDA62aYj0VGZ1w1jPx
         GS/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/goRGcB+vGttr81W/pGl3XCB9S8srlKDBpxuflKoUXs=;
        b=HA8IkLEOYkCv0jryMfhovwJS740CPkvFUDvcKs95KLEmXP7mz59T05DAZA0iTlr1w/
         eHSdpkYENUg+1ME6FngIeph6KOUJbDEibArLVL4/2Wbl3hKQxtoa2sdVYLW6LfNsDYYV
         vnCf42j9LMIbYirZXFs6qhmWobLUz+R/9AHlrcX0rk/QM6vHdhcxoQ4QawTwjbm20ydd
         ND8J8pWitdLDxyngGz6gbJ29tweYTjg6Nh0c66AYa/ZjN5gSVZecWK9Gvjf0aPCR91Cn
         LoFc8VUX/n2o4sgpCAkkWJI7BgIbvlX4qJf5sSYWBTQSe6dduhP+C7DuC3yInK+Lds1g
         w1Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684514362; x=1687106362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/goRGcB+vGttr81W/pGl3XCB9S8srlKDBpxuflKoUXs=;
        b=bZhX9vxlWrQiy02RfCOaOrvZDelZ7VHxkf3yGS73AELdLxBLaX6EaJHukMGzRo2JHN
         DtX6vqS4kioB2Doke9/cr/4Aa3Ekkuwev4NyObqTdaekHhHRlKQM3ogHxrA8dDsZ8qu4
         qKiP5427MvDmHF6sDfIJRQcy0yF3ZqoUv2+czpaQlxxcpNU3jJuAfc4lkPUZDFYrOGO+
         rmbANVhB9bet0SzpyWQn4BjllGzRNrWf3gIo6n7YOeyNx6EsPTS+V5TdTuMdS6Go64AB
         jgV7H1gl7Zg2VRdUB/7MW6y0cpfpjO1fJ0bgwZFm40SEt3akrdi5ThcYT0zfI8lzc/6Z
         4JMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684514362; x=1687106362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/goRGcB+vGttr81W/pGl3XCB9S8srlKDBpxuflKoUXs=;
        b=OmDf5KQ5BD/+3Q4iOQAGjWX6CWN5JhTBQyIVKBzIO+1lhB3oWs9HFl5YRQ31tvxG/4
         LwfD3FcPp/xcMslDhzNrYIK38ZDk16gHmIpYaTbOt2mkZoLp9Puxxoc2wrCObAYhvxfS
         IKgP/trgjqac0jLJIIMMriFrup5/BoDxsUom2qY9K7Z+dypOT18RvefsNuEgY14GxYfv
         EtyabcCO4+0BnmavFDKy3vtC4nvYqpNUJ1ex/2ENe2wlczL/UNKsDuI0d5CQC11o7OPk
         qFX631/bzOKrZIlLvLsa6xxxrJtLU4v3Rx4LsJUGMGJYO87ljCuM+RxDNFsDQM6znOAa
         ZFyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxLzE7V2PeSaMjE9FlM7JMGLsO321NUrOAya1W8kythLaH8RWJh
	5iAOFzDWlQjTgAbIRSA9lgQ=
X-Google-Smtp-Source: ACHHUZ58HZgKMUKZ63J2Kw/OCoAo4drEaFcjL/V0oa3H3wHirROxH9A0INALKKq+mhINkrGRnflboQ==
X-Received: by 2002:aca:ef08:0:b0:38d:e632:8308 with SMTP id n8-20020acaef08000000b0038de6328308mr734920oih.7.1684514362704;
        Fri, 19 May 2023 09:39:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cf03:0:b0:54f:f771:42f3 with SMTP id l3-20020a4acf03000000b0054ff77142f3ls3273677oos.1.-pod-prod-05-us;
 Fri, 19 May 2023 09:39:22 -0700 (PDT)
X-Received: by 2002:a9d:7a91:0:b0:6aa:f707:691b with SMTP id l17-20020a9d7a91000000b006aaf707691bmr1234149otn.0.1684514362150;
        Fri, 19 May 2023 09:39:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684514362; cv=none;
        d=google.com; s=arc-20160816;
        b=qqDPtK1fl4TWK6l8YpUGafLxMNF8hBKQ168zQyMFwGdJog8e5D6CQVEVxuCkF6LEKV
         YdwhOBUoc2lsJNMXHvUlzB1oMT4OqijMD1ACtJDhfPXgEOjUPqp/DMsRd6Mt7fYU1ez/
         SjlpK3MJ0bf+oed2tlHsgzOFYZQJ0zNWC/fJHliVbCzEzQTY2GCGGwSMZ+gVwNPVQzko
         mXBOxa/36TNSNBPldYNp9ik3ztGmkOBxKqx/0VOFo0CNzof2NKl9wtZs6ALWqY2Ed0G1
         HOGyW8Yl32zc/x6LNnu5vmEyrI+9aTfuirO4cgXbhvgP9d2Gb8N73cjIb3GmoPO+ZMFg
         +1ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=tm5yWitQFobo7XTUh5Htl9d+/ov6l57MkDLyYMRoUF8=;
        b=V8Nk2uBu+QIKVtIvJS/m24/4uSflByXJ58jvQevzd+844pWJuJ6NtE4EzD/HG5uZM2
         BTmQGa9r5LRtYOpa8KCTVOJ5qJrDBZl18tQ9eJkV2vvUbvsbUXaZaK489Da4YVEUCq70
         CwQq8RSdTWO32HRtL6LIXEGVra3FkWmtEaCqNu9h3EOnokXAIAgMLvVU536fIDcXG/7t
         M3MBwrrOrKlmBUXYjANO6PgGsDRb+vIEUVNqcsx9grA1bdMdWycK6BpAQkQKjhU/3C7z
         vq+qLurL/qwy8/j63zOxCJWOMh2EbiFCjn1DY2zBCUmHPJmaAxKurXNaxCyGZNTXH9VM
         9Kjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ca11-20020a056830610b00b006ae01d53234si393354otb.1.2023.05.19.09.39.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 May 2023 09:39:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E6824616E2;
	Fri, 19 May 2023 16:39:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 75B3DC433A4;
	Fri, 19 May 2023 16:39:18 +0000 (UTC)
Date: Fri, 19 May 2023 17:39:15 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
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
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH v3 1/3] mm: Call arch_swap_restore() from do_swap_page()
Message-ID: <ZGemMxjj6sC2H7bW@arm.com>
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-2-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230517022115.3033604-2-pcc@google.com>
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

On Tue, May 16, 2023 at 07:21:11PM -0700, Peter Collingbourne wrote:
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

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZGemMxjj6sC2H7bW%40arm.com.
