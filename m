Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUMVV6PQMGQEWAR5LBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 52605696C12
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 18:54:27 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id kw4-20020a17090b220400b00233d236c7b4sf3668890pjb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 09:54:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676397265; cv=pass;
        d=google.com; s=arc-20160816;
        b=N/N9/lYsqhIzEV8O/tIB5AjjcIqhSfVcCFgjSSNHp7EhYk7cZno+3yhuEZfdji0Tyq
         HZQ9vs1tZVhhOBzWLLplj31iSzpTxJaGaXe96l4735HY7JZjwOawTaLzGbZ0ZGD7d8RQ
         LLetEzZ01PeDsCMSAYHT7hHD9WZTHJvofotf7KrbVxTurpFyALaOtbl1X4xtmwX4eea3
         B2PvAbtZo5B1ykVzwNusHq2OKUxmyigpLRKYThpl0x1a7mhzlXyNAKFoHfSoVblHz9Mz
         wWA7cq0nQHCqVpNEtdD0slywp5VqHjGYX5OwIq5iKaGcQsMOUBp+7KI23aMqx4P6IlyD
         uXNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/rxbPGJHSVc2xFrq6IgIq5XC6Ei4bmok4sxa0nWAKHQ=;
        b=ANFxC66icUXYsLZdYgbvuyPrF/R2s06E35XEMhGKPvcipknueTo4Y+AJlA3SslwRUY
         sbA02vKCTlE3A/aRx07ImCJxXvKXJ8/5bv0BhFCPUxcvj42EkBld7HOiF4RiceDID1FD
         NDRUbpN33vWbun2/U2iKis/QnybqsyibslbYVErn/k7epwe12xMHWM5xjSJmXu9t3Shx
         Cg2GxFZ1i9dL81JIH7TO2E+uh6YN71rU04UjbZPRAWVfgvDEbAl6MaxxcqRRFKq2dVwt
         xcxSsO5Q/vt++IimloezIEQMIoABq3WPUlQICqzl1m54+gknjRA4fZ8g5LIl239hIsky
         gunQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/rxbPGJHSVc2xFrq6IgIq5XC6Ei4bmok4sxa0nWAKHQ=;
        b=ctjQ/twHd2yUK2KU/tiBXxl/vRWMLOzQnzvxplkPaMFORXVbmvHir2EiQZwbr17V7q
         EPB/h9ejkhnjKXxtV74KIJpOOgm2pBJWGp7Ux89PiPys0Qf1Y7mHvPLxYJV5GmWej3ms
         7kUn1UC8iRyc4gWxbrSiVr+dIWOhzDkpuHEFy+X1PRRerfIlIfKi+UHV1soAKwWYV1TM
         0a+x9Bs8/YaKYd8Pim2RsE92zDih0n41GHZRQJIBCdCujNyo5I7fZHp9pIou8T2X5oW8
         tPZcA+h1eVLRYdxLhxYZs8x82GVFr2Aaz4/Dv0bxwZM9qB78jToYyGhIveeqvM4RB2J9
         TT7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/rxbPGJHSVc2xFrq6IgIq5XC6Ei4bmok4sxa0nWAKHQ=;
        b=sshIcgzVvBPxbwRIUQEVzp9JXovB4o3Z6ZUy8hq4meJtw1t71/1vyp87TsAY+O3/El
         opNp2ia23pwcQc1K5mmhWbHUugh8Wf/zB+5kCqEf93Y5WDYng52Nnyos3JpDWceMnYdr
         H2fq0SHnYRRGkQ8Dd1k24ELw0+7LGvmFJwFgNXhuflKonxiFUXINcFnDs72DJr19fvZ/
         C+uwUWFtYhkEhFC4wz0goTSX/5P2jkUSKgfL8A/Cnnmb2ljrwdHqrWHDtEBRZTNZP2ca
         S+X0JeoyRlQRs7WrrHmz+fS4l0IpYtQXiYy3+RwrYSfYuQ22K65MOk1RVl8rC3xWtph1
         sG3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVcAl1beWFZMMrqR+cuX0SDv9xh8F4qM05VmYDasBRjYEWY61zd
	/jnrBKP0RKLjrmhwhvzmmr0=
X-Google-Smtp-Source: AK7set/t2sIhlJgEP9yRQ/ZkoKPJ/MUbSo3RZZR+L87TLfYT4mF4XjYD5ktKCUcc5V0oAbLGBBdbOQ==
X-Received: by 2002:a17:903:183:b0:19a:a815:2861 with SMTP id z3-20020a170903018300b0019aa8152861mr906287plg.21.1676397265531;
        Tue, 14 Feb 2023 09:54:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e38d:b0:225:cae6:ff24 with SMTP id
 b13-20020a17090ae38d00b00225cae6ff24ls1199963pjz.2.-pod-preprod-gmail; Tue,
 14 Feb 2023 09:54:24 -0800 (PST)
X-Received: by 2002:a17:90b:1c06:b0:230:9802:fbaf with SMTP id oc6-20020a17090b1c0600b002309802fbafmr3610930pjb.35.1676397264558;
        Tue, 14 Feb 2023 09:54:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676397264; cv=none;
        d=google.com; s=arc-20160816;
        b=ojXrQuHrJh3IvpQfDiUIo5/GijKDGnb4rADUtdyzhQUbIcugVDbizvFjbAjYsfnC9W
         WfCURT49Lm2wOWhpjqBGj3TVGPdHMaw9RcTkIT8omOwozBNZi0yNj069hUtY8uTrXdJk
         zTXRK+rs2EJcjJS5/xJCoSgNf4ulxh6SELugq8K1+/LpzfZwvGBiaozEJC+po6JUSSqM
         sCRrKIpRNHQIjpu8C5C/auBn4feJgUjdmt+QWJ71XzF9aH7X9kYW2P4+Wk0tTDFYIox5
         6lTFtHFS4MJMEtXP/HrQi9tjft89SIMrvWcjBh4fZM4wWWLitkV720e2FMo7T5lyiVTw
         suhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=4vrfRF2+j8chYU1CJ8BqfAG6vP9dgP33/j7x2xQS3iY=;
        b=CZN7nVqzCEKVtkg/nH0UGFFcOEGxGS0Q91ADDVOiKAHi55AgCsMn0eQzzATz8BiEXK
         uo6aSeNw/aJpYYviWVPR1/Z2U3OVeUwfXeBfrgm77PAwsIBd7WifdjLjXOsyx3EypSFw
         tniIQLzpS/mZY2IjsgTNX6aE3v5aRMQR6fTipFGYLLIDwsK12OkAI2k27jwXq4HpPlR1
         EboWcSwJ5ZHEmMsoCiBooVFQsVdEGBLo1sLkg61sM7phgcU2MDSUbTDl6P4TIwRLTj0I
         Ml3SgKPS04x4k8rOtO/qTZ+NC9VE5FzwWUP14+a0crTzMPuNs4Gu5rLZ4bkIC0XTZrJl
         8KrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 34-20020a630b22000000b004e968328928si945984pgl.1.2023.02.14.09.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Feb 2023 09:54:24 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EF5AD617AC;
	Tue, 14 Feb 2023 17:54:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED906C433EF;
	Tue, 14 Feb 2023 17:54:20 +0000 (UTC)
Date: Tue, 14 Feb 2023 17:54:17 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	linux-mm@kvack.org,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com,
	will@kernel.org, eugenis@google.com,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH] arm64: Reset KASAN tag in copy_highpage with HW tags only
Message-ID: <Y+vKyZQVeofdcX4V@arm.com>
References: <20230214015214.747873-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230214015214.747873-1-pcc@google.com>
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

On Mon, Feb 13, 2023 at 05:52:14PM -0800, Peter Collingbourne wrote:
> During page migration, the copy_highpage function is used to copy the
> page data to the target page. If the source page is a userspace page
> with MTE tags, the KASAN tag of the target page must have the match-all
> tag in order to avoid tag check faults during subsequent accesses to the
> page by the kernel. However, the target page may have been allocated in
> a number of ways, some of which will use the KASAN allocator and will
> therefore end up setting the KASAN tag to a non-match-all tag. Therefore,
> update the target page's KASAN tag to match the source page.
>=20
> We ended up unintentionally fixing this issue as a result of a bad
> merge conflict resolution between commit e059853d14ca ("arm64: mte:
> Fix/clarify the PG_mte_tagged semantics") and commit 20794545c146 ("arm64=
:
> kasan: Revert "arm64: mte: reset the page tag in page->flags""), which
> preserved a tag reset for PG_mte_tagged pages which was considered to be
> unnecessary at the time. Because SW tags KASAN uses separate tag storage,
> update the code to only reset the tags when HW tags KASAN is enabled.

Does KASAN_SW_TAGS work together with MTE? In theory they should but I
wonder whether we have other places calling page_kasan_tag_reset()
without the kasan_hw_tags_enabled() check.

> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/If303d8a709438d3ff5af5fd85=
706505830f52e0c
> Reported-by: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee=
@mediatek.com>
> Cc: <stable@vger.kernel.org> # 6.1

What are we trying to fix? The removal of page_kasan_tag_reset() in
copy_highpage()? If yes, I think we should use:

Fixes: 20794545c146 ("arm64: kasan: Revert "arm64: mte: reset the page tag =
in page->flags"")
Cc: <stable@vger.kernel.org> # 6.0.x

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y%2BvKyZQVeofdcX4V%40arm.com.
