Return-Path: <kasan-dev+bncBCT4XGV33UIBBVVA4OQAMGQEJXEWOOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id BD56A6C23AC
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 22:29:59 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id h11-20020a0564020e8b00b004e59d4722a3sf19135068eda.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 14:29:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679347799; cv=pass;
        d=google.com; s=arc-20160816;
        b=bpLdDDWKRlm5th4fv+OP3XwheqB74AUyuFEBxmzmydExFz4qv82StgXDK7Smw6OfIa
         wWRs5Sf3L6x73OKSv4K7bx33CmJ8iPXrT+VrcqJ8Af4/TZo+XfjJwMftlHsihPnupCqf
         q3qEXCw+y314+Vi5Ejn/sDL66CMrvHl7L+Eeu7pYU+6wYfjtAD1ntCBkoSJWSWs+IjCZ
         iBPa5nbwy//KnkpiAR1dfhkQ0p7KTg58mr+QqlxVPDOLzfVraAZ3OId3GFjuCF7sPEIl
         cHhDz3oNEHRQBcEJKEatNJd3V0ZAEYHaF141eQMmkg0KSv6f2Pj3SX9jpEIkBJOW2dRR
         d0kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Lyj1p59u9lqxY0NX2x/8NXGDpiGcHq3RLvc5wT/QsmQ=;
        b=pNmAQAwH2A5M6rF+q3TkYodlQAbL2bnvmAzOHGgKv1kvU8DuvW+0VYmzTtlMYRoBSK
         y2WsZ4j506RanvfC17xULprvGfjTnqXyN1Cn+6Tz5y/QxGrd7CdJjznF/xvWUsbgo1J0
         dwhYVme5ERiajJisXaUq5zPw2pvXda+ojes3HITTqj7PjMS/dbJV9F6af0mzsU36tIdj
         fA2Z0+9Wvz6DRR2u3GZTCvCYBdbxQEROzT8mgUFUB6nrZPxsERZmrQYBmyK3LzQPt3y3
         vwgNpWlDPX6kRdRIw7SPUjQH68aDuY6YR9kb0uNow8/ESkfXUYgzWzfTt6zWt8oYbSzz
         S31g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qmJ2xFhN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679347799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lyj1p59u9lqxY0NX2x/8NXGDpiGcHq3RLvc5wT/QsmQ=;
        b=ZLAOWJTNLgHQOfiBWb/rn0QaCgTviLl3rEPKSK5xGTSyg1tA1SxgD4rNmwSFOuctkD
         0ST4qnMPReqz3YQtZQiVOv4SEudAa4uqNYcXW6zXnPY9HtbPEEIsboszPHeljq7AB5pC
         yJLcfZHOB9FOuHBNxAE8fvWKIIkSccM+iMvOTevOy+TK1r0hGPU4OBt9VNiBhrTYBeFB
         oDslRera+i9JJKusdxDdU7V+uUdD4RILvx8hFxL7Pbf30WZ1LofH0iwdOU4Z183kPZaA
         QxrSyKcGZrw6v2Ycf9Iod3Vfztvm/MnunMUERpD6YJWEBuRUmctBrHaDejTdzvs1DKoK
         hYNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679347799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lyj1p59u9lqxY0NX2x/8NXGDpiGcHq3RLvc5wT/QsmQ=;
        b=HYGaDG+7Pe83CqChXNfpCsXzs1AT9mFEOEdz1BfGaEmf5xmYguw0pRsFm7opHDmOqU
         JxJBAzPKculj8ZsjnfAOxMf7qwFtG6i7v9MtxG7yIWB4IAUkQVjeiq0ECKBGxgSduzrM
         8MKPQfzHXpudrj42kKTtyZ0eG+mIpMmCnkmv3QqjnWr6AqkM9Oqxz6cVV/0kF7yItfLH
         Z19x6z45rEGrKZLb2bz+nKqoUhbm/C+vLDPG8dIWOxyyS0jHd1TSDWe8eNrjaYzpj6f2
         jrI4CHp93SmFtC1BtsXAYtz7r3ghb6a/7tmce7lt3njgl7tLNFw8w1/lGRLEdgmaRHHe
         j8pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVV6Mr5uYKmWyzmus0fdtZ1KUdEXelMMEzgRlH9+AzHJ6l7L+No
	ohxd14GtrvXfpSNJAEuAjFg=
X-Google-Smtp-Source: AK7set+jNn82kcI9Cq8CzlX4ppEWb1NkIhKWJxOjK49zXO9a4Cw1qugPW+9mh7I+UzOUYT61AOGePA==
X-Received: by 2002:a17:906:6b94:b0:931:faf0:3db1 with SMTP id l20-20020a1709066b9400b00931faf03db1mr5037403ejr.4.1679347799020;
        Mon, 20 Mar 2023 14:29:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2908:b0:4ac:b59b:6e28 with SMTP id
 ee8-20020a056402290800b004acb59b6e28ls5658250edb.2.-pod-prod-gmail; Mon, 20
 Mar 2023 14:29:57 -0700 (PDT)
X-Received: by 2002:a05:6402:12da:b0:4fb:59bb:ce7c with SMTP id k26-20020a05640212da00b004fb59bbce7cmr1061395edx.32.1679347797330;
        Mon, 20 Mar 2023 14:29:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679347797; cv=none;
        d=google.com; s=arc-20160816;
        b=Sl5ZKkYyUZEE8QC4hPYs0QM1Kg5YsZd9oF5Dm+J96/DXaR0DtednnqzRoWFBLT/Aa5
         2LlyQWIRmJwas2uWtjFah7gWiEmi5Q3TskdA/zoOGt4Y7JzLXstVXBmPRUleDWg7d1gp
         Kb/GNigTlcYpnmF7dAeTioivle2b8MBzcTxIMecpZclL8BwFNZGyqoVElHOGXZV7gc92
         ac2I5h8nmhZQQV9IdDI/JM2drTCxhkCaCvLoyns3ja/SgQn0Shpsap35Hji3r+IfUU33
         gsOjIwfMcFLmFgjpaO3dbiERCOGS2z85TV0NMFoU6A0BU98TiFIy5EcfDO1Gx7lrPMuJ
         PQJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZznKLHPmLqzByHKs5cAsCEw7L6nMeJIsu2bjHffmCV0=;
        b=oV99CYfTZOuasTQI9SkJrVxPltQg2IEiFL1+l17yZY9mKQPnBo7RyFFnCRHUcndBNr
         ZqvacbW1p/T0rSpWmUdXDlE/Wg7uDAzn1oPLpk/gMl80gorlIA/Y3rjxaa1tQBSTX8dN
         /lf0MEje4jbIhQ4n8eSqNCknuue7mNSXP6Q8KyP8JCEOcTMKzWxi4M3L+9v4COZ6F8Ia
         4sOzAqD1dKNeP9KoW9q5YLjWozbHJz8fbkggyR5mfe6pz+LwS1zVl56Os/6psOdwhoHa
         jA/TK2c/1i2u2IJLkIFuqtoEQns2rPJnzuMxp3Exdom2m2P6sGOebs/PUQvSgfPCJrNL
         qwBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qmJ2xFhN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t13-20020a056402524d00b004bbea073a82si438428edd.5.2023.03.20.14.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Mar 2023 14:29:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id EDAA3B810A7;
	Mon, 20 Mar 2023 21:29:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 54EAFC433D2;
	Mon, 20 Mar 2023 21:29:55 +0000 (UTC)
Date: Mon, 20 Mar 2023 14:29:54 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com,
 sjpark@amazon.de, jannh@google.com, muchun.song@linux.dev,
 roman.gushchin@linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] mm: kfence: fix PG_slab and memcg_data clearing
Message-Id: <20230320142954.fd314c5e46c1d18887ccf8cc@linux-foundation.org>
In-Reply-To: <20230320030059.20189-1-songmuchun@bytedance.com>
References: <20230320030059.20189-1-songmuchun@bytedance.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=qmJ2xFhN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 20 Mar 2023 11:00:59 +0800 Muchun Song <songmuchun@bytedance.com> wrote:

> It does not reset PG_slab and memcg_data when KFENCE fails to initialize
> kfence pool at runtime. It is reporting a "Bad page state" message when
> kfence pool is freed to buddy. The checking of whether it is a compound
> head page seems unnecessary sicne we already guarantee this when allocating
> kfence pool, removing the check to simplify the code.
> 
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Fixes: 8f0b36497303 ("mm: kfence: fix objcgs vector allocation")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

I'm not sure how the -stable maintainers are to handle two Fixes: tags.
Can we narrow it down to one please?  I assume 8f0b36497303 triggered
the bad_page() warning?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230320142954.fd314c5e46c1d18887ccf8cc%40linux-foundation.org.
