Return-Path: <kasan-dev+bncBCLI747UVAFRBLVA46NAMGQEFAIMBHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id E7D7E60ECFC
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 02:26:23 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1331cbf6357sf9778992fac.11
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 17:26:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666830382; cv=pass;
        d=google.com; s=arc-20160816;
        b=j0eRyAqBsCOC8UbJlasg9ryG4sZwd84G6wybOE3EgaqTYQ65wrPcCrMd6OxFaV+p9y
         q27XFxCbddYRhXFqOcg09o3AF/Qj93c0wm002YkOoRNkJPSVkWc0FgjwW1uqgrS5OOv+
         bus5A8rEOXyZN1c8LinNid6kB1fcoOopOWUsyFyHvJ6TUvxsO8Ihe4pyIgazTy+MUBjz
         Ys1sd2toB+wiCB3VTnatyGg5C3ELWq4Srr3q+K+ZhTn3psg0AZz9TVRruiOdFPX3NDFy
         0Qg0eXzRRe1gyPYGpRmCBSY+g4FHf7nz7WRFOhhY7YjrYN0kpB6xhlo0lIkffgepvw2f
         rZPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GcB95pvuROZRg87advsges5g+/nqP/BNA9viX6QkAjM=;
        b=HvBRjvVpB32yAZeDn27AFmKnmEjlWJ0bxKJhBQfUx+HR4hRnOxqLZFgIBbvX5SpT8C
         WoyXNkt1b9Io9VXNf5qFIaiklnLGF9DlvoPaWnBoXBO2NFPwUxH4L2flcGTW1Apu1Ebd
         mpP8XimRlGclvVGl/AcrUd9PWc/4K3TrDyZ6XEJtSSv4EZ3BElCh2rqCJC0xAWVHrGH4
         y9u3dNsWCcbiClnjKsFC4+wMzn8dVjtTNqor825yiPqto80cAvBVZ2iVmSaeFPLPUJlj
         wwvda1GnVpO0Z8OBEGwGp5IEh9xnFu0rhO8M+kMkGTp/jxFCyWxmyWED3q2Y2jMepUd1
         0B1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ijvBgS35;
       spf=pass (google.com: domain of srs0=xc5h=24=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Xc5h=24=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GcB95pvuROZRg87advsges5g+/nqP/BNA9viX6QkAjM=;
        b=feb+xWXGcmc8qLcEWLlhf2N/Qy70LhPHaoV1O58GW00ID0SimObFIGn59MAALHoraF
         pv/RXaF5Es9Scupw98tENi3OglbJpiDFvwdTu94KA7iI0IiHG7NSg7WpoYrguapd6M80
         ngq0EUa5IyAqjaddC0Mr4EwrOPZenzs2pcvO8sANKrmFoO6qJIFoRfuXOvzMToy6qkSC
         pEfiVR+9NBxbOJdojFfxQA66UJDmwZibkHQRkb2rwUMJ4yoa9DEcpiy3ybpfXtLq0iQY
         etf29eZfwdYTvQsz1TDSfYzuV9vHI9x9b570DFODPfKcnC26YzuPBk7y0UJwCd5ecoKA
         +eLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GcB95pvuROZRg87advsges5g+/nqP/BNA9viX6QkAjM=;
        b=xMR+m6RbTdp2oyKGvZ8Nhen9KVd70OD8h9BMxiW9Go+N62JoTQSkEZkt3qFAwsKpTS
         hxRroAkprrAzyeTGcw6ZVmZ+Zoal8PZrNaZbGZiglyRapfsoT53IWZtrxH8ar4pTCVkb
         qOZNayOH1O8/Yswn3mcWQ7Coc6vbrh4fhf92OCqq5c5wJers6WU6NoOX/hc6VXdOVNcH
         NHQMNoN3tuRT58ZncQOplarFc0L0/8ulLASr0p1gjc6sO/ahoUhP9H6PRQm0L3Rbm1Qr
         57/6EfMkc76jQ4Y3DoFRDx3muKQeSs5w7qIUlRuBo4JmAscfTXH+f85hs2pYYM/xblX8
         10zw==
X-Gm-Message-State: ACrzQf3rXfBAn50C18MI5TGnT4i09D/nTKRUbPTj2GlVQ/W6iBMP7t5g
	VaTjfj5QsSCCoROlmPIf5sE=
X-Google-Smtp-Source: AMsMyM7hPhKvkxo0xmIa7nu/2BgNC3/q5tWF1zxzHMtuSiQBqzrDIyYmb2Qy11IXVk9eai4bjnnFDg==
X-Received: by 2002:a05:6870:d584:b0:137:2c18:6864 with SMTP id u4-20020a056870d58400b001372c186864mr3762588oao.245.1666830382394;
        Wed, 26 Oct 2022 17:26:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4d94:0:b0:350:a26c:b39c with SMTP id y20-20020a544d94000000b00350a26cb39cls5229123oix.4.-pod-prod-gmail;
 Wed, 26 Oct 2022 17:26:21 -0700 (PDT)
X-Received: by 2002:a05:6808:3007:b0:351:3de7:82f4 with SMTP id ay7-20020a056808300700b003513de782f4mr3197363oib.103.1666830381880;
        Wed, 26 Oct 2022 17:26:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666830381; cv=none;
        d=google.com; s=arc-20160816;
        b=KeQhqre8N1gAVSkOB+WTRZEthDwUrce2YP1GevyxravYrw/b8JwexhOwsLbSEwjo5x
         F1Lrdyi0i/cPURV50Tyx/ZovYjlDO8+1natdkuF96gUZWhUpVK1rhNmI3+RcNmo/mfwY
         yjujlsez2xUpJGkoZ8SNRjyZwCpv9JtTRx7lGKG/2J8cGLdYAQN46GMdlCZp2nwuyDe4
         3lQGoERgh1UoWS4sO6C+y9PbEiCFq+DJ7UatB3xd6G+Oa8iOVL+QulOFycH1g3qRCSbr
         2pVw7c+31L0ZVd/QKmPEXsSY/dS8s5pv6uhqXeDP1Y6qALRfmkf0skVH+3EQ+gLMhfHy
         EpvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HZh5FWwEvzCuhST+974hqDrLBeiYLFft+qhaMj5G6Ho=;
        b=gVt3GNDcGN5W7hOYRcBSN38Le3Gbfon2Tyr268j0s7fZXOa0giK5/YysC1v7+pxuns
         jIm3jklBJn9T4HYAex1JcbMaobvCfumKGiL1GOBCYpqUuNUlkkOBGlDgr14MCKNT1G34
         R7yeKzDIoVgb2FhLl7Gw1S60xvEXyB9gYBD1Ilgij5/zkh93Qoc0hxOdzavCeq66A7jo
         K4pkZU8KW6MoPStmaEbdLIIV4XZCwy9csfPCDv1KCJ3gfkxDKFUUHbHEHXqQQ6lemYeE
         0Eukrm4S6qfvQ4NDEP1f2hh7BDcSCCoBCiDJKw9R71IzGl07OrzzRQHLiAjG6W1xl8Mx
         SAAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ijvBgS35;
       spf=pass (google.com: domain of srs0=xc5h=24=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Xc5h=24=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z19-20020a056870461300b0013755db641asi554046oao.5.2022.10.26.17.26.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Oct 2022 17:26:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xc5h=24=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 65FFD620D8;
	Thu, 27 Oct 2022 00:26:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2F3BEC433D6;
	Thu, 27 Oct 2022 00:26:20 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 7e9c09b8 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 27 Oct 2022 00:26:18 +0000 (UTC)
Date: Thu, 27 Oct 2022 02:26:15 +0200
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, patches@lists.linux.dev,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: Re: [PATCH] kfence: buffer random bools in bitmask
Message-ID: <Y1nQJ9ZFizv0bzgI@zx2c4.com>
References: <20221026204031.1699061-1-Jason@zx2c4.com>
 <CANpmjNMmHa04Fqf5Ub5-vz6HuqT_Gg8GmEfKD6rv8JeMfBZ32w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMmHa04Fqf5Ub5-vz6HuqT_Gg8GmEfKD6rv8JeMfBZ32w@mail.gmail.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=ijvBgS35;       spf=pass
 (google.com: domain of srs0=xc5h=24=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Xc5h=24=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Hi Marco,

On Wed, Oct 26, 2022 at 05:04:27PM -0700, Marco Elver wrote:
> Is it to avoid depleting the entropy pool?

The entropy pool never depletes, so no.

> kfence_guarded_alloc() is supposed to be a slow-path. And if it were a

Ahh, my huge misunderstanding, then. For some reason, I was under the
general assumption that this got called for every allocation. Given that
this apparently isn't the case, let's indeed just forget I posted this.

This then means, by the way, that there are in fact no fast-path
users of random booleans, which means get_random_bool() is totally
unnecessary. Before I thought this was the one case, hence open coding
it, but luckily that even isn't necessary.

Anyway, sorry for the noise.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1nQJ9ZFizv0bzgI%40zx2c4.com.
