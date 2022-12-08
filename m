Return-Path: <kasan-dev+bncBDBZNDGJ54FBBR42YWOAMGQEK5IARYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD41646706
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 03:34:48 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id k19-20020ac24f13000000b004a49391ef9esf7725785lfr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Dec 2022 18:34:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670466888; cv=pass;
        d=google.com; s=arc-20160816;
        b=i30+eAyAlhT3K62HlTwBB/FNSbjwA6TYaGMDdL474AE295yzGSRPQ++/c2q0sc247Z
         sm+Zf9VnmKePwVMYIwJBqSaSlrfXSJgPq6RJ1bZH5pIjnQts86nOwHCryd81lGFTUosi
         EGqDsczd0xcGO3o4TJ9GV5QYrfCdCb/cXmXelGa7EEZJMZ4+by504YpmAlwn/8/lBdmI
         EdTRY2GqjBAfj5M/HH31TUbGvcXFoFzmqqwqcc+52oTZthypsdxnHeh4gwKZNLVxHs/g
         BVWbMd06A/WENYXRxLzD2WvYfU1JsMMinNWVN6rsAaSFmyrAw17ayAMtH7JxF7BiuNyE
         F/zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=59XxkSdJjKIGB4tPrj6xC2MWa6YTdJGWwSr3j1seZpU=;
        b=pGVjZq7gh8bNsefawDy+gTMnbUHltFdXmfndhSw9o7W1myEDkdDOfcjBJtMi9NVtkL
         lOFgZGc03xrpKO5HWvnxjaLkekH1/SOfa+Wu8UWCqQv68K0lPbbbzxylA8n+81+GCGpu
         xHLYQd/0kcx1wrMrFto/dOsxzdso1swT/hmfEmrBSO4S4mOe5hfkbCTI529vxeggsFLS
         MfmdPWE2VNI4mfeD7jnS7b05UkvkKO+2lU91NaDDzrWHF4uexlKzSnUq9tSsfnFkDST1
         OQLPZ0dXcjXNrYyAEZSNXaizAaWSlQeL9I1ZG6YM9Vo6CGko+BLZSr6AxDnBEnXXVtsy
         3ndQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=elFqximT;
       spf=pass (google.com: domain of kuba@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=59XxkSdJjKIGB4tPrj6xC2MWa6YTdJGWwSr3j1seZpU=;
        b=IGjnE3+AMNdQQHFncvMaUxbsdtGVHHhWanU3iWIGVmxdtjuWqmcych0qdt4n/quEaL
         hJmSsvjJ6k+9G/BO4OprFrqJI92wgvgvevsWKGK0/73LAC4Zl9+Qsk4A9Az9Vo9TWcLq
         84zfMbx/dKpFmI20KpA2WmmkiPocDtUGEVQB8/TPPlcpsjhGu/RurHRGIDvnEMTnJa1r
         VZMERIa9viAtKci4VNETSGkQITtInW2bYrmbP0oWb84Or0BfAt6GOHp6jhIarlcMVYLO
         aFyhDvGCFkHxmGxn8B5pVc/ZBc7mh7FJCzBjg/+rU72e4vRqN31Al7OYMWCZU7WFB5G/
         1JEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=59XxkSdJjKIGB4tPrj6xC2MWa6YTdJGWwSr3j1seZpU=;
        b=AE1WZKsQu3PX6brbyxiHCVo0KNFgIFYus/04NJfs59X+pLZSECMUtuz7Za3fgx+7cg
         5O5vu5QMvCmy5NjLmrMGO2W+au8ss6lkgtbJ7aLYzYWeaUUy3J+x42HCD7ZAwCxiKen4
         wExGk1C40cB5YIjm3GTqIhc3OW3zTtiufCTjix0HwD/xzvZkGeNFICUghKl58sC8Ti+U
         oHjHZwHW9sJmYyyGB0nvDOt65oT48oCPJXf9E2kSaq7o7dbs1F/ZQCiiLOVwmw26Vapc
         wEUIHZl1GO1amVu4t98q5LpZKaBkCTKhpQdyzADr2Gq5udc2qlK4PZ0HShO+oPW6PxIV
         t7ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnA2tsDltngsU8b3xW3YryEfMW5KZ8YFnjewSiibFUGZ5ULwUJH
	EBOopmrKA2WpmAl+GxDEg3Q=
X-Google-Smtp-Source: AA0mqf4b7m6A5SIULbBwItqFutNCFpjHH4u7EeAfxU17myZRBHQ9ghiAiizNqYxzqvxveKvhlm6kTg==
X-Received: by 2002:a2e:a26a:0:b0:277:34bb:ea2 with SMTP id k10-20020a2ea26a000000b0027734bb0ea2mr24007720ljm.427.1670466887534;
        Wed, 07 Dec 2022 18:34:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2012:b0:4a2:3951:eac8 with SMTP id
 a18-20020a056512201200b004a23951eac8ls1175452lfb.0.-pod-prod-gmail; Wed, 07
 Dec 2022 18:34:46 -0800 (PST)
X-Received: by 2002:a05:6512:96b:b0:4b5:9182:9344 with SMTP id v11-20020a056512096b00b004b591829344mr1601475lft.408.1670466885937;
        Wed, 07 Dec 2022 18:34:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670466885; cv=none;
        d=google.com; s=arc-20160816;
        b=gcYaxLKpnIVU7oAk6BH77p1c8+kaORcJyddAza/r7Kl91dna34Ga5gz68MwsjW1s6G
         NiTOj6xRWh+h7m+BGMj79K3y2K2n4DtF9YRAL3gXuO519K70RumXF4V52aJ0ZtC0+6A5
         D6YjkZ3b+3ESYXLFvxonGV0vTEo4cBz885sAc3OmHv04keoJvQv06EeSHdnkoo5zwsUL
         A0AisYWj5WLk1GWjtRgdYeNZK18N4kBzMwcfCNg296XwV1y5sMsj3WbKcA81iG9Gd4bx
         nob1WRWDrzrZM3LKkxgvezMhOpJ4t6m57kBvrYXDURSMdYRKNn0pVgTJ6XQ+JYWgaqSc
         bfpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XbxpXkgwxPJEWUbE3zMhjV+UAGZUquvYAvPXSCAM8cQ=;
        b=Px7aZGbOaNlZK0XdflJuzFWNq6v4IRFTnDPRbRmbQMQzqQsInn637oILZamPUNEh1y
         DdkaHDRVXAXPm5/Xm7hZcN0cDWNmuuFNLUnoaO/ln9XNUqoLIP1z+YflncYNKM27hz6J
         hMQ2PbJnv80039odohT41OnGfLe5bWWWzrcvWdI8bBphdK97vvaJxqDGbInQlC34N1hI
         ouMy1/aQiT7wsfYeVXvuxtsKgIILC4jXSS8K/XxrL9Mdr/BneXZRLKaoAfMofWlXiL9k
         DYWAA92YjSzDLaX3leREg74r+8w5ETHPgFzvxgGSwh+zrQWcAZu4FZ3FiMzw1RJL5Vsz
         mUEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=elFqximT;
       spf=pass (google.com: domain of kuba@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p6-20020a2eb986000000b00277385b7372si963923ljp.4.2022.12.07.18.34.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Dec 2022 18:34:45 -0800 (PST)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 42595B821FD;
	Thu,  8 Dec 2022 02:34:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 51241C433D7;
	Thu,  8 Dec 2022 02:34:42 +0000 (UTC)
Date: Wed, 7 Dec 2022 18:34:40 -0800
From: Jakub Kicinski <kuba@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com, Eric Dumazet
 <edumazet@google.com>, "David S. Miller" <davem@davemloft.net>, Paolo Abeni
 <pabeni@redhat.com>, Pavel Begunkov <asml.silence@gmail.com>, pepsipu
 <soopthegoop@gmail.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev
 <kasan-dev@googlegroups.com>, Andrii Nakryiko <andrii@kernel.org>,
 ast@kernel.org, bpf <bpf@vger.kernel.org>, Daniel Borkmann
 <daniel@iogearbox.net>, Hao Luo <haoluo@google.com>, Jesper Dangaard Brouer
 <hawk@kernel.org>, John Fastabend <john.fastabend@gmail.com>,
 jolsa@kernel.org, KP Singh <kpsingh@kernel.org>, martin.lau@linux.dev,
 Stanislav Fomichev <sdf@google.com>, song@kernel.org, Yonghong Song
 <yhs@fb.com>, netdev@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>,
 Rasesh Mody <rmody@marvell.com>, Ariel Elior <aelior@marvell.com>, Manish
 Chopra <manishc@marvell.com>, Menglong Dong <imagedong@tencent.com>, David
 Ahern <dsahern@kernel.org>, Richard Gobert <richardbgobert@gmail.com>,
 David Rientjes <rientjes@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, GR-Linux-NIC-Dev@marvell.com,
 linux-hardening@vger.kernel.org
Subject: Re: [PATCH net-next v2] skbuff: Introduce slab_build_skb()
Message-ID: <20221207183440.4c80918b@kernel.org>
In-Reply-To: <20221208000209.gonna.368-kees@kernel.org>
References: <20221208000209.gonna.368-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=elFqximT;       spf=pass
 (google.com: domain of kuba@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Wed,  7 Dec 2022 16:02:13 -0800 Kees Cook wrote:
> Is this what you had in mind for this kind of change?

nice, thanks a lot!

the only thing left to do is kdoc updates:
 - the existing kdocs should no longer mention frag_size == 0
 - kdoc on the slab_build_skb() should say:

  /* build_skb() variant which can operate on slab buffers.
   * Note that this should be used sparingly as slab buffers
   * cannot be combined efficiently by GRO!
   */

But this can all be done by us in a follow up, there's probably
more cleaning we can do in those kdocs.

> v2: introduce separate helper (kuba)
> v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221207183440.4c80918b%40kernel.org.
