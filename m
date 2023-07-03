Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQ6HROSQMGQENBBWKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DD0F745F65
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jul 2023 17:05:41 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6237c937691sf26981106d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jul 2023 08:05:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688396740; cv=pass;
        d=google.com; s=arc-20160816;
        b=v1A+FLmKo7Vk2+LTW9ojCHv2dNdeE0aeEY+qKcO2J4TJS0X8DK+5zz60RLfJfMCr4S
         YGUIkDCQf+5W2E6ujyFIgP7+qVt/qb9wQHsID69paE6vbswHfBixleuNsZ4dvD1w25RM
         b0piQK7Rp1W+gbgc+wN7f0OPe8vKskz4zHgPrnD0p7ldsxT0YwBMR2vRWXPSzbXPWSAW
         ak2IqCC/1QaLRpLZ2i8jtugr4yUYbCVwySkhrKx+4beWhElhITsPaa15UygxbrjYZH+P
         PdlL02Wopu1zFmdYKFDaeFb0t9vJnbejAmaSqp8ATwrTV4y1helwAxsVZcdFWRiWA5T0
         HfHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DlpItEHSI1f9B4sH2cphdRzWwbPyugvpqj7DUPEAGJs=;
        fh=7eRN3Hzzf3Youu5ohttmWxGeDRMfgcfsReV5GltAtO8=;
        b=DZlTeiqQ1VWcZ6QVB5XN2yoqb/RqqqAnDnAGb1Q6Uv1PI9nMjHvFxb8ZZfrvrXOM6M
         sWCkC8+mscvaG1Q0Yu85z3V0afVtFKJVeWrZQdYpmM7yradZgcrMKmhLNvcqJYpGRdqx
         FGcF5BpwLc05FjXUbr8vb+vSM6tpkWUD5ZVjsmEaRvlhuSD2vE1cQEFERqCC4HhNLzYC
         jLaGsAJRKmXL67VAQ4zWFlEb6UQ5WrkCjB5aYu0+4sAs0uWe54igK3xuTi5ZlTQH9U0W
         qaRrolq/ub9x5Ak2CStniTlBxpxJukZkOMOGJu/12g6c2RydRx4lga0L4HBPd/KmwcaY
         vGdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688396740; x=1690988740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DlpItEHSI1f9B4sH2cphdRzWwbPyugvpqj7DUPEAGJs=;
        b=nYczQxaX624Vy3KrpaVsptLzzhtZfk0JWpcuWKYuPlP6SK2j9tWRAWoW1or6gG+XxM
         4lIztLMBKqTKz6052OBezC1I6mGFZD4UJApWFgPWImA2tGTKdshpKBSk1V8Zy/0gsBiP
         uaddAXJprrPvZ1x2J9Kz48cbSwk8QLqPs/HfoJtuofWY9/jG0T8Am7D+OkUx08a2iNEo
         u6EbzvE/H5xoDc58b/sw6LdbhA8NxqJqsU4Y1SCjbwrfPQ9e6wKxeRMabpyDBfX2JC53
         G8+Ip5aT8Q6n5oAjkPwS3Z5su0M4rti1QOkneWPAZWoNPQFppzXj43ZJp/NwVb4rS1Ac
         Sehg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688396740; x=1690988740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DlpItEHSI1f9B4sH2cphdRzWwbPyugvpqj7DUPEAGJs=;
        b=RlIx087rLMwEx6mqRZ/xcenqWwSe4AZNnhUjyQlLnW1RRlT/SqSk7DMhbQo/yGkgJw
         x1KGwSrPC8SQ45FrY/xKpQoLMmmGQbVTRqBd59lMevFdKH/oppvOg7YT1n3GxtSItjUV
         vbtVMSUH14YhKJt6cvjtLW4kJqPZLk2xdWz2GAKQjPQDdRP0Ki+yyfEgAHeut/xxKjTK
         rm8czcG2QRdoGxRPiiMHl42g5jzIhK13/fgGJ4YyDkPNN7dfm0qNCpxqSwiax3f6u8Gj
         QJBvN3YEcpo1qMYFGyEN+rcXR4lFEXhcJpsa/D/HcvEDYzNQF58ZecFtMlb02TI4czuO
         0q9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYzcsrEOpiSiPmEy9I35Zzj9gjO16I1gx+sjUlWCDBEZULZ2q5v
	NgdeyWdePIGVu+zF4hIoVz0=
X-Google-Smtp-Source: APBJJlG3YEkb4ev2czC1yqW6H7hYs3WtAziN9gENksGa8GcoScBVatBonx6TIQqko+k1CpdqOuXg9A==
X-Received: by 2002:a05:6214:528d:b0:635:daa7:f859 with SMTP id kj13-20020a056214528d00b00635daa7f859mr14050770qvb.2.1688396739992;
        Mon, 03 Jul 2023 08:05:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ef4b:0:b0:634:c778:c1c7 with SMTP id t11-20020a0cef4b000000b00634c778c1c7ls85406qvs.1.-pod-prod-00-us;
 Mon, 03 Jul 2023 08:05:39 -0700 (PDT)
X-Received: by 2002:a1f:c1cd:0:b0:471:4e22:775d with SMTP id r196-20020a1fc1cd000000b004714e22775dmr3884644vkf.2.1688396739421;
        Mon, 03 Jul 2023 08:05:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688396739; cv=none;
        d=google.com; s=arc-20160816;
        b=Ly51McOI2/ipjvVLTSuAw+K9+eR76KU20OULt5mUtGranlxSepOD2aqCwBEaBb+dTI
         A/nx+SXowy5R7U0F/vPtgne9q4NWq+VKv9lYPKqmfn28zXkvezeIz6mrVJZM8ubPZUBy
         mRP+8I9z2b8zHw8zx2xR+SZl/Z1ShnQ6QUS2HtUdgiiCOZYCHWCnabJcXY9GVz8HcQj/
         ECLBsBIB1JFUKsI8+TSIOmeigL+ltlZQ6DumTkjYxEXFogLg6nlVy4qEwcB2MRKFCr8v
         7GnNMwfr/TRx/l6RdSGXhlVIyNYa4AjWdjAhR9+NG6Esprk0G0QRCl8zoCBoJ+QN4m8o
         FiHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ONnZupwIZvuh/ltSdCN//qSxBADWCvN5UiHKQCJiD+A=;
        fh=oZM15v5/RBviWWTy+NnHYlV670LuwfGo5WCIpkmkMPI=;
        b=I4ViTOL9WCpFJop62E3BPNyyNWKJ4gLezT2T7GhQOlNc9uJjLoRRPr2Wc/cVPO9AR2
         dNOV2TznJzMaHZJyUA70cF1mwL6bz0/ZzWyjIxhIg4U3BpyYxIVaRRuQukJTVViD98Nf
         3yU/G8j0xd4zk1nswO7Ul8/UljMxh3D5J3xNgD4txOwqahxDofnZUPdVQFGn1IdgHH8z
         YxiOe3BlvOjtVD0SJh1ZgSmcQmwrIIO1y6Ht/gpNyzZqRB3+xofsywAAX7jzqJW+iJ9P
         7C0D7fl1jdha+LQkN7oyRk3AFMbfWf1PKCeBDx+RFM6jqvN5dNH1JXK4udF9UM58XBXO
         Z1TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id q140-20020a1fa792000000b0046557175e54si2228515vke.1.2023.07.03.08.05.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jul 2023 08:05:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F164360F7B;
	Mon,  3 Jul 2023 15:05:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C2816C433C8;
	Mon,  3 Jul 2023 15:05:37 +0000 (UTC)
Date: Mon, 3 Jul 2023 16:05:38 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Peter Collingbourne <pcc@google.com>, Will Deacon <will@kernel.org>,
	Qun-wei Lin <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Casper Li <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, eugenis@google.com,
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
Message-ID: <ZKLjwjYUM2zSRtJ5@arm.com>
References: <20230523004312.1807357-1-pcc@google.com>
 <20230523004312.1807357-2-pcc@google.com>
 <20230605140554.GC21212@willie-the-truck>
 <CAMn1gO4k=rg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A@mail.gmail.com>
 <ZJ1VersqnJcMXMyi@arm.com>
 <20230702123821.04e64ea2c04dd0fdc947bda3@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230702123821.04e64ea2c04dd0fdc947bda3@linux-foundation.org>
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

On Sun, Jul 02, 2023 at 12:38:21PM -0700, Andrew Morton wrote:
> On Thu, 29 Jun 2023 10:57:14 +0100 Catalin Marinas <catalin.marinas@arm.com> wrote:
> > Andrew, what's your preference for this series? I'd like at least the
> > first patch to go into 6.5 as a fix. The second patch seems to be fairly
> > low risk and I'm happy for the third arm64 patch/cleanup to go in
> > 6.5-rc1 (but it depends on the second patch). If you prefer, I can pick
> > them up and send a pull request to Linus next week before -rc1.
> > Otherwise you (or I) can queue the first patch and leave the other two
> > for 6.6.
> 
> Thanks.  I queued [1/3] for 6.5-rcX with a cc:stable.  And I queued
> [2/3] and [3/3] for 6.6-rc1.
> 
> If you wish to grab any/all of these then please do so - Stephen
> will tell us of the duplicate and I'll drop the mm-git copy.

That's great, thanks. We'll let you know if there are any conflicts
during the 6.6 preparation.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZKLjwjYUM2zSRtJ5%40arm.com.
