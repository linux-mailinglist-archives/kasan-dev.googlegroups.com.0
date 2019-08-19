Return-Path: <kasan-dev+bncBDAZZCVNSYPBB75Y5LVAKGQE4PCBGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4636D923F6
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 14:56:33 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id 71sf1968039pld.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 05:56:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566219391; cv=pass;
        d=google.com; s=arc-20160816;
        b=fERRISnk9tszeV/is2jB9nu6iGIqRt+abBzwL0YqsSWAXqP3xsWEjAOKA4doSp2PJS
         4w1y1UsWUqYcv8pWMRSVsM5V0ip3KVYG+k9D2HmLhDcyCcDNnIXq8w6IACivShCg6YSD
         NLzUKEt4Qk2pzveVyw6/b7I0yogrdH7Q9tgXsDOb2Sh4U/UeC2hU7iiRceWW0vGSMmJH
         FJ35lz5xUqBsnCofCvVlCF90Kii09mVNS7+oPQAQlA6FoFv9ckDML9NbCT5hY2FfjbTT
         La6OiVC/W3EWLeK+aH2p6QBVJ+aPnfGPRu5Skm7sFpGExc8OuZbCZfD67hlZMDiuMlSf
         6D5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9gppcRalumzZn5nVKsQIT+bzUDdtTLkU3MiGe9Nkz+w=;
        b=X6xJdn5tGreEti0zMNu7xQYjhMPNFE5WJRZRxdJMikwvvAXqBdLhQgjtJSIcTtIThU
         Cvu5zjHFYfATo6Vdo16hc+KEREl74DVHVinRjo8Mok0Lh/c0e1BgG544F31V4jPrE9DD
         n47XVIUGV6ruTPm8KpWG/Lu3QSj5rVk5PlDeEKosy9MHUD9Sr4EeDTlsWiTFAck17fDd
         KZCtzNptkesVjw2yWFLFn3VgGuBrJfLr0qnJ3HpdyYFyvmeNXmQLLVE0/IK4mifmYigZ
         x+O8gJJCvmsbvnR3nukvTO6dhTI7hSdHQh58GfVYS0i2/w4mFKKIG3jiQJzQZbxFdf9v
         mpaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=G6j37x4g;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9gppcRalumzZn5nVKsQIT+bzUDdtTLkU3MiGe9Nkz+w=;
        b=roCTOCXI3FQFv6wtAaHOJVw48wdVc7ptFkU9han3xMb1h/EBvLTIBMY4a54o0CQySk
         ZHVjPOXBj1XsWXrMILDUoEuohjdfyNVQJWsoaxVLvCK5t9ycAhIs5VODjgMSoV1Zw0gj
         +12N7lrBYhLAY4W/wCb9rK1aLBxr4BgCwS5gwr11rFL5SRRkafAxLUKlRpwfrs/abW8E
         tBEfqSGSocN6JDeC7P6wq3WCxJua3DJ5QTc5mr6bx5YFSOcT5gQBxMmSdw6+mzyS8xvs
         jXPMi9Jti1+Zecw+ijlPHSSP/ZePuKUVFJW36ssDEmpjwRWSbNtS2o15Dx8iXeFqmxlW
         6PBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9gppcRalumzZn5nVKsQIT+bzUDdtTLkU3MiGe9Nkz+w=;
        b=gjWZ4IYe1mlfR/qd0y0NW4yYZaLaiEBdkRBAVwBRMslDKq3wRn9pQ55lYq+S5Lb0Vh
         E8N06BHgjYsa33+s61QFwqFh7ZFPNm+YtmQsEOqhxfrjzCAl0nFPCCzDBagFHlYRuegu
         xP46BvKphG7V2UVmGwMvm2c3h+8NgQEFiTA1IDgpkzo1w0ulqNdWnt3uyEMCmsxUpXkW
         0Zf8iED777p/DglIly09bgF4Id8Ga17qb7KGk/E2UwsFZO8CixJ5cyAcwDw7XQe/nwkg
         XzJA3BgQpr+b21jGDAz20xbKLssiAyUtt25CQjAfO8nuvTX4XnKaBMqt0432ztwzdWD5
         5XLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXMy/5BiHwmlD9R9VatTm1Cmu0WI5Rk7cJ9tH+V8Fa2RsNdIlSq
	objrz9+0s6rcTMwa6q20XI4=
X-Google-Smtp-Source: APXvYqwzW0Vi/TOP7roB8DsMOHVMZUEV/N4sFAFmhzpQff3i6HOjquZ0XtxlZDKRUCG+Dnjz/lDmUA==
X-Received: by 2002:aa7:842f:: with SMTP id q15mr23822110pfn.250.1566219391845;
        Mon, 19 Aug 2019 05:56:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8346:: with SMTP id z6ls4015292pln.8.gmail; Mon, 19
 Aug 2019 05:56:31 -0700 (PDT)
X-Received: by 2002:a17:90a:e2ca:: with SMTP id fr10mr10929812pjb.72.1566219391599;
        Mon, 19 Aug 2019 05:56:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566219391; cv=none;
        d=google.com; s=arc-20160816;
        b=LFLM4V3Pa0pubErR3BR5xkSOXf1GOet351aQYlbdY4uBForL/w5LES8dvUaY7w4nxw
         BElttK71eNJoGyZRyKLtgDzFw3Y3ie6RJRg/ZE0KEhLGTpp+u+G8I9JJ6uAHw05jrAV9
         OwnIvwTLYIRHOzukq8EotZUqnd2a9QkZ21cTKJKxmwri95u8dAOHnvifHJmfjjTzOzus
         XZ0onaZ6ZH02MDQPoVYLLjrxZlAYSa3pm3DRIhTYtWE+dN0w7UpyKRAJ/Uz7j73sUoUX
         ypJVV+orU+c1lvp/uLRD59bz4j0oL4Tzqy3dIJ1gyOlz9TzUe/rb8Z2GryizWqTgk9sJ
         EY/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=R6yXXBgZg+o5QQAot3xwq1KoOzttzifDq8QrxYrqxoM=;
        b=o57INvevKB+enZRuud+kb46sOqguJvX/aphGnxwDufoPf2fijkMJwY7nKlyc7/oc5e
         IJQz+wMLdQHG3a0754fN2Vuqdl/Vv1xcnBLGtyusH89qM0itb5M4gSFGaDvs4Aai3fx1
         GcKmWY/eO2P9zvG/V93XZpRbxTGYii84Cpj+RAgunoshFQMzELVxePDjA9PUnPlBCGmU
         uGEJf8V0gVCH0kwqy0p0gHvLQiDhXFKF+y+5ONrwtNVD+4yz0CcimeNN7HTPrx6vWKhS
         xpyg5AwI71sa2oSuAOzeoBOOvaMTv1fRNujRD4OXx5nnjCHym5ixQgjmfORRsfWQ2bNZ
         GhiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=G6j37x4g;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u199si716487pgb.1.2019.08.19.05.56.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 05:56:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 073A7205C9;
	Mon, 19 Aug 2019 12:56:28 +0000 (UTC)
Date: Mon, 19 Aug 2019 13:56:26 +0100
From: Will Deacon <will@kernel.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>, wsd_upstream@mediatek.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=G6j37x4g;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> but it will modify pointer tag into 0xff, so there is a false positive.
> 
> When enable tag-based kasan, phys_to_virt() function need to rewrite
> its original pointer tag in order to avoid kasan report an incorrect
> memory corruption.

Hmm. Which tree did you see this on? We've recently queued a load of fixes
in this area, but I /thought/ they were only needed after the support for
52-bit virtual addressing in the kernel.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819125625.bu3nbrldg7te5kwc%40willie-the-truck.
