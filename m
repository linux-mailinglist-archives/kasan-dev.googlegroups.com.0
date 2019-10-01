Return-Path: <kasan-dev+bncBDVIHK4E4ILBB27TZTWAKGQEXUYAVWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E203CC328F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 13:35:07 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id p14sf3957634ljh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 04:35:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569929707; cv=pass;
        d=google.com; s=arc-20160816;
        b=In1B7qPpdlMq5gPCjEVG8LPhUwj+qyEnno9v8FcZspVZOjaxLfuUB7u+g7lXEonr+7
         IDFMxioXZxbN0VXVGyr/Q6TFTmPOzytQDfDZKj4aCYGEe9zjGRPXkZsiNHam64NdTSqn
         IE+YNDaaZjfhUhHMMYuLxkSO8hn5UQdkSI/MubpmhaSutFuXGtF1P1PswOVRWbsVwSLa
         LTJjp+D9QTAO2Km+LQ3J057JIOqbp3WO2Dwlv5QRW4ZNQy5F3lO8vnQdPUmaa3+jmY57
         i0J1oA3Em3Zx1k6bvuEr/TeelrCS+MTp7qj47OrtBjYaw+6LhplHVLy4qBAcoAIdoqfL
         fGKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Kv0GE1+aRIsyWS1cf9zO57PrTmxOfx4jpcdDLPVPF4U=;
        b=LN2U2QFDVgSohhJ51cFcR+vGLAJDryCJ47bns90UROSCIb7QampejQVHUC64GxhX/Z
         z6FSOlAsk1ERkxLGfO/zobblJd/lTOrVi6P3r4xVEl2DcrwUcsl4jl4Sp0PrDCAJNOms
         Wvk0KpSXls4vhmsma2nMD6ya0Ig0JhrqVIS/nUYfIqKP6rnFH4k0ROCDcWMVhMaR+z7T
         ZUthai3pLxeJTh2HRUolFlCN73SxelyrQnWD0OlBA17AYj84BiTTbfXtPoTLhxmyrZ89
         OrhlATAxTxIBa4K0cOgDyWB3xPz+tuKowvYwOFp0UvJW9p5vnrT0i8WLeH6jn60SfAD8
         BGgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=P+CATDmh;
       spf=neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kv0GE1+aRIsyWS1cf9zO57PrTmxOfx4jpcdDLPVPF4U=;
        b=p7tFiDzVNmBv0SBb5e8QIoDuu7fe52qlF6iA6gNF7Yq4D6g6WyZQQzTlY8YS+0tg9e
         ZUaZ9epw/oRi70tiG7Sw5fc/Z1iHVT0uwn4XayOGZ7VzrsMIutxNACce6l76jhoc6F2F
         PrXaOW4BVOe+u90kh9jiPeCMXpb3nQ3S8AseWdvziBjQ6jY0x89CukAPgVTyQz5HsIT/
         32dAntMrTmftjMiEzJPKgllBq/rF1EWyLbVDTV3I3v0ZpikHfPV7V6kfUE18iZwhQ4uk
         uuKGgVlBoj3xvKc+IJ+ICdpNM6iAVi1jAWpqln7igJM/ZydI2KrBU/Oj76wFeAra5Y7P
         lQvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kv0GE1+aRIsyWS1cf9zO57PrTmxOfx4jpcdDLPVPF4U=;
        b=tYPLvMCB3Mpykws4gNst5ppk2chPQjAXMNcSDe0Pe22Hu08S22UHHHpM8kbcYfx5Vc
         jbhZmwV0vyHOI7WkX8W9hmFUwPfezA2koGg1V20sNIkZKbQCgA/kcETzMdEF3MNgmwHZ
         nzUDeMMhvOHfWS67O3gsSU8WIKMECteivK0W3xhcLldm5RP/1tyxQLoEnuI6pn0rfrRZ
         P+ZBBIoS5q3nsVTgg5Hkm15PaLE3gfRk/V9yzbK52VTLO66FO2CLWIfZomLFkdLVLXeA
         Wswyr4jDJTgDxooJwrEqdjOtSWhxVbLEiFPOxV8C1aP+19fHIZVjA7wlgSKVNnj7cXVB
         JU/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVpfAvRwsqnViqdPUqJ8x1KJ1CvdzrSFyY5rka8UkHRoAbUPKe
	XC6+iWRJWTqFHmYokpWTm/M=
X-Google-Smtp-Source: APXvYqyetvVWbPOEe9ucJ/hLhk3FEdLnDI7TfbCYVqdD2ZlJfsjUA5KhkIDX79QAdEkU4FcJMaMxTQ==
X-Received: by 2002:ac2:47e3:: with SMTP id b3mr8159503lfp.80.1569929707509;
        Tue, 01 Oct 2019 04:35:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5d57:: with SMTP id p23ls1482020lfj.4.gmail; Tue, 01 Oct
 2019 04:35:06 -0700 (PDT)
X-Received: by 2002:ac2:5445:: with SMTP id d5mr14100960lfn.43.1569929706612;
        Tue, 01 Oct 2019 04:35:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569929706; cv=none;
        d=google.com; s=arc-20160816;
        b=GBiHLIMfuJytPUki1IZiRfI5z2G5FGEG/g5X8uXK//njRG5sRpgDCJRYk2i5x7+pHC
         fvQfWI8bVV8l7l+sTfb4aewv+myodYPzPpVbvP7enPVYIoHm/Oz173jcXHAbXMmsG4Uy
         BeHNkU/WDvvLMKyjQjMWaUV2my9r+g7pinEy9SDkz6SXkdojs6JtY9roF1yWAv1jWaCc
         DTIKwhWbfxtWjj1oPOZ25iwDShsmPosQTla/7iIjvfeLfQNOpuuBxLNU0GaqnjsPT/zD
         Vhs/MAgPWqTKidJ3x23bDoAUBDVRFaRGrmJndlF8EHvFwKWD4avxSvONyFH9KZV5g1On
         jCHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=E97hATFqUaGgFuCNpdc4AOwFPOf5+SqGe40+poznacI=;
        b=hG6R84aREMi0b0t4y4umDwg13ec7O6vBzRz2ViZt8Z2hJj0I4oVYwR5OkH8GBFbjg3
         sjW3AIZmmSidBjQbBxGm7IUqKA7Hab9S06uNaDqGsRI9d/4YfzRG1RpdvG4+EieTEScn
         dC27fvV5jDK2bqOGGCAMHv62zP/yL8U/D43a/X8r02fQIyvkR33YkK5pBAmv2NXhTLur
         g3DIFt84pRYwJydvRshyNMo768RKvkofi3+fM4zGHlprVX/KW5MFw4ZlkDBHQneB5l1u
         mUYFuUxCbYWVlokqZDUiHQoTQJFoCYXTtUuLvxgDfTTnWur7NKLkwTNe66QumEkeK6Lw
         ymAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=P+CATDmh;
       spf=neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x541.google.com (mail-ed1-x541.google.com. [2a00:1450:4864:20::541])
        by gmr-mx.google.com with ESMTPS id h6si859139lfc.3.2019.10.01.04.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 04:35:06 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::541 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::541;
Received: by mail-ed1-x541.google.com with SMTP id y91so11539040ede.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 04:35:06 -0700 (PDT)
X-Received: by 2002:a50:ce06:: with SMTP id y6mr24178667edi.282.1569929706062;
        Tue, 01 Oct 2019 04:35:06 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id g6sm3087125edk.40.2019.10.01.04.35.05
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 04:35:05 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id BC366102FB8; Tue,  1 Oct 2019 14:35:05 +0300 (+03)
Date: Tue, 1 Oct 2019 14:35:05 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Qian Cai <cai@lca.pw>, Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
Message-ID: <20191001113505.kidbhjl7u2hawxvb@box>
References: <20190930122916.14969-1-vbabka@suse.cz>
 <20190930122916.14969-3-vbabka@suse.cz>
 <1569847787.5576.244.camel@lca.pw>
 <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=P+CATDmh;       spf=neutral (google.com: 2a00:1450:4864:20::541 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Mon, Sep 30, 2019 at 11:39:34PM +0200, Vlastimil Babka wrote:
> On 9/30/19 2:49 PM, Qian Cai wrote:
> >> --- a/Documentation/admin-guide/kernel-parameters.txt
> >> +++ b/Documentation/admin-guide/kernel-parameters.txt
> >> @@ -3237,6 +3237,14 @@
> >>  			we can turn it on.
> >>  			on: enable the feature
> >>  
> >> +	page_owner_free=
> >> +			[KNL] When enabled together with page_owner, store also
> >> +			the stack of who frees a page, for error page dump
> >> +			purposes. This is also implicitly enabled by
> >> +			debug_pagealloc=on or KASAN, so only page_owner=on is
> >> +			sufficient in those cases.
> >> +			on: enable the feature
> >> +
> > 
> > If users are willing to set page_owner=on, what prevent them from enabling KASAN
> > as well? That way, we don't need this additional parameter.
> 
> Well, my use case is shipping production kernels with CONFIG_PAGE_OWNER
> and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-time
> enable only for troubleshooting a crash or memory leak, without a need
> to install a debug kernel. Things like static keys and page_ext
> allocations makes this possible without CPU and memory overhead when not
> boot-time enabled. I don't know too much about KASAN internals, but I
> assume it's not possible to use it that way on production kernels yet?

I don't know about production, but QEMU (without KVM acceleration) is
painfully slow if KASAN is enabled.

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001113505.kidbhjl7u2hawxvb%40box.
