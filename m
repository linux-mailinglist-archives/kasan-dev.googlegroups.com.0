Return-Path: <kasan-dev+bncBDQ2FCEAWYLRBQXDX35AKGQEUDB4K2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B8A025ADEF
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Sep 2020 16:52:52 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id y2sf3537724qvs.14
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Sep 2020 07:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599058371; cv=pass;
        d=google.com; s=arc-20160816;
        b=lyJbyHyRrxXt8/kymGo6YcKswORdXLYQ+lJXfSP0WGHXOSq9LNiXmectSWmZ6QoeqP
         CFbm2Em/OLYOt+nFWdYDsHFHNinLofAsTupo/dEJ4rzpSIR8wlcry18q0jf0K0Ku+Ra5
         DTwZ886K5o8YQFHX6RmPO+ZCe1WVNYQaNzJQIgK3DDhkNeMWktLluSNmy6Y5LwgrlkoI
         Rr3zFYaBZ2yWrBKMp2ehQZ4CbEui5TyNEySqcRE+e6qSboG1xVsGPEAyInruOfrLwcfO
         EHWB4UTe954S1ra2HP2Meol7eSWGTu90/eZIB2gp7cFuz0WqGEwhDgvJdu7hMTN19yP0
         1FJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/na3m6wKit4ot4wDL/ZdwLAjs85jMmihU23K9hlS2v8=;
        b=Tk697TUAeR95/yc/Si4RyBDq48VCJd9dyvElZroeslSYGfiizt58cWizxnGtys0wWN
         abss7W5Y8wrCgnPVmDUxS6gxCfb4aR21icJyUlemv+v1AcAMz+/Xnd6ki2DidlD5xVjq
         7yixPiRn6Jz6xaoOZ3Qx2Ex2pvc5XK+ObRU4zdtJQqz6zpSd6zq7e+aHBQ6sQ0ITt11u
         R1I+FyzbtUFmgV3wAq0fti1Ymcxasy5+53k7dbEBoxbDtWBuXtP7jynxnovcNFfAhtrx
         vXyHdJqgxgPRmN3XTHXCX+tm+hHU1abS3OWat7EhuyNNcnNaI1PoTGaGG6jSXhKj6Sx5
         cBWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=u1QrlX4t;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/na3m6wKit4ot4wDL/ZdwLAjs85jMmihU23K9hlS2v8=;
        b=HOeybFrmG/zIkddLP4dJF8PaevCbkfGNAlRQTqjGQMj9psRly9rlR3KVjlcbdSsMe9
         jqmvBbQ9LoZ4EsRSRON9FwlNX7mxt1tIvt8K8sbBQFiXlWqvA4wiFzSvc9iz7ql2VngO
         kUs9sV72shn6ke9Aq3+Pidg5LKxUpn2E0f8RDG2fQwt4iKD7yGoQURbI6g+MfwkjD8Rg
         P3Hy8lqjfIPSzm6kR6Qln9Esr1amXD1T5jq9m5aAZ6RHLUxlBPUqKKLGkIrF1oErz8IP
         +1n0pmFrTHiZCUYtfwSutKSUvnHmu7QKrgSpdDRUG7n9D3PoWrfwBOCZebYVhRKfVRc+
         tHUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/na3m6wKit4ot4wDL/ZdwLAjs85jMmihU23K9hlS2v8=;
        b=l4JVipG9r1Lgo9g9x+nNPBtX5q5rwDHGUVdP54J3jT7/UDvSOyhprdKRyicHaJ0TSS
         dAfO6Hr+m7v+B+bOsUR/fgMt/IJmVspXFcRgRRUNZF5hs6w3FwnUwgVHlG3rvCSPfIEq
         ThXLlYH/T8v3iu3BT4WmaYJ3C3bFLmfJswomLGaMiJsSdhWCw07DHpTvu47AkClKrKcs
         LPLtwdlZ3EIDnxG9/vsQxGDyABI6KIWX58sCpqwcVsKEQgTl2rc1c/JF/Upnku+IY27R
         G4W9vQ/nSKS5mCHanvJ+6Lu7+dZ1YAq/+EXZ1/VuqfNJW5UL8VlRE3KbbcaCt6+41Ucs
         IZBg==
X-Gm-Message-State: AOAM532bVxioxqFzCCP3g/7g2MXLO2CeBkVmXQqy6DcNmIguYE5KKlSy
	cMRVnseghlpxtanSI/IrII4=
X-Google-Smtp-Source: ABdhPJyGS2tTcrxbp04p8OiyPbuTtT8/B9LP8ykrXuA9RFzHKTtwGTIQ7mCNgDoYG18b2436IXd/Ig==
X-Received: by 2002:a37:6805:: with SMTP id d5mr7052382qkc.116.1599058370795;
        Wed, 02 Sep 2020 07:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:dca:: with SMTP id t10ls940352qti.9.gmail; Wed, 02 Sep
 2020 07:52:50 -0700 (PDT)
X-Received: by 2002:ac8:4e51:: with SMTP id e17mr7148592qtw.173.1599058370253;
        Wed, 02 Sep 2020 07:52:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599058370; cv=none;
        d=google.com; s=arc-20160816;
        b=GcuX1pokJCuKT49VBThE4Ju6qpBg9Nz0NqI9tXg4AvE4PmieyQkaOP3r4h81B34nq4
         lxplfoPCxOi48sdLoobbVXd0zlIgtN0SgpZ0oz07WXHhhzkxflAM50gG4jMVeVrCkx/W
         5BGGxjPOQNBdq2OVsuxsvtCLSVsNFCNfqdThzyG2eBKt5YAreS4a3RPq4/HvKSxiV4L7
         iCr1g2ADNpCLwCmwwohc9AwPrdnKLgNVxgZcXLrQjpTjrwg5O+rJfPOURpiCKSj7ErC6
         hdjONuM4zgFBcOesGK+GhC9HiQUNI1gjVpxG2HlsobPAuTTJKrbJza8L9K66AdO1KNZ6
         STKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Umk5Ulvu4oLoYIO+HUXZ2g8XNW9wJ6mMmUfCXe6cwzE=;
        b=IrM9NRdBg/uxwIy87QM+Pk7RRJn8CzMlX6/D3izhB/POa45wAjAsQA3buK8Yy89T1G
         mFrwW9qhDMBxlCe3WH5ZRS/oQETpi+LM56r5Df46mfiRn7rA3Ddf2P2KSS/hBBGCdLhw
         UDxPc+qPSCFzEOe2/9BmOlkTCcwYy6XdB1sfO987BOYTWjl2lljFnokqtzHmmeY8bZ7G
         VUhsOxLphSV/GYyA0iM77nx+yy1rqUPK+v4rEO2YN03fer3KJ2bgv+NOS7BMCJCkLppX
         WudVyLdLTLqx1nv1MXaEr0aJ3YIx2y2REpjDd6lHpMRwup0i0UyPxpw9H2B7FDDxhuNc
         GTHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=u1QrlX4t;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id b1si219823qto.3.2020.09.02.07.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Sep 2020 07:52:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id f2so4595524qkh.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Sep 2020 07:52:50 -0700 (PDT)
X-Received: by 2002:a37:8b01:: with SMTP id n1mr7286182qkd.62.1599058369875;
        Wed, 02 Sep 2020 07:52:49 -0700 (PDT)
Received: from localhost ([2620:10d:c091:480::1:a198])
        by smtp.gmail.com with ESMTPSA id r11sm4772987qtt.2.2020.09.02.07.52.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Sep 2020 07:52:49 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 2 Sep 2020 10:52:41 -0400
From: Tejun Heo <tj@kernel.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v3 2/6] workqueue: kasan: record workqueue stack
Message-ID: <20200902145241.GG4230@mtj.thefacebook.com>
References: <20200825015833.27900-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200825015833.27900-1-walter-zh.wu@mediatek.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=u1QrlX4t;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Aug 25, 2020 at 09:58:33AM +0800, Walter Wu wrote:
> Records the last two enqueuing work call stacks in order to print them
> in KASAN report. It is useful for programmers to solve use-after-free
> or double-free memory workqueue issue.
> 
> For workqueue it has turned out to be useful to record the enqueuing
> work call stacks. Because user can see KASAN report to determine
> whether it is root cause. They don't need to enable debugobjects,
> but they have a chance to find out the root cause.
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Tejun Heo <tj@kernel.org>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>

Acked-by: Tejun Heo <tj@kernel.org>

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200902145241.GG4230%40mtj.thefacebook.com.
