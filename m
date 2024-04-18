Return-Path: <kasan-dev+bncBCK2XL5R4APRBDMIQOYQMGQERO5WTPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A45E8A9392
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Apr 2024 08:56:15 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-22f4b682e92sf749002fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Apr 2024 23:56:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713423373; cv=pass;
        d=google.com; s=arc-20160816;
        b=jVsoAndDBeguGa44ELXWcEwqwKzUXFHUDBKNcjQBzKH/gxc190OyYybRPIlSOD5AiR
         TJM06QK3sFUufAHOy1nN0ROZ8RkNax9iPIawvcmVjT2AwFUWOFTF/FF2Riv1CNcw4V8X
         Iy7YyuZoRW0JzRbZpnRwWw+p/yDpj+1UVgpTyoqhIJJLdkpgFlBsGU3aFuizNV2w2uAs
         7w7KUcDJljGnDe8y18cFfEDQ8h19fSaUgq/+i6bNPFyLGm75bt74SFSeGQfMUjSNEaaD
         5PVD+68g7tbeN+ikb31nHrB/AKjim1S79n6S/ZIneQyDXCjywwDBsHIyfg5OyywADQ/t
         GNEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=799xucSpsZPRipfsCAF6PUSoTWO8DWFkipYqsXHhJzA=;
        fh=d8fDGs80PDoOS+bmt/YYsK69vrar1rgs9RAzdbRnn48=;
        b=yqud6dQe/LQY7Aqb2CLp9TwajHRFh2QkT18hhoaRBzWko9opNHDiMTFyje+nlknC3/
         ELkD5PTOFJYeEpwvrfYSkWjy/ZYXxHiwmMjsZQW0tXmvv7SN2XUxnjYAeKiaAOXSHuFK
         AwKhxkseZx04WnLvV6wZWiVL8IE/0hJxR3VgO12NPU0n+r1hfQ8CkDaMKE5N34SFVjL5
         vbGlmBcF6BoX4IAe4v7VkfySBiHKCAlIumsymLNi/C6CfOkfPsaeFcmKPT76w024K080
         iYKAprdeIjrAiq1qfOXmYbzuNmtZqXnPKHChkZpA2qxAKPvKytlu2hC0c5cvoe6LZFbp
         DQbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=rf4a6dBH;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+b8e85ed0b4bc7900b6f2+7543+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713423373; x=1714028173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=799xucSpsZPRipfsCAF6PUSoTWO8DWFkipYqsXHhJzA=;
        b=MI6/VDueH6vf/UEjvXved1d+U1xfwOfUsfI/Ze6Dy64qXyGOsHRKnJMTB65INhr5RH
         FJVqPx9ypvDzthbE5o6ihpf4z6R4JZi82zfn+CH196Dja8WN+Vcqo7etQpc5NSOvjOew
         +AqKd+tq8w7K1md000irk+HXNU9qdHGtIPQyTrBIea9Osce4SeoBrXZbkfv3KEUDBghQ
         hbX1QbAkxRiz2SvEjs5swSqCyV8jNVb5VgyJ+rSC13LODZEZ1Z49hbfVk/cKise5M4VW
         MZUvgpU1aKLwFo7eVfF6/FbON5gWlLdUQC3Pkk7oiUIabvzBSq7LJmr1d/h1ApqG5YTc
         bVNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713423373; x=1714028173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=799xucSpsZPRipfsCAF6PUSoTWO8DWFkipYqsXHhJzA=;
        b=RwqKdSEAw7ubI0o/NPV84tX40qx02akcMRp1KSate7oLjpheQxuhwDGAfv0B3/CSkQ
         42z4giLuyqJcO5LGSAaxeL0kmsZLggVHjYzY2vdmk+m9PV3xaXEqAYIP+WdII8XwE1f9
         55jiEA+hysX3VhZteHdt5q9tUFQ6hjkLbhIXJMF4t518J8cjua4vM7EOIOXNUqzU3uo9
         RvCo4uo8UgRShJ+hwoY/Dghd+3umxkSuqIjmvTvhACTbd7ZH0YydOTkqtCZ+P5uierr5
         d9ipFs8+D0LRsftoB0a6KdxVBBQPbSINUaU7ig6qEdanFPTwRsvkoYo7jSdkcargasWJ
         kYQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTYMBm/fufwHYBVB9FAzWEKudUVrcEMtEXG2pWOde1hM/N7o6Hyau8UoktMxG8YAt5HhD8RmoFyKl9dLSg2ll2kityjzroGQ==
X-Gm-Message-State: AOJu0YyeYF7M3ecq+mTw+Irclv1TLV9BKRuMBdzkrjTMYElmSC2/ApGM
	7zK+LaysYS7qrnAEW0TH9A2TffAcVcp2GOzlbAhP8dwZkM2AvQX9
X-Google-Smtp-Source: AGHT+IGb/y4qpO3+8ewgHXYoWMCZWABTey4uoiu1gRlD2xA/UPmWm6dtSmhcipDK49EaLkEIEuUgrg==
X-Received: by 2002:a05:6871:2b1d:b0:22e:cfce:e942 with SMTP id dr29-20020a0568712b1d00b0022ecfcee942mr2302014oac.21.1713423373611;
        Wed, 17 Apr 2024 23:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:56a4:b0:22e:b386:74b6 with SMTP id
 p36-20020a05687056a400b0022eb38674b6ls1196620oao.0.-pod-prod-01-us; Wed, 17
 Apr 2024 23:56:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3/AU11X5O6/gW6fgLG+N4e7RsfjKJeBQ/RzahFdBnjw3SgoGcwh9GBGT/eLkMhauEoHMunXp3+8f2yA4vhiJ6oM5hQaJ/rYCYhg==
X-Received: by 2002:a54:4699:0:b0:3c6:f5ba:9883 with SMTP id k25-20020a544699000000b003c6f5ba9883mr2003468oic.23.1713423372862;
        Wed, 17 Apr 2024 23:56:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713423372; cv=none;
        d=google.com; s=arc-20160816;
        b=HbBswwcfS2zps8twGjZMbxnzGxTdHSMfH+B4YC3/klqtxykfoMG98KLfp3igWB+KWV
         9u+2arkmJ8e1jfE50fVUr8J9ifQvTQqy6YaB8ZGeSJ7wpBorfRt8i2zaOHLyItRK81r8
         BoUeBDJi13rWrtDyzVfhlZ9MWfSrWtCwm1Hl7T2XWa6K7+wOHk4lVkKp68xIMHcMuMjQ
         mtDgV7ucIQPZjG3Gl6cPbDa5//d4UqCvQZ5gm6sHUtgL37CKWZjBgl3qYKMMK7M4tcwl
         NJH58M//raQ+b4ZO5GjI8Br50Sh50wBkLXK7p6Fbhp2HqX342eEGxzTNBD0fVnbPycXs
         11Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rf7iH3kMuOmRA9x6ghFFTvcsrJ/ISQqGDxDhjq51q04=;
        fh=XT7nj5sD5mLZnMVsazD67CBpRFsUam35XF5zYGaGZrE=;
        b=EnGB529mK/D0Dngum5ACj0v3gmsteAXCFaEIyPqEJLBrf66yCupT6Trzi3MrS/w+t2
         ueCU3/aOwCrovJAkRKbbYtLGLO3gb2yfNESPnya2AeItidQMchKerVNj38l5uwubja4T
         mEvFynKwmNzuKfAkMxmB6TF4LELM8nVyXUKx3U+Jsrtq6HGnHfDMnAekug1nuQHVcnJ5
         fPX2Tn81AAlH6lpJhdX1ZzRSOdY6tGx0gkA/W66F5OA7knGyoLStCAtKUVNyIq4VwxlZ
         HnO7hGj1Po2/7j2ob0LdZcsSGVl9MtKhwqQ8LZIa7n3WLD2zTVxKQCRbo5xwEArp+D+A
         b1jg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=rf4a6dBH;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+b8e85ed0b4bc7900b6f2+7543+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id a3-20020a056808128300b003c5f1bfdb6esi96755oiw.0.2024.04.17.23.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Apr 2024 23:56:11 -0700 (PDT)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rxLgm-00000001Bod-2kwO;
	Thu, 18 Apr 2024 06:56:08 +0000
Date: Wed, 17 Apr 2024 23:56:08 -0700
From: Christoph Hellwig <hch@infradead.org>
To: Dave Chinner <david@fromorbit.com>
Cc: Xiubo Li <xiubli@redhat.com>, linux-xfs@vger.kernel.org,
	chandan.babu@oracle.com, djwong@kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com
Subject: Re: xfs : WARNING: possible circular locking dependency detected
Message-ID: <ZiDECInm854YiSPo@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZiCp2ArgSzjGQZql@dread.disaster.area>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=rf4a6dBH;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+b8e85ed0b4bc7900b6f2+7543+infradead.org+hch@bombadil.srs.infradead.org
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

Adding the KASAN maintainer so that we actuall have a chane of
fixing this instead of a rant that just gets lost on the xfs list..

On Thu, Apr 18, 2024 at 03:04:24PM +1000, Dave Chinner wrote:
> The only krealloc() in this path is:
> 
> 	new = krealloc(ifp->if_data, new_size,
>                         GFP_KERNEL | __GFP_NOLOCKDEP | __GFP_NOFAIL);
> 
> And it explicitly uses __GFP_NOLOCKDEP to tell lockdep not to warn
> about this allocation because of this false positive situation.
> 
> Oh. I've seen this before. This is a KASAN bug, and I'm pretty sure
> I've posted a patch to fix it a fair while back that nobody seemed
> to care about enough to review or merge it.
> 
> That is: kasan_save_stack() is doing a fixed GFP_KERNEL allocation
> in an context where GFP_KERNEL allocations are known to generate
> lockdep false positives.  This occurs depsite the XFS and general
> memory allocation code doing exactly the right thing to avoid the
> lockdep false positives (i.e. using and obeying __GFP_NOLOCKDEP).
> 
> The kasan code ends up in stack_depot_save_flags(), which does a
> GFP_KERNEL allocation but filters out __GFP_NOLOCKDEP and does not
> add it back. Hence kasan generates the false positive lockdep
> warnings, not the code doing the original allocation.
> 
> kasan and/or stack_depot_save_flags() needs fixing here.
> 
> -Dave.
> -- 
> Dave Chinner
> david@fromorbit.com
> 
---end quoted text---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZiDECInm854YiSPo%40infradead.org.
