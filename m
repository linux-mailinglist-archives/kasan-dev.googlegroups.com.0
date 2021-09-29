Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR562GFAMGQEGK5DN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id AFB8441C4E6
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 14:42:47 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id n3-20020a7bcbc3000000b0030b68c4de38sf796305wmi.8
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 05:42:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632919367; cv=pass;
        d=google.com; s=arc-20160816;
        b=GNnNeeFqRJGgq8X+sCQa3VkLuaLFRZQPz8Ucz4rmFpXu/QSuMilXr6Sn5P0mKChuyR
         g1ZZWcgWzo7lzKtjn2r5uOobP8b9QvURgXHUz0dfao7WgDDiHjeadTTDEUU4BrPI0iLj
         2JTzP1GYXJU7MOIDO00iG1qdoJ0r/+Ncl2HqBbHVSck1zQ93SV/s30Vn/NSofOJshlHL
         ojVn3/5F9V7Ql/m7Q+CGPH4LXIXhe4fVdbmBZhSkeNWjpk88POY/tFtGVJnP8y4GvKx6
         2P/QD+vuUY/HEIYCwpC6lvH3oEe2Tj49BfW6EPxwsTWVoIVUv1X1tXn78/coBXMgtIL/
         NbQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=787AkogiiNVxHCxAtBKyoho8How6NbKQQGAuE2UE1/4=;
        b=dGTAAt5N7/yh5nSHcfWVIWjnEHftdyr2c37Gd8jkTdJaO6ElVhXHWHxek3D7KGBPA3
         eN0DT6kCMwzOH0ezuGVmzh25/uDmdCzALy7d2Tvti5ZK4EivntlYffUgW7K+4M+k9kGf
         7JuaLh8MprPX6ITu2z+82YAjaGY22ldC7SDREh4hpLPrPoLWBfyum2G1G54xQtb49gEZ
         LXPLAL1DqTg0ulnGF0vTM0rzJQkzU8ytLq0pqAAQcuqOIskJ7fDl7n5+l5c1Dmmcvi+u
         e1uGxoB6vHlDbSOBfHPsaE43XvqN8FtD4FFNd0AzaIgQtoEtHf5geV+/ngZFmjueES+/
         HutA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="SQW7/3a7";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=787AkogiiNVxHCxAtBKyoho8How6NbKQQGAuE2UE1/4=;
        b=MxRc5SvAA0taMTrwnoJY/ygFxTGVHVbXjsxyPYR2NvcBDIEYzhcL5WmsRU3vw+pwua
         EV5jLBwJOcV+uwQkWGrZ+LRLwNFbTMglnQweMft1gT2Irdm8DtO7BO5qgohSRFUspxeu
         5T28h24JDzxbHp/DieDnNSTEjM7xpkamYObbDtj7pS/TwruZ8RYrLNQT4w/vxtQXCylL
         WYRrmODgY7X5yKKzCdKryL8TQjSi0iFrIBe930TbNWiZWh8nXk67EmYTot9WeuWy2Y9W
         QUwd+7T8m5oH8MjFcL8qYZz0iyRYEYWZ0UvfWIG7gz8vC17/9ZJGpsuAOhH0ERT4dM8H
         6E8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=787AkogiiNVxHCxAtBKyoho8How6NbKQQGAuE2UE1/4=;
        b=CcxhAWTfgUrPtVZunb+erL4myyK4VPBhTfvBa784uOP97fPlSX+Dl3d3J0Gxxr0k7T
         S/DbCMTiWbnPNZYShJF8jJ4qqGhCftJXQjySB078/s/4+KRl/CwIRxfDWNwqxWDqtKkx
         wdvpyNEvH628HxbgDSRZM6m901wsKJl90mJ71yCYugarB1+RwF+lvLmGlH9qJe38cogY
         zxZk+8z3CJCFvDprxLQHXPbjVglIg0pEqYioOYQUFJfEbc/+LmD0RIiUwildbxFXkW3W
         rdRtKuxaNdFFSaGM84Y37VDqILv3I2NYdWQw3PFqaYnPMowLpRHsmItLwTxpurjs8+Fz
         8nWg==
X-Gm-Message-State: AOAM533/THgz/2BAtUCVaZpXryP+W7yQ2UTWlsx4xoO8GleiFiqUw4UN
	4hb07NySkfmtEon2h6JhY8g=
X-Google-Smtp-Source: ABdhPJyxp5zdNKwyn1UeyXGZOdQG9HMrxusDFkjbivmBez1d4cLGoM3tI3E5gr1uuQ/89q/jeqjBSg==
X-Received: by 2002:a5d:6047:: with SMTP id j7mr6649671wrt.327.1632919367475;
        Wed, 29 Sep 2021 05:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls2983001wra.0.gmail; Wed, 29 Sep
 2021 05:42:46 -0700 (PDT)
X-Received: by 2002:adf:dd42:: with SMTP id u2mr6510847wrm.39.1632919366527;
        Wed, 29 Sep 2021 05:42:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632919366; cv=none;
        d=google.com; s=arc-20160816;
        b=keUeUxKFQDpoXZk7+eax22+MDp+J8Pi+oJd2+UNajy6XDaQGGSa/7oxGJf8hsQ9wWa
         oSFi3zje3K4+XSP9fzwv0I3mewytGEuxfckEaZTTjsgIXwJYM5pLlRgKIv1SPSMzwUri
         /GFIyH/1jOx1RPL6gxXLv0UDK+zlwSfaJfQg7uSnWyGhyrG1OxbYFvfdyGCbLP+AJ2WN
         okXpFKg2RdzVzBFNM1lQCo5oqSJGxGRmlJRBl9Xm06RIoADH3pmvYqi/BVAI+l2WyA9z
         G0ADfM9rmmLVEy4BK/3qV+b0VYoY6YYR3KiaJv3/qYEoF1/IB4mqI/iHSno5jijy1U3f
         fzhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7Crw1tVUQAw1+Hp0YgsE0e4Jsu9zg954QmWXXzjua34=;
        b=SeTrhx+b3WbPFmzy8sxL1DR9Ap7M9NPbv0jhHim210D+7TKHpETJlkXsAjaR+3OpPo
         1ZkFbF44Ruol2RywgAqaKXEBrEcCxC7DGh5q571/EzPouKRyajtOkgNzN8UgTYcY82B9
         sumIvkxjdD5P7DNKFq5UVOsb6UgBe8Ch09e4qXHF+/bXZqk+7EgvGvT0pputTupL18w9
         nYt0ilCf6gMU6WltejksSPas2k2j+vIqSajaIVZwBNNJ5RrDkH49FsZSYMzQBD7g/OUQ
         GjfoWd2ZXWi9pTA5UQeWR8XdIPmUz60X/EgFoVslGDDYF7Zn6EShIboc9O/tcgCp2ZrH
         5MvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="SQW7/3a7";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id g8si193094wrh.0.2021.09.29.05.42.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Sep 2021 05:42:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id d21so3992173wra.12
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 05:42:46 -0700 (PDT)
X-Received: by 2002:a5d:4cc6:: with SMTP id c6mr6595976wrt.108.1632919366025;
        Wed, 29 Sep 2021 05:42:46 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:c9be:b970:304:6a4d])
        by smtp.gmail.com with ESMTPSA id c8sm2257328wru.30.2021.09.29.05.42.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 05:42:45 -0700 (PDT)
Date: Wed, 29 Sep 2021 14:42:40 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: yanjun.zhu@linux.dev
Cc: ryabinin.a.a@gmail.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH 1/1] mm/kasan: avoid export __kasan_kmalloc
Message-ID: <YVRfQDK0bZwJdmik@elver.google.com>
References: <20210929234929.857611-1-yanjun.zhu@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210929234929.857611-1-yanjun.zhu@linux.dev>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="SQW7/3a7";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, Sep 29, 2021 at 07:49PM -0400, yanjun.zhu@linux.dev wrote:
> From: Zhu Yanjun <yanjun.zhu@linux.dev>
> 
> Since the function __kasan_kmalloc is only used in kasan module,
> remove EXPORT_SYMBOL to this function.

This is incorrect, see below.

> @@ -521,7 +521,6 @@ void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object
>  {
>  	return ____kasan_kmalloc(cache, object, size, flags);
>  }
> -EXPORT_SYMBOL(__kasan_kmalloc);

Sorry, but this will break all users of kmalloc() with KASAN on if
!TRACING:

	__always_inline kmalloc() include/linux/slab.h
	 -> __always_inline kmem_cache_alloc_trace() include/linux/slab.h
	  -> __always_inline kasan_kmalloc() include/linux/kasan.h
	   -> __kasan_kmalloc() mm/kasan/common.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVRfQDK0bZwJdmik%40elver.google.com.
