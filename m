Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHUJTOJQMGQE3X3UI6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB4450E4E0
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 17:56:15 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id h14-20020a25e20e000000b006484e4a1da2sf3462163ybe.9
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 08:56:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650902174; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzs+PmoIjU8RV1DFZ1KuuIMMZT8f9HhzaSy/+RMprInYj3vcoDVk2YZXBMihSkpKHM
         SvkSDS1+/Zu1O5JB355uz+dzjhzBYya4SD8JPfDfyYj42NRcz6eQ4RxINzegNV9ZhRSY
         nRzg1POMLfspMYMFGnVvEuQvHrq4XQkoj+/yMFe8uvAzqkSd8MXRaXekX9C1UnmWGla7
         sPIBgImuBcrgi2zXwf4Ehvyej5gKch9CVodbULGSNAx4tAPepr8rFWHEXYWBx6b6oM16
         dimy7ikoIxE3OHmMteFFMAMLm5hXboKOpRIlPUuXNMmXCMjUi042wQwz5JZTBoub7yoM
         euhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x95NMd4ncLGLZf67EhgPuEVxDfbg8Ld3iASaO90CfNY=;
        b=E6kLqyGr5Onq3sZvVhD5k6ENf/5exqm1bf2jtOSS/VxRGSertgJ+2UV1UU8GFUJ4uF
         Y0jqhpqe69ckKkV6vQJoClKCYWL9qQXyM10dFFhy2O1sPSQn3QDMWlWhrLpaiMpAGd6b
         ZLSR1RrcXTkd6OiS8sVUNR+sbzyMQNjlsrW+xECBmgo6mdw6Y4X8viuGy2/Lhjm73973
         w6D8SGYIcfa5Zeyc/+S2Qe32/4sp4VdUSmuVXHPzwQtMXuahThsxRa/udU9/EXj0j44V
         VhnLzuUaknG7mZ/ul1Cjrdw4AGSkzcFm6/TO79ZQ6xcIJlR7su2VwGiLzwDD29+w03w6
         DoBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x95NMd4ncLGLZf67EhgPuEVxDfbg8Ld3iASaO90CfNY=;
        b=fYWM42wIHe2KkdFl5UktIH5BAjwS7UeU1UkeMfuZzmDzb94W436gF4+jxdZyx6Dc18
         iaxHNBNdo+o1GUL+i89jgQKrmhE+9Hok3eRgi8Zp6hEDvbCm3uVrsybmqeo/wbKEG6fd
         YgAck40IIbyrhsxdZWc8iL7u/O9gxTeViObPvx65LwnCZrrCCEq4xgVO4HWxLq+cmhVW
         pJU3fRICqKbnAOA+gSZ3p0dQYv7Ujxcd7mitaiDbzk1KMieMd0dfuYdEk3rPO1Iq1JdG
         UKjLX40IYNJMilpi/zfOOGuOQ95Kzu/hqkOyJVeRaJNwUpRDgu33UziL/9QoQ5Ox2tCn
         DlDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x95NMd4ncLGLZf67EhgPuEVxDfbg8Ld3iASaO90CfNY=;
        b=ewysIvRtGGNjtz3Ys8YU/Glvnzj/zhQ+dlPyNdwB1rc/HNLQgGHHfzv3YyJxEHTO8K
         l2ZNiiv6o5tlbQZh7jGQgDqr4XoeVty7HYMg72mb1QaWqWB11tH00QCdRD0NGRHz0i+L
         f7OGPnOgIX7ycqmbBZ82ftbDFfYpoNKeHmrReA5v0SkEJxXyk/BczvsS0L0AEd+uC639
         jNKGFfHGKqyvA0u6XyaJNrTWxYd5PZWrNMortMOHTXNsmzjksUy6R/AxPZfe+PJvb3xV
         5ZHFpc4+hq7clhe1Ku5qN/Z4RKTEtEDHL6Ek7T2endh25xxT2ha5qacNuS92itmvbpSk
         +T+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hPDwawVXlX5JB7JAHlyQVUPBPRnprhpsWIStENepJi5sRMMNB
	5JajNA2Q74PvV52c4/8HZkI=
X-Google-Smtp-Source: ABdhPJxPsZPdowPpmq6w/nFiUuzztniU6+jhS/5xo6Dpl2fJ2hLF6eAw5gMLZ6Crxn/+tB3RxZrqDg==
X-Received: by 2002:a81:2517:0:b0:2ed:e0f4:83bb with SMTP id l23-20020a812517000000b002ede0f483bbmr16665257ywl.15.1650902174099;
        Mon, 25 Apr 2022 08:56:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:13c8:b0:624:97df:9f91 with SMTP id
 y8-20020a05690213c800b0062497df9f91ls12663777ybu.11.gmail; Mon, 25 Apr 2022
 08:56:12 -0700 (PDT)
X-Received: by 2002:a25:7209:0:b0:645:3b43:94 with SMTP id n9-20020a257209000000b006453b430094mr16491893ybc.44.1650902172630;
        Mon, 25 Apr 2022 08:56:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650902172; cv=none;
        d=google.com; s=arc-20160816;
        b=Iw5UlH35t4L5JChUe8GpFoCSfIePhhbndIdenKNvY4WueU2owSwNnvebWFneads1SP
         QYxDEgmplPlosSYJGcL+JiTh7GOSHrRpY217dipe3WymnTsQKZJgX5JqYjy3jE+RFiiT
         cxkgMmv28hcPe4IGt1yOO1WRb/viDJ6PgsjlhJw7DmVwEuxLHh+Qbyk+PTJGqVPuiVA4
         ppMtKWihEIrV9E7bLZ9K7GVw/Ap1Hv/hGOtnWE85XfkTWbK0aFDkq0h+B6o2mCHDmBLP
         tPTgR1KoHisMEWGwovEehFufuapcl7dPwTR7uf3SEkIy1SDaQXE50MdwpnwTr3Pd7Xr9
         VJGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=1SLmJ+Gt1L0k/kCkmeaKgKiRoc9tt47YHMUgXXFr5D4=;
        b=hLFcUPrKlNZW3HUBIv4vuNVW3UXqVpU/W0our54+B2NF9Rd8wrGmSUAX8YWdBg5Vq/
         D4DmlzDkxGz/5MimCKxTSAfeew9Gr0jWmkwFVayjdlJDguVRAUuoprwyeW0LNZ5YuC1t
         urhUwCxK5c4w3UnIGH6bjZWz0+F6g0WCtcgnqAflf2qWEBIE6o32XNz6cyPwgTqnf+fc
         TqC+3M32xXZWk+4SX0UUKai1TuE2c5aLEl+L/YEa8CYnsUervaIDNCiO42IZIqfqUlot
         HpcPwnmKwpyApRIiC32mdc2a5bEUUYXNLYN8Oir9mOLGzOJOTC+RrxiHTRWsI7DE7QCU
         HNPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id m6-20020a253f06000000b0064551d50110si1089186yba.3.2022.04.25.08.56.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Apr 2022 08:56:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3B91361278;
	Mon, 25 Apr 2022 15:56:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0018C385A9;
	Mon, 25 Apr 2022 15:56:08 +0000 (UTC)
Date: Mon, 25 Apr 2022 16:56:05 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
Message-ID: <YmbElapU5VRsCuTv@arm.com>
References: <20220422201830.288018-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220422201830.288018-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Apr 22, 2022 at 01:18:30PM -0700, Peter Collingbourne wrote:
> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
> 
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
> 
> Before: 169020 kB
> After:  167304 kB
> 
> Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmbElapU5VRsCuTv%40arm.com.
