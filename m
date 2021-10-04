Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGGA5SFAMGQEDOBVGPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 313104212CA
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 17:39:05 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id g9-20020a0565123b8900b003f33a027130sf14542065lfv.18
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 08:39:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633361944; cv=pass;
        d=google.com; s=arc-20160816;
        b=iCcg3t23dsElB9EeAR+4Da4G5mstTLA9SsvqDmI3W6nV3Yc/YtSAh0EUM+CjLdjIfl
         UO6GgvMSILcxZhxBEZRpa+lwdyCsJLZBmznL4eRJ6ilmdR7T8GI9CZlw/IKGOMPpe/d2
         7B3mA3sY+ge+FvDoplYiJaX+xOsQIp8OiawR7Q7G/WcFwp9OP17vb7GR9PxKF6vgm50V
         XXDeMVj0H8pQizU1mqwqAu0JIZalTexpXlfGNMZmhKsyG/9Uoz+IQAiUhU2b5q5wS5FC
         PtZAwq69MQlfHL1pEhPzqlvgSg+Zq2MDfnKpx1xF/MWbxhuoNUX+Pe1PUqp/gtsz07sx
         SeVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=cbM4yew7a6nRuon6mAFgjYjzh2k5VwJaGoMm/Vl7Sr4=;
        b=FHawLbXxuqLekLHbnfbEGZykOkeoRFRb9slgYR9DH4NDA7NTfNk5AyI3ePrtmg3shQ
         Paq0YKyOEZodN9LJ3Ft4Jt66zWfjYtjfBON8eXzwUPSy3MDcnY8cmfkc+S5KRX82N/UL
         9YGfvxT42dc7xYpm+Ut3IA5CQAfGKW75H720XkByIUPjWAWUz3sfPn7a/d0bXmH6GBTz
         pl9EMS6pECgmoVUVnrN9TX3u4rhH7AMVu4QgOi/g6QhCZYFGZDGmsPIkj9eIoFGqTpYw
         WdkT9fC1TlsWI6oW59lbPJ5Mqx6pNMXYKZA3/mP0XlWztw9jSBVifP10FO//XFxx9Qbo
         jVkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cbM4yew7a6nRuon6mAFgjYjzh2k5VwJaGoMm/Vl7Sr4=;
        b=Jchvl2reHt6800TOFFewHUNN6XXrGZvfZWvY+f0yZbB6yQpw6svSv4npFveSJYLve3
         OfVR21ukjC5UfNMGjQRKd5CDzhraOhgLjST8yWRvTEBl2kmM9RkgdxkRZlCgUG/4BPpa
         6gDjICwGC75MeuQheihMZ1+kYjp9OpQTO1Ue1GcmAnv7V3mdZs2/vtf+grkLa98cEhg6
         EFbGvde9cZptZP48e/cJUCRbm2cok6cUjzsIlaDYpWPP0OKwRFqBSsb/z97EfjjPlRbe
         7VoF5FtV/WWQi/ydsDE6DnlPn/SOO6CQ+6bM3OrmMK2c/IsK8Ec2KWPJQ1/HGgQYQDQP
         B48A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cbM4yew7a6nRuon6mAFgjYjzh2k5VwJaGoMm/Vl7Sr4=;
        b=pdUxVx6Xt3ATjdFzTjKNHNRSLm5i/plDcevE+D21OIW04ezRYdDdEYvQR25U8I3USc
         tCR25Amk4Yuto1QnzLn6/X8DoIypl8up2od1+qItyLeNBxFfazDvPl//HxI1oPV7JQeG
         RsT8i5QJAG9sGBBCdP5MaY/Hh5MMDmO8kZIZmTkUoFIjE5pdbrpL9ziCWb13qEuG2EKG
         IWvSmHE+VKBTqDP5JZBX1Estj2l/vR3Ix9ytXLfaQfQGuDTT6MoThyju0AwBmn+TDzOP
         P2WN2jvBi2Yd3SAd28zYaHsg/iplp8tj5CbQiEcqMxSGsTbEHUEP0nyRCmopYgIR6Z+H
         +TUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Gvf7yAYsgeAr781W9xx8MTew4yDr4k8PC57hXwX5oLuKNFn1R
	C4dr87ZkNh/soW9Azcoburs=
X-Google-Smtp-Source: ABdhPJwzqfYj/r/2Irp7dNUrSeRo3infimxwHXk0DBTbIWzzd7jP6Cf9LrE41/LqyJDgOEN+uAZWLg==
X-Received: by 2002:a2e:8789:: with SMTP id n9mr16954245lji.480.1633361944766;
        Mon, 04 Oct 2021 08:39:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls714358lfa.1.gmail; Mon, 04
 Oct 2021 08:39:03 -0700 (PDT)
X-Received: by 2002:ac2:4f92:: with SMTP id z18mr15130778lfs.354.1633361943786;
        Mon, 04 Oct 2021 08:39:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633361943; cv=none;
        d=google.com; s=arc-20160816;
        b=u+PiGcq2/MIwDnNrQ/ACWtcMgxDx6mGqSlm/2xXGdzp/r2aXL6JBcXy8P3cTLQ92Ld
         89QU9keVMYdUIFOCmk15/19NkOo+x1APRM1LfZsOigGxcm61cW3tvzAcCuPSAWu02l0x
         MhqO7iOCC8D4dqma00jpkjlzD4izMGvoWzBznRG6ewmlN8nXqmZarI8hONVi7P1zCQuW
         VLC9+/ijSB7k/5McwbSdlB+jCAcVpH0MepfniDp57OuqJkpvFILyDu4qJhh68TusxvGT
         cEFT0VZmsq/onnHKNtoWZxNIvQg+sJo6BZVj3M/IFMX1TYRIQxwXmAu8QyOsIWyNxiKQ
         QTEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=dHsDduF08+vA/MySoEGLZHHGTMlQv/Us18guP8jOEec=;
        b=HhkRDyHUyN8bTbCzDEqusBPsTg+wW0U5H80ohEWbOwE6QWTorrZjEDZkBYYlIB7HSj
         icSheE67rZTttkJV0WIUxQIjc4SLkVsYNEuSq5tTXGDYFmFBFx2yXnwEhUdj3hek055r
         ZUeS9wvuYhfzSq2/PaCaEer1CRWh+IeCZPJY94Wt/7fUYD+PvPrn3qT1J38ObdFuYgPx
         vEmJ4zAMuUdQtRESNBTToTe1oEynnvecZdseQHOMhU7muh9jYXpkZHOTlB5ellzS/ilq
         uKCSVWcMh31Y4L3+c6R5KgHn5XsmwkrU65PpCC7tloEHtcLCOg/korNXTVxkoLycSqm1
         Ud6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z21si647677ljn.1.2021.10.04.08.39.03
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 08:39:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 87568D6E;
	Mon,  4 Oct 2021 08:39:02 -0700 (PDT)
Received: from [10.57.53.1] (unknown [10.57.53.1])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 061213F70D;
	Mon,  4 Oct 2021 08:38:59 -0700 (PDT)
Subject: Re: [PATCH 4/5] arm64: mte: Add asymmetric mode support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-5-vincenzo.frascino@arm.com>
 <CA+fCnZeW35+ZmvM6SxZSb_NAMqsK42Ds_ADVKeVkfs9MT=Aovg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <cd011cc0-5d3d-b642-55c3-fa2107f7f826@arm.com>
Date: Mon, 4 Oct 2021 17:39:16 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZeW35+ZmvM6SxZSb_NAMqsK42Ds_ADVKeVkfs9MT=Aovg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 10/3/21 7:15 PM, Andrey Konovalov wrote:
> This part is confusing: mte_async_mode gets enabled for the asymm
> mode, which contradicts the comment next to the mte_async_mode
> definition.

Good point I will fix the comment near by the mte_async_mode definition.

Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd011cc0-5d3d-b642-55c3-fa2107f7f826%40arm.com.
