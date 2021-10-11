Return-Path: <kasan-dev+bncBDOPF7OU44DRB7USSCFQMGQETCPF4QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id B66B7428A34
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 11:53:02 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id v9-20020a50d849000000b003db459aa3f5sf12790949edj.15
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 02:53:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633945982; cv=pass;
        d=google.com; s=arc-20160816;
        b=oFHtj42hmz91BtHelr8MQx4vkRDueIU3L2prgis1y52unCXEAWKgwdqQn3QB7ST9HN
         em4fv0Rk57gUGWvTl9SyoxfH6OODb5oKP62UPLArF/bDgmapGvMz/mo7LJ/Weg/LhKjD
         9Q8iwt9U8mqYjPOObf74TfxZMgltv3xN6TDCn1C9yoYMRBm5neX+xnZLDRnkDAPNLd4t
         5oDEmhYJuZDUy7CkQKZ6W5U2ITWHZshhCP0txFkqaOyx2ReR87kYHw8sPHkWvHXGdsgq
         yNyMLTI8anEY9v+UI+gdUl6exfYmvXoVbxaced581Qj/o7gcHhDD+Pj5E1etZRZD/yUB
         6iXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JfmxR5n8k7I6n0d+PwOhKUZ9+Yuvf+A9708WDp7y+WM=;
        b=V4vNEtZ0qke0Q1HR0IO+WI+w+looVV+Vxgupij8Q8jMYrtbwTJdSu0HJczqO9tTUq6
         33WOpaIG9kvCnDbfcbi+Yjso8u7A6jRabaczI8umXffx4bfQho+j9HbnL3w5PX4hgvPT
         b1BQRmdq1W4E+RNqsGitqRQIcpCRUehZriOR/f/wd50lHW6lJGhYfMdmostTPkQMcacv
         TGr8bOsjU1ec4rSYtvwFzUmxgn+SZz5tcqo+uyXIsMT6pTdGw/Y7OuHVlpV8YdkzF9qn
         /9B4wnEUkN8IQWZNgRsli2mrk8wRVSC9kdmhJJEP+jfvsZz7voOjaOvLqo1W0KGo/pcy
         Nwaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="pab4lT/n";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JfmxR5n8k7I6n0d+PwOhKUZ9+Yuvf+A9708WDp7y+WM=;
        b=Rn9BAQiJbREgFxdEYFYT4WSHQjS4y36FG9oRSDnys/98u/K5qfiDirHvCVP05PQ4ht
         bvwN9Uvm0ndONUM7yyEUhDSEuRqEG/YxjIXtZucXvTvCrYkf2rt5YXEypZXNMJ0CehQZ
         3AmwsH4KvzY3S8Oy/hb3T3E+KfRK8cYVBIE60yOCr15pvlrD0zoT9WJOJ71uw+lD/HPh
         671i5jd+j09eIvDjCImvQZ/8zrsFQ67fjO/kemYuWqFOZK7TznPA810T8XuIre+rUosS
         gFcuOAy1k8+AswgDgmmQ69NeHpFISw5hTQ3PTmr86kicV8swrXMlGecTwKU0MczCyi3E
         rc3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JfmxR5n8k7I6n0d+PwOhKUZ9+Yuvf+A9708WDp7y+WM=;
        b=3GGCn0lgJwR8DrLask4MnLCxCZDunmFVzoQGlbCrY/UpfuseU0LQpJu1s5G4Cnd3bP
         DvoMTcpifzhBD46838scAUPpB7xJpXmIAN6CzqEowMcMoDf3TswZcbvyAZDFSfemSWuI
         uHyrR41ZPyeeYY8Oag+bl/0UBR06Ilw7dWFxavTpgHLcxwTy7jXaA0ut7gbuYASR19eE
         5cwfsUGWhJiJUC8YJcOTBaQTVDQO9KWMszYxyRY98bjZIxduNa2SnTnm1D+bT1IAJhe7
         quP9WVwQEmisqCnrgWiX7MIq/BZYs0e6SX1ca6ilV3nSBaXyD6zHJMtqaufiV2/K5UXX
         XNCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RUELu4Zp3OP2SVGMgl8auQbRSKhgefmE1hl0k0NNPa36lFmRg
	xAEWOafZglBf92a2g52RBc8=
X-Google-Smtp-Source: ABdhPJzx0H2N7z0tdX4rH+zYzfeZx7lYxLE2uNmLr8f62n0Q5ZnwTqWhb+LgIkgCCrFZstKQKgEHjQ==
X-Received: by 2002:a17:906:a2c9:: with SMTP id by9mr24301262ejb.305.1633945982499;
        Mon, 11 Oct 2021 02:53:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:75f1:: with SMTP id jz17ls4283234ejc.2.gmail; Mon,
 11 Oct 2021 02:53:01 -0700 (PDT)
X-Received: by 2002:a17:906:7007:: with SMTP id n7mr24006213ejj.275.1633945981568;
        Mon, 11 Oct 2021 02:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633945981; cv=none;
        d=google.com; s=arc-20160816;
        b=Wz6PRqz7JrRKyi9adBy17gn5VjEg2EVuiggBO0FpAlhNn0RiuYQX+3u7S3/1SePhT7
         rSXSaT502VMHbc4sEzPBAXbUJ0ABQvDFsfpWo1R9WtIzYr4SkPXn9Nwggmatfckl0y70
         6V/x++XyQv8uCqW828WDs12on3oafIuyANUonMzLXKFgGqfz70jI4j9q7CeHj7mArU+7
         LqGnw8hgY5zIGO5rpT1KqOVIMYDh124QenTg6bp8pOY8B6hXmXr0AG/ZGdfMpcpaW0Ur
         b5xmeU98fSj2Ia4NePvhHXc6AAO/xRgrOKtrF74UeeyZLR49KPTL+tErdU+fgg8//HuA
         D/eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=x+ebBDbVVXbydAVIXajg3Ac0CDuAQFka9vVAII+KcTQ=;
        b=G26emNVN2Lc12aWDJrAlSE28VRa00YAthhzfyz+HoqriVNFwMdbmJuPbpEP+b8Sppt
         24BEnSGVabsxcQiSeSUhcH8jj9AAwQGAzdmp/BO5isnNuea6hHaxWTxwuNKwHoGB8gly
         Udy22FasB7ng0RlmBK4bN6qiRomkhFYQjplmCiW2mYKLrEXd58/bCy16ED0uOfy1zhM6
         b5BCJjFp7juQpngTXHQBNEUZpbGrohZMOQiU/CnbDVz1xWuoKS3x8w4815N6bDWvgkiZ
         ENrXoJ4IIn10gLnhA9akGcZpeu4/Y8tb/vlz3TZtEa4VpYiWqeJptMWhDsxd5O0OQDuQ
         KiVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="pab4lT/n";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id i5si550420edk.3.2021.10.11.02.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 02:53:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 4FB183F044
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 09:53:01 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id l10-20020a056402230a00b003db6977b694so7053594eda.23
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 02:53:01 -0700 (PDT)
X-Received: by 2002:a17:906:5d5:: with SMTP id t21mr25107363ejt.160.1633945981071;
        Mon, 11 Oct 2021 02:53:01 -0700 (PDT)
X-Received: by 2002:a17:906:5d5:: with SMTP id t21mr25107343ejt.160.1633945980885;
        Mon, 11 Oct 2021 02:53:00 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id p7sm3955215edr.6.2021.10.11.02.53.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 02:53:00 -0700 (PDT)
Date: Mon, 11 Oct 2021 11:52:59 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWQJe1ccZ72FZkLB@arighi-desktop>
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
 <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
 <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YWQCknwPcGlOBfUi@arighi-desktop>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="pab4lT/n";       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
...
> > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > secs timeout for TCG emulation to avoid false positive warnings:
> > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > There are a number of other timeouts raised as well, some as high as
> > 420 seconds.
> 
> I see, I'll try with these settings and see if I can still hit the soft
> lockup messages.

Still getting soft lockup messages even with the new timeout settings:

[  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
[  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
[  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
[  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]

-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWQJe1ccZ72FZkLB%40arighi-desktop.
