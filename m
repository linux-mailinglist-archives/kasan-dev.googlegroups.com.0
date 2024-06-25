Return-Path: <kasan-dev+bncBCT4XGV33UIBBI4Q5WZQMGQEXWPSVPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EEA34917458
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 00:43:48 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-377150fb943sf10626905ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 15:43:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719355427; cv=pass;
        d=google.com; s=arc-20160816;
        b=XD5PVG1n0iI1LKIIRwaveGqkwms8cJopVVM2RbdQiSyinFXHIvrvpTYjfdp3XBucDI
         LPxpsEJMVGGMC/84mfJ8d5bYJ10FETs3mqc7jVBT2ofKJ5IFp8TzCrEw/jmUiKCcZygO
         iOMvGVf9G8lySTfIJ7dENAtrUF2HImNL1qB/CH8/8SQZMntPRQDK3lrJ2cXppr1OhyFi
         obxVXBntpbXcsmIEHQkUeZrxXArfXkyznN+ZAnjqwQmbM1k13lsVA6gjTwk1wcj99ceL
         gr7wA6C5i3NNU+9WgfIl0Hi5qvCove3QvKhf6vJxJyMUCm9monYV5ptBXRSDdacN4avt
         lU7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=R5GMsoPjLPXgBcmH0krTI1d0ESRS754RrWfDXQl1+Uc=;
        fh=Vw4D4zW/Lz7yP6eQMRoY+u2EDAOhWt7MXgoVlP5ytgw=;
        b=A/VxHM0V44QEZuqvy0EJVcyiGO+2Oy3GSJR4vlObmUEUzDmaalIfbrzRilt/K1J7Rt
         Bszduz8jjkVi2J76Q94LGugM2/jxaUjwqHmi+ZPF2yh7WVIprdUJffUTOxh04PTAvkGk
         155EMNvUsdQD+l6QQ7nNATkXmVS5IiI3Nr1OE3UyiTCMgp6eba8OgOii47xI/GaYqDMa
         q7rZFdnqdwC1kvRg8mvzaR6GtJh2KqDlruOzDAKG539roOaZAkXjy/txpSECSH1JniFZ
         U8rag5ehXekCG3GYOYWhxAKQ9EngPmPsR/H6xMHtD+cKNVTiTFXbJlY2LfbzaIQ5R1na
         r8oA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LalejVUM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719355427; x=1719960227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R5GMsoPjLPXgBcmH0krTI1d0ESRS754RrWfDXQl1+Uc=;
        b=D6xsNcwhf9hd6Xe2BIvqpTLs7NaVXvbEhSOsz8EZKidZVaFabjTfFgGC7ZDegYenbt
         Rch+OCUlXfdkm2cQU5G8QrOBL9zsHC5aT7HgQ+Tl3tSH8flPuwYRnli87ZjEbvhFxUZG
         PvdlGeO6vxDjwz9uUcfVs1A5i3qguiPdxv40nAeUouqlynjPGwlqFaRQ5PEh+uQRDn1D
         uGx3Fx9JcDT5Mx7BCvocfxkDWXtLcRxr7Mx/JPwBUVrbNKxIS3p65aSM6umbowp6O7tf
         EAFo5cMf4Ld+f75NMbs8q2c6NSKSlZOV4952dgAFW0SP03KcPEOg2ZTJ4FL/peuC76yA
         3O2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719355427; x=1719960227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R5GMsoPjLPXgBcmH0krTI1d0ESRS754RrWfDXQl1+Uc=;
        b=LZFxumrILRvZxbKMIFenEAjW8xK6qc8ZE0JKw2Cnzwf1VYwcV7qSq+3ZynMkz5kNQj
         kdZLKhbzinKk0k67pu07wwTF841djLm2S+mV4Lrw3H+MsNxedWm8cpnbW0QKTQ5Ekphz
         Oy6YEFgrqoh22wMwrRp4g6fsDZLguSwJ/CzyXhEV6/SF8snwz3tITz+BZ19yY+eLGiY3
         NVGDWxUDa4KHavHPDvwmcG51Wa7KI7QBB7tQAOcXr+XQdZLnMiM4Ycw5oMgrPw5L2mmx
         9Qee0a7UjM+XOolgU7QPMlYcu84iwfQJCBFAx9VuCVqmQYtBMGrLtBz+PpV+ZtaZ9vtd
         vZ+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsdglNeRBEnitsuPB5mR3YLt7CchMtaDsu+NWqVYh2lly90wYQku88qCfEP3CusXMbaMvvS5/kh1KNPoBVKDZjEj0laPf2UA==
X-Gm-Message-State: AOJu0YyQa8JiCyyC+LtNCIOZ4dAhHQqMOKg81fR654YoOWvJf3qCG3zI
	DaHwAV4vUKyT0fNyEBBCRzfvymfyq4qA/zrmBluMleENZ3ISfq20
X-Google-Smtp-Source: AGHT+IFyFkidkcxZnQ4rgY6csioHVxtcr5R44bf9FruzOQO2oqGRjidggh5k+hK76+61EvnYJFfdrg==
X-Received: by 2002:a92:ca49:0:b0:375:e04f:55ac with SMTP id e9e14a558f8ab-3763dfba0f8mr105465295ab.16.1719355427614;
        Tue, 25 Jun 2024 15:43:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3886:b0:375:a4ed:3509 with SMTP id
 e9e14a558f8ab-37626ae39fdls49217285ab.2.-pod-prod-03-us; Tue, 25 Jun 2024
 15:43:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZmqUSE+IPvvqeNOTh5WJN/20B6QbdIyod9xqWWstUBZFD0v8ZIIcDc5OeGPwc2TizVv7HaBeO8mBN2hqQWq4yux3h4ajMLoSlsg==
X-Received: by 2002:a05:6e02:214c:b0:375:aa46:4a30 with SMTP id e9e14a558f8ab-3763e0600f9mr130799675ab.23.1719355426724;
        Tue, 25 Jun 2024 15:43:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719355426; cv=none;
        d=google.com; s=arc-20160816;
        b=LrHOPgZGs2w3/dZOUp5a5QzJeJngQC2cdWUI3oJFE/H8Zpg19ceCiMn8q9aGDX8gjh
         /3RWDzAvj6fL4BkOX0GpF/0jWoND/jhhUNFwj2fzrNYhOYFlpjDx8qHTl70a5sHWKbK9
         1eETGXSPA2tG3cOCsoRqNdlAIv3M598mg/ySqsVpWQ/uDf8Y7wnkUY9C1sgLPm8jAC9o
         CZyNcb58S03e3z5vJShKpo2sgqtft0EViRohJ9FwxgDtmXnXjm8dfqUQ/FTfAIBejjGc
         nToUwoNYRe0qqW+9mcp8CLk9DMx3AfGLov4pbhtABIQKGz+j9eMMW6zP+gc61oB7ngvd
         FdlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Bw5IY2Lp48TOvNbNeQ37qr0ewoVT/TKuODoQTSIsLUg=;
        fh=H6CH34hcYenSB7FXrgY3SiQWBl/4Errpy/cWaxiK6f8=;
        b=hvyyUET7JoOW1a101If+5kziCF8agBnmHhJMtcSp5tNEz8MS5X11pFa9IOSRq40avb
         J79lWoxm1ETUTL+aBhM0mWSCFSZU50cyIDoEbGzPSQr7WLvoIE4kT2b1paNVCvHBsxtM
         y101J+X4oVKDXHIleFUe1eZyx/rYXkGUayCKWozJFQFWo88Kg1ZH8a0wGE3EdF84YUNS
         yLR1myvjNDYYQK59jwbXYCunf6eeHNTFnnC958HviH4HOjbcKarpAucVtHemlfhJvxL9
         iTP4TSzKrdeLPSDuM1GgMIaP7u4BMr7rggncAhVB9z6InH2f2ZS+A2cc32nKk7xaIlts
         HRbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LalejVUM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f3d60a9si4515465ab.5.2024.06.25.15.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 15:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4E80861780;
	Tue, 25 Jun 2024 22:43:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3666BC32781;
	Tue, 25 Jun 2024 22:43:45 +0000 (UTC)
Date: Tue, 25 Jun 2024 15:43:44 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com, Mike Rapoport
 <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>, "K. Y. Srinivasan"
 <kys@microsoft.com>, Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu
 <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,
 "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,
 Xuan Zhuo <xuanzhuo@linux.alibaba.com>, Eugenio =?ISO-8859-1?Q?P=E9rez?=
 <eperezma@redhat.com>, Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>, Oleksandr Tyshchenko
 <oleksandr_tyshchenko@epam.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 0/3] mm/memory_hotplug: use PageOffline() instead of
 PageReserved() for !ZONE_DEVICE
Message-Id: <20240625154344.9f3db1ddfe2cb9cdd5583783@linux-foundation.org>
In-Reply-To: <20240607090939.89524-1-david@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LalejVUM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

afaict we're in decent state to move this series into mm-stable.  I've
tagged the following issues:

https://lkml.kernel.org/r/80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel@linux.intel.com
https://lkml.kernel.org/r/30b5d493-b7c2-4e63-86c1-dcc73d21dc15@redhat.com

Have these been addressed and are we ready to send this series into the world?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625154344.9f3db1ddfe2cb9cdd5583783%40linux-foundation.org.
