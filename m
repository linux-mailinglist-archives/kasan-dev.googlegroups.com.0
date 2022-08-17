Return-Path: <kasan-dev+bncBDT7BHX6YALRBEM66KLQMGQE4BHUNUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 425A25969B8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 08:47:47 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id q4-20020a0568080ec400b00342b973d2e3sf3532926oiv.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 23:47:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660718865; cv=pass;
        d=google.com; s=arc-20160816;
        b=XME/vDJ3fPsERMXMhpUEt8OBX3BOLicdaO1R92lRg9I+RaXPaRSjWNKdwm2o5VhpP8
         c0KDIkRtXt0ouX3pK+6kYvFH2Tt77NE73i5OYl5j5K8CC5dsq+I9PZZYpgUvlyBBpoBg
         Yg5AaPPO2Mobgh9i8FxGRQw4ULqGGp+e82Cqf2wShLs1zgJYhMfo7n2rjFiWB//eI739
         DHvOsVLxvPpLhYfq2RtYdPvjx7cxR3x7kSYA4bEXie/VNPPnG1ajxUvAFtnUJ4uwgz23
         2EtoL4+VqsTrIwc4pkP+cP2ixg6dyWZUtOD7Sf3EVw1wqg+xygXo07vaL3LaSbHjsik5
         u6wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :date:subject:message-id:mime-version:sender:dkim-signature;
        bh=mbNjEUZ4crXWWq4fGTMySKgfokDvSFg7XZWv599npOQ=;
        b=Uhycp4/Izi1rZQNb/uUgPB6r171cOiNolne69rJljH+kUfkjvxwdEd0ysfnQf6w6DV
         em+Eg63c61/oHoK+W+2eqDMxFdG5esH+30sI5oWetMlOYC/pSQbIKoBTqL1am/c9xfkj
         9sqwiR8JwBJfNxFYsmfoq9H+UlidtngzyNOPlC+VlLx0ah1nPoTaPT6O/FO5X5C2F9yL
         laFSlWIcRsQMaiwzbu+czzvqGQyCmnmfPstvQRaK6/f1MVO6tSJfHGHkALTBAR53zCMb
         hRVzh4RUJmZjwrZZ8Q8itrffb0YEJXSJEpqQz6sQK+kvKk9y/A2ptA0xAXUUGwkdYQmO
         amxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 47.90.199.18 as permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from:date:subject
         :message-id:mime-version:sender:from:to:cc;
        bh=mbNjEUZ4crXWWq4fGTMySKgfokDvSFg7XZWv599npOQ=;
        b=JZMxucJ8bThZ4AJsrkr/HTGx7o3fm16+eLzCZVroOyDC9j6fcFhWxEvUwVNyZT31Mz
         BoQTB7XmcWZXerryETLtG9lD+SAfabVM8ZhY94Vax0mwA512WZn4aYQelCWaSJMamAjl
         HdDN3bbp3t2kbzjvlkzenR+iF8b1nQdHrwd5F/n3rWXqqFgIs2pbzfXoRfe1OpOMZPSR
         SAxLriNqbaEF4C/WyJ4qi3lltXbmvvx38azkDQgM1+40sxixk7C+B+QzRe2Qp5+U1quE
         Xeph2TzF7BsJ6prHPV3X7GJWtr1Y1gBZndBnK0KT1AXf2pjMJNCzITtqS9ItRi9PFp88
         RxnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:date:subject:message-id:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=mbNjEUZ4crXWWq4fGTMySKgfokDvSFg7XZWv599npOQ=;
        b=66EURCERQgnLleHzUIykF1kY2KdMA+QWVaJ8q9XHKFnr8q/YI3fFj6j4MtoIvKq8XI
         8KgkeDX8hvos4ZEjMZkbe+IVX4+qfq3l9+aHUziUlHVHlSqGpDyS6Otr3LMWjEn5/Nzy
         Efpz1JTRVgix241CskE9+aaBGmObXU2lmDE0f7M2QwORqVcSY0uII5cJ2SHRN36S/XcF
         orN15W0e+TERNRIvzLwMUqFEvVNls7wgNs0jcicVVF5n1r0QmtUoylU+EIYMzTM4C8So
         e/Y5jaCA6zlFplLuAfXUUzYYpu94vzwBIFdEV8cupEzeT9rjEJ/6TzuTgLzge4i9lRwg
         AIRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3HT7ajJPEEIxjP2FyL6zao50DBYV3y36Bb9ZCZdsnKl0u7XDDK
	rdxZb7Nk1U3P0Rkfpl7BbCY=
X-Google-Smtp-Source: AA6agR7sft0EINYx+nSTEIBZ4+kynV/74kK+Fihl9Jcz1P22iz2SvnLpnaPXlVKqv9vmu9ZRPe/6Gg==
X-Received: by 2002:a05:6808:e87:b0:32e:4638:302c with SMTP id k7-20020a0568080e8700b0032e4638302cmr834128oil.89.1660718865769;
        Tue, 16 Aug 2022 23:47:45 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:f:b0:344:8509:3bb2 with SMTP id u15-20020a056808000f00b0034485093bb2ls2389481oic.4.-pod-prod-gmail;
 Tue, 16 Aug 2022 23:47:45 -0700 (PDT)
X-Received: by 2002:a05:6808:13c5:b0:344:96e8:82aa with SMTP id d5-20020a05680813c500b0034496e882aamr909768oiw.67.1660718865368;
        Tue, 16 Aug 2022 23:47:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660718865; cv=none;
        d=google.com; s=arc-20160816;
        b=lJhcUmgFyizDAsZMpXKX8o0HWAp9njvFFWcyOy4teafKVkOG9USE8lEUmkmsCokfND
         Kqi+8dTVP1NKaxF7q/yX1OGo/23hHBQkI3qea2cqO08V+U7x7eWZMeDlirsjWWpN1xPP
         2U/TNgwz/AQYU4sR7BZa3CPm6PBKwMwZ3KiN2DPAQEj3P1QjGQBi0skf7Ohmm9qpW28P
         8s1Xm9XAL31qf/gZye20g8Bod9DkOrdOP7EYu00MpNKdErvRtx+fstwEJDoe+5qtuJbl
         PedXWM7W1zikGIbhbwiW/BC+jpeT9V/FCW0AMShGP8XgJ9I+ZqOeTUubcjX9iO+T0S/T
         FCEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:references:cc:to:from:date:subject:message-id;
        bh=ORThCAQiC6zhdJvVd9BPKP/J9bo62a/svHyV/dsQjX8=;
        b=N1PhkdfS8E+IxiovPfOAJFauiFVtCMzyskv5zMs8vb413L9jjhvtl9W4ggyjAKlc6d
         HNH9K8AZCfmwVtJwfXCSLTVHynLVyh36FzZqsTYCG4npTO/T2HTpvX2VQZGVc/ut8h30
         DSbqzLpZf2Ulo5JqJKDCZE1O+Czj9EuYbiolHKukmqrPIzK1Mn88PdXZXhA5CEVP6TB5
         KEccKy7U1jvIbqW8SAXT9J2+5NruvfLEGWpCXL7OewUmte/fvQD4xoXtRbvkBLFlVcuW
         CBMWcJFnLwhasyz3Pcjm164aX+gWU6sLmCDZwBhTJQt2XmZ+tf5FXupU1WCwzMccH6CB
         wcfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 47.90.199.18 as permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out199-18.us.a.mail.aliyun.com (out199-18.us.a.mail.aliyun.com. [47.90.199.18])
        by gmr-mx.google.com with ESMTPS id j4-20020acab904000000b0033a351b0b4asi845730oif.3.2022.08.16.23.47.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Aug 2022 23:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 47.90.199.18 as permitted sender) client-ip=47.90.199.18;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R211e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=ay29a033018045168;MF=xuanzhuo@linux.alibaba.com;NM=1;PH=DS;RN=19;SR=0;TI=SMTPD_---0VMUSyp1_1660718846;
Received: from localhost(mailfrom:xuanzhuo@linux.alibaba.com fp:SMTPD_---0VMUSyp1_1660718846)
          by smtp.aliyun-inc.com;
          Wed, 17 Aug 2022 14:47:27 +0800
Message-ID: <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
Subject: Re: upstream kernel crashes
Date: Wed, 17 Aug 2022 14:36:31 +0800
From: Xuan Zhuo <xuanzhuo@linux.alibaba.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: James.Bottomley@hansenpartnership.com,
 andres@anarazel.de,
 axboe@kernel.dk,
 c@redhat.com,
 davem@davemloft.net,
 edumazet@google.com,
 gregkh@linuxfoundation.org,
 jasowang@redhat.com,
 kuba@kernel.org,
 linux-kernel@vger.kernel.org,
 linux@roeck-us.net,
 martin.petersen@oracle.com,
 netdev@vger.kernel.org,
 pabeni@redhat.com,
 torvalds@linux-foundation.org,
 virtualization@lists.linux-foundation.org,
 kasan-dev@googlegroups.com,
 mst@redhat.com
References: <20220815113729-mutt-send-email-mst@kernel.org>
 <20220815164503.jsoezxcm6q4u2b6j@awork3.anarazel.de>
 <20220815124748-mutt-send-email-mst@kernel.org>
 <20220815174617.z4chnftzcbv6frqr@awork3.anarazel.de>
 <20220815161423-mutt-send-email-mst@kernel.org>
 <20220815205330.m54g7vcs77r6owd6@awork3.anarazel.de>
 <20220815170444-mutt-send-email-mst@kernel.org>
 <20220817061359.200970-1-dvyukov@google.com>
In-Reply-To: <20220817061359.200970-1-dvyukov@google.com>
X-Original-Sender: xuanzhuo@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of xuanzhuo@linux.alibaba.com designates 47.90.199.18 as
 permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Content-Type: text/plain; charset="UTF-8"
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

On Wed, 17 Aug 2022 08:13:59 +0200, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Mon, 15 Aug 2022 17:32:06 -0400, Michael wrote:
> > So if you pass the size parameter for a legacy device it will
> > try to make the ring smaller and that is not legal with
> > legacy at all. But the driver treats legacy and modern
> > the same, it allocates a smaller queue anyway.
> >
> > Lo and behold, I pass disable-modern=on to qemu and it happily
> > corrupts memory exactly the same as GCP does.
>
> Ouch!
>
> I understand that the host does the actual corruption,
> but could you think of any additional debug checking in the guest
> that would caught this in future? Potentially only when KASAN
> is enabled which can verify validity of memory ranges.
> Some kind of additional layer of sanity checking.
>
> This caused a bit of a havoc for syzbot with almost 100 unique
> crash signatures, so would be useful to catch such issues more
> reliably in future.

We can add a check to vring size before calling vp_legacy_set_queue_address().
Checking the memory range directly is a bit cumbersome.

Thanks.

diff --git a/drivers/virtio/virtio_pci_legacy.c b/drivers/virtio/virtio_pci_legacy.c
index 2257f1b3d8ae..0673831f45b6 100644
--- a/drivers/virtio/virtio_pci_legacy.c
+++ b/drivers/virtio/virtio_pci_legacy.c
@@ -146,6 +146,8 @@ static struct virtqueue *setup_vq(struct virtio_pci_device *vp_dev,
                goto out_del_vq;
        }

+       BUG_ON(num != virtqueue_get_vring_size(vq));
+
        /* activate the queue */
        vp_legacy_set_queue_address(&vp_dev->ldev, index, q_pfn);


>
> Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1660718191.3631961-1-xuanzhuo%40linux.alibaba.com.
