Return-Path: <kasan-dev+bncBCQYDA7264GRBS4R6OLQMGQE772UTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B2F8596D07
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 12:54:05 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-334ab1f0247sf38036017b3.7
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 03:54:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660733644; cv=pass;
        d=google.com; s=arc-20160816;
        b=botJSha3HdqspLXVG0bK0Tau8d/NI+mW55dm1nopcW/7mudnhjTvMCn4cDnWrkhiuI
         oGRSmtfZmom6ZDctSmVzkdL0AIr0ie4xuDg7fWwwqbsAAu+6T9/ehnmiaJh6vN3g8RXi
         YKcmDfDl+N62IGSso1nychV/66cZ8VCO9zgmp2eVzTtyd18V9RY09boHv16yXP9d/km6
         Mc8XlKVaDL4ZIx22JH5Py+x1HgTnZcVYlKaepUamciV0+XDaN6tRlEvoL0rSZ6UoW5Ds
         q21st5VFaOhIT1cYtMPtfswEnhOOcUxJW+pAP3af2PYbHhY5ZRyf5jpgPsvTMlZKjC3V
         A5RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VD8aerOWUe3NWuk9EdmVEu/pKl53LXU4bWJefzXRidc=;
        b=TUSitT6+k55EKNGs75717yHR8VoINW7KGOT8Z0n0o1v3ACXVLFCar/sdHcJuwXat44
         IJgZk2FpsYgHgx5p9FVw65ZHFbhxwxjdAUGQ6ySnt+u6Qvn5B4HQLqVbKHiNYlH+EF4R
         UfogAVtZoveoBOkx0JHpw+RAvSrvVyoSm5c+E3XkCE4KjVTqycsLT3hUbVVajnq3kEaR
         468YAu0C/2ZgFlrOzeBkhX0/eR/iUrgxp32XlKgrbZ3UotzZYXiuuAncMO7a1aMMj1iV
         bTJy1iUxz9g3jemXC50TpumSZTmnbYeLo13qUSi0MadFYZdeZtU1dGfBMTAlC+ytHjuH
         hz6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=S8+n9d3K;
       spf=pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:in-reply-to:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=VD8aerOWUe3NWuk9EdmVEu/pKl53LXU4bWJefzXRidc=;
        b=GbPq54j34N3nrsADWQM5x3oFYo8eTKFs2qUTBgOp13ewAzkibAZVydqXb1gd6mT5si
         gkA684LsJxhyptdcFKxrNHqW72xRRghimFVhVC0/qcBb6JhRxuKmYxD/VHXeOP3WDHZU
         FWg/AT+AWNET1liBGgC/8fDCbglXtA4GPhCNOJpc0O53kaE6GhPqamykpkgP6Y6USTTz
         9iXKCe6FJ68bC55Cg0aQLiehUVieUC2G/BriWIDmvhBJS+Fr2yYroxvjqvvmJhs8DBQq
         Zkbiir4IXHsj+ZT1hNa0q2jvZ+pZFfoY3zAV5hbl6uQcqpkJNv3DgD6qSvy4OXF48h7m
         s7Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=VD8aerOWUe3NWuk9EdmVEu/pKl53LXU4bWJefzXRidc=;
        b=EcPDIWfJwXGBmgZHvGu8s0FC3egg1Fhtg1/fMglTS3r4o8Kv4vCJf5Vr9Pc64BF8rv
         azHmvRQVpj3ZIruCYOAU3uSSIeBuOtOjCh+r6NpvLBu3+uKqrFz03y1nfvn66DgU7WK8
         YoRkqM/oFRd5ehSXOSDp8acUyRZkpbdO/RR1mx1ZBGAkkwLswdxR0tz6wnG8a16DFwFp
         zKxSp+ft1nKKIUM6gDGemwZuOR5Be2L+Xa9jeOVxGRIwOo3Plx797rFufshpfmxAWb/F
         23LLrZ2hCMM7Bs7o6wzijJ6qaRrJTNLe18sV/6xH7LlivMPohkyWI3emv2Vh+PgVKB0Z
         4gAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3m1sOl0fAWIwm//FjZKFjNXJUyIWVHDYF4XW3id79jyqwc5cOp
	CZDeg1e0ZuvZ4m0GkddZqlk=
X-Google-Smtp-Source: AA6agR60O7XBpUmHazlmbwxy/ccMVrtb0xYQ4c0uTOfnJ13C2WjatAOBDNfgSpwJ8Nf3xu/ty4FRNA==
X-Received: by 2002:a81:a084:0:b0:326:d475:4f8 with SMTP id x126-20020a81a084000000b00326d47504f8mr20047122ywg.284.1660733644038;
        Wed, 17 Aug 2022 03:54:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:95:b0:32f:dc69:5a33 with SMTP id
 be21-20020a05690c009500b0032fdc695a33ls4268120ywb.9.-pod-prod-gmail; Wed, 17
 Aug 2022 03:54:03 -0700 (PDT)
X-Received: by 2002:a0d:ea86:0:b0:334:97b:101f with SMTP id t128-20020a0dea86000000b00334097b101fmr5239944ywe.120.1660733643446;
        Wed, 17 Aug 2022 03:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660733643; cv=none;
        d=google.com; s=arc-20160816;
        b=BAu0Vx2L5MmrE3qLoZApzIFwTlpdmKs3Bupc9Itb28HX//jrYgMowSPNI4fNWnCycw
         DGx29l3fbOhqloV8d4jbuCGkvJocUODzw6VGHADWTP23JCNMaeHx3aBizRYRNKkcHVG7
         fEGnApJLggzMjhoE9MJl5Rt2NCjmtqWayqwZp51Sf0lwYzQUFjofnulaxtC10YfBFOQ/
         ozd4T8d6K3FFy6gmZwaOi8LaUP63ZHApc9U/+Z5nvkc9HiJW9AVcTRs8tkszpv6SAK5m
         QCYX3OzrkOjhqPbtnsuAw6SKEmG18QVKquxVmf8Byp+0BPXYslESwE9Pzo7um85keYsm
         5KOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gWHtHY6d40uY0Ij4s58yaxGtL5XuSJS0/N+jf5H/pmM=;
        b=E0HRgXuxtB5jp89wezB2K2fAWa1H9rVuLEc7A77Jdhgu/vSD3OjH8XAeG+yeT0S243
         xjvpVw5DRDlmBdb65ZTOz1VZWzq7DJdUb3RAXQM8a3QfBIyr+K7OvftieeP5uxwU4sTE
         nCPi49RYGcmCbRQtvHyKsheET6N6gxPUQVcmVp59m8fyVYy/6CDD7T6TKuK+61mzV81G
         Xdt7LOqgulK8vTOapGW2YyCsKmThdeqrC982Mdw2m42BK6HMpFXDRGv6REY3MhXl4Rdl
         2lgP8gRNGchBtpWfTeuPrjMzbNYUzddng+bGtGZcTJme2eTYAys2Axve2cBWH0nWgLjO
         NlvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=S8+n9d3K;
       spf=pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id s127-20020a257785000000b006716b97bbf1si190837ybc.3.2022.08.17.03.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 03:54:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-274-0_6OmuPxNauSwFwjcFs4VQ-1; Wed, 17 Aug 2022 06:54:00 -0400
X-MC-Unique: 0_6OmuPxNauSwFwjcFs4VQ-1
Received: by mail-wr1-f70.google.com with SMTP id o3-20020adfa103000000b0022514e8e99bso961556wro.19
        for <kasan-dev@googlegroups.com>; Wed, 17 Aug 2022 03:54:00 -0700 (PDT)
X-Received: by 2002:a05:600c:4e11:b0:3a5:bfd3:a899 with SMTP id b17-20020a05600c4e1100b003a5bfd3a899mr1743692wmq.185.1660733639795;
        Wed, 17 Aug 2022 03:53:59 -0700 (PDT)
X-Received: by 2002:a05:600c:4e11:b0:3a5:bfd3:a899 with SMTP id b17-20020a05600c4e1100b003a5bfd3a899mr1743679wmq.185.1660733639576;
        Wed, 17 Aug 2022 03:53:59 -0700 (PDT)
Received: from redhat.com ([2.55.4.37])
        by smtp.gmail.com with ESMTPSA id p27-20020a05600c1d9b00b003a35ec4bf4fsm1905896wms.20.2022.08.17.03.53.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Aug 2022 03:53:59 -0700 (PDT)
Date: Wed, 17 Aug 2022 06:53:53 -0400
From: "Michael S. Tsirkin" <mst@redhat.com>
To: Xuan Zhuo <xuanzhuo@linux.alibaba.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	James.Bottomley@hansenpartnership.com, andres@anarazel.de,
	axboe@kernel.dk, c@redhat.com, davem@davemloft.net,
	edumazet@google.com, gregkh@linuxfoundation.org,
	jasowang@redhat.com, kuba@kernel.org, linux-kernel@vger.kernel.org,
	linux@roeck-us.net, martin.petersen@oracle.com,
	netdev@vger.kernel.org, pabeni@redhat.com,
	torvalds@linux-foundation.org,
	virtualization@lists.linux-foundation.org,
	kasan-dev@googlegroups.com
Subject: Re: upstream kernel crashes
Message-ID: <20220817065207-mutt-send-email-mst@kernel.org>
References: <20220815113729-mutt-send-email-mst@kernel.org>
 <20220815164503.jsoezxcm6q4u2b6j@awork3.anarazel.de>
 <20220815124748-mutt-send-email-mst@kernel.org>
 <20220815174617.z4chnftzcbv6frqr@awork3.anarazel.de>
 <20220815161423-mutt-send-email-mst@kernel.org>
 <20220815205330.m54g7vcs77r6owd6@awork3.anarazel.de>
 <20220815170444-mutt-send-email-mst@kernel.org>
 <20220817061359.200970-1-dvyukov@google.com>
 <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
MIME-Version: 1.0
In-Reply-To: <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: mst@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=S8+n9d3K;
       spf=pass (google.com: domain of mst@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Aug 17, 2022 at 02:36:31PM +0800, Xuan Zhuo wrote:
> On Wed, 17 Aug 2022 08:13:59 +0200, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Mon, 15 Aug 2022 17:32:06 -0400, Michael wrote:
> > > So if you pass the size parameter for a legacy device it will
> > > try to make the ring smaller and that is not legal with
> > > legacy at all. But the driver treats legacy and modern
> > > the same, it allocates a smaller queue anyway.
> > >
> > > Lo and behold, I pass disable-modern=on to qemu and it happily
> > > corrupts memory exactly the same as GCP does.
> >
> > Ouch!
> >
> > I understand that the host does the actual corruption,
> > but could you think of any additional debug checking in the guest
> > that would caught this in future? Potentially only when KASAN
> > is enabled which can verify validity of memory ranges.
> > Some kind of additional layer of sanity checking.
> >
> > This caused a bit of a havoc for syzbot with almost 100 unique
> > crash signatures, so would be useful to catch such issues more
> > reliably in future.
> 
> We can add a check to vring size before calling vp_legacy_set_queue_address().
> Checking the memory range directly is a bit cumbersome.
> 
> Thanks.

With a comment along the lines of

/* Legacy virtio pci has no way to communicate a change in vq size to
 * the hypervisor. If ring sizes don't match hypervisor will happily
 * corrupt memory.
 */


> diff --git a/drivers/virtio/virtio_pci_legacy.c b/drivers/virtio/virtio_pci_legacy.c
> index 2257f1b3d8ae..0673831f45b6 100644
> --- a/drivers/virtio/virtio_pci_legacy.c
> +++ b/drivers/virtio/virtio_pci_legacy.c
> @@ -146,6 +146,8 @@ static struct virtqueue *setup_vq(struct virtio_pci_device *vp_dev,
>                 goto out_del_vq;
>         }
> 
> +       BUG_ON(num != virtqueue_get_vring_size(vq));
> +
>         /* activate the queue */
>         vp_legacy_set_queue_address(&vp_dev->ldev, index, q_pfn);
> 
> 
> >
> > Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220817065207-mutt-send-email-mst%40kernel.org.
