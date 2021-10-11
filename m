Return-Path: <kasan-dev+bncBDOPF7OU44DRB2VUR6FQMGQEKS5XWTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA7A74286DB
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:32:10 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bq35-20020a056512152300b003fd45087a72sf11883016lfb.9
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 23:32:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633933930; cv=pass;
        d=google.com; s=arc-20160816;
        b=rq9z2RAVyZgSclJ9OhDnXM6390Z+BYxrU+NZxRmowDTupR+6Aor7jAoXVkXWhWEYeT
         yrNgslxT+5EPYokgg6cI8lGOYtjMYUL4MfbOW8u6+DPDeIN17W5Y0a9lflqoNSXTPdtK
         IH0ypWUWogGah5mEvWaeQc6vL2yN6gmgkVhp0nO3t8UEhNi7B6mZvO1qSvL6+wXlL0O9
         SXutfC0eGU7qVitp1Fqe28wzU7x9cDx8+xGH3gR/+OvLnfbSTtyeEm1mY8wrDWGt52iS
         7jbIJpocpVq5/lPQ/22sFU0dbq6IWCnXy1YyOD8Zzo9v0PuwlOLqxOUAzG/jfn2Wu/d2
         6O1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XE0ZoDCb8HR85jpM5kZBPjWbg9jmqbnwHrVHyD5SuNM=;
        b=RBi/U6oaEOcxFm0b4/jU2cwbhbqNOWPJUJIs5ad9Ma5T3PKuXhpdgxrimPX6Sdqvsf
         X4lsnerbsQNumes5j+3fdj1MjtI3+tDZYnEr2K8rND3MQ8KgwBmPupYUQf3bpV5TFt0F
         LIx9H3bHtegD2nGtZV1Lo0rn1JPOjr4kCJkSrLAKx2bG+tscYtQGZ5CkflmmKaHVKPDZ
         uhWX6zzLBEMa3errR2LjY5LwVNlkveXrEYSqdZVU2Z5WLVIKxM01nOY3X3ixg8Kt7pOA
         9hlOnCybs7+cN4zAJSalvs8V8msxf6QTNHNuBkJHbnVHhacC1wLYC2BtdPmLW8bQRjdI
         5pBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="nxEy/w5r";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XE0ZoDCb8HR85jpM5kZBPjWbg9jmqbnwHrVHyD5SuNM=;
        b=R8Xuy5NrkeT8jYqDnr4BJqEiSH1xkGPfWN2MbpFDH6l1DZ2Nq171Ifb0Y3UHVUPYbS
         LJN6iOYkSSnMq2H2pgPvV6UBcdtinN8JN1jfn6kqB1zHU1sOFHI1Zz17uBC1T7kqWHiv
         zZdPgOL/q7lvR0HvCclbHOxGfAF41d7Ojwa+PUU+33SgI/oMJclcAjMiqKhxjPtqYoGo
         or4fnMQcMQkbr94n8rGZnzBJ21ZgfcRn4luUradiugbh7g1t/DjDaDXMLiRfNbjAvjyT
         IkFeq24wDzh70BWVv3wKQtYQdbx5odD7tts+tyAgZoHMm5cDY/8EYTKF7DNvifzMUs/o
         z6Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XE0ZoDCb8HR85jpM5kZBPjWbg9jmqbnwHrVHyD5SuNM=;
        b=u5V8tSwAzIjEwnWcNuvHtgawarmIGbRJK+m0TRNxa3EFK0TJzlSEPFo+tatDOmqpUl
         ACPzY6rmCuO7ndbhdIV8PFkVTsaSCt1nO5KnwQfhdvjlGniscIH8ohyzesAjD3rF1km4
         CqYfyem89mxTU4gbMGRnZKVb/vko0PaKOG6ytalamPKiyg8gMaPBjAeLhaS8sHBIXykw
         cy2GwPAf/wVafUZ/rsv8xdcUD3w1gWUJewP1f/xY5DdMkExXNFCjWnjJI3tpr9ydjOK6
         YNvTHoG2Vz0vxOrBijJtsifVPsBZhCYR3on/GJ/BEfzjFvMwH4kWn33jRfdSBbL0Cfxq
         kbaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w6bVlBCLHodRWeyU9t9yJO+TcORnou7CakAJcbcvFeefoRtPf
	1xhwXB8FDLWHSMeH3kSqbLU=
X-Google-Smtp-Source: ABdhPJz0mOivzowkd5rJPZaIs8sU91CKka/X/evYm4bs+D3NmwArbnb8MYaOMwi/6vWWdB4/6Le5Uw==
X-Received: by 2002:a19:8c4b:: with SMTP id i11mr25878483lfj.278.1633933930348;
        Sun, 10 Oct 2021 23:32:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls1673132lfr.0.gmail; Sun,
 10 Oct 2021 23:32:09 -0700 (PDT)
X-Received: by 2002:a05:6512:3b8b:: with SMTP id g11mr5618909lfv.216.1633933929387;
        Sun, 10 Oct 2021 23:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633933929; cv=none;
        d=google.com; s=arc-20160816;
        b=0MGVWGwES86XGVtutz1EGUBE992hCYPlwhhAUEPI9XX63IJUIJkh6Ulq33SR+r96GI
         QyZLlEPb4wFq9Gh0cbuan6FSWMtGP2rSWDhKgBCAxigDZAVahvZTft9TXUlYX9yIrELM
         r2g2Ek4KBIqNeDFhoPnbUbdgIRn2I3yoLlhRqTZCMWxzYpZitU0fjNrJREjLxhtXuYMz
         tMHrqJRjKKtzDBkM9XtQFO4qHAZ9RWof5RFxEtrWMN5BGfPbPxTtC5JnOxCN9t3/w4C/
         lJd6HUWnFoOdSiHw39IrizKfSD3+sUPStNu8TNGfyY/PB3FOFwaw2HSUuH0I18gJa1m9
         D3BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lwPipFh22ocDNcUOEMMzIfuiqy6HWce+IYzbCS/BeoI=;
        b=RztGNj32uRmvDbDE7rSa+8I6l6EsmdLFTZ6TCaUn1E/V0HYBqUxU3QTZRgi6axPod1
         RGhkMHNRZrbbAEKFEex6wohxvsWv7N4pdk68tftpWGlir05Wzo02Malt6j4IuxR6MN5z
         13L3rK6dd6hB5djadeQDTl5A8x3GAqRsWQqL6N2yHiBteCjSMHR6O63AUhD2jbhawZSF
         WFe4dusOYqQQenIA/LPzTpb3GiENaVshO1Exik6CUYXSZpjRPwsEpdZWboBe6C/emBYn
         4jjlGH7SJNFuYHLEU4UguiNg4X+i3NKcjmCL4tsnPqWVO4YIFoE8h4ZPtImkboXUUB64
         f80g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="nxEy/w5r";
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id k8si243817ljq.8.2021.10.10.23.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Oct 2021 23:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 8F53E40000
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 06:32:08 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id c8-20020a50d648000000b003daa53c7518so14868144edj.21
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 23:32:08 -0700 (PDT)
X-Received: by 2002:a17:907:334f:: with SMTP id yr15mr7244662ejb.8.1633933928111;
        Sun, 10 Oct 2021 23:32:08 -0700 (PDT)
X-Received: by 2002:a17:907:334f:: with SMTP id yr15mr7244636ejb.8.1633933927912;
        Sun, 10 Oct 2021 23:32:07 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id o15sm2945745ejj.10.2021.10.10.23.32.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Oct 2021 23:32:07 -0700 (PDT)
Date: Mon, 11 Oct 2021 08:32:05 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWPaZSX4WyOwilW+@arighi-desktop>
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
 <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="nxEy/w5r";       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122
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

On Mon, Oct 11, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > I can systematically reproduce the following soft lockup w/ the latest
> > 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I've
> > tested so far).
> >
> > I've found this issue by running systemd autopkgtest (I'm using the
> > latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen with
> > any recent version of systemd).
> >
> > I'm running this test inside a local KVM instance and apparently systemd
> > is starting up its own KVM instances to run its tests, so the context is
> > a nested KVM scenario (even if I don't think the nested KVM part really
> > matters).
> >
> > Here's the oops:
> >
> > [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [udevadm:333]
> > [   36.466565] Modules linked in: btrfs blake2b_generic zstd_compress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> > [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
> > [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
> [...]
> >
> > If I disable CONFIG_KFENCE the soft lockup doesn't happen and systemd
> > autotest completes just fine.
> >
> > We've decided to disable KFENCE in the latest Ubuntu Impish kernel
> > (5.13) for now, because of this issue, but I'm still investigating
> > trying to better understand the problem.
> >
> > Any hint / suggestion?
> 
> Can you confirm this is not a QEMU TCG instance? There's been a known
> issue with it: https://bugs.launchpad.net/qemu/+bug/1920934

It looks like systemd is running qemu-system-x86 without any "accel"
options, so IIUC the instance shouldn't use TCG. Is this a correct
assumption or is there a better way to check?

> 
> One thing that I've been wondering is, if we can make
> CONFIG_KFENCE_STATIC_KEYS=n the default, because the static keys
> approach is becoming more trouble than it's worth. It requires us to
> re-benchmark the defaults. If you're thinking of turning KFENCE on by
> default (i.e. CONFIG_KFENCE_SAMPLE_INTERVAL non-zero), you could make
> this decision for Ubuntu with whatever sample interval you choose.
> We've found that for large deployments 500ms or above is more than
> adequate.

Another thing that I forgot to mention is that with
CONFIG_KFENCE_STATIC_KEYS=n the soft lockup doesn't seem to happen.

Thanks,
-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWPaZSX4WyOwilW%2B%40arighi-desktop.
