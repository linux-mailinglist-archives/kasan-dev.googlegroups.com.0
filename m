Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB7EQXWKAMGQE3BFUTIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F2DE534C83
	for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 11:29:33 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id q17-20020a0565123a9100b0047889d19f70sf601757lfu.5
        for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 02:29:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653557372; cv=pass;
        d=google.com; s=arc-20160816;
        b=J52JPo0+8tKBbaf8QCbZhE6sK/u7L6qJegElMlvgfpy9xyHi9CXnAs0Ic51ytn2IjZ
         mC7X6NGlyI6IqN7bqe5dIZLvBCz906nKITrsgdlnTuCtCDT25HXN5WDVL090JN56a7+b
         06L/ir6zF42CBHmg5/5f5F4esYr1hKa+mAWFpNIaLYqa3XphF0qQyC82nE6z7KfAfsgE
         uCh+dvTXMQkbrV+eCbugvf3wZi6h5V0vSKC5fth29hijEW4LAmhcNzdlJ7OFdGw1OKbE
         L49MO5KQL6m9IZSSwEO4pIAOZ9nem5dW0MgHNJJ86ZDHaESwCA2rLfGgGdlfDHxChVlT
         on/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=qLZJjBdlqVbckXcG+tl2Y6L28ir19yUJ2/unsbGMYo4=;
        b=NLnjbhIhi7Rltid1hc7NKyrUFd3LGXVcMWxvq8XYNNLKfsM+FtUXxckoBQNb2CWf8H
         N7+xMeHcwfx+jA38lrbS/UnSm+GyTebKR0YH0aFDbARr3kF5LBXlPx32I7TWBopX4iPb
         AxCJ9mssRLSCDiVtzSB34gq9zWB6GRvv6m4VCR5rtb3PoIpmA6675hKeFSeFfGql66sU
         Ct9V0DL+qz14/QJJM9gksB//4feuoJ419kBXJZGkURu6QWK0KvcYh4u6+IJTPgaiqMt3
         zfbclqLljJvQpNc4dYA6XcKQxYxJlLARZpW8q1xURv+ziH8UE5L2znuUVyTtk8mvEeDD
         Yllg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=ulLljctp;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qLZJjBdlqVbckXcG+tl2Y6L28ir19yUJ2/unsbGMYo4=;
        b=ibMw6GKKuHJvmkt3Fb1Lc3EPAR1t3OrA9vKdxiOxlRleJlvElNi15EYBRtbcGTY5aq
         3Zj+8wUSJBP4nkI+X15REW60XlWlv6eqocRG1bvlOOzfKQRKzfsXp0JLOTa7SJ1iiAr/
         asEdag6NR/rU5OXZtCHiSptyDrPVmQUFotjloPQwKneyATqeLZU0YP7R0Dg9k784a2N+
         auLuDdwQvYScUVLU8MZkpWxTmsJzAq6VsL6DSehwEnOMIsmFZjMGaPfvCjfRVZW4Xqrb
         x3W0oXXBJK3BRWmEe6CWQhCFVPd0S8/8elfSVveoqJQkllxvBdIhZEpuUpMAj8ijBIOB
         uMOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qLZJjBdlqVbckXcG+tl2Y6L28ir19yUJ2/unsbGMYo4=;
        b=LaiIiKbscOmlbEik8yZf8HQQXHsvXzH7lAO2RdCa/I4CNYdGc21VPwKESTLVRX8M3J
         N6x8kupZAhjU7K9mXvlfIZaqDEkUmf9ErFHWlqJq08G9pMMWLk73RcKmWB8ZQ2rTGono
         IV3NtuUm79SPNrKt1UOVfZtDkxZd9K5YrZo1FYSOHqMaMQSLOYTCUgwKSrcECK9TXZQl
         55R9VcfN7u4V6/4UfUiBf+Sp/fznxnAFJVttqveJSfvwx6govvkrGmX4XdmXlLMIgbH9
         D692hQ2yczms950GKlWdH/ALAqxhXfSnzgiCbnBj5jLokVeBLX2c38ROzH1kjQPTzX1Y
         HOhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530264u9uYj7TkcvDc4OiJAf4gxgEem0aKLztst7NizAmIEtoA7U
	994rWyvpDri54lFgViAn2j0=
X-Google-Smtp-Source: ABdhPJyot3fTy9DJad74JYLrw+BLOn896dS3HBCDMVczh4d9Vk+Rd3vRHChETXNithAnRrRJuy1Q3w==
X-Received: by 2002:a05:6512:39c6:b0:477:cc74:d734 with SMTP id k6-20020a05651239c600b00477cc74d734mr23778567lfu.363.1653557372476;
        Thu, 26 May 2022 02:29:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls6109897lfb.1.gmail; Thu, 26 May 2022
 02:29:31 -0700 (PDT)
X-Received: by 2002:a05:6512:22c9:b0:478:8583:6c16 with SMTP id g9-20020a05651222c900b0047885836c16mr9357347lfu.661.1653557371258;
        Thu, 26 May 2022 02:29:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653557371; cv=none;
        d=google.com; s=arc-20160816;
        b=xxHLsr+dMzeBz/yTr5f0Q8FEjr0vN+oH/yalAZKKUeBkjuv6bdqPS/dE7/Wov2yg+z
         Vp5AZds5QCxqrx68tDKJh5HjoxhNG58ae+jzOPxq1joyH38KO729B93WANRrgkMwpP6w
         C6dHInSX4fbtMToDImrA9QfJNeuzXy2cvSd3zIE70GJy2QeseOlmJ8JQTctEjyFx2aUG
         v+VfW5zhcEH8/RgKGRixTaN/PFXX/8ckA+Udj1IvfmtLrnqRjGcvHBoizbipfVlwRo+0
         SaNL5V5r+xmwKBrU7f+ub2nY9DPMkis7oAWdAN4CCdoyYBCp3B3B0/rsMZZwKEKGkZG/
         rKeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=qHlaIf1SKEc8acyjb+0lgUrClk4IwVEQpDXem5UwINU=;
        b=YKA/fYomcvVvUGXDN7y5YBB9KkWgMhkumE6cNvKH9I4sBBDZVtXOLn+6ASc+4wwdQZ
         5KKcdvxsgRjdLk3r6FJRI3DK65vz6HSYN5xni7/Hcf0sFNtkGPVRkILt/mzPSh1KWxzA
         MzvI09vE5l9YpQ6uvQxUf7605Ie90144barUHsfd55lxnhKzo9eXP/cs29Ad57iStGvg
         ghsuZp6jB5hG0ultsl0pRd1jAY8NTyV4xxDGl9y7Zm5Skbs3+2qzCJHvBgt/jqvltVZb
         /YHs2olbY/Y1lvOb2xQ+54WBMtS2/qtb0UBfp9t9ynAxegqF3SP0q7R8cvOf7nEv3ZKw
         SJCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=ulLljctp;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id p24-20020a2ea4d8000000b00253da2da6d9si56728ljm.6.2022.05.26.02.29.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 May 2022 02:29:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nu9o1-0055HB-74;
	Thu, 26 May 2022 11:29:21 +0200
Message-ID: <d5558b1a1ce7e1cb878f12462ae63a4d7b1b17a1.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>
Date: Thu, 26 May 2022 11:29:20 +0200
In-Reply-To: <20220526010111.755166-1-davidgow@google.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=ulLljctp;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2022-05-25 at 18:01 -0700, David Gow wrote:
> 
> +#ifdef CONFIG_KASAN
> +void kasan_init(void)
> +{
> +	/*
> +	 * kasan_map_memory will map all of the required address space and
> +	 * the host machine will allocate physical memory as necessary.
> +	 */
> +	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +	init_task.kasan_depth = 0;
> +	os_info("KernelAddressSanitizer initialized\n");
> 

Can we remove this? Or maybe print it later somehow, when the other
KASAN machinery initializes?

As it is, this gets printed even if you run just "./linux --version" or
"--help", which is a bit strange.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d5558b1a1ce7e1cb878f12462ae63a4d7b1b17a1.camel%40sipsolutions.net.
