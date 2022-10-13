Return-Path: <kasan-dev+bncBDY3NC743AGBBXWXTWNAMGQEZJEPQIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C88A5FD2B8
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 03:37:36 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id t4-20020a635344000000b0045fe7baa222sf190004pgl.13
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 18:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665625054; cv=pass;
        d=google.com; s=arc-20160816;
        b=0SzRjCPAn6EMQ8h8Film7IeEI90tZriCIxK064sDZB27LTtruQb634tuoYvHlpRn3s
         HB8WIw/gctWOysEoCpbiidQFfxvdDlNL1Agjd08DS0qfqjqwFhss0bxVuNVtKApVySiL
         Uaez2zkq/DdmG/XFjgqIbbXkcym+7LCyYKV4+zNfWBNKlcbjSnNrs5fQSPJaD7noR7qJ
         HyBVH1O/cVtm8kKLmsmBEu0Iz0Q/TWGBdaatTZppvXQXRlbtRNHe+YX+aoDGCXKnQdYO
         WEqxX61+5Tgor1SNn6ktp0ZsJ+/y6UT9sPB7F/i9y7GS5ZSZfxODXo3wC48PP5baZ2PT
         HEGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=HclmfMYKERMlwF3/VxcpV21QRf5HMrvXwdRrYfyodnQ=;
        b=ElGM4FPMI/pAcjI5iDz42lJDLkbtDgHnyMyK/qPGpalqvOLIfn23CpQg7CD3/gZ90o
         WZfH0xNyxSgv8nHunhKgk6QNfkEaEvy7r/FUIf9YamhXdUYz0Zl9+D5pBcLfwygVxynp
         i3U8j4Df9il2eRSsYdkxADbPDotqtP3mI5oCqv08VOYl9I0yjB4T8vKavBqiyqBV1nuY
         /JTuUYhzBsXnSH80bO9YPx/g7r54sRWPrPBxfyYmkRZfV1aJV4q23ypretHlNVGmp0C2
         fHgTh9MN5HKq5Fh01mBqQpoJNSntgxSZ29R77fXXBVoC54o+mm0Y4BT4tGuCexsgR9F3
         P7Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.15 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HclmfMYKERMlwF3/VxcpV21QRf5HMrvXwdRrYfyodnQ=;
        b=sBf7QzCQMj588RbINhKxrsj9HtwJ5VOQTfQiTQOzDbDZ6ocydaE53WheU1WHFb48WK
         1m0Rydgdrh232QvBmXhJu6rkmUOW9+J80BnxBU8l5GeqIXjJRctuKh3wqDxGg7d5X6hC
         2+e11y8GoDRkiGR26P2x8XAJp7UrQmuEzG2HlIGEVxrg75UKYTbcC0AK1T+OavCDw/5w
         1xWnAGKfj5yA4bEGd8HeZ/KalzMHaRJvgFRhilZgVrp6IRQcVgpxgdh71nsbingVohNa
         AWuysAmXraoI4wmsrCv8/ny8fGdBMyi+sz7NIJuWuvv3b/g5xD6rZh9Ts9hwrUHjb4iQ
         D9hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HclmfMYKERMlwF3/VxcpV21QRf5HMrvXwdRrYfyodnQ=;
        b=xcQ1aa/1LWD5nZ1Uak0ZkUmvOfstuxNgAx0V4Rg+rsW2E+y9I/Q/Jaz4TD2x9s/KaL
         GyGdLINL6G+90UgS7ADwNFMga9TyvvhuQqWU60cBxgkYF6MmU2XKIKlqvip/GE6yyIx9
         0hce5yNyMyquqZvMJrRRe9yi5ahJwmtKqUOLaXALPsiTVQH0Oy5YT6oyDS0Yof45HMMx
         iJqOFeQVzFGJ1Upc5ZRAPI2+FfTeSl0NNI2ca+TDZ66kOXjJdL5HISET06K/EHD+JXuH
         PR/fnYjgbi/VpirCnhf5zQ1/VB19tS4ualdX0o7NqzhLM4MalrImLoom4KxrVHu5dYOt
         VqFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf10TBC/bIR6IRDfgp5YfBUy7KPhRo/vIN6d0zNtm6NWlp3ggNH6
	/vltc8g3JUYDYm93BvIzfIo=
X-Google-Smtp-Source: AMsMyM4K7+skJg/AtUpBb7ZtAIcHFG94IkwE0NyGxFFJvWtAUMFdHMzhqBiXCUnY880OUzyXAx4mVw==
X-Received: by 2002:a17:90a:6405:b0:203:6eaa:4999 with SMTP id g5-20020a17090a640500b002036eaa4999mr8322499pjj.8.1665625054312;
        Wed, 12 Oct 2022 18:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8410:0:b0:552:637c:1282 with SMTP id k16-20020a628410000000b00552637c1282ls404769pfd.3.-pod-prod-gmail;
 Wed, 12 Oct 2022 18:37:33 -0700 (PDT)
X-Received: by 2002:a63:7984:0:b0:439:57e4:97a2 with SMTP id u126-20020a637984000000b0043957e497a2mr28455208pgc.191.1665625053462;
        Wed, 12 Oct 2022 18:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665625053; cv=none;
        d=google.com; s=arc-20160816;
        b=QTWDm+FOqkYYS/iKfl0x6+827dmiHOVLBW6vyrD3JdQYRXhix1Mowvu+2agzR2xgua
         ZJFdiHuRevmTOGK0IlbBITxgpmrEL1ynkeUaYq13pq83tuG3GrVjkI3R7F4lBfvF2RJV
         cjFbmZTWrcxSM/wLM3vYE7ywAPCKM92JsCaNo0enPYSJNRFWpjG/8wHU61lVbrpSrO86
         DaVuf8671g5JiLa+Z91UrY1XEt9V+NF6xKpu3W4o5MnRpJ5pj18LYnIw7p+kA5bC6IT4
         eGsahFJ6UW1nzsw19hHJwhFuZslMwTjyPrnhBmxjW6YM8rrzoGo2yUx/rpIw0THBjSm1
         8l6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=c2YwssGIaPysLPcR20mrskERCj5dzMDhD63/1J4p7RU=;
        b=WLv+IdnleenwiAJoy6x8RdtFZVxx+NRZJVVrs9XgCwdkdaAOPi9aiGF1ejz1Op/Hi/
         IXBdp2+HWKvA+esixy0wMsGrpPN+7jSn8PYgvdPiVA29Qhr0G4yW0fus6pK2fHUpV+EV
         PhxO9hm1uuK31o9vyVQbCj28DsXg7ZvzdTdk8lg4kErVU1VISfvOefiEY4KPdpyFCUTI
         MXvtn3mLr9BOUTKXWC9uZxDoafx+gj0nxYzbQO0LRivYEC6S/C1/mzqKvbo/tQA4GXGw
         GTNiSliWAqjaxquzb3GC4RYv6WzwbbW4HXTdufIqH9jIQTv+xdcFXfTaEsEp+btpQjgn
         xkVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.15 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0015.hostedemail.com. [216.40.44.15])
        by gmr-mx.google.com with ESMTPS id d2-20020a17090a8d8200b002025f077b2csi169445pjo.1.2022.10.12.18.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Oct 2022 18:37:33 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.15 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.15;
Received: from omf20.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay02.hostedemail.com (Postfix) with ESMTP id 640C9120237;
	Thu, 13 Oct 2022 01:37:28 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf20.hostedemail.com (Postfix) with ESMTPA id 56EDD20026;
	Thu, 13 Oct 2022 01:37:01 +0000 (UTC)
Message-ID: <3f527ec95a12135eb40f5f2d156a2954feb7fbfe.camel@perches.com>
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
From: Joe Perches <joe@perches.com>
To: David Laight <David.Laight@ACULAB.COM>, "Jason A. Donenfeld"
 <Jason@zx2c4.com>, "linux-kernel@vger.kernel.org"
 <linux-kernel@vger.kernel.org>
Cc: "linux-fbdev@vger.kernel.org" <linux-fbdev@vger.kernel.org>, 
 "linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>,
 "linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
 "dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,  "linux-sctp@vger.kernel.org"
 <linux-sctp@vger.kernel.org>, "target-devel@vger.kernel.org"
 <target-devel@vger.kernel.org>, "linux-mtd@lists.infradead.org"
 <linux-mtd@lists.infradead.org>, "linux-stm32@st-md-mailman.stormreply.com"
 <linux-stm32@st-md-mailman.stormreply.com>, "drbd-dev@lists.linbit.com"
 <drbd-dev@lists.linbit.com>, "dev@openvswitch.org" <dev@openvswitch.org>, 
 "rds-devel@oss.oracle.com" <rds-devel@oss.oracle.com>,
 "linux-scsi@vger.kernel.org" <linux-scsi@vger.kernel.org>,
 "dccp@vger.kernel.org" <dccp@vger.kernel.org>, 
 "linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "lvs-devel@vger.kernel.org" <lvs-devel@vger.kernel.org>,
 "SHA-cyfmac-dev-list@infineon.com" <SHA-cyfmac-dev-list@infineon.com>,
 "coreteam@netfilter.org" <coreteam@netfilter.org>,
 "tipc-discussion@lists.sourceforge.net"
 <tipc-discussion@lists.sourceforge.net>, "linux-ext4@vger.kernel.org"
 <linux-ext4@vger.kernel.org>, "linux-media@vger.kernel.org"
 <linux-media@vger.kernel.org>, "linux-actions@lists.infradead.org"
 <linux-actions@lists.infradead.org>, "linux-nfs@vger.kernel.org"
 <linux-nfs@vger.kernel.org>, "linux-block@vger.kernel.org"
 <linux-block@vger.kernel.org>, "dmaengine@vger.kernel.org"
 <dmaengine@vger.kernel.org>, "linux-nvme@lists.infradead.org"
 <linux-nvme@lists.infradead.org>, "linux-hams@vger.kernel.org"
 <linux-hams@vger.kernel.org>, "ceph-devel@vger.kernel.org"
 <ceph-devel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>, "cake@lists.bufferbloat.net"
 <cake@lists.bufferbloat.net>, "brcm80211-dev-list.pdl@broadcom.com"
 <brcm80211-dev-list.pdl@broadcom.com>, "linux-raid@vger.kernel.org"
 <linux-raid@vger.kernel.org>, "netdev@vger.kernel.org"
 <netdev@vger.kernel.org>,  "linux-usb@vger.kernel.org"
 <linux-usb@vger.kernel.org>, "linux-mmc@vger.kernel.org"
 <linux-mmc@vger.kernel.org>, "linux-f2fs-devel@lists.sourceforge.net"
 <linux-f2fs-devel@lists.sourceforge.net>, "linux-xfs@vger.kernel.org"
 <linux-xfs@vger.kernel.org>, "netfilter-devel@vger.kernel.org"
 <netfilter-devel@vger.kernel.org>, "linux-crypto@vger.kernel.org"
 <linux-crypto@vger.kernel.org>, "linux-fsdevel@vger.kernel.org"
 <linux-fsdevel@vger.kernel.org>, "linuxppc-dev@lists.ozlabs.org"
 <linuxppc-dev@lists.ozlabs.org>
Date: Wed, 12 Oct 2022 18:37:11 -0700
In-Reply-To: <d45bd258e033453b85a137112e7694e1@AcuMS.aculab.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
	 <20221005214844.2699-4-Jason@zx2c4.com>
	 <f8ad3ba44d28dec1a5f7626b82c5e9c2aeefa729.camel@perches.com>
	 <d45bd258e033453b85a137112e7694e1@AcuMS.aculab.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4 (3.44.4-2.fc36)
MIME-Version: 1.0
X-Spam-Status: No, score=0.88
X-Stat-Signature: jmxt1u5agdpi9w76hr4tp6uotie3p373
X-Rspamd-Server: rspamout03
X-Rspamd-Queue-Id: 56EDD20026
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX18KEIRmyyr9pSEavQqF5X0dTzAEITyiJq4=
X-HE-Tag: 1665625021-540494
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.15 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Wed, 2022-10-12 at 21:29 +0000, David Laight wrote:
> From: Joe Perches
> > Sent: 12 October 2022 20:17
> > 
> > On Wed, 2022-10-05 at 23:48 +0200, Jason A. Donenfeld wrote:
> > > The prandom_u32() function has been a deprecated inline wrapper around
> > > get_random_u32() for several releases now, and compiles down to the
> > > exact same code. Replace the deprecated wrapper with a direct call to
> > > the real function.
> > []
> > > diff --git a/drivers/infiniband/hw/cxgb4/cm.c b/drivers/infiniband/hw/cxgb4/cm.c
> > []
> > > @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
> > >  				   &ep->com.remote_addr;
> > >  	int ret;
> > >  	enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> > > -	u32 isn = (prandom_u32() & ~7UL) - 1;
> > > +	u32 isn = (get_random_u32() & ~7UL) - 1;
> > 
> > trivia:
> > 
> > There are somewhat odd size mismatches here.
> > 
> > I had to think a tiny bit if random() returned a value from 0 to 7
> > and was promoted to a 64 bit value then truncated to 32 bit.
> > 
> > Perhaps these would be clearer as ~7U and not ~7UL
> 
> That makes no difference - the compiler will generate the same code.

True, more or less.  It's more a question for the reader.

> The real question is WTF is the code doing?

True.

> The '& ~7u' clears the bottom 3 bits.
> The '- 1' then sets the bottom 3 bits and decrements the
> (random) high bits.

Right.

> So is the same as get_random_u32() | 7.

True, it's effectively the same as the upper 29 bits are random
anyway and the bottom 3 bits are always set.

> But I bet the coder had something else in mind.

Likely.

And it was also likely copy/pasted a few times.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f527ec95a12135eb40f5f2d156a2954feb7fbfe.camel%40perches.com.
