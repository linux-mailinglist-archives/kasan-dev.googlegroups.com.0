Return-Path: <kasan-dev+bncBDY3NC743AGBBO5FTSNAMGQEGTYOFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F0705FCB61
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 21:17:16 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id b13-20020ac87fcd000000b0035cbe5d58afsf11836708qtk.9
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 12:17:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665602235; cv=pass;
        d=google.com; s=arc-20160816;
        b=qaQs3gKGKOtfcbBqXN0u/L9sNzYpxA/ltMm+EIYnIQBmydzJBruI1/TPI4Y+Z1Mlks
         OPGnV8LeKDAlhjnNF273Cca2R+tUx2OObpOzQy+KvQYPR0sWPuFuRW19NIq/mzs6nOO0
         1iR9hip07DdyAcqENt+7X9GeyiCY37bVQ9JUNXibJJUx3ncqh7NJiYhNwzqWP9FQuVP6
         Lh+O4afEDJd5SJcRjWyADdX9M6H/m8hyu/1Lg3YtJN+162DGd3995qAug7jr5vLK8+F+
         YFz/pfRXkMuLCtFnEgLI6w8nLbS2d3xcCWWGaj7kiH3qlLUAvXUUvme5DPayGnJj7mEE
         agPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Pfxk2ZRTIatsX4TngDWYEx362VUsRK4n539qUVjsFKw=;
        b=ch5S1HR1B72ZwPXw4O8RzOkdzGda8r2hCeEL1X2ghufHlku19I+pH8w84ojByIziIZ
         71yD4ig3gW9fcTKBsBc6GeZ3/wCBfwbU+lsblgaqhMUtADES0R00gWQbofbIhX9G/bx5
         J1zsUBZxqq021P300Q1drWjODEV9Dw8w3bvUYysBnTaFWGs1m8X+jtl1YUe7DCjXv5t8
         hIbKUvHcU5BhU3Q7GzXBHCwgMMGTV7AbFpKJHaYm5lqB1XQo4eKcnTDsRskIhDjunW6t
         cyDqg0h2aDP845VDUzKj+rahhXSBUOyFQPs1lsRUJN42K3SweiqtX3f/085CIrAGWHU8
         5v/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pfxk2ZRTIatsX4TngDWYEx362VUsRK4n539qUVjsFKw=;
        b=DfNR8cJxoCFsc1WN8UF+xIJAlJaHMFQBR0N3W/Q+nKgBZm+Rh0+ctKdJgn+Jw/NnHR
         Q3qfif/mSPfENBpmnj0wPSOYzDK1xwExE5rhMn92qrHAaCEbu8g0ItcjGieZlzib0NxS
         PUJTzT+9lCBBALXg5qou29IFWsyaz80mMwE+5U0IOep48T9kacudPOW9g1CyZjrJWY4c
         uWGh2UETBfdmbyIKA1yuklYcx1KOJBmFPmFwWow2Dkhe8lIglrkrAwtvNCVLzbjPRBr/
         avWW01/bTpizZUNGhcd9aNtP2Put04lSJemqzFeUimHSxxE3hmn7KnHO+VlfpWXzuNVF
         7zkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pfxk2ZRTIatsX4TngDWYEx362VUsRK4n539qUVjsFKw=;
        b=YE9trBAiZr8lScR2mmV7uFrySOVX03D+FZLNoQR4HNITdUxBTggqVeseXr2+IphANX
         ljBCfKmD1/Ect7pQTKwoLzO8dBTNmJ07p10igYD16kl9/0jW2b2ncGOZ18dEa1N32hHE
         XAHsT1ucZJhRwcg9F8U7ttkSfGus0Br6owzpyESNaRKK/yV3ZWbpcu2Gcc6I0kQsAGiI
         86pMqte+SGI7MH8UpmhyRadzNlGHlO/3uHTbUA3R87/NYunOnvheU7MKrqJ//FgHg00O
         5BxZLK/OiC4VMCruth5iCxMUZlDWee0hxZeqVvBGkuducZxlNn5T3uwWpBCEGvlQkkxd
         txIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2+7hbln8Spovw4gPMPk+L0Eyx2COKj81QAFS0vz7pAXdputKHW
	34O+k9/nwM4PhYGWoguEmBc=
X-Google-Smtp-Source: AMsMyM6wp76n1I8Kp5TVWOdt+mB4wy0NlCycB7MtN6gSjfJv42+L8eZT0XeG1RYgJUY0B9VJ51/qcg==
X-Received: by 2002:a05:6214:501e:b0:4b3:d08f:b58c with SMTP id jo30-20020a056214501e00b004b3d08fb58cmr21088558qvb.90.1665602235172;
        Wed, 12 Oct 2022 12:17:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:13ec:b0:6ec:5250:5785 with SMTP id
 h12-20020a05620a13ec00b006ec52505785ls7178555qkl.3.-pod-prod-gmail; Wed, 12
 Oct 2022 12:17:14 -0700 (PDT)
X-Received: by 2002:ae9:e718:0:b0:6ee:8335:4191 with SMTP id m24-20020ae9e718000000b006ee83354191mr6535475qka.83.1665602234709;
        Wed, 12 Oct 2022 12:17:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665602234; cv=none;
        d=google.com; s=arc-20160816;
        b=i1SqvlKa/a9zlbL8fmvTqJNYCx0KWUyemR9zTlGivXqjpDRGhsbiMf79Ff7aONkOkt
         JBsqfah63FaHM/30jv8Llcw8LiCMlllwwCJLrKz2sHZAKQ40WEnOy4lGZEV94Z/RBN4E
         LzK7gOB0Oy2eJq9ykpRNFx9No+6IGeHZaCfO7/6s3+yv6OZLBnbhuETapsCwsc7t3qVn
         bClVd/6BJWa9lSAiNsYXLl/XtrEM/LUJpq+ks7FFh/SzPWznMaBeqABXStZX84+KY/EH
         M7U37INEZhgORO6JmWVCQt/t2yFIPYIFzcLeGmql47nsGYKmy30FRxjSDmtRIOwqorUn
         QeEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=izjM8/fBCeAKrIyQwhR5+E8ak9TExQ8d3Dqs3aJLPmQ=;
        b=YAO+kG66VGU6yTv6cLehKd9/mPJidBkphkPVbJ+OShLPIMiGK4RPdwI49kkljcbAtM
         7twDhem9nYOzJGO4C2qgzEbLtzTrTXUnO9iiTN+ikvJu54UlZkRXLSisfCdUukW8tpwy
         pIuQeBnYkdgxVcycAqYzC/YhxMOq/Ki/YmxUhfAlw3Aqu3UAfg9JCTRMEVf9J9owdzK9
         rcTRy+9QnkTwKID/jP+IbEjvMG0apLm6P/WnP38kCssumVkejBC+zsFEo1omdl1v4gFv
         ZLRjJHpR2xWfruQDOk0g+GYXDJZrsQQ0F2nU57fnbR9neGarx4mlMxWZor98PnCSMnMg
         6PKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0016.hostedemail.com. [216.40.44.16])
        by gmr-mx.google.com with ESMTPS id z7-20020ae9c107000000b006ec80b54a06si327219qki.1.2022.10.12.12.17.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Oct 2022 12:17:14 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.16 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.16;
Received: from omf12.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay01.hostedemail.com (Postfix) with ESMTP id 2096E1C6C41;
	Wed, 12 Oct 2022 19:17:09 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf12.hostedemail.com (Postfix) with ESMTPA id AB9FC17;
	Wed, 12 Oct 2022 19:16:43 +0000 (UTC)
Message-ID: <f8ad3ba44d28dec1a5f7626b82c5e9c2aeefa729.camel@perches.com>
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
From: Joe Perches <joe@perches.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, linux-kernel@vger.kernel.org
Cc: brcm80211-dev-list.pdl@broadcom.com, cake@lists.bufferbloat.net, 
 ceph-devel@vger.kernel.org, coreteam@netfilter.org, dccp@vger.kernel.org, 
 dev@openvswitch.org, dmaengine@vger.kernel.org, drbd-dev@lists.linbit.com, 
 dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com, 
 linux-actions@lists.infradead.org, linux-arm-kernel@lists.infradead.org, 
 linux-block@vger.kernel.org, linux-crypto@vger.kernel.org, 
 linux-doc@vger.kernel.org, linux-ext4@vger.kernel.org, 
 linux-f2fs-devel@lists.sourceforge.net, linux-fbdev@vger.kernel.org, 
 linux-fsdevel@vger.kernel.org, linux-hams@vger.kernel.org, 
 linux-media@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org,
  linux-mtd@lists.infradead.org, linux-nfs@vger.kernel.org, 
 linux-nvme@lists.infradead.org, linux-raid@vger.kernel.org, 
 linux-rdma@vger.kernel.org, linux-scsi@vger.kernel.org, 
 linux-sctp@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
 linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org, 
 linux-xfs@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
 lvs-devel@vger.kernel.org, netdev@vger.kernel.org, 
 netfilter-devel@vger.kernel.org, rds-devel@oss.oracle.com, 
 SHA-cyfmac-dev-list@infineon.com, target-devel@vger.kernel.org, 
 tipc-discussion@lists.sourceforge.net
Date: Wed, 12 Oct 2022 12:16:53 -0700
In-Reply-To: <20221005214844.2699-4-Jason@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
	 <20221005214844.2699-4-Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4 (3.44.4-2.fc36)
MIME-Version: 1.0
X-Spam-Status: No, score=1.40
X-Stat-Signature: c3d78nppyrywoyngway5d943fw3wwtdu
X-Rspamd-Server: rspamout03
X-Rspamd-Queue-Id: AB9FC17
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX1/Qw27OeRP8/mQW0Su38d7rwhSo1NO9QCw=
X-HE-Tag: 1665602203-428634
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.16 is neither permitted nor denied by best guess
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

On Wed, 2022-10-05 at 23:48 +0200, Jason A. Donenfeld wrote:
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
[]
> diff --git a/drivers/infiniband/hw/cxgb4/cm.c b/drivers/infiniband/hw/cxgb4/cm.c
[]
> @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
>  				   &ep->com.remote_addr;
>  	int ret;
>  	enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> -	u32 isn = (prandom_u32() & ~7UL) - 1;
> +	u32 isn = (get_random_u32() & ~7UL) - 1;

trivia:

There are somewhat odd size mismatches here.

I had to think a tiny bit if random() returned a value from 0 to 7
and was promoted to a 64 bit value then truncated to 32 bit.

Perhaps these would be clearer as ~7U and not ~7UL

>  	struct net_device *netdev;
>  	u64 params;
>  
> @@ -2469,7 +2469,7 @@ static int accept_cr(struct c4iw_ep *ep, struct sk_buff *skb,
>  	}
>  
>  	if (!is_t4(adapter_type)) {
> -		u32 isn = (prandom_u32() & ~7UL) - 1;
> +		u32 isn = (get_random_u32() & ~7UL) - 1;

etc...

drivers/infiniband/hw/cxgb4/cm.c:	u32 isn = (prandom_u32() & ~7UL) - 1;
drivers/infiniband/hw/cxgb4/cm.c:		u32 isn = (prandom_u32() & ~7UL) - 1;
drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c:	rpl5->iss = cpu_to_be32((prandom_u32() & ~7UL) - 1);
drivers/scsi/cxgbi/cxgb4i/cxgb4i.c:		u32 isn = (prandom_u32() & ~7UL) - 1;
drivers/scsi/cxgbi/cxgb4i/cxgb4i.c:		u32 isn = (prandom_u32() & ~7UL) - 1;
drivers/target/iscsi/cxgbit/cxgbit_cm.c:	rpl5->iss = cpu_to_be32((prandom_u32() & ~7UL) - 1);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f8ad3ba44d28dec1a5f7626b82c5e9c2aeefa729.camel%40perches.com.
