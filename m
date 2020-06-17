Return-Path: <kasan-dev+bncBDY3NC743AGBBTWGVL3QKGQEX3S3MAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 389E11FD95F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 01:12:16 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id r13sf1764516oic.12
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 16:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592435535; cv=pass;
        d=google.com; s=arc-20160816;
        b=VoozWF7IiN+WtSz2FITVvOkEYUz4RCY1Vj/2kQJiFsJRlxxQFeooxF/7wRseiXoQoK
         XTZcTPHBNn94A/veQ0NQMTcxorz35l7feeiWkF1TbvWJTtI+ZofGIPeCrgTKEUrjxSXE
         8W0j7RFqx6lnX/fCZwPo3Zze9d1B19zj7pVUqd96DdoBTQ3OoX81x44qtR+hmSfPpqP0
         dCgpLytRPGEzPKK7Obu4fVrKiU0ZzUQICL17vVV/BG2KEBPF2CArrxvoU3LQjZGZ9eKg
         hxTQUwCsFYqKxfGRhFuYE81rJs+A2eVlLU5TyOUUWFoxo+oBSECwNLYpfQlX8PxKTMdT
         u9GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=S3d6Ik/TWM/wrfJ9Ylmx/N1MFrFRsLZkEL6uRvRdYMY=;
        b=y7HUvghJPwCaFknqYCFxJDQeqj8tL76BDfGK/Sji2BoVkfJpTHrwq400YilaystORI
         1i0y7e1C4aErBvZe31ZjTODr0tJ7qfYzqpUP0voA5+GK661rzaY8s9LP5dxxYaVeExjS
         xbltV+4Ih5p339ylfYfTzxzlnu4cFjHR+CtCZkhhccN0HcWvmDEGaEDNttXaEcS+Phbk
         /MU8PmAZqkytzoowT8qhTHvEvpQdWxPasmpJdIDc7ge0hvCvBffk9XBcxS4RCNemyCCy
         OME6YoYW3F0ulN9GvL3SNQ5De8BE+vT3G3qmTg0XSY2CixaCvE9eJfHxhwhMWJk7eF3n
         yY1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.224 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S3d6Ik/TWM/wrfJ9Ylmx/N1MFrFRsLZkEL6uRvRdYMY=;
        b=pSlgaA72MBRr/j1iAuc/OMd3+NtGmpZ377bfhVdUd4WJKnSWcyqllZdfTyjYWgH83y
         yBbAsirDal3nBBaiGP1iTzmjaVvOOC5uXeKwIQglC/m9nLmcqRqLsFbYBUfeJDet0Jjn
         SvGYCCsGvxv6VRjIXCe9rov8ZpA41sZOGIsAnUjQx/iDh4KY91KVuatU1cPysi9WTK13
         w4VbmixlcL+UgtZ1pVzapoe+ank5klZC0Xb7GMLMgD7nCCTNevwYG073W0/DAZon6W9u
         yWj6SxdPueciLXkO/bUEYBJcGz+la4dje5Ff2vNMVGW4PG1kN0aM3x1FOFN3zQby63dX
         5pTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3d6Ik/TWM/wrfJ9Ylmx/N1MFrFRsLZkEL6uRvRdYMY=;
        b=PDpt0PPW76zXMUwfOC46Fv+cwnWe3wQhm4cDL4OXGHLgsOIZxftwAMc6NLbdyoDysP
         rZBEZRlmWdwOr5vzKQI11Hx6aksPYc/JoUXftxplK5WUNC6hWyczDgY2S8MQotriH6Ib
         EujQqbTKjTkjdaClW8sire11DN8tytMGlYf3fVioFVbxbO3nga++DeijSlSOQlxw8LUA
         3BTTKinBt6P6dQ89dPyKL4bk828oUPmHdnXZg+wlBydKLw1O8cOfzILjZqQ6FlWbWcHQ
         GpHy30YfwaCMu73TFwUc+NayE+T+2fboEpGtda9pLuhySJz6pso0162sclOLC4SKv8GV
         yPRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531javJXf6oaCwSUanz3WszI1OS21kJGk8EDYwnbIcxig8CJFywu
	EhgZV9pKjgJS60uZOO2h5LY=
X-Google-Smtp-Source: ABdhPJy76vV2WVLFIL3NrFW3RQJifMDWqVu90QifkmKGOhCdcr9jbPlaI1bri7QaI871B8DJFKS78A==
X-Received: by 2002:aca:f255:: with SMTP id q82mr804979oih.153.1592435534892;
        Wed, 17 Jun 2020 16:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1db7:: with SMTP id z23ls871389oti.9.gmail; Wed, 17
 Jun 2020 16:12:14 -0700 (PDT)
X-Received: by 2002:a05:6830:12c1:: with SMTP id a1mr1127069otq.123.1592435534517;
        Wed, 17 Jun 2020 16:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592435534; cv=none;
        d=google.com; s=arc-20160816;
        b=f/eXW6wPr5kUNFXiuq3a0rLHFMqNjScWTgsVg3c2+AubhZE1h1DUNEfVZAWPVmhYfe
         anyChNW75V3ZedpcA+r8EV1aSnt+49Ds5SO4KfUaTdemFohrMRPvgBAKF06hCs7H05r1
         emap9j0gBt9LQXMh/2tK2gcRIKYwmhNbdRxrZ2nNH/KoZSEzP8igfWn1RR4cOulmFZLF
         h02ls/c3LV8h8b3LjBplYWpHGfli/HdLST5VpujjsByZ+CnaXG/O5KyLnoqHJjRaZ9F4
         mAmRLE4K9XteDUkdCcrY/zglHagY1RItvdIEie6n/kNDIhH6IePabSYiAT/0GdvFLQmU
         /YfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=recntTsl370RwohBSKRBmscfTG0mHqoeOfj6Z1LB+ZI=;
        b=KvzjQMG7imMBMMU8p+En9KAYuOsd1nI+Cx8yT3YXCgUW+SUsZo4WnikBGl6x3Jix4B
         S2Fb1Vnze5vw6pAjW3U5Xe9IJQYD1vfCQBEkBVXdPWu2ub1GGfxHd4R2wvijLD9fjWRE
         fEM6bJBMIfL8zog3loy3AXo2Yvls7zi0maeQtGENwfNSO9sI1+n6D8b7xYg2lURgTWhy
         XTCfzwE/xnU7CTyuLlfXpcdCl7uWY+AapTPYZXCf0XbnSYaLMGX/hkmLJ71H5RdcYja4
         I9xvSI4ZsxhT0uK88Fpodol64S9QDQnkzqdvA0Br7teyAKn993cDRhBs97Djn291GjL1
         pIOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.224 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0224.hostedemail.com. [216.40.44.224])
        by gmr-mx.google.com with ESMTPS id h13si128007otk.1.2020.06.17.16.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 16:12:14 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.224 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.224;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay07.hostedemail.com (Postfix) with ESMTP id C6BF8181D330D;
	Wed, 17 Jun 2020 23:12:13 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 50,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:800:965:966:967:968:973:982:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1541:1593:1594:1711:1730:1747:1777:1792:2194:2196:2198:2199:2200:2201:2393:2525:2561:2564:2682:2685:2693:2828:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3353:3622:3865:3866:3867:3868:3870:3871:3872:3874:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4321:4385:4390:4395:5007:6248:6691:6742:6743:7875:7903:9025:9108:10004:10400:10848:11232:11658:11914:12043:12048:12050:12297:12438:12555:12740:12760:12895:13069:13095:13311:13357:13439:14096:14097:14180:14181:14659:14721:14777:14915:21080:21433:21451:21627:21788:21811:30054:30070:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:3,LUA_SUMMARY:none
X-HE-Tag: anger66_3706ec726e0b
X-Filterd-Recvd-Size: 3931
Received: from XPS-9350.home (unknown [47.151.133.149])
	(Authenticated sender: joe@perches.com)
	by omf11.hostedemail.com (Postfix) with ESMTPA;
	Wed, 17 Jun 2020 23:12:07 +0000 (UTC)
Message-ID: <38c5745d14cff75fe264a3bc61d19fd837baf7ad.camel@perches.com>
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to
 kfree_sensitive()
From: Joe Perches <joe@perches.com>
To: Denis Efremov <efremov@ispras.ru>, Waiman Long <longman@redhat.com>, 
 Andrew Morton <akpm@linux-foundation.org>, David Howells
 <dhowells@redhat.com>, Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Matthew Wilcox
 <willy@infradead.org>, David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Dan Carpenter <dan.carpenter@oracle.com>, David Sterba <dsterba@suse.cz>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org,  linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org,  linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, 
 linux-amlogic@lists.infradead.org, linux-mediatek@lists.infradead.org, 
 linuxppc-dev@lists.ozlabs.org, virtualization@lists.linux-foundation.org, 
 netdev@vger.kernel.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com,  linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org,  linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org,  linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org,  linux-fscrypt@vger.kernel.org,
 ecryptfs@vger.kernel.org,  kasan-dev@googlegroups.com,
 linux-bluetooth@vger.kernel.org,  linux-wpan@vger.kernel.org,
 linux-sctp@vger.kernel.org,  linux-nfs@vger.kernel.org,
 tipc-discussion@lists.sourceforge.net, 
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
Date: Wed, 17 Jun 2020 16:12:06 -0700
In-Reply-To: <17e4fede-bab0-d93c-6964-69decc889d7d@ispras.ru>
References: <20200616015718.7812-1-longman@redhat.com>
	 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
	 <17e4fede-bab0-d93c-6964-69decc889d7d@ispras.ru>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.2-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.224 is neither permitted nor denied by best guess
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

On Thu, 2020-06-18 at 00:31 +0300, Denis Efremov wrote:
> 
> On 6/16/20 9:53 PM, Joe Perches wrote:
> > On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
> > >  v4:
> > >   - Break out the memzero_explicit() change as suggested by Dan Carpenter
> > >     so that it can be backported to stable.
> > >   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
> > >     now as there can be a bit more discussion on what is best. It will be
> > >     introduced as a separate patch later on after this one is merged.
> > 
> > To this larger audience and last week without reply:
> > https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> > 
> > Are there _any_ fastpath uses of kfree or vfree?
> > 
> > Many patches have been posted recently to fix mispairings
> > of specific types of alloc and free functions.
> 
> I've prepared a coccinelle script to highlight these mispairings in a function
> a couple of days ago: https://lkml.org/lkml/2020/6/5/953
> I've listed all the fixes in the commit message. 
> 
> Not so many mispairings actually, and most of them are harmless like:
> kmalloc(E) -> kvfree(E)
> 
> However, coccinelle script can't detect cross-functions mispairings, i.e.
> allocation in one function, free in another funtion.

Hey Denis, thanks for those patches.

If possible, it's probably better to not require these pairings
and use a single standard kfree/free function.

Given the existing ifs in kfree in slab/slob/slub, it seems
likely that adding a few more wouldn't have much impact.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38c5745d14cff75fe264a3bc61d19fd837baf7ad.camel%40perches.com.
