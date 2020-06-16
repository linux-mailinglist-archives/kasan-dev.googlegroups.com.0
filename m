Return-Path: <kasan-dev+bncBCPILY4NUAFBBZWBUT3QKGQEE2KAFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 550A91FBF25
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 21:43:35 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id p11sf7419uaq.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 12:43:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592336614; cv=pass;
        d=google.com; s=arc-20160816;
        b=aYEUgp7U9SgCKXCVj4TIXTzQqJwNCid22WVTufcTin8IAc+E/qP++kSaSSBHNfNpzI
         0ChjzmvEP3wMt24PyYMzQ4Rb4IYCkwrajXKQdajlNr4VUjs3H0s1eINhOd3gtpidEEFc
         kjundrNDt7dGtmjEbbE3YH4tA2cV/n3/ZC9AvVbT38NpnBeGzZxdbctWG2mmgn2kSWpb
         kwIYuz3CiXVH949OeckB8Xcb8MXctVFtNgGophnL+Dt2JapA7SsvpEEbfglUNOjnrYFi
         /EwqBodUCIrhZ3Sg7pn/eSdVSg48T9RJMXQMAXN3lckSrQdB8VTOpg/IJJs9PklsRFcp
         y0jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=TgegRLQuqNo9msVKay47z4jww+Q/7maHOcv8rfiSCSA=;
        b=NnBTLJe7v08Vx0O1fhPbJNhHbwbR+WcSocq57ApiAH1A5WpqM9E5jqyIfGG+MGqkqx
         bdQ0i+0LZ0g5yyj/Bwit/8RpGiH3wlNhzQvj4mxQ/Zjfdb9ryvfsQnSLisEuPeaSUq0j
         n5Q1F3IDPpVMb05ZSE/lXNq6J20DQymlS7v0jtvUl7QE2n3wsVvVOMHjHDauDmanh1s+
         Q8EPYtBHqmxr6RukvhGQwDQ3Yk7myTVILSv4woWWcj5FKUF1GYp47hJTZMn3d6kIgPBI
         Fg0FkiLqq961O9t1dSCC0lvtlctcGg5swSpAjPhmP7NWeffgA9ENP1Rqic5CR1yQwiDs
         mCGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="XoScRIB/";
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgegRLQuqNo9msVKay47z4jww+Q/7maHOcv8rfiSCSA=;
        b=fsjaTAcONAjIvpSQmIzLsqrgdw2r04A4tjRUh5udQiWakEcE1w/XiPitjguMbEGnt/
         G6+36fiDEfUoJqUwsVEpB0ddYmQoK63NQNaQpR1BLxiK0AMqaRKeHJ8tsTaMEgVd4/LK
         M+7Ov/htns/lvTlRaB/g6ZlkR/Jl0c1AsdYgFKz8Hu/1ePSgAgto5FwU3NTSDvrEDwhO
         1eD58asegYpy2Rs3aldukogQ8CuSKHgEf9O1pqoUiHG3Bon9n6OHNpLM5rt31IVPnRKo
         osFFdq0LpRRiIpqmIL4yb4A18fcQ5DqEVWFXm4x5ur94ckRF/WL07/ar2EKiyD94JdS5
         F6fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgegRLQuqNo9msVKay47z4jww+Q/7maHOcv8rfiSCSA=;
        b=kXlZWFPd39mzqm416FnEByZRUec4DXnwhyV/ZDZmEkPSUzOXzrNsSUWePXpa4XNZ/D
         aTxlDS10gt130Gu9Cc7/f3Wc7+tJ/49C8ArYxBoREo/Eftho87Nkk+yC8/dMwxKEIDH1
         E0oI+b2LW2rJZUilQ4zqiagdoBtE0R4Vh3OILHYljb/saJgoGnumOHvAjPWSF3ht4A1i
         Gdlb2ca3quucJfp0yYfJoYC7MuwpjOVBpfyLZEvvdXHbQCmxuJgoqDHuTourr7VPC54O
         k+R46iDY4b3QuwGrPvwYdOUtZr4s/KS0X4Rioqmtv8IUl/Gx3pfGmT7nSdhXPsumwx6Z
         oHrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328kEqZCs4w+GNOF/8/knvLUABrCL5rHPHaxu7GdtURRBFEB6uz
	lFSqksos+Qz0q3r6QdY15UI=
X-Google-Smtp-Source: ABdhPJxSyW7kyxsRWqDc2Os91qmaABBvL5gyBCN6eP7RXnbEc4YF14JKW0IyUrLBBNKwRJjdziZdbQ==
X-Received: by 2002:a05:6122:1054:: with SMTP id z20mr3135081vkn.80.1592336614079;
        Tue, 16 Jun 2020 12:43:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2593:: with SMTP id l141ls837258vkl.4.gmail; Tue, 16 Jun
 2020 12:43:33 -0700 (PDT)
X-Received: by 2002:a05:6122:31a:: with SMTP id c26mr3218346vko.71.1592336613701;
        Tue, 16 Jun 2020 12:43:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592336613; cv=none;
        d=google.com; s=arc-20160816;
        b=NbKa24OjwxebX3u821lK/USvyfc0YZS6y+xxvpMQmSYRYcHcA5EEYrIEwvOPGAAJqB
         kDorXsT83flUKX1HLKcjDdovHySY4huedMUEOQIbaCO+UTmsEfRDx7Pd7iEPM6UQUYHm
         jjkw7NTvMjPxEpVVbcG+XbejdSIFlnLk9tPf6eN2y9K42gP2/rTc1YuFt16CXP0u88Rb
         cNkS/SW3Y3EsynWiSZ+nglcl7dA/dtZb8/E4v9ckSq/nJBMt8gr/Q2C0NJftSmkwIG1h
         3uJy02iiJhzySV4AbJ2AzKZocO0GLferZG+IIJDE9q0k+hDn+Z8C0dOlgTHNqzbB3RSw
         oPqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=7Z6fHUpD/YKa1+K4csbSQ8hpcds1t8FVRWhxbaMjfP4=;
        b=hAEBA/tGaTyavDVQV8C0Hriy0uNdrkkITWVK14HtxDVmx3hiGXVgOZ4fTcfofXPbgm
         W0bq14KD8fEQ3amNCv4E15OJwe2nCCR//GMRXI0S9YWrvmU6/MAjbjKu2oZ8Zqu0SyIC
         6xu3icwBNAmkD03QwAQbTEAJwb1IiHKh6sXn9VN2mmdYWtmRXvkw+/bBoUhE/yQSQ+LE
         y2Om6oRySYji2Q5Tw8QgIGQEzf8uxL6r7BbEvaU0zwCIz/D5GqNkE9zqI2K2TpYlWBT2
         G28D6d9oNhfuTffp9eT6fMcHJ/lPhuxTM/zYj4md0/EI5+UI0OB2Stc9Tv9DyUd28BPf
         YGUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="XoScRIB/";
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id y7si161471vko.5.2020.06.16.12.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 12:43:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-144-TJgrp6WMNr--nG8NkXkVIQ-1; Tue, 16 Jun 2020 15:43:29 -0400
X-MC-Unique: TJgrp6WMNr--nG8NkXkVIQ-1
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.phx2.redhat.com [10.5.11.16])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 0BAEEE91A;
	Tue, 16 Jun 2020 19:43:23 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 72FAE5C1BD;
	Tue, 16 Jun 2020 19:43:17 +0000 (UTC)
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Joe Perches <joe@perches.com>, Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Matthew Wilcox <willy@infradead.org>, David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Dan Carpenter <dan.carpenter@oracle.com>, David Sterba <dsterba@suse.cz>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
 linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
 linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
 linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <5c70746c-ecfc-316f-f1ff-ab432cf9f32d@redhat.com>
Date: Tue, 16 Jun 2020 15:43:16 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.16
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="XoScRIB/";
       spf=pass (google.com: domain of longman@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 6/16/20 2:53 PM, Joe Perches wrote:
> On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
>>   v4:
>>    - Break out the memzero_explicit() change as suggested by Dan Carpenter
>>      so that it can be backported to stable.
>>    - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
>>      now as there can be a bit more discussion on what is best. It will be
>>      introduced as a separate patch later on after this one is merged.
> To this larger audience and last week without reply:
> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
>
> Are there _any_ fastpath uses of kfree or vfree?

I am not sure about that, but both of them can be slow.


>
> Many patches have been posted recently to fix mispairings
> of specific types of alloc and free functions.
>
> To eliminate these mispairings at a runtime cost of four
> comparisons, should the kfree/vfree/kvfree/kfree_const
> functions be consolidated into a single kfree?
>
> Something like the below:
>
>     void kfree(const void *addr)
>     {
>     	if (is_kernel_rodata((unsigned long)addr))
>     		return;
>
>     	if (is_vmalloc_addr(addr))
>     		_vfree(addr);
>     	else
>     		_kfree(addr);
>     }
>
is_kernel_rodata() is inlined, but is_vmalloc_addr() isn't. So the 
overhead can be a bit bigger.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c70746c-ecfc-316f-f1ff-ab432cf9f32d%40redhat.com.
