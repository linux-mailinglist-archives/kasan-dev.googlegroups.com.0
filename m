Return-Path: <kasan-dev+bncBCPILY4NUAFBBEEHUP3QKGQEQDEUN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 399F71FB188
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 15:05:21 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id l11sf14467356ils.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 06:05:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592312720; cv=pass;
        d=google.com; s=arc-20160816;
        b=QQ2gLITJyqnCANMhCIvSOrycGMGRDAaCNNGqlZuF86/86ozBY1t11N4H9us8VZTdG5
         Jy0NwFF2SG8RD/uXmNd1oR7CRM1ZT3qo+eLS6do7gEqknuACuPSEGiqs+MNKlHyCtajW
         CQudd1pOlZL+drjjcRxT7G90IfqKGkDm7kRKBgybDKoFc719Bwznp7PQbuMi6d3vmJj+
         xtW/0RvHDuK3x/M6nwGWTF/dawvNWwfIMYa4gnPI1fBUQ/nVcjb5mYDDX/iUiKSi2HfT
         BK6uUaxwnwIh+lc4Xu5WgjodyUnNEeNDsf/CBIPOc7e7lC/0up7urUGlSB+JsQh48zmR
         lfzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=cYNVRMAAg81Lk09asrAizvDAkaBOIvxflBtiJRyNfVo=;
        b=eCG/DMinXF66lgluTDOqEjQraBXkfK1VQkhsOs2H21sPfi+68BMtQURvb6kX050FEe
         93sJ+Q+ysrF30+upbeD4DLO86EREdUPzEIUNuR/uYQ9EXDb217uSH60crTQcFyiFQf5i
         dXU+7nloSy3WqDAf9L+IqHytptaG3QCohtg2MvmjetfOF0FP6yV4eVwBcA9AO/ck88IP
         L9B6CEWKBIQf+IGfAsw/d3kQetscuB4kzlCrXl37D/wc+aAFbmBl6jW+Scht7HPk51pA
         6tM766oQTRStxDOD4somqh31M7VFcG0aU5r82DoCmsT0l2sCKazGVnYXX3TUd4ypZs20
         F7nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DrTWSdc5;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYNVRMAAg81Lk09asrAizvDAkaBOIvxflBtiJRyNfVo=;
        b=emPI048E2Nto39/kgdRwO7MJU8A+tuGR5iBmw1Samlr7U4R3k4i2aWjRriNps6aoVc
         vawQ6sJDcgr+4xlyruux5MP85RebLMKzBPKQ+ZXeo1Nz0JsmX3tnRUwtkpf6BtPCp0vR
         ZwWLy1WkTg7isD5jVdo8yYr7F+/GXkTaU5fkvFpbuJaMsyMf1Ys7TsUPHZmu/9CxkHDL
         EJH8RI6TqYJXpU6AY/U/62ZKICEm5y4SL3pmePxrESSgI5PfK3uEYiCkJRrlKOcxUAvg
         pJXRwwBmNgXiLKgWykXFU7DO/FL1XenhsBLq/0JFI6C9GAb9nQGZ2DdKwWNCBOVknRej
         +abQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYNVRMAAg81Lk09asrAizvDAkaBOIvxflBtiJRyNfVo=;
        b=EHqG12XpblC4FNOn13JBLgZZowyUSFRWXH719gWUFDf4fX15fElDQIq+xpDqgTViJB
         1Bd4+13szWGuk5jOO581QkA7vI+OCKg4DfemTO0f07bHLM1QCEpHrH9vV6OwNrN+jMZC
         qvj8O+e9z+rxhhIoAgjvA8gP87oa24fhbT0BBuhpxoAZ4+XRALDAdmsR+OiFQLshvYJh
         HuDISS3jMF/3AiNtMK8ULh909YSqgvQr2xa8jXARn25zlpC/VWU/h8u1zbQZZSIw5AfO
         slP0Aherl2Ka5KHTdJtasryXvAUmWkb5rIALTsPL3qFZrG63HmX7tQL1f/zvjSQdSnT5
         8QSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IncLINPdTXW82ILR2Vlr99bR2CDZVKFcuwJ8GtLtWvsHb0UZL
	PDzRJ7onHig+n/xR7HDS58o=
X-Google-Smtp-Source: ABdhPJz9sxtJYYLrpQB/7/5fQ+xe4dVJc16XkQ/sUs94W/F4yZY6tfIpcfXFWHXyK6PC6rYpf2ZS+w==
X-Received: by 2002:a92:cf4d:: with SMTP id c13mr2958904ilr.207.1592312720182;
        Tue, 16 Jun 2020 06:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c205:: with SMTP id j5ls4560023ilo.11.gmail; Tue, 16 Jun
 2020 06:05:19 -0700 (PDT)
X-Received: by 2002:a92:2906:: with SMTP id l6mr3100776ilg.105.1592312719859;
        Tue, 16 Jun 2020 06:05:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592312719; cv=none;
        d=google.com; s=arc-20160816;
        b=AlXCBl+dfcd/0lOnf/wflaOqHDlzvU/T63Fucb2yntaGkAPa8LaU0Irx6nVBPlowuU
         mXkukvjq/NA5YY7/j7hHHe6+UoHMCgQxdl/nOWCBQhPahdja5y+ccBTKL2rU6NRa0siH
         94VaNoE6GJMnN8T8mlw0jtjMHJRP+vCuxowLSSBRIEChdRPEZ2jvWHxht/+h05fp+YoM
         7Cb3uWl2j3PZYjENM1/XzZA8T8oQ1JNwjmEoj5KcZITuIYqsooju2Zl6XiFfG5HRr9bk
         oef2/XtpBwqZJSsAa7J/Y12sgTCYlCxDjMo9V832p0cjd6dW7xdBcej2N7IWvB8lJu+t
         5THw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=7nZX/JZoMn+I5qsocsgLqRgQUtpNpbf+EHIybmwJtOc=;
        b=wgv5XRy1WjaNhzvOtdbSN4w2NGvCdWWEYz0Y462u7GcUxRcytGijxRbZBxApEh24nk
         PwgNUWjCPm1obJtM+aB1iBO6QMErRt0jZITtcgllFFye0tv3DXlkXjyFBYLpcgU9phVR
         3rJiaxACqSo7zwXtnGuUovlJEfkgMXe1Mppi9jVhi/pt68lnSpc9KZ5uVclrYkKta525
         snro5UX/EegvgT+Da6WoNfgfqZhuQ6zFLFXFTuNbnfbWgj9GBAnWxdDfwzLjrZ5MZAlX
         OTZWKEbsyrzeMqQ8GSrHzT+2hW34wTe9YJOLjgcyBitaEtur8cX58nnMkZksgZgoWyhc
         B6Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DrTWSdc5;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id x10si1017194ila.3.2020.06.16.06.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 06:05:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-395-9xOyBG-QPzmPq6osX1JXvA-1; Tue, 16 Jun 2020 09:05:14 -0400
X-MC-Unique: 9xOyBG-QPzmPq6osX1JXvA-1
Received: from smtp.corp.redhat.com (int-mx04.intmail.prod.int.phx2.redhat.com [10.5.11.14])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 108C8107B7CB;
	Tue, 16 Jun 2020 13:05:07 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3337D5D9E4;
	Tue, 16 Jun 2020 13:05:01 +0000 (UTC)
Subject: Re: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
To: Eric Biggers <ebiggers@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>,
 Johannes Weiner <hannes@cmpxchg.org>,
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
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org,
 stable@vger.kernel.org
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-2-longman@redhat.com>
 <20200616033035.GB902@sol.localdomain>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <56c2304c-73cc-8f48-d8d0-5dd6c39f33f3@redhat.com>
Date: Tue, 16 Jun 2020 09:05:00 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200616033035.GB902@sol.localdomain>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.14
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DrTWSdc5;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 6/15/20 11:30 PM, Eric Biggers wrote:
> On Mon, Jun 15, 2020 at 09:57:16PM -0400, Waiman Long wrote:
>> The kzfree() function is normally used to clear some sensitive
>> information, like encryption keys, in the buffer before freeing it back
>> to the pool. Memset() is currently used for the buffer clearing. However,
>> it is entirely possible that the compiler may choose to optimize away the
>> memory clearing especially if LTO is being used. To make sure that this
>> optimization will not happen, memzero_explicit(), which is introduced
>> in v3.18, is now used in kzfree() to do the clearing.
>>
>> Fixes: 3ef0e5ba4673 ("slab: introduce kzfree()")
>> Cc: stable@vger.kernel.org
>> Signed-off-by: Waiman Long <longman@redhat.com>
>> ---
>>   mm/slab_common.c | 2 +-
>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index 9e72ba224175..37d48a56431d 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -1726,7 +1726,7 @@ void kzfree(const void *p)
>>   	if (unlikely(ZERO_OR_NULL_PTR(mem)))
>>   		return;
>>   	ks = ksize(mem);
>> -	memset(mem, 0, ks);
>> +	memzero_explicit(mem, ks);
>>   	kfree(mem);
>>   }
>>   EXPORT_SYMBOL(kzfree);
> This is a good change, but the commit message isn't really accurate.  AFAIK, no
> one has found any case where this memset() gets optimized out.  And even with
> LTO, it would be virtually impossible due to all the synchronization and global
> data structures that kfree() uses.  (Remember that this isn't the C standard
> function "free()", so the compiler can't assign it any special meaning.)
> Not to mention that LTO support isn't actually upstream yet.
>
> I still agree with the change, but it might be helpful if the commit message
> were honest that this is really a hardening measure and about properly conveying
> the intent.  As-is this sounds like a critical fix, which might confuse people.

Yes, I agree that the commit log may look a bit scary. How about the 
following:

The kzfree() function is normally used to clear some sensitive
information, like encryption keys, in the buffer before freeing it back
to the pool. Memset() is currently used for buffer clearing. However
unlikely, there is still a non-zero probability that the compiler may
choose to optimize away the memory clearing especially if LTO is being
used in the future. To make sure that this optimization will never
happen, memzero_explicit(), which is introduced in v3.18, is now used
in kzfree() to future-proof it.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56c2304c-73cc-8f48-d8d0-5dd6c39f33f3%40redhat.com.
