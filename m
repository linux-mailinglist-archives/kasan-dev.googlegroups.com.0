Return-Path: <kasan-dev+bncBCPILY4NUAFBBLVCUT3QKGQE4XC6D5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 78E701FBE1A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 20:36:32 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id v15sf10171916pgi.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 11:36:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592332591; cv=pass;
        d=google.com; s=arc-20160816;
        b=kuf6pj8Qqk+tvA/kalfHEqtnQpPCZ3BUpsm+zmNPw+xaO4+XAIkQCfQqmkAPQl0OTT
         f/8hTQO6AfZZpF/2de0EaI3QqIqZ/mntTKNSF2LR0yxWws6R1CB/ppbumdy9ZZOhoPMb
         x231EJa1zXN5djkYB6ywidGq2u3jz0tI3Th995YOLVthgqblwRXoxP9XbJw6MQb6xH29
         /KlLcEIG356CW6faiQ+qE3jBl42lkvI2u+H6bgnbL6woCknQ8DUwbABhDa7ugtEkC64j
         IZBeZQHVj+wwjKwOZg/87NFti3lewsVEeiDOVLzTHBoPmmTGgGVgAqC4sZPIlxYAd7lS
         k4aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=/LYKxoWrDcrTQZrd9SMNTK2bL48wdjMaMumYaqvngZ0=;
        b=jfHnqB4PO2MNOVnRPoC2uKoWJ9OzjHVdQ6RP1bOmMtmqKZbBGVOarRZCVpkwqceTLs
         TwjErJUQ7v4bjKvwXr1NBka/zNGCEF3qGWKv4gLEHWOK13p+zGHw67qd8O1Fq6wqf82f
         NXb6fxqVCv/ffSCCQlM8kzwNtebakc3iHvcvfDSOjbZvTti/B4yYVyA/mUe6sQIn0nBE
         2PSUMMAyr6QIDih+IuPRi0rfHT/OY7n7h14mAx3T0PfqE4xVtf3oCob7bi310VXI/S74
         FXkPxptbBqNtQfEHI7TzokKk7VaZkrvyngHrVCFAn4x5n0KOHPixTRdel3UaVyJzthHH
         uYKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=jC1SVPU+;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/LYKxoWrDcrTQZrd9SMNTK2bL48wdjMaMumYaqvngZ0=;
        b=QotIpekZcugc8RqVavJ5g/3oglGw/7pi/zeMMPVh0LIPL6ooUuUey9wOho9Hy4Eg7F
         OClECfYsQ3rslJWLTQ8K+SZC2MTEKGVfFCEXPuhx9nZqdT2ErCAmqcea8FTHZhPv0knQ
         cYEemCTCJRQm0gQ+OalWwGFvhsZEVo/+BV8zKJuw6zRxGo/2gJYuqI3KI0IWXYGv6IYY
         4Q9yZe2ex3jQzM8GMavdxD6AWKhUq4J+B1Ll0lyyaQq61ZX7wCYAWVYygp9kHTarF35P
         ZpKZO7MV+YN2rOsY6sffgGxALyfcKy590zJ7aGogqRvMl76oqTm5/DN4f91YPaA2BTp8
         PurA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/LYKxoWrDcrTQZrd9SMNTK2bL48wdjMaMumYaqvngZ0=;
        b=YMmuv7RuKJH+rF01cF8rfLpXkgTHtDeQ6opgmFGJ6R3t1B9+ZFtq1QWtFepUimGoby
         LShKY2SMpkOzVg2s6+aaLCuEkufe6Ckn4zgnBwj0uZCzTMuJOblLKbPOQc1YDuxHm6kk
         Mnlh8DVTEO98DP/bZzYNWjTAc1b/yBJe/EJfVNGFOywojoWjO+Y5M4GxuNkNHeYBGl/a
         Yh9pdKykAPqjfEqPhGQ1gj7exALUy+slHlsDX+VBLRt0PZpZZ51IF1Zeb9UudzK/VPbs
         dY8oAq75smVJ+avaDg0xUcdf9LRs46C3wkcOSxrX3IxUvApR6hG9TyCq2kFrFqU9Sgv1
         YHqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PJ4USIhWToqzChNwXFDICyNqgedx56QdG0m4ve+2QZtlsDH4t
	S8DahMPXgcpOQilU9GOmRvU=
X-Google-Smtp-Source: ABdhPJwSolDWtndRo//T/B8hW+02gzwJo6s5ebi4bL5CjiOKw01/sSA/WwbH0HA0aYEfxmoCtCDf2A==
X-Received: by 2002:a65:5302:: with SMTP id m2mr3116066pgq.88.1592332590898;
        Tue, 16 Jun 2020 11:36:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d34b:: with SMTP id l11ls1738558plk.6.gmail; Tue, 16
 Jun 2020 11:36:30 -0700 (PDT)
X-Received: by 2002:a17:902:9e0c:: with SMTP id d12mr3217894plq.197.1592332590474;
        Tue, 16 Jun 2020 11:36:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592332590; cv=none;
        d=google.com; s=arc-20160816;
        b=sQswLFOsGhH+rfrAkxM6Nl8DkgKoA2IiqS/lvZmhfwXdRhy9VkBrTXtQh+UgQjzCHV
         SGjjRZJve0MLWJY1YG5Ji5H7ZWk3GjGYRoTiv+k+oeocqcvvH7uKH+V3iWE53BuptR4O
         dH/NcjxEl/e6ft5MVkXf5cokzdGoZpMAmZn7BbBJfGOnwIC/lXY9DvuFwiX0uHXAteQ5
         ISMPOyGIu39SqkgYKwHrTHwK2fuywy3WTLoYKf/bF5EGaALZLpykjdwpNt+FykPJZcES
         BjRcO9rleLdIDiuv2VVE/Uy99SzMz2XKysnQC0fKDMFDu3aqLntUP9+JcLgk7B5W9IQW
         LrJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=7/6v2jfN6UIDhJeosnSs1R4UAP7mOiLuFVPEnJvGTnM=;
        b=bGcze7ywKg5pFhdQBzbyEmgMpmF+iuPYDsiNq9F9Chc3cCNSCbTzej2qKCiu47yjRH
         pDqgl+hTznptES/ithPPEVLEiLSosUI9R3IY/15aa1xjNqkL35CVUgccVcy4nxsRDHRh
         LsnhYaa75gJq3K+bEGN6hKzSMeEREeGK70SXDq2NTOC4ynFnuI3MQ2IeKSpXqEb1KKug
         FUGdEOhvn0djG5b70XTEYGhGKdiE/WYcPJpuuIC+LZRiYsCO2OKtXXEwUhJ6J5EzlDSZ
         slAqfiB3hzuY7PECj5mL+nhiZr7t1Upvq+Kvi+RPCc4PCZECz8PVMD1rGDHiSFqbAwvO
         ywtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=jC1SVPU+;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id q194si1235358pfq.4.2020.06.16.11.36.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 11:36:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-73-AXrSOJCONRyyvrghDqFtvA-1; Tue, 16 Jun 2020 14:36:27 -0400
X-MC-Unique: AXrSOJCONRyyvrghDqFtvA-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 2578680332A;
	Tue, 16 Jun 2020 18:36:22 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3B77519C71;
	Tue, 16 Jun 2020 18:36:16 +0000 (UTC)
Subject: Re: [PATCH v5 2/2] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>,
 Johannes Weiner <hannes@cmpxchg.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
 linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
 linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
 linux-cifs@vger.kernel.org, linux-fscrypt@vger.kernel.org,
 ecryptfs@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-bluetooth@vger.kernel.org, linux-wpan@vger.kernel.org,
 linux-sctp@vger.kernel.org, linux-nfs@vger.kernel.org,
 tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
References: <20200616154311.12314-1-longman@redhat.com>
 <20200616154311.12314-3-longman@redhat.com>
 <20200616110944.c13f221e5c3f54e775190afe@linux-foundation.org>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <65002c1e-5e31-1f4e-283c-186e06e55ef0@redhat.com>
Date: Tue, 16 Jun 2020 14:36:15 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200616110944.c13f221e5c3f54e775190afe@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=jC1SVPU+;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 6/16/20 2:09 PM, Andrew Morton wrote:
> On Tue, 16 Jun 2020 11:43:11 -0400 Waiman Long <longman@redhat.com> wrote:
>
>> As said by Linus:
>>
>>    A symmetric naming is only helpful if it implies symmetries in use.
>>    Otherwise it's actively misleading.
>>
>>    In "kzalloc()", the z is meaningful and an important part of what the
>>    caller wants.
>>
>>    In "kzfree()", the z is actively detrimental, because maybe in the
>>    future we really _might_ want to use that "memfill(0xdeadbeef)" or
>>    something. The "zero" part of the interface isn't even _relevant_.
>>
>> The main reason that kzfree() exists is to clear sensitive information
>> that should not be leaked to other future users of the same memory
>> objects.
>>
>> Rename kzfree() to kfree_sensitive() to follow the example of the
>> recently added kvfree_sensitive() and make the intention of the API
>> more explicit. In addition, memzero_explicit() is used to clear the
>> memory to make sure that it won't get optimized away by the compiler.
>>
>> The renaming is done by using the command sequence:
>>
>>    git grep -w --name-only kzfree |\
>>    xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
>>
>> followed by some editing of the kfree_sensitive() kerneldoc and adding
>> a kzfree backward compatibility macro in slab.h.
>>
>> ...
>>
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -186,10 +186,12 @@ void memcg_deactivate_kmem_caches(struct mem_cgroup *, struct mem_cgroup *);
>>    */
>>   void * __must_check krealloc(const void *, size_t, gfp_t);
>>   void kfree(const void *);
>> -void kzfree(const void *);
>> +void kfree_sensitive(const void *);
>>   size_t __ksize(const void *);
>>   size_t ksize(const void *);
>>   
>> +#define kzfree(x)	kfree_sensitive(x)	/* For backward compatibility */
>> +
> What was the thinking here?  Is this really necessary?
>
> I suppose we could keep this around for a while to ease migration.  But
> not for too long, please.
>
It should be there just for 1 release cycle. I have broken out the btrfs 
patch to the btrfs list and I didn't make the kzfree to kfree_sensitive 
conversion there as that patch was in front in my patch list. So 
depending on which one lands first, there can be a window where the 
compilation may fail without this workaround. I am going to send out 
another patch in the next release cycle to remove it.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/65002c1e-5e31-1f4e-283c-186e06e55ef0%40redhat.com.
