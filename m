Return-Path: <kasan-dev+bncBCPILY4NUAFBBJGKUT3QKGQEA3QVARI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C973E1FBF82
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 22:01:41 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id p18sf16368241qvy.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 13:01:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592337701; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePZ/Ol8d/GB7nYpLFSqECfXoslyPEnigs8JbMfBj6iD8PybNWnX7dnhxQaWnL8i4nK
         xG0groh/+8nNnRERn+7uYRgoF+P2mAYzaJUdv+RxX7qnsK1r/X1DuZlpr7pkOLYx4fDf
         ZrMeFsHIGkUaKvaWZhjXSpnQzG1eD2yUEnO2dPp5/ez+T/wV08/Ex3AGz0iwX2bwATmu
         fygWbpbNas0hegWQAdCHo2yOurZzly5JyYsfct0OZzzIFjQWhVeP71VjxbBwkIbsG0kD
         Jp082NW2Tj/1fOiipbIT7Vre7Y1WkRybKZDziwhnwpRq9hL+uZdhLf52Aqjobn7wVKlT
         k/6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=VLjm3fXtlzxCkJMr7cAXJv3b5IUOE/+BugUwpzkkCsg=;
        b=Eu/seJrcUWLJMcpUaR7Ae9GITan/Gc52uannvvEEcW3CC4Ki61g92x21Z6ytDWVZbM
         dmBF4GWIXYws7b0t/8sH6XyQWNhjZonVlQjkx/arlgyZKnYCN+ulYLnu43mBX9/AxojO
         QMgXIVuuFI3QuZ24JeBf1g4eRxYtksyb0nXbwGp7afCjtK2zYpObQv1qAW9r/cLwB2v+
         Pcxa65DJ50pnyDaDkms+bEWOzCLP2JDcAlh0pYNdPMsGbloBoeOxcc1ZmFvL5dGAl7Ib
         OxyISsqBZMJ+zbYwbl+3xSQLU4I5i6f+T/AgKSxp21Gbpdvs+2wjWn9tTBYtsCx+THOk
         1Ejg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gwuk/kzd";
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VLjm3fXtlzxCkJMr7cAXJv3b5IUOE/+BugUwpzkkCsg=;
        b=K/gBHGDXoP6dJRdI8VW/xuu+EGwjQlYuuhqMWy+2TTdzraJHExXCWO98dJLqHGfLae
         pHSu7xUz56O6CKZlk1foFFCn7II17Zx/f4Tt7DUiQ8Fg7hfJMFiRNerg3q74Y/OL5CXL
         Fz/GpiMquHKL79ewdSWFzCS51HnoggWqGq99mupTkHUBNMfSiMIhYFIOzrk2ZDUKB9kk
         aGhJEgkTIpKv9u5bYmuzOQ7+7v/bCipBWkuqUe5OZIE1cn+4KAweKZsosgUctG9rAlsd
         MqUp4We4Bx/OVHP2cmJXfue0kwYLL0UDisOsf3MUnFkPEqDY0hp28ywgdzYcxFyjDcpL
         10UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VLjm3fXtlzxCkJMr7cAXJv3b5IUOE/+BugUwpzkkCsg=;
        b=TaiihYKXiF1A9RS2Yg96EyN6lk7YRqPSKj15q5NEbrzdL6/h+Z8kwJ6yuZyDI0GaEv
         ijUJaZuDNOe4jcQEXvooMxh0jKwAl64HrerVoIL/OMzRjtUPJs/A9bYs2nq3ZAZIeG6I
         qR7ZNXOXTw+mfw1Q5Bpzq0s78aMm1v/ko0nB7l+B/NbW4wgD5HTb+VXCww3SIBhCgKZv
         jZ1PIta0bZ6LbQfXvKbpVaSORHr44U6he5BPHhlDctsRXYfPBBmjuQrl2VGzZZTrVjfj
         6Ki61KePHLJoDyo7/2mUlt+7Pg8zLImxHK/LgtQVt8vrS3uitZ4Xi4umKCl5WlyjRiYQ
         GNHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ihq3Jphtw97pi6AaOkt/mQpxPSBUlxO1FpXrIJnUACMxNvlsf
	XpCpfuxNWn9Sbip5yMFt6pA=
X-Google-Smtp-Source: ABdhPJxTyGxRBS6bbbgeeDKqzKfEaARjJd0/DWBwKUWL+c5bdtmAcoFusbsCUiLH53o2vyyS/W9Qkg==
X-Received: by 2002:ac8:17a1:: with SMTP id o30mr23731229qtj.140.1592337700878;
        Tue, 16 Jun 2020 13:01:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c8b:: with SMTP id y11ls7231823qtv.4.gmail; Tue, 16 Jun
 2020 13:01:40 -0700 (PDT)
X-Received: by 2002:ac8:7c8e:: with SMTP id y14mr23771400qtv.365.1592337700491;
        Tue, 16 Jun 2020 13:01:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592337700; cv=none;
        d=google.com; s=arc-20160816;
        b=ym4td0+W1tm4NVXKFqmVecy81UmPqWyJjDW6F8wPuOzjuzuhOTr/a6RWpZpnLAGCUj
         iUx8Gzd2qpgLM57rZQl1+icVZTOcUFe+z4sy1vMtKo9Dmpl8F5AciRZDDY3wf0rqZQhV
         GmsckuX7VfGz5IggLF/W4ohFf0w0xGgnNZxPsHmsenDxL7z4aumVIZ/+SSMDtymy8TUb
         phYQhLsqMNGjsGpgDth2pCBqysdfr15Fd9AEovTorTXJZHgBmiZJ0LCdgJ0/nqD3qSAk
         pRzn7AAM6XxlItzTz7miUmAmSSUlRzBKJ1ujw8evQ0VuQ/5vf9Gc4nW3D4A5unpiATar
         Gmvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=IZuHuVBorvvnUwBUanoxn5EJfFFGTbG0F4JYxmnKd8I=;
        b=wDDiwn2hLa4I9eTWedY6CYfI+MkBy0jr0JCnNNkKNiLwH9CaAieHidFDUkMyeBYs4h
         uUZPyj0GvYXzTx3BrS1WD1JIy52TGIeOYsQ50Xns60Mh5Z8CH4CougJyU56Fj0v+qynp
         SPyFMpqwVNkEJYd+sa4Lt8hOQe5b/twcC6/MpVRZmYw9nuvsujMPAIxW/H3kfzam6vqe
         rAUus7Ump4+Gi+IBGjfuod9vIYQD+W54qENJlEL1EfU60jTOgxR+sXtitV2CxlocycR2
         TtGarvO1lG2EmDglWHpIFKOLmeIIPLa7mcePKCF9EGxaIieasKsbU972F450ozrqimpz
         93mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gwuk/kzd";
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id v199si1172307qka.5.2020.06.16.13.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 13:01:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-195-RsA5jiRVM622hegDVDAGvA-1; Tue, 16 Jun 2020 16:01:36 -0400
X-MC-Unique: RsA5jiRVM622hegDVDAGvA-1
Received: from smtp.corp.redhat.com (int-mx08.intmail.prod.int.phx2.redhat.com [10.5.11.23])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id AD51C8035E9;
	Tue, 16 Jun 2020 20:01:28 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 4F41719D71;
	Tue, 16 Jun 2020 20:01:20 +0000 (UTC)
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
Message-ID: <7662bfe8-b279-f98c-3ae3-c3b889aea1f5@redhat.com>
Date: Tue, 16 Jun 2020 16:01:19 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.23
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="gwuk/kzd";
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
>     #define kvfree		kfree
>     #define vfree		kfree
>     #define kfree_const	kfree
>
>
How about adding CONFIG_DEBUG_VM code to check for invalid address 
ranges in kfree() and vfree()? By doing this, we can catch unmatched 
pairing in debug mode, but won't have the overhead when debug mode is off.

Thought?

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7662bfe8-b279-f98c-3ae3-c3b889aea1f5%40redhat.com.
