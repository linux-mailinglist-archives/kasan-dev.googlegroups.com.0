Return-Path: <kasan-dev+bncBCPILY4NUAFBB6UA3D2AKGQESIVDPLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F2931A895C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 20:27:08 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id y21sf14210856pjn.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 11:27:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586888827; cv=pass;
        d=google.com; s=arc-20160816;
        b=M1CniFqUZ80ksveBO2QQ4N2gM8I3vHMnhpWDN44iTzyi2/7foj5whHpu2Q/sNL25Tl
         Y2vIN20UIfqgZ9eCIJ4tuw1QDeKtoqbb5aFnhvfO0GloiOxVq68ek+NIT4ORIyt0ZJQD
         SYMM0woGCWabXQNmRWs9F5X98nCg34fb82tOprJmSL0B3MaSR2GBpcFZEwPyQOwF9SCH
         ezY2qb4nwOeCS/bxnsted/i/mq5B3mRfcRDUpLTC7v8kLCjiMeqFPxz1mEh8oHqNunyD
         eqgdmdZCf1ee44DlMjnoCPJP6NaXnU1AKOI9KwoMv4TQeqaOsuHIj8gZLXuvHtXKiQMW
         18GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:to:subject:sender:dkim-signature;
        bh=ZM8XvulrGgWo3m9w6SGy+AgNahS64hC2J3ofa+FPSA4=;
        b=HjGayeiPwKZ6rx6V6GekIk0gNg7bK+StTiN1G8Oc3G/uxvdT66IEwlk/TwEnFEmFRA
         Idg4JjkGri7+snJ1z7wAFwDJ9NVNFRufjvHLmE0mjd3/Tzms0APL2Vl5d3n7Yzkx/7UA
         IwOe5OY62rXHeWmJaJwBWi3XzzVczmOuTKv1HULJ//SNeaGt0SYsiF7AjoKcGRvwoZWp
         Kf+6cpJBarhi6AofTCBuyI4u4ZxkcRN/WCnvxwv/8B4Ah5nCjaE4JtrKaX/zu5oUemcW
         +QtoRwqrew6ZK4xDj2FpZuLwhhEyCO/xCOCFXlOh7CgFPUQkQEPnC6BgjAL0fHq6DLOI
         JiFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=evzNfjaB;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZM8XvulrGgWo3m9w6SGy+AgNahS64hC2J3ofa+FPSA4=;
        b=adj8FGtEBP4h1QVlRdebiuUXm67Of8eNrOxHZFpWHr9O4EWG0sWavpIKaBfikPUcds
         GMfhgF42/7k/U4Vwu7PsJVc+kn5vOSezTyHK1YIZXQUJeCdBML8Ss3xvXgNe7jOmzNRa
         GmLYNt8DUQD//ZWYiBCINzTuQFwqTAJvLjYeWAVkZzDtT27sx8PUnVMm/k6CQgNKao0w
         ubMSBc0K61ldvf0c1xgP9r5vsWPia4t/EZj0nT6IIJ7qO+VyflDd9b3jVJXzWJW/ZmG7
         c7JXaiqBI2KRjeHj500W/4Gu9tC9TpnaxFSUZXGthvUnI5BRtNH9jMQ2z0m7TCGRD0eb
         1VGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZM8XvulrGgWo3m9w6SGy+AgNahS64hC2J3ofa+FPSA4=;
        b=F3u3/t4RPhXZEecunO5tNBzUzThJiBa1DjrRNaPZscImhBUSbc2gyFPz09np237QS6
         aGIJurRsSTK4zoywRT6qzBeNAU5ELZnOmrnuGy6ADVfCTjmTmv1mOs3rLb3IOdGCsQZ1
         Em/T9KXyhH9IDsFLu4gGo9pLGCQ8Q9EVxWRdSTp4dUlyThw4VAj3UFxSnGhR6PkB0Ye3
         XqNnbllAyfwfbP58qrVE3JU2fmREsbaIgh+nEHS6C/D48MCD3zvBHVlZmaRLZJMgTY4C
         wrhiHnppQU5ZCrUfgXQXVjHxZb8oLd0wVTG35s+/aJUMCV5lbjlDDV43HvI2Gb3yvC7H
         SHRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub/lbbqjoBWL25ANaDoBT9ircN8aYNEJviVCNGvnULOTVfn/hwF
	DwLr5YiVdjnM1pXvNcJqqtc=
X-Google-Smtp-Source: APiQypJnFW8VSZobsGVUoCjzd8YMwnc0/Ie0G62TVJI88PeWeLQepGdz+qtkRaWhAqSTkQcgz5LPjQ==
X-Received: by 2002:a17:90a:1946:: with SMTP id 6mr1722092pjh.42.1586888826874;
        Tue, 14 Apr 2020 11:27:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b58d:: with SMTP id a13ls4454791pls.0.gmail; Tue, 14
 Apr 2020 11:27:06 -0700 (PDT)
X-Received: by 2002:a17:90a:65c5:: with SMTP id i5mr1637771pjs.18.1586888826505;
        Tue, 14 Apr 2020 11:27:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586888826; cv=none;
        d=google.com; s=arc-20160816;
        b=ESvyOJxIVABI9SCs1+4LrDdyHf4pw7V3vENCoz4RT9LebQSOYj90X0BpD4oYeLBmBD
         fPk9cngPTfxwp0mBAXeYhqhZ/59zLRqqf4v0jz+aZrMA/oshSInD4FvTCnYqCBxzRNS+
         +v6zpLIxv1DKjq9eoNFfqm3hM8cNIynLnJdSAOFtXhDbVNF7jlU14habrwq7l4Vszuow
         llx3s1SDFVL14jgE5daX/GCzcGU6XUeFosuk28BEODKlKvVS4bsUvSmV0GEXn2TJF1iN
         X/goBY8cv/HrwCiROylVguMWNGnw8h2y30BBL5jVLf+KJ6u4pxQVLCr16wPA4EYVcW1R
         i7hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:to:subject
         :dkim-signature;
        bh=TLv7+DlAPTIRbMlPGq/MKTxn9g95YUGNwTJol6ZbUDE=;
        b=wWRSJHuUdADyXHd71I0DS5M1xm0ooqG6sdHxpqXOuri2vz4zOsVfEuOd3C5z8ik5B4
         bByMoTxVxh1cIx1iuJvMn89IwmLgutiCjwrQJagDrMxscVa8xEbmNbjmPL4IzPFwMcSV
         XnX3XROWBqMFc+Smndj5L7BDAu3ZI4Y4k62OoEP83V7/DWgXeK+qNPgQ3ZeqMNn02jpS
         uyt4UA7X0fyRvXfabJcVbWk7Riv52QboytjOWO5F4oC8kWHh9bprS7A28p3fLLjXmK+c
         0NGjBGQm2aEn7T5xnyYvRxw4xDyLxioW5bWYkSqwHUnJw6pN+0+03Ees3I1IBlGDErMj
         i13g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=evzNfjaB;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id g23si1156357pgi.5.2020.04.14.11.27.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 11:27:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-449-lrwga1poPzOYOa4E2pXY4A-1; Tue, 14 Apr 2020 14:27:01 -0400
X-MC-Unique: lrwga1poPzOYOa4E2pXY4A-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id E975D13FA;
	Tue, 14 Apr 2020 18:26:55 +0000 (UTC)
Received: from llong.remote.csb (ovpn-118-173.rdu2.redhat.com [10.10.118.173])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 936D410013A1;
	Tue, 14 Apr 2020 18:26:48 +0000 (UTC)
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
To: dsterba@suse.cz, Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org,
 linux-crypto@vger.kernel.org, linux-s390@vger.kernel.org,
 linux-pm@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com,
 linux-arm-kernel@lists.infradead.org, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
 linux-integrity@vger.kernel.org
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
 <20200414124854.GQ5920@twin.jikos.cz>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <3d8c80cb-68e5-9211-9eda-bc343ed7d894@redhat.com>
Date: Tue, 14 Apr 2020 14:26:48 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <20200414124854.GQ5920@twin.jikos.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=evzNfjaB;
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

On 4/14/20 8:48 AM, David Sterba wrote:
> On Mon, Apr 13, 2020 at 05:15:49PM -0400, Waiman Long wrote:
>>  fs/btrfs/ioctl.c                              |  2 +-
>
>> diff --git a/fs/btrfs/ioctl.c b/fs/btrfs/ioctl.c
>> index 40b729dce91c..eab3f8510426 100644
>> --- a/fs/btrfs/ioctl.c
>> +++ b/fs/btrfs/ioctl.c
>> @@ -2691,7 +2691,7 @@ static int btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
>>  	btrfs_put_root(root);
>>  out_free:
>>  	btrfs_free_path(path);
>> -	kzfree(subvol_info);
>> +	kfree_sensitive(subvol_info);
> This is not in a sensitive context so please switch it to plain kfree.
> With that you have my acked-by. Thanks.
>
Thanks for letting me know about. I think I will send it out as a
separate patch.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d8c80cb-68e5-9211-9eda-bc343ed7d894%40redhat.com.
