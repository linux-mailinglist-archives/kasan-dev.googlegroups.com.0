Return-Path: <kasan-dev+bncBCPILY4NUAFBBQV7UP3QKGQEDN7WMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CF1F61FB56C
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:05:39 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id y12sf14577539pgi.20
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:05:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592319938; cv=pass;
        d=google.com; s=arc-20160816;
        b=mEcM5fbQae1slRON+7H2oJ4zY3j1k2aTEI4oeBKc9Yj4Lt7FUmY/ujLZ/s8FNjv8Hp
         XP2X4qr4JsYPI90h/mNJhbqCqNIFABi9OvfKekWZZSUot0gt+iJUy8C0dwWbTjhd0eqQ
         DG2dCQSnmT1tV9S6DBpM5bEbwg/YLCZ8uihoRLS7lUiGtjVMyi0HEq35SzpfskTl7/dJ
         5obKA9FbLiilpFlxyO/XjJEk6B/Q42QNQ+2xV12WPqM+iPZShXVwy1WVRj3aRBPcIK2h
         23/2MxJ93aWL72XFBQ/WblZ+Ifwlqg4lSXWgjEuImUpqrIpZwIieB1oAlJK1YSrRo7pq
         eqFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:to:subject:sender:dkim-signature;
        bh=AHBw3PUPOvE96EjAzn0/ioOl5fp1NP8rOhxTcALC5nM=;
        b=xfRXGNxnJHgUB7268VN9PypFrd383n7hrksvKe0fI2vrvg4bttWqTmNmEgVGkP8mj4
         0TgRYYNfPhJK/cAnJsawhmyUNME/tS4Ek1L6k1M+YchDqL58tvC1kZOWSBkaeOjsNZRI
         SDUWRBpj30vT6dzBp477jfmPo1bzvjitCQqG41xgmcNi7H/tFgTqPlGRbQhArI3Gue5g
         xxSFycUvtxhaWi0GKhK6ksKj2TQENK4sKebPLW3YpcX/MI84Yq7HCnIcm1yFwK5lbGhV
         2gOQzjS6H7lrSYAkVLvcGSLWnbZlOnWnhS40iXGpbR6BN3dA+1u2fvlUi++6LOjjORp4
         C9Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HXehFBmm;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHBw3PUPOvE96EjAzn0/ioOl5fp1NP8rOhxTcALC5nM=;
        b=TEES6mDyuvUEWuKkMCw2LZXwkurKIzjZkFd2jw603i0M9KgrSiBcMUz41J4lLj/+CP
         +PwAUt0ICdSIGzpHm4xqxj9gGPXspZm/XG7123UJXx68jwa5pC2TsYxTwU6sCkW7blOQ
         oPPhNduBzXhMy/EvvKUSnDPbAtd2eukoexagbY8kF8HdZAc1l5mj0REgO2NSLDccZYyQ
         nxseOvtw0LuqksX4tRHsbdap1f3CJiQ70o+ZnWrbm4mNjkY6U4pPlY5N+YBrU/xNG/Fu
         45EVTYyehZs4FVr9kwX5Q6wa0dKg4W9x/z5SLc40FeQ7lIc1OjHBZm/l68epgIO8mrn/
         +bRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHBw3PUPOvE96EjAzn0/ioOl5fp1NP8rOhxTcALC5nM=;
        b=giBWp8pXMp9T8mb4kVxNvtFxP8WATlzyZQuR9+Apmpz4xqB+snBeUYHUdgYckue07y
         ln+OQVu7SgTeDfb+aj3gkPthWdyq1JibSVcU9Wa0k9OdN4jel6YgHsfeeAPkZb0vo/Wl
         kWKXI7jsF4HNEjCv+0uw0sZ7mYqoGjNEDrW2bZ2H3HlWqCAgume6AnjehFQm4zV6ueUY
         vGupWYMZ9fxqpDiL/mKzPMrNkJV09d96ldJSyUXlxhG8EjNhtSHZ//TMndjm3qtqtKAO
         5cpr5JAN2M8CvhHdDhm+zB7g4LSNd9YF4zCQHvvZwvNFgZvzqEgDxLRsj5pC5zyRuC4t
         WbDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XvpaJtzORgSC0tXlZGyMA79shV+PbToU0mOYedzrwJ5uN4yGZ
	aYftJQRzWhxMtCx/rUxZL3Y=
X-Google-Smtp-Source: ABdhPJxlVmzsXNAQDpl4tuMJlQJUbduvx9+yN/ZjU5S670YiujjCnzA6fWZrzRHO71Z2nT5BgDqwxA==
X-Received: by 2002:a65:6703:: with SMTP id u3mr2368677pgf.179.1592319938402;
        Tue, 16 Jun 2020 08:05:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls41943pjb.2.canary-gmail;
 Tue, 16 Jun 2020 08:05:38 -0700 (PDT)
X-Received: by 2002:a17:90a:c695:: with SMTP id n21mr3486772pjt.206.1592319938029;
        Tue, 16 Jun 2020 08:05:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592319938; cv=none;
        d=google.com; s=arc-20160816;
        b=HJb4I8ELOScxoJN1rLN6UDqDxutXr4FsQVPRgbMQJ7eaf8JvEDIxyG+yMSQe6HrmhJ
         MEcCsXwXVnYs1EIMeC0YROPXAU60bH1dCjALsx/evBdUpr2w9mA5YIz734HA4arAqN9z
         kMNPQ68KycLk9q3x/Kd5e7EqDHOHr0lhiB8jtLo+atuzl6nOKFla04ItuvD6qDdwhIxg
         vKvdt+7BSwhuVnLjLKrCju5oL+44DQfVrNnAEMODQVes+4MJr2zyCPq/8SwO1LdotZc5
         14dp5cLrhD+jmLmQXzVM83qSgO9/w702+ZayoaxbyRpMO/BOEquvX9r7pZa4PzUlR0sX
         73Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:to:subject
         :dkim-signature;
        bh=rXbjvJPZU9GzTq8LOO4SZ69J1AJAOxGiWdFnkvpgDCI=;
        b=Q1m0b9wucP0Lq7rBdr0zsVsWa/nYjONUbrjYr/8yCFAnSyIT57ahbPLPlZDcpz63lD
         RFQPMQRcIUBpdaVA+t6CTD+DT8mSo0cvwDWj9gDNpwftlAajrEuw4fukKAXtHQsbn7gq
         6SeolC7sZVvCdoZqW7yXUMJ0Wdnc+m07NrY2PeZ2KDvAEPb+MbwjdCclTBduv3+pUakO
         Vb6fbf5kGjgKmFVXwFACecY95atM5kayK7TKisb2n7iDlIUt+5lPWPeygokVEfv5NLpN
         vpQYRPvt4gkVZh4PcZOfVePSSuUyFHaN+LktfC5OPSSARhg3h+XB+WMbjO8ybH7rH2hB
         XHBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HXehFBmm;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id q1si49363pjj.0.2020.06.16.08.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 08:05:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-347-rhm5WjahMFKJc8Xm5_1I2g-1; Tue, 16 Jun 2020 11:05:32 -0400
X-MC-Unique: rhm5WjahMFKJc8Xm5_1I2g-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 6B20C100CCC9;
	Tue, 16 Jun 2020 15:05:27 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 897CF7890A;
	Tue, 16 Jun 2020 15:05:22 +0000 (UTC)
Subject: Re: [PATCH v4 3/3] btrfs: Use kfree() in
 btrfs_ioctl_get_subvol_info()
To: dsterba@suse.cz, Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
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
 linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-4-longman@redhat.com>
 <20200616144804.GD27795@twin.jikos.cz>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <75152002-5f02-04b6-a811-29ef79961e0b@redhat.com>
Date: Tue, 16 Jun 2020 11:05:22 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200616144804.GD27795@twin.jikos.cz>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HXehFBmm;
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

On 6/16/20 10:48 AM, David Sterba wrote:
> On Mon, Jun 15, 2020 at 09:57:18PM -0400, Waiman Long wrote:
>> In btrfs_ioctl_get_subvol_info(), there is a classic case where kzalloc()
>> was incorrectly paired with kzfree(). According to David Sterba, there
>> isn't any sensitive information in the subvol_info that needs to be
>> cleared before freeing. So kfree_sensitive() isn't really needed,
>> use kfree() instead.
>>
>> Reported-by: David Sterba <dsterba@suse.cz>
>> Signed-off-by: Waiman Long <longman@redhat.com>
>> ---
>>   fs/btrfs/ioctl.c | 2 +-
>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/fs/btrfs/ioctl.c b/fs/btrfs/ioctl.c
>> index f1dd9e4271e9..e8f7c5f00894 100644
>> --- a/fs/btrfs/ioctl.c
>> +++ b/fs/btrfs/ioctl.c
>> @@ -2692,7 +2692,7 @@ static int btrfs_ioctl_get_subvol_info(struct file *file, void __user *argp)
>>   	btrfs_put_root(root);
>>   out_free:
>>   	btrfs_free_path(path);
>> -	kfree_sensitive(subvol_info);
>> +	kfree(subvol_info);
> I would rather merge a patch doing to kzfree -> kfree instead of doing
> the middle step to switch it to kfree_sensitive. If it would help
> integration of your patchset I can push it to the next rc so there are
> no kzfree left in the btrfs code. Treewide change like that can take
> time so it would be one less problem to care about for you.
>
Sure, I will move it forward in the patch series.

Thanks,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75152002-5f02-04b6-a811-29ef79961e0b%40redhat.com.
