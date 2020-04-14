Return-Path: <kasan-dev+bncBDLIXLMFVAERB5PL232AKGQE7H2ATXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 652CF1A7BD4
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 15:09:10 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id f85sf14239630ybg.12
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 06:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586869749; cv=pass;
        d=google.com; s=arc-20160816;
        b=XJGhEEGxa1KGxu8SoidNAq+nYprwo6oUAgj5ZE0WG+zlNLG1bO2CB+9nJJD4JGi65G
         Kf+C1tzGa3m8FiQuqCyAnvd56pgxMA0flM2xnISCYDRqv1tJxcSN7Gw8jrLmb21j00jc
         Gg5K1cmN4rfAE3Wnwr3IBXHFynFe2ti57TYoBwSgR7dGTKn3ufrr4HlQa5/sPet0jWUZ
         LXUlk5HjZfvdBzBx+H/JTVJkp7qycKZyE6A+E1cm2MTQQ5atGmEOwuNHG09HN1foZL/r
         u6ECVzGEIy7+sZIl1NhT07nojXe6xDPV/aUD9NGpjhMDXelECMcZcmNtPcnirUtN1Um3
         E29g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:content-id
         :mime-version:subject:cc:to:references:in-reply-to:from:organization
         :sender:dkim-signature;
        bh=ZasOjvaLLP8HO0gAyDzfFZindG+hDZE4WQ/2nHO9H84=;
        b=Me5lEU4utWXXnZYSwIwPQim9exYkPbGu/SQ3o/wod11v+jFlmwSiZaHunscGsfhae5
         BHfNfExcNOt/6iQ70eh7a9QOMuw7yjh6XRZk2UR1WsZti/r2IVv7Nm+A+F/uaC/CpFm4
         crPGmOZAYB/WL9atTNbafUH7zkXfXIKHjWYJtZfH/ls8gIFM4qtgF68AT67KZfwiRNSO
         HYV5KtYpjkEAh0dZwNU/kz3RJu+9H5Ld3A08v3aR1XnTMRP6nMwjHCiQGviHYNp+n4pN
         o37IITxCdPq9wLxu1LDW0avwqoodimAoH7bNkDJJXcUHnGZCRaMRUzkUTGc/Wj8hIOZm
         O4YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ASRnl81I;
       spf=pass (google.com: domain of dhowells@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:organization:from:in-reply-to:references:to:cc:subject
         :mime-version:content-id:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZasOjvaLLP8HO0gAyDzfFZindG+hDZE4WQ/2nHO9H84=;
        b=JiKEmINBqBhZp9lbFmM5FJ5301+950fXaTSbB84gAbJYkJ3bBZddiFSd2+m9ezWTyG
         sUYFUtalvE9MUZwT+Y7Vtoknr9Z4JULkNlINbQWIuwSufT4H1BYCKGLkziYPZbVPqpm9
         8ljqI9XMXU8h2fyM+zOSadXUr0nvAUi0CFgzYMoOxIz1aGai+Efg7Jl9MByR4R+zQ27a
         G8Oee/uoMGM8EnhUi31+JykvIel3krSfGf1hp/gyjok7OmvzO8cPejQeSdwpuoX+wMAd
         XrwSSTFTs/+Yc9wRw5Bu3DpwWEqoclTcGof8EjQ3RcH9Tf+A8NYF5oldfKFAqeg+c9kN
         QUIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:organization:from:in-reply-to:references
         :to:cc:subject:mime-version:content-id:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZasOjvaLLP8HO0gAyDzfFZindG+hDZE4WQ/2nHO9H84=;
        b=QrYGx2HCorgkAkl13WRpy6Fzr+iGNxv3KkYQ2g2jHT5R4YVYyI1GVR9btF3Kxwvy1e
         VPb9km5wFJfgIlY493Si3FJHS03M19nZpgdm8ZWBucaE1YuUdzzZg96xTUyn6a35T/B1
         IjNNblPBzyI2KHvAhOogIOMTVPM12aHUdZaDPl1Ea1ux97ZqYsF/vSjqQG0wYjvVdFeb
         aIsG5MraKsMGdR3zFJwW31pqrmR7khGedZ3hU4IvBeGcfNkCLjI+G/ytco1c0L/luP7P
         yLxVWZ9cCwtjhTLKrxmnbr1XM4r4HjuGqa8mwHnciyZg9lDQy97x9I9WhAGD5np9iC+O
         21IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pua5duhB2BMK5h/OqgkCn2/GKH7Z1rR05dMXx/8iohm61deUi2i7
	+qteKAKmm2APGzo1R0G1HR8=
X-Google-Smtp-Source: APiQypL+C59oVrt3+u74THnrU+MKYoq9QShrIZ8+j6QjpO1ire2PjuZLQTY8Q8lYh+OFeqg4Xt3j8A==
X-Received: by 2002:a25:2454:: with SMTP id k81mr22733104ybk.470.1586869749351;
        Tue, 14 Apr 2020 06:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ac26:: with SMTP id w38ls1296546ybi.11.gmail; Tue, 14
 Apr 2020 06:09:09 -0700 (PDT)
X-Received: by 2002:a25:9786:: with SMTP id i6mr36121482ybo.68.1586869748921;
        Tue, 14 Apr 2020 06:09:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586869748; cv=none;
        d=google.com; s=arc-20160816;
        b=OGgpVIUzLH24jiBzcp5RBjGJdfeQWl07hOwkR1jmGR5NoJWLwzMo9EgVSptZwP8nsc
         4y64v8QcDPvqEIrYHEiZei77vhXFL+r/BbxkOZMOoEnJ6rl5wS+EfAm5E7dsFeYqVBXd
         Vzjhk4TV8o5Bttp81GtnNWn4BFvQy4ouNq0pD/elqM50pRWuC+vnAeMIGQ/Rq1cZfEjA
         srjoDQ7x0NZ1yXYu0++XtP4Egor7aLYLTJoKl0Jj7CN65cUw0tJCvq3bpsp+DAY95Otx
         +m0gIMypXQpAFFGaZVHA6j1bX4uvqA5JTn1PRC+7uMkD+X0K80rcBTITFU+zjmyBogzR
         8prw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-id:mime-version:subject:cc:to:references
         :in-reply-to:from:organization:dkim-signature;
        bh=hBYiVbPBfUS+AcwD+sXBpDKSbw0tQLOGN9sYzZKYAmI=;
        b=uioknreUBCSOM9nRf1YLVloHuGf6+hQsjOde7LVSn9+9eOoqFpwUopMLZ392bJN9M9
         /VRxLozWthwX3N2HtXKY/SNtTg/t2/ex3gd/NNHwDfr2yFMMderM3Ys/hFDd4jW2xiSp
         utvLsGtKv9hUdBkrDJsSAj8u1YkFL+ubS+HvnNgA0q+LKcgabFgUnN5gqpBN+M0cZdyA
         zxqgi7OUjF1PvJMCcNxq4+5CtZGyPnn1UWNOA9UCMz6kGkRVeFXvi1Df4FKPIsI+3n8e
         EmvnNzi1d9lpH/b/hXDfGv6o7o5eMvnPGDtATRi4F8A6QxSNJbDvZ7u0LJsjL2leQ0sJ
         R2Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ASRnl81I;
       spf=pass (google.com: domain of dhowells@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id f195si808152ybg.4.2020.04.14.06.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Apr 2020 06:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhowells@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-106-PA7uLtZsM327ACx1G3T_7g-1; Tue, 14 Apr 2020 09:07:49 -0400
X-MC-Unique: PA7uLtZsM327ACx1G3T_7g-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 96CEA8048E4;
	Tue, 14 Apr 2020 13:07:05 +0000 (UTC)
Received: from warthog.procyon.org.uk (ovpn-113-129.rdu2.redhat.com [10.10.113.129])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 5AB5418A8E;
	Tue, 14 Apr 2020 13:06:57 +0000 (UTC)
Organization: Red Hat UK Ltd. Registered Address: Red Hat UK Ltd, Amberley
	Place, 107-111 Peascod Street, Windsor, Berkshire, SI4 1TE, United
	Kingdom.
	Registered in England and Wales under Company Registration No. 3798903
From: David Howells <dhowells@redhat.com>
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
References: <20200413211550.8307-2-longman@redhat.com> <20200413211550.8307-1-longman@redhat.com>
To: Waiman Long <longman@redhat.com>, herbert@gondor.apana.org.au
cc: Andrew Morton <akpm@linux-foundation.org>,
    David Howells <dhowells@redhat.com>,
    Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
    James Morris <jmorris@namei.org>,
    "Serge E. Hallyn" <serge@hallyn.com>,
    Linus Torvalds <torvalds@linux-foundation.org>,
    Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
    David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
    keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
    x86@kernel.org, linux-crypto@vger.kernel.org,
    linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
    linux-stm32@st-md-mailman.stormreply.com,
    linux-arm-kernel@lists.infradead.org,
    linux-amlogic@lists.infradead.org,
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
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-ID: <3807473.1586869616.1@warthog.procyon.org.uk>
Date: Tue, 14 Apr 2020 14:06:56 +0100
Message-ID: <3807474.1586869616@warthog.procyon.org.uk>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: dhowells@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ASRnl81I;
       spf=pass (google.com: domain of dhowells@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
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

Waiman Long <longman@redhat.com> wrote:

> As said by Linus:
> 
>   A symmetric naming is only helpful if it implies symmetries in use.
>   Otherwise it's actively misleading.
> 
>   In "kzalloc()", the z is meaningful and an important part of what the
>   caller wants.
> 
>   In "kzfree()", the z is actively detrimental, because maybe in the
>   future we really _might_ want to use that "memfill(0xdeadbeef)" or
>   something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. In addition, memzero_explicit() is used to clear the
> memory to make sure that it won't get optimized away by the compiler.
> 
> The renaming is done by using the command sequence:
> 
>   git grep -w --name-only kzfree |\
>   xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
> 
> followed by some editing of the kfree_sensitive() kerneldoc and the
> use of memzero_explicit() instead of memset().
> 
> Suggested-by: Joe Perches <joe@perches.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Since this changes a lot of crypto stuff, does it make sense for it to go via
the crypto tree?

Acked-by: David Howells <dhowells@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3807474.1586869616%40warthog.procyon.org.uk.
