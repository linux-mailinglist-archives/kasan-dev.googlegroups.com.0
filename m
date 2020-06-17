Return-Path: <kasan-dev+bncBDHP5ZMLXYCRBJEXVL3QKGQEJ2HMIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 81AC91FD745
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 23:31:16 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id p24sf1706930wmc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 14:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592429476; cv=pass;
        d=google.com; s=arc-20160816;
        b=oNJdgzeLrcFMrChlGLyAOJsTA3BqXu40y0+I7wbKBRLL3lPrPW42mbIJcsGDuMiR6v
         tIa9qPWmaw+RZBBYKe/BlZ+hXMl6BkPz6hBG6Et5llmRXYqeFmW0NiQOtyy5EIlbmNqG
         FSjhCp7s0GEngXQaucZsOl/TrNyUztRS+WI2eVYZnolEYHpEmockOVBzOt6KaT2dp5Cf
         E0Hjci769skK2929vdO1HbkGBrW0Ib1ECdz/KgY1MJYy2V0BEVxDWPT7o7l81brgFgKU
         3fNdEKoFKdTS74Fsj/SMiliSj0DGMK7K0rVvozQ2CyNh4RovpNa6Y2QWGt4tCtuxSnRj
         cf3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:subject:autocrypt:from
         :references:cc:to:sender:dkim-signature;
        bh=tw79uVLAM/2x9J5KX2/xxfqgrgzSU9kfWD1g2HAwOCE=;
        b=dNcdPsRqIL9NsqAtdb6rBRwS+lr3stjG5ZITkB9lYJ/AtVkJ7mkALd+p2on/W2XxOK
         jegI/e6YPvL+Vg7gWgM3LI7ojIIj51+UBsLSUiGHV/6ATJF2uDWN8twV0ZMkrZXO23wQ
         NYAQU/PvzaHAAqW2KwHpIils3IijMaNytTFV09CLTOLGdqie0FvIOVIv9KT6i2CpKvAr
         TSU+T4zeI+INTutVIeJbC53E63r4Pr7CrSS8R7Tmd0yExvrklRJAC89HZpW+I6nsp7Pk
         PoXGX+0zZ0++o9n8BEXdFRg1Ka//qTbC+FlyBpJqYSvdBTP+eBrE6W/8YT5mMh/7/VB7
         2P+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of efremov@ispras.ru designates 83.149.199.45 as permitted sender) smtp.mailfrom=efremov@ispras.ru;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ispras.ru
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:autocrypt:subject:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tw79uVLAM/2x9J5KX2/xxfqgrgzSU9kfWD1g2HAwOCE=;
        b=eZet7pvgFC0uhL+93jYEbgFrxEXwOvBsq0JhOwC/Lwk5PFWdFGXmZ7gfvUqwXWwxhF
         6DW4Q1l2aUXs6il9StEdZ5xQ3ERtWwp083Q+9/auEcOiefaqnQ7023D0VtBtUP0PJ5SZ
         DTZnW3VapWRVXawKKqr4IkgSOqMGfOZo9AL1MN1MgkJWW5yA0um005lC4kM6GFwhU4cQ
         X/3RZwd+yNyQyBzhT9ytuo+Va9mZ5aDoZjPglmSHvv+ZaPpxUXB67a5aYubTSrrW55ox
         mAWvsoK1XtPhwLW5Hk4JjtRKfzxLYl/uQJj0bkVHBWFPc4UYHl8QmZ1+uj7GhlnyvJ2O
         VFUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:autocrypt:subject
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tw79uVLAM/2x9J5KX2/xxfqgrgzSU9kfWD1g2HAwOCE=;
        b=KFKOSiAGfDvC0uNm3YPIpbrAiOCE76u8C2kCkuw7wojbLeroT8eqTHUvL6NzKjGCUZ
         COrc/tnRkEJ15BnSGfUixHfzC9j6rfCTOpqRde9zbG8M3j/wWGC3WRK6iJO3QZ19QuHg
         FmKupMiOl6+z9FU62VRcPl6Ni2vz7qL43JCnUk2iIQhiDw5fc5BjdJ14arC1e5ipacGi
         YDRgwXNx9R9yCcBWMmPkvptSDVBpEq8OA5z5sYzfrH/topWSs9iZId6ZrX66eFgljBLU
         tK7JyVvZLK4JOuSQy2aQtJfU3zR0wTL5EjGUEa652yLg+GTGVq4gIrRGRti/0gFLwmNL
         fy8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ms/U4fxQRFKGHvpJGb1uTRk+WXEsskL8B8YSdbzQVYTCVcqqX
	HAnT1tFNDuyiuiYLAgkFsj0=
X-Google-Smtp-Source: ABdhPJx/12zpSm16tqAqnOxgZM2azO56s8v24KfH6Rg5t3S/aJpIzF3wt1QbLFN0CrJ/Rvi4tN70KA==
X-Received: by 2002:adf:aa42:: with SMTP id q2mr1254575wrd.360.1592429476189;
        Wed, 17 Jun 2020 14:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e510:: with SMTP id j16ls4701122wrm.2.gmail; Wed, 17 Jun
 2020 14:31:15 -0700 (PDT)
X-Received: by 2002:a5d:4bcb:: with SMTP id l11mr1238942wrt.363.1592429475527;
        Wed, 17 Jun 2020 14:31:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592429475; cv=none;
        d=google.com; s=arc-20160816;
        b=xFArQnPy426hPNi75vrCIRoHEnQTc53p/WJ8aQRg9LsxsyBzf6pgRa4G0Gouhf8ZVH
         wSpW/iIzMoRsPsQkrD6tDtYqWLMfRyMXSK5C0m0w+599kbe8QfzGePKyk0tMQWp9akxI
         59EmkF0PPBOXq9WDGLGhvvhJG9xG2+1yd54Joz2IGKc8Usiq7+yKaqW9cMeHl+0c5BYu
         k7GTiAKgwAKBt02+Y8GDd1PhDtGryQsQiGwGHhmcluYcwnGpvKStHUXyUkuRPAdLhJqr
         uhqz2LtZzMYXK7yWTy8y5Qx9DC/kaTeCoY/tOGePj8ete1NA0evxw/5RsG65ij5icEfw
         g7qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:autocrypt:from:references:cc:to;
        bh=RKUGEk6zj8LHdC9L456BsyYSoKpcBueo5EnIYdDtm50=;
        b=ZRI/kOFgXiExT0QexH9sWdeHZLzIfZ+G9MfAvZrW+qHSgwUMjdVA+oCjJlqf5L3EYO
         v0YvZmvurEGyjEwwKoU9eqMyV+lfEihQwHX5sQVSgXJ1HiJ4br/TWfok5yjzDGmtjggw
         6NXTHrmuYdblyEpD/WeC9eNgHjKW1dmZuPYFuX0EaTe2op/cxO/K3TibWxLg9V/x+ztn
         y3bHOIPRljMaLHoI+ZHhHYU0wXS83GJ9va6JGGQQEJA/389JYBN4xWr20F3qQAvMiMvB
         K8imYG0ikOKchH7waI7bB8NnPAqp7Erm4DjA8xwiQk4p1c/TFyv73s/i407qY9I3mhbm
         /slw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of efremov@ispras.ru designates 83.149.199.45 as permitted sender) smtp.mailfrom=efremov@ispras.ru;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ispras.ru
Received: from mail.ispras.ru (mail.ispras.ru. [83.149.199.45])
        by gmr-mx.google.com with ESMTP id l4si61956wrc.0.2020.06.17.14.31.15
        for <kasan-dev@googlegroups.com>;
        Wed, 17 Jun 2020 14:31:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of efremov@ispras.ru designates 83.149.199.45 as permitted sender) client-ip=83.149.199.45;
Received: from [192.168.1.8] (unknown [213.87.137.195])
	by mail.ispras.ru (Postfix) with ESMTPSA id 54355BFD1E;
	Thu, 18 Jun 2020 00:31:03 +0300 (MSK)
To: Joe Perches <joe@perches.com>, Waiman Long <longman@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
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
From: Denis Efremov <efremov@ispras.ru>
Autocrypt: addr=efremov@ispras.ru; keydata=
 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
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <17e4fede-bab0-d93c-6964-69decc889d7d@ispras.ru>
Date: Thu, 18 Jun 2020 00:31:01 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.9.0
MIME-Version: 1.0
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: efremov@ispras.ru
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of efremov@ispras.ru designates 83.149.199.45 as
 permitted sender) smtp.mailfrom=efremov@ispras.ru;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=ispras.ru
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



On 6/16/20 9:53 PM, Joe Perches wrote:
> On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
>>  v4:
>>   - Break out the memzero_explicit() change as suggested by Dan Carpenter
>>     so that it can be backported to stable.
>>   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
>>     now as there can be a bit more discussion on what is best. It will be
>>     introduced as a separate patch later on after this one is merged.
> 
> To this larger audience and last week without reply:
> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> 
> Are there _any_ fastpath uses of kfree or vfree?
> 
> Many patches have been posted recently to fix mispairings
> of specific types of alloc and free functions.

I've prepared a coccinelle script to highlight these mispairings in a function
a couple of days ago: https://lkml.org/lkml/2020/6/5/953
I've listed all the fixes in the commit message. 

Not so many mispairings actually, and most of them are harmless like:
kmalloc(E) -> kvfree(E)

However, coccinelle script can't detect cross-functions mispairings, i.e.
allocation in one function, free in another funtion.

Thanks,
Denis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17e4fede-bab0-d93c-6964-69decc889d7d%40ispras.ru.
