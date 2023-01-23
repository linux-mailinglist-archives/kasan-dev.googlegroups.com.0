Return-Path: <kasan-dev+bncBC32535MUICBB7ONXGPAMGQE4PFZ2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B637C67799E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:52:46 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id u9-20020a544389000000b00363be5d9f42sf2947580oiv.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:52:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674471165; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMiruwmyHabktYOx2tyy5eJe09yXiRmPGkfrGnIHEwaCtFHTyOOqlgRAsFWG38UeBy
         9QVdGSCsO8+QG7rpQdQnIOlJMpALVcOaJqTgpWhCt8bq3hV5pNx5IEw5Io6aobD+R3xd
         80khxwK3hIymd4FSPJXEo4Sxg93rqpBvGQwVpwqtmrmko2hihpKs/yxHMcHNt7+GQF7p
         YKTCHDxlNJrCACr8TA7sInMzz+9yfnbQeWLhLyCoYnoCvefsirgtPj4IkOGCdfjP1W66
         4jS9URjvNyMIHsLYvv5dfdV02dDYHdb63rSt9Xc0nCQpOpT2saBfCty7gY0n7OroyZDr
         wq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=qjjPjkv8xUf90LgL98Wh3BOMB4rgSvBJcA8QPfP4XPc=;
        b=C9llcVTuxCBDcxaB1lO6w8c2C8SClT7ha9mTy9CTyo34sfNi7IdWwmUKH4H/HSPkHa
         tF7upLbAdtC3P9JT75ZQAARyOuBkbkYYKiWjlFsFlw0s/o4Fvv4NgWdNxBfFaxYsFvZJ
         r8ZyoLN7YPli+kiJyAKf9Seh3y0wLON0yPLLFj2AIbdgHjZJNiwVjPxwimRJF15Sy5MS
         pl7ByMkcPrrAf0KIfX1x4XoOdEFnINvzh14YkQAvzPXhzOe5FKulwuhvyz8gTIUkqzDB
         R+Kc+B78z79vj0+1HPGHxnezflDMESjMt0Yu+oAD3J2lwV08QVBYXqB6q+FdUmkrtb0e
         59MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EFaneoJL;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qjjPjkv8xUf90LgL98Wh3BOMB4rgSvBJcA8QPfP4XPc=;
        b=Kl+MIkqjPHcUkIDQZh9ra+g4KFwgWvzrOs4UrvvWpv2fD3SE1Yo+N09KpmXh+NEw2d
         2tQtEdhUPanoBTro3qeGhAmQ7iSV3/ROhndILiqR7/H641Odah3sTZT0VRHyuBnO2XnR
         J3pfwC8Lb3EQ8bKkI9GppRQrlKBAKQW83M+QFbmyxRnSYuJ90NyYKf2FDRjA8jdC3nvN
         fDIcOj/rx1FqSFz0id0STAWBicLQohyN0KfNRvOEavEJNEuMdulHFdhdEmwLBY3dKJnF
         tkpo+vocnI0KFfIfVj/l6kVDjXW0zrcWVEWE1vcako8uFyMgHv+y78sSCkWWtz3LhUdo
         0AHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qjjPjkv8xUf90LgL98Wh3BOMB4rgSvBJcA8QPfP4XPc=;
        b=r+cexiqZbpLeyRPLd0nzk1Hb+bM4I8SeNL/DBsqB7vkY0C+K2fPCfw46W++meYLEvE
         b4sIYzC6wEeZq5b2rVYcK1uhhyt0abMuPq/FamgNOI4bPpxi3DJJlY3zZWW5F+G7hNlW
         0aZy9ek28SSVkM/ygDPK/TqKc7Y/g4UsVTsDvhj06rh71PRnlPBRSgz5grTp1RlEThTx
         dPHr5VEjz4yvBs+g5n/JBw9kvVt4vzn5wMFHNfvQB4zgurlEM87j7oM+QBbw+gCkoU4b
         oaTcLpP8iN01SFyXq/W+8UGkJPjmNAnbfQnupJKdw/Lp6RVIl9GFpkhcUba8yDiAbOlG
         l50g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kplgMy6+YueAofGwxs1RaENE7MF/4FA5pADvwrJrbEgPUHxhB2+
	maOPDcwNCtxXTgM//9UNWr4=
X-Google-Smtp-Source: AMrXdXurlhwhPixAo2J81LtOKZiEUO8YS0zzEMVB148jEOXwpgW8Er/mHLjQiPp3pkmwLIEbvE0kJQ==
X-Received: by 2002:a05:6808:6147:b0:364:b767:6b0a with SMTP id dl7-20020a056808614700b00364b7676b0amr1056669oib.167.1674471165471;
        Mon, 23 Jan 2023 02:52:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:601:0:b0:36e:b79c:1343 with SMTP id 1-20020aca0601000000b0036eb79c1343ls2353082oig.7.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:52:45 -0800 (PST)
X-Received: by 2002:a05:6808:11a:b0:364:ebef:819b with SMTP id b26-20020a056808011a00b00364ebef819bmr10903612oie.28.1674471165037;
        Mon, 23 Jan 2023 02:52:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674471165; cv=none;
        d=google.com; s=arc-20160816;
        b=OGBDT/eZwS+ZJTiNmp0A6tBGXfECA+7aV369FcPvEcCbJPE8xXSkhj2QsITca5n06H
         VAgUY7OgbdGsYp/cMzRGctZwle1mLc2X3x11n/OTWqszEijbieXCvBkXzO1EE73OvcjR
         I7h0NvjpeGokHu3G0t2cyW9oEy1PZ7WJIwrqJF173b9Iub0pf5utqFE0PFJkn+/uWm48
         9Vost0sybQSGx+HmPiJJh3StOrdP1Eij4lQ3C1cJpUgVqxNsLC1H/d5O2fVmJ7Tn3aYQ
         Vs+HEt08UZMU+heXxlMc1MdgaP+opEU++SRt6He2HJbtAitSDeTzLvM/eq8QtF/+WLkY
         YGAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=uyQSX81TV4iPEZmzzjjJSEQn2sgfl/lM7Z7oXwXQWbk=;
        b=vykjhMDJXNxqAKoDjcsWOi+QWtErxhchOcCQh52w3t8A3jwE826oV5o/NQ6Nvuf+WL
         5GwV10odoP1stQGl2KGvFn9n0yH3djWO1UHnP3JgBfCUVn32OGrcivdTRM9vaJvPKBVW
         a01UpghxGX6qAblgxYZDMSdcWKN/B4ya64nmqyaJf2dkbR1tAXB3gLU+ZkfrDer7cfqJ
         vW8BbpCx2ZoyV0tk2EmXjHjdydUmaHwM4x2P39B2ZemccXR8576oeXCCLFMwuC7pW4Co
         I5YeTKwzc/un4yyDAhd8rBrdcvpoWGx3wlF5pZTXknbLx6c6aHIHmn6iupdS5SGTZcHL
         IROg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EFaneoJL;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id z64-20020aca3343000000b00359a21e3ffesi4207048oiz.2.2023.01.23.02.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:52:45 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-627-XeCwNfjGNsCMGY0WCUm9fA-1; Mon, 23 Jan 2023 05:52:40 -0500
X-MC-Unique: XeCwNfjGNsCMGY0WCUm9fA-1
Received: by mail-wr1-f72.google.com with SMTP id r1-20020adfa141000000b002be28fd4a7bso1893565wrr.12
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:52:40 -0800 (PST)
X-Received: by 2002:adf:ef07:0:b0:2bd:df97:13e7 with SMTP id e7-20020adfef07000000b002bddf9713e7mr20604746wro.65.1674471159628;
        Mon, 23 Jan 2023 02:52:39 -0800 (PST)
X-Received: by 2002:adf:ef07:0:b0:2bd:df97:13e7 with SMTP id e7-20020adfef07000000b002bddf9713e7mr20604733wro.65.1674471159367;
        Mon, 23 Jan 2023 02:52:39 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id n8-20020a5d6608000000b002423dc3b1a9sm3849375wru.52.2023.01.23.02.52.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:52:39 -0800 (PST)
Message-ID: <1bd0430b-2270-e554-5db9-ec670167ca25@redhat.com>
Date: Mon, 23 Jan 2023 11:52:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 10/10] mm: refactor va_remove_mappings
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-11-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-11-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=EFaneoJL;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> Move the VM_FLUSH_RESET_PERMS to the caller and rename the function
> to better describe what it is doing.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---


Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1bd0430b-2270-e554-5db9-ec670167ca25%40redhat.com.
