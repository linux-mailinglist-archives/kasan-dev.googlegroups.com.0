Return-Path: <kasan-dev+bncBC32535MUICBBOVJ7TCQMGQE22ZJZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E87B4975A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 19:39:08 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30cce8e3ceasf7984862fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 10:39:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757353147; cv=pass;
        d=google.com; s=arc-20240605;
        b=cNC0mKMBJ/cYGs35FP+DoClx7E7giT5TziCaB8yZye7FQVDzwi0Dg+rRQ+0xztZ9uS
         rMl4G/Kej5zF8hXVcL44dpX8w/3L/zpbUJet7QDwPX2jEPe/LCiZzePxwcFogukDByBj
         BXT9uhJlqX9XcNWMQrq/MYaVPKIJKDyQdYjoXhXjI+E9fDD8lEm1j19wUN5O1xEEaOzm
         n5r5TCq47pu8LldtcfSJ2qjLjX9SHs6hfEafwB9S+TKtbcB08Ynsw3xpnh+KhXlPEUU/
         bCFBH30m3jw3FZQFuP4YRztt+LOEWBwUu778aogE2nRHS33zWIBj0FpRYK2ydFHJV5jx
         Ax/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=VgrAWyd7367oCyThfdrG6uWI9bJTpHA4GHI62ivu1jE=;
        fh=SYvK81J1TnIuKs3MoNXAegBMSimhmDMDuwvDMkOy2wY=;
        b=EyZEwMlc9DRHGX9geqJKBL5OGlbtz7xwRYmbLXyylXh2AIfJKuBGAnnhrYL4bGXBiV
         3dxR50ALsNGDv8WXJXX1R4tFYPFAON1WlV9t970+s/EZevZNfA84Yc0DuISrlPmdqSX0
         HqwjntlQqUxkDHUKWB7Fg4637qwNs6TEVXoHsEfQqXegmedpvewLYsWFlwWp+y4pREKv
         +bp78Yv3s7YkHIDzglG8VivvAzzrb22VD28fvKmL6wJhPc92sh+d3QrkwuQ0EDBS2yzG
         Mvet/duO5pxq9Eh1ePkjME+0kHzJ+AtWMqUkWosbGjHSgI8jvv0izf6nimcFoAznrkED
         LX5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fK27Frs3;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757353147; x=1757957947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=VgrAWyd7367oCyThfdrG6uWI9bJTpHA4GHI62ivu1jE=;
        b=SLdas6HfqO2J1Ig95pMogzOhSA5cJU2xSr1Z+0Z3+J1vWk1Ou3HT8vtCX9W4rNLuag
         8LEdJYFfpmYFr+PvdCdcgxf9/1HmTcLHSnZKs3d4ZOYokH/DroewoiQm6g5RDxHSkKyx
         w5W2JFD6aAwbwrgNFQ4Izf78ixq52cHDIhh+y3V5RH6lUB+vANNCZCT2nXOE3Muey6+X
         8wNOTbjkXwmh7NrAFpvSyJeft8beFrmPGtsTLBLeuo9mY5/yqfEk32aES3SQ2QH4NBpw
         A0xcegnSPIf0/HuSZCCPfP67z7rKYA7hvuQM3QrveA9K+1a4aAv+nYKHyzAjeRM0TCep
         9Mbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757353147; x=1757957947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=VgrAWyd7367oCyThfdrG6uWI9bJTpHA4GHI62ivu1jE=;
        b=BArpUknRAvfwFBgEnztFOXHQLQqNOKLn1+pDDpyjpQC9CsZal7l6+17YOAfoje+jn7
         9cZlsR/sceerZI+Fzm6/HQ4rF46sEC8vdb16ulTWYiI/o24YJK5CsdwOTRtdkP7jLMf3
         H6kZXgpcJ2Id157YtaD2Ii2iKH2AcxlGRS4h7kiwJF5aPdTjNoNYHJtWbYNyg7aI9bFW
         SO+m/Rp7JiSuKTu6AjqkZ66QKHw6MDy1O1Xk1BziTrQ4MEy34lKDLC65BjkhMJmkBDOt
         H5gTKW1mRHSKwaPzWWX81Fr6ogMTqGxYvBwvpu0McX9m9Qsp42m21XUMgAw6Ny6eJgS9
         b7tw==
X-Forwarded-Encrypted: i=2; AJvYcCUPOWAoNSqSDpT1B63lcTRy/fBnFIp1kvsiaBNHv9KmurNb+/uVGTIJ1Rw5NPjP89b8ZkQt7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxbz4GWwd9bFd/i6cIe6kv8jWR3yyP+uewyR7QMYyw6l3zuhqGf
	DLjaDMJONUo7WqzPUVufeAIVHl/RitCZElaF2ZstAViOcYUI/pBIWsno
X-Google-Smtp-Source: AGHT+IFp7faZdRvN57tOSOOgCBLS9f+VZdxY251YH+tLPhhcAeMH03f65UIy19MSjynIbFFhEzmZeg==
X-Received: by 2002:a05:6871:a6a0:b0:301:a704:ef1c with SMTP id 586e51a60fabf-3226480eb24mr3836547fac.25.1757353146823;
        Mon, 08 Sep 2025 10:39:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7pyrqTqE2vvYEWqBFW6QDosn2OnCU6cNOGM9e1DFLcmQ==
Received: by 2002:a05:6871:291a:10b0:321:2522:a7af with SMTP id
 586e51a60fabf-321272b45a0ls1472941fac.2.-pod-prod-07-us; Mon, 08 Sep 2025
 10:39:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2T8kmnGWBj0areqF6SAKPjdywplpPzWfVEVK8iJ/FB7fyGqOZllKpld9i8Q2r7JGJmF76lCjVeo4=@googlegroups.com
X-Received: by 2002:a05:6870:b4ab:b0:319:c75f:5e84 with SMTP id 586e51a60fabf-322627424a2mr3711901fac.9.1757353145793;
        Mon, 08 Sep 2025 10:39:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757353145; cv=none;
        d=google.com; s=arc-20240605;
        b=MR1yax8cikDyFVrFHEqsmczaLsNPac8PWWEUrseDyAdvan8vY7leyQvWXF14r/Vuml
         C+9PvL9+wflISkwzfFa9HABo1Io35xmKGb/JgFXt/P8BIlvxaN0IpR7rKiPXF1QyP1c/
         5rqn/pA2wRk6IUGVh8m+2ZZgd6cK+2wQEQ9zS/cG0FC9ZCF5DUic5ELqMcFr9/cKuXqn
         h7usq16LKyUu9Uto09Dv3xcCPR9wtT4TToRcgtnk9uIXpWuCIXhN0vIChTU+wzuc1nU9
         wcqBbOuimlYjW9Bfe0hnbsjLzxf8eJkCaTLMG4azZ2QXSskKtlf2o8rvU49+lgHIILg8
         FJ+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=3P5EwsaOJG0kp/tyGnSgePetI5hCYz4arKjA4KqYxlA=;
        fh=LL1LeWdg9e4gN6mSohmwA7cA8619KES/O6mnKc9I88w=;
        b=cUDhUWzrdOrEwOEb2EB7wtMt/Tc0QoZ8XuJJgzNQLuIxN5bgH6ka/6s5xYKFYu53Ho
         qtulkEIs8i0/ZysFnEnuP6thRpAABdDBaVoTnk79JFNfz8cGW3BRBN0+2PggGzo39UjP
         aM7VoW2malI3hA+zFQdQ0JLAq6nbTOyqxLTZNzAQwq6jPbsf7emjEblz45W9hPmpLl3d
         HJdCgH78USzE9hu2/wz2SgC45HvjQzK1p5AD7YxEEaIQVbWpmRBbKeTH9dpXFj6lbFzj
         eFsPKADi3hJcb4i/M5tOYT55583pkNlOtCBq1juGHHSpnb5Hl79KSRKJBUdMY/0rUDzb
         Td3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fK27Frs3;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74ed2626a9dsi176982a34.4.2025.09.08.10.39.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 10:39:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-477-dO2bm-aYNWexoaNOx76evw-1; Mon, 08 Sep 2025 13:39:03 -0400
X-MC-Unique: dO2bm-aYNWexoaNOx76evw-1
X-Mimecast-MFC-AGG-ID: dO2bm-aYNWexoaNOx76evw_1757353143
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45dd66e1971so31516495e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 10:39:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVtgn/UwP9KEHzej77w0HH2+ijP3h6EEubvYzjYbUShINpP0wz/pyFHBMog7LlOVJc+FlON23Yeqac=@googlegroups.com
X-Gm-Gg: ASbGnctwkEThsucZUmxvK/AENhHyqqgwQW3r9dEohRsD7x386JLrhTjY7O76yaNGTaa
	JAOmP4jGs0jPd7RXi+mkptmsej8SmmDbjTFir6KlGDa2Qii6PFOwB760YAVynuid5w+5Z/xp+wH
	K5E17Yz8i4RMroHa5cfBHa2XZvdk2S2UZk/3NsMVq7t+BZmjDCRu6AVmEm5BIYnFC3zBz9+mId+
	UDACa+kjUSdz01LfiOeJBWz1Rbe3710MMXrcLeBGetfFhXyQLfsZpLBcGG48QhgS58NSu8yKwvu
	aFd05xrBQXka2fhVFaXMtSnXlcaujLktAuYCBrU3R3ScHoZLTSQWmTiMnt+KZ7cW3OjWrhcGjMx
	94FOIzynf+IeV2HpvC+C6ko4jOuhaYASuRWOXV/q3NH/qruSFW+drnY22d3XRennz
X-Received: by 2002:a05:600c:1c9f:b0:459:d3d0:650e with SMTP id 5b1f17b1804b1-45de870ac82mr30366575e9.13.1757353142601;
        Mon, 08 Sep 2025 10:39:02 -0700 (PDT)
X-Received: by 2002:a05:600c:1c9f:b0:459:d3d0:650e with SMTP id 5b1f17b1804b1-45de870ac82mr30365735e9.13.1757353142034;
        Mon, 08 Sep 2025 10:39:02 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e92a42asm450957385e9.20.2025.09.08.10.38.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 10:39:01 -0700 (PDT)
Message-ID: <225a3143-93de-4968-bfc5-6794c70f3f82@redhat.com>
Date: Mon, 8 Sep 2025 19:38:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 05/16] mm/vma: rename mmap internal functions to avoid
 confusion
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
 <07ea2397-bec1-4420-8ee2-b1ca2d7c30e5@redhat.com>
 <a8fe7ef8-07e5-45af-b930-ce5deda226d9@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <a8fe7ef8-07e5-45af-b930-ce5deda226d9@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: zLKhQRzoIQ42yxXQOJgCjgiLksKpeA7pwd2o7PfpVAY_1757353143
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fK27Frs3;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 08.09.25 17:31, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 05:19:18PM +0200, David Hildenbrand wrote:
>> On 08.09.25 13:10, Lorenzo Stoakes wrote:
>>> Now we have the f_op->mmap_prepare() hook, having a static function called
>>> __mmap_prepare() that has nothing to do with it is confusing, so rename the
>>> function.
>>>
>>> Additionally rename __mmap_complete() to __mmap_epilogue(), as we intend to
>>> provide a f_op->mmap_complete() callback.
>>
>> Isn't prologue the opposite of epilogue? :)
> 
> :) well indeed, the prologue comes _first_ and epilogue comes _last_. So we
> rename the bit that comes first
> 
>>
>> I guess I would just have done a
>>
>> __mmap_prepare -> __mmap_setup()
> 
> Sure will rename to __mmap_setup().
> 
>>
>> and left the __mmap_complete() as is.
> 
> But we are adding a 'mmap_complete' hook :)'
> 
> I can think of another sensible name here then if I'm being too abstract here...
> 
> __mmap_finish() or something.

LGTM. I guess it would all be clearer if we could just describe less 
abstract what is happening. But that would likely imply a bigger rework. 
So setup/finish sounds good.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/225a3143-93de-4968-bfc5-6794c70f3f82%40redhat.com.
