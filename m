Return-Path: <kasan-dev+bncBC32535MUICBBNND7PCQMGQENC3YQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E4D6B48E27
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 14:53:11 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-329ccb59ef6sf5262651a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 05:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757335990; cv=pass;
        d=google.com; s=arc-20240605;
        b=YGpp1ohJTlgMGo6JVYkUHq0Q0msB4NzkWPhsRo4bkwVvWqhA+yRoXZHM4s2/5sGbaj
         6kcSyUQmqOF2hSSfqGgz+lKLHA9xv++V8Vc/3b9eYWe2H2f+4YOgcgT7LD8lChchU7OM
         SoUTFmfKaUQ0tQZLWDGv9rPEi/CkMS+ULkQl4qAD00ybFoEnwt/troRGENqTZw62V1Xg
         PXtRZy8NEyAJiwnxUUc6kxj7S5O57ippcQ1NLedwqUx7YwNYJM2wLc919HFNOtUgfo1E
         nhq8bAEgmOQ+O45PehKBRbul8cjw61I5+wzx63aOTSzbe0SFlQZCW4jcmLOGtawNAxML
         Rznw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=KgmCy7weXKczGr9oEhpW2lupDRHD9uWzLBbnWZ4GRnI=;
        fh=q+6YhGfZLj+p4D8Cy8TLV5LKdI5J89JyxrC6zZQ1deg=;
        b=gwnlzYf6ZTTr/0qXF5cIJ/kkkVPiEURIgZWkUDv13VdWcmzztFCa19hK6JvG+EUSps
         X0ZpeiqoxSfXYCYyJEfqwK3Un2aV4YBSUk7hUYRhE/tQPGiJsKCTJOJtqQZ9rJns34rB
         hq4x4EYDGBUsgoiPodOH6UkXGQ0nggbd6E/rscfrDuTMAJQSD5QJjiOeMuHRKxV7B+ik
         Ucw2HrY+mVTsHLvo61CtCxOHqexlESOQIaAL6GzLZPnCxBMfsNjyv2ZzvgdVJos87irq
         7xNhXeskW2S7ND7vS68bMjct+CjJzCoqCxQSoUV4dXm3+FbVFcPNJV5zAR2+5WNFP2YW
         ipSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bnu3yxtY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757335990; x=1757940790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=KgmCy7weXKczGr9oEhpW2lupDRHD9uWzLBbnWZ4GRnI=;
        b=CPNoBrvPAuGKuiUqx/g/WPhtnU6aP5SQf7z8BJJVMbk8V8PrKAzxr+gcSqhHYqXV/P
         1iYZgsu1FT38Ij+cFiRdqiigWNjC5Obw9Ouza6zn0ZoXjmmRqAWyqlDYB4MJ12whkEto
         Ca06CrosZauCO5wsdM691MlezNTVm4xby4wpd8fdsTU/vkJZ2WLlnG+iuzTnp/4L5aFE
         pt+3rxP2r9iLXRr97qb1X5PDfu53INl/Hj8BKFpwjMQ0Iu6Ma/i9T9t0oShdJK7QTVeZ
         EFG2rYR2DFWUs7bN2N4iMvTLvlh2wShclWkClGT/qja7XFb25Iwth3phD+7byQ+Vme2Z
         OnUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757335990; x=1757940790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KgmCy7weXKczGr9oEhpW2lupDRHD9uWzLBbnWZ4GRnI=;
        b=u3HXLqNMWd60AAnTJDy0OKs900dfcyg6o0S1pAGxm34FVr2SEqcA3kvIo7ge/PXsyW
         zw+CBTx/b8fTIX+pG8h9ueXpqdGWp5mab1VfcT1qV6M4v4ZiX6sxhiiwar4Ign8QypFY
         jH1Mz9+lgz7YG0kLldViNjx72r7Id5wOs4HTSlP4QZUhnBk2CXMNQEgyh+x7RMJQNzlo
         ywx75zBCScBdCHQo4vMEAqn7XZ6WVbuJGeipc7eKu8Ds+eM4Oy56E1Jm5sewRVVOU1Mu
         LOyR5FWMUoXll+2z5ZUOOixxzP+2NMSz0PK4tVfjz1EgilgfvNn0qnYqnnhJtb8FZaue
         T3sQ==
X-Forwarded-Encrypted: i=2; AJvYcCXd01q2tE1256B4dcu2kE1ge2nEuAev+dFIspS3ii8CN2UJ+5MRq9/sUl2Myk7OawUsRYHmSg==@lfdr.de
X-Gm-Message-State: AOJu0YxkOC+FNxgdvvca+DKES4068lg6KTeIPxdKh+7jDqZKYq9dvuRU
	r8UyQi08sbycwlC8zEIUo3QaJgsEm5QnbbZQDYPOkvJEH/dxztkLwYTy
X-Google-Smtp-Source: AGHT+IEwSMcx/s+AJykgF+ZDJSNTySw5oGj48HKSgq0PqeeHrhdJPgV7xRTz2xiT/ZkEVIm+VIEQkg==
X-Received: by 2002:a17:90a:d444:b0:327:6de3:24b6 with SMTP id 98e67ed59e1d1-32d43f04f1bmr9631191a91.8.1757335989856;
        Mon, 08 Sep 2025 05:53:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Hm9zWlW3c13tI9QhevXzvPWpTU70+RSh6p4FxZRqVDQ==
Received: by 2002:a17:90b:4cc6:b0:327:d8f0:e20b with SMTP id
 98e67ed59e1d1-32bca9fbac5ls3850331a91.1.-pod-prod-09-us; Mon, 08 Sep 2025
 05:53:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWH9XqVRTqaYkTdv5SPaNuuws9wcz7KpS+ZduvCGMS9hw6CBhXafezV3Oah4c2dcp+MYFhRT6AIr4=@googlegroups.com
X-Received: by 2002:a17:90b:3f4c:b0:32c:38b0:593e with SMTP id 98e67ed59e1d1-32d43f04f10mr9458368a91.5.1757335988235;
        Mon, 08 Sep 2025 05:53:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757335988; cv=none;
        d=google.com; s=arc-20240605;
        b=VKtLLxWyjeaDN9+XE+L9tqdsPbgqUFLJvYIXa23Gkj2Fm7UHz8XIb3xeuPJYc6b2fR
         9+dIpk0kdjxZC4xG/9w3PuidagOyF48NULggaSbozAeXA3E4+tECJ80SZF9mHyHiZ8tZ
         LLlpc5DelN/fPe9bkbUaVcGRsdUukca9W55yzbHloDjNXpFR1zPL8NcOIYxoLvL9zAhA
         rBKzoqNIzVf6GVW6owSJaG7Ulzqj9qTV7D3yRxqEHaYorHakCMhY6HkcC/SWB3la5ljY
         8wIditc1FPjntGF4yK1ET3MAz2q1eu5EQYXiRUewU5w+QaJ/lcGPKIi1z7Pgk0P+lzG1
         6QSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=nqKqSNT26uK0ctF10EJrKeCsL0Ppf+8ee2pPXGgNN7Q=;
        fh=HZWSHoX7oRCf713W1UHUzjIFbwFXPXSso8Z20EdlJZE=;
        b=G9ksMQ4PwQBvPHbDQ7ZmwrEKqR3IogKEmC9rYG5gzF8l51r0PYDNSza2BIUZOiPrrF
         zb7//MlpqT20frBKfEHLRj1hrcPhC9pokyGoCr/mYxb2/HrrgIoY39oLyj0G127dzOuA
         kjFUT8bGBmSqhjpO9VAVWyaLa8FNw3SlqkXGLkj5Iz2DuZVW1Cx+FVWDomECkvH47ApP
         XAWljvp7cgeH3z7H5/ll3PmE330KPGqFK30hfoTyj50V8o2n+sC5oSohNVWgFJboJ3HT
         nlLhxJim71KR0yaXpH3FfJoKA4mTw83qxSIurFMuYh/kfQvxihdoNQi5Ys4rcv3ulHHP
         OpHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bnu3yxtY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b91305464si571480a91.0.2025.09.08.05.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 05:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-561-mienWj5nPIq3HOUPZjwsIw-1; Mon, 08 Sep 2025 08:53:06 -0400
X-MC-Unique: mienWj5nPIq3HOUPZjwsIw-1
X-Mimecast-MFC-AGG-ID: mienWj5nPIq3HOUPZjwsIw_1757335985
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3e38ae5394aso2512564f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 05:53:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVk2MztR5D+C83LkeTfn01yK3YdkPicyoNeF2kZArmQItEvMe9ycxiF/Pvk5ZoxDlHZLcjFQbehJE4=@googlegroups.com
X-Gm-Gg: ASbGncssr5Xn8eaMoVgzNOkZiJbRlvgJX+u2GdEgDLZ4l5tNE+RZrEw0YIkvngnR9Vx
	5feaICXG+JBnBlf9MRLpGA6A2Bec0sgasFNqlFTHzO3+J8Ya5FxzE7zoEk/Hz9LM40TyLCyzCPh
	yYdqGFgbRXyV+yeijy3uevHr9yGBHrIPEagBfN+hKnfy2ckJSOF0J7b7BYsfP1x/XK9QVMsQpsY
	77kRiqshxKISs7+6ixsjAdQLnJQT3h8lFGHvYCg2ztbzZj9THNm1CN8jXLmxTUx5msMeAlShl8b
	T0DsK5FSUMZzoecflHHSm6rpCAZjpAW6WDUEPupNRQZsLpgQ1E6cpmtndevvVPXkUgBTOL+ih96
	Ka/Nx5qe4Ct6TaE9G2SzZWacJ94M9ZpnAR3v+ZrydH2DsWzBbIb5Mkm7Edq8hZTkg
X-Received: by 2002:a5d:64e4:0:b0:3df:58c5:efd1 with SMTP id ffacd0b85a97d-3e6427d6e15mr6188422f8f.25.1757335984537;
        Mon, 08 Sep 2025 05:53:04 -0700 (PDT)
X-Received: by 2002:a5d:64e4:0:b0:3df:58c5:efd1 with SMTP id ffacd0b85a97d-3e6427d6e15mr6188391f8f.25.1757335984032;
        Mon, 08 Sep 2025 05:53:04 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3d1007c0dc8sm40030772f8f.53.2025.09.08.05.53.01
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 05:53:03 -0700 (PDT)
Message-ID: <7ee0b58a-8fe4-46fe-bfef-f04f900f3040@redhat.com>
Date: Mon, 8 Sep 2025 14:53:00 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: John Hubbard <jhubbard@nvidia.com>, linux-kernel@vger.kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
 <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
 <727cabec-5ee8-4793-926b-8d78febcd623@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <727cabec-5ee8-4793-926b-8d78febcd623@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 4rhU3jAKdMXcEck1WF243lrGCcsuJYPBcCjBYxB0i6E_1757335985
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bnu3yxtY;
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

On 08.09.25 14:25, Lorenzo Stoakes wrote:
> On Sat, Sep 06, 2025 at 08:56:48AM +0200, David Hildenbrand wrote:
>> On 06.09.25 03:05, John Hubbard wrote:
>>>
>>> Probably a similar sentiment as Lorenzo here...the above diffs make the code
>>> *worse* to read. In fact, I recall adding record_subpages() here long ago,
>>> specifically to help clarify what was going on.
>>
>> Well, there is a lot I dislike about record_subpages() to go back there.
>> Starting with "as Willy keeps explaining, the concept of subpages do
>> not exist and ending with "why do we fill out the array even on failure".
> 
> Yes
> 
>>
>> :)
>>
>>>
>>> Now it's been returned to it's original, cryptic form.
>>>
>>
>> The code in the caller was so uncryptic that both me and Lorenzo missed
>> that magical addition. :P
> 
> :'(
> 
>>
>>> Just my take on it, for whatever that's worth. :)
>>
>> As always, appreciated.
>>
>> I could of course keep the simple loop in some "record_folio_pages"
>> function and clean up what I dislike about record_subpages().
>>
>> But I much rather want the call chain to be cleaned up instead, if possible.
>>
>>
>> Roughly, what I am thinking (limiting it to pte+pmd case) about is the following:
> 
> I cannot get the below to apply even with the original patch here applied + fix.
> 
> It looks like (in mm-new :) commit e73f43a66d5f ("mm/gup: remove dead pgmap
> refcounting code") by Alastair has conflicted here, but even then I can't make
> it apply, with/without your fix...!

To be clear: it was never intended to be applied, because it wouldn't 
even compile in the current form.

It was based on this nth_page submission + fix.


[...]

>>   }
>>   static int gup_fast_pud_range(p4d_t *p4dp, p4d_t p4d, unsigned long addr,
> 
> OK I guess you intentionally left the rest as a TODO :)
> 
> So I'll wait for you to post it before reviewing in-depth.
> 
> This generally LGTM as an approach, getting rid of *nr is important that's
> really horrible.

Yes. Expect a cleanup in that direction soonish (again, either from me 
or someone else I poke)

> 
>> --
>> 2.50.1
>>
>>
>>
>> Oh, I might even have found a bug moving away from that questionable
>> "ret==1 means success" handling in gup_fast_pte_range()? Will
>> have to double-check, but likely the following is the right thing to do.
>>
>>
>>
>>  From 8f48b25ef93e7ef98611fd58ec89384ad5171782 Mon Sep 17 00:00:00 2001
>> From: David Hildenbrand <david@redhat.com>
>> Date: Sat, 6 Sep 2025 08:46:45 +0200
>> Subject: [PATCH] mm/gup: fix handling of errors from
>>   arch_make_folio_accessible() in follow_page_pte()
>>
>> In case we call arch_make_folio_accessible() and it fails, we would
>> incorrectly return a value that is "!= 0" to the caller, indicating that
>> we pinned all requested pages and that the caller can keep going.
>>
>> follow_page_pte() is not supposed to return error values, but instead
>> 0 on failure and 1 on success.
>>
>> That is of course wrong, because the caller will just keep going pinning
>> more pages. If we happen to pin a page afterwards, we're in trouble,
>> because we essentially skipped some pages.
>>
>> Fixes: f28d43636d6f ("mm/gup/writeback: add callbacks for inaccessible pages")
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   mm/gup.c | 3 +--
>>   1 file changed, 1 insertion(+), 2 deletions(-)
>>
>> diff --git a/mm/gup.c b/mm/gup.c
>> index 22420f2069ee1..cff226ec0ee7d 100644
>> --- a/mm/gup.c
>> +++ b/mm/gup.c
>> @@ -2908,8 +2908,7 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
>>   		 * details.
>>   		 */
>>   		if (flags & FOLL_PIN) {
>> -			ret = arch_make_folio_accessible(folio);
>> -			if (ret) {
>> +			if (arch_make_folio_accessible(folio)) {
> 
> Oh Lord above. Lol. Yikes.
> 
> Yeah I think your fix is valid...

I sent it out earlier today. Fortunately that function shouldn't usually 
really fail IIUC.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7ee0b58a-8fe4-46fe-bfef-f04f900f3040%40redhat.com.
