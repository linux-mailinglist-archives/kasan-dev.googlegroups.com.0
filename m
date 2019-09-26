Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBQUIWLWAKGQEARKZOFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E7763BEE67
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 11:26:26 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id n3sf881906wmf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 02:26:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569489986; cv=pass;
        d=google.com; s=arc-20160816;
        b=yX5Lic+nd/3PljATg4cAn0KdMmVCqaRej84Qe5BmOsbQyztUHjXlgRr7yC8ZIHkBzL
         jM5tnkg/jRLj30uBY04dQ06Ts1jG0Jgeu8xz7YIg4Z74t7SO+XjHclo1FBYGyw+CT2sj
         i3lP5jqkJHQOuc3ZpaRwhtEw5NCZmGOBaT2jpIdyS50D7S47zo99Lc52zMUpFmBXmxeK
         9wEWA/CI3h1FTdZ7mo/DWFhGn1kAZNVFIXr0zXvQxpnP1ysd+SuU7CmeFb3T3ucjUPIe
         N+K/hSRok+tSWrIPmnjW6ebvUTTqa3FQmv4P5SovFiqC35CuFiwCkL7r7WZA/53+mzcj
         u/Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=MB41XP/eMchGVRaWY0MSsKG62BHdNUgznVX9v6ZUrok=;
        b=qJHpBGtRukO1+1gb3WDCKIPQGk3wj9ffGR4OMBubxVLJWTW559UfnJv3caYRBD5dyX
         SCj/2TxYxs2LFkIcs8GKUDsPS/KPjF3McE7KkaG/nTjPnbEWJ+OzY7sidGdqO4AZYiL8
         L5fFV1rWUhbVt7RdXCBFoagdVgVnSQGcQLtVecehofd9rqDG1Kb1PhkzblemgV2KhE1n
         cBsy4dqnXoLrJ1uTK8zCmBHB3WgNwQcaFfW4A2E4aYWeMezsH+rKX0F2MFkE4qEDoqkh
         IeF9enMxY0fxXLaat0GPh44lZXtvOdxJHG0vAlxW+F2Wrq+Mu9uztHkw26gnssvUVloo
         UFSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MB41XP/eMchGVRaWY0MSsKG62BHdNUgznVX9v6ZUrok=;
        b=BFAo/2E7hWb8p7Pu7TKYFv8VlfLAma3LdjGVDPYt8PhFz+8IFQkYpy9Cloa0MfL7BO
         wlvrIuBNlHVmuSfXuGWChVT2/41FZDoYY6dyCFuyoDx2OIM6OuAna3vkMj5v9Yi0+/1x
         b1M6qvA5UNA+OH7ZWBtW7M7XxEsby7wTijyPFmIA7xFusPy25Zg6zGHYJJvvyxqh2XHL
         bgp7ZyL+aeUMnA2IIjpYENM04DWbpNLLWkLl8VbEfvbt8mTiJvXnhYUzzDB70ZGw6RsV
         Cv7HuSAWubYxgiuQHuU31Atlrf8o5APjeFG3vwaHSZmHav1kqcF0q3s88iti+yQAVG7n
         LvDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MB41XP/eMchGVRaWY0MSsKG62BHdNUgznVX9v6ZUrok=;
        b=dj9qRdYX4TEwRCBbFyAtQnz6iUzveDTd5hpOGN365V7FM2e9a6vtTivnZuRu/myrSp
         B59MUxGUQoH+axwLYgNzoQnChv5DZkmJQnhcd4xmP0GwmlmEv1eaayHpVeaM3D8JMp6K
         Myko0MNvWsXTMn0jGDvpS4rkXFcLxwNj5vLmY4cgLIU5zDuu+ekLK0uYExUp3evQQPl6
         DMFoiPUM0SdK4AHp1kNtK3VADDSlfV0zBULPihTiwXcr/oELDM7GokfA1B+EEkWhHCYC
         HpQo8m4vc4Wt60X9MUqYE20ZCiQiqYZqdS1iUSRhdiJtkzgvgGDVrMiYXqliuYV7cgH3
         Bqfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXyZ3Uv85k6NcMQLpjuXkPyQEAqc0mW9yuBexZcDV/rJx17NwpU
	dA48HWpxbNvwvoNKVC5cCk8=
X-Google-Smtp-Source: APXvYqw1xeLkx9WxM22pQq+n2Oh7HRAAY76l4Ionh28DS6Zn4oYCSMJShvc9IYmYWoh9r0ZUmzDjbw==
X-Received: by 2002:adf:fe05:: with SMTP id n5mr1245112wrr.355.1569489986594;
        Thu, 26 Sep 2019 02:26:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbda:: with SMTP id n26ls630327wmi.0.gmail; Thu, 26 Sep
 2019 02:26:26 -0700 (PDT)
X-Received: by 2002:a1c:c1cc:: with SMTP id r195mr2285435wmf.50.1569489986009;
        Thu, 26 Sep 2019 02:26:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569489986; cv=none;
        d=google.com; s=arc-20160816;
        b=rkQ2ytK9nbyHBEgA0EuC1G7yCEkkYRbvp/4kzDUDM3WOxiBXc4EUfd+yALsIe6kcOz
         UYAhP0irmGNcq1i1N81ZkXvxQ+vH2zmpq9aDAeL22/H1shJu1HHHjBEue9ZGABA6xaUU
         zqw0pxk4Deh8qMjbGp9pJRPgt452kyrrZ0wk9x0XxC3Z1B0MbKIYpkR+WHk9EBHno5PC
         7J4HV4KDq2Phj07d7MF15gC0mfshykTGN9V+2um6GKCbMQAlxIZtltCFUVHotANX5adq
         JZG9mBkBIYmlaN1CLXPykNGokmVT8KP+9P70C7EV/DoRwszLEWIogXrofwMLuJQIlsXq
         wQLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=tYGl+PMk3vy2WEja1yebZBa8k7qNhFqW7YN1d0URQDg=;
        b=Vg/qtY2cI3qVAnjaYxe/toE1S93HHt+8HETFcJov/3yy7Y3ktWn3+SlHIQZ7KseFnT
         gFDoZeUYdI596j1tHY9cXDiCTI4Nb65tE9CkzaIHiYHrJr2YTmyHdm2aeZhLcDvDdYW5
         nVWCROibLB/EGaI5vXy9h8usfQqjSYYTLGuTy31PiSs8z50GlZhrl/f8CyFyVK/xqKU7
         O8OpXzPYy18Ev0wCLt253ZUGBSSc9eCtqyN733MFTTtT0Tuql+sYx6BIPttUQfKCNY1t
         8g2dqix2z4cONRHbtSBk7I6AnOjnmmYhN6uQFJ3j81wlU70y9RD+LhMTBg+PCQDWBZCM
         cB8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id t15si79383wrs.3.2019.09.26.02.26.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:26:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 2E23AAC10;
	Thu, 26 Sep 2019 09:26:25 +0000 (UTC)
Subject: Re: [PATCH 3/3] mm, page_owner: rename flag indicating that page is
 allocated
To: "Kirill A. Shutemov" <kirill@shutemov.name>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Qian Cai <cai@lca.pw>, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>
References: <20190925143056.25853-1-vbabka@suse.cz>
 <20190925143056.25853-4-vbabka@suse.cz> <20190926091855.z3wuhk3mnzx57ljf@box>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <f3d5425c-a833-0c14-3d88-3b7fbab47e5d@suse.cz>
Date: Thu, 26 Sep 2019 11:26:22 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <20190926091855.z3wuhk3mnzx57ljf@box>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/26/19 11:18 AM, Kirill A. Shutemov wrote:
> On Wed, Sep 25, 2019 at 04:30:52PM +0200, Vlastimil Babka wrote:
>> Commit 37389167a281 ("mm, page_owner: keep owner info when freeing the page")
>> has introduced a flag PAGE_EXT_OWNER_ACTIVE to indicate that page is tracked as
>> being allocated.  Kirril suggested naming it PAGE_EXT_OWNER_ALLOCED to make it
> 		    ^ typo

Ah, sorry.

> And PAGE_EXT_OWNER_ALLOCED is my typo. I meant PAGE_EXT_OWNER_ALLOCATED :P

And I though you intended to make it shorter :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f3d5425c-a833-0c14-3d88-3b7fbab47e5d%40suse.cz.
