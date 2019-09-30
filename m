Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBQ7TY7WAKGQEISRAEWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1252CC20DB
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:49:08 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id k9sf5909080wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:49:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569847747; cv=pass;
        d=google.com; s=arc-20160816;
        b=K7QUBDkSxene4Gyeq7XwVy8h3N+5CLZPrdFbGP19jEf+/8yJ/mkt9DFLAJj3zZ8fAM
         KtNOFdd/oQOUz2tAIxz4xJ7FK8XtNPEySHDcMutdUKBP3P6yV0YRfK9wi+xQfoDTxrQo
         ahv/c1cHJ+86WiRJTYdYm35Oev6Uf8osDnW3bfKM9RE/+jaIFQ07impNhvrgXG+Qm1e4
         1sdCSo6MD5PcKqhRdtkyD6rk0N7Hx3xtLDQ9fprWt/4Qhn0I8mQ8cpM7pdgwf/y22X6h
         pdLjEeOXav3JQjLspCRt6W6ia4DHRjs6DyLnJpTeGgAfxV70csoX4zjx/c/2HaiWkyRP
         lPaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=RUB7lVyG7AWH9WFn6Fix0aV1TYrX8eyON3KRymhck7U=;
        b=pjmc5ECXj6uDx/XidO15gmO/nM4uLgxa8EiGep/gjXjHQgra6jWywD0YPlHcZid4Ee
         b3cNvBxFzSp79SUG4giL4McGDLRMssg7zQ4H9XXa/3Bzi/0zXzdlCRQzcWI/tj+QgTdx
         JUbLozEbvPrV2Xs83e0c4M7npZS7f6RMT8WvXT+Kpl0OuVmb7UwnXevxdBZGAC1utsHK
         5ifSJAft+crySrwRWpzSmpIBHM0mqd4s2HRfYDqTjI1QD+GfprnpElhQW8IIt3nxZTFs
         VHvAajhMBDDOgjbM+msSHPeldaFKYApWYke9qXDOYTYFbeOpBe29U3pKNvY/3mSET7zw
         ZUIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RUB7lVyG7AWH9WFn6Fix0aV1TYrX8eyON3KRymhck7U=;
        b=W8clXtpa4muts9sxKu+KRvxV691DAx764bnmrkMkoAGH2WritNYBaLMZagPF8Mv1If
         BqWuOIEVD57BmyQygkCShNnWNpV2jDXl016ryZMfCEdQMXcKcTjKsBhmCebj3qAX+1lv
         VLF6rA/uiuDGWVceVtdD9IM13bCLpenWtN/9ryLAyNwoKEVk+VKuExWnyBnsF0csGyu/
         v2lGsidg396SuErnV7eRxY5DCSJTeYq3yhhAZvOkQm1BDaJq+5W49nZq8k6rce3FX53Q
         Td9mFZ5RouEchyEbS5u/h5dau19RTOyX5LMLIe+FO4NIQ06LdW/06ix2vQJ8HrM/yZD5
         4qvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RUB7lVyG7AWH9WFn6Fix0aV1TYrX8eyON3KRymhck7U=;
        b=sdXGFMDUYIC0q2LZHeMh8V3Lip2J1eEeJRII0b0CLYKU+RSi//u9TGjQq5Pu9KiJyc
         IQyfGshRsJ+3AIjaRabsEcHd0GGtTPDNZQrTMxxeyOR9dEAeEhwErZc5SHpT4jbn0xbv
         yNKI7cyH6KzIJY3FJbU1TCWVOsY7jQoUvmQ7trmYVVr4Ja+whPc7zUleaOP3nNa7qoOH
         /x1IL0737QwRbctcxuVYtvGITFhkKoNmKuUdZrl5uvsTYFNBKYlS4GvgT3l0MTx6A6mh
         YM4X+OMFbVt/ZLrV9heb9UQk9XuL8aozl1q/VPHzullDiudmeddsWEegINFN5+XrxH99
         Y3GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXqvv7DUVn8ycMhcLscJaW3s8/qAMmhisNp4/SjxiViGrRBfo9R
	cfPg+Fg84H/JFHl1e03bf5U=
X-Google-Smtp-Source: APXvYqyrvs5ONtSTBeWfhYyaaVYMKGrb1XwIC/8hFfzrNP7Zk193e0S750xYcbv3AD4lVYdX2U89vQ==
X-Received: by 2002:adf:cf06:: with SMTP id o6mr13234528wrj.366.1569847747762;
        Mon, 30 Sep 2019 05:49:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c8d9:: with SMTP id f25ls5014050wml.5.gmail; Mon, 30 Sep
 2019 05:49:07 -0700 (PDT)
X-Received: by 2002:a1c:7306:: with SMTP id d6mr18056517wmb.62.1569847747256;
        Mon, 30 Sep 2019 05:49:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569847747; cv=none;
        d=google.com; s=arc-20160816;
        b=bi/kGc6sEK3j2pLpfId6eoAai9dOttVS8FkJmMFU2q9Zeb1vLPmOE+kqkcjC3qaAjR
         oil7WMn3OXR4ewTwcZAxpwj8xSI6GMH0sznRB8+DxkmhpCr8SldYvbrFY8gfPeZPotEE
         Yjn3EHbSkh0w+WrvgfxzsfiCsZG1jOCKyoml/63rZgSJp6L9/keOFiQRle8dSJtzDbno
         6393rU+mzrYVd1b567dfoeTv0ECaeXZbT1A64yfFvMy+1xPP8jiCeiUVqQqoq2s0Koo9
         U4eLjBHzkMXoBrpV5eEkHffGuuZWCOkIIUOt3AmW84qLdviaGTR5Zr4DNrH51iFucIlg
         WkBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject;
        bh=Fla2OOaK7vkBTXgOGC+y5rTJaRxbKv5XinbmVGI0Moc=;
        b=fScC26PzVw9E6xBLKBjcuDHEvSYbY4WCe3wlVdidp53BLDMCmMcyLFS0JX0rWy0WML
         sFNORPP85xIo5zwOhhkwBFVWMXXaMxHZmyo1vb5E44sJ1ZXl2+4eE2COQ6kOuGGVh61J
         v9s8mCBtuGF/JZhC/c61jQaF9fAiLA8+PMdR6veVD/LdLSM2S+uh/WISgSjmPNUTcCjw
         +pNOu/pdZTvfiaWRVycbPBtKEmZJKzOrAN5LDh0VpWm31TDonaaan/dUwTp939jOKH2u
         1oBV5ahf7B/r66g+geTvEUMGttssC4ta5FXyu2c6wynybUizx8+n+ZVczvv89PWEIRGK
         D2QQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id u15si628885wmc.1.2019.09.30.05.49.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:49:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 8C821ABC4;
	Mon, 30 Sep 2019 12:49:06 +0000 (UTC)
Subject: Re: [PATCH v2 3/3] mm, page_owner: rename flag indicating that page
 is allocated
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Qian Cai <cai@lca.pw>,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 Matthew Wilcox <willy@infradead.org>,
 Mel Gorman <mgorman@techsingularity.net>, Michal Hocko <mhocko@kernel.org>,
 "Kirill A . Shutemov" <kirill@shutemov.name>
References: <20190930122916.14969-1-vbabka@suse.cz>
 <20190930122916.14969-4-vbabka@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; prefer-encrypt=mutual; keydata=
 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
Message-ID: <4e93dc73-191f-012b-f082-ee8730a90400@suse.cz>
Date: Mon, 30 Sep 2019 14:49:05 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.0
MIME-Version: 1.0
In-Reply-To: <20190930122916.14969-4-vbabka@suse.cz>
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

On 9/30/19 2:29 PM, Vlastimil Babka wrote:
> Commit 37389167a281 ("mm, page_owner: keep owner info when freeing the page")
> has introduced a flag PAGE_EXT_OWNER_ACTIVE to indicate that page is tracked as
> being allocated.  Kirril suggested naming it PAGE_EXT_OWNER_ALLOCATED to make it

                    ^ Kirill

(again, sorry, hope Andrew can fix up if this ends up being the last
version)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e93dc73-191f-012b-f082-ee8730a90400%40suse.cz.
