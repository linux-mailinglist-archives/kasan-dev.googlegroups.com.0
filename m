Return-Path: <kasan-dev+bncBDVIHK4E4ILBB74EWLWAKGQETJKDXTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0ACF6BEE48
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 11:18:56 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id z1sf665884wrw.21
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 02:18:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569489535; cv=pass;
        d=google.com; s=arc-20160816;
        b=N8CYL5UDEbnoWgdTrtMks1ApnWVfJ7CaP78tCDJ0744/Ggf5/vXGrPsjqsQmMa4vXV
         M6pmNc9dSK8qm6eYiEEv9w3G7kPLcWvPGGWNKwbJ2Lki0OSSRxAYTQuU6LEX0cN9309J
         vksICGTyevTzNNbHvDyLK6I+o9wtirWWQERcMNpSjhncYE4Ff4FEYoKRESSpV9U01zH0
         2iefjC9Hvooj+cIBp+y7/n4HZro63jdLtIbYRQD9PwpTgrMV/RWpDhgPdxk8OyxWGT3y
         Vrv3752EagK7k3PuE8hv4wNszTJN6BqDpXMpI9FFYfIqUN+SYUQxUcxJuTNgjCslRdsQ
         2ERA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4dbmdE/jEaZH0wJ87e+crqcyh40tJouFkf55vuHhxG4=;
        b=bH+czbgste2ORbFHyvet6WAlqDrG1YbpvkM0hLutrFmbKwz79J1aEopXDk1e9gok4k
         TROYJw7QiSrJvhS42s2tAsYdnO7TcreDk+UGMmR9olqWEPI7tpK4okxmDP25SRn14ayC
         HA1CHYCBlJZ6Kl2BkVUAjTOJ2dRhK1Lc3PMv/ePHYI+e+IeVVhgU9+XpfMSv/wF4ElcO
         9Ladwce/827Hv/hJ89e8clGhlgj6fjGOuNQDsSrjY8wLzqeQ7YuivLyw9HCRK/E8qtAg
         vGOHH5laMhzEF2p8+Rf+c7rIC8ON/ziKBiNEotWh0Bfe1izuJkhdyun1JaCTpbsfKiQB
         94Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=mRe5YO4G;
       spf=neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4dbmdE/jEaZH0wJ87e+crqcyh40tJouFkf55vuHhxG4=;
        b=QsNiF3zB7JWCbk9gYNsoZKVVFKYBRQ3yaYnCg0leKkHt1AW7v1ZVSp1OFBK7OVcrja
         dJBWIQLFL1YAMbB9yX43MMN7dm3QNH1iBDDEKVZynXsegRag3Kbr3G7F63IBZ0938dTu
         SRrm+Eb/3BHIS8sdCGl6KBmDYHISIUNs/1v6KO/AxzpZ48lmH1VyM6DMpfGhm9I/vmRP
         SlOlb2wzyKoJai817v4L4Sn2mu2cxAw+8D4BAUqcDD2ZcIkbfvRhjRySykYRn3zIFu3a
         HwffpcoEqZSJuEnnY3Dq8xnoXoVAB1kvu5+m6tDEa+h7TcheZEX8U7l6Q/iGYpDK6h21
         bGvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4dbmdE/jEaZH0wJ87e+crqcyh40tJouFkf55vuHhxG4=;
        b=g0V+qGlfOZzy4hNR1k+ou26Q16EQFRIm8HQ9rTXqRcg5Wjq9DvBSDifHgbdxXrlTEy
         RBGO/8wDVPJS7ADdtHXMRKj/x14vgtOffHoOzXr6kuQEHTZ72fQTPWH4amI9+8iCLe3M
         eMKeHn3QnkGD0aqyFb1gSIRBcNs394votYFv/Nwc+N3uqyfGzw90OgAhTnymf2i0GQfz
         ZP1eoZGgvty4CwO6UBjlyG0MQqSoFsQAlA84fh3t4bdNRP6NjhGUOyc/jSFkRYA0Dd1U
         ByveEqf7dsW6WMpSm+sM3lHZkRKZWDlVPt1Q+zdPs0ZFB9brdtyeVaiIkzRRtnyqdmjw
         2Eew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV5GznGqEX4GOmjDJC4DeICJJl4ccuXfJv3DLHaJc5VSEjg5tF0
	Zkjzs8/b+J2DTY7GVQmVWos=
X-Google-Smtp-Source: APXvYqzJnFMZl5wHt8A8W4WcIxLXRDLOGDaMVfbIcM/DzzhFYOq9HZ0tLW8pC0s4lbS6yl4dVoIkXA==
X-Received: by 2002:adf:e849:: with SMTP id d9mr796250wrn.358.1569489535760;
        Thu, 26 Sep 2019 02:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c8d9:: with SMTP id f25ls613650wml.5.gmail; Thu, 26 Sep
 2019 02:18:55 -0700 (PDT)
X-Received: by 2002:a7b:c391:: with SMTP id s17mr2229941wmj.94.1569489535326;
        Thu, 26 Sep 2019 02:18:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569489535; cv=none;
        d=google.com; s=arc-20160816;
        b=UCyTefbzImZominvE0916i/moJdG6hLJgO4mpMfNYom+yXG6Ex5MWnxtB9PSvXc1qu
         E2vAthu89H/g8q6ugEQTeCnJnYfBJULwfNndr+kOU+sV5hkaY/VbM7kwJGWY57BxUIgC
         oznesokCu1ZO9GDXkRSRrmhMFMqY/1aRwrsPxEPREEI2dydYE2HUiFqmoH7aKczvlU4n
         MvjYxe9Y3tHl04y/lO/STPvFiLLTVt3xQDkTyRBl9FulhsaUHkmoARN7SKTYBuRZcPvi
         KPkw63ZspQaZ3XrK9KeYwavEevyBJmlY1lxAKuip7SXKmKkGdTCwd+D3pQ08hPFgPF8K
         ri4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CDj4POLTtLONQOD1mW6qh/tKEDe8bqQ8HYY1swpGKfE=;
        b=qvaHyXy0thBGWJ/483TUDrDY0bkafOpbEIiik80VQ/rZwdJm9M+UJPCjeB8EA2QlR0
         gtRRlT717sC7WasPS06igWA/9WT6WkXN7DXeatn63akgVsGEDX9N7Zf+B2quKflyt+z3
         4i/fPhqfQLNpH+CRGRdgcbw/x56DD7D+CJmCPSoMkhTzt6DfPeA5S7+0a+Xiwd7T7n8g
         BFF2QBwptQ9oG4+4YqEwK1nOQQYd0AK7qGcENZYGUzh/zS69f7m/HQV2UaZ3gZOi8P8m
         aQmDa2hVCXBQPhszgfaWYyEpzOkqH0x6YUxdzQhGG5UdhVT4YwkA6frF4cbgLFOGwlpF
         8vOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=mRe5YO4G;
       spf=neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id s65si102438wme.2.2019.09.26.02.18.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:18:55 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::542 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id r16so1277644edq.11
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 02:18:55 -0700 (PDT)
X-Received: by 2002:a17:906:79ca:: with SMTP id m10mr2114613ejo.292.1569489534839;
        Thu, 26 Sep 2019 02:18:54 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id f21sm350556edt.52.2019.09.26.02.18.53
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:18:54 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id 3E923102322; Thu, 26 Sep 2019 12:18:55 +0300 (+03)
Date: Thu, 26 Sep 2019 12:18:55 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>
Subject: Re: [PATCH 3/3] mm, page_owner: rename flag indicating that page is
 allocated
Message-ID: <20190926091855.z3wuhk3mnzx57ljf@box>
References: <20190925143056.25853-1-vbabka@suse.cz>
 <20190925143056.25853-4-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190925143056.25853-4-vbabka@suse.cz>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=mRe5YO4G;       spf=neutral (google.com: 2a00:1450:4864:20::542 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Wed, Sep 25, 2019 at 04:30:52PM +0200, Vlastimil Babka wrote:
> Commit 37389167a281 ("mm, page_owner: keep owner info when freeing the page")
> has introduced a flag PAGE_EXT_OWNER_ACTIVE to indicate that page is tracked as
> being allocated.  Kirril suggested naming it PAGE_EXT_OWNER_ALLOCED to make it
		    ^ typo

And PAGE_EXT_OWNER_ALLOCED is my typo. I meant PAGE_EXT_OWNER_ALLOCATED :P

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190926091855.z3wuhk3mnzx57ljf%40box.
