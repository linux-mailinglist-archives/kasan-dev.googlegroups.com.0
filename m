Return-Path: <kasan-dev+bncBC5L5P75YUERBVMBVLXQKGQEFQ2MPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E0E911551F
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 17:24:54 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id i29sf1224097lfc.18
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 08:24:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575649493; cv=pass;
        d=google.com; s=arc-20160816;
        b=WNvwSb0kj5xdZBpJE/8Sg9AeDqAL+zP8/6oyaMvTEmirFuAdm0q2VjdG6VEezliqXh
         Ul6Wi1NDVKCnYXGplh9R9tzcDmL/oBgYSQL9Hc/tZIlh+tM2DL7bSuZInAAknEGJGbD0
         +kApFaE1DQ99m98QIzKrkJx1DaQ87M3N97BzP1ZomRKGX1eQ/mtHlan8c5QNmQApoDz9
         3BGSWLdROoos1LWgOAdjV1mC2hrdR91dOrEadGT5HmM+PFNUCY/4wxe8zihkZsBvP/Vl
         8JYDmqNqnjL+I9OmtFXO3nHiqOPNhmHOB8l45tPpt6U0J3xBjoUMekXH/+iId7ThIO7f
         Bsmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=0hF+lyS5Y27MBz7+VTl843HTVQ+XCcYBiYJA+ZssoDY=;
        b=S60QIBVOAw01dJ8DnJPQOUyUitS42F8rNBXAwMY/vahSCMfa+8yrO2Q3+Hd7l0GEfK
         UTNbuDeJhlC9VpLm8NfstORlfcwyrgVHYDgvdSnY4JgpJkoASjmnIU0rcI/Wx8GO65RU
         aDOIsDkqKnmw++zKhg7wwxL/igsS4/YredoTSYORH6K2srzmH/+NDMXVKbV3H+tMRNrM
         QLYNesgQGdHh5XERAKzVSLbYTqzyhWV2itv/M1/P8zSF1oUCitYjHQsm77Q9JZGvq+lq
         MSlp8GUioE3WavVZCdtXaIDiOji4YTbkppV/uRPDTagrRA40R15NaUDO5d0Q/zqGCuN4
         HhvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0hF+lyS5Y27MBz7+VTl843HTVQ+XCcYBiYJA+ZssoDY=;
        b=KgqFVVLWaV/Fm8V9L69L/36cIVBP3sW7AtEgZSPqskgB/vzJ/7K+aOgKhF8II7e+L2
         KZj6QcF/Bw9B3XH/Fbu7asLtZrcEfm+AN4p9ZREWcuW3MJbVNxSWdJprUgOJYQaQV1Lj
         qZinK9jeJc4Cri3nbJmsIFcwCiBCTtiEMDdV7IHqndSe+hgGq/hLK/bRFG4NaIy7AVyh
         J/yt1aF5NMIhBD88PpKH3IbMf4jiSv1jt7egI8uL/I1d+yn2roUKfY9SlgujNd7RVqul
         NOrUAyiNC8cPWZVtMPo/8ZrkMriKfIVUh9q3gdbT9v9I84v+UtynYpaoyB4vk/nfZh8P
         X83g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0hF+lyS5Y27MBz7+VTl843HTVQ+XCcYBiYJA+ZssoDY=;
        b=JJJ/GraovUlPH2uiDor9JgbMNFuZxp9mKEeHEi7kqbbS/zUN+YH3U0mnKbnQ06xNNA
         3Zzm7UpXKwgyKwIE7wHy9z1pMJT3anAH1hjGfZILhp5BOSqwkE/YSTcZ4/hBtSr1sdNj
         X/pK9YD5BRsrk8SYEOnll7nnwSiBOoLH1pz8BBsPY8pr1onvRmOLfAORhGLYpZDlg2cu
         Wt7znwSpV/ehwex3uPDekRXOVyYkB9GUsGbwiEpX7GbxGRg10AHGHvyZ1uMTLaiENxAm
         YYsv3JBlk2qkpAywifUivc6T0a9FPwzn7fuvgQBwWUwvF5cNN2RqX092gSq2ZcYpzxBB
         IuvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVr08U6yHWHpg6tlQvOaXxf/W2SKCgZ76jMUtx85nM6gDCix0D+
	SGZwNKnxpGkysnNEu7c/dVo=
X-Google-Smtp-Source: APXvYqxOn3RUrzsXgKxfde+lvEtvXRbAOGrywK9aQ/bhAlmdUNS6d3R35I4IGXeXTv95is2mdhBSnA==
X-Received: by 2002:a2e:88c5:: with SMTP id a5mr9345591ljk.201.1575649493766;
        Fri, 06 Dec 2019 08:24:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:95c7:: with SMTP id y7ls1080492ljh.16.gmail; Fri, 06 Dec
 2019 08:24:53 -0800 (PST)
X-Received: by 2002:a2e:9a04:: with SMTP id o4mr9696430lji.214.1575649493151;
        Fri, 06 Dec 2019 08:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575649493; cv=none;
        d=google.com; s=arc-20160816;
        b=sKQK7qIr3JJ3jKjUSdnNUtrGm0JFi+YM98OMse49ZPTkJoUypNPPJBDTl31tx+gQU7
         pXpsx1yELmdHaFsiTAKVJtc715KQ0EAC/ZFgRK6a00drqR6248HGEP49Qj+mxjUM80Ye
         UOrCIDCmj/OIzbDxATpduxjRNe/jSdHVBfLPfIUP0A6lDKVQthAeXHyHz09CYXJq4uJr
         /I1xU9G2+wukvNMHXrCFXgF0ObPcnmCgxetyoZag2+HCAt20RST6/g6pxzRTHXpJZhfk
         VbHrZ5Dkx8CDLYWq30jkYFxmix7U/Nt0NlQFCMO9PKOm9yXNEA4ZGk8d+umXyDT0I3w2
         CADQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=aaKOwGMmzy/zjiCCtxiebboL7YJc6Xa9oaUziJ7LZ2Y=;
        b=iDs/TL+1iA0gcNva/penkxaewfhYG41889PB10xN6ZNujCsWnOPJ1mEm2Oedc0l34S
         JRQb4nq5yn6AvKIONzonJeqJeKORQfygN0Ri/MlWBsP95WxnlAvt3Dt+cWPMszmZT+FD
         Zh27RKgxf0P6Jvr3LgtaGItD/KxiSX7B9n+1xOIu+D4p0CcmC+3X7cdqfZ0HmzGh+464
         fXL5SZn+vpeOjxwJZv1LTX29yn1+Fw2GZatLDt+JWQJtPVzgALX3BY+/VgYxnqDySFJn
         CV5w+rQZnoALBaVSFyfFG2eLHsMLwWd3PN8q07CfD8e9lLub8Mdct+jlUzph8Lh9wgzC
         dZpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id 68si581146lfi.3.2019.12.06.08.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 08:24:53 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1idGPK-00009T-Fv; Fri, 06 Dec 2019 19:24:42 +0300
Subject: Re: [PATCH 1/3] mm: add apply_to_existing_pages helper
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, glider@google.com, linux-kernel@vger.kernel.org,
 dvyukov@google.com
Cc: daniel@iogearbox.net, cai@lca.pw,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191205140407.1874-1-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <c4694ce0-2166-325c-bdca-1655c7c359f9@virtuozzo.com>
Date: Fri, 6 Dec 2019 19:24:25 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20191205140407.1874-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 12/5/19 5:04 PM, Daniel Axtens wrote:
> apply_to_page_range takes an address range, and if any parts of it
> are not covered by the existing page table hierarchy, it allocates
> memory to fill them in.
> 
> In some use cases, this is not what we want - we want to be able to
> operate exclusively on PTEs that are already in the tables.
> 
> Add apply_to_existing_pages for this. Adjust the walker functions
> for apply_to_page_range to take 'create', which switches them between
> the old and new modes.
> 
> This will be used in KASAN vmalloc.
> 
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4694ce0-2166-325c-bdca-1655c7c359f9%40virtuozzo.com.
