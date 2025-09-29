Return-Path: <kasan-dev+bncBDJ6T577SMNRBNX547DAMGQEIZLAXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F8FEBA7DEA
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 05:36:24 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-33428befd39sf8218369a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Sep 2025 20:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759116982; cv=pass;
        d=google.com; s=arc-20240605;
        b=dh6Y+BK7W3kEX3BGzBfBa/tz5OpXyh8ulJogx2AczILstnO4dM+U6gCmBt/fRZRSE7
         gR/HHXqZD/X69LCAMIdancxkzxlWHqWeykGh8QgQuZLVu7JcFqt2sIzzfmJww/bYXLeD
         C2CuoxlrG9IrbIyElDk9q9gcqbh4n7PN46NmF1VK/cLfcFmol6rCZdRl3lsIAb/yoo0e
         wfFwO7tqT4x53AnkagB1xikI5bc0gaI3JuxuQ3OxsgQ4QXyX4TM7IVJ3fu74bO44bgvX
         9sbJ81oYKOSbu76pQm9HVLwkUC5Njkbc2E35Kk2Lw+lawFkLjQWOyJU6rSTFDA0jqWx5
         WUwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=lzn2IHcBKKIMCZ4t5wLOqr1jzKDkDafhqR2jcdm9uwA=;
        fh=kZXCEasQ92l1LbBfen8iw++ktFmHDqCNHcE8KT1DYz0=;
        b=Dm4kqXj5zR1xVX1tgFeooJ0rEW7WlHDQ8CXr5QElTeRweW9q0Jc0Ta5XzYW/tm8BiF
         z0vFKhIWHeqfPT6RK8RYBRmElFMF5wPwz7DWx7LuNfBCDPjVb0/vZmoiTB1sbvxjkJw7
         n6+d8G2SEyuKtzRIDDd4CUU6jBQhcRqxjPAYEL0+o9jBxki/IodY73/731wELT1vsGNn
         k+/fesbp9TrTdanJy8K6sZyyC6WyHBA+C6kIrw9W+l1UR4Q8GtTxzxW5Rm9j6XDSaN3t
         LdO0mdosIqx9S01xOLOa53JZ2uIlfOSLEDAt985DkPPectXztmuVsiu6cSgGdoPxSt/d
         Nyig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=dev.jain@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759116982; x=1759721782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lzn2IHcBKKIMCZ4t5wLOqr1jzKDkDafhqR2jcdm9uwA=;
        b=Gm4ufzXVRcUpPWPBV8xSr6LXxaGDhKyi3FGH886jQLYxuS9/7cDOb/a+H0b6pNCVbs
         WbokapjFFeb0U40lExJmdMRPh9P2pORl6icAAMMA8DFC0KSd+I+Sb5aIsk0fCh0f+GXL
         PYXN3Ws8ac8nD3aL9Ngy3LGJ7mgY+DUrbS7oA88dlLWjtwjq74MyUEoM+5XwAywCLnMM
         /1ZVeBbAEtcIqECAqg6SifTAc35DQjFrpLAg6NTtXQLzNwV97KjzQyA87PFbT+5K5qbN
         ZJpnEr3KjYIsADRJoFiob9HckeMEiyMRS3giAQ1qB317hChbsSy6FbhYQyjL6iM+WNHN
         KKsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759116982; x=1759721782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lzn2IHcBKKIMCZ4t5wLOqr1jzKDkDafhqR2jcdm9uwA=;
        b=BZeYOMpSdtg6leGIgbBsPmT4hbKWG+GBphPgD7r3BwWj74wm8CygtzFaMyNKoDNfBA
         3mwBLPul7FG9LaJ3+tK7UFeyTYmxQNacSZhreW0/CkcI5KRRMfbDZYin/Kla4Qoy9atU
         7FWEb7TohBBng2hrhPwRCS4FoD7/Jn+7yrHHbnEsnGsI8D7HZrIxxwoQzzGA39isY6pS
         mwnaha/+8EkBLyQl+9FPKaa5qFZWcBfY3XN1f/CZsc3C2svYSK9mig87UJBqRCrw39Pa
         usKIoPH09Sb+7tHS28X2RhEjqoDc7kiY80qXD3OMu8YRRmbfelJpT/oj2hSsJt6WcSep
         2NQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3T4aMddacs1lqg/+mjJK73CIpLuKUlN1e9YhloAZtT6yMW0DIhLZ4yKyIePA4/rdF9cZOaA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5GtrTkhuaeCOHyfOiypDEVRkF5jnLdwK4SJ3DmGOVN5Ej+/y3
	fe5t/TmjY0HWGfe+q/jXWGMlXgTR1OB2XHI1eGPwdWYxBTvXxtOtOhgC
X-Google-Smtp-Source: AGHT+IE861Y+wn4BU8lgFSOx62A0etBrNCASjki83oChfrdK9Hx3IjSBdWRGm8JGzfWHI9VH6KENQw==
X-Received: by 2002:a17:90b:4acc:b0:32b:c9c0:2a11 with SMTP id 98e67ed59e1d1-3342a257424mr16063411a91.4.1759116982427;
        Sun, 28 Sep 2025 20:36:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6FOrxv49hgYw0fp8npKH8LZUdNwzx4T2HUQiP89nOPoA=="
Received: by 2002:a17:90b:3d48:b0:32e:ddb7:ede6 with SMTP id
 98e67ed59e1d1-3342a5fd60els6223456a91.1.-pod-prod-08-us; Sun, 28 Sep 2025
 20:36:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjllfuzBjTryrFAL1CLTJmsWW/79/L6ThDdqcXacZ5P77LnuZ430xgFhSGm6E7QDY1t4ihR00MoTk=@googlegroups.com
X-Received: by 2002:a17:90b:4a92:b0:32e:e18a:368c with SMTP id 98e67ed59e1d1-3342a257491mr16420068a91.7.1759116981097;
        Sun, 28 Sep 2025 20:36:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759116981; cv=none;
        d=google.com; s=arc-20240605;
        b=JS6tF9BhOxNWSYLOanAW1WUfz3hcTUaD5gxZnn6aFtAOAPkHV9X+B7XzrM/I4CWm4s
         SjqCkcY8/GgebicO80PI844zU2Sx+KUEMsjouoFgQDnC8ma13c6KbrMMd3fVGtU5S1YC
         CCn5RGjU3uJWWYJ+qQVYBU8+hHOM/qQv8SkoeLwIZ5ZRHm9diWBIouEyFdAxFMbesUUi
         k4AKXgw1GSjl8Nf7a/1vJAljrmYEf7OMqNPLjHk/QEdsFr8LjFuyqTjKNFCK/ImkcYgZ
         AsbBscI8s8LFY1y6gYB6armw0DVe+PkaKGwgVtSNR6H36AmI9WQYwEdRWk03BOkpOk9A
         ZnxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=JGDnRdobfQCA94hTso0Evwk2L7bqYVznDxPJPTdsSGU=;
        fh=ifv7CkFOczjMMAr3ikxyimpr+8CFW9WMCjKGsFHW1YY=;
        b=Z6RLXKNGyZL/ZjlDE7F+cB3xbaMpslN2+G+n4R4tOyI/yQQ0Ex5JcHLfUW+H0vlS2F
         bvisRe70WQwXXGXizLRKLuA4tbVM++2xjQjwGPv42RZHm0zTpvm5h69EDtw8mAwrC+RQ
         O7ip/y/5kS0ovtb0mhwfmDqLAcaOy/EbFX8gji9zSMLfu19usA7WUUkXGxPWpZouVKDs
         MObCp6Culp/dZxHPXMgx0iFZxrFjLzCMNklkoBO057MwCniZO7gC/PF8dRc1rK0C8SY9
         tVTRMVTyecKpyUvDakvnsr9ssg6M4LmErKJt/N8JfH9b6sW8Im3AjK5RMv84HXgu1+Nh
         72kQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=dev.jain@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-3341bde8647si605696a91.3.2025.09.28.20.36.20
        for <kasan-dev@googlegroups.com>;
        Sun, 28 Sep 2025 20:36:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E8E6514BF;
	Sun, 28 Sep 2025 20:36:11 -0700 (PDT)
Received: from [10.164.18.53] (unknown [10.164.18.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 06E033F5A1;
	Sun, 28 Sep 2025 20:36:09 -0700 (PDT)
Message-ID: <1d7fed49-f67b-4a70-bc67-7643e2db4e99@arm.com>
Date: Mon, 29 Sep 2025 09:06:06 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] mm: Fix some typos in mm module
To: Jianyun Gao <jianyungao89@gmail.com>
Cc: Liam.Howlett@oracle.com, akpm@linux-foundation.org, baohua@kernel.org,
 bhe@redhat.com, chengming.zhou@linux.dev, chrisl@kernel.org, cl@gentwo.org,
 damon@lists.linux.dev, david@redhat.com, dvyukov@google.com,
 elver@google.com, glider@google.com, harry.yoo@oracle.com, jannh@google.com,
 jgg@ziepe.ca, jhubbard@nvidia.com, kasan-dev@googlegroups.com,
 kasong@tencent.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 lorenzo.stoakes@oracle.com, mhocko@suse.com, nphamcs@gmail.com,
 peterx@redhat.com, pfalcato@suse.de, rientjes@google.com,
 roman.gushchin@linux.dev, rppt@kernel.org, shikemeng@huaweicloud.com,
 sj@kernel.org, surenb@google.com, vbabka@suse.cz, xu.xin16@zte.com.cn
References: <3c3f9032-18ac-4229-b010-b8b95a11d2a4@arm.com>
 <20250929002608.1633825-1-jianyungao89@gmail.com>
Content-Language: en-US
From: Dev Jain <dev.jain@arm.com>
In-Reply-To: <20250929002608.1633825-1-jianyungao89@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: dev.jain@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=dev.jain@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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


On 29/09/25 5:56 am, Jianyun Gao wrote:
> From: "jianyun.gao" <jianyungao89@gmail.com>
>
> Below are some typos in the code comments:
>
>    intevals ==> intervals
>    addesses ==> addresses
>    unavaliable ==> unavailable
>    facor ==> factor
>    droping ==> dropping
>    exlusive ==> exclusive
>    decription ==> description
>    confict ==> conflict
>    desriptions ==> descriptions
>    otherwize ==> otherwise
>    vlaue ==> value
>    cheching ==> checking
>    exisitng ==> existing
>    modifed ==> modified
>    differenciate ==> differentiate
>    refernece ==> reference
>    permissons ==> permissions
>    indepdenent ==> independent
>    spliting ==> splitting
>
> Just fix it.
>
> Signed-off-by: jianyun.gao <jianyungao89@gmail.com>
> ---

A patch is never sent as a reply to a mail - please send it as a
separate email from next time.

Reviewed-by: Dev Jain <dev.jain@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1d7fed49-f67b-4a70-bc67-7643e2db4e99%40arm.com.
