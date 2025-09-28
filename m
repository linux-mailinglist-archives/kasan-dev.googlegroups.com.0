Return-Path: <kasan-dev+bncBDJ6T577SMNRBQW74TDAMGQEUOINOAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 24606BA7095
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Sep 2025 14:53:24 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-79538b281cdsf76674656d6.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Sep 2025 05:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759064003; cv=pass;
        d=google.com; s=arc-20240605;
        b=JEb3ain70u7M1H04uU5I9FfgNS24XtIwoce+Eop7eALU8coueDacz3pW2ewnyTSyBt
         rZ4TpidyLBJVWNQk2LYtN6ig7hH6O1z9n8HdD0S4J79rFRhCCcXwnRHp4CXr7mzlDi1W
         Xj5PkKRk6CC+Oj1bviGaCEbUIxlR/MxYGvMY9WiNv1LjvQ9DtEl1eovKqu9btJiJIsGK
         QZsh8ymz5wKsiT66qehR6lifYBQc5T5rNy+LV1MUjz2tT0SJ9t03VEEr1+lg513VodQy
         dvHFTaSb7rLih08ne8QcOo8YfivvwkLHXJjgsIWyVoiLGySTIHAuil+ZKKu4y3EuGY2y
         j2Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=mude6UZveA/6eUvwNQVVvdxxQ3TZH4RSrkfoAC1JVug=;
        fh=y7Kz1PfN5NkZr9Ox/uu+aUGkoXj8WWTV20y+2zZIc+c=;
        b=ijFjzskF+EmB2gy+RoRDqWqGYBaeMPQMGjeJH4O8jbmH28/JNRhbvJ+M9QYNikd5zD
         rSAnxvnMlGKLywZ21NvxsqaD8J3dzF/Y5fV/rzvf1l94hvlpBHJonHGIgyC6QCr1kNSh
         i26O8FX9HPVqAI+94xXvjMCx+Z/ywC8YdLiUOwfk8U39eQkoWxKxjhnD2LDxVHPYzrm+
         Lcc3ZTsKyHN3ppbiQVneYkLNKVkYDNffIKrRaCGI+U5+72rjitJ5vQjfsxHoKoPcwxs2
         DQ9y7Mt5A5kTyTcGJf9o17IB78Xjh62z/HZWayBeRvHIa90cgg4VBnYqoQobs63YpYDI
         +RXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=dev.jain@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759064003; x=1759668803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mude6UZveA/6eUvwNQVVvdxxQ3TZH4RSrkfoAC1JVug=;
        b=C/7FLT36/3L3XU7whd+LC6q1tYFPwQAIQFSIo7LlIi6sbMrPnjwJtcfY4dm1OtNboc
         9O3ZO/lB9cd7ZcxVDef6LAgrnhMHw5pLL90kO8BIaJ4zjpO5G9R+judCLLFtKMaPUPkP
         KIsGLiG0IRTwDLvbUqVyam44jqiyial5uP/og0vVpuPv2rBV219XjwMAGpuZhouD8W6U
         yb0NllIaSoeHuWhrzMoZsL1nvwFqHmc5qDDJjTTTqGuc8Ftt9pxgxx5kmt5/XoMmxVcp
         ST7rUW48heDn7A9BD5m2Ol/Kq7qY3HGGxXjsn3eowVVB2SsDz79uVO1vs6n3Rqh535SB
         2O8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759064003; x=1759668803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mude6UZveA/6eUvwNQVVvdxxQ3TZH4RSrkfoAC1JVug=;
        b=O8U0+wiFWpFE8c5n60VOC0qoVj1YGM2AH2F1OL+4aenR0vYVOCdU74a0arUxiMG1VN
         jaAGMp/jZRgtW8nht/eeNRbLMmF7jFaKUu6D3t7Yo7Qi/ubvgbitRsa3tOIxNY4e4FhJ
         Wr2dxP/vwq5uYLPaMmKGddJnD/UXgtwNyrxexFrSqg0puCDgSw5/DjYBMEbaEvyK35UH
         2j1p1R633mZlRLMWC3VIJeOlA8ttTLJfSGBnoURYYWGIaW8AAf21x1reBodXsY771Lj7
         cDeOi/6d1NiA0nko2LlMINhQbzRBsEKPNi7vL9q8rOFs72sPcD47YrgGjthYhCcVm+km
         GFcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWl9dLWv0gVRHNfTEKidWOl64mnmD/GbquDhmVeWvxoOB8oxJ7y9pW90vMTl55PX4fGW9yO7g==@lfdr.de
X-Gm-Message-State: AOJu0YxZE+VxxRqDv+bmJxC+WRhiAwEgpeiiRjSVVGfTdpZjR8JGPtkz
	Lp7XiZUeMX4SwNK8lecggaz8/HE7FERo1DsOQU2G1U1vthTJGACu0UBs
X-Google-Smtp-Source: AGHT+IFJXBDe6AwVy0yPKGGilDUrMgD4Ia+Gg36H3NS6SVA1YA6hdDGoYAFb01l5TE7USNFMYgY4Ig==
X-Received: by 2002:ad4:4ee2:0:b0:7ae:6bfe:d9c with SMTP id 6a1803df08f44-830a1c6ff1emr72743666d6.34.1759064002538;
        Sun, 28 Sep 2025 05:53:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6bySprAreh9pDsReEk6/P5gn6b2Cp1XMqjhemGVaX9yw=="
Received: by 2002:ad4:4513:0:b0:76d:ac47:1aa2 with SMTP id 6a1803df08f44-7effc4133bals40347666d6.1.-pod-prod-00-us-canary;
 Sun, 28 Sep 2025 05:53:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUx9ZYBimt5nLk5J5tWL+b/2Z23QIxAotqtnrCBlyo56ACIgsw6teWIkEgfcyLfjIUiOrXsSH2kMhE=@googlegroups.com
X-Received: by 2002:a05:6102:6113:20b0:59b:f140:ebb2 with SMTP id ada2fe7eead31-5bae22f8e82mr1710233137.7.1759064001784;
        Sun, 28 Sep 2025 05:53:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759064001; cv=none;
        d=google.com; s=arc-20240605;
        b=k5IcdSIcxE2NrsE/4ogVDoXo6exch3g9SiQK3Y9EOea99/KhIk1BfaE6mS95eswYKP
         OlkT9eyhI1yFOkyqNfS/HzkuUXg1OaNwAgDzFdbFhE2+qIcM3zv0uhmsv4Njl1Mh92ll
         2p96RNMgGibeErx2A/tBuA2Vd49y34RVEj1IpgK+3OPoJkHq3pe/oxfhc2IkSN2X/FEu
         kWNNqsNRiJGs7vty6bOBPrOy9A9Z0G9tXCIIjG5uwINzjao44WMtJpMmFLsExSg4FrVv
         YMpAFHMot0PXb9YlF3yIf3H9YQzODnPOl02DmqCzPLg2OW4v/XOmKg9acieinqsdprB4
         M91w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=A/34jcHK76hSOU5Qxl0fTUUIb+wh5jncdNnqgpmsHY8=;
        fh=6vfHSGeOvPxVdSvMdTzXCdoXYGyxBlFUPXEcqRqsFv8=;
        b=gp0VFJW2IFXGVcRUpc8f+NX6qGetSnq4XD76Pp+T4Cnc77fjSLXWfxw5W+9VmHeeN0
         gA+74HfZwX3mrFnMVJGWkBarP5mvxbTCZbLKEYORc/bbZe60Pf9cmurJ01V5ppSp8S36
         H0hRAKQybptby2yO/3n0Mi0WZDkGvyCeZXRbt6DnVAGj1NEwaeykxdN5eXI6ibr8JEGY
         GPt6PyDkyFokBybfNxkvKd+dXVjjkek2P5htqelSDEV/8yzBKfSye47HVu1qNtpNLlds
         JwxP7tND8WBk29M/lRIliLdzBbXEhtpgxOqciKo+x90UP5EvL/lz6gA8ULvFRf44OrK7
         qrgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=dev.jain@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a1e0cc1a2514c-916d36c168asi373878241.2.2025.09.28.05.53.21
        for <kasan-dev@googlegroups.com>;
        Sun, 28 Sep 2025 05:53:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dev.jain@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C7006150C;
	Sun, 28 Sep 2025 05:53:12 -0700 (PDT)
Received: from [10.163.64.48] (unknown [10.163.64.48])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 120893F694;
	Sun, 28 Sep 2025 05:53:09 -0700 (PDT)
Message-ID: <3c3f9032-18ac-4229-b010-b8b95a11d2a4@arm.com>
Date: Sun, 28 Sep 2025 18:23:06 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] mm: Fix some typos in mm module
To: "jianyun.gao" <jianyungao89@gmail.com>, linux-mm@kvack.org
Cc: SeongJae Park <sj@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Jason Gunthorpe <jgg@ziepe.ca>,
 John Hubbard <jhubbard@nvidia.com>, Peter Xu <peterx@redhat.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Xu Xin <xu.xin16@zte.com.cn>,
 Chengming Zhou <chengming.zhou@linux.dev>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Kemeng Shi <shikemeng@huaweicloud.com>, Kairui Song <kasong@tencent.com>,
 Nhat Pham <nphamcs@gmail.com>, Baoquan He <bhe@redhat.com>,
 Barry Song <baohua@kernel.org>, Chris Li <chrisl@kernel.org>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 "open list:DATA ACCESS MONITOR" <damon@lists.linux.dev>,
 open list <linux-kernel@vger.kernel.org>,
 "open list:KMSAN" <kasan-dev@googlegroups.com>
References: <20250927080635.1502997-1-jianyungao89@gmail.com>
Content-Language: en-US
From: Dev Jain <dev.jain@arm.com>
In-Reply-To: <20250927080635.1502997-1-jianyungao89@gmail.com>
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


On 27/09/25 1:36 pm, jianyun.gao wrote:
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
>
> Just fix it.
>
> Signed-off-by: jianyun.gao <jianyungao89@gmail.com>
> ---
>   

Reviewed-by: Dev Jain <dev.jain@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3c3f9032-18ac-4229-b010-b8b95a11d2a4%40arm.com.
