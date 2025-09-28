Return-Path: <kasan-dev+bncBD4YBRE7WQBBBCU74LDAMGQEZCVB45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 407B4BA6565
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Sep 2025 03:29:48 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3ece0fd841csf1897681f8f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Sep 2025 18:29:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759022987; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkHc3Lt7KwAvSmyc1ewFsdIv6mMHp6ahzdrRfe5bKtA5d6izl0HIiv/J8jMrmrxGUE
         ddiFE+VniqmRHn2g6tgTeslGG6BmOR5XhpznU4Woma11ZB9eZKvEpwQgfLWLH7E5kI6j
         3YeoNcv2S/040i41w1M5ngeM9JJa3f4YLqOdYKEQNgq88wam5qttVhDwaM2S0lpdEaMC
         wQPu/Rm+qavLRda6zIgjzbjk1yCum+ZH6kca2ok+9fBEaT+OanTi+0YnLZwdzH/WkfUq
         o8E056K0Eiat/qfY2CHT8+tjqzbU8yS58gVQzvV/n/VulwRMaxl1kDFE4IYLNcrcjvI9
         BwfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=C94YEAwSPIbJ/2142WFOZXRKr4LMIAAd1uFvcIpKaIs=;
        fh=TJgYP5B6W13TnNYJ0vkCG9gy3XZ5lphjh+Y6dUOdMsI=;
        b=A3lNkZvRqh8Iwu9h0nPOCJyiKEK63GY0fFVzDfPWyhs3/PJpRqAO5xMzxQchOSAqFz
         m+bLK5XCmJhorCkAJwItHuaKyGMBLZlo8n4TzodJjaWa9cbFnXNjeo0qrsRKAGhSrdPK
         9DxNYCKzFMaKOG4rN7dIqzcVk3DjaHhciTV2SXyUHqQjZN7Kyzo4ljaaiek38AlSptST
         U0sduBG/0kQV7PdkIdAa4AHnGY7Pnyo3kkeRuf3pWUD6Tvg8IOp4PMJWKRueo8k2NqLM
         7EgUgv6no2hw/1XsTsXB5qInmPxYdz4gOT0I588OWl3bZYGOAgnc7SBrfjtskjT0spYz
         5bSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FJk2cLMn;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759022987; x=1759627787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C94YEAwSPIbJ/2142WFOZXRKr4LMIAAd1uFvcIpKaIs=;
        b=a3MDqckFgA6K341/HcM204oMICeW1m/PiThal9qAWLpDUiNNui42yB9tSmoUP9HSRM
         GRDyhD/EW+Rwngc+DGI+wq1B90Oyqh1wKrpQlFxcVVMlFhegUwb3+8NFXkRnbGBjYSlW
         OZM7eI3VYJhRnvL6Z/IAJYtGj8/rii5TVkHCm3xQwNZwuCwnscLJjYq2Kt/Ett51IUst
         kphDsAVLwZJzLotuoM2noJeN9Qssh/rUIgZnJspg91sOfILQDtnPHTKlH9QkwVGp2LQw
         oNdSzJ9JKfrKymdhUGlvUl+A+QBW8LbZvso7OkvDcJhgb5CdsZpdMUg7p4c4TK+jvMMw
         4IGg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759022987; x=1759627787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C94YEAwSPIbJ/2142WFOZXRKr4LMIAAd1uFvcIpKaIs=;
        b=HATVyNfouZqhfQxBSERgkl+THyCKXMfxwPq9VUQ/hU74ztPlauaTjaQbzgX8eDE3Qt
         OtKZvH68CDcgfXwy3lTg1TVfjsOVoVZkPswrxvfN6xlP0lcuf1VxgO3sXcf+ahdqnSKx
         QHGFIiEK3GtHKc6JCG6bft4nSsy/RiVEG7i+mdYiX9K7Thae8/aW/i5yaVNCeq2HRHMc
         o0M4J0LgmWZ8QfztpOG+NyG0IiKOqqEY32M0Uz4Kja43+OMZNTWkUNHZ3gnUpPT2GGl3
         6v492WpcQxZ2pjc6gsGnpNW07vS1DjzurauN3S+e1R48aX7MmXM/AbrJHXVjOAgQnfJ1
         8jgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759022987; x=1759627787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C94YEAwSPIbJ/2142WFOZXRKr4LMIAAd1uFvcIpKaIs=;
        b=wtGw5bxtdSKbJjVl/a7R0J6cpgpDcBHZx3WD6VuUAKSF+MRNw94IYVvtNujEPOeZC7
         PeImvO0fOSAhY4yMk/DCjGQSvWQtzNR+HTb0yzzBcMgKHOHLNEY87TWodsL73nv0+0L9
         EFUHfheh12UedqK2hhM4NU4JrCthaQajngZYGGUw2H8faTw5uM0gPVQYD+xWmnJm5Ddb
         vIHtLfBKgEle6mIQonSrmpRAUm9iSc313HdJ0xKT6DZkI/o/lZ3gxLvZS8Z5vcE6rz5j
         IhFkQfnMbFvunrg7wxNCW1RXhNMoA5iL+efhqEgyZOvwbcTTIRbkuLDGZ5+DquW2nyLC
         KX4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVomxTia7CxxIx2SnMqhDLayYjIr9aq4F3JbPW/XkHCqPlPPe9yCwllKQVpnBoe+bjwLv9Azg==@lfdr.de
X-Gm-Message-State: AOJu0YwjN2uw7+hWWZOjbPIyljeSeO3lmHdI1MA2DJHOjQqZ91yl/e6x
	TdRzp8G2YIGTfYYzXg6fu4ArYZmrLTHLtrHL+cekmgNoZPnNZX+x8EnZ
X-Google-Smtp-Source: AGHT+IG+yq0TRw2hQsycCrEIQeP8hjydxYCvgyG5apLkYMtrE9DA/eP1jHcW32sP6ynF7/HUj+GzKw==
X-Received: by 2002:a05:6000:2c0c:b0:3ee:1294:4780 with SMTP id ffacd0b85a97d-40e4a05bf15mr7799287f8f.30.1759022987165;
        Sat, 27 Sep 2025 18:29:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7ujKIkbUsOS4bGdtktgZTOp/1I/tSsOHQMqBopLRMROg=="
Received: by 2002:a05:600c:a187:b0:46e:359f:690a with SMTP id
 5b1f17b1804b1-46e359f69b1ls17881145e9.1.-pod-prod-06-eu; Sat, 27 Sep 2025
 18:29:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXeqQbQe3VEfoXuou5RATwt9QYrQlSaMRtzt3cp4SlsxRcfduipWpZasPKu9vHidi/BYuDVZ2/JnYU=@googlegroups.com
X-Received: by 2002:a5d:5d07:0:b0:3ff:d5c5:6b0d with SMTP id ffacd0b85a97d-40e44a5479fmr8024376f8f.4.1759022984101;
        Sat, 27 Sep 2025 18:29:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759022984; cv=none;
        d=google.com; s=arc-20240605;
        b=LI2fsvUo+pq7zaUfqhjhuIYv1dZuHRSBgEzh74/IcBaWh6YSHIEJoXsDs4v7dCKnyq
         YS8ok4A2UcxGUsFn0tlqeu8tOwGyTEBu5utIZ8UxoaK46IzH27ggYxq12axrP6OMj61f
         GomLTJ0LjxjXVCQfB/IY9YCkzvF3CO3eaJ8Rp14NVxqEQGbZw4S/c5vblU1KHpH5uwRD
         /iHMnJxn7JIsdfZnEbImLVNUnaxqeh2X46aWTmKOTp3WAtv+MYg8M2Gr9Rjb8kKngVJx
         Ob72dNMZbiIEuTuS0ddLogcxTKFKezlSkZznKohUOrQGowJ8IkRMx18JQArGVCFlx5Y2
         ejZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=qaaA7VF/d1dd6Y2aehhgBQqzOxirTeBTgDR7whafJPs=;
        fh=9C6cifIw/m50/OylpUu1/73JpW5FeZtVAx7mgphjNoI=;
        b=IoWaTFidlIt8pDTIxSnZ2k4laeSF/VQTKWSBZkNayiTg1Bt47VE8xXwC2QkIg3ancE
         KOR2O5nRF0rU9e+wEIZXZcuKFGbXWyxvZA6qcaYKFWl+SNM+5wloQz0s72AcumSLPE8P
         ni23EN0Vkq6eaU8EsMuxCrr6jaLKcn9XTHvF5aeINQbPXnpcFGe7fATJE8NexoUsleER
         OtAIZFVOxxfBDhsSmYMCy/j2b7xFngoN9P29rKz/EGmJADhR2JgmkJB3UFUDiiOnJB+v
         nbpJCPTvDZxaRi9OPj8Q973w3wdYHkq82IKs8OSfGWEht0GKVEBQTAUBsb/aLM2NYPtS
         KFaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FJk2cLMn;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-40fbe9d6eafsi194439f8f.3.2025.09.27.18.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 27 Sep 2025 18:29:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-62fc89cd68bso6597186a12.0
        for <kasan-dev@googlegroups.com>; Sat, 27 Sep 2025 18:29:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUvTejHWCxCRpkRK33EI4HfGBzPPRf11QycXMDnTeO2Fm+8rJ9uhHLxO9DT9VxBAjzpvcJz2jwqzsg=@googlegroups.com
X-Gm-Gg: ASbGnct9YPT1ghCziqfWaFnVIS6p73YnNz9X9IGLC9fR0Djqw6NkfRFANTBresfbVIH
	oDwppM/WWnqavIDt0+ooRd+U+aO70JXRRY3rLWkezAdfUyaGiOjDG91qZEVWDVkqjoxlmgWiktD
	2QV0OLUE7XTHAqh9I719e4YQ0FYs/iV88PvtPgPlgDDai8OjtCUEY/gZndYznYpG6LNkLn/hPwF
	3O4nnN1JPiKHqUUPE4F0eNeYZA+SOZjPCV/HP0Xhewr+E9COCmLPogy60uJj0oxr67X/z0CKjnw
	iTJ2TKF/5BV3ds1O6fybTaoLZCapNKIjWaBdecZ0uxyHAPjZqLu3Jb1lnNccs7hrVY7USAysEnl
	S8+U5OjfA48l3hmVcO/0p9wte6Q==
X-Received: by 2002:a05:6402:44c3:b0:62f:ce89:606f with SMTP id 4fb4d7f45d1cf-6349f9ef17cmr9469195a12.12.1759022983448;
        Sat, 27 Sep 2025 18:29:43 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-634bf4a5351sm3206980a12.43.2025.09.27.18.29.42
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 27 Sep 2025 18:29:42 -0700 (PDT)
Date: Sun, 28 Sep 2025 01:29:41 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: "jianyun.gao" <jianyungao89@gmail.com>
Cc: linux-mm@kvack.org, SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, John Hubbard <jhubbard@nvidia.com>,
	Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Xu Xin <xu.xin16@zte.com.cn>,
	Chengming Zhou <chengming.zhou@linux.dev>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Kemeng Shi <shikemeng@huaweicloud.com>,
	Kairui Song <kasong@tencent.com>, Nhat Pham <nphamcs@gmail.com>,
	Baoquan He <bhe@redhat.com>, Barry Song <baohua@kernel.org>,
	Chris Li <chrisl@kernel.org>, Jann Horn <jannh@google.com>,
	Pedro Falcato <pfalcato@suse.de>,
	"open list:DATA ACCESS MONITOR" <damon@lists.linux.dev>,
	open list <linux-kernel@vger.kernel.org>,
	"open list:KMSAN" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] mm: Fix some typos in mm module
Message-ID: <20250928012941.wildyant57igw7zi@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250927080635.1502997-1-jianyungao89@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250927080635.1502997-1-jianyungao89@gmail.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FJk2cLMn;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Sat, Sep 27, 2025 at 04:06:34PM +0800, jianyun.gao wrote:
>Below are some typos in the code comments:
>
>  intevals ==> intervals
>  addesses ==> addresses
>  unavaliable ==> unavailable
>  facor ==> factor
>  droping ==> dropping
>  exlusive ==> exclusive
>  decription ==> description
>  confict ==> conflict
>  desriptions ==> descriptions
>  otherwize ==> otherwise
>  vlaue ==> value
>  cheching ==> checking
>  exisitng ==> existing
>  modifed ==> modified
>
>Just fix it.
>
>Signed-off-by: jianyun.gao <jianyungao89@gmail.com>

LGTM, thanks.

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250928012941.wildyant57igw7zi%40master.
