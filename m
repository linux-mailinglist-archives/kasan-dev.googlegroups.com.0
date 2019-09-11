Return-Path: <kasan-dev+bncBCXLBLOA7IGBBRNH4LVQKGQE2WIZNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF78BAF5BF
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 08:27:17 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id f18sf10075302wro.19
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 23:27:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568183237; cv=pass;
        d=google.com; s=arc-20160816;
        b=eTz2L4H2h4ONo/rgdNjODWjnLLkiS0fhWvXYsMyGFgAB3n/wXEKb3/8lCUAnc3EqPk
         V1pd5PTxxwbVvV3gcfiNN3pbGraMkPD5YBr5DWIrPvJLlPG7EFyd2aJiK0DH46Ha/eOr
         tLbZTH+Zm+qnHfXvg4pTImXj01lHMGqd1lNzFpyQpqwn6VCC/s/RadK/0dmFZKqpRuto
         dewTH9V12sqinD3EGXzNsS67736uPZBegZgTeZdJnY9W57jJbKZ+yMXdbUDj1FRz4d22
         mVKqd6mmT9B8sOTecYBE/NqDasHksO4jzmwiHt1cs5rsuQF7e2mp67crv0UcOwn3Tel/
         y4Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=reszjKQSJXTRTPj0JULR6znMCGP1Wf7yXaDUiKzB9ag=;
        b=d9psvpLXQr9SOwt5WwUY7L6gUOh38jkOg1kOb6mNsSYIM/YF666TJscYJwAn+LAUcJ
         Aig0p+W1HSckBID8TKNgzZ0ZU8NJdApp5AXoP3gnyDQNMvoLTOAxapF85/mxVTzg3NMQ
         AI1+MYk+RWCIuMKLSCX7uqFiOI1AAcQ0ZsP4DZkCCYRX7heT/wREXKkGeazXgguLpBQU
         a3UuT7/6SpS0m5w1QlNOn3WStjQVTnoLBbESfo6RcvNRPK4WP9cXCUiOvRjTj1oI5mq1
         oOl/mC96dpx5dsfJiIfH/v2AEVvjnz5zVqnWbkv0fim8oW9SkbWVNZg8+9M0VvX+znKI
         qvJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Vv9CIr4I;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=reszjKQSJXTRTPj0JULR6znMCGP1Wf7yXaDUiKzB9ag=;
        b=Pk7Hv8GkVxsxsxp5hO/tsYZgEDcIpMOslRTH0tw9FToUpO4VVQvik9wR4VFNzg8Ah2
         P6ug9hGPiy/HeoZn5hNPZ4fQx6cZl7P4PWw5SNy7rITX+psmnFkiNJ34+YI1dRdWonVP
         U8DWHwvKdMaKXQP2pdCmQTt8SIg8iDB1Iy+c67U+UC9rlpQTgkmVrhB1OCso/JpmB+eb
         YtLeSl8z0Sb8rmbMDzXwT6XHvgepEoYhFqZvSM57LDnbULlyS6KudOFMrE2OGspgicP9
         wZWlUP9muIdzx69wF15F/rWOLQeXie/QuSOi/UzbUMG5t4VHEvCNl2PU13aLsEUdOwpd
         EC9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=reszjKQSJXTRTPj0JULR6znMCGP1Wf7yXaDUiKzB9ag=;
        b=Gil3Ysf8TsD27u2qzDyZ0khuvjXf+Yo7H3zUnb5lE47Vxu3JpsSWF2sxiK/POSl7ar
         ZlPCu6uOjMp7LYn8YihCJJu2k2m091cFUVwxib2MM5Qey0ggyH0+M2ARuy+URAqz7a7O
         97oMQyV4wb1FogS55xabFTN0HEmkSzDc8cndjSGHlEtz5tFii//f0socVY3EfFqyVkGo
         Z0gM8K/XTO2yjoHhnu+DrfWrAYL/4VR7zwrWWyy3IpUfp7kLYuxRqqrm2iSJRBAGAalO
         Rgc6CTFlZQufn2Sy7sQdou/ILsrI/GGRvmF+AqDYt0cbL2soEM7lvD3GyxWAQvZKM6Sg
         U1rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUleb9Pwg6/gndCEwfZAC3RA78wSPeDgDx8oZXv9F3E9K146Tm5
	+WLfJzI5hvMzumEt67yFTKw=
X-Google-Smtp-Source: APXvYqyHerWLtVkWrb2Std5jpjnWhs1drZoc6XOkgfnLSvWJSlV0afG0wTQefD0NxU4yhX9DwNP8FQ==
X-Received: by 2002:a5d:5281:: with SMTP id c1mr7098226wrv.339.1568183237515;
        Tue, 10 Sep 2019 23:27:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7502:: with SMTP id o2ls735042wmc.4.gmail; Tue, 10 Sep
 2019 23:27:16 -0700 (PDT)
X-Received: by 2002:a05:600c:285:: with SMTP id 5mr2648364wmk.161.1568183236971;
        Tue, 10 Sep 2019 23:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568183236; cv=none;
        d=google.com; s=arc-20160816;
        b=iWEBT9XChnYrrtUtYetw4TP7Lo/1RfJ30JMDg0cBDetoOxSFIqIe2Dny4MpG7QkC/j
         rVZSMyQX8w8opQLKSj9OJLP2xWMeWmggEm2HLzCFXc75FU/dhFsJ7+IDElf1Skl9g/F8
         s3IB2nX7ARpyaTXEyNsCEOfHBB9qms1eNy6BPGo25ODCVt+0hZ+RGUJyoTEw5CSdsaYl
         AUlmxMWW8hJJqONz2roMel1wKJ0gnnY/ySMw+9iarAUzRA3Ctn2K30C6BQhPWhsL/oDE
         Fhv6CrltAeAHdk1B4dpEmjqaq4RFPFYLAjrJQHxR5wqzXjOMFuCDm4fTstz69v5mRvv3
         LPfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=8DN7IMEU4e9mFBvwAi2QoWhd7U2FAikrDh/bbqIdhac=;
        b=rIOO+oMZ2baVIxKfqgN95EWqq9UK9XL6j5J8yGd4UaLr26X1ivyROrUPCn7ZU8sz19
         kxLJD5GiWE6dXj613FO24wExNUc9KQGQ5NKO78atvhOtboJtddDXAu/b28ZmkFVwF6Sl
         rgqNeSk7PJY+ke1D4fCRnk0HDoLo3S44wwdP/TxSNOZ7ZZPgoMOCLiE+j2LwJyM551Rm
         MP6f3XHNWJx2P8OFQ1JqdL5AgeegsBO+xiZb70VbSHh/5woHQg4FfMNYtTXaGwbxXN6m
         oVUtsQUfFue6JPLL/sE/i/EB7+gHDd+ZOnXyInc5ocxgCDpJre0mnlggkiDv5kJodDow
         KrXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Vv9CIr4I;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id x13si146933wmk.0.2019.09.10.23.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Sep 2019 23:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46SsPv54XQz9tyFD;
	Wed, 11 Sep 2019 08:27:15 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id w1BPK-Y6gRxf; Wed, 11 Sep 2019 08:27:15 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46SsPv3ylWz9tyFB;
	Wed, 11 Sep 2019 08:27:15 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6F62D8B7CA;
	Wed, 11 Sep 2019 08:27:16 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id haPxXK31oHYl; Wed, 11 Sep 2019 08:27:16 +0200 (CEST)
Received: from pc16032vm.idsi0.si.c-s.fr (po15451.idsi0.si.c-s.fr [172.25.230.103])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1FCC38B74C;
	Wed, 11 Sep 2019 08:27:16 +0200 (CEST)
Subject: Re: [PATCH v7 0/5] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20190903145536.3390-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <d43cba17-ef1f-b715-e826-5325432042dd@c-s.fr>
Date: Wed, 11 Sep 2019 06:27:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.7.0
MIME-Version: 1.0
In-Reply-To: <20190903145536.3390-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Vv9CIr4I;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Hi Daniel,

Are any other patches required prior to this series ? I have tried to 
apply it on later powerpc/merge branch without success:


[root@localhost linux-powerpc]# git am 
/root/Downloads/kasan-support-backing-vmalloc-space-with-real-shadow-memory\(1\).patch 

Applying: kasan: support backing vmalloc space with real shadow memory
.git/rebase-apply/patch:389: trailing whitespace.
  *                 (1)      (2)      (3)
error: patch failed: lib/Kconfig.kasan:142
error: lib/Kconfig.kasan: patch does not apply
Patch failed at 0001 kasan: support backing vmalloc space with real 
shadow memory
The copy of the patch that failed is found in: .git/rebase-apply/patch
When you have resolved this problem, run "git am --continue".
If you prefer to skip this patch, run "git am --skip" instead.
To restore the original branch and stop patching, run "git am --abort".


[root@localhost linux-powerpc]# git am -3 
/root/Downloads/kasan-support-backing-vmalloc-space-with-real-shadow-memory\(1\).patch 

Applying: kasan: support backing vmalloc space with real shadow memory
error: sha1 information is lacking or useless (include/linux/vmalloc.h).
error: could not build fake ancestor
Patch failed at 0001 kasan: support backing vmalloc space with real 
shadow memory
The copy of the patch that failed is found in: .git/rebase-apply/patch
When you have resolved this problem, run "git am --continue".
If you prefer to skip this patch, run "git am --skip" instead.
To restore the original branch and stop patching, run "git am --abort".


Christophe

On 09/03/2019 02:55 PM, Daniel Axtens wrote:
> Currently, vmalloc space is backed by the early shadow page. This
> means that kasan is incompatible with VMAP_STACK.
> 
> This series provides a mechanism to back vmalloc space with real,
> dynamically allocated memory. I have only wired up x86, because that's
> the only currently supported arch I can work with easily, but it's
> very easy to wire up other architectures, and it appears that there is
> some work-in-progress code to do this on arm64 and s390.
> 
> This has been discussed before in the context of VMAP_STACK:
>   - https://bugzilla.kernel.org/show_bug.cgi?id=202009
>   - https://lkml.org/lkml/2018/7/22/198
>   - https://lkml.org/lkml/2019/7/19/822
> 
> In terms of implementation details:
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate a
> backing page when a mapping in vmalloc space uses a particular page of
> the shadow region. This page can be shared by other vmalloc mappings
> later on.
> 
> We hook in to the vmap infrastructure to lazily clean up unused shadow
> memory.
> 
> 
> v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/
> v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.net/
>   Address review comments:
>   - Patch 1: use kasan_unpoison_shadow's built-in handling of
>              ranges that do not align to a full shadow byte
>   - Patch 3: prepopulate pgds rather than faulting things in
> v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.net/
>   Address comments from Mark Rutland:
>   - kasan_populate_vmalloc is a better name
>   - handle concurrency correctly
>   - various nits and cleanups
>   - relax module alignment in KASAN_VMALLOC case
> v4: https://lore.kernel.org/linux-mm/20190815001636.12235-1-dja@axtens.net/
>   Changes to patch 1 only:
>   - Integrate Mark's rework, thanks Mark!
>   - handle the case where kasan_populate_shadow might fail
>   - poision shadow on free, allowing the alloc path to just
>       unpoision memory that it uses
> v5: https://lore.kernel.org/linux-mm/20190830003821.10737-1-dja@axtens.net/
>   Address comments from Christophe Leroy:
>   - Fix some issues with my descriptions in commit messages and docs
>   - Dynamically free unused shadow pages by hooking into the vmap book-keeping
>   - Split out the test into a separate patch
>   - Optional patch to track the number of pages allocated
>   - minor checkpatch cleanups
> v6: https://lore.kernel.org/linux-mm/20190902112028.23773-1-dja@axtens.net/
>   Properly guard freeing pages in patch 1, drop debugging code.
> v7: Add a TLB flush on freeing, thanks Mark Rutland.
>      Explain more clearly how I think freeing is concurrency-safe.
> 
> Daniel Axtens (5):
>    kasan: support backing vmalloc space with real shadow memory
>    kasan: add test for vmalloc
>    fork: support VMAP_STACK with KASAN_VMALLOC
>    x86/kasan: support KASAN_VMALLOC
>    kasan debug: track pages allocated for vmalloc shadow
> 
>   Documentation/dev-tools/kasan.rst |  63 ++++++++
>   arch/Kconfig                      |   9 +-
>   arch/x86/Kconfig                  |   1 +
>   arch/x86/mm/kasan_init_64.c       |  60 ++++++++
>   include/linux/kasan.h             |  31 ++++
>   include/linux/moduleloader.h      |   2 +-
>   include/linux/vmalloc.h           |  12 ++
>   kernel/fork.c                     |   4 +
>   lib/Kconfig.kasan                 |  16 +++
>   lib/test_kasan.c                  |  26 ++++
>   mm/kasan/common.c                 | 230 ++++++++++++++++++++++++++++++
>   mm/kasan/generic_report.c         |   3 +
>   mm/kasan/kasan.h                  |   1 +
>   mm/vmalloc.c                      |  45 +++++-
>   14 files changed, 497 insertions(+), 6 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d43cba17-ef1f-b715-e826-5325432042dd%40c-s.fr.
