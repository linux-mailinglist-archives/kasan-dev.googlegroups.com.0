Return-Path: <kasan-dev+bncBC32535MUICBBRMK7SRAMGQEILRVQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 487EA701437
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 05:34:30 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-3f41dcf1e28sf28361975e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 20:34:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683948870; cv=pass;
        d=google.com; s=arc-20160816;
        b=I+rMeyrMdonrsvq6Uf/jRZqE2H7D5FPlgVk4E7bxVktnCMhGs7LWv8w9+E3UfltuEO
         KOjQd/QgBdH31ocAq0rgLwFgyTJ1ihomPijT0nZ+XYeDi0dWELYyLM5oFye2Oz+9/1EP
         4ghYwTiYo/R+ZiWBtQZBQ54IgaPej1ACnzO8Kz/HB+93Mbt/3680tH3qZpb/Sss7CuEl
         7Fxh2eQDa52Y0btZhnqRfqXzxwtjEEgzHD9yAkbIWCkdmyk6vlT/TuVtFATLhSqb2baa
         +85KNI38IwJe5EUN788mibwC5mp7rnlgf5BbhZGsF9H8iscYANZKiMcEJbO2KhLdcW99
         rmtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=PgbemjlFyDIJ9MOidhGbrIMMn6ELP6B/TKdmRjlyNgE=;
        b=RmwgnSUKkkCQopCDG3TJQ4a10mZFJgnkFqHBajxpqrim2wltoV1TwovpcQ31p39r2G
         x5CRAT67OpRSnR4htb6uo2MnTiOQdzrlNThu106KntH8qVfh1Dt8sz3TYjtamvTsos93
         twuYOlbOrAsgwhNetrPX/sTMSaPRllcj6m8CkxUchqp26wWMEh7FEocIUiLNrLfJ1/lT
         Ow9Ub6KcQOxpcx2t5hjAGPdODmVmfmj5WUwBneUmqDUIoeXe37UksqooG4qTDY5vpFqz
         N64n5kxJceG01rcRc7QA7J6XK6r9k3dRVSBX4deL7GSrHW636/ntXy9QwtlZQIMeXlwy
         yAhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Zc4hkQfY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683948870; x=1686540870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PgbemjlFyDIJ9MOidhGbrIMMn6ELP6B/TKdmRjlyNgE=;
        b=p/JxEaD6KBgB0uik4jxJixPh4KlQ5H7NzcdJTzoZNQaCHMo71j5FMx/QoKLtZLVPeH
         yemlC8bcCM8/bZZCzGk0XD01192SFih1zr+D3sWeygGvo/KRUAClT+MfkyQCGmKXV8oD
         I9hr7Fn4L4KzR6yI+A2Fj3XicStGzNMKeOK7dbjxBOu/65aKzSKKOQjLQyhFLR26Rjmp
         GRZ1zOB1FGhOXflFnRWr3z8z/WUXqas16zgcFxkbtCdwTmIu43CdRhKGMiD84ZI99nWn
         OyLDIRyEd/QM5OjoAhBVmkLBrhg985xvWT7Npbt0Ndu584EY167fgYkhLQv0u8/iCPF4
         CnrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683948870; x=1686540870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PgbemjlFyDIJ9MOidhGbrIMMn6ELP6B/TKdmRjlyNgE=;
        b=BSI03rLkYjfG53NxFu/m3uUPRX7QVnXutDh8rKkAsZdfKPQ2R20orZVFk6JMn7/MBZ
         5SJcwiJATNxovUeK3jYNFnWkUY0eajA2OsHmI8kyjh6nonWlyslnE0kv1BaGyeykksIB
         Hrftu0HZqmqohNIgzJg1C5BUiNyAIlen8qpZnmSGoVL0iUCR4F756htAfUXCTf2o3Jv0
         RD8Gqda14GrC6lVciCATLXuXIxtts7ti5dBqymTBdj+UFALqQhlrwmnplvN6/b8W5SUg
         yualYwn70OHQCUxq5Ar0N4jm4HXISmZ/Wq8xu0pClkN+/6Z6jsXPmeQzj026O2TMyjhw
         qKdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwjll8j/AZJcOCNDDe0Cxutbcf+VdcZ5KwQEJMURf11sz9j95hl
	gnHeWlxaQ/ujLu053dxAXy0=
X-Google-Smtp-Source: ACHHUZ5hCX10nRYuizUKewdZAYWj9zdvIVmYure1xFjSiEfLboue/gR3YTZQohiWn7Bph09auY7TfA==
X-Received: by 2002:a5d:444f:0:b0:2fd:da4e:f706 with SMTP id x15-20020a5d444f000000b002fdda4ef706mr3623794wrr.6.1683948869617;
        Fri, 12 May 2023 20:34:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:16cd:b0:2f4:1b04:ed8f with SMTP id
 h13-20020a05600016cd00b002f41b04ed8fls3974681wrf.1.-pod-prod-gmail; Fri, 12
 May 2023 20:34:28 -0700 (PDT)
X-Received: by 2002:a5d:4085:0:b0:307:f75:f581 with SMTP id o5-20020a5d4085000000b003070f75f581mr20862292wrp.18.1683948868214;
        Fri, 12 May 2023 20:34:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683948868; cv=none;
        d=google.com; s=arc-20160816;
        b=LTu5ZxJ8ZbV2bFyNwxq6bhJ66Cn0CbRm6ENtxRmGxSUJMNjCvl8/vRbRpSuj1Ax/VD
         zwpKZWIV+QkV0nTrOVE+f8d7+ezewe6egcreryyWapQS7EtUhf333pTBb9qkscEUqVoR
         BS2JVINNAF2mOvJL0nG+PKiPDohKA8G1SlKF5Ux8MGnUNVDH3CGJbrug3RvKKMy9TUrK
         l48hYf3CsAr842JWhdVue5dRX+67wvWc88BrG8q+URWTqqxHyujsmX3WH5qvG8z7obb3
         Qw+UoqLfXL325TrsPYu8URLpr+50z3dBxRuEGM0w0Xr1atv0rtLN93gj7HiIdY1sg6il
         tGbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=5iuN8vfyC5tHnzEyX8BlDAD7L1Af+tn1GvUhlcPzN64=;
        b=SFeo7OWHokfSV9glC7q17j5Ue+oqvFTanN2kUULSv7oBvA6wst5kgCKPpU3N0AM4KB
         PXqFQ6o9iVOYJYT3aorvlvbiKAcz3QD78a7ZBZcGXTcQ9rhEvKKuXt1JWlAqtbCHv8Rv
         FwS8h5UNuO+WPXV44sMF9FJHa+kDxJ6sDsFM5rLllPqizXtjYCDLFgxrl+aQ6tXVfaPN
         tJTW2apeE3Jwk+QFKVf1gp2Ihxd0bOdtul3ZNz02BRmzYwN4tL3h5/BeDNWcvZY07/xV
         HMabbXe5ZslJTfxKUD5a+w+1IkRnrFhqgBlDjYLhPPBcXdxgUM69RGXVFjsWbX+u2jnS
         q6EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Zc4hkQfY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id bt6-20020a056000080600b003062fa1b7a0si1391147wrb.2.2023.05.12.20.34.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 20:34:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qv1-f69.google.com (mail-qv1-f69.google.com
 [209.85.219.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-634-47LWmURZNkyMpDatjItBbA-1; Fri, 12 May 2023 23:34:24 -0400
X-MC-Unique: 47LWmURZNkyMpDatjItBbA-1
Received: by mail-qv1-f69.google.com with SMTP id 6a1803df08f44-61b78e49e99so55207806d6.1
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 20:34:24 -0700 (PDT)
X-Received: by 2002:a05:6214:c8e:b0:621:5e3b:8eb1 with SMTP id r14-20020a0562140c8e00b006215e3b8eb1mr15765380qvr.21.1683948863651;
        Fri, 12 May 2023 20:34:23 -0700 (PDT)
X-Received: by 2002:a05:6214:c8e:b0:621:5e3b:8eb1 with SMTP id r14-20020a0562140c8e00b006215e3b8eb1mr15765364qvr.21.1683948863330;
        Fri, 12 May 2023 20:34:23 -0700 (PDT)
Received: from ?IPV6:2603:7000:3d00:1816::1772? (2603-7000-3d00-1816-0000-0000-0000-1772.res6.spectrum.com. [2603:7000:3d00:1816::1772])
        by smtp.gmail.com with ESMTPSA id a11-20020a0ce34b000000b0061b62c1534fsm3391537qvm.23.2023.05.12.20.34.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 20:34:22 -0700 (PDT)
Message-ID: <2bf4062d-b3f1-671f-0aa4-7f3e98402160@redhat.com>
Date: Sat, 13 May 2023 05:34:19 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH 2/3] mm: Call arch_swap_restore() from arch_do_swap_page()
 and deprecate the latter
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-3-pcc@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230512235755.1589034-3-pcc@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Zc4hkQfY;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 13.05.23 01:57, Peter Collingbourne wrote:
> The previous patch made it possible for MTE to restore tags before they
> are freed by hooking arch_do_swap_page().
> 
> However, the arch_do_swap_page() hook API is incompatible with swap
> restoration in circumstances where we do not have an mm or a vma,
> such as swapoff with swapped out shmem, and I expect that ADI will
> currently fail to restore tags in these circumstances. This implies that
> arch-specific metadata stores ought to be indexed by swap index, as MTE
> does, rather than by mm and vma, as ADI does, and we should discourage
> hooking arch_do_swap_page(), preferring to hook arch_swap_restore()
> instead, as MTE already does.
> 
> Therefore, instead of directly hooking arch_do_swap_page() for
> MTE, deprecate that hook, change its default implementation to call
> arch_swap_restore() and rely on the existing implementation of the latter
> for MTE.
> 
> Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")

Can you enlighten me how this change fixes that commit? I'm afraid I am 
missing something important.

What is the user-visible impact of the problem, how was it caused by 
c145e0b47c77, and how does your change fix it?

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2bf4062d-b3f1-671f-0aa4-7f3e98402160%40redhat.com.
