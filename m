Return-Path: <kasan-dev+bncBC32535MUICBBXOGXGPAMGQE53CL2OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 880EC67794C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:37:18 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 9-20020a05600c228900b003daf72fc827sf7273615wmf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:37:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470238; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWC2VmbqJe53ISyuRAxhadI10+HrxfSw4EsaBXLU7lYPUZItsrX5o1hLP6OqMJhXeV
         CMnQTfoxc25P9w4zAIVd4X3se7RHn4rGswU/emb13opt2iqe9aadKWM7IilDhDWdh+YM
         p2Q/5eBDXwVx3kygZhbIAabZfFj3b0Pn/VseXNn6J8WE6J/qEN+6mqLEa08nAayMONwt
         LWqsUTq18UiwV33nvdlh0fB70N6T5rKLP+BtPuMoVvObFg/iqyaW8dX/EmfhTq2ps0oK
         ZTbFIE5K9GxXJ64m7RgaGB2rgRRCQdhGuX1rnHWHLk+f7Aq25BeaY3qppv8C7ie7Yeqn
         3fZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=oDMWXqgZAL48wrN6pbQb6Da73znOUipoaCma+VMBUjA=;
        b=vrQAfXnLg4yU8eq9uOd6NtwGhWxWE+tIQfUaxeOrdaOxUT82rq3MIBwuuYr+cbLl1M
         lXASTpxaPMDRYPXHBLx7L59rboRLWpHWEtJUs4aTk2c6CIfzh+9f52XqCKYvTILubrjC
         sdlUNIxQGW+AqNimRswmLhOzOhSnRVa1XcgbrFowgO1rLYkZJKilnNVQEnxNy1H9fUGT
         U9ndgSXiySkqyU6bhbU0tDtsUYgvIrdxlw17ZJ9zy75DuzB+Xi5KrZPsqoTEn32b64Zt
         Swq+iYunW5Sfahm+W5yY7RcXkExwSUoSyXGfGbeBwHfIc3jBYS23Q01WGLNU2jQdaFav
         +v7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Hlj0qrAY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oDMWXqgZAL48wrN6pbQb6Da73znOUipoaCma+VMBUjA=;
        b=KYEufJnQ2x1lz4HCDk6ZXddYy7jpPO6WK9XvuVisiSlf/iYDAXAdA4x0DFCmMsLAcg
         KKCsqaTsQ6A9io1jieefl2kmRDL/sI8GTa695t0MRLe+3NbeoMFQ5wPS554VhDWR7GhF
         OJG1KSSb2hSZ28snotw90i96KBD1z5hkb2+wUWudEztVYrbXMye3K1sIgr9uDyCH8GHD
         8hjveCyRcuWoXDQUNhV9cPD7tCAQGE7e2ZMi+Qf+wXN8u27BphJGWGSbAp7z0uDESQPq
         eAYtvBfd6Rm/pGAF+01tYGOxA7EV6kFHTXT5exw0QgfWuCToBF63RnI7Ik2RB1z/soOr
         y7xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oDMWXqgZAL48wrN6pbQb6Da73znOUipoaCma+VMBUjA=;
        b=i0F74fYlc/BVvRzo0DRyyPh8JtYGZQFEvSkNQA2MK0dsMtR2HeQg0gwXN2dZBkDpf1
         Y5SXLKUct4kEQ5f8gW5SUVUHd1RWqZt7KGfS5rVl9BvFwCvMzpIY6vmDeqr1t0zwzNyX
         p+l25AFm44GfmEbklDgSOWsN5xS+LYgJXjLFiOz8I8MIeLdfvIsioFfEIan0JTEwzEsv
         oFA8PS/IVvFKhupathHdpGNOBv8/ourmpp8N0ZQcayD/vBOsz/q8WWa1iChuY0G/FnJE
         TZnhOQS0PvrusKf7leXiWmWedzLny/6eR0idfHEHWi5LdyHOXQRjnldjQpkwddczSMmi
         fohQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqlnQbPLauxf4JQe8rcd50QyPhpFOvoB6OgKBAbGYtw28BDLi4h
	a105v/sXWuiWFVotBTdWg+g=
X-Google-Smtp-Source: AMrXdXtdNqafjGIFvUqiHyiarD8rzKa7lqxvQ+PIdjDV9VjlXtbhUuo3xrYqlWGuVe7yDVLfvUVLhQ==
X-Received: by 2002:a5d:46d2:0:b0:2be:50b1:c10 with SMTP id g18-20020a5d46d2000000b002be50b10c10mr621197wrs.652.1674470238079;
        Mon, 23 Jan 2023 02:37:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47a9:0:b0:298:bd4a:4dd9 with SMTP id 9-20020a5d47a9000000b00298bd4a4dd9ls10223330wrb.1.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:37:16 -0800 (PST)
X-Received: by 2002:a5d:4bce:0:b0:2be:4ae1:215a with SMTP id l14-20020a5d4bce000000b002be4ae1215amr11796815wrt.16.1674470236864;
        Mon, 23 Jan 2023 02:37:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470236; cv=none;
        d=google.com; s=arc-20160816;
        b=H45Z5kWOti1s63Yc54vY44fz5Z8Dh/7NUY+wn9W48oDvnHmj+xJDykre7BZ0RXylR5
         Rh1/M7J8bo29m/8f1yaVN9OdPSn+LWRdodfBV5/UISoCKaS6qRmRHhG99NGYE6NQxf8i
         XEUKbctYqJksu2lXruatUsPVGz/HI+fv8tm6CX2SJlmykuqv1JWBaJ+kdgfLtss74/dX
         Vldbz2c1n5HFBeNOmmCnGEnSHzRde1c4nOSD9r1HRZB3G3lkmhXxP8MWOQScyCqZ6ELX
         WvjPCCNppJQaOD7UXqz9YvmwevsadAoTgmgiGHSDozqcRGdxBFl9NpFU7zK0yAkxR+oK
         UkPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=97nOSUI3JR1wE6WexR91D0yIRA6YHyk9Wid7L68KGuE=;
        b=c58cLZph5cMLJS0YFtGDi3BrFmfcj6YH4qbu+bi0UoeB3nhZVMHLd3Jz3O2Y/DAxMk
         DAtMBSHZj2MvUrMaG7IQgiJ7EKhjBRTCrLFY7GZaMl/O8ARziJ05AEsx1RUPGTdn+M0V
         rccBb2rWkuJet8GqwKf9RAr2/zO69qfs5UuqZ3t+JdnqI5UlwK32pke4sgaQ/HXxLNAx
         rgc34JtnH20neD8CoS5AzAgFSSQRt9NsFdgrhvVBkB6QKCldxB4O2s0wyk8G2hSN3ZbA
         x7+y4j5OOUDXB3fNjym5zsZzNzNn3F6mXfmarEXPhtcisQfFlIm51OSCd5vFGR8izbNW
         5q4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Hlj0qrAY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ay20-20020a5d6f14000000b002367b2e748esi1081909wrb.5.2023.01.23.02.37.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:37:16 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-594-prK_e9j6OzGg1sd5SLN7VQ-1; Mon, 23 Jan 2023 05:37:14 -0500
X-MC-Unique: prK_e9j6OzGg1sd5SLN7VQ-1
Received: by mail-wm1-f71.google.com with SMTP id bg25-20020a05600c3c9900b003da1f6a7b2dso9233226wmb.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:37:14 -0800 (PST)
X-Received: by 2002:a05:6000:1241:b0:2be:5343:6add with SMTP id j1-20020a056000124100b002be53436addmr10785377wrx.55.1674470233303;
        Mon, 23 Jan 2023 02:37:13 -0800 (PST)
X-Received: by 2002:a05:6000:1241:b0:2be:5343:6add with SMTP id j1-20020a056000124100b002be53436addmr10785360wrx.55.1674470233063;
        Mon, 23 Jan 2023 02:37:13 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id h3-20020adfe983000000b002bdf5832843sm21268027wrm.66.2023.01.23.02.37.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:37:12 -0800 (PST)
Message-ID: <ad5ff935-bf1b-bde3-7f4d-45457f483fc2@redhat.com>
Date: Mon, 23 Jan 2023 11:37:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 03/10] mm: remove __vfree_deferred
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-4-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-4-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Hlj0qrAY;
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> Fold __vfree_deferred into vfree_atomic, and call vfree_atomic early on
> from vfree if called from interrupt context so that the extra low-level
> helper can be avoided.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad5ff935-bf1b-bde3-7f4d-45457f483fc2%40redhat.com.
