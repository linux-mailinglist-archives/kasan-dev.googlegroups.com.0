Return-Path: <kasan-dev+bncBDJNPU5KREFBB7PGYPCQMGQEKU6TFFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id F301FB3AF09
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 02:25:34 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b2b3cd4d00sf42094241cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756427134; cv=pass;
        d=google.com; s=arc-20240605;
        b=DXkox9fEGY0S5bj+qLwk8ugrOFFTY1Yvos2ryMOFRq/nsFQ0A/Cyltg1s4E8bLrHyr
         3Yfcj31Y/U/ZFiIgRGtDLQWSEhvZS4b4DmLhHzN8rRg5QQbgyutTc6W8XMv4SNrI/aIQ
         QAXA9Bw8vS1SNayGCGW6hcTXKW8i0e9/R92aKdIdbuZ7yA90r5/Ob2ZykWZfaVv2uGIM
         zTKrTPqsKvJmeEjLE3BSpWyaQmvnSlVhvWPNSuzSDnhrOnl56YMGn9sFXgqy514v8xCj
         0xmq99upGssySZEcByKnNGXujJD/T1TiD8Anr2GSOmLXieO8XlAgRBmfm6dPRDfeTMyU
         efLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:organization
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=r8R73lv4DawDqRVGfIoTm6XrBL3McL+kAak6PRcEoro=;
        fh=0nPpeG4d1BPjc5UOfPwafD9p/odfgO2xx2B7NGBpbZQ=;
        b=O69XuJ3T8gUWkD+uXF+KhuWrSZg53Fbxxpf1/8acP8Z5sStiQOFXM/2rW3vk/XVWBI
         wNm7WWW/S9pTCVqqq7BltQf/HS7cHGpM48BM1m0JcJ/ntH+nxLlfQc+qNSF4bssqkq2W
         a65TQsYRW68qcIhqH7O4KcHtN8lgKE+5opbTIb+7yWqYM4U/Mg6Uz1czh81LikMXG37m
         XOYCbmwc05oIBxOWCY/BL3rbek1449uSCoAhvu64xo+Tt+ULyB0nNfH8GnEBu26nunm7
         wVIQJXVrQlGwhbLFA4J/D9JIbXWqZm+WZ5xUhQOk0uTurC7gkicpiDApWGXmz6WHTqKd
         aPfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="u/oWKLrG";
       spf=pass (google.com: domain of dlemoal@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756427134; x=1757031934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r8R73lv4DawDqRVGfIoTm6XrBL3McL+kAak6PRcEoro=;
        b=KCaczhO6llfPfFN4lrdQyhYuFZkVFXrbyx+iLwC3F1bF7G/heTxoiNg0YFabvtQVx0
         Tz6MJ1M6uTB9Fxa9hZV7KOZIjlk3LrenYyhPBZzXvNV0eu4R8XK4Qm98QP5BKT68Uy3L
         7RWNs0O1YRfQpAsmXVf6UCX/rPZfoBwkDTWiVQgAxyuqdDiu9Z6uInURgZ+/TFJ2YS2/
         3XRfbo0tbBo/+DpQuxvZZl0FKKsaKPwSdb5Gob6K1oqpM6svzdOlQjWnt1qJOsCw1Qn6
         Cw+2HWO9GXYUayiKTT7z4Y8YCiAwzZ/8paiFpQaSQNwjR3ok6AQQWhETtgf8Xx7b9OHe
         8J+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756427134; x=1757031934;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=r8R73lv4DawDqRVGfIoTm6XrBL3McL+kAak6PRcEoro=;
        b=cHmf+rHUTy9E3NFUFPoqE7pw6NvueBZqTVP+9sXlRdXR2tXsrGt7Y2pXjCnIAdrXxN
         2TM7XwyYsUNhVHKxBk/1HOJU1qvnW+0TZJei+3fkqe8plSjplPsldl3VBsWvlnS6outz
         a3Eo3ZciWzsmco3m8K3YjDHAqSRLvr9fwyfy0mliVsFROHDXa7ag9y5qDTjjQxPWUl5n
         nVt9ra4GLAGj9/yJ5AkFW8b4Pj9AXHjkXWtZFNubtmXvM1RgvgqdT2dOUz4GLIiY+hNq
         Hlr3HLB9yaC0qiAsrypruFMc3GeM5A0Uxyt5KiRRpvE6cmjN3gVsTGU74JjD9owfI1sO
         EBVg==
X-Forwarded-Encrypted: i=2; AJvYcCUgk/Fq0182Lds83sJuOB097ivZTmQNwDxpoBLDS5k8EIn4sshl10lcf45J8xcBEH78ov/iJQ==@lfdr.de
X-Gm-Message-State: AOJu0YyORGqsfFJrrz8cgyyjpA+vLt/SaEb6ufmiVLDx8a6E2vaVktfV
	m2x1MstIpRhVOK1sL/ygnmdJ3IaSfkv3SsTt+Fj3smofHQUcloZhRyxi
X-Google-Smtp-Source: AGHT+IHDaR3eLwYerOFgBRWnvQfGp77Czv5pMLTwr9J6WKhmzhD+Dq7XffiPo6NlWaq5MG4dEflV3w==
X-Received: by 2002:ac8:5c91:0:b0:4b2:d6d9:cf6b with SMTP id d75a77b69052e-4b2d6d9dba7mr137854671cf.12.1756427133624;
        Thu, 28 Aug 2025 17:25:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIYGJDmXFKI+ArQA6lvBdxXqtr+dbGqS5aJBhijZAplQ==
Received: by 2002:a05:622a:1a20:b0:4b0:907c:917b with SMTP id
 d75a77b69052e-4b2fe630d6cls20960361cf.0.-pod-prod-07-us; Thu, 28 Aug 2025
 17:25:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpibQ+gudlYc4H6/8qCGn7VG433fsCLT0F/Ptg1yRFNAQNqg09prTS3060feheEXgy6WCrbCCwV8o=@googlegroups.com
X-Received: by 2002:a05:622a:410e:b0:4b2:fc60:6396 with SMTP id d75a77b69052e-4b2fc60647dmr67227421cf.7.1756427132843;
        Thu, 28 Aug 2025 17:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756427132; cv=none;
        d=google.com; s=arc-20240605;
        b=hK/prThgtcHtcAUYMQxDdvjC0vnJ/rXiMUi3fvqA9Wo6aRQDr5z0o8YLWunVekgXZR
         41GTLaTopKWxI1oeUE9HlpGpSrjTBjZ8sWITGBG9XlB3IfUqQVDLSun4URM4J9KZhjFY
         Gue1ubgPY3o743nlUEWri9mam7p27wPP6s0AFcKVj7eC07l9sMTyjrXcbK7eaQe4hFno
         +Hg4kZewhbnoxO9zjcDHtsC3r57BYdbyr6/eWCnEWLZwWDv9kBeHBanbbqE3lW3Ac4Pw
         COssJ6tctKSqODeSCLxYopjLavqurz2kVyoCg8HCHHjbjqhE4IGdk6mGx4yWQ6OeXZvr
         z+Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=9qEiRJT6L0KlzrHaKsBXIek2jdzMCUk5kk8Lf8Edofk=;
        fh=qdtluGAZLllB6I5rB36PbmG0XwQyjWY9GS7A39WZ6pk=;
        b=PbeUzG97TOdBPSGn3LipOX6j6CEeuaMwk3K3+vYEpy3RWD8Erya8glgPFZ/31IwGQJ
         PHbju+AQ3eRhby2jFks1h1p2W5+kQ5gDxEoER3W0UVIM61gnWxtYZ60kRLBQ8MfmJODw
         TcgiHcNdmBPtmDw/4kLrcIy6072fFJwjdrujMFtqNMw9tFQaW2S/UQqOxxV6tkTnxj6f
         miwrL1vqagX8lXFPjv8i4t+pTbs5eT8suAM1L1PnJ0OvK0AJ3U4UMvowAX1s0Q1hJHOK
         UPXNSpkXaWQ2o5Oe8kuMYV6h4gFJklTNMLZ9vW3irAY5229t1YlxW/8G+HQQkKKmXaAe
         wFnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="u/oWKLrG";
       spf=pass (google.com: domain of dlemoal@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b6b4844si414981cf.5.2025.08.28.17.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 17:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlemoal@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BA50844450;
	Fri, 29 Aug 2025 00:25:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 12DD3C4CEEB;
	Fri, 29 Aug 2025 00:25:23 +0000 (UTC)
Message-ID: <423566a0-5967-488d-a62a-4f825ae6f227@kernel.org>
Date: Fri, 29 Aug 2025 09:22:30 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 24/36] ata: libata-eh: drop nth_page() usage within SG
 entry
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Niklas Cassel <cassel@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-25-david@redhat.com>
 <7612fdc2-97ff-4b89-a532-90c5de56acdc@lucifer.local>
From: "'Damien Le Moal' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
Organization: Western Digital Research
In-Reply-To: <7612fdc2-97ff-4b89-a532-90c5de56acdc@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlemoal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="u/oWKLrG";       spf=pass
 (google.com: domain of dlemoal@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=dlemoal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Damien Le Moal <dlemoal@kernel.org>
Reply-To: Damien Le Moal <dlemoal@kernel.org>
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

On 8/29/25 2:53 AM, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:28AM +0200, David Hildenbrand wrote:
>> It's no longer required to use nth_page() when iterating pages within a
>> single SG entry, so let's drop the nth_page() usage.
>>
>> Cc: Damien Le Moal <dlemoal@kernel.org>
>> Cc: Niklas Cassel <cassel@kernel.org>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> LGTM, so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Just noticed this:

s/libata-eh/libata-sff

in the commit title please.

-- 
Damien Le Moal
Western Digital Research

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/423566a0-5967-488d-a62a-4f825ae6f227%40kernel.org.
