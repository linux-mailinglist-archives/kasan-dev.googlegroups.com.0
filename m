Return-Path: <kasan-dev+bncBC32535MUICBBLEW7D3QKGQE2EMBEKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F1B321295C
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 18:28:29 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 75sf17320860pga.20
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jul 2020 09:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593707308; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWNp7y098/tfLsY0sIqSDzhvNOg8bIwOhiLiBLb++DCgM1c9CCgRuEFdiaWrWgEBRG
         0PiKKACzOUx1Yo9yV5LBlHCRQ0iI2WA790y6PXZMlpdclwuYF8gW/1i/yzj6GFKbQ+hq
         QTqMW1rkd78QFR+PuYTQB5BOI/2DHO5wqivZo5hqD1tvQZJE6zUnQtQHGVoHUMTSScs+
         fNCHwgt0CxmfKGW3c57AhUJmLWsnUypW1lk0brHKnnxwvjN+/RzVyejEdypgwKaqgfoD
         uadjvHhfwTuyb1JxR3JKvbRqPBuPTblO+0MB5Abyb/OQBJXDz8Ch8ccup+sQBQSu4E81
         nNLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:autocrypt:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=lFoP84d1dKTckLOq1gaDMzKpm3NNT/PKPGfUTDuNTm0=;
        b=hg6tD/RX/lEoAyVO0myZIjOUM/dqikq1zYK/1cHcF1EhesPIRsezsVh0eVY3mNRUnE
         C+IBWVAaL5yUVIOu+vD/7hlQ/5A8lFcpcrGJb9UYwgFs0ibPOm4FjXO8m+08fhAki95A
         80VcsSzjIjGPiA0JcQBhs0AciZMFf3vxToKz/2XmGF3Az7ZwC7/CFLqw/sKjuxA4vDmd
         6x75swsNy0QQigP2+/3HltpRvVSdcffn843ToCb3BDYfc7ajNis58gJndSfVb01rcPcu
         Wqq+girgRKHGy3LYgB96c9gzf9AVKKm9V4D7+4KL6XDpVR6llRYzumNDTN+6ga6DcE5m
         xjEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TSlQPp3V;
       spf=pass (google.com: domain of david@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lFoP84d1dKTckLOq1gaDMzKpm3NNT/PKPGfUTDuNTm0=;
        b=kJ2f+7geZIWfFtfBxcupLd3FgksFUU0Imjt32tHM4/rBxtSeFcye0wVI5uOEqeBbuu
         B46DWL0fmfvcMGYJ1OPDan8ovteW97tJguqS+vgw7PTy8sOwW6eAk4ZQMFjYHIAAIWo0
         3Ao60T5MkMoxhInrlzIh5DT3IBUkckAeK8d60k4/jmTVT3l9TX+2QpIZuYLpfK6S/WTR
         Y73jTeznDvNcOYkQRg/3DgyQlrakMUWQL4pl9vxAlBAXElA7GFqX7R7cu+dYC9+RS6Re
         qtMI2E/i+L/cAyXl1wZV3ExX1BshlQ8I04yjTgtfP/WXHSFyTUDhd4ARIuHwLrAjVX3R
         mGpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lFoP84d1dKTckLOq1gaDMzKpm3NNT/PKPGfUTDuNTm0=;
        b=QYG1Ykl3xWh5GtwUlqBefdP+M/ifqGcEDMdyKNUl13CJc0Y12gxC8uMjM1EG5WbE64
         gBd2YvvKE7eNNuF305WCT7KIgMAsyW3D9EEvcnviclUn9eJcTNn9lFE6VStpBVJ1L4FU
         zVrJOlx/DTS69EgxECHKlIVEcQTnUGdTAfiElJr73Nh1k87JubnoeYb3od8d1yoXucaZ
         tRF8vrnlhHDyTNVMG/4ahhl3HHvZLPU+5QOdtncUA6a8duqUqNsXz8UX9jqG5CD1W2HS
         3+dj3c8/g2oEPQoLm8seobJ/FnrvK9lsFH2t4WIB6iJBoVL6oduhCx3xiwqrwm6Xewgo
         2ctw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EQhcBJMp6epgbQ1GX3HdFDMDkbcXqZFYnYv6RPKXotfAySaOB
	x06hVHHeqMzucL4J516bsLY=
X-Google-Smtp-Source: ABdhPJwpPPNJTuZ7WJP8vYO5vvNfrmCED4UcHr/OYnPTe71UVo1L6ndOXSA7yMSYnopiDZ1JTnsS+Q==
X-Received: by 2002:aa7:9422:: with SMTP id y2mr12508643pfo.211.1593707308230;
        Thu, 02 Jul 2020 09:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:658c:: with SMTP id k12ls2690968pjj.3.gmail; Thu, 02
 Jul 2020 09:28:27 -0700 (PDT)
X-Received: by 2002:a17:90a:d304:: with SMTP id p4mr22323234pju.153.1593707307745;
        Thu, 02 Jul 2020 09:28:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593707307; cv=none;
        d=google.com; s=arc-20160816;
        b=zl3erx6CM5Xz/RIlo1bSBMvX90OjrsOYKUWCWvs5o0hYaaZGhdrDnJM7Phvaz2VDh3
         tOa8572tndlu8Dl3V3i8GH4IrZjWa5FctIItfD2Xr7umljL/VYwEtf44Fdk9ic9N6v/9
         Noa1o0kIC8vY1M9E0N4Gp/rct7Ou6yjkuZRcuJ+RjRY9k0Zl2JRtq5h6lnqkqp83QkFx
         aS0EtwwTTPhyBQPNxPplnEElr4b2Une799yLSNJMlrCBADXHL2Q80UpTrGIO0OCi3Wxh
         Texpb0UXn2Xo8auiMmigSAEvRYhVac1W3qBKk7Y3GvANzHEmuBt+QYYIBLbgeK4Kwn5U
         nD5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:autocrypt:from:references
         :cc:to:subject:dkim-signature;
        bh=pnlNDy7ujCkThYhfgbphAy3jEPnIKMybqtU8WhwBYYU=;
        b=nb+xOTPTwod4HcwYOwcwgt+f7lfJZs64KdI5yBWIvDwSpP3TpoHBdb5KLZkoPxmbTn
         jdMoit01H3FNIJAPVeal/WsUQhH738A6dbYieVVW4x6AcXXOTdsz8wtYsWFotLsMpa5K
         VDguQf55p/IGBYC0ispc+Jum4nDVERJIsQ0bjANRFpUYclfuEALJb40UuOFJb5meSBTS
         61GsXZpqbHOmRfqapVRXIcRQoGv4oqzyayrNLAf/F/5eDr2RTFrjk4wgkQnxaShXquae
         w6yWTS7AfTtPJYo+vCABon53cTWc9ckQlaqcgbL+hwNqV7lBOyVnC766byTMYiMz3D6H
         aIVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TSlQPp3V;
       spf=pass (google.com: domain of david@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id mz9si620807pjb.3.2020.07.02.09.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Jul 2020 09:28:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-424-UImTSbjUPxWwzxl1EfVJlg-1; Thu, 02 Jul 2020 12:28:24 -0400
X-MC-Unique: UImTSbjUPxWwzxl1EfVJlg-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id BDD2180058A;
	Thu,  2 Jul 2020 16:28:22 +0000 (UTC)
Received: from [10.36.114.38] (ovpn-114-38.ams2.redhat.com [10.36.114.38])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 4CF9D7BEAC;
	Thu,  2 Jul 2020 16:28:20 +0000 (UTC)
Subject: Re: [PATCH] mm: define pte_add_end for consistency
To: Wei Yang <richard.weiyang@linux.alibaba.com>
Cc: dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
 akpm@linux-foundation.org, x86@kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
 <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
 <20200701021113.GA51306@L-31X9LVDL-1304.local>
 <da4a470e-f34c-fbf8-c95a-93a7d30a215b@redhat.com>
 <20200701115441.GA4979@L-31X9LVDL-1304.local>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; prefer-encrypt=mutual; keydata=
 mQINBFXLn5EBEAC+zYvAFJxCBY9Tr1xZgcESmxVNI/0ffzE/ZQOiHJl6mGkmA1R7/uUpiCjJ
 dBrn+lhhOYjjNefFQou6478faXE6o2AhmebqT4KiQoUQFV4R7y1KMEKoSyy8hQaK1umALTdL
 QZLQMzNE74ap+GDK0wnacPQFpcG1AE9RMq3aeErY5tujekBS32jfC/7AnH7I0v1v1TbbK3Gp
 XNeiN4QroO+5qaSr0ID2sz5jtBLRb15RMre27E1ImpaIv2Jw8NJgW0k/D1RyKCwaTsgRdwuK
 Kx/Y91XuSBdz0uOyU/S8kM1+ag0wvsGlpBVxRR/xw/E8M7TEwuCZQArqqTCmkG6HGcXFT0V9
 PXFNNgV5jXMQRwU0O/ztJIQqsE5LsUomE//bLwzj9IVsaQpKDqW6TAPjcdBDPLHvriq7kGjt
 WhVhdl0qEYB8lkBEU7V2Yb+SYhmhpDrti9Fq1EsmhiHSkxJcGREoMK/63r9WLZYI3+4W2rAc
 UucZa4OT27U5ZISjNg3Ev0rxU5UH2/pT4wJCfxwocmqaRr6UYmrtZmND89X0KigoFD/XSeVv
 jwBRNjPAubK9/k5NoRrYqztM9W6sJqrH8+UWZ1Idd/DdmogJh0gNC0+N42Za9yBRURfIdKSb
 B3JfpUqcWwE7vUaYrHG1nw54pLUoPG6sAA7Mehl3nd4pZUALHwARAQABtCREYXZpZCBIaWxk
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT6JAlgEEwEIAEICGwMFCQlmAYAGCwkIBwMCBhUI
 AgkKCwQWAgMBAh4BAheAFiEEG9nKrXNcTDpGDfzKTd4Q9wD/g1oFAl3pImkCGQEACgkQTd4Q
 9wD/g1o+VA//SFvIHUAvul05u6wKv/pIR6aICPdpF9EIgEU448g+7FfDgQwcEny1pbEzAmiw
 zAXIQ9H0NZh96lcq+yDLtONnXk/bEYWHHUA014A1wqcYNRY8RvY1+eVHb0uu0KYQoXkzvu+s
 Dncuguk470XPnscL27hs8PgOP6QjG4jt75K2LfZ0eAqTOUCZTJxA8A7E9+XTYuU0hs7QVrWJ
 jQdFxQbRMrYz7uP8KmTK9/Cnvqehgl4EzyRaZppshruKMeyheBgvgJd5On1wWq4ZUV5PFM4x
 II3QbD3EJfWbaJMR55jI9dMFa+vK7MFz3rhWOkEx/QR959lfdRSTXdxs8V3zDvChcmRVGN8U
 Vo93d1YNtWnA9w6oCW1dnDZ4kgQZZSBIjp6iHcA08apzh7DPi08jL7M9UQByeYGr8KuR4i6e
 RZI6xhlZerUScVzn35ONwOC91VdYiQgjemiVLq1WDDZ3B7DIzUZ4RQTOaIWdtXBWb8zWakt/
 ztGhsx0e39Gvt3391O1PgcA7ilhvqrBPemJrlb9xSPPRbaNAW39P8ws/UJnzSJqnHMVxbRZC
 Am4add/SM+OCP0w3xYss1jy9T+XdZa0lhUvJfLy7tNcjVG/sxkBXOaSC24MFPuwnoC9WvCVQ
 ZBxouph3kqc4Dt5X1EeXVLeba+466P1fe1rC8MbcwDkoUo65Ag0EVcufkQEQAOfX3n0g0fZz
 Bgm/S2zF/kxQKCEKP8ID+Vz8sy2GpDvveBq4H2Y34XWsT1zLJdvqPI4af4ZSMxuerWjXbVWb
 T6d4odQIG0fKx4F8NccDqbgHeZRNajXeeJ3R7gAzvWvQNLz4piHrO/B4tf8svmRBL0ZB5P5A
 2uhdwLU3NZuK22zpNn4is87BPWF8HhY0L5fafgDMOqnf4guJVJPYNPhUFzXUbPqOKOkL8ojk
 CXxkOFHAbjstSK5Ca3fKquY3rdX3DNo+EL7FvAiw1mUtS+5GeYE+RMnDCsVFm/C7kY8c2d0G
 NWkB9pJM5+mnIoFNxy7YBcldYATVeOHoY4LyaUWNnAvFYWp08dHWfZo9WCiJMuTfgtH9tc75
 7QanMVdPt6fDK8UUXIBLQ2TWr/sQKE9xtFuEmoQGlE1l6bGaDnnMLcYu+Asp3kDT0w4zYGsx
 5r6XQVRH4+5N6eHZiaeYtFOujp5n+pjBaQK7wUUjDilPQ5QMzIuCL4YjVoylWiBNknvQWBXS
 lQCWmavOT9sttGQXdPCC5ynI+1ymZC1ORZKANLnRAb0NH/UCzcsstw2TAkFnMEbo9Zu9w7Kv
 AxBQXWeXhJI9XQssfrf4Gusdqx8nPEpfOqCtbbwJMATbHyqLt7/oz/5deGuwxgb65pWIzufa
 N7eop7uh+6bezi+rugUI+w6DABEBAAGJAiUEGAECAA8FAlXLn5ECGwwFCQlmAYAACgkQTd4Q
 9wD/g1qA6w/+M+ggFv+JdVsz5+ZIc6MSyGUozASX+bmIuPeIecc9UsFRatc91LuJCKMkD9Uv
 GOcWSeFpLrSGRQ1Z7EMzFVU//qVs6uzhsNk0RYMyS0B6oloW3FpyQ+zOVylFWQCzoyyf227y
 GW8HnXunJSC+4PtlL2AY4yZjAVAPLK2l6mhgClVXTQ/S7cBoTQKP+jvVJOoYkpnFxWE9pn4t
 H5QIFk7Ip8TKr5k3fXVWk4lnUi9MTF/5L/mWqdyIO1s7cjharQCstfWCzWrVeVctpVoDfJWp
 4LwTuQ5yEM2KcPeElLg5fR7WB2zH97oI6/Ko2DlovmfQqXh9xWozQt0iGy5tWzh6I0JrlcxJ
 ileZWLccC4XKD1037Hy2FLAjzfoWgwBLA6ULu0exOOdIa58H4PsXtkFPrUF980EEibUp0zFz
 GotRVekFAceUaRvAj7dh76cToeZkfsjAvBVb4COXuhgX6N4pofgNkW2AtgYu1nUsPAo+NftU
 CxrhjHtLn4QEBpkbErnXQyMjHpIatlYGutVMS91XTQXYydCh5crMPs7hYVsvnmGHIaB9ZMfB
 njnuI31KBiLUks+paRkHQlFcgS2N3gkRBzH7xSZ+t7Re3jvXdXEzKBbQ+dC3lpJB0wPnyMcX
 FOTT3aZT7IgePkt5iC/BKBk3hqKteTnJFeVIT7EC+a6YUFg=
Organization: Red Hat GmbH
Message-ID: <7562991b-c1e7-4037-a3f0-124acd0669b7@redhat.com>
Date: Thu, 2 Jul 2020 18:28:19 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200701115441.GA4979@L-31X9LVDL-1304.local>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TSlQPp3V;
       spf=pass (google.com: domain of david@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 01.07.20 13:54, Wei Yang wrote:
> On Wed, Jul 01, 2020 at 10:29:08AM +0200, David Hildenbrand wrote:
>> On 01.07.20 04:11, Wei Yang wrote:
>>> On Tue, Jun 30, 2020 at 02:44:00PM +0200, David Hildenbrand wrote:
>>>> On 30.06.20 05:18, Wei Yang wrote:
>>>>> When walking page tables, we define several helpers to get the address of
>>>>> the next boundary. But we don't have one for pte level.
>>>>>
>>>>> Let's define it and consolidate the code in several places.
>>>>>
>>>>> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
>>>>> ---
>>>>>  arch/x86/mm/init_64.c   | 6 ++----
>>>>>  include/linux/pgtable.h | 7 +++++++
>>>>>  mm/kasan/init.c         | 4 +---
>>>>>  3 files changed, 10 insertions(+), 7 deletions(-)
>>>>>
>>>>> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
>>>>> index dbae185511cd..f902fbd17f27 100644
>>>>> --- a/arch/x86/mm/init_64.c
>>>>> +++ b/arch/x86/mm/init_64.c
>>>>> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>>>>>  
>>>>>  	pte = pte_start + pte_index(addr);
>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>> -		if (next > end)
>>>>> -			next = end;
>>>>> +		next = pte_addr_end(addr, end);
>>>>>  
>>>>>  		if (!pte_present(*pte))
>>>>>  			continue;
>>>>> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>>>>>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>>>>>  
>>>>>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
>>>>> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>> +			next = pte_addr_end(addr, end);
>>>>>  			pmd = pmd_offset(pud, addr);
>>>>>  			if (pmd_none(*pmd))
>>>>>  				continue;
>>>>> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
>>>>> index 32b6c52d41b9..0de09c6c89d2 100644
>>>>> --- a/include/linux/pgtable.h
>>>>> +++ b/include/linux/pgtable.h
>>>>> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>>>>>  })
>>>>>  #endif
>>>>>  
>>>>> +#ifndef pte_addr_end
>>>>> +#define pte_addr_end(addr, end)						\
>>>>> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
>>>>> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
>>>>> +})
>>>>> +#endif
>>>>> +
>>>>>  /*
>>>>>   * When walking page tables, we usually want to skip any p?d_none entries;
>>>>>   * and any p?d_bad entries - reporting the error before resetting to none.
>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>> index fe6be0be1f76..89f748601f74 100644
>>>>> --- a/mm/kasan/init.c
>>>>> +++ b/mm/kasan/init.c
>>>>> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>>>>>  	unsigned long next;
>>>>>  
>>>>>  	for (; addr < end; addr = next, pte++) {
>>>>> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
>>>>> -		if (next > end)
>>>>> -			next = end;
>>>>> +		next = pte_addr_end(addr, end);
>>>>>  
>>>>>  		if (!pte_present(*pte))
>>>>>  			continue;
>>>>>
>>>>
>>>> I'm not really a friend of this I have to say. We're simply iterating
>>>> over single pages, not much magic ....
>>>
>>> Hmm... yes, we are iterating on Page boundary, while we many have the case
>>> when addr or end is not PAGE_ALIGN.
>>
>> I really do wonder if not having page aligned addresses actually happens
>> in real life. Page tables operate on page granularity, and
>> adding/removing unaligned parts feels wrong ... and that's also why I
>> dislike such a helper.
>>
>> 1. kasan_add_zero_shadow()/kasan_remove_zero_shadow(). If I understand
>> the logic (WARN_ON()) correctly, we bail out in case we would ever end
>> up in such a scenario, where we would want to add/remove things not
>> aligned to PAGE_SIZE.
>>
>> 2. remove_pagetable()...->remove_pte_table()
>>
>> vmemmap_free() should never try to de-populate sub-pages. Even with
>> sub-section hot-add/remove (2MB / 512 pages), with valid struct page
>> sizes (56, 64, 72, 80), we always end up with full pages.
>>
>> kernel_physical_mapping_remove() is only called via
>> arch_remove_memory(). That will never remove unaligned parts.
>>
> 
> I don't have a very clear mind now, while when you look into
> remove_pte_table(), it has two cases based on alignment of addr and next.
> 
> If we always remove a page, the second case won't happen?

So, the code talks about that the second case can only happen for
vmemmap, never for direct mappings.

I don't see a way how this could ever happen with current page sizes,
even with sub-section hotadd (2MB). Maybe that is a legacy leftover or
was never relevant? Or I am missing something important, where we could
have sub-4k-page vmemmap data.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7562991b-c1e7-4037-a3f0-124acd0669b7%40redhat.com.
