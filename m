Return-Path: <kasan-dev+bncBC32535MUICBBIOHUKZQMGQE64CVAZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B7D0904461
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 21:21:07 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2c3214461cesf1330464a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:21:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718133666; cv=pass;
        d=google.com; s=arc-20160816;
        b=V7JkIgQVxlTPkNc0N6dn/m1GUupwLEbmuLlqVKr+dABoc2ATuoPknbwJ7w3Q27+0b8
         MNQR3pZF/x+OVmA+rVpXttddnSgyX+L29rufkVZJKgNaaF6PfcFcw8u2/9aOpX0yI/bb
         ZrffNWIDlR6JJ64NsPT5Xsnj1hNnZr9jbYX/LO+W67EqaL1G56IDW/ucAbAM/SIWpca4
         qPqu/t1CGfWrJjsPbdtvNri7UniP8l1/N6gQdwb6z1YZ3dCBJxWjOT24aB8IBIRTICG6
         0HoCB2QDkwVsaIGtBFx7oIvWNMGIPi2Vua2gSMrn4+/KNGuQUmqtG6KFmOPcE9DgbjMJ
         gRqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=aF7+eV0aN+5/VsWSZUk0Wcn1rOJ1pYxs9ZVW3fNAhwQ=;
        fh=LlqEZfsugfmWUooFaFKak9dJfavq110tVfWMTSX6eEQ=;
        b=Gw98OWqVO87czcjWfXJBIu/VEsYCN/cJ1lfMQzazURUlzTaWEspIh91SbEeq/0yUFf
         hPCn+1CHuMvTQaccc9dac2mLyBnOzwDQReBTRWjGKzRDpUX8Q2Zj7+iIsK3VptHg0ApG
         BBoNByXnJ+aMQqBlyEGTq7QNB+7O3h88MDDzvHKVghqzeApuU5cPNdflxwStiljtS5aW
         k8nN1StfLHVkf9LNgnk+gAC/4E17oWlkYsH13cJt+3El8AD6fGHE3u3crtHkGAG590Ca
         4+ZPugljOcuPgq9z8NiHIcGh9nNo9XK2JPf9nzTfm+coqiETefPtJeYxTZROcZhvTVyZ
         /Hzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=exjtnSIF;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718133666; x=1718738466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aF7+eV0aN+5/VsWSZUk0Wcn1rOJ1pYxs9ZVW3fNAhwQ=;
        b=oHOd7iKAQk0tu//TRsO4sv3TOkc8qdwAwBHiCWmpqdCcfq6kkrMo62zhLE93Onfne/
         Iogw3hQyzQhXZlfM78+RwKaQF+Il9cLcWEAT3ZLrTMWqwqXu21y8DD/AM9Y6fQYaS48S
         GLkNdIBhYQ73Gx4tGSvF3Yji9XIcLUFSGBolAhl5+1S/WFFLAOU13SZML1xOHzmB+atE
         ioBu7Kb7pXq/OnzdO634FCgyYsDZQUKZ9Kf7RMk49If3ZsR/gxSVmOZazYN7AqFnC17f
         QTRrBnHLCtcvlcCQ6qe0dg8g0cjYA7OwRK9ltbKONilX71agnlRVYJ0U+LJsqGgV8IzU
         adFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718133666; x=1718738466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aF7+eV0aN+5/VsWSZUk0Wcn1rOJ1pYxs9ZVW3fNAhwQ=;
        b=mLKyMbX6Z0IZ7c4teIxvihItVy4EbOGihvBzfvV4V8VAAaS82R4l1vhYyGKD202yS3
         e4djmmhlMAGZTWNgslELjpeUGZ7Kprld4MK4J0sKPzMmzRRhoZOzE142/831uHv3vtJL
         yb/IrF2XbYy51zkXhutKOLvjUhamKKa1OZO30WShqGJzMw0lzq/ZTOjldb9PVTQMuHDg
         UneuFU3PNGCjETCGHckxhN8Vt40tx4ekqE1UctoTxASMpraFXCBejgMBM7PglhFL+U5m
         7vQJ47kc6ueOwUlM4O5djpfz2EuuvAlmLtCUzxt3ljLbJ52Y+csepQx8ueve1EoGn5/R
         7R9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEYOtsVHTmgHbXykRa3vrRxGz1qxneyXXrXAoC0vfC3jxGZWTw0XiDEsYzD19kDws3tTyfU9x+/nCAJy2oEjvd1ix+NqZ7lA==
X-Gm-Message-State: AOJu0YxPdfoyXjkQBI+cxKpnMduxNgpPTzAVRbuO+7SqRxBtuTYcmeXQ
	6CbWXb1z6IRQzVpXxPSqKI8OMDNsCelyWlAwlmMaBi77DVUT7H/X
X-Google-Smtp-Source: AGHT+IFyn99XBDNuyYjn0aktnw9bFTN0VD9ELB/SflpZcLShie0lRPxFzjNx3dOLqFE5mJEQii3btA==
X-Received: by 2002:a17:90a:f606:b0:2bd:faef:e862 with SMTP id 98e67ed59e1d1-2c2bcc0b39bmr13056457a91.23.1718133665783;
        Tue, 11 Jun 2024 12:21:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1e45:b0:2c2:c750:8678 with SMTP id
 98e67ed59e1d1-2c3287775d4ls953040a91.2.-pod-prod-09-us; Tue, 11 Jun 2024
 12:21:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKlV/assykMhlC0FQ+K97Je2AU/erzu+3KYl6DUvzUIsTnL9EJZnQNjpZ3k0ToOQj8GGS/MVkQXzqfR9xfI41P2brCdAK/Upa49Q==
X-Received: by 2002:a17:90b:b15:b0:2c2:fe3d:3453 with SMTP id 98e67ed59e1d1-2c2fe3d3560mr6836207a91.18.1718133664300;
        Tue, 11 Jun 2024 12:21:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718133664; cv=none;
        d=google.com; s=arc-20160816;
        b=hsqDcgbfyJRY8xuUVTzGU8ceanwN/dsWi121EbaxXE+8Sf41dewYfftNrrlIqLTZlI
         iov9H+HHTMNGDdR3NZCDquluy8VdZk8gT1a81VPSlonTUffLj7KY43YoAXISQLp5K+Ce
         nkvGyAMRovEhNxMd1s7eWL9e4Ebst8U/pVjeRU7rQ/v42wOOTD0jFS6NGTzgvRV1XxTm
         4nRy2jBtvOV39uj35nmJw7bbF+H4nYv8j7ZWhC1Qg19O3QpDmovgWKhk/7uCE7weknum
         5Ajw5NVO6gkUPKoLMeULWj4sSri4g84vlgKXzzNek4D30lmPbnnSj4KtCSlQm8j594Qw
         UXuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=iaiFAJhQM+Rt1OjOGeJr7VugpzhyWLTZGK0DjHGr1/Q=;
        fh=55DZ1HKi4BWoUu0JqyhHEtCL/dcmxAtdIoCzrLPerZI=;
        b=I54fw65lW68fRIKwNyxs6YD9cUKYfktn+jbDRHPyh2mVNcsmaBYrh0SQyq73J6JRxC
         Zl4yi8Zj50hCB3fLpSdJz5r3MhpnmuisLgdIu2roeNP/jd/7XGh07axK3Xb1ugi4rN+U
         zHKD95yDXlWIp+aKSx7vUWUx6LebUlr8XKS6I8mDpxZDTS6j28/hc2diTRCpYzhiWHUb
         HfohrVsuQAcw+WSShOAH7NVA9D+BRBOAn0qXKFo2VxBTezqbD7G1lxCQdh8nOWJXDSii
         Q7L9NxIUx6QbliX906+mQ2GLeCyki4zotcTUxCnyhnY3U4ED2MPeWj4ZgacnUWtxOTZT
         iIDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=exjtnSIF;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c29c20bb24si823471a91.1.2024.06.11.12.21.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 12:21:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-681-ifbdF4JSMXqcqoZxF6n7ww-1; Tue, 11 Jun 2024 15:21:01 -0400
X-MC-Unique: ifbdF4JSMXqcqoZxF6n7ww-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-421f3b7b27eso20604915e9.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 12:21:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBdQuSBuA/l/DjtPCgIvAs16uCe3vqoSXypMvdICeE5f1J5IhfTxIkiNe3A2qoiE5jXp9z9T2ya2ZTT0nfLdGdpa2plQpb0Pb2nw==
X-Received: by 2002:a05:600c:4e87:b0:421:7f30:7cfb with SMTP id 5b1f17b1804b1-4217f308036mr79478485e9.40.1718133660217;
        Tue, 11 Jun 2024 12:21:00 -0700 (PDT)
X-Received: by 2002:a05:600c:4e87:b0:421:7f30:7cfb with SMTP id 5b1f17b1804b1-4217f308036mr79478295e9.40.1718133659765;
        Tue, 11 Jun 2024 12:20:59 -0700 (PDT)
Received: from ?IPV6:2003:cb:c748:ba00:1c00:48ea:7b5a:c12b? (p200300cbc748ba001c0048ea7b5ac12b.dip0.t-ipconnect.de. [2003:cb:c748:ba00:1c00:48ea:7b5a:c12b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-421fd7573c0sm65944095e9.38.2024.06.11.12.20.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 12:20:59 -0700 (PDT)
Message-ID: <6165471b-e86b-456b-99c6-c308bf5d6e4c@redhat.com>
Date: Tue, 11 Jun 2024 21:20:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Mike Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
 <2ed64218-7f3b-4302-a5dc-27f060654fe2@redhat.com>
 <20240611121942.050a2215143af0ecb576122f@linux-foundation.org>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240611121942.050a2215143af0ecb576122f@linux-foundation.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=exjtnSIF;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 11.06.24 21:19, Andrew Morton wrote:
> On Tue, 11 Jun 2024 12:06:56 +0200 David Hildenbrand <david@redhat.com> wrote:
> 
>> On 07.06.24 11:09, David Hildenbrand wrote:
>>> In preparation for further changes, let's teach __free_pages_core()
>>> about the differences of memory hotplug handling.
>>>
>>> Move the memory hotplug specific handling from generic_online_page() to
>>> __free_pages_core(), use adjust_managed_page_count() on the memory
>>> hotplug path, and spell out why memory freed via memblock
>>> cannot currently use adjust_managed_page_count().
>>>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>> ---
>>
>> @Andrew, can you squash the following?
> 
> Sure.
> 
> I queued it against "mm: pass meminit_context to __free_pages_core()",
> not against

Ah yes, sorry. Thanks!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6165471b-e86b-456b-99c6-c308bf5d6e4c%40redhat.com.
