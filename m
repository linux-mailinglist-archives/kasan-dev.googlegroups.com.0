Return-Path: <kasan-dev+bncBC32535MUICBBKVYUCZQMGQEP54IXAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 17BDC903815
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 11:43:08 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-254a2c2d865sf2731044fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 02:43:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718098986; cv=pass;
        d=google.com; s=arc-20160816;
        b=dBGZXfpkJfHuXuasDXlETch7sogPtCsPkUDt5VxoQsS3zrTYN3r0VIIAg0TG/C3QSd
         lY7aztdA/T2FT2KHLtKHC6a78n/2uFqKOrTiDbBXl0hMROTjp9do/uWWcbgoqpnGQrAw
         1R/QwCWR1JCz/56iff50GfUhmOLQtWCxopcwHp6q1mtxbDdQO5sKANUOUzeueGhGrzR2
         ABIht/ve1mZrPc+2F8n1t1CP8u3I+TKgWfe8awsbvv36UcSzmJ1m/QRDVB0glUtye9rQ
         vzXSy+YD03KionpPx3g/zqI5Pp8FVBaRzF2t6arjQc4OZvTVliTecqvO/QyELn0/0J+U
         S9Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=7eCDpHgqnKuy5pQMBZQP7k7YssmtnPrm7xMQ4mbo7O8=;
        fh=WVRKXd3ndwNWwHau+cau5ALJ3sP3w1fDpKGcT/AiZnU=;
        b=VBzxWgLxr+9Sf5cxjPjWm2ygqoQrcsUKcaEOrL+XNIfJVSJeSTHJkf1koW7Hgd61q5
         A5ng90PZdOUUEKtsEUMIHvLZwtCgC4YoyTva8PaJcSfLq5nL1+q1eb0lyM41B9VDhB4L
         PVAaKeB8n5wZGiZXTTGYlOZaDN+lwQM8MfASo80585FKgy3yqgtAotoaUYu2cWS3NE6R
         MYKYtLmbH0NvgAkSSYG4IYFIP+fHx5MfEcbUEFE1RclGtjkAnClO8vew8ZDTd22XN+32
         wuPSAprlmgZRhA9UQkRlzCdi6xrcTq3noHN4FFR2iRtxEtz7R/eZR5L05w70wfie3RWP
         xViA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Xq8flxKR;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718098986; x=1718703786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7eCDpHgqnKuy5pQMBZQP7k7YssmtnPrm7xMQ4mbo7O8=;
        b=fDOLKd/U7eGJpqOXgVXc66370oxOGLtr8UzQiBP8gSTKZZnDcV7GP3Kujo5sPDammX
         tnuGx722woI9CZenMags+Rn+gBL0KV/6Q3jECKUUEFZSxvs7JrKt2RZzWhc2AamnM8ga
         5MInta/dmRU5BnPdJSGaLY2NR5cnxOIN6ePpF+HFIxKr/aDbZkr5kkId9GzbnfkssCec
         yoMzGhLA4jxdOBHS5NmILnpnjoEslDffL3WQ96vr3mxkS4iVTJfOX34HhLpWw3dG367F
         PT2Ki5cRnlN7gIIufDsrHcUdP1qK40xAZu5HExlIY5F9bRckWjVDbFk3c/eK/1UPDsDa
         Wbrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718098986; x=1718703786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7eCDpHgqnKuy5pQMBZQP7k7YssmtnPrm7xMQ4mbo7O8=;
        b=RqJO4OKWmuCNePnPNHoF6ckB4CTyKHeTBh4IKb8PQa+HLZ3kIlCUb1QQI59kOK0e3P
         Wg4vUBcu+qyb3lOpH9xFSvz+zevUpviUINoKsq7EiOnTrb6msed19RhXCwfUXpNg0VyN
         /DS6aoT3ayQxQ9exaD2UBUW+EzpyjG7pMaILW6sUhD+f1L2bwK9d8ANt6EKLCOPDGvbq
         oE/qKxbp3M4k03fH4c6jbbMBTMfqUZD4PDuAuAyvFO/d/znk4YMJLHrn73w+AcZ4nuV/
         nUWOv3Pi2FBCHnXFkBiIkJtEi86js/v0Erii+KY2I54ARNQ95gqzPkdoyENvlYP2LVZH
         LYlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzGX6wPkkOSyw0FZ5SfGQeqtfJBrUynuSGOp/9pDp7VtR0/4hnuXlLxiScMbpbp6lwkxW3ctn2SAi1835SL2j/bn0i3ImGCw==
X-Gm-Message-State: AOJu0YyrtFuX5d/habuVlTQy4iua4FD4sWJ2SwJ/3HmhUe9grOCmpoZT
	WLMRQvbYIvtU5NdDkUaqUHHqaJMTtp/W0R8VieHUFfxcIkx/eQjG
X-Google-Smtp-Source: AGHT+IH3LGiB5WsqSNNXPY6CsMReijFpT2RDPoSbkUFiPqpVt7fWqLEmmHDgPKrs1QNNi69X4uBOoQ==
X-Received: by 2002:a05:6870:b69b:b0:254:a009:4c2f with SMTP id 586e51a60fabf-254a0094d60mr9445583fac.37.1718098986341;
        Tue, 11 Jun 2024 02:43:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9299:b0:704:4c5c:1acb with SMTP id
 d2e1a72fcca58-7044c5c1df1ls1768907b3a.1.-pod-prod-03-us; Tue, 11 Jun 2024
 02:43:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuKrlJzheJ8ECnWwf1uK1/AWaQ/1I4E39cWmMQQxjEZf6Ip+kxycq3D4jmYHXr0AnotkHi14EhYa3nkH2C+nLkGJz9jvsV07Xevw==
X-Received: by 2002:a05:6a20:3d81:b0:1b7:77ef:b125 with SMTP id adf61e73a8af0-1b777efc43amr6180229637.21.1718098984889;
        Tue, 11 Jun 2024 02:43:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718098984; cv=none;
        d=google.com; s=arc-20160816;
        b=vmLd1UYtZREbnT8t9sBGPd/gUqI41IhROi50TR9YWnM9wec+W/Rws8ONplVmoFZBgW
         Mj0Pq8pUNuN2n23F2thR+xKlKjQWbHmjjfw+5B8rYX9pIMeBgl0Kk3xNw8OvtGxL3PFc
         HOfFxgRqyph8V7/r4juXuHYDGXcJx0j+XS5d0AZrJ0GNT7g3IUAGNlnf8cjLsgxgZ6hs
         MKxzV7TlPZdn/jdLFEFEZKJowqoUkfokvrq9fEty63Pd/4GXT/sce92dAsQlabgzAL61
         6z7plV41b+VBXxU6F+cOtAIaX+gd/9eEglZrCM9Irw+EORRcDmMIEzDo42q1Kbhe5vB2
         LGwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=4Fvo4snqjmjLL5YGwAq7AoShRlEWBSMshPzLS47jMwA=;
        fh=Mqpo3w94PQa30euP330nK9dJqh7aa1If+ksPpk5CJik=;
        b=etiNNEUh9lzLPEA+F41R9k1j/zFr5A4V54cds6Y45HlS7B1u0HiS+JjpFs/z1tWbw0
         +pm0zICGu7geX8HxFfRtjYhwkyqkw3YxD39VsKftnWum70YWHKnvrvnfN0RyZoNlXSMc
         AsYsts85p/t17Yi3Cr1JyCTlcIZplaW8dv/MUwrRyiu4mVQ9zhZdTUWQXVXxpLtQmGvP
         BvoIkQVzTjh6tl0C3KrkdJvRHnNvA0vP13GsvvHRXY0Pag1Mh3PdQDkbRk0MAbnRRU8D
         OcCJMNnJe/hQi8+/K6ov31/JorNs7jlA82Cug/Ec8Rvtpf2RI9EoxceRGSkSCxZuaeP/
         BZCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Xq8flxKR;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70417015bdbsi429135b3a.0.2024.06.11.02.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 02:43:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lf1-f69.google.com (mail-lf1-f69.google.com
 [209.85.167.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-157-b2H1UrPwOYmXu9ujkhydpQ-1; Tue, 11 Jun 2024 05:43:00 -0400
X-MC-Unique: b2H1UrPwOYmXu9ujkhydpQ-1
Received: by mail-lf1-f69.google.com with SMTP id 2adb3069b0e04-52c0bfd6a89so2798036e87.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 02:43:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbRw+QvOmobAmAtTPfDD/wleWqF1QvVKinUM44IBva30UDjhawzq4Uf3hsNAXCrccf0oQqahdRd6xhMOnUx5nWNlDIKjyLMdlZJA==
X-Received: by 2002:ac2:5a43:0:b0:52b:e7ff:4eb7 with SMTP id 2adb3069b0e04-52be7ff4ed8mr5513966e87.59.1718098978991;
        Tue, 11 Jun 2024 02:42:58 -0700 (PDT)
X-Received: by 2002:ac2:5a43:0:b0:52b:e7ff:4eb7 with SMTP id 2adb3069b0e04-52be7ff4ed8mr5513958e87.59.1718098978571;
        Tue, 11 Jun 2024 02:42:58 -0700 (PDT)
Received: from ?IPV6:2003:cb:c748:ba00:1c00:48ea:7b5a:c12b? (p200300cbc748ba001c0048ea7b5ac12b.dip0.t-ipconnect.de. [2003:cb:c748:ba00:1c00:48ea:7b5a:c12b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4215c2cd247sm176185215e9.40.2024.06.11.02.42.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 02:42:57 -0700 (PDT)
Message-ID: <824c319a-530e-4153-80f5-20e2c463fa81@redhat.com>
Date: Tue, 11 Jun 2024 11:42:56 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
To: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hyperv@vger.kernel.org,
 virtualization@lists.linux.dev, xen-devel@lists.xenproject.org,
 kasan-dev@googlegroups.com, Mike Rapoport <rppt@kernel.org>,
 Oscar Salvador <osalvador@suse.de>, "K. Y. Srinivasan" <kys@microsoft.com>,
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
 <20240607090939.89524-3-david@redhat.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240607090939.89524-3-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Xq8flxKR;
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

On 07.06.24 11:09, David Hildenbrand wrote:
> We currently initialize the memmap such that PG_reserved is set and the
> refcount of the page is 1. In virtio-mem code, we have to manually clear
> that PG_reserved flag to make memory offlining with partially hotplugged
> memory blocks possible: has_unmovable_pages() would otherwise bail out on
> such pages.
> 
> We want to avoid PG_reserved where possible and move to typed pages
> instead. Further, we want to further enlighten memory offlining code about
> PG_offline: offline pages in an online memory section. One example is
> handling managed page count adjustments in a cleaner way during memory
> offlining.
> 
> So let's initialize the pages with PG_offline instead of PG_reserved.
> generic_online_page()->__free_pages_core() will now clear that flag before
> handing that memory to the buddy.
> 
> Note that the page refcount is still 1 and would forbid offlining of such
> memory except when special care is take during GOING_OFFLINE as
> currently only implemented by virtio-mem.
> 
> With this change, we can now get non-PageReserved() pages in the XEN
> balloon list. From what I can tell, that can already happen via
> decrease_reservation(), so that should be fine.
> 
> HV-balloon should not really observe a change: partial online memory
> blocks still cannot get surprise-offlined, because the refcount of these
> PageOffline() pages is 1.
> 
> Update virtio-mem, HV-balloon and XEN-balloon code to be aware that
> hotplugged pages are now PageOffline() instead of PageReserved() before
> they are handed over to the buddy.
> 
> We'll leave the ZONE_DEVICE case alone for now.
> 

@Andrew, can we add here:

"Note that self-hosted vmemmap pages will no longer be marked as 
reserved. This matches ordinary vmemmap pages allocated from the buddy 
during memory hotplug. Now, really only vmemmap pages allocated from 
memblock during early boot will be marked reserved. Existing 
PageReserved() checks seem to be handling all relevant cases correctly 
even after this change."

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/824c319a-530e-4153-80f5-20e2c463fa81%40redhat.com.
