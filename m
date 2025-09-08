Return-Path: <kasan-dev+bncBC32535MUICBB3XN7PCQMGQEQBOCDDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ED86B49372
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:32:01 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-329745d6960sf4631753a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:32:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345520; cv=pass;
        d=google.com; s=arc-20240605;
        b=iB7PODWNEcNkG3FFs59v6HsJht9hQDwmopM4GiJz2/wScie9WP8+bAl9FrFY9lYIha
         BoFicyjXYPVR9OXT4VmCAtXgaHxfKzAYG9zZVsktWwjGzzb92R+iElS7SFPOFwWiHhqX
         DcjEHsSrKz68b0CFCnRYo6m2BKFy8so3MlpgkfhkBSgjTK0hcEJuzwP2FZ+dnJKTLoye
         liccylJhJ5On1mSMM7DzorZLO+g0ra6GXEmwBk7+ZS5skTRIf3mNmvx/vO5M1oh0i/fC
         sTBvkbx9LFyNwYikgm2e9OuIMcs518b0pY+ZH96hHxqHQMnTpP+7zoSYAmWr13d/1rpK
         wU0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=yewJjRX7I2sqRUJDgGK1FXBidwhz6fi1YdOCa0nte80=;
        fh=nPFztKtOmCKc0BfLv+N/gyK3jlc0Vq2AWXsBT2sU8uA=;
        b=Ao0yz6NFUOuXMShFd72grijRcFr0AXdFjb9pTQtvU8S9KoNCELzLmTpvc6+lt0dNsb
         KL2fEXNcTNR1Rdka4uHbULADJ35nD7OPccU8PyegzDvwkCGwJQdDCpPGSbumwglv60sh
         pKrfAT2E4B6PMov0CNrISbRmGo+IlepO9OyWooeoPNL1RfMKOmO4NLZZR+MnfenIutCJ
         rbIfQc+IsfQmSi/CTYV4/ZRHgHdi0RBX6815URF0kPgyqJX5ZIr6dN80JDNIPSIDeNBb
         5NYnYpEtQpxkgaFBU0rIh6EQkxxZKubpXg+HzpEcSJBq4DKCrlAoQ5wDCF3OGthW8Ssf
         8+xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ASKuLYOU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345519; x=1757950319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yewJjRX7I2sqRUJDgGK1FXBidwhz6fi1YdOCa0nte80=;
        b=gxdRT4dANdzXR5APV6gY2QTAyPxK5RSXlRdi04HoQeu1sBCD9dFmKHt3/3vkS60Ww2
         OiVaLzbbQF/DSyIHY1VVKJk97TARx3GY6mkd9kPLtYoCK14fVB4/+HVIcpoNXYkVVux0
         82hdMfBZjOv+V170rYm7gBMT4k+g9GdQQiov9lfLELmq4Xb2nY9IuMoWdZiWAu6KObtl
         z5uZ0HR/TMeFXEKJtrm8SzakvdKWQYS8sMl2OjJDJDuOR4VsMbsDgqBRbbXX/e5dXh9l
         Ys2I8MbUqbOk2EFfm/CZczS4cfEf0/HVCQcGjiH9E/jPdqx3vutHQqLtPbobu8jMoNvd
         8x1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345519; x=1757950319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yewJjRX7I2sqRUJDgGK1FXBidwhz6fi1YdOCa0nte80=;
        b=EwQJFYA+WXmwlndBx94tAuyPzotunzspGRRdAEaEseTHg0KULVHdqP1reOQslZyH0n
         Hur3NFfgocV6RhjvlJRNUgbWaf1Gb5pes4zOYSI5VvuELkVfITnY0hnz/OTcMqU9Dg09
         pAF8/YKvMmhC6N3tbhcrMM2kLwWMiMcl7eEKP4+eGXBgYPS+fwBvo0afJkv9YNdYeEHe
         l+isdDUH+/chirk8otREg7XYD8rReCBl9kVPeOkV2QaO9RuCuppyX+4RYT4j9BIi0Qt1
         iYcJFdg8bOXYwGfeZyU0YgUVG6J4l6ewWDaFRQ2avHz0H0gaKnKA3vZ4InqHBlcbk2e7
         kKAg==
X-Forwarded-Encrypted: i=2; AJvYcCUzS9XJegD1BxyW5QopilBn5apzrzv6o4egf/3Mbgduy7UcpFXVArD3P9EEKXdmrTkLJlsYkA==@lfdr.de
X-Gm-Message-State: AOJu0YzLZndpPY9Mr25+SdtP8JiyEqoElnbZyWTAptzyVZYYCYpnPr+7
	o+wGc0Z50NPviJusMAseffX6pD00l0SI6GC/0lWMt6ONAIoDiv7MQBDp
X-Google-Smtp-Source: AGHT+IFS3Cgn7zk+DtPrTk4rjiQ02pP0CO84StW2o05kE3tNU+m2HjYuIukr7eoSl0E8Zl2a/cSfYA==
X-Received: by 2002:a17:90b:1dcb:b0:32b:ca6f:123f with SMTP id 98e67ed59e1d1-32d43ee718dmr9729969a91.5.1757345519366;
        Mon, 08 Sep 2025 08:31:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcH/2oJNMlbPXvUOe/n4mDDJ6GNfPS1HlRWdkM9HaFsPA==
Received: by 2002:a05:6a00:f86:b0:772:437d:60ca with SMTP id
 d2e1a72fcca58-7741eeff3e0ls3269512b3a.0.-pod-prod-01-us; Mon, 08 Sep 2025
 08:31:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVRMjYpoRBbB4Vw6O7WavQtFht6GJGJVPhzLRy71xY+kk8lvL9vbDJdS9BDhUe0MJJYjr+acRnthI=@googlegroups.com
X-Received: by 2002:a05:6a00:148b:b0:76e:885a:c33f with SMTP id d2e1a72fcca58-7742de65de2mr9613369b3a.29.1757345517504;
        Mon, 08 Sep 2025 08:31:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757345517; cv=none;
        d=google.com; s=arc-20240605;
        b=QYutw/V/sCYSN5S7QD5v4t6n/Jutpyh/Yw+tDDKUhE3jYwDlEOrxZ+yeFb69U7IeeS
         p9hAFLs8kzdU60K+haBmgQSwNbrU+VxzC+5OpkwpppKthEd4ajiiG0zzfJiq/OjB0cpU
         gvrQkI424MHchaVdeuX4lzsD8JVV/YtuF5N61uMBPmOJwWsq8j0qeDdCUcuaUiMjRQh0
         5pSqyElkYCBXR2PHi6WVZvibba5edER5L7hdpbxdDJ7z620JeYBbc5GVxr2/7vXunPMr
         wWrcYhZeyI9+JZjROuzhLXmXlptEynPM9EkQuHTXytREEm+AaEGPoOj4ndsd0eQPQFOI
         lRJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=3/AmiyqDL9vHReNzfhyWcNWwH+eng+cyq2XKxF08kzk=;
        fh=mkw/wglPOtuonBCSr35VHbjmXUHfC6yTsJB+NNuFJv4=;
        b=WyGPKDqPk9hIThCM5vXUDWTDBDGlSdKBUCNOzET2RBSTcpJf9Vslp5ehRRiGMZgP/r
         DUl/KmV7ODXHuil5gyXDVJrYOqTlLK2Kpn40yvM1YXbQs2t7CVYqNokE/vXtkVH3cBJO
         7N1SXZzHVjZlVOhc3IZPdaZ1pt5/4jNwNVQbDUOOxpam+78EG0cmrFDd3sPcAVIfsxM8
         weEx0s3NGHZn4k5I+pmplXLh+3OwbCtkc3mmr63SnMxXr6GORek1OAyqcN1+e4KPijbC
         gMgyZV2KD9P/AfExKutkdjrG0+nXQTF27rknRYrBd7ciQUfOInHXcjLlvrBKh4Ne822h
         jcYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ASKuLYOU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-772436d7ef9si57865b3a.3.2025.09.08.08.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:31:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-597-roq4o42wPpmr5-ydT3REcA-1; Mon, 08 Sep 2025 11:31:55 -0400
X-MC-Unique: roq4o42wPpmr5-ydT3REcA-1
X-Mimecast-MFC-AGG-ID: roq4o42wPpmr5-ydT3REcA_1757345514
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45dde353979so12572055e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:31:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUkboQ5pTEIo0aZ5Lfgiu9ZgOE7L4aR0OIePfBPn2umGIy7JKlffjDzOK3ttlwMEIAfS/MatqK8rhE=@googlegroups.com
X-Gm-Gg: ASbGncu2LlUxEf5Dmp6GXQkcqf8fr5qPEk/MLcmxbcTdp9Rsw1wP01+vWNHVPjMpxhZ
	zOYxPCdYfYLXKNqJkHVJ30IdCkS8cqCB4b70gxsUiNBc4ZexfSN6r2N5qB9qFxNZg14BO8y1vSJ
	8eDV4KVEDB4qSP6kBqLzLSktccznUemIWMq7kwSGAEgHiQ0BdYdSnkxqdauNcyhzaN5NEJgaBE1
	UPTw5FPTksZ1HAVfNhlaC3DW89Y3eXbcjGgYj+mberHJBQBaSAqn93c01DZNh/B4ZA+GI+2c+uT
	BZZ2UApxl5VVjEoDRwUGq7ZQr6ksNJyHSIbTlLLXuMkMMDJruFYWglhrYOm8NFYjK2qBcKZ81tB
	yq3XZQzw7ruYhB61QcOlOEJ/0c5EnVF9oyIqO4wjSvWbDl4OyF6nvN44a5KrhP3iA
X-Received: by 2002:a05:600c:468a:b0:45d:d19c:32fc with SMTP id 5b1f17b1804b1-45dddeb7e1cmr77122625e9.10.1757345514026;
        Mon, 08 Sep 2025 08:31:54 -0700 (PDT)
X-Received: by 2002:a05:600c:468a:b0:45d:d19c:32fc with SMTP id 5b1f17b1804b1-45dddeb7e1cmr77121535e9.10.1757345513379;
        Mon, 08 Sep 2025 08:31:53 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3d7ac825b88sm28792480f8f.7.2025.09.08.08.31.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:31:52 -0700 (PDT)
Message-ID: <cb2f3d85-928f-4a48-9f14-0628c189f10d@redhat.com>
Date: Mon, 8 Sep 2025 17:31:49 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 02/16] device/dax: update devdax to use mmap_prepare
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes@oracle.com>
 <e9f2a694-29b0-4761-ad7a-88c4b24b90b7@redhat.com>
 <a97321dd-d8a4-4658-8894-14b854661d34@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 xsFNBFXLn5EBEAC+zYvAFJxCBY9Tr1xZgcESmxVNI/0ffzE/ZQOiHJl6mGkmA1R7/uUpiCjJ
 dBrn+lhhOYjjNefFQou6478faXE6o2AhmebqT4KiQoUQFV4R7y1KMEKoSyy8hQaK1umALTdL
 QZLQMzNE74ap+GDK0wnacPQFpcG1AE9RMq3aeErY5tujekBS32jfC/7AnH7I0v1v1TbbK3Gp
 XNeiN4QroO+5qaSr0ID2sz5jtBLRb15RMre27E1ImpaIv2Jw8NJgW0k/D1RyKCwaTsgRdwuK
 Kx/Y91XuSBdz0uOyU/S8kM1+ag0wvsGlpBVxRR/xw/E8M7TEwuCZQArqqTCmkG6HGcXFT0V9
 PXFNNgV5jXMQRwU0O/ztJIQqsE5LsUomE//bLwzj9IVsaQpKDqW6TAPjcdBDPLHvriq7kGjt
 WhVhdl0qEYB8lkBEU7V2Yb+SYhmhpDrti9Fq1EsmhiHSkxJcGREoMK/63r9WLZYI3+4W2rAc
 UucZa4OT27U5ZISjNg3Ev0rxU5UH2/pT4wJCfxwocmqaRr6UYmrtZmND89X0KigoFD/XSeVv
 jwBRNjPAubK9/k5NoRrYqztM9W6sJqrH8+UWZ1Idd/DdmogJh0gNC0+N42Za9yBRURfIdKSb
 B3JfpUqcWwE7vUaYrHG1nw54pLUoPG6sAA7Mehl3nd4pZUALHwARAQABzSREYXZpZCBIaWxk
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT7CwZoEEwEIAEQCGwMCF4ACGQEFCwkIBwICIgIG
 FQoJCAsCBBYCAwECHgcWIQQb2cqtc1xMOkYN/MpN3hD3AP+DWgUCaJzangUJJlgIpAAKCRBN
 3hD3AP+DWhAxD/9wcL0A+2rtaAmutaKTfxhTP0b4AAp1r/eLxjrbfbCCmh4pqzBhmSX/4z11
 opn2KqcOsueRF1t2ENLOWzQu3Roiny2HOU7DajqB4dm1BVMaXQya5ae2ghzlJN9SIoopTWlR
 0Af3hPj5E2PYvQhlcqeoehKlBo9rROJv/rjmr2x0yOM8qeTroH/ZzNlCtJ56AsE6Tvl+r7cW
 3x7/Jq5WvWeudKrhFh7/yQ7eRvHCjd9bBrZTlgAfiHmX9AnCCPRPpNGNedV9Yty2Jnxhfmbv
 Pw37LA/jef8zlCDyUh2KCU1xVEOWqg15o1RtTyGV1nXV2O/mfuQJud5vIgzBvHhypc3p6VZJ
 lEf8YmT+Ol5P7SfCs5/uGdWUYQEMqOlg6w9R4Pe8d+mk8KGvfE9/zTwGg0nRgKqlQXrWRERv
 cuEwQbridlPAoQHrFWtwpgYMXx2TaZ3sihcIPo9uU5eBs0rf4mOERY75SK+Ekayv2ucTfjxr
 Kf014py2aoRJHuvy85ee/zIyLmve5hngZTTe3Wg3TInT9UTFzTPhItam6dZ1xqdTGHZYGU0O
 otRHcwLGt470grdiob6PfVTXoHlBvkWRadMhSuG4RORCDpq89vu5QralFNIf3EysNohoFy2A
 LYg2/D53xbU/aa4DDzBb5b1Rkg/udO1gZocVQWrDh6I2K3+cCs7BTQRVy5+RARAA59fefSDR
 9nMGCb9LbMX+TFAoIQo/wgP5XPyzLYakO+94GrgfZjfhdaxPXMsl2+o8jhp/hlIzG56taNdt
 VZtPp3ih1AgbR8rHgXw1xwOpuAd5lE1qNd54ndHuADO9a9A0vPimIes78Hi1/yy+ZEEvRkHk
 /kDa6F3AtTc1m4rbbOk2fiKzzsE9YXweFjQvl9p+AMw6qd/iC4lUk9g0+FQXNdRs+o4o6Qvy
 iOQJfGQ4UcBuOy1IrkJrd8qq5jet1fcM2j4QvsW8CLDWZS1L7kZ5gT5EycMKxUWb8LuRjxzZ
 3QY1aQH2kkzn6acigU3HLtgFyV1gBNV44ehjgvJpRY2cC8VhanTx0dZ9mj1YKIky5N+C0f21
 zvntBqcxV0+3p8MrxRRcgEtDZNav+xAoT3G0W4SahAaUTWXpsZoOecwtxi74CyneQNPTDjNg
 azHmvpdBVEfj7k3p4dmJp5i0U66Onmf6mMFpArvBRSMOKU9DlAzMi4IvhiNWjKVaIE2Se9BY
 FdKVAJaZq85P2y20ZBd08ILnKcj7XKZkLU5FkoA0udEBvQ0f9QLNyyy3DZMCQWcwRuj1m73D
 sq8DEFBdZ5eEkj1dCyx+t/ga6x2rHyc8Sl86oK1tvAkwBNsfKou3v+jP/l14a7DGBvrmlYjO
 59o3t6inu6H7pt7OL6u6BQj7DoMAEQEAAcLBfAQYAQgAJgIbDBYhBBvZyq1zXEw6Rg38yk3e
 EPcA/4NaBQJonNqrBQkmWAihAAoJEE3eEPcA/4NaKtMQALAJ8PzprBEXbXcEXwDKQu+P/vts
 IfUb1UNMfMV76BicGa5NCZnJNQASDP/+bFg6O3gx5NbhHHPeaWz/VxlOmYHokHodOvtL0WCC
 8A5PEP8tOk6029Z+J+xUcMrJClNVFpzVvOpb1lCbhjwAV465Hy+NUSbbUiRxdzNQtLtgZzOV
 Zw7jxUCs4UUZLQTCuBpFgb15bBxYZ/BL9MbzxPxvfUQIPbnzQMcqtpUs21CMK2PdfCh5c4gS
 sDci6D5/ZIBw94UQWmGpM/O1ilGXde2ZzzGYl64glmccD8e87OnEgKnH3FbnJnT4iJchtSvx
 yJNi1+t0+qDti4m88+/9IuPqCKb6Stl+s2dnLtJNrjXBGJtsQG/sRpqsJz5x1/2nPJSRMsx9
 5YfqbdrJSOFXDzZ8/r82HgQEtUvlSXNaXCa95ez0UkOG7+bDm2b3s0XahBQeLVCH0mw3RAQg
 r7xDAYKIrAwfHHmMTnBQDPJwVqxJjVNr7yBic4yfzVWGCGNE4DnOW0vcIeoyhy9vnIa3w1uZ
 3iyY2Nsd7JxfKu1PRhCGwXzRw5TlfEsoRI7V9A8isUCoqE2Dzh3FvYHVeX4Us+bRL/oqareJ
 CIFqgYMyvHj7Q06kTKmauOe4Nf0l0qEkIuIzfoLJ3qr5UyXc2hLtWyT9Ir+lYlX9efqh7mOY
 qIws/H2t
In-Reply-To: <a97321dd-d8a4-4658-8894-14b854661d34@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: G8ngYPbYVH8tEcaKktQ0reZNQvI3jQs1-JJui-SLAHk_1757345514
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ASKuLYOU;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 08.09.25 17:28, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 05:03:54PM +0200, David Hildenbrand wrote:
>> On 08.09.25 13:10, Lorenzo Stoakes wrote:
>>> The devdax driver does nothing special in its f_op->mmap hook, so
>>> straightforwardly update it to use the mmap_prepare hook instead.
>>>
>>> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>>> ---
>>>    drivers/dax/device.c | 32 +++++++++++++++++++++-----------
>>>    1 file changed, 21 insertions(+), 11 deletions(-)
>>>
>>> diff --git a/drivers/dax/device.c b/drivers/dax/device.c
>>> index 2bb40a6060af..c2181439f925 100644
>>> --- a/drivers/dax/device.c
>>> +++ b/drivers/dax/device.c
>>> @@ -13,8 +13,9 @@
>>>    #include "dax-private.h"
>>>    #include "bus.h"
>>> -static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
>>> -		const char *func)
>>> +static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
>>> +		       unsigned long start, unsigned long end, struct file *file,
>>> +		       const char *func)
>>
>> In general
>>
>> Acked-by: David Hildenbrand <david@redhat.com>
> 
> Thanks!
> 
>>
>> The only thing that bugs me is __check_vma() that does not check a vma.
> 
> Ah yeah, you're right.
> 
>>
>> Maybe something along the lines of
>>
>> "check_vma_properties"
> 
> maybe check_vma_desc()?

Would also work, although it might imply that we are passing in a vma desc.

Well, you could let check_vma() construct a vma_desc and pass that to 
check_vma_desc() ...

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cb2f3d85-928f-4a48-9f14-0628c189f10d%40redhat.com.
