Return-Path: <kasan-dev+bncBC32535MUICBBLVY57CQMGQEJRSW4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 01683B469AE
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 09:01:04 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-72631c2c2f7sf59422136d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 00:01:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757142062; cv=pass;
        d=google.com; s=arc-20240605;
        b=Euhvh63uNZmLoGfDjyRPxbh7fplbTzNV2VpkCJJzf89/DQdtlLQv+xqORpea9v7t+v
         1/g6r6vV5enj3K9NvjO/WC1HINZjwCrnTIl0tFZaNyvUOw2iE4PH/mqYYXklwbZ5rSWO
         B3c6a/3jznJblMOKwy1l0nbMCwGcrjQC2GfgVtO7jOwyrSr+34rmDpOPlp2ZhvP8QjoH
         0IgP812x056RBmTSVxKbKt/Wtiqrn0jg5Hdvy4+Yd/7eBlYuP7GpfDT9YBFofvmNR5SV
         1KnxeYOsbCBFkDVRmmzYiq3B8vnsScR+dTx0XesxY+X/EGiohILJUarx5dTznmNZ6+v2
         u9LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=DZKEBO8SxK0446FQixVBfFhn0cKXi2V1WDE8aaxlcGg=;
        fh=+dLaSZDoHyWcNQ7AHWMOQm1rLWa1S+I44Y647BiFpbQ=;
        b=kWJX8wk7DweB/2jm7nSpM9nk8jJTO+eVTh/oNdNIwUdxWXEFeWKFUdOspe+eTfiT2C
         JMswLTWaj3DdYR/ylHJCTF0qpwMbghsSqRoOb/Uqwqdn3p4nwdKLisEmpOI88w3YRuCy
         mvZGyZLRrPThyDBEoO49gmI7x027BUf6KdS8aD6eRtg0t+Emkn2D7hjAY5sNF8oTCbBa
         02njQWi2pnU7zjM4rOId7HP5U+9jYuhsWMj0WZvhSJyGwGmX8MwRu1K3iXlzuu5CiAgc
         +56masG6WjiJmeABsVf6N88x5j26JuZjnJ78SRidf0182z/2m2htd5HOq6SM8dIYkADV
         m7/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KGpHYhHx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757142062; x=1757746862; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DZKEBO8SxK0446FQixVBfFhn0cKXi2V1WDE8aaxlcGg=;
        b=vVJTxw9q6PMzf2SLS6e4c4E/Qm/LW0xEjpv2d++v+4Yor+xb+foU9hM3z4i1WGdGuI
         sN9njTrjOiPpgQs2W7Wfczu/xoJvemr8tOnVcsxjSvfv1VA3n8M41QiYV+g7DocsxBVP
         8GRKjkNiElJ2YkoqayDyz+OfLq2J3kbpu3G1TsYN0zH/WQNBPLw9LVIsiouxQoILA+Kh
         lcjHDKasrPtOgqG6kaWr3krjwmE8E92x2IBhCQqwHNPBDSO5r21q96he2I6QYqOVYk0F
         AtNtclTJKITQ6IkW197yJqUyr7MW0CuAw1zb9nNjwUNUZeE3XdW72dBBh35odF8i9+xU
         3Pzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757142062; x=1757746862;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DZKEBO8SxK0446FQixVBfFhn0cKXi2V1WDE8aaxlcGg=;
        b=LArT2aOWO7gjX+iDakNWF1lYjjJ6vXjirkBtqHp/tiTXgeufWQ+boJQ3N5EZWG8Q4F
         kPXzlq+tYepDFeSH0WPsJZVjy/Kg6rwcrb0jaDMH3lF/DC5vWfPlI9nj3xkivqEkvqU6
         iiCgwdgDs462dJ0y9sBZ45wBCi+8v/5dCYCgjpqxM6JR86xy7tV4CG0Ci0yktH4f9mhJ
         GnrQ0ZQclVfFxhurMZ5nznG1qPTH/VPOfQWFBHwv+h2s5bw3Abl2foPbs86FxcHSF0ku
         s4KFQCHXZO2RLJ/E9x5SfvGqpde/g4FOXDDuEfOaio0KjRiJRH7wo2swd8X57mZMRj0P
         1Qzg==
X-Forwarded-Encrypted: i=2; AJvYcCUFS+KX6HcT15IXWY7cVP8Pjb4feG3It2CNuaYvX7z1FiRBzlkWlKQzP1xr1ZJcvyLlR5wXVg==@lfdr.de
X-Gm-Message-State: AOJu0Yxkjh/uvJ3saRuNTeoXxttAR31xg0XZK4q/TFB0ODEqxyp9Cznv
	zlEUQ2l0TRUrkEVvx9t735kFo0G/+hLcGHCjecNIkEgaOxJvfetCjYAr
X-Google-Smtp-Source: AGHT+IF5JKe+kOoTX9xdsNqM5gNWfoxjjKLUoGVeWPt3A1CqSBCfNx1DcByIPwde8DoY2v+3hLWnwA==
X-Received: by 2002:a05:6214:21cd:b0:71d:d902:692b with SMTP id 6a1803df08f44-739344a86cdmr13032166d6.29.1757142062303;
        Sat, 06 Sep 2025 00:01:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcy0AXKIj+6H0H9lzKYRSgBtVb/Nh9Yvw23arGXNTaeWg==
Received: by 2002:ad4:5942:0:b0:707:4335:5f7 with SMTP id 6a1803df08f44-72d1b4f52adls18236366d6.0.-pod-prod-09-us;
 Sat, 06 Sep 2025 00:01:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmylHzWAx4E1ShhKrABV3eX33zv70+S6Tw7mTjA7reWMmusT5tfMSKa8gan6VjaqKBj5HUANW3MvA=@googlegroups.com
X-Received: by 2002:a05:6214:202e:b0:731:736a:bcd6 with SMTP id 6a1803df08f44-739492cd6a4mr12572966d6.65.1757142061367;
        Sat, 06 Sep 2025 00:01:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757142061; cv=none;
        d=google.com; s=arc-20240605;
        b=jqEcicttzWv1Z8xhFElzpBO2pViKT46FtMKNDvuM+m4BWqb6Hy+ET+lIwgWdFQ4JL+
         qNt4iCllf9CxfpEMvVyv4OJYVPKkMskI9xBPCNCYKIiHvIRiLQerQ0fD0sSjtI2bk73v
         d8fXqYJyeCO8dTOS9UVfDfN6D2SO3Zqap+BgL6OnQCLhiQJIIJXpJZXe5yYG33obqOZM
         KqWOpuurd/KNwQJHjjK8A6IFjdtR32AbFZbWpeNZE9g6AFK95iFMpHQSBWzbntr4ar6a
         UYq+OIdaFliu4JY5T1JaOSyrvhgEEm6ZO7KMS8rqa2o/sKcRPAuaAlQ6ymZiyaPorgTK
         I2yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=T2JJG+ZfsCIb5mNyWFksWhvinuGju8fueKzmBULEe5U=;
        fh=1y061sX5Ds0ObcxzCKr50K1UbKdNBfgv64wkTxOY+SQ=;
        b=EXf12+EuMzZnqQet9d2oYmgchcFI/M2zAumhcFnJIDOhKcMml5U0kRJp1zSswtZ1yU
         dgecTjdXA65i4kR/GxH5z5U2VEkUBuDV//Sy3R+z+fJyyBTE6PFe/0sZ8gNp6vYx2UHz
         D8A+hw7X3f23qbCdV36Ef+pP1vwPS/Ul0vW99oud+eUK+mvNXKXt7woq68guCFcmPf89
         erzWjYCeLg2ttCoSWlXFbSKvrPkRjzryZFdnQC1BtDrNdP8cAQrfF1j0m78i1n95PZn1
         aQwypL75X2NBwLV5uOj+voNOa+RdFtkbTWjzBGWeE7Wu+YT1bF0Ok3PkAuppSZAhUr04
         Hn/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KGpHYhHx;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720a2dd4bfasi5096626d6.0.2025.09.06.00.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Sep 2025 00:01:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-108-N318b1Q0Oma9i336hqOKSQ-1; Sat, 06 Sep 2025 03:01:00 -0400
X-MC-Unique: N318b1Q0Oma9i336hqOKSQ-1
X-Mimecast-MFC-AGG-ID: N318b1Q0Oma9i336hqOKSQ_1757142059
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45ddbfd44aaso8215205e9.2
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 00:00:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUjmPkXU7o/LflQowaC3WR5KnVviem+BP0a+JqQvvI99fKgF19FeBhbFEtCBklECUC9onPU4s0XGJg=@googlegroups.com
X-Gm-Gg: ASbGnct+o+ee5ND9jAP4YBXtAPtCfsX5GfS4VHvItqjjjMbUCtI0mlA+Kx9LVqA281C
	5dGJ+qs2KSvIBsZ5gQtb9Dxk3U78FRTViBZfpE3umvaQB2wumNeq07BaSF6lgOl9s/fxaC9PcLg
	Q9NbfrRdsuhLy3mOA+3erZnFmSGEk9MNLD0dRBWH/qFh2eTWE8Ih+KLgFVq4eJub6JMpaVTxHgg
	UM2SMnA492US+NA55qlJDOzEb8+a9vcPGIqGHuUGf2/dJOiTKwYH10enIq6s4zL9gWRl50O/E2+
	wGlyFZMwh3KXPDLs7vs7FKz8Y+9xY8lYDugovCkDgwzBD5pjA+42VUYHD6k5v9pzvobUD23U37w
	NfEncGNfjTFsG72A9WtDBM7b/jeve+Pdg6DeJAVKqLjLFm1Y5p1+dSk2fMP+hjpLMGXk=
X-Received: by 2002:a5d:5f87:0:b0:3e2:804b:bfed with SMTP id ffacd0b85a97d-3e64c1c2183mr835320f8f.42.1757142058687;
        Sat, 06 Sep 2025 00:00:58 -0700 (PDT)
X-Received: by 2002:a5d:5f87:0:b0:3e2:804b:bfed with SMTP id ffacd0b85a97d-3e64c1c2183mr835230f8f.42.1757142057809;
        Sat, 06 Sep 2025 00:00:57 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f30:de00:8132:f6dc:cba2:9134? (p200300d82f30de008132f6dccba29134.dip0.t-ipconnect.de. [2003:d8:2f30:de00:8132:f6dc:cba2:9134])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf3458a67fsm6794555f8f.62.2025.09.06.00.00.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 00:00:56 -0700 (PDT)
Message-ID: <815cbde4-a56d-446d-b517-c63e12e473de@redhat.com>
Date: Sat, 6 Sep 2025 09:00:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: John Hubbard <jhubbard@nvidia.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
 <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
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
In-Reply-To: <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: EkDrqzJCUbakMeFml-zKhnf0pzoHOZUoiN7VdknZnvM_1757142059
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KGpHYhHx;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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


>    	pmdp = pmd_offset_lockless(pudp, pud, addr);
> @@ -3046,23 +3041,21 @@ static int gup_fast_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr,
>    
>    		next = pmd_addr_end(addr, end);
>    		if (!pmd_present(pmd))
> -			return 0;
> +			break;
>    
> -		if (unlikely(pmd_leaf(pmd))) {
> -			/* See gup_fast_pte_range() */
> -			if (pmd_protnone(pmd))
> -				return 0;
> +		if (unlikely(pmd_leaf(pmd)))
> +			cur_nr_pages = gup_fast_pmd_leaf(pmd, pmdp, addr, next, flags, pages);
> +		else
> +			cur_nr_pages = gup_fast_pte_range(pmd, pmdp, addr, next, flags, pages);
>    
> -			if (!gup_fast_pmd_leaf(pmd, pmdp, addr, next, flags,
> -				pages, nr))
> -				return 0;
> +		nr_pages += cur_nr_pages;
> +		pages += cur_nr_pages;
>    
> -		} else if (!gup_fast_pte_range(pmd, pmdp, addr, next, flags,
> -					       pages, nr))
> -			return 0;
> +		if (nr_pages != (next - addr) >> PAGE_SIZE)
> +			break;

^ cur_nr_pages. Open for suggestions on how to make that thing here even 
better.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/815cbde4-a56d-446d-b517-c63e12e473de%40redhat.com.
