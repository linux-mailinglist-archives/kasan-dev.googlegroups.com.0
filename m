Return-Path: <kasan-dev+bncBC32535MUICBBRWYWLCQMGQECTRD3EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 00381B34A62
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 20:32:39 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70da94b2895sf69376696d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 11:32:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756146758; cv=pass;
        d=google.com; s=arc-20240605;
        b=N0OKn3sDUd22JBDT1aeYeflLbTWld0b1XWq16SHTpAQAtE1/TO76B23ZVQZUfLG3H8
         DaGwEQdtRjB6vZtd/frNPSxP2n45PD9HG39edwrInZ7VLwhucGU8rl18EnNF44lLSvFa
         GfXiJFxvfmsVHIR+dVVQ95gNrcH5WLFEraYmoFYUOpZ+Hg6xEgsP5R8/MkC9HRuIoRuT
         5Mvavb2IvN7piRUtuU6wCFVdaVwXSVU14jANbreaOUUH6NVJRKL+x2tYEodOTxJvEo/C
         /788uatSSi9RDa+tK9/xcZ7ral0ucSEdMRpRa/miZ3KQDeoWErGjWuUmG1awbBgttWvX
         kEkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=eXP/t+9q7KsJfVqEGzhjghqaQWSazWfLyVu0Wamc0Bk=;
        fh=iFgAlcPmVBPeRXz4CDBUm2bCo2CMcCiRWA52GkPSjf0=;
        b=RaLxHTDSlK/TJ4IQ2QH3zYyc2BOL2MReGu/c5vpP9ZQboV26WYBio0oxDeqij8hdEz
         M3hyUhYloy+YE6yN/i6XMzGBTI2jHbjzZnd0wf07sxwlPodQ2qz/fH+Bw5c4Hsuzztjp
         UzwteZEXO/U8ajj5QJpJK6PKYBdVXizcieNXwRXakMhA0pKFCZOygk8fA7XVOOJJhVRo
         ISo7Z2GPScq9lmzi2UWn8PgixqPtmHrV5HFo/Nh48YFb670o+rzg+7JGMxOBZJIvkNfT
         ti8tm+KZq3qoFm38DCGH88+mBKfrlxT9bkDU1zK1uFMukXClsQW+SMWOvrwwuW16jIYH
         HwRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZgtXYbvz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756146758; x=1756751558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=eXP/t+9q7KsJfVqEGzhjghqaQWSazWfLyVu0Wamc0Bk=;
        b=PIN83vbfVd7w4LjIRu8mRe8o3CBwhnWlLLeNdEktkcQeZptoGjwtF4DsA+sms2bGa5
         Bb0AjrMLB7ys2jLsfWUCpU6EW1PZFjQBB++yThdlO8EzdvJsFf4Hwic110TDRK2SoQEi
         o0GtvVmOCgScmspwmm72QuvR1ZQnElSuGlCBBZh0vGMERwp+NLFfkEtQAcBs9beBlsYT
         I69fhq4mXuvu1O5R63h82fHC2yZnxJo0H45PmOxRKWxY9s4/svXpk7suBKig4ekHKog8
         VAHKb33E4RSbEr6SapwJpTpkKkXCpGDVHr9B4i2xKI0ozr17gasnIJod74Kzw7SEikkm
         YTfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756146758; x=1756751558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=eXP/t+9q7KsJfVqEGzhjghqaQWSazWfLyVu0Wamc0Bk=;
        b=ideXtO+UE76qRZFOPyVtmo6KdgyF+8Y9WD1CgE2ekG4qZR629XhCaWP6maObZounXD
         Z6ZryIjPUBt+xVdf2PKY93GHpti+N6Amrg7M/8pKaYjIOJ4SKeygl7VpSArmFS4943VQ
         fa+/+u65yI+UcGswPuBszFkKAjqOcBmHfHFMCJx1TnnRr7DIUVPfLwLlayZaWIe6h8x5
         aUfPwXGEBiazjWe7OywjnLoItzIDK0AY1SGLVw7fIu+LQCNjKPZsWwEaQ8mbEuvoBcUz
         16Reg0yEYsDhutPeCUdu+tIyksTll3gR8CaIIhglUdih5MoImrgjcAPYa6MzOJsH3QjX
         n8Gw==
X-Forwarded-Encrypted: i=2; AJvYcCXTAV8WKUxMrFLJri/6WfAGxug0Rkr6s3K1UvciZFjH8ABqi8iJwsIsfIPtxmssg83C2o29Kw==@lfdr.de
X-Gm-Message-State: AOJu0YwBnHco0XurnUzQMvefzbs1ukACZvMK5y4ADUVbr5dpckzKGRVT
	Zb/K08LOu8V/zNLFF9M72jJmYX5J9XjtPqWjQQCJEAx1exE3nBm7/IYU
X-Google-Smtp-Source: AGHT+IG81e/IipCHdg7Sgr0tuNuGVtujwsFgmgpHFdB0rjpGj+RIBZFfs0GrlJJ8DSPLfd6CfpdsaQ==
X-Received: by 2002:ad4:5f0d:0:b0:707:4cf1:412a with SMTP id 6a1803df08f44-70d97172598mr151622506d6.29.1756146758304;
        Mon, 25 Aug 2025 11:32:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc7cZX/qA6Y9SpMP7Kz9Fbr+6aLgHAwf31o4+eiMMulKA==
Received: by 2002:a05:6214:5096:b0:709:626e:c1f5 with SMTP id
 6a1803df08f44-70db5cc6a65ls27644966d6.2.-pod-prod-04-us; Mon, 25 Aug 2025
 11:32:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJeGf5M/j0/OsvUvvEJKtNHaO6r3AENHamewws8V3+jw4bDHlDkc54ezFMPVcLqwdZ6nJGjENIWiw=@googlegroups.com
X-Received: by 2002:a05:6214:5086:b0:706:ea6d:e161 with SMTP id 6a1803df08f44-70d97200b5dmr132929916d6.32.1756146757371;
        Mon, 25 Aug 2025 11:32:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756146757; cv=none;
        d=google.com; s=arc-20240605;
        b=TiOgTCNkP44TL/nIYtaN2RsLq04Y/64Qd2Kf0EH9/88ENnrDsNtpYRXJodMHshOiFH
         D/8CfFOUE61BvjasdXzYWr3Y2Ao0S9SMlk9mYeM91aCqVPIPcKkf9R2hWQYbrJXFPrDx
         27iHxZB4sFwA/FQtPFmpQJbsRwcPbQxBiTyYLhJXzVkBGh7r4Sj7xLlKPx1fcnQKGpOv
         LNht7zo77CONYCUhEosxuKHIcWgfauGUyssdBKJU7/KyB2UPXIUMnCdrdf6UK8ezkCIf
         eStYb5eKK2G/+ntfB61lHJihvEZy2ksGQ6PmyEOE7F/fQQfUlBAZPOQ/FoZNJsjLSUPi
         2s5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=bluti57k39MttADONVHVsAxBvXyqb5R7ZWo2ok70EgM=;
        fh=Rvr7FKaEaNuhXrDPDTxD1dACzz6T72Gq2R5OL8FEA3w=;
        b=YePBdwaBG5mFmCIlmGBMdlWlRbRZhoZ2V8mIFcD7Qv0mZMu+yevOJoBx1VF9WmGWca
         QIXICF8gDzdwbt+xo2jqIrh1+hIGUBExOwj65H5dcHggMwgf2qUyw9hYW1jz+eN8EQiD
         xRMp6PSB8d810iqOjDCj19HTO05fel1FDZS01qA3OUVCciz1gNXmYvOQ8oAdboRMywnH
         eDhUZACF/R72EzVLMVqZZFfj5hPKX0STebhT/m33+cil++eF9m1ISYcQyUjTZOFzWksy
         OGP+sxPEzy7Enxw+LEGb8L/IyCdUWcd/w/1JeXYoIvP2aQiPNASZfToDq506dT8iFbjm
         nUHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZgtXYbvz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70dc547bfe2si999846d6.1.2025.08.25.11.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 11:32:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-253-ZjJABJnoMUGV2HgPKF44WA-1; Mon, 25 Aug 2025 14:32:33 -0400
X-MC-Unique: ZjJABJnoMUGV2HgPKF44WA-1
X-Mimecast-MFC-AGG-ID: ZjJABJnoMUGV2HgPKF44WA_1756146752
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a1b0ccb6cso23633505e9.3
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 11:32:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUljFqWWgM9MbuKukLBxMHma3U3ygoHFC001dbEa5RmaAnzYEc5+W4wcUcT4bAUa56elUuat06Cap0=@googlegroups.com
X-Gm-Gg: ASbGncupmbsb62Yb4o6P435dvW0aVYAVeQQU9rOwvXwJoV67KN/ShNxXIOb6ZGFnBDn
	NNaFl8MZocZzpR+aIGONbRb4Fs2vrFqrXIAUnfWrdw2wdkxDyVRVnp3tYHjYkTFwA2m9IDv34fv
	1GFt4JuOer5jsgQ0QWohcsKtZt+apJgjRs0qWqv3GcP9Y6FTxKp/TGqV5EUVXectC2jXo2fk3Lj
	hQZz7sKpl0ykPJcJlva+7aHr+14Wc9yk2PeiHCkSfOBpP/Cfo57fl15QFgIFXgAy29acezgtiaB
	+r3ZhtzqvKcLbuIJF9GxuPk2bFJhbBWjVM1OnjlseTpl7YOWfXntdt4gdcMxIihWK4EhLH4cVN6
	ZUEuJ98kiLK0gmA76wrnYrxbzRbVOz/wEcN38Oz++PJ2T8RQTPM7cW0GmNXwhQHtaO44=
X-Received: by 2002:a05:600c:4e90:b0:458:a559:a693 with SMTP id 5b1f17b1804b1-45b517b957emr126710455e9.18.1756146752223;
        Mon, 25 Aug 2025 11:32:32 -0700 (PDT)
X-Received: by 2002:a05:600c:4e90:b0:458:a559:a693 with SMTP id 5b1f17b1804b1-45b517b957emr126710235e9.18.1756146751795;
        Mon, 25 Aug 2025 11:32:31 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76? (p200300d82f4f130042f198e5ddf83a76.dip0.t-ipconnect.de. [2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c7119c4200sm12481975f8f.53.2025.08.25.11.32.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 11:32:31 -0700 (PDT)
Message-ID: <7ffd0abd-27a1-40a8-b538-9a01e21abb29@redhat.com>
Date: Mon, 25 Aug 2025 20:32:27 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: update kernel-doc for MEMBLOCK_RSRV_NOINIT
To: Mike Rapoport <rppt@kernel.org>
Cc: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>,
 linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
 <aKx6SlYrj_hiPXBB@kernel.org>
 <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
 <aKyMfvWe8JetkbRL@kernel.org>
 <dbd2ec55-0e7f-407a-a8bd-e1ac83ac2a0a@redhat.com>
 <aKyWIriZ1bmnIrBW@kernel.org>
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
In-Reply-To: <aKyWIriZ1bmnIrBW@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: PgX0nHybwbERWvl2BTiV5S2n85XIh_9f4EsyoC-wggs_1756146752
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZgtXYbvz;
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

On 25.08.25 18:58, Mike Rapoport wrote:
> On Mon, Aug 25, 2025 at 06:23:48PM +0200, David Hildenbrand wrote:
>>
>> I don't quite understand the interaction with PG_Reserved and why anybody
>> using this function should care.
>>
>> So maybe you can rephrase in a way that is easier to digest, and rather
>> focuses on what callers of this function are supposed to do vs. have the
>> liberty of not doing?
> 
> How about
>   
> diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> index b96746376e17..fcda8481de9a 100644
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -40,8 +40,9 @@ extern unsigned long long max_possible_pfn;
>    * via a driver, and never indicated in the firmware-provided memory map as
>    * system RAM. This corresponds to IORESOURCE_SYSRAM_DRIVER_MANAGED in the
>    * kernel resource tree.
> - * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages are
> - * not initialized (only for reserved regions).
> + * @MEMBLOCK_RSRV_NOINIT: reserved memory region for which struct pages are not
> + * fully initialized. Users of this flag are responsible to properly initialize
> + * struct pages of this region
>    * @MEMBLOCK_RSRV_KERN: memory region that is reserved for kernel use,
>    * either explictitly with memblock_reserve_kern() or via memblock
>    * allocation APIs. All memblock allocations set this flag.
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 154f1d73b61f..46b411fb3630 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1091,13 +1091,20 @@ int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
>   
>   /**
>    * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
> - * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initialized
> - * for this region.
> + * MEMBLOCK_RSRV_NOINIT
> + *
>    * @base: the base phys addr of the region
>    * @size: the size of the region
>    *
> - * struct pages will not be initialized for reserved memory regions marked with
> - * %MEMBLOCK_RSRV_NOINIT.
> + * The struct pages for the reserved regions marked %MEMBLOCK_RSRV_NOINIT will
> + * not be fully initialized to allow the caller optimize their initialization.
> + *
> + * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, setting this flag
> + * completely bypasses the initialization of struct pages for such region.
> + *
> + * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled, struct pages in this
> + * region will be initialized with default values but won't be marked as
> + * reserved.

Sounds good.

I am surprised regarding "reserved", but I guess that's because we don't 
end up calling "reserve_bootmem_region()" on these regions in 
memmap_init_reserved_pages().


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7ffd0abd-27a1-40a8-b538-9a01e21abb29%40redhat.com.
