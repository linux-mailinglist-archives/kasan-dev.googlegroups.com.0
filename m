Return-Path: <kasan-dev+bncBC32535MUICBBD7Y3LCQMGQEUOH4BLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CC25B3FADD
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 11:42:41 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-24457f59889sf55018345ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 02:42:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756806160; cv=pass;
        d=google.com; s=arc-20240605;
        b=lsA3+K10xvxf1mdTXpFLyQKHNya4tTvHRSSs9re+L5bOhX+SojFLe2vhmm6ugUhVi2
         sYXqjOSRlJLHpNqJNEdd5VBVdQffafW2lMjnJeSSyGN4zgr6BUYKFNlEiIR0xK3zOT1G
         BZbsjLP0ymUaPxy788hw3nGQ5WaJJo1IuQFYDlRnEIA00vrMIXk3D8YZJdSI5oFD5TpA
         S5RG7NdtP+ztmd+p+EQJ9OWBE+uTHpdks/PL8A4iq7lTaTIE52ml3m+WZlHrI76I87Vk
         e2ABPWDgL/mV59OfD8ifhoR/Um9NbtYcKX0EGtygEA5K8bbzmYlke9HVCoILT1V52/Ns
         tNNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=oXGJkYutZ95UvKoNEuMitReq8AqA0Tyo5WvgNYuZJNI=;
        fh=vF2/LBEKbIqhzeWTASbLBzbVeLpGrYUymqLmOlcXIHQ=;
        b=Zb9fmw3BNNXAaAUI+XHbBQxkf6QPX49zZQNIS4KKLcyDqVu5P+XtzV3xDt7SDosW9+
         TcGsxRqeXoBVifGL2btOJySc0RnZMrzeKrKPrhOYdMtWfYVjwphUBOZfw/9ctzN3sd2M
         yqbsHHTl8ruj6RAbf3kNcBxvzl4uRPUNQtNsrcDJZpB/5qR3CJSwk+sXRxzK+BGpUPUw
         EFMl/yVRLsbIsRQDEhmTu8kWcHMnc61fCQv+n9pTpKLc3kS/oKCUPlQtj+tm/9VzbKTw
         g7P0lO3hRZz4rz+UKk+VCQOnP5gsypEwZADkxHKkywOUMAlK7HzNAd+Pbh5rZhL+lTpf
         wtsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E9zJZ1ao;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756806159; x=1757410959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=oXGJkYutZ95UvKoNEuMitReq8AqA0Tyo5WvgNYuZJNI=;
        b=mC6S+xjZQdvNi+cCct/N1xk1c6BMdq7RQTl9WWDJymvIGnCFTRuN3GvZuieuUSRrA2
         VR1JlEPbndTr1g3gd7QNrMjjmmB9KYUljyMdWrzeegpi1RnnIkJWcgvQ0rECcAvBYlgF
         zueATXoFl4+M+7p7AEBNrjf8WmBNsZfgtQtzADr9iC6PYm5oCdokIcuLwdVE4JsGd1S5
         9tGACo7pjgMdrMk/BPFSMzE33JKRSfV9x1dfTGSva78zS32jfnOQ6kJiXciQjqnELBo5
         4GzjyVAEeBf4gsoM/MPxze4blIXuQON6RiezSmkoZf2+fdknAUn3o8qFJbMrfsjruQBe
         GqWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756806159; x=1757410959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=oXGJkYutZ95UvKoNEuMitReq8AqA0Tyo5WvgNYuZJNI=;
        b=ZS0/J7SlfgtdPg6JZgJStOWHbBO4qCrxnexiXMyA5t+Y0E5TGGnm63vgLpx5PvnxRb
         9oK6rG3B1HbwWNjtjAyyAsyErVLf8Zp32cnolf09O0sDOjvo3UKcCaxF0b9jiEerBbHZ
         ywo1uUb/BI7ONwk5WoJMujUAy4gnOlhyOzv+0LBN3Qg2XD605PP38lgiITUjZ4rnPZQu
         HGkSrcnYqTCZzfMuOWrCRYq95Nj2lR8f7U0SOAKH6WjcmFI8+Ze2pYWUhB0MbRKmcw91
         bpLqnHHS/61Ft4q0F98KZIXWzsFn+85dWDvlLaSjosDMzXaNYbYYJR8Rig8qquqznzF5
         v39Q==
X-Forwarded-Encrypted: i=2; AJvYcCUwfh31KNptRNKfi+yrbaC6rHqHhIJGPo4UxQ6ZeNaVfkdvJzJ7jLF/LJXt74uB8p1jVnpSRg==@lfdr.de
X-Gm-Message-State: AOJu0YyiFJ/ZvKB5187lsEsJz1Cvm9IwCQbC18L8WMcsKLqxxcm4E9Vd
	IUBml2Wnc8wVCt9S3/5379hWDK08nbR3mx0xs8jFig6QQ6lAwihu+CQq
X-Google-Smtp-Source: AGHT+IHbtR5TmKEflu4AIdbSTpbJETdrPb6hwfOJhhGWwEV87p5W17JaI1o2pq9TMUsEcu7F1XdyNw==
X-Received: by 2002:a17:903:1448:b0:248:ae62:dd with SMTP id d9443c01a7336-24944ad04a0mr113850625ad.42.1756806159599;
        Tue, 02 Sep 2025 02:42:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiRX7cQBM1f/2hTKiqTu/GhzQcpzS2FBX/TVmXxGDBzg==
Received: by 2002:a17:903:1894:b0:248:c926:8445 with SMTP id
 d9443c01a7336-248d4acdfa0ls41014785ad.0.-pod-prod-02-us; Tue, 02 Sep 2025
 02:42:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTfLULEQ8BuSn+Py6f96v7Z7HCbnI3aI9O4wMvO24BDjeSupzVPZ0nZCEvt1olSTO4QDGKofs4cFQ=@googlegroups.com
X-Received: by 2002:a17:902:cecc:b0:24a:aeb6:f1c8 with SMTP id d9443c01a7336-24aaeb6f63bmr99788935ad.43.1756806158153;
        Tue, 02 Sep 2025 02:42:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756806158; cv=none;
        d=google.com; s=arc-20240605;
        b=A/L/PGVbsrKLzh9TOXmOLDSoyeqyuaz3sM52npFh8fYeTrK+7hkdrPpEsKy3GHhy/m
         0WFPrCym1Q8RTnMyRtlRYW+s6aqgQOb3HMzYO4ahGi6It40EdECkNKUO8qf0OohZ+Ate
         MwMUFWyJv5lslKtvZ8bT2mmPeVA8smhufyMi7uGnhhvNyjY7eFmoTQATKi32Oo5ZaLe8
         jiT2HEG+I1TcOJmR1IRZr6r5XBs1boPGMsuv2ZPVGtMzXHoiZIcDKlOVgWtgaas1vHo0
         486cAnNEB6qwZ5SdITMMSwr88YyynBySe0QgUosKyHgufuK6AHp1749hQhRhuTlH3WH/
         cIWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=asWSuLH6iU8nN8yxFqi4dFvgrrSedS75Z/J4pSraBcc=;
        fh=hyVVMftxjUB3VeNVXNoRHem7HscilUupyVBOlY5qsqA=;
        b=V7IqRs7TXwxuTaMccM5OF/HjWhdS5TycFb3i3vTyuxA54ya/JJ4WYN6waO0q1/L5pZ
         MBLrbTN7vQrODrvFvz8EgaeyjczKa8/EyAuOVgx0bth1AITFkhtZgYQrfKZVoRcAZc2H
         zEHkuMVwKq0aew1Ch1zoI7bJRN1rrIUa6iOXLHMoMZbOLAVCtN8mrvFF3cPgwdV4MHze
         8sBmpxifv/8UWe3GJCsc1AN2Vvl7qqY4krfk3hTG4K01+GBz3r5Nq8AUc23eiH4Ka7/D
         A1gNgFk4gFREcqIzqendqEy1aqTA9xVoAVtW0vaMtgHQ7oV9q7hHDW5qL3GloabwXdEw
         sXBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E9zJZ1ao;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-249065a5756si5030355ad.8.2025.09.02.02.42.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 02:42:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-502-LArA1v6MNQ6RopBxL176Mw-1; Tue, 02 Sep 2025 05:42:36 -0400
X-MC-Unique: LArA1v6MNQ6RopBxL176Mw-1
X-Mimecast-MFC-AGG-ID: LArA1v6MNQ6RopBxL176Mw_1756806155
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45b7f0d1449so19751575e9.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 02:42:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUI/4K1WfBozhRRP1wBK02tsnSsdUC6r2XRcImBgWY/0Dt6p4GNayhBT9Vx/6+sUx8FfCWdUxpSLJw=@googlegroups.com
X-Gm-Gg: ASbGncsRlxkQTuzZawwOazanU4luXVeGocKx/F4R/NQ7RB4/ma4mYJfeySYqOSBNs9E
	F596cvLrphyPZXJCxKk3r5AjsysWZDlIDZ9u2iXhLI8MSQ5DdHEvjE3W2a6aMF4plZysDAxRp9A
	OQEh8y6D4Xp+RCpunizhphP1a7DiNJSl5kx7iaZJ7VhyCZc0SSlcXFhy1aIvlrxgt8kyqWMij/c
	X13ANOUyK2u3MC+U7+WlfgeeM2m3xhftfHSxn4jH+iw5MC/m2STHm36NcBiwOORx9PVF9s+1nmE
	xxc2SDUmGL7SBC1lzw0lf1PJ1vcrgjxjLAgBLeeNQdGpjv/Ud7kU9KMDtCQ18/QSjvD9SmIK84D
	kM0CZPR/IBxPkdEFp8VklURGhYf5zXt+R3jwTbPvKfL5lxoeGp7nvpECO0c4Ysqagrd8=
X-Received: by 2002:a05:600c:1ca4:b0:43c:ec4c:25b4 with SMTP id 5b1f17b1804b1-45b8554e2ffmr100852865e9.10.1756806154858;
        Tue, 02 Sep 2025 02:42:34 -0700 (PDT)
X-Received: by 2002:a05:600c:1ca4:b0:43c:ec4c:25b4 with SMTP id 5b1f17b1804b1-45b8554e2ffmr100852105e9.10.1756806154215;
        Tue, 02 Sep 2025 02:42:34 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1f:3f00:731a:f5e5:774e:d40c? (p200300d82f1f3f00731af5e5774ed40c.dip0.t-ipconnect.de. [2003:d8:2f1f:3f00:731a:f5e5:774e:d40c])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b8acbe982sm57017205e9.6.2025.09.02.02.42.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 02:42:33 -0700 (PDT)
Message-ID: <22019944-2ef2-4463-9b3f-23c9e7c70b2f@redhat.com>
Date: Tue, 2 Sep 2025 11:42:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 26/37] drm/i915/gem: drop nth_page() usage within SG
 entry
To: Tvrtko Ursulin <tursulin@ursulin.net>, linux-kernel@vger.kernel.org
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Jani Nikula <jani.nikula@linux.intel.com>,
 Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
 Rodrigo Vivi <rodrigo.vivi@intel.com>, David Airlie <airlied@gmail.com>,
 Simona Vetter <simona@ffwll.ch>, Alexander Potapenko <glider@google.com>,
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
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-27-david@redhat.com>
 <4bbf5590-7591-4dfc-a23e-0bda6cb31a80@ursulin.net>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <4bbf5590-7591-4dfc-a23e-0bda6cb31a80@ursulin.net>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: j1Xww8SormkyjW3hzlNolN5kFK8cZpo2ciprVgWdUPc_1756806155
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=E9zJZ1ao;
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

On 02.09.25 11:22, Tvrtko Ursulin wrote:
> 
> On 01/09/2025 16:03, David Hildenbrand wrote:
>> It's no longer required to use nth_page() when iterating pages within a
>> single SG entry, so let's drop the nth_page() usage.
>>
>> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>> Cc: Jani Nikula <jani.nikula@linux.intel.com>
>> Cc: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
>> Cc: Rodrigo Vivi <rodrigo.vivi@intel.com>
>> Cc: Tvrtko Ursulin <tursulin@ursulin.net>
>> Cc: David Airlie <airlied@gmail.com>
>> Cc: Simona Vetter <simona@ffwll.ch>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>    drivers/gpu/drm/i915/gem/i915_gem_pages.c | 2 +-
>>    1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
>> index c16a57160b262..031d7acc16142 100644
>> --- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
>> +++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
>> @@ -779,7 +779,7 @@ __i915_gem_object_get_page(struct drm_i915_gem_object *obj, pgoff_t n)
>>    	GEM_BUG_ON(!i915_gem_object_has_struct_page(obj));
>>    
>>    	sg = i915_gem_object_get_sg(obj, n, &offset);
>> -	return nth_page(sg_page(sg), offset);
>> +	return sg_page(sg) + offset;
>>    }
>>    
>>    /* Like i915_gem_object_get_page(), but mark the returned page dirty */
> 
> LGTM. If you want an ack to merge via a tree other than i915 you have
> it. I suspect it might be easier to coordinate like that.

Yeah, it would be best to route all of that through the MM tree. Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/22019944-2ef2-4463-9b3f-23c9e7c70b2f%40redhat.com.
