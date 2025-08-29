Return-Path: <kasan-dev+bncBC32535MUICBBDHYY3CQMGQEAK4WZ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B01DB3BE12
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:41:18 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b109bc5ecasf49407051cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:41:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478477; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zgj3IgfWIGASH6G3VQIt7ur6m+lRaYkM/bxGZZgxFu+x2E70/8daSGZI5fc7l9fCkJ
         RmehHMGe7A0T/s2dh24wAkwDlowBSW5ISQid96dLxfstR11N6+9etBj1Gwtfl3zGZB4s
         q6hz0O+asiVRMSaE0Znl1Mt7jke3lmkBy8PHIWOLmCgqhbyRSJyafGwtlFFN8ZSNdhmn
         Jb8wUWdHaZqW9qK+MX0Ps3IEg6T5yWuPH8EEa+NQNS+RbnH3IFDY8o2M2vixFfEGlY0p
         OW4tiDTuz85zJ+pjCGdVQQTcJDrtMigsYkVA2KeBx9L9O+HwecD5tnaPMmEtOt/GlHSW
         MI2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=T74J9ysKZrpa0CcOJEdEO7EHNFzDrTpwGwSPERWyfK0=;
        fh=AyPAMkpJ0385T88xmGNqktAT2CefkEJgwXgSbZm8G9E=;
        b=a9jpUkztIirp6HFg0zZLEdN5k6mtspQAr0XLcunftlkB3ADZqZv3lIxM0lZYrQ6BSs
         N2xcw7H7fKHfLviGdno/loe0Cr74RB5cyairH5IpNmCHG1JEuIEYuUejUoInhlgrMMAc
         wY3RZa+pZKMvALaUNqMeXh57KP3QvO1eDUMnzOkWrXJQIRi/VqVdE1o+C4cVNxmR766A
         dN5AAsqLYAeDi0O6pbpkHuJ3gSXhXf5PBhezud+7HOIPZQGfAQFW+X8FDR4RgH51FRdg
         xNOZmqEtZpLIUiUo3fi+x5dUVzWtFoHpo5PYfLoYmA2KTtJKdVgryAYxwZ+7aZBpcEMX
         6ocw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DxlbUizh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478477; x=1757083277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=T74J9ysKZrpa0CcOJEdEO7EHNFzDrTpwGwSPERWyfK0=;
        b=xDFLoU73wWCJiv3HVNPnBK9FcMbKdtSr9pv2zOd4hPQKxNOGBbcqz3qGN+UJ1LROgb
         mSI6ahJLW7OsUBL++Wq+t/Q6I24RBEoFGrgB44aU0B0s2HilzS8AKy52uK6HMKfwR1yZ
         xPMiYT7ZOFZtTCyrHwdRkEe8CodRNEeo7FgVMnXKCvKPAliUjOWtCscG1YPz5EFKTFVN
         +zNLnJqYtnSZPVQbt3kI2G4/WB9Mf2sEohteUlDA0T1A7A0a0JYTIkj0k4M7vJ/bPLsb
         BUheYDfAWGJeb7n4P6b2+DJp9J29NgeGj6Yz1b6lEetfLb32ZOejdbcl0F364d2eV99K
         GHjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478477; x=1757083277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=T74J9ysKZrpa0CcOJEdEO7EHNFzDrTpwGwSPERWyfK0=;
        b=kpZydLWY5EXnEWHwYVmSFhXSYm3us59Dz69ZZ7FV4spjBYvfGFu5eC6kkyljZz4qJl
         toCJ27l5DLUzyZdmpf1p7KAvSlNjbACkmsihWw3/9BA/tPWbegb2iv+7xreno0vnpDiW
         x2+Vqqxb2ADTUx96S4tC8TIv4EnfyLIOoPsSm/YUe1T5Y4pTxY7J+O+EbF2TD1O9oU2B
         aO5Rc13/IuT5IKaAVQEHwZXFJWfQccTLaAxVQs1/cIv97cLqN5WVuBPWj3XZpPYq4tY+
         0JKzkZkNDVyz/q2372no39zIskVJYuhX/VvVb++xYRpTy8DgWXbJqlKp2muuqEPKW+LR
         TTyg==
X-Forwarded-Encrypted: i=2; AJvYcCU2e2NGftPLVz0aS+PiWNINxbMZ/xbXBmgrsKuvsVVTndHTlNaODpgcPNp8q4hmJxy+bBhosQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy3VpKENHMk5RJhnyVLNIyZwLS5bOIRYTpGIhehIG/bXBIJyBuP
	IhCIzhPlMIrAhGFEzNptbzx+8QDyCHJSSVJTZ6QufKB3DoLLuPLbJkV/
X-Google-Smtp-Source: AGHT+IFx81iAL8bd9CYNr6vOTSOYqRKXI/3e2hIIK7tqXbNtVtmzkUPlm6WQ/qMA2YKdN6zJtf2ZjQ==
X-Received: by 2002:a05:622a:58cd:b0:4b3:552:2794 with SMTP id d75a77b69052e-4b3055240damr59389021cf.60.1756478476915;
        Fri, 29 Aug 2025 07:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrMJVkJT9CDxEBwyunCXUZ3JBU86EvZFmb0Nc9geNlXw==
Received: by 2002:a05:622a:11d6:b0:4b0:7b0a:5903 with SMTP id
 d75a77b69052e-4b2fe87a378ls38250291cf.2.-pod-prod-07-us; Fri, 29 Aug 2025
 07:41:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYzqMYlED5jCByhZoG9nm1wsiOtc92XnTKEyYeLi7OqvcE6Z65nZpms/D4BCXiaPEBvUdpAWBvHAk=@googlegroups.com
X-Received: by 2002:a05:620a:4483:b0:7e3:2c33:6d9f with SMTP id af79cd13be357-7ea10ffd6dfmr3654908485a.31.1756478475944;
        Fri, 29 Aug 2025 07:41:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756478475; cv=none;
        d=google.com; s=arc-20240605;
        b=P+tOT8a7NdKoA9Wzg75ygkhIdeHhGXM9dorTgDbqDawWljAdBIWj0zkgLwUF+7FSXC
         GNX3/t8kzlDA8CWl84EHX9x/1+jItluITwLRThte5n73+c6AahLJBpWLajmIAK2vmQRa
         rsdn+I/o+cqtstArqLM1hXbC7SHbOwLRM0ziDaMZoH+2YDdszfKValV34Y384bocBvVY
         F0QttILU96VAz2pue8HaQShsguLxywZseAJK0x40abw2Wmdmnwb5donkDqlLJX9XlWJV
         8qrljHeBxCz/API8/8n7wbyTwmVlTQ/ACzWPSPm2mjfmIMBlCj8Ax59Tfsy8Glyx+hF5
         Qq4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=IaQHZcwb14XTWilYbwjP6AKy4Qvx/cjgmhYjWqgMQRs=;
        fh=v0Ro1v/dKsCnbrxw2UL7Jip/35Cr4yihOuaH2R6gRJQ=;
        b=AEhuINaFESYjyQG2/itmTDBMC0NsUv9oXHIqnNapER0ZE/UHv5o9bmWs+heZE4zimI
         mdsW0u76TogchTAoT9GsxkeCBjeiw5HexQ7izBX1P3m4th5qkD56wwZys0wYmbe6Qmce
         tK8uvBBna6rX3GdNhiG5rdwgsqHcI3bEH2G0ppI1yXbhBfeeacXIYl82mJitclXsu0Z5
         7bqWy1hKKpmalrLexP5lu7kl//I3WcY+75Pd08G7oqpmVEcp8VvGobXVjyNBIUnggxnp
         e87WCIEGj0w3vt42rXDcVxY3sSkubq6TQDFHhqsDVDD9XNoAQAhsET7WqyZai7PaVX7R
         JQOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DxlbUizh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b660eeesi1020791cf.4.2025.08.29.07.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 07:41:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-131-ajTso9C9MjSU0yzlbfKl9Q-1; Fri, 29 Aug 2025 10:41:14 -0400
X-MC-Unique: ajTso9C9MjSU0yzlbfKl9Q-1
X-Mimecast-MFC-AGG-ID: ajTso9C9MjSU0yzlbfKl9Q_1756478473
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45b467f5173so17487785e9.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 07:41:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVLwe/aWlzt6KthEXTl4eHg1/ShX4wnwzZs3VcRCAP4Ehe1PtQnjoNXx5rpvHTLfkUSqz536E43eEY=@googlegroups.com
X-Gm-Gg: ASbGncsa+oF5qqAve3OPgCVHSfSnBtJ7e/IgBjNM4G8yPVj9GUBGtjFWPYzbpylEgDO
	AVqQvvb8rzl9PMgenDQeSb11yox+uHQekrNQTrOOaaPsUeCPGWO9mCg0bgPvvvtek6HnHbcXpYb
	pEm8RUFlQR/7OuPWl0KlVLCTiZ80kOVBflKOJhHLUZFZdm+32L01y++ve1pDfvQ2Ra/POXhH1Lc
	LFcCI0ummche9tL8mcG0zFs3cDshAwbHRwRNG4oL2hy5AgpNCLObv7i9Cgxa2FPgYjN8KD2fBCY
	e3bUTiUXTCQBIA/TXButrACMjbMSjFpmrjqStX0Uguf29lrwhHczlO44ZTAMe6RE6A6WGQ1R19F
	i9nuTnURvmEJQkCjzhEy/7Kjn7rSkk77wZLNSpMm7ZBQI07eqddq4pHPdp+gztcdt
X-Received: by 2002:a05:600c:3b1d:b0:45b:80ff:58f7 with SMTP id 5b1f17b1804b1-45b80ff5a3emr17032635e9.36.1756478472629;
        Fri, 29 Aug 2025 07:41:12 -0700 (PDT)
X-Received: by 2002:a05:600c:3b1d:b0:45b:80ff:58f7 with SMTP id 5b1f17b1804b1-45b80ff5a3emr17032245e9.36.1756478471858;
        Fri, 29 Aug 2025 07:41:11 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b74950639sm95314275e9.17.2025.08.29.07.41.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:41:11 -0700 (PDT)
Message-ID: <4b053602-7c80-4ea4-8617-0f5e526c02f6@redhat.com>
Date: Fri, 29 Aug 2025 16:41:08 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 33/36] mm/gup: drop nth_page() usage in
 unpin_user_page_range_dirty_lock()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 <20250827220141.262669-34-david@redhat.com>
 <c9527014-9a29-48f4-8ca9-a6226f962c00@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <c9527014-9a29-48f4-8ca9-a6226f962c00@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: RsyDoLs1968GqBn8GmBL533F7yEpSbjdFqA_xPrAfWY_1756478473
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DxlbUizh;
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

On 28.08.25 20:09, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:37AM +0200, David Hildenbrand wrote:
>> There is the concern that unpin_user_page_range_dirty_lock() might do
>> some weird merging of PFN ranges -- either now or in the future -- such
>> that PFN range is contiguous but the page range might not be.
>>
>> Let's sanity-check for that and drop the nth_page() usage.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> Seems one user uses SG and the other is IOMMU and in each instance you'd
> expect physical contiguity (maybe Jason G. or somebody else more familiar
> with these uses can also chime in).

Right, and I added the sanity-check so we can identify and fix any such 
wrong merging of ranges.

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4b053602-7c80-4ea4-8617-0f5e526c02f6%40redhat.com.
