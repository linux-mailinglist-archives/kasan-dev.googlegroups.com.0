Return-Path: <kasan-dev+bncBC32535MUICBBOHJ7PCQMGQEOUFHZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EF8CB492FA
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:22:34 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b5f75c17a3sf67883541cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:22:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344953; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rp7DLwWeVi/ew3k3tascyEZnPc4LurglDaq9YqirK2JQpt4stzewP98uWoIhowuqlM
         QMDHhAj3s+lJtGPwuG9XS9n4PKf0YogGUhEp1IaAdC/WtzPoMzohAmM3NGMG3ZfqOfY6
         c8RtU2BK+ju+mARDpCKJCuGIkjr+dnKxAB53+99i9rw/GewLsUu3CDmdc3QGxwDAzUMH
         9y7vNrIc7JwfoD1VDPMInlRSVLzMM56Os56uE87DA2VI/4r1N6/51vgFevpqGpk6f3Yp
         h9B+xgex+4m+IJ4RrkwCw3qJmS05OWSu044Hu4UDIV57fPzJFLGYLYza7l8VYsDA9L5C
         g0Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=mwbSnXb2MwaAYAXCHXb3Am/SnIgfiiGmu3/wmc56GuE=;
        fh=8vZUMHNXiXYBZ8PTfS6l8DKsyVlfgSwAdvlqy3wBkHo=;
        b=EIjvvGAB3yl/6zP9ZrQxRkbVoO+RRE2/9t1ZxJWSSpG1BKPm9CUPowKDTCS7q72cHl
         7LbxSA3z70L3imDKMLLGXt/jIESLJJzEuGOT+HB4f1j0+AFn3A67KHPv98w3i1x/4122
         GwJSTOSdOY6+r6M7BsyNLvTOXDTDq3fKKsesj47ZXzA6vKdpg/MF5gFZmPQfk/EoKgmb
         TdK8xg6KZL8LogK1aUh8b5KYYS99r94sqYo4ZIs+WWKIvzNun77ItQOOmm6EEgTT7TSp
         6kAoV858XagwrTtD2Z61f6kGXYTawHJuqsVBocEZr90/svy9gU92MRiGf1B4Jx774XyX
         VtFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q1gHV7iQ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344953; x=1757949753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mwbSnXb2MwaAYAXCHXb3Am/SnIgfiiGmu3/wmc56GuE=;
        b=fQKZpi6D3/NHimqZ1ZJUOgh0g7Tg04OLw9U9LcJkv1qf0s688jH8HvZrxJv4P6BGjA
         BpBfVKsd+UeMwzqQJLi/uI5wZKkWI4IYYD9l1Sp6kqepsIF5qg5BnlGKZ1zZeJefD382
         SsKr2SV7Gs1fz6n5ome1NIpG0QKgjrBiUIKPdVcb5UWZziDrUoYvuOFDxRemoTLk9Uod
         QiEqb6D8/ZV1jfNdzCGbhG8mtMUWBQarplfNZmdwe2ZTP3vDEip4HYbzASgBkLezbI/i
         iyYChX8u6D0MRqsChdHtz4rZizkn3VzIfGOOit988Vw7WBlkyTVNW2vnLZ/7Nab6iI06
         SJOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344953; x=1757949753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mwbSnXb2MwaAYAXCHXb3Am/SnIgfiiGmu3/wmc56GuE=;
        b=p97jtQQ2mKiVMSJmGV0i8/qcSHvwJzo7mOnBf4J2kXP3t0/GD3bgt1bNJtycEn6woB
         Oji7mcMWLuI1kzMfVc7Uwi7JPnmZU6hKK6oTnd6Zu9oT2md37v/aGuZxGLK471yOgxUC
         1DlA6nKwqeaywYwdkTvXq5nggcX8Koc5h4Em8kTfxcoCoXGwXpiyAZHrm5DyuLHx/KwA
         +ddxKxe42YIOQSk7MgmEBPrRULDhajm2b+uEK1Es8pWypBZnt3kpxDr/rT/xeOQ36I6+
         KpP8+SXvJjQZJ7G2JegvCqgAayENYkKNKDZ7oHtk3FMDYGT6IdU+LA5b3MqaYPLZhl+t
         CdUA==
X-Forwarded-Encrypted: i=2; AJvYcCUX/D20oqzO7uZCgtUV77fQrNAIXejxpauo9/U9z2bdbw7r7kYRWI5jfBI/Deg9JSpIakQP+w==@lfdr.de
X-Gm-Message-State: AOJu0YwJwgi7OpRLgqTwexg5DamT1iBcZvSqo6LQOA4gSztgJ2b8M0b0
	algGj0VQxSnwJN7GQqmn4ZziyrDxPgLVpy1zo2AiUhGPc2ePGvCE+lNE
X-Google-Smtp-Source: AGHT+IEnwpyZ6Lqzm3MaGFbH1IVFt9e31mOamhC6RiZu5YuXy18KQ6hZ0jHgR8/WD50aCTQ4rdBzyg==
X-Received: by 2002:a05:622a:55:b0:4b2:8ac5:25a3 with SMTP id d75a77b69052e-4b5f84b5754mr102833691cf.76.1757344953154;
        Mon, 08 Sep 2025 08:22:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuzQmzs2vYk4JsTRb3wD0T53BpDxIk3xnONzfLP0Vaiw==
Received: by 2002:a05:622a:1893:b0:4b5:dc6e:c1df with SMTP id
 d75a77b69052e-4b5eaa1a582ls71494891cf.2.-pod-prod-07-us; Mon, 08 Sep 2025
 08:22:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmsAAr1KKjLDjJ0SbwcNeVbxu4LhXffgvfC066MX0lJQGrm3cBscCQnf4Mp6yUWEhnZBm+HR6AIa4=@googlegroups.com
X-Received: by 2002:a05:620a:6494:b0:814:5d2f:6fc with SMTP id af79cd13be357-8145d2f08d7mr587187885a.66.1757344951351;
        Mon, 08 Sep 2025 08:22:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344951; cv=none;
        d=google.com; s=arc-20240605;
        b=IcUJlhRVFi4OGmeOEQPhODe8nQwE/RTMc6DW4AzCGOP/mPIGpgQDEuxz3AuQVhnN4h
         9O1Cv5X/Wm0z+r/scffJJgyrG9SeQoNM/mFm71rvIOhtj7yjFkcbzfyDegenO5iPfreK
         iHzGmxZKz95DyejU+1HJgKuYgZsozLamL3JgRab6lGOUo19pwdqcflUgrxKZqHuQTxr8
         MHt1fbmJsrP06am9KlusvCEUaWe50Uik5t01up4JFwsLHPRIg39uFYVPf5B65deHYZCa
         clap69x4hN52bLYRKQaX9GlhtjPQnrFLFBXKq+CVwRlL2gw/iJieX9gv/O/beazDCmnf
         Zj1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=w4KMjz9pZf6Gn5SDTmwCP/agoyxxfuBiYUtMKRyfuzo=;
        fh=Bt/GeF2C6JUTO87Sui6ACaC8WdoLoUJs9XcP2IBot3Q=;
        b=ESOfd0rkORqmyPKQu1hKxtr9U7Ro133Jet150HO69XtM9/fKCtajTe70LtTnNhKiPT
         jvhRckjP53tJH1YU+CyQ+dMZjQwIhvy85NymlSJ5bAi+TyFXFxlaL/7zY3zwJvzcOryO
         diNRbXakCW94eGlODsi3W1X+1ThIIJAlDbNk+J5O+QPoTaPZn4MZ0/8UKK0LjBsZt1sa
         lTwsSSp5iiGSEyZgMjSz7lIPPw+K45E+c3z9Lf+KvoPh21kZSaAfVQr+a+ArSR3lKZaM
         Vhgp9+s8AUODUN++RF1w56uGlH8q4zcwpqJHqWg6vsGfxWzpbpvPM1yNCVOnwWiKqKBk
         +Cag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Q1gHV7iQ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa9e926e9si56340585a.5.2025.09.08.08.22.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:22:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-379-d6vG3uPrOj6rozxW6kGDmg-1; Mon, 08 Sep 2025 11:22:30 -0400
X-MC-Unique: d6vG3uPrOj6rozxW6kGDmg-1
X-Mimecast-MFC-AGG-ID: d6vG3uPrOj6rozxW6kGDmg_1757344948
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45dde353979so12497305e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:22:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPvm8RA2pLHc5eseDnk0VMO7wxdcxVcPP5qTyIFYc2n2eeh/Ttue3mvJsr2rMAJuglRvJt5fNwWHY=@googlegroups.com
X-Gm-Gg: ASbGncvlXsTv1KF1bbI8flbXkZHM/mPa08hsyRbw1CBz7e8662C5LvkHaEcWR2jxGNU
	haqkWFtD6Uty8vPZlM9nCGw1cfJDQf6mmiLwy3O8IOUr/VCj6sOYXumRGkxTD7L6ILf4gBzdbji
	uxcM4eHQw+79Rmhas4R1dJ9E30LLScFJEBCRxDI5gP+BrJEhQuCBh5K46V11Cb7a5Wt6JpiHCqV
	J1ZPnu+IQs8BtUtXzTFH9+vPXnvPSgyU2X7hBR/173RSbR81C9x9/vvLIPbmA3Nax4sNVtW7Nww
	GV9jg3JyWW9eUBmqMCvfra1dg0ch76GTf+OEGugHaiP+2XAKCp2xzSkVnQB8VxjgxURGeCJNfXp
	n6iehrqOuhCOyRmXms/B4vdniU2mmL9PdWGFmafGPlDk81XaQXEDQDF4jkhSwc0I9
X-Received: by 2002:a05:600c:34cb:b0:45d:e0cf:41c9 with SMTP id 5b1f17b1804b1-45de0cf447fmr65100915e9.22.1757344947792;
        Mon, 08 Sep 2025 08:22:27 -0700 (PDT)
X-Received: by 2002:a05:600c:34cb:b0:45d:e0cf:41c9 with SMTP id 5b1f17b1804b1-45de0cf447fmr65100515e9.22.1757344947304;
        Mon, 08 Sep 2025 08:22:27 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf276d5e5fsm42252142f8f.27.2025.09.08.08.22.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:22:26 -0700 (PDT)
Message-ID: <83d3ef61-abc7-458d-b6ea-20094eeff6cd@redhat.com>
Date: Mon, 8 Sep 2025 17:22:24 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: Mark Brown <broonie@kernel.org>
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
 <f5032553-9ec0-494c-8689-0e3a6a73853c@sirena.org.uk>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <f5032553-9ec0-494c-8689-0e3a6a73853c@sirena.org.uk>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: AdaAV1EXQvNslEudOjFAO2ZlRuwqC7XmxpKd5oHXr8M_1757344948
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Q1gHV7iQ;
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

On 08.09.25 17:16, Mark Brown wrote:
> On Mon, Sep 01, 2025 at 05:03:40PM +0200, David Hildenbrand wrote:
>> We can just cleanup the code by calculating the #refs earlier,
>> so we can just inline what remains of record_subpages().
>>
>> Calculate the number of references/pages ahead of times, and record them
>> only once all our tests passed.
> 
> I'm seeing failures in kselftest-mm in -next on at least Raspberry Pi 4
> and Orion O6 which bisect to this patch.  I'm seeing a NULL pointer
> dereference during the GUP test (which isn't actually doing anything as
> I'm just using a standard defconfig rather than one with the mm
> fragment):

On which -next label are you on? next-20250908 should no longer have 
that commit.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/83d3ef61-abc7-458d-b6ea-20094eeff6cd%40redhat.com.
