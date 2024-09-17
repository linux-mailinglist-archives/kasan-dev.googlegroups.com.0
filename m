Return-Path: <kasan-dev+bncBC32535MUICBBJGRUW3QMGQEOKSCWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F00F397AFB8
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 13:31:49 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-277fff096f1sf2294992fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 04:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726572708; cv=pass;
        d=google.com; s=arc-20240605;
        b=DS9UDRLgK0mi6iW1LyQfOhhRp2SR0kUYWBpe84mltaFEJaxtNnzaP92bOHD1cEhUP+
         x8+jhQls+4p+eigq71GhCrUeiylb1mQ2Cxdh2e5kPi7KN8/MpfRRYn15CSoB10hiSufF
         XGM6WBp+3xY7QslKIWvs82/F931jcjRGUBrUJ76Ov60wfbvJjPkJrbJvDrHrwnUzfcuq
         eoVucXnB9V78wt2PNUj/gYh4ut4kSybJu4n5QXmIx04cHxNaI4QxYdDi3rQytMGIO7uX
         HuAtZEkAoVSmYHt1ooEq/Umxen3axLuVFXWRarK+oCz7bdA89qeH3KIvCeeJ6vPGgkAi
         VoBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=kQqQlHB8m4eC5NJ0RtcTHwEDLq/h78l1JnCIcBmN5AY=;
        fh=Ry+zN8U5u2+/N/LZ9Rq3kWxSieRfqDGs6GrKphECZdU=;
        b=bYQuGLNRL8wr4Qd2Nrq45us49R5FakYPbNwd5UvlGXbi+kULmBVP7dbNJb8dc94ZmL
         nmTbEPR1uHQvE3ctfRZsG/ItFUefdedWY/2L+jQLwBrIgtFmXAzFHQFZZoiTpn+gztcb
         PZk6W5QFu5XKjXNg7j8sEswZ+Smbk4uvr25eQAwd/H94KvsLImb01ghcIpvKKAVxlBsE
         iW9d/RHZ/YEhLM9uiP02i8yGZtsrers/KAranNdNZFrqCx/c8zUDlCOJTZXKLlDPMBha
         RIIGRSZYiXMarpF2XwRgqk7WB37hNDlb1f4gr8696gZizKTXXovB+0TJ4wNt/tW9yRyP
         zBnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f4iTh5Kw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726572708; x=1727177508; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kQqQlHB8m4eC5NJ0RtcTHwEDLq/h78l1JnCIcBmN5AY=;
        b=XZnJo6VKFMpOJNhTnI6Vn1l/RF0+J619NVsMYCU9bW8CHjBV4gCgwuLv1zOSA/WcMj
         yO06vL8ZwRu3K0voZCz+amgMH0pQ/nvaflBzMXBchkPJJTJewSZG2qzlHNQb0DgL+FzQ
         z1BwP3AUsEj3ZwVli19bMkIx4t3MRbs0LhUiWVoI7a7aA/yBKvYrGpM4pneezXiS3meC
         pGt+bWtwaZZQW+6qiip82BiBDmOtYM1TKJSCch/d4UT+zGoxugKZb0XAYDBMwlqELXNp
         YDowTE7hZaNTLrBuDq3iPzMJAI/Iu6AutdWuiKvw4Q2KA+xVZt+rF7TB5Mwl0g0WKB9w
         Ryow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726572708; x=1727177508;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kQqQlHB8m4eC5NJ0RtcTHwEDLq/h78l1JnCIcBmN5AY=;
        b=USc3E0iJgxjxGikTMEdTOQMuKweGZc29/XNPpQi936+qoEXhmSK0fCO6HTAKtbam58
         k968qeR5K8gWSGje3VUord83PGjEvsd+CLmLWbmD0kaZhGH1/6d5ZSfBCNa+Sgt15Ub+
         Qn786jmxRtG2VybBW1lLVauxe/D/w3Z/E93Fz5uyGubT8pwCKhc8xyslrOrTni6h++t1
         JJTNazeW4oL60CgwehNZMcrMz9U9uBICVsdVkhfRzl8IFx2p4x4ycmNoQw4h4dcFcXaV
         3+G6Nn4TONRKGNxU3xE1xii9O277/ww2F9DedqMsVPmM4YUnXKUyYmG60+huD+KqWar9
         kMTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVvtlLgM/Stvv52JpFkE6e4wfNfKGwChD77LG3nBCZmJT8Ko3rN71KtlU8QRDE4dJ5/TEFEA==@lfdr.de
X-Gm-Message-State: AOJu0YwjoeCakGUcb2Gz3BXG1oieubRyTLkzOaoOusGtgKLSnSecFPTf
	lEaq67HORgzlsxy/FoDI12TW8zqEN9XUOeQwNm8mAZqFFEty/ola
X-Google-Smtp-Source: AGHT+IEW14DNNUg1AEYrsMvPT9dnl7XAlgwtTrJK+YT/nqn+TKnd8Gp5jVlsu4AVLv/PaCiXQgtfHw==
X-Received: by 2002:a05:6871:1d6:b0:277:e2fb:4035 with SMTP id 586e51a60fabf-27c689dab3bmr9548675fac.27.1726572708540;
        Tue, 17 Sep 2024 04:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:280c:b0:277:de3a:8aab with SMTP id
 586e51a60fabf-27c3af699b0ls1166871fac.2.-pod-prod-04-us; Tue, 17 Sep 2024
 04:31:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrmZyHy6t6+bBec/RreIrEDP/Q/8pPzdRMzCwehaO8jARm9q0g8f3NyDKz8q3lXvY7tJ0YjsGB+1E=@googlegroups.com
X-Received: by 2002:a05:6871:24e3:b0:26c:64f8:d6c4 with SMTP id 586e51a60fabf-27c68bd62f0mr8023451fac.38.1726572707701;
        Tue, 17 Sep 2024 04:31:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726572707; cv=none;
        d=google.com; s=arc-20240605;
        b=EnMmyYfze/rkMy/Gc6GySF6E9S95vQld5dPqfGAKhshotxYw8ZkJumeevH1KBJcchG
         iA9DsYynpM38JDOSyNFNP+/x5xiYXpU/eDJtLy9tFXqMzR9pefGkm+uRyehPw6YUguCl
         K1jhDgUXvFnJQ7OsiHlXaOdhLVeJZC8MIscqNM+xg+AEhtnk+cEnaJNuilir1J9d2qg+
         7B+4YbETYi+RheP7iUMRmmap8Qlg5TdCrCKQJKm0bj+nz3JkUrEhgodTGFqG2FxRLRRn
         x0/BWUdlgJ3ij2OaMZCNSHRnYdkBPYCcEpmUywu79QrbCA1I8CboBl9q7xUtn1idbDM/
         OfKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=oul+0D/MDGitLa0XxGud62DDDYkyjjPr6iJYhvpm5HA=;
        fh=ZG+aLCEPibS0p5WV7n0vaZkU3pfx4uKz3TpKocHf1Y0=;
        b=fCdPiPUnce0x2UjRrtPMP7itBiU7oFBt9T2valMzCNP2kWdXCMtjMEAkTElFR9/kAB
         fgSFDGo5e7wqmgWHA9o/NqELmqlTq+GRMu1ZjdkfanbU67uVR1poiaViLeoPe9q4QOhV
         bCR8d0aWwb+907Iuure8REjRzkS9O8MdJ0D3wB30yilY0IPpbJ+SOEGF6888SzYJ/+zZ
         p67xQt4SdBOt+TPQ69J5dB0BWb2FZP28t839TpaXtAgFgjAxUX8ffoYDRxct6lEISmSs
         buLGcLNBp1EcDKBUyf4xhaQWjj8pdJBP1EDVaXBOzQV2NtkX7HeVbzpw7UGf1Qu+B4gk
         aoFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f4iTh5Kw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27c95b64b77si308217fac.5.2024.09.17.04.31.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 04:31:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lf1-f70.google.com (mail-lf1-f70.google.com
 [209.85.167.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-81-ry1zUxX4My60dLv5yj0-Cw-1; Tue, 17 Sep 2024 07:31:43 -0400
X-MC-Unique: ry1zUxX4My60dLv5yj0-Cw-1
Received: by mail-lf1-f70.google.com with SMTP id 2adb3069b0e04-535681e6f8eso2023860e87.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 04:31:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvi4KtV7LvtQTuwyVXEZyvpVykv9AnO+5cv6AIbyr7tF5/MAjioeiBdTaJjvUFHf+zuLDs1mih1IE=@googlegroups.com
X-Received: by 2002:a05:6512:1242:b0:533:448f:7632 with SMTP id 2adb3069b0e04-5367feba053mr7554874e87.1.1726572702221;
        Tue, 17 Sep 2024 04:31:42 -0700 (PDT)
X-Received: by 2002:a05:6512:1242:b0:533:448f:7632 with SMTP id 2adb3069b0e04-5367feba053mr7554843e87.1.1726572701637;
        Tue, 17 Sep 2024 04:31:41 -0700 (PDT)
Received: from [192.168.55.136] (tmo-067-108.customers.d1-online.com. [80.187.67.108])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5c42bb949bdsm3535380a12.84.2024.09.17.04.31.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 04:31:40 -0700 (PDT)
Message-ID: <5af75d55-f65d-4c3d-be85-402386ece04d@redhat.com>
Date: Tue, 17 Sep 2024 13:31:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: Dave Hansen <dave.hansen@intel.com>,
 Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-3-anshuman.khandual@arm.com>
 <c4fe25e3-9b03-483f-8322-3a17d1a6644a@redhat.com>
 <be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49@intel.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49@intel.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f4iTh5Kw;
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

On 17.09.24 13:19, Dave Hansen wrote:
> On 9/17/24 03:22, David Hildenbrand wrote:
>> Not a big fan of all these "bad PTE" thingies ...
> 
> In general?

In general, after I learned that pmd_bad() fires on perfectly fine 
pmd_large() entries, which makes things like pmd_none_or_clear_bad() 
absolutely dangerous to use in code where we could have THPs ...

Consequently, we stopped using them in THP code, so what's the whole 
point of having them ...

> 
> Or not a big fan of the fact that every architecture has their own
> (mostly) copied-and-pasted set?

Well, that most certainly as well :)

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5af75d55-f65d-4c3d-be85-402386ece04d%40redhat.com.
