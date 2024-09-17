Return-Path: <kasan-dev+bncBC32535MUICBBC5RUW3QMGQEYMCXUKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C08FC97AEA9
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 12:23:09 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-7cf58491fe9sf4066840a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 03:23:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726568588; cv=pass;
        d=google.com; s=arc-20240605;
        b=DOzzfYlNcwLFq3AUycPJwKndBOmrwLmsWdNxf62x2xRswemAFE8Zk2DIyzMrNd6EWj
         xl1EQleJSWpYCEnnQfaoeLp5+HzcJuI0CfaMiSd39CvdByPPpNWxg/BonNkB3UA7HZYo
         +A0xpp5R3fay3VgXQwJyYhxu8tLmIKgPlMEQHskNovB+DR0jq/o4UUyRIuObH4YzJ3tI
         4M4usYus2ERt15ge1aPB/+9lHHLf7UMY/yAHFVGfv5eOzVW3s6jKJqMhJCgmWill3xny
         6rWCZqn5zKkk3QT6F8DnExek/4cDCe1pv2jcO9/LwFeBSskcy2S0Y6RzqLpJyRsOXEqr
         AZAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=aYLmjXjk4AKmGWTqJIO8hZ4sg1ikpl/uYLLVkh9VUiA=;
        fh=jFnAMKFuck6mV7HdEnV5b5cNqTQm9NY6Z27Ou/F5Dsw=;
        b=GYIAiZLtRl2W9aEvC4GZN7L7In4cZh1a9xoHKM9pHfLf8uiC2ttt155fAsZikPug+S
         n3txYG1dXLE64pZjJGnkjhMGWbfgPG8GVI2eOtQmNpzykAK9/aEIrfqmql6QRKAdPYyD
         LKcpxEp/GnMTUwV+zpOrJRctTSBLNhLOv0oXlTco9fzcxilhoiRjI6TusFjgi0iYTEwg
         5UtMxDVxZtNsMTeza7BtWjedecAmr1OFkhoFxh9vjUwNU9ZeTY5MVVAmQfq60g461E0p
         vmAEEWX8wetvTaQmLkL++HnJwMkFxWypYmVE90IcHs1T2vBfBwqYpJfhUquTeNDop2aR
         /rXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RD7cqE4L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726568588; x=1727173388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aYLmjXjk4AKmGWTqJIO8hZ4sg1ikpl/uYLLVkh9VUiA=;
        b=Dyz4QjmTn0diHzk/LJgQ+B8SxpweXkTA3xMWPZq+ee+yxE99Bnr/hb6LQ6BwOQI9DB
         CdYMneR92aigEddwU8myFEf+2GAsY7pckxcFyZep6Nb9weS3oL2S4XlaaJ/f5W+r6UVQ
         RZ2M59nPfMuRdN2Af+2HeFg71Lk2boiphRowjk6fojb2xSI/SG7T+GqFdWDPEtQs41EF
         FWyv1wkOrSmsH2SgSGYE9n4yfgGPF/1kui4AcdhegObwE4cT6kOsFMbgwqgsbqo3EfPs
         cR83rEIAaBVghw7a63rc1r9ojMiPzYaqjj0PRLvoqO/yG0m+AhOOhZI2eCsYc1Gz4Woi
         nJgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726568588; x=1727173388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aYLmjXjk4AKmGWTqJIO8hZ4sg1ikpl/uYLLVkh9VUiA=;
        b=Bl+aYAJnugtCiJZIrM0VKaN3EiY1HEy/Gqwt2zuyZ1gPR0Y8Vdf1xHqik3exXYYt0y
         9+omOrWgaCdIrk74aK18dppg8/1KsCDKCVgljJxZPUs7hnWEX9rGsgT2w0vOhzn/RpJx
         NnOf5VV31PrF3Ql8MwUV50vZ8QmVxGNVo267zjvsuIXWyy2FxC3beCqGhcHUOqITKmbT
         u0Y2ZXJcrWzUtxeLoV6aZIQv2FRWa21Jqxg3sXUVePIsV73hBZScK6ve9iyyNBHOxt5S
         tFQnLsNbwvEQgiyu6Knyn/HfCJYK8Teunh/7kbnYbBcNPKK73Q7lhjCikpWQRvmhYvp2
         y0Vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKWVDZKqkqct9K1LF+L0FyQx4oYRMS8K+OWIT8HzjXBK1ST+h4S71CaQhJme2VyGsUHhvSwg==@lfdr.de
X-Gm-Message-State: AOJu0YzBZIxB/8CL4CkF+tAFgoHGXXFKkG70tdtCuSufixBIdRCbh1bZ
	Tn0NX+7K4CVXVtoaJw9sA0uyciQMOuY1BfNoTImiba4KfjaWUPGd
X-Google-Smtp-Source: AGHT+IG5P4eRYUpR1rSTIaGgsA8qrGpfaRAtwt8xvzZuA7XV4LvaSt8+xMQBBy9oLacQd9/ontW/lg==
X-Received: by 2002:a05:6a20:43a0:b0:1cf:6c64:f924 with SMTP id adf61e73a8af0-1d112e8bff8mr23869580637.38.1726568588135;
        Tue, 17 Sep 2024 03:23:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a8e:b0:714:37ec:7afa with SMTP id
 d2e1a72fcca58-719259e7919ls4483996b3a.1.-pod-prod-05-us; Tue, 17 Sep 2024
 03:23:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAkxdFuekJUSEhbaF10O+w1hiA2MmKet8I4h3AmSyyDkUXN82MGiE1gnXh2MHjZ1dBwZKPC4YmfSs=@googlegroups.com
X-Received: by 2002:a05:6a20:b40b:b0:1cf:4624:7f42 with SMTP id adf61e73a8af0-1d112b6503fmr22970996637.16.1726568586849;
        Tue, 17 Sep 2024 03:23:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726568586; cv=none;
        d=google.com; s=arc-20240605;
        b=DwsbnTB9ma3bFbyqEF1F7j9IDcS9Llo/HPJBZSc/iYPiaJTW6YHjTQB+Z5T0xPT2WC
         uxpZcJXpLjDxKk3YJj1X9zecjIABaH+FgHX7bcUZx7v8aPwu3Zs6sNhowiTzg6d2JOZn
         276K1NQ9zgZhHMuvSBNWHUhOZtJumcil2x02lkRlu7GJflNvet9EJsUzzlWerpabB6fY
         /agxHicBPYWSJ43uq9OUErfrSDvyIn3D0RkheSsu0oB72yhei0CQFR/Vq6TtWxe+vC8w
         HS2BcQQzBo0Y5exc6Y+dFJyCRFFv/JQkQu0sMd6mGeoLOCsYxfiR2DznyTa9hjfqY8m8
         Cbzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Ydd/x8z/rWdB1y1aNRkIvJ800tcht5bmAGltsT132Qk=;
        fh=gllIrPhtwYlGJzFA8QAvmFVUXeqU1KsR87F2vyzvSRc=;
        b=M+x218XYyr0PpLtC550YHWTELByAT34mNRbKxEesHM+10xfp5MnD23PTvnBlTDOyHE
         rqd6fyEDCw/wgIwtFHFb7EikW4+eWdIVkY7GqtNjipuMvku5FvIJxhSFuHzCMBo3IMvs
         gHqusTi8lzI7NqxhEyrylqlmiAaZCzPF8A9oWzTs5ivcddgEeA8MJU4xVr1cLI/jj+pD
         re/AYk+5ZtmoJMkt7tNny63tmZbFUyMFSZPh139ENs9ZLwFVKZbtDJQD0FNsdQ2sXLIB
         vfnXPVKEokQBl+AWVk7lJFJ2l6qcWHJjiOjIDurm+yNom1sLK3z98h36UEyhhSHpqxf4
         K0TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RD7cqE4L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-719449b29f9si239207b3a.0.2024.09.17.03.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 03:23:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com
 [209.85.208.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-279-s9KS2Z_pPGWRVh_Rrmf-Fg-1; Tue, 17 Sep 2024 06:23:02 -0400
X-MC-Unique: s9KS2Z_pPGWRVh_Rrmf-Fg-1
Received: by mail-ed1-f72.google.com with SMTP id 4fb4d7f45d1cf-5c40e8678bfso4332683a12.0
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 03:23:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUB9oWz+Z4ewthgzIUTpsruuzfh3FStps+jmXmSF6mYKNPOgNHANqikhhDixGIOgnQ2qmLodg9FC2M=@googlegroups.com
X-Received: by 2002:a05:6402:354a:b0:5c2:439e:d6d6 with SMTP id 4fb4d7f45d1cf-5c413e117ebmr17061211a12.11.1726568581559;
        Tue, 17 Sep 2024 03:23:01 -0700 (PDT)
X-Received: by 2002:a05:6402:354a:b0:5c2:439e:d6d6 with SMTP id 4fb4d7f45d1cf-5c413e117ebmr17061190a12.11.1726568581014;
        Tue, 17 Sep 2024 03:23:01 -0700 (PDT)
Received: from [192.168.55.136] (tmo-067-108.customers.d1-online.com. [80.187.67.108])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5c42bb5fce9sm3504885a12.56.2024.09.17.03.22.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 03:23:00 -0700 (PDT)
Message-ID: <c4fe25e3-9b03-483f-8322-3a17d1a6644a@redhat.com>
Date: Tue, 17 Sep 2024 12:22:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
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
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240917073117.1531207-3-anshuman.khandual@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RD7cqE4L;
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

On 17.09.24 09:31, Anshuman Khandual wrote:
> This drops page table entry address output from all pxd_ERROR() definitions
> which now matches with other architectures. This also prevents build issues
> while transitioning into pxdp_get() based page table entry accesses.
> 
> The mentioned build error is caused with changed macros pxd_ERROR() ends up
> doing &pxdp_get(pxd) which does not make sense and generates "error: lvalue
> required as unary '&' operand" warning.
> 
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Dave Hansen <dave.hansen@linux.intel.com>
> Cc: x86@kernel.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---

Not a big fan of all these "bad PTE" thingies ...

Acked-by: David Hildenbrand <david@redhat.com>

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4fe25e3-9b03-483f-8322-3a17d1a6644a%40redhat.com.
