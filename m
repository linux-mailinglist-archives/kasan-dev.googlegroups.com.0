Return-Path: <kasan-dev+bncBC32535MUICBB4UNWWUAMGQESHWUH4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EBCEC7AAAB9
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:49:07 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6bdb30c45f6sf2362697a34.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695368946; cv=pass;
        d=google.com; s=arc-20160816;
        b=YH1s/X8jd+XAifen8mPQ3GiY95TFToDkL25NOt9c8vbR/jWmhxiMOjzxqDgUQn5TLS
         NUHuCkOi4k705dKXv7JFwyU04NBVaNH2u9fQSGuWEr1SbPWUga5Kxymz32k6IyWwu2hX
         iDx6Pp7Ec1t/4EPmgvdvYDe7jDu6FC6ungbhdQJLqlQ+Fr6z2BiXazfPlZCVy7ysA/nl
         J5PCPf6Nyp5BeCojTdEDlWS7IKGCXpAuKPEWHD7jRMpVuYA9nyQE1Bt1UblYl3ylnF47
         5kBzs8awqiGLFsaA+kviGwa6o4oYKd4u6DWdgKRgHUKr97g898LXHKtJtBqCXL08wrVX
         Q2Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=IFS0rZQsJrG2RZOifNO6sPe1H0M8OnpScsWiqM+pyQA=;
        fh=ZFMRVDpVgWAupkSR2uad0L0H+cb1+ssgUTt0E3blSX4=;
        b=Ml+MA6DKh38pNyfHSyJuszHEpSQe2KeAS+YGA3UVcdRbyYsC4JWNXzRD4EGHhRrQ/o
         FTnm4lKFuLD6o5g5oAjX8r8faUO06wVc4598bWtblJfVUDoebE7b7sVSq1uZ+FhFPnXn
         wK2GsNZ38RC/wtxx2fIBuTnugFveoFBgvCovlHZVJb9StyvGYHpsRT64Vt+H+5IR15e4
         Fa77V710bWMee5AqDcOvnUpllNytozNnPk454xn1YFA2HWiqnpubeXZ/u8F2WPUkA6NT
         EwourooXFcKM5qLwR9oSvRkcUrUoIWfG3lsQ0CYHF/PnVWwebB3gnP1oj1X0w9DwdI76
         3IQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iWCkoFqu;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695368946; x=1695973746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IFS0rZQsJrG2RZOifNO6sPe1H0M8OnpScsWiqM+pyQA=;
        b=gld48bangGwzVjCHHK3jbwnxEhAed6AORpXn1O86Ru6s/59WEzVjo3vEjgb4D8mRco
         fO4qG3cQUOZXxv4TuwQVSAd5xJtcSjJLPrPVyUtuCJDbC0T2VXPKbeQm5t1/CHq4VSP9
         V+v3fYat1AXVta2xJH7qgj3G9V/pNEtP+K4VYWBd4VSMhD1b0H9zhceGtp9aV4bVXixE
         DGKV0N4d6Zd4W1ooEolc6s+EDBMkXvHZrsMiUxQo+La7h7RKKQkHGSpKPTYFV4DpoHiD
         DbcCtsIAu/kD2+KX+ZOjdxnfOPijU19UyVHU24HbLmsaRfIHqvOmkYydp1xFpv/XXZJD
         178A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695368946; x=1695973746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IFS0rZQsJrG2RZOifNO6sPe1H0M8OnpScsWiqM+pyQA=;
        b=t3GL9cX06UomqjlIse7vO5qQlvP+mrp6Yt6DCiPiNmHuU8qGJD3yWwx9xJKwik7JXp
         xNVghjpoe8jPZDu29Y6Iiq9Qdslt6jVSCidYaLXXOviVPwkceRNLulVx8ZYigAMwktpD
         xaWl6Xh21Pkg5bgi7kiqW1H5P8VKz004uNqJgC6rKKTc2LPf16YnDhW3IFugqgmg3OQU
         4IAJLwXDMoiRk6ESgdrmlTgk57Obuy5CISl6FIZm/xt9HgPpY/WLqgNnZYt53xsFSUG7
         sGxwkcCX2FEjf6MpkalNXjW0B1DtApm1Xoegcc+PrK/9WxUDr/a4S+xTvLgALPFqFQ6z
         w7OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxVcqEpcbUB4T6CRzuQUkmfuM3QzBxtCgGqvaPnxlD31wWp0cwH
	GiaI+ALodK/OVl5eJhypxqQ=
X-Google-Smtp-Source: AGHT+IFvUMuXBgseJFyfBOfKxgNOAFTc3cVo3z/fZNomiOI/DAAxPr2kxSOOdfAxMiAKX/0MqoYoYg==
X-Received: by 2002:a9d:6b09:0:b0:6bf:df:66d5 with SMTP id g9-20020a9d6b09000000b006bf00df66d5mr7261970otp.35.1695368946542;
        Fri, 22 Sep 2023 00:49:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2c46:0:b0:571:23ad:3b20 with SMTP id o67-20020a4a2c46000000b0057123ad3b20ls803283ooo.1.-pod-prod-07-us;
 Fri, 22 Sep 2023 00:49:05 -0700 (PDT)
X-Received: by 2002:a05:6830:1054:b0:6b9:68fb:5a28 with SMTP id b20-20020a056830105400b006b968fb5a28mr7743016otp.27.1695368945507;
        Fri, 22 Sep 2023 00:49:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695368945; cv=none;
        d=google.com; s=arc-20160816;
        b=jQdXmAGkPpLh1PxspaUznzWuJ9MWG9ZkDfb9tzBrL798sadp4JuutA+c69Egk/N4SO
         FLYQ2NQwrUJVyrTaExG3OIQ2Spt6uEftJkTOAadKtUFKLAZ2mGfb85anWPQjI5oORhVO
         n6VBjTiWhYiK48Vj408BGor4592D8vFLXvdg847GshsAAxpRG/Ev/wBW5+zzm1axunzH
         wJtdgIrdSe8vHXuxGVaRxMtbf+E/s6d/MBuTRH6z5tq1KQdDS9RnQUxjjvev72pPBOYj
         AUW2+l8gXasDRI81nk9CdyGKz58G/B+T9FaIFmAFgWmuxZtXyGgvE4EfyI8a9BPRngC+
         HVFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=mUrChINedqPMXcgm7a4g3Fw1rlxjkk+Lujf8OPdqplc=;
        fh=ZFMRVDpVgWAupkSR2uad0L0H+cb1+ssgUTt0E3blSX4=;
        b=Y/vu2SxPdVn9EYdqlFe6qUVZmV92soFIhDgFEHnfsQdknJ22X2JyT8UTiQ0kp6iwsq
         RXDB4eOXD5hVzRYQamQJWiBog1QtIpu4fBLNCxnDTLbJz0n+WkuYI9Q6IP0B+VKOhar8
         WaTabR+3PCGfYH4LEzLjySghwK3vMIfUHlM8PvLxRjweZJdfq5OD11+7pnAD0Qc+vtxn
         vvOzhfi5anyC/wOqIPkb/7ukkYDZ6cNHXiRVGcecPYIISEvbEh3y63vPvPriS4/wlVnl
         3Zc3xVXcB8uekO8BNtdRwld6/Ax7mFMYb/mLie/VnRIxfW5+6va0SRsmyuAAjloBTiJs
         z+8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iWCkoFqu;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id t63-20020a638142000000b00578e032733fsi352319pgd.5.2023.09.22.00.49.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:49:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-253-sj5szJaUMhK_OhB4i6Qisw-1; Fri, 22 Sep 2023 03:49:02 -0400
X-MC-Unique: sj5szJaUMhK_OhB4i6Qisw-1
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-317d5b38194so143424f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 22 Sep 2023 00:49:02 -0700 (PDT)
X-Received: by 2002:a5d:5966:0:b0:313:e391:e492 with SMTP id e38-20020a5d5966000000b00313e391e492mr1358472wri.17.1695368941624;
        Fri, 22 Sep 2023 00:49:01 -0700 (PDT)
X-Received: by 2002:a5d:5966:0:b0:313:e391:e492 with SMTP id e38-20020a5d5966000000b00313e391e492mr1358452wri.17.1695368941281;
        Fri, 22 Sep 2023 00:49:01 -0700 (PDT)
Received: from ?IPV6:2003:cb:c71a:7100:dfaf:df8b:54b9:7303? (p200300cbc71a7100dfafdf8b54b97303.dip0.t-ipconnect.de. [2003:cb:c71a:7100:dfaf:df8b:54b9:7303])
        by smtp.gmail.com with ESMTPSA id x17-20020a5d6b51000000b0031980294e9fsm3738383wrw.116.2023.09.22.00.49.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Sep 2023 00:49:00 -0700 (PDT)
Message-ID: <2ed9a6c5-bd36-9b9b-7022-34e7ae894f3a@redhat.com>
Date: Fri, 22 Sep 2023 09:48:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH 1/4] mm: pass set_count and set_reserved to
 __init_single_page
To: Matthew Wilcox <willy@infradead.org>, Yajun Deng <yajun.deng@linux.dev>
Cc: akpm@linux-foundation.org, mike.kravetz@oracle.com,
 muchun.song@linux.dev, glider@google.com, elver@google.com,
 dvyukov@google.com, rppt@kernel.org, osalvador@suse.de, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20230922070923.355656-1-yajun.deng@linux.dev>
 <20230922070923.355656-2-yajun.deng@linux.dev>
 <ZQ1Gg533lODfqvWd@casper.infradead.org>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <ZQ1Gg533lODfqvWd@casper.infradead.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iWCkoFqu;
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

On 22.09.23 09:47, Matthew Wilcox wrote:
> On Fri, Sep 22, 2023 at 03:09:20PM +0800, Yajun Deng wrote:
>> -		__init_single_page(page, pfn, zone, nid);
>> +		__init_single_page(page, pfn, zone, nid, true, false);
> 
> So Linus has just had a big rant about not doing bool flags to
> functions.  And in particular _multiple_ bool flags to functions.
> 
> ie this should be:
> 
> #define INIT_PAGE_COUNT		(1 << 0)
> #define INIT_PAGE_RESERVED	(1 << 1)
> 
> 		__init_single_page(page, pfn, zone, nid, INIT_PAGE_COUNT);
> 
> or something similar.
> 
> I have no judgement on the merits of this patch so far.  Do you have
> performance numbers for each of these patches?  Some of them seem quite
> unlikely to actually help, at least on a machine which is constrained
> by cacheline fetches.

The last patch contains

before:
node 0 deferred pages initialised in 78ms

after:
node 0 deferred pages initialised in 72ms

Not earth-shattering :D Maybe with much bigger machines relevant?

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2ed9a6c5-bd36-9b9b-7022-34e7ae894f3a%40redhat.com.
