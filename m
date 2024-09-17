Return-Path: <kasan-dev+bncBD22BAF5REGBBNOLUW3QMGQEH7U64UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F20B297AF98
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 13:19:18 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-82cfa70028fsf917603739f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 04:19:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726571957; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lq7ZwfuYPnfmPWVJAC1pqEEH9t5erPQ8tCL3AG5E7uTU0OisrUxhnPLyyf5R7P0Q/k
         gY8LVmdzBJkHRS7VUzOOYfQklwLm8m9oPKMT+VbPHlBcyLSa0m+dajIp5F8NVuXBZMbp
         KWxOCR5w2mRG07cJqY0Wa1TKRr614VJIscVQ+1NRoslUGNzs50+TFYIxsLLcrmpwzOAH
         OU7MEufsFkmAFGOsxsxtK2cakaT/d8nmT91zF9iB3q9DqlMllDFZkyMjBA6Fdw1qf+Eq
         UER5MEqov59U27f+Chcx11898WrTsD6DAxZCukjsZyPFtBfobn4a5aJImq0ePG94uYXV
         deEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=Fn+WXL7ndEJEYp4JE/wU+wE8MWQPq8tjDLn0KMyOdks=;
        fh=RFGu4pImRWYz8esxUdL+xwfGgZCEwd7wDAZTYqZsdSs=;
        b=jdA1E60KeGqjc8Ft21jU8UQiQGpkmPJiMWN1OzIO+IcdnXv/z617S5iJlygTx2QZfd
         uO3GUeVIfi7PLoKQsgP5dSh6h+FjGkCEcwdgqPOQgcF07jdir+x0qjd46wncaap9NVZV
         wJzNcqbO2lU6wmD6LLbk4GWo8C4pz4/07LOh7bk9I5Iw8WLXG+eZMLN/8LZqS4qVqw6e
         OhcTcvxEeuZEZjIPoBNOWEJsOv7BjtmqVt2Lg2tz6lBH6vcjrFbQwDLvICg42949xba5
         T+csFeJgxXI2MowMqf+MnJLFsBAhraHnbA+XPc1BOcba2DQyR46/2NC9QnrJaFIdqza+
         7ssA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ejWdcGCm;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726571957; x=1727176757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Fn+WXL7ndEJEYp4JE/wU+wE8MWQPq8tjDLn0KMyOdks=;
        b=eEjwaUZo53MQDtYd/uLSnd85N4bbX9chi2NdKPXr2OGDexN1D+eT1NIiJ25i2OsLdY
         9C0pheQamrO0Ch18FQs+Ute23S0tT10zHcDn+7Sl+Fe7RNPcGaEIvnRYMPp/it0uOJUZ
         /dnpOsArsEhdXoWDl0ARXpiP8lLVBsRlq82PMJrvC6AVTfPBT+LK4SzM+ObWYZhpaFs6
         0Mew3y+9DdL8486BNlg37zmhU18ZWqVZ7Te+l6gAF8bA7hw1y0vQk2TtebdvHwzLv9tG
         zU7DfUEXA6f5bWnh4Z0hnHicdKZN4hURor2tjbiA1X+ESHkHZ2x9L5U5oi9/OmPUyyJ3
         /klg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726571957; x=1727176757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Fn+WXL7ndEJEYp4JE/wU+wE8MWQPq8tjDLn0KMyOdks=;
        b=DBnRbhoKWQX35pCExrpqhV/gsTo5/sIAZwjcU5XQCbR2vFTtLWM8NYRM0PdoukTBk6
         7bq5bSAcMVCU//67/DCy8A32naj0TtqStTvLwnAkhaUvdxzDsilUOMNxh7QptJL97mJp
         yD9LLKyOTrBZvP9bnMbslEGtu7KYlEADzYKH163Dr2EMbt/MB+5PxL/RFxTgl7StZ3GF
         mbTNP6D3wqmkcsBVOiSA2Wv2OZZlUXqqqz7bJUw31vL8jBpK+6JYHjtDKk9TJIHuZNrx
         kFqdh9njDh+uvHefPc+6zqr/rKOi5C6KfdcwV6rxbDXl85grAvRr2K62n9fyTpT2kxRb
         M86A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3n9CstmWO4CYz8c3i5qLT0Wnpon4k0hm8o6/Kndav1El+tCcpFXGyXGY2uMIHcbrYbZKGoA==@lfdr.de
X-Gm-Message-State: AOJu0YwS0FokxdnPg462AJfP33x22JaIIEsPOAAAYs1T9OpO7ZZ9Rh9s
	BI3B7ds+09zkzSQi9R3oW3BkgWITYMCMm/PNEzHV/cuZFEXHRfY5
X-Google-Smtp-Source: AGHT+IGJHKVBXxit3vGt0HDg0FgHrhJ4wG0FfnQqJ6GI4yh5n08NK0idf9DSwxt7GxhNfSx0S2PSlw==
X-Received: by 2002:a05:6e02:16c9:b0:3a0:8e7c:b4ae with SMTP id e9e14a558f8ab-3a08e7cb62emr98729745ab.2.1726571957405;
        Tue, 17 Sep 2024 04:19:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:11a2:b0:3a0:99ea:845a with SMTP id
 e9e14a558f8ab-3a099ea8564ls137795ab.2.-pod-prod-00-us; Tue, 17 Sep 2024
 04:19:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxxpXUH+suXPTj7dt0y4gGpvg6jRdB6G6MFySjKphheKmWioVSZwEJaUGqgpXgIIr8/7cKo4pydqk=@googlegroups.com
X-Received: by 2002:a05:6e02:1a27:b0:39f:558f:dd8b with SMTP id e9e14a558f8ab-3a074c9928bmr182488875ab.12.1726571956645;
        Tue, 17 Sep 2024 04:19:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726571956; cv=none;
        d=google.com; s=arc-20240605;
        b=BFLJYCqjJGTYPKoWR5dNnE9gzj0oeiW/ntmNmIeUhxOps6nLYdkIg6E0yaa+jlI2Dc
         +As/bqXYnCa73/7HD52kICSIlNWkL443tNC8mABudbeHRARah4jhKbeCpVnly5mumUQu
         Bc+MZHavPuBL/9Xzg1taXk9CngySJQPfqCP+VphNAwy+5KtT4ogyqKbsFeed+laMU518
         T5dSbiZLSJlo5e4BoDZXQzlNxiGzElaMeVPpElQvSP3WVR3VJe260V+nNg6A/P5sCZgZ
         ZVknlHiqjCyPvR1FMtIwmBF4+hplhG9UykPiu7AqhbW0vGT5tcMhcNyYo6G28qd5+MQs
         2T7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=9c0r+SK6yFndixT3JCN6TZFvWJo6HS+B9/y/Mhtg7+A=;
        fh=jBiTzc91hwsGtUpTtND9KfzJYHLvwUTcsV5otc0Ms9I=;
        b=MzgRm2nWVxkDq0dncp/fyVHGyHHKSbWlGUPRLHZ+Bj+uM8LpQwECTuLOZ3B6VLsp3J
         iJC/jrUF25bZZAgUOAQ+3XVDtgWKIBPTRILk+cqWBNpdvpmZsxIGxsRM6yWZFt9Jeztb
         BmrhfUr3dTFH0Lv2U/Fmq9Os475mDVX0gIoaZoG/FoCxhLyZzT6xsb7tZ4HN5rzMRUKj
         PSp/6PlWEifTdg2atY07DtCbP4UbG9eCKhXoV7OrkvZp0vS3uEsqbTKeTXwUMhbQ40oX
         K8AZJT8FNNDVAgpcRAyH283KzE64/N1Wkf9cm56XiZtIWquWut2tB7FR1dxfmZ5pEfx7
         YiWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ejWdcGCm;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d37ea31746si251074173.1.2024.09.17.04.19.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 17 Sep 2024 04:19:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-CSE-ConnectionGUID: ZlVxttlGRP+6wSfmdHDO5g==
X-CSE-MsgGUID: Rd3YxMKHRlag1TmiT5f6lA==
X-IronPort-AV: E=McAfee;i="6700,10204,11197"; a="50833167"
X-IronPort-AV: E=Sophos;i="6.10,235,1719903600"; 
   d="scan'208";a="50833167"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2024 04:19:14 -0700
X-CSE-ConnectionGUID: xNdd4YEhRlS1ILkNUGMgsA==
X-CSE-MsgGUID: 01TQws4NTHq+/epabNaElw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,235,1719903600"; 
   d="scan'208";a="73982179"
Received: from fpallare-mobl3.ger.corp.intel.com (HELO [10.245.245.10]) ([10.245.245.10])
  by orviesa005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Sep 2024 04:19:10 -0700
Message-ID: <be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49@intel.com>
Date: Tue, 17 Sep 2024 04:19:00 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: David Hildenbrand <david@redhat.com>,
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
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <c4fe25e3-9b03-483f-8322-3a17d1a6644a@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ejWdcGCm;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 9/17/24 03:22, David Hildenbrand wrote:
> Not a big fan of all these "bad PTE" thingies ...

In general?

Or not a big fan of the fact that every architecture has their own
(mostly) copied-and-pasted set?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be3a44a3-7f33-4d6b-8348-ed6b8c3e7b49%40intel.com.
