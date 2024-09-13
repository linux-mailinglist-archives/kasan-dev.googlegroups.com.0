Return-Path: <kasan-dev+bncBD22BAF5REGBBLPJSG3QMGQEIUHGT5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C17E978690
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 19:21:52 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-7d235d55c41sf1370887a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:21:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726248110; cv=pass;
        d=google.com; s=arc-20240605;
        b=TurrnHIzQfjLsCJ5e60nQnvQ3xu2IaIBVY7qaBXQpfw+wgLtYfHF/KuqfLYJLL5Z/l
         M52uSZTLK0OAKw2FEh60vxoNCQQisY3IqIRHclE34U1nrctxe6hxdr7pQDs6XBWNZyPN
         O9O9+VN3qSqgPEE39zCEzhhbroes2C2Lui8k5VuN+HbkLThsJpruRI1lytNaYsd01Omz
         i+gVYCbXlmwuip0qJzwlbFBnkZ5x8+wq17/tJoEi6r3Ah5vBTT+ZawXsMuzx4ixKyMGv
         XL9J5v31WWaCav6T0VK6d5Qof9zy/rgPYQcrMbdJ2GO1OWLjoj3vVPoHXF1oUiuEN4I/
         Bt5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=93sHltV7uCKSI7iD2oS69e8ODzHb2FUnv0xC+rY2tAk=;
        fh=j3eSH5hgOtZESRXsTSNp5/QuDny8gdj1gCIGp5DdpIQ=;
        b=TPTWHsiYBh5emrNpQvEW8HlWLC9ifXT4qZxDqs0NYrdYM4caRl3ulKWFMsXijpDkPS
         GaetfhK4qqgk2RiRILIzcrDT+ixWW798Ma1HV9BRR3n8ckrmlCt54i6sOKBEnwPbiSTf
         +YUqPItQ4l8cXoOO8sn+/hQg+wZi8QESUVTd6qO4oRkq57WdOFRdV3gBpz7fDn+Y7H/v
         6M+OnLMD8+NsUtcA2uy0R3l0wts08qfRnCGbt1vu4WSxniry3YgEFeyJeZIoX6Dt+Usg
         rwtFaEU8YbxJ+uhh9GgSPBqieE/fRb1b6dmfZjrG8N7716Is4A319SEYLbIswBz0NFJD
         K6EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AHIukaGe;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726248110; x=1726852910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=93sHltV7uCKSI7iD2oS69e8ODzHb2FUnv0xC+rY2tAk=;
        b=i8PXY/htguq8rYRegBP28ti2BU5HqC/lN5E5u0e0nrkWYx8rqcIBwHZLoLheEYUxzr
         nqp+BO9C6WYKZfy+hlMZ9wPQ3gsbBkQ4svS+TTOXAW8TWBELJpldQ68RFdjGCm3c92jw
         uaAK5xxFFvT2cjZVEH2vwfoEw7k5XndJbbkceOb4ElG5MRH8g0zJQwnPm8aCpyd8lyQV
         D+BuYxmaboflr5gTuUIIppNE3aPushohu3lKeNSj4h1UL+XXFH8BthOSM5Nlu/gPhk5A
         uScHXxpENJ9eh6CV3Iwpze+QnYeXyJh2rBgzcMzJe22YMJVvDizgZmeJcoWjn2nnfx8t
         +HNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726248110; x=1726852910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=93sHltV7uCKSI7iD2oS69e8ODzHb2FUnv0xC+rY2tAk=;
        b=ZvarfPQ/nT+X6yUfTu7TDST/p4M7oT8TyiRHFB75HE/aRk6/28cw83yzRldfpyIhqT
         JbaFEjjCCQh0moHZu1JIJdFeBcXUxFne3DgC63j5WAzHc+n/WBOAdVA/yIhMHkagKGHM
         aW3J6LfBGZDbcQuObvZK+2QgnkHlrcJsPOzs+ZgdcFye1jAzoTSI9L9jLlI/VvvVsF8N
         IrCZVrRY1osvm3KuNDHULHPs/rifu0GFU9xBjurvYqcvaXQE9moedGUxrhBnoSjDkYEX
         1Ci2JIBJpMVdpN/VKziqY07SlpC1YirGi4DMoG2RX4ZoTColzjwlI0eG9TxhfmRPXhXm
         PN0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUikMDXEnOCdrvFwaPhJdXJxhc9wgg2Q7Kwk7Gv9wrpVDZGk1bBruoZDWYa1vdpmlKPBIqbYQ==@lfdr.de
X-Gm-Message-State: AOJu0YwmRg6mlmFitcWhG/U2G5LEzLl3/Z6sKHXtDcnFnz4miqhwbOLu
	NMlSp3fbtod4F6ZbUak2mb09llVKFkNZg0SChG7Ej7FMAVlkhDSb
X-Google-Smtp-Source: AGHT+IFh68mO0aWQRFDft/FTMNhquh2U1yP61FKwMDAFCqVzxZVU66q3dnpPNv0FSdkDo9MBOkef0A==
X-Received: by 2002:a05:6a21:e85:b0:1d0:56b1:1ca5 with SMTP id adf61e73a8af0-1d112b32479mr4875574637.3.1726248110051;
        Fri, 13 Sep 2024 10:21:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4b43:b0:706:a89c:32b4 with SMTP id
 d2e1a72fcca58-71925850b67ls2104185b3a.0.-pod-prod-06-us; Fri, 13 Sep 2024
 10:21:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXT3CHqk8rxvyJF0ZNbtUSxhp8iwI5QZIe9E0pTKwXJRgZBUlrQ/AIHVyH8VLFSG+57ef36+TiMkug=@googlegroups.com
X-Received: by 2002:a05:6a21:4581:b0:1cf:3534:9146 with SMTP id adf61e73a8af0-1d112eb46a2mr4780976637.50.1726248108801;
        Fri, 13 Sep 2024 10:21:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726248108; cv=none;
        d=google.com; s=arc-20240605;
        b=Dxm8QZsLCOTohxjMig1TmzIiHHw2wRXCpG9X8waFs6Kw0NgdEcPNNpZFkkW//hKzH5
         411fvBdEnN4Ba6czdxHwsdBAdWLHLYLwlqa1fmXtLaE0wJNHR/iN2yyyzftHRYUbD/zC
         iRUc6HUEIq35XIcbTTxzGx7SPvCJMAxs9+SFkuxhb0TnMpRKQJIqi3CD0meCpyqZ9/lr
         2kydA7YdaBMS6ZsTgHtadLaKhr2ScvUKEl8OFwY89KypFHCQ7Sk5H4iRdnblOZwUpn7d
         yKZxb0nkdPpI+fGD6t1l3zOgmX18SX0iX0YIxteovQxYPp+iPCerr0aUFX8DqJEG2Zra
         v8pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=79/o/xeQuArc1/2zAHjCjM9ULnnYMrBSWHdVAhyawN4=;
        fh=tXzh43V/4wEM271HLFmmGi3ImKfYQIqg5vkzJknwMaE=;
        b=Vc0x7afAFa4UUyhN9I1Nk9v9bdrE56RLlmGfaSsI6dEb+OCr2dVIwgOQbzkkhGBWRM
         P8mPklDialwHR0vkeaUUXnwyY17lG99Ff4QP3cVgyUgyhstcr7YtuMGUFH4MPWMKO7Aw
         vshoQBEe5vr/yL7t8YiI6sRB9mYZryU3OfVTuF+UbuFnvrAGFE5XLuj399NDOtS2SjxW
         jwhjI1KT/jXyLHrrSmdNyz2gRlgcyP1UsrnsGbNkgu3ha80JgEpsolq1HCuDbrc7Mriq
         HkyNmGPpuNLqolVXQYRG9J+Molr0nfF5tzUpvqjflm5oSQmrs/LSR7YpNL7iXsQKvxij
         rQZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AHIukaGe;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7db1fbb31f3si252081a12.2.2024.09.13.10.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 13 Sep 2024 10:21:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: Mcb/OhCDSSuOtOe6q+1NbQ==
X-CSE-MsgGUID: PTyq6MG6QkW/0mCXMP6cJg==
X-IronPort-AV: E=McAfee;i="6700,10204,11194"; a="13515754"
X-IronPort-AV: E=Sophos;i="6.10,226,1719903600"; 
   d="scan'208";a="13515754"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Sep 2024 10:21:46 -0700
X-CSE-ConnectionGUID: pZq42LnVSmarDZKTdgSiuA==
X-CSE-MsgGUID: 8DBsX0MoQL+CuXku25so0g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,226,1719903600"; 
   d="scan'208";a="98978570"
Received: from ccbilbre-mobl3.amr.corp.intel.com (HELO [10.124.220.219]) ([10.124.220.219])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Sep 2024 10:21:45 -0700
Message-ID: <8e8a94d4-39fe-4c34-9f5d-5b347ca8fe9a@intel.com>
Date: Fri, 13 Sep 2024 10:21:24 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/7] x86/mm: Drop page table entry address output from
 pxd_ERROR()
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Ryan Roberts <ryan.roberts@arm.com>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-3-anshuman.khandual@arm.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20240913084433.1016256-3-anshuman.khandual@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=AHIukaGe;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as
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

On 9/13/24 01:44, Anshuman Khandual wrote:
> This drops page table entry address output from all pxd_ERROR() definitions
> which now matches with other architectures. This also prevents build issues
> while transitioning into pxdp_get() based page table entry accesses.

Could you be a _little_ more specific than "build issues"?  Is it that
you want to do:

 void pmd_clear_bad(pmd_t *pmd)
 {
-        pmd_ERROR(*pmd);
+        pmd_ERROR(pmdp_get(pmd));
         pmd_clear(pmd);
 }

But the pmd_ERROR() macro would expand that to:

	&pmdp_get(pmd)

which is nonsense?

Having the PTEs' kernel addresses _is_ handy, but I guess they're
scrambled on most end users' systems now and anybody that's actively
debugging can just use a kprobe or something to dump the pmd_clear_bad()
argument directly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8e8a94d4-39fe-4c34-9f5d-5b347ca8fe9a%40intel.com.
