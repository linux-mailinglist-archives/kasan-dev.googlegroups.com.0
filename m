Return-Path: <kasan-dev+bncBD22BAF5REGBBDEBRO2AMGQEAGGQSSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8933B91E2AB
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2024 16:43:26 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1face4419b8sf4970155ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 07:43:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719845005; cv=pass;
        d=google.com; s=arc-20160816;
        b=HfVQQng0Xel0HYRqqAkxc8y/+bQWTlwZIOrQEDqsmaWUN4UUBRz7YM8UyyZ8F7aKnN
         ePQaMDT6M+yGbUXeMXRnIFqOh/bz4ew5y0sdGjvM7iLbjvDpXb37bM5e827aziMVpWMn
         M0AKSr+dEsiGU4oH1aMK0dpAJ61EbT6bjAxgT7YubwdarllawOVf9xC3KWHvK+kzhq4E
         X70oADIJa4PDFIR+HWPHR1NKe4bRT6LlXrr6FPEh8CpBOQyse0sxzNkbyHBmQzSkS2i3
         jIlBkzJn7qLewlk9kYwdl17632YvfoYX/sjCAykSiPTjOdB/YN3bY2oCNbbvS+2cpF3P
         80OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=8BzyePTud6fVTEtLCgZx3BiaTt8bwpuqIjQhgngF4XU=;
        fh=KTDQTAbfHatBguVLFROE4uSTbzWB6+js55HLO9Ag2A4=;
        b=sI0Gn1aKECNdbMqmqaQpbdRkExYGLUiAdU9sJ9MRprT/oMQyiZ4+9GZst8rTLDZj/C
         eeGONqwN6F5WheYu0tDBszF1ZAvGsGAc81sNucxUMTiaAEWHBJsksJmgEe5FAMMA+vih
         7HbBteYwgoBrsHizji5XWVfsOjORN6O27uEX4W+6bb+bPuo23otLAOnDHw08eUnvhXmY
         PcqqMLQqgZUuuB1CWe2T6S6eXIIY8F6CAOu6K8ZGkGNJt+sM7Qokw62gzD+fV8r9UBuA
         sKN3FwRpk0f3o1BD6wTYLmAYomYT89feNKec5ZTwY6678PpafB3IZt7w6gJ6KHg+eoy8
         EcMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CLdhSmTx;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719845005; x=1720449805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8BzyePTud6fVTEtLCgZx3BiaTt8bwpuqIjQhgngF4XU=;
        b=bNmuTNvKN5fyuD9wz9gJbSfs08mHIUrBrvfvCw8yptNmSTl5HKCQl+I2bMnab1i7O/
         4/zSYi6Rf4VDjPgSqUd5Lv3/W6BAeec/CEpClUeIHECUKOLHirKTVvM7V6bKTovzWOJ+
         G+bHFRIJbVfWwCrR+p6rGN7Ziazss53JJ0dRCTm2v0ecDRF8PdOSbNbJMGdIOtHBT2ut
         1HHpX8SE27UfhIJRxcVaE+5RqHX4I3eGh06tV14aieNhAmq4pk5kcEvNH/wugbqzalSu
         EJNu9z0YVlBX3hoKpM6Ebq2ZyuLFr9TZrOMS42PKJmjiyjUJmqVwunVix49bUebo782w
         X6nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719845005; x=1720449805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8BzyePTud6fVTEtLCgZx3BiaTt8bwpuqIjQhgngF4XU=;
        b=q6G+ferdJSiylPB5zhkf0Y5YFz9i7SJD1xLHSbMbSc+370Xs80dAkEn31fYxWGh/0G
         CYaNgJlUAEpjx2WwRQ+6J61CNcINN6ZdxCKy9L7V5es/XEjXCqVd2qCq7wG9Bm17kNs1
         awr82FTa9f2DAU/bPrglRp0LSkwqBM4LLo//CK2yxLGqkpe1rUe5mteoTqUIcwFxF2+d
         uGlvP3d7zns9MjNVychGIzaWeX/FcVRgvHQw9nW7iZ8V5ZfXIbPGqL+r/sMssGc6DHdo
         QL59qnUnj/Oxp6rFtG1cUnqPjqGZ9LZ/GHfvaxa82su8MGnHBtUjJ8+cVQMA6q3to7mm
         w/nA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWe4nal0sp/qlIGNwSQsNzub2aOwCEfc7Q5kNn3Pus3m5Tjr9JV+3/usg/0hnj/3VQp+PT5HV2zK4sDn4ddMQYGFuuUxD3jQ==
X-Gm-Message-State: AOJu0Yw1+pLOQBOfHk0F2n0hk9CBZpuDkaBvDqbvQGuw14uZZXyqlzNs
	9h0Jbw3HPDCel+Bw7cxdEC9/mc3wXLD1Nx1yNjDsq8++YL3gzpfe
X-Google-Smtp-Source: AGHT+IGnblsOhrd/VBuK8Ibkih8KHtAuJbCrc76UJ8cq11M+bFYS8F+JojSZnJ6Y3i8k/bgXtXGCZQ==
X-Received: by 2002:a17:903:294e:b0:1fa:9b24:c1d0 with SMTP id d9443c01a7336-1fad8162091mr5076165ad.8.1719845004857;
        Mon, 01 Jul 2024 07:43:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5ac5:0:b0:5c2:1c26:de10 with SMTP id 006d021491bc7-5c417ec24afls2081587eaf.1.-pod-prod-04-us;
 Mon, 01 Jul 2024 07:43:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwR7RtGZYLs6nkR1rpS13U36butmcmGWumWCpYGIFkr2lLwfPIhdumA2Zhw/GmUmiNzLzciyZINPS7ZDpl9WVBakDpK+VbxjZ5fw==
X-Received: by 2002:a4a:e1c3:0:b0:5c4:396d:dca8 with SMTP id 006d021491bc7-5c4396de055mr5246205eaf.0.1719845002383;
        Mon, 01 Jul 2024 07:43:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719845002; cv=none;
        d=google.com; s=arc-20160816;
        b=A6giVADudl+Buh69Zs4bj/KqToAtglSQOjj6meMZ5svheRW+s9caIX71pbXm27CNL1
         hl7g10jJiVNDP6PZDLAcqeI3xvlrABD/SoLcsq9sZMMGhDXrqm2/1XMeQqJYkJJQH9nQ
         NlMQ1mGigB2NHa7YdVsGznGLgVL2KyBGL/4uoE6GzEYSy192Y8opt4mx1xGnyxrLQEDj
         qrc9qr1jehFYT0fzdYm7IT8h8YJjv59bN1Q2WrrmQYvuopcrPV8o+NPUbMreNP7AFkxY
         +FuGWL0ThEcT5J44lW3tGb/3B6eUfnWLeGnNwi/MRG6aQ7FknGh1P+yYgoFGET4vKJwn
         qSQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=wyEmc0PMtltBIYS8EWszxEQa5QMIWo9IcYqQ6KPvzyI=;
        fh=kK0JR9utuTk5HzRkNM50cLutRmJB2ESL32HM03l3D+Q=;
        b=upcLiv0YT1RKzkMZtdCCLAaCuvokaiwE4OE0NYRsf4ZwgS14yIuwJ6LGm0icUt/XkZ
         41VQMvrGrZKMwE1U6oARUnR4LGPbcNddYgrXRK8mTshQZUzMSXaLW8eJmeVyyyYng5Wk
         t/10FpaXVBbGk+mlbmP4ATRWzVNypJyyZzp/0J53rCKr4GnVz7uIdXqWi+Sg1saGhbEP
         3vo90/+1qvRwo1CrTwZlepJWefX2knpStGn5WczoocCIF6/T6g1RDVEBfRGjqkLucK6f
         4H+wcV6uIs2nhgfbrwjDkTvZmnuXJ5PFQmeGHepgATVORTAFhznbW/XWX4Q5F+Pg5n0Q
         D/gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CLdhSmTx;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5c4149ccd64si237769eaf.2.2024.07.01.07.43.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 01 Jul 2024 07:43:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: n88VyDOsQfyzsJVoPO9CPQ==
X-CSE-MsgGUID: f9RhuwnDSUmxPlk6ToZuxA==
X-IronPort-AV: E=McAfee;i="6700,10204,11120"; a="27571872"
X-IronPort-AV: E=Sophos;i="6.09,176,1716274800"; 
   d="scan'208";a="27571872"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Jul 2024 07:43:20 -0700
X-CSE-ConnectionGUID: PDTDgxzeQMaW1EAg+NtB/Q==
X-CSE-MsgGUID: qRW8Z8hNT5WSfLwvtBc7OQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.09,176,1716274800"; 
   d="scan'208";a="76731148"
Received: from rchatre-mobl4.amr.corp.intel.com (HELO [10.125.111.36]) ([10.125.111.36])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Jul 2024 07:43:18 -0700
Message-ID: <33e838a0-dd84-48b2-b2d6-aea173ab8ced@intel.com>
Date: Fri, 21 Jun 2024 09:16:16 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com,
 peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20240621094901.1360454-2-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CLdhSmTx;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.11 as
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

On 6/21/24 02:49, Alexander Potapenko wrote:
>  config LOCK_DEBUGGING_SUPPORT
>  	bool
> -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
>  	default y

This kinda stinks.  It ends up doubling the amount of work that ks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/33e838a0-dd84-48b2-b2d6-aea173ab8ced%40intel.com.
