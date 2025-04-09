Return-Path: <kasan-dev+bncBD22BAF5REGBBFHZ3K7QMGQE5AV6KVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id B3FF0A82EAB
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 20:29:41 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-47693206d3bsf151694901cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 11:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744223380; cv=pass;
        d=google.com; s=arc-20240605;
        b=RZSla9FbfyU+mV309ZgvtOTKtrCtw0zgYwfLTgo3s1l5oT9jOLaF3uBIGand1GYN4x
         OPGNSgQQtQhD9P5fNsZp36PzmAr/nwKQYU7ywKB+yGKfni7IBWCpr4pMclM/cAUqFoGY
         Wo8exevL2yx/cUJEKv/NFbC17UwQBGT4lsoL7Ur4+QtZE6TPlQ8SeG/yWShNzCJElFPg
         bDJJz/gsE2ONvrYgdHfFM9UvGA3XDNsndICbhgsnWTizbyDkTnZT1/yQPxnjTxqfA4JJ
         sixwmaDns2RVDG2aBfIMJladaFUQSzvq+gXEc6h/QcF/H6qkksk/znQedflWaWaHgGwK
         oZxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=+iP0vYtR1dyoGADiJfv6WtllYpEu0wKlu/IVZTIfBEs=;
        fh=Nwhml7rdCQLYAv0hJ8bWuLB21X85B0V6VkRukuWMoq4=;
        b=lohj9aMqS0I3T/YeI9+hqzlHhmAiFRNC4gsuXrnxY5uxyjNwXJTD73Ga6nsePMzpUC
         KuTz8lhg8KgfgbcNlaZyQruCkz4fyhCEMzDhzhIhPIXbcjQ81gL5I2wrjWUoD+mLbXX5
         CfmKcJyRfNpE6NvNJOuf6Lx5QYM4vIYQvs5iRltpl3idreoPr+0EHct721ryQs9VBfKv
         TVp+UJ0WbvKw/zLTBQGCtTnFZipmS+WAHHW3lqnpqa3JxkkEeEitBC/iIfLJU7FwEwP0
         zW1Nb0NrMcBJCjvoTt40qeMTa2U5B0Ta29AzD08Zh6ADqGdo8V9p69VNGHM1gzUxvEvo
         Gt8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="fgc6B/+t";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744223380; x=1744828180; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+iP0vYtR1dyoGADiJfv6WtllYpEu0wKlu/IVZTIfBEs=;
        b=Tb3elJrH6YWN+X3qtStKvxtWM4VzzZGaS1bwkwhI4g4wzMmDy+a76bnxyqiVDRUB2n
         a2rYSmDPHaxacCuF+9v923GxRdLl/+JAU2qjZkZp1tHl5I9bd9eKfy6CeIxvOMCqZjTZ
         fQSOSWQUq1MYjJ6ClbbLEStp44ehuObdax4YBlDSRm40mJpbkvXtKaftupUUlS1vWnhT
         LpnYOI52f+7OUvx3++E1LGRD3NiEYWBx2GOB1+p5wjEMTOKEXR9+GpGKhODKawL76BVM
         qy+0zoD8SjKAErmTalVVdDHDNq/eHEHnCrmiQRHIQO/jsTEnNGe7RHVAMD4mlblz3f5s
         4x+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744223380; x=1744828180;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+iP0vYtR1dyoGADiJfv6WtllYpEu0wKlu/IVZTIfBEs=;
        b=ZvWYCmOb5V1yBFd4g8Jk4jCDRna0OHHdaAUVjFAZioLs/WGi15AZJ8xzVogbGVULst
         k9BLoDxcBU+H+Dz2BwIEpcERXhiJAzg6WR3FLcEsAwQOG3f2JMFzFlaWtmL34lPidM6q
         CKIRgJmDvi1WNzo/VGX48cXFQo7+Hm5LGW7ICWIEpKNLmNjNp+quOWRwDJrxqx19UxNk
         hfLWXHRmlFCLM2L8JRjdR6p5AwEHQFg4AR1O/vsuOhaUZE3uM6eNPas3w26CAcUvKk8J
         vg9x1K9G9lEDv+IKd/iVKq9EotBNo+r6JkjrDQcCWEbaeebM5jycJ/UCk1l1XHRVEyfe
         x+sQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLByvLC81rX3/ZcvhdkyJHQGfDQLfFbxSUWDQ+CbJi6Bj3E5VdPVMaRDbB43dBJdYhadmUww==@lfdr.de
X-Gm-Message-State: AOJu0YzLKyxzeyxmU8Op6gyb1Dkmq0IVKdaEemIMR8UlbnNMRNIirq/X
	JYqDT3WeQWWKE8o2i7KgERpCKK5rWBsbC41MX0TDKhLQ1B6kkRYB
X-Google-Smtp-Source: AGHT+IH+FGAmGRYuzuK7THQRgN4o0ccdA20dGauThg7D50FvnYUBf0Eic08NYfdMqeI2gPN4YdXCRQ==
X-Received: by 2002:ac8:5f8c:0:b0:476:964a:e32e with SMTP id d75a77b69052e-479600c1294mr44645901cf.29.1744223380573;
        Wed, 09 Apr 2025 11:29:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJlXNmiZyUkEKZYHof7kbsp23hIsA73d0BoTDrJKPvQzQ==
Received: by 2002:ac8:7d92:0:b0:477:1169:ecdf with SMTP id d75a77b69052e-4796b4fe12dls3291721cf.1.-pod-prod-06-us;
 Wed, 09 Apr 2025 11:29:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzvg1XgqQ5JLqQRIZO8n1PJTtVM9E9kJ8gYohEeh6q1of3NsePAzKp1s7f9u5YJk4FMa9Wh060SRU=@googlegroups.com
X-Received: by 2002:a05:622a:1995:b0:476:a967:b247 with SMTP id d75a77b69052e-479601570a5mr47116041cf.47.1744223377250;
        Wed, 09 Apr 2025 11:29:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744223377; cv=none;
        d=google.com; s=arc-20240605;
        b=eG6hFWEBybd7HFC010P6pdi/jfrLUuJ68CmVvw5wjsBvuQ6yCki/Ffx+kWoK8Td9MD
         qYsUUh+njKmLzqsZMUMh0gGLRDoFhrhli+3PokqWGo0kNekGdp3JRnw2lmYWSv1Dmwwh
         Zi6ODaAvMuZ4Hi0LThCoiSUHfIiSzN1/bb7SJTa4AEtlDNKl5fUOF8a/KC82uM45FnR/
         kucSWWdxM61FttqhpL77aIYXk1+N3e+aLiM4GCdlP6ATAfQ34hOsBY8QbiWDDmMseo/v
         +tXZc8S2haCROsW6+9bH+thEaIZrVeErSDtoeQ5NG+9hKOLHFQMCjsGLWjXdkiXNdUVe
         LMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=q/bqVqy224cGEX4Q+bGswtTw2+aFSSbBz2tPihS9H14=;
        fh=gGPVKbHUX2Omcvuc8J48EMglbdecp5b+AI6gox0GcQM=;
        b=A4jV/0qV+IuVlJjXF1jo64vvL72+Hr01XwlOEVMbTED8UsRMpm8jJ4NsbbAD5mHx0f
         531vaOdkUIsCq9U6Hvz4i2Z3TWSck63hu2dsSvXgX3j1Z6hx8t0Gj4MCvMqhmDHiq1th
         EBeqnFPwlfIvN5mN4B2egFRSfn/V7mJiSRm9Oi5ohSQ8MbksWKS6nTn47kEZGeykfa7K
         iXgL3OPn+03kCHasAeu1ivqYi/FFa5UsDufYwomhT8R37/NlVt+VY/LAVlCuw3xxLsg1
         HO8VsPd+vptKQDsboJNv6Fpnnm/4QdHJhp+EF6H/rKa18js3BXK1j2SJ26CCaqccdLOk
         DMoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="fgc6B/+t";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47964b97f46si898501cf.0.2025.04.09.11.29.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 09 Apr 2025 11:29:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: TViAxt3kRHqTTo2y/FuWzQ==
X-CSE-MsgGUID: mB+phb/LRx+WYS9Wp16ZYg==
X-IronPort-AV: E=McAfee;i="6700,10204,11399"; a="45429969"
X-IronPort-AV: E=Sophos;i="6.15,201,1739865600"; 
   d="scan'208";a="45429969"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 11:29:36 -0700
X-CSE-ConnectionGUID: OYu0cAbzScCswQ/sr0tt1w==
X-CSE-MsgGUID: Wx9F5wsaQd2PJHrJj+iwYg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,201,1739865600"; 
   d="scan'208";a="159629133"
Received: from sramkris-mobl1.amr.corp.intel.com (HELO [10.124.220.195]) ([10.124.220.195])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 11:29:32 -0700
Message-ID: <fe8192a9-02ba-40c9-9ba9-8582547cd3f4@intel.com>
Date: Wed, 9 Apr 2025 11:29:30 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 10/14] x86: Update the KASAN non-canonical hook
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: hpa@zytor.com, hch@infradead.org, nick.desaulniers+lkml@gmail.com,
 kuan-ying.lee@canonical.com, masahiroy@kernel.org,
 samuel.holland@sifive.com, mingo@redhat.com, corbet@lwn.net,
 ryabinin.a.a@gmail.com, guoweikang.kernel@gmail.com, jpoimboe@kernel.org,
 ardb@kernel.org, vincenzo.frascino@arm.com, glider@google.com,
 kirill.shutemov@linux.intel.com, apopple@nvidia.com,
 samitolvanen@google.com, kaleshsingh@google.com, jgross@suse.com,
 andreyknvl@gmail.com, scott@os.amperecomputing.com, tony.luck@intel.com,
 dvyukov@google.com, pasha.tatashin@soleen.com, ziy@nvidia.com,
 broonie@kernel.org, gatlin.newhouse@gmail.com, jackmanb@google.com,
 wangkefeng.wang@huawei.com, thiago.bauermann@linaro.org, tglx@linutronix.de,
 kees@kernel.org, akpm@linux-foundation.org, jason.andryuk@amd.com,
 snovitoll@gmail.com, xin@zytor.com, jan.kiszka@siemens.com, bp@alien8.de,
 rppt@kernel.org, peterz@infradead.org, pankaj.gupta@amd.com,
 thuth@redhat.com, andriy.shevchenko@linux.intel.com,
 joel.granados@kernel.org, kbingham@kernel.org, nicolas@fjasle.eu,
 mark.rutland@arm.com, surenb@google.com, catalin.marinas@arm.com,
 morbo@google.com, justinstitt@google.com, ubizjak@gmail.com,
 jhubbard@nvidia.com, urezki@gmail.com, dave.hansen@linux.intel.com,
 bhe@redhat.com, luto@kernel.org, baohua@kernel.org, nathan@kernel.org,
 will@kernel.org, brgerst@gmail.com, llvm@lists.linux.dev,
 linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman@intel.com>
 <8416848c-700a-4ff0-8a22-aa62579d60cd@intel.com>
 <ycsp2mypsnnwcvmogvbxgpmw7hia4y5rvywa2xbam7lbuhnbx6@adg6uaasx6ci>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <ycsp2mypsnnwcvmogvbxgpmw7hia4y5rvywa2xbam7lbuhnbx6@adg6uaasx6ci>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="fgc6B/+t";       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.20 as
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

On 4/9/25 07:34, Maciej Wieczor-Retman wrote:
> Yes, I like it more than just generating the addresses in the parenthesis. What
> do you think about this naming? KASAN prefix and [k/u]addr since it's not really
> the lowest/highest address in the whole LA, just in this KASAN compiler scheme.
> And I changed 1<<56 to 2<<56 so it generates 0xFE00000000000000 instead of
> 0xFF00000000000000.
> 
> 	#define KASAN_HIGHEST_KADDR (void *)0xFFFFFFFFFFFFFFFF
> 	#define KASAN_LOWEST_KADDR (void *)(KASAN_HIGHEST_KADDR - \
> 						(2<<56) + 1)
> 	#define KASAN_HIGHEST_UADDR (void *)0x7FFFFFFFFFFFFFFF
> 	#define KASAN_LOWEST_UADDR (void *)(KASAN_HIGHEST_UADDR - \
> 						(2<<56) + 1)

Yes, that is much better.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fe8192a9-02ba-40c9-9ba9-8582547cd3f4%40intel.com.
