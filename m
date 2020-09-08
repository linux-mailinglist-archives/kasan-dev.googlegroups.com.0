Return-Path: <kasan-dev+bncBD22BAF5REGBBK5V335AKGQE7A5NHMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 559F02612FC
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:52:28 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id 196sf9261511qkn.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576747; cv=pass;
        d=google.com; s=arc-20160816;
        b=dKj/+Ikac3lxUyYooiDl6QC/61Hv4cOhyafNy2688AXGf4/JVPNLDm6hfxp3Z/FzxW
         pqmyZc/5GiqjQ8iZKY/0iNIORG60X0ku1HPlwwCNnpzKVrG4bSrxb2qQZ1Vt1JY0Of+g
         d+VbhvVlkV4ughH6XgZDtOLdCi0Hg2c+yYGBk/siba8tr3Ls8vbkt9ACgIeVtzFtrnyH
         l8woXK1SudEJsNBIaKrHXKUDXjOaU3a754tAn5N9/75cnvKNXoT+kEWCNz5pOgznoYME
         3HY1xN+BNQhWV4lvJk4bW6W93LMG59qu9KoJazOgg2tQ7ZVD6bc9UGygxBw/44d0rhpP
         xRhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=WCOfb6aXzgPDbNfVCVTI0PoF22Vc6EP0z57gflxsn+w=;
        b=aTrhF0H0BtmZpQEmzZ5vo1rRbJ4XxZHGU6o5qvYiL+otYnAJwQAtOuaCppaceZ6J+3
         yWFVol/e8JpH8TND8Qzhut31lDJRA+Z59Oztsx9dzGFmmU7D6aWTv3WARvRtFkGYPfAF
         2FsQ6a3P/mFibS7CKRoVzcd3bp/kiAk7lBcrP5H7uQ4FqpS2jqPpOC60aOf87x50mQqb
         qEJU7E0HrKKXSx1j87bLBU2/zcuogC4O1WvcOSB5n1Z0Mb/Y3mc/vSQOo4fjox1U8O6k
         sa6/SreJvVZp2+NP09DH4AezJ1BakjCHRAQaNkkW1xK9SsU3G8w2hdwZiI4g8qKsc/pe
         GmDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WCOfb6aXzgPDbNfVCVTI0PoF22Vc6EP0z57gflxsn+w=;
        b=Chr1yfpsXNQ2XSNIIjZF/IKvGPyYhE1xPpfSgT/Xf26fmVg3BgJcz0aIGGaR5dKzVc
         UYA/rTuii9ve13bWR6b8CwCIJwoAkC/mlS2ng0BCAWAFb1oqwzjxl1F80UfpesQS5nxf
         sW/4CRcwelDTrXzlw+wuG2FI1k1keDV9NvsOjdVv4v4E0hiE/xhDd5DHqJDpJXcL7K0s
         YihmwXb2eTrrBkyB7S34TBh8mnjcH5sNMVMXqh0pu2Hn8KTudZi9LpXCcwF+bIsQoMg1
         o2Bc6uTUmswleX3++E0wU1X/OF4ZuzKEpfZIKnF00e9f0oteplQovkN2TKss2ukUOkIh
         ggAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WCOfb6aXzgPDbNfVCVTI0PoF22Vc6EP0z57gflxsn+w=;
        b=OPbdGqvKmZ5qc2oAWGi404skWFFvC5SMZHy6zLCf0nbLPbL/KePt7cmFe67R+UfZH9
         VEB821VV8b2o6XetEmPjYlSiD1nRPBLqB+jiil32t5d70IP5WirkeW97iE1ayjWXqDHi
         Ps/Pao59Ho9eSn5oEE1Q/W8v+HRauVoSR9St9nAWQuLf6wewmteYl/E8GjUJ3KqI2Vih
         vu3mUtxM0Mcj8oBxrsTC09Dfl423mAQRtdAiMAgVZ0Qsdm+pziRjUFGNM3SoLDKlwAsp
         M2RNx+5Es2i912pnnuLUIEzNrVbgkOkqfyJLPXQdDRjrKsuZPnr4Cw8A53NAmeQAMy8T
         rjjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yuuxjHj/JbuXSJrofadKRaTH0u2ydKcrKX4aDwSxkE7W0e0hc
	DNyqJptDRoTG1lzMrB9J8bM=
X-Google-Smtp-Source: ABdhPJz9bB/AyzBwpqF2ZB2+lAjSjG/IBHOO4zoKPXyuSFLqhNTEF4fW+IisKDLTFFQ6SLm8PkN9yQ==
X-Received: by 2002:ac8:7388:: with SMTP id t8mr407332qtp.187.1599576747257;
        Tue, 08 Sep 2020 07:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f303:: with SMTP id p3ls3265706qkg.10.gmail; Tue, 08 Sep
 2020 07:52:26 -0700 (PDT)
X-Received: by 2002:a05:620a:cd7:: with SMTP id b23mr458419qkj.192.1599576746830;
        Tue, 08 Sep 2020 07:52:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576746; cv=none;
        d=google.com; s=arc-20160816;
        b=Wnjd8SjK+dhilsdMmW9iEAFFQwf3PZVtwBIAVVe8LaGcGm8ZWRhYaGlYDewGEjkJby
         o3AFhe0FkZiulIaDzMT76ejeT0v38IjNC+3VrsI+EffXWcIovIzn08awubXAuIo3pkCs
         w3q6Z+F09VaeAe+iXAfr7PAkVVY1PcWgM3wDn1pZVufJiabngIwvdXhJ28Wgx2X6fVg1
         Ha/HeS3FaPGJFeSfqpBnBj9PV7QtS1cLbw5K9FpDFG9fu2xN6yJ+NJ7DsVaLsu+GzVRJ
         tNQwvNyxtMUEHjqDXMCCAgrM3bemTn8J+GtXyxgd8JHek6s/BylapjPzXiRb2wWncldq
         Ybow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=IuiPIgU6/CPyvdhrx8TmaQ4tUgqwF7H9B1slCJbVqok=;
        b=ERuX3dHq4nPbSlZXErp1jRFCdeCYv3tnCSt/w6KLtIvLqgkZk1pc+OQ3w2oAVMxX7o
         V3b81m5DmOSFWLrDXxD4plVaBIkJpvYxhniEePCiP7deAtvtfA3xvnb2PReAb/qhBA7Q
         JwgaUGueHg00Qk23pEOsveUyW8EQgxJ6mRaRrstM/fC+dsN3Kck/B5pnDOeyM8xp/MFk
         Jy5+tJs4775d6/WItoxEwhHxBdHWcIpWrA2hZygLdQN4Od1BhlL0A0UKWJw6Q7TZ0TVp
         mMTnYHs+4OJ5A5sEsvz5xGn4kSabwdf6OClHU3RmtcInYYZWApscxC770QK3enKYMemq
         Nsww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id h17si794294qtu.2.2020.09.08.07.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
IronPort-SDR: VlZkCDdQaq4dQ2+lWUOfW/ICyjtX3o5XqV9RKZB3Nj4Zxy8SOQZ3f2PtyC4rXfH4hWwH6o+f7V
 JBjNQpiZ4ijQ==
X-IronPort-AV: E=McAfee;i="6000,8403,9738"; a="138188459"
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="138188459"
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 07:52:24 -0700
IronPort-SDR: cF4qspwrWPTljoE8NCBQQk2v89rOLtcknOBa7JrhGhb9jR0+sbSiSqviGAmBxjGghA5eV08ucx
 cLguvrY2fPLg==
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="505096844"
Received: from sparasa-mobl1.amr.corp.intel.com (HELO [10.251.10.231]) ([10.251.10.231])
  by fmsmga005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 07:52:22 -0700
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>, glider@google.com,
 akpm@linux-foundation.org, catalin.marinas@arm.com, cl@linux.com,
 rientjes@google.com, iamjoonsoo.kim@lge.com, mark.rutland@arm.com,
 penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com,
 aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de,
 dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com,
 gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com,
 corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw,
 tglx@linutronix.de, will@kernel.org, x86@kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
References: <20200907134055.2878499-1-elver@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
 z5cecg==
Message-ID: <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
Date: Tue, 8 Sep 2020 07:52:21 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.55.52.151 as
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

On 9/7/20 6:40 AM, Marco Elver wrote:
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. 

Could you talk a little bit about where you expect folks to continue to
use KASAN?  How would a developer or a tester choose which one to use?

> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error.

How much memory overhead does this end up having?  I know it depends on
the object size and so forth.  But, could you give some real-world
examples of memory consumption?  Also, what's the worst case?  Say I
have a ton of worst-case-sized (32b) slab objects.  Will I notice?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e399d8d5-03c2-3c13-2a43-3bb8e842c55a%40intel.com.
