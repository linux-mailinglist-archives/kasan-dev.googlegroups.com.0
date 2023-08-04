Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBROBWWTAMGQEAWLAQ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CC5617709B9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 22:34:14 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-4fe3cbb4398sf349e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 13:34:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691181254; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sqzr2OErh8hrQLHlQc+2IrcCID50vNvIVOvqKODr+YwKqbb9fJJUXE6DPNflUvoyD7
         3xyRnU3pO+ebG9+wadondHuknUYLpHS0zB+nUwtHAdBngVDPHu39H0g+FAlvEHIj2Hv+
         MRhY6d/i/+dB4rIFEi8k/Hno46Guhrh7JckV7bNihC++VbNotpOB6vUAIjXVuqMQwBRd
         CYcC6YJx4Tdm0rLNYuWwitGDW5IddCmLXnyavVMO+lnYWeo4q41uQPQJGMa4Nn3hDsPF
         C5+whb3eVjhm9EbECuOToQEEFFBQzQVfLKVDAse39Fm9q6qiXThHcKXAUatNQMIYQivG
         B9zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pHCVya7vhb++zK5dxEczo9bBjfxdOm3r8N1N3c84kqc=;
        fh=oI/Xiro4+EHjElptEbxeKLLzFvN1qXeWbIHTFIMB7YM=;
        b=xM8ihcRGYAr3qJofvi+qHqJhosqgml+K8YeXRS9APUWuCNqs6QWriB1k5EOLsvIG0O
         6ImlYnbNeX1s2JWL8fVWQWUxjp5VFZSCXaQzVz+PzwxkoHiJSoUcpSwj+lJI1deTqW/G
         bU8iKtZXK5L9JLVSgUySCfiH6Uqq1neTEhvywktGO0cFJvF7h2d71cPSUoVkhOoY2fdU
         6G/j6/808/t/5ygCCzW2ZDTTwBZMO5uuyoD8vHzq5OLGUp3cKvxzS4mKTo5MX/je3LFl
         ZxNwMQ/MZg66dMYkfLccZvOiZpIA+/Kqop1PeqckdvjRsWc428yt/cYWmevZoKsUSyLF
         OwdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CsLBcNAC;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691181254; x=1691786054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pHCVya7vhb++zK5dxEczo9bBjfxdOm3r8N1N3c84kqc=;
        b=Ddw8cZYGzDVJEYyQNVyH/XOszw1NQo3n8S07TSCdHsM2R0RInU3w8ML2Trjdey0g0x
         TEUYA2H2LSHdbUnIV6IMygeruGPjc5mdssTxc1C5UxwvlgCXYMmz9jXfCnxHITL1FQcm
         4YoV66qscZH0d9ptyZ0VcornP59axkmkD6D12qGyNgqwMQzrBBxAXxb3QBw+NKhhw8La
         1w7rkjmdpbGZn2gH5b0nOfjx2puw1eK5Sutx8AlXdRtiB27BxKwJJY78EyX/pkCMF6rC
         os/2y2KnX7DSHRT4C3xJHECnvUedVHppPGSDbY303i/4jV+JLLM59gTJe1MvtJyDV+D6
         Zx+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691181254; x=1691786054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pHCVya7vhb++zK5dxEczo9bBjfxdOm3r8N1N3c84kqc=;
        b=E0OIgfuJ6YX0l4syefb9gShp85WFO0k1OgeBhKyngNAGOase/9xhBtuoO5ghxGmPQM
         nnptp1Flp5r8x5kjOCW6k0wHb2Gd7xMPAjAstbIQkJga0wJlv9EL+QAhRDjQ5cI8WrrG
         v6hfFKfU02a7u6LVCCqY1Q4zJJXwom+o/JrmIxB9X+48CIvQpHTcAvnfhbVamz0QrdwM
         a6gwUi1aXH26pNqYbPk7rffKQasTr26ATsOYYW+4FdIXYUwL6Y5Ccfzh79mhe+VvuP4Q
         QFuy5AZmjLp2Jcgs6qZ/OtF2iriwisCuLHgMkwLbT3rDG2tTvAvZNeu/I7JPhTE5H4aS
         XTTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzKYFeskyXAnhAnWvfe9PwSywbx7FJx8YcTHYnGuqoCPKaeVaH4
	MZTtFS/zoKPUIp4KdM9lOFA=
X-Google-Smtp-Source: AGHT+IFwXjhl0X6ly9GqOQlNBuijn2+lAqkdb3Xeu3IBm5zUPSzNbZYwK/J7IpqkRVr08Ed737s4PA==
X-Received: by 2002:a19:ee0b:0:b0:4fe:106e:e2ec with SMTP id g11-20020a19ee0b000000b004fe106ee2ecmr20692lfb.6.1691181253798;
        Fri, 04 Aug 2023 13:34:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5046:0:b0:4fe:13bd:d940 with SMTP id a6-20020ac25046000000b004fe13bdd940ls172227lfm.2.-pod-prod-05-eu;
 Fri, 04 Aug 2023 13:34:12 -0700 (PDT)
X-Received: by 2002:a05:6512:2821:b0:4fe:5fc:9c4b with SMTP id cf33-20020a056512282100b004fe05fc9c4bmr2447061lfb.15.1691181251864;
        Fri, 04 Aug 2023 13:34:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691181251; cv=none;
        d=google.com; s=arc-20160816;
        b=BuZFLlm3A2jXISkq3ajIDGR31NXZ8yLu8aoAWyjHugK1HQBguNLJ76df3qF/JeHXjh
         TnubpoKd6SEIWZl1PrcE/MEVHt7vN5jv1JvrfbPZHo/VTBImg2mp8K9SvZzL5GcMwZDL
         SUCz7zMhXEtJmzPi/9i3UWdZXGVOpYkLqVhA4wx8rV9pi0Fgclno46RLM1vQaNOvp3q8
         ViYiPnBvJP9nO5lKjA29o4MlFMx7HUEO3pHdDbvTAUn4aD5CBbVrZQbp/dnLac2a439z
         n2BcphMoGMZS0frL3B+YYY2W2fhwMQ7J04nOhBckxI3TUlTjk8fp3/6jXBQo2LhqVll2
         P28A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=PUt6XfM4QVaZmaffnDjDQpnQshBAoyER3wY7WoNtv+c=;
        fh=oI/Xiro4+EHjElptEbxeKLLzFvN1qXeWbIHTFIMB7YM=;
        b=G3bzUA5PMq8Pwt8NmcooFhJqBR8qG1P3sUkbf+hIY/bxMAyiB8XGDd7eCaKSnknMQ+
         gFZQfSflQ/OlsvKjY7OFnHtp+oVHDXbytJehl3SrEc9J7ZqCIMJnbRVgtOV6jkjWAPKq
         ErtotX8Jw015/fPTG2mHLHLXr12tCQbvfvFz1B221xuTdWa8qXutqD2q3qxK7P9wdicb
         iHDzL/ajEKvqY5RCj/k6i/fOu3Dbdlc7v6iwxG6UQ9ef1a7KagWqNUsWvV8sm3eOrirg
         46eUeZHDOm5cgKcZE6fWdNQ2QHUpkdpF8WY7PDHc8MP2gz4yyXePQcLPO0w7kW7vSuFj
         qf4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CsLBcNAC;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id v21-20020ac258f5000000b004fe3478235csi192692lfo.7.2023.08.04.13.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Aug 2023 13:34:11 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6600,9927,10792"; a="456619033"
X-IronPort-AV: E=Sophos;i="6.01,255,1684825200"; 
   d="scan'208";a="456619033"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Aug 2023 13:34:08 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10792"; a="680087031"
X-IronPort-AV: E=Sophos;i="6.01,255,1684825200"; 
   d="scan'208";a="680087031"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga003.jf.intel.com with ESMTP; 04 Aug 2023 13:34:05 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qS1Up-0070AP-2g;
	Fri, 04 Aug 2023 23:34:03 +0300
Date: Fri, 4 Aug 2023 23:34:03 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v1 4/4] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZM1gu3+x9uLnDwVB@smile.fi.intel.com>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
 <20230804082619.61833-5-andriy.shevchenko@linux.intel.com>
 <71ce8516-21cb-32c6-84d3-b3f9bb3d625b@rasmusvillemoes.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <71ce8516-21cb-32c6-84d3-b3f9bb3d625b@rasmusvillemoes.dk>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CsLBcNAC;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=andriy.shevchenko@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Aug 04, 2023 at 11:31:58AM +0200, Rasmus Villemoes wrote:
> On 04/08/2023 10.26, Andy Shevchenko wrote:

...

> > +#include <linux/types.h>
> 
> Shouldn't this at least also include compiler_attributes.h, to make it
> self-contained?

As I replied in the other email, this is guaranteed by types.h.
But if you insist, I can add it.

> As Marco said, please just declare no_hash_pointers in this file as
> well. Perhaps with a comment about not accessing it unless one has good
> reason, but I suppose that's true in general for all kernel global
> variables, so maybe not worth it for this one.

Sure, thank you for the review!

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZM1gu3%2Bx9uLnDwVB%40smile.fi.intel.com.
