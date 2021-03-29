Return-Path: <kasan-dev+bncBD22BAF5REGBBL4BRGBQMGQEAN5RJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 279A334D964
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:03:45 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id z21sf362412pjr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:03:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617051824; cv=pass;
        d=google.com; s=arc-20160816;
        b=cqeecmGzgxPj7c4uXUCQ8MboaIlh+pyWiDAVueSAdYbvUUWEtP865HX/mRJpuY/Ugc
         poBicXHvP1ZxYnx8U3f9OYr4J2ean/dzL2KktNd4NN3F//JOMnkfFtigMg6vevniBur0
         sMz/JuUnlyXFwiYLYpFY3vvuUY49DfMLv67Doy3Gm9O4ZFignaprFqEwo8FeAPNJIqwO
         6zEYUGsOKngGCeU+lo7C5++RkB+2twGM82Uy9BW3EDc1QOIEffoTxgzSImiyIEI2Y5vI
         pNEJkfDR9pKohRsH7+igy/P3iTO77+Q5oLKBsUu4m1+OXcc+WwM6HWbLRcAgvxHpDI2D
         lAVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=Wv1JcoZmSgfb6CBt5RbGPuerhtGKH6o7JtaQbXkq5cc=;
        b=rvYDf/MuC5qmF63SPsG8tNley5vQAzlM0B5A3CozzuDCpTXnGuuvy7mjl1W8wGqvvt
         SfGaz1jaKiU8xsSoCgPyD1FCrYJgnMNwgna4H+99FQWyrIfepbB1GYz8F8heiBMFFZ67
         KYDX/uuqPlCJqaGiriEYTj/y9qe/EAqIRLoW4sQDTlQ8nX4dVp4iFDGbqrkdoUo31OqL
         /8OfSnrIfpLdD0GvxOh/Gi2F5XdtVlO/Z9L/p58qjKqsBB7yTxbSE97qXNuLAjDn7LpP
         8MQOxQ5Q2546GVH+WwHU6vd4wPfmT2CczCeA7pMcPqpAsEJLtEBqD9Juzfed4PVevtyq
         SBaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wv1JcoZmSgfb6CBt5RbGPuerhtGKH6o7JtaQbXkq5cc=;
        b=SIdnEHlxw+/qKNAy/GIl26AXeWmaZR92IEU77K+WehBOLWpfoBq057t4w+0KmroCwj
         s4UrbT7ea41GCwLw1jWY17j49Q08a7SpJJsEY4gakojX/DVXEPoKlNpajNiuGwMJ92ev
         82h3S/mDJc5CxEe5jxhTObdgY3+Js9N7FUdMudMfHMrKpit0yb+Xvc9Pyg774SUL5dy7
         B9QBGpQ6WCLNYK61ZZjjS2Qvbh7N+s2+9At+Fz486Je3J+/nEp53YmTYbC+5zvisZ0xi
         uiof/xikQJtuIHOYvG1gMiiY4HIa1BVqHIDGMqP1jITtoaZzMYX1yGd8S4Iqdz0sws95
         rVEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wv1JcoZmSgfb6CBt5RbGPuerhtGKH6o7JtaQbXkq5cc=;
        b=fqOHdEzVp/VsCCebcRMws25hFe/nLcqHGyu9wjFyDWxxVUsV2EJUegKTPZOdIjnX1q
         ckbj4QWceY6alo+R/x/wwJRPTxsQSHOTudb7xdhroGFMDS92Zp0thQ9wqZ9VUeOli8iK
         vHo9slZvuaEvjhVtq5RFLGBxlKh/fHRuLF2FPgPRCHVNyhdp9qNIWomfKOGop+ghgrbC
         3bLXxASbJPVwTmprSge6vP8yr+Qsb1d1mGPFpfXWtT0P62WBIYvkUHRS5HPlkS0t7xFE
         1C0Sl5mrA2aX3I2UC80GUZRCWFiSIy3xGQntXIrl35nKo5QGpycRpiJ4NQA9anOF7Qdk
         Hzuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tx0Xv+kLKT5K1PebvxVCLZCuDRt8RS4xdkU6v4r4j8Erxkt//
	5QNgZspIXp6BN+uZj/2+xls=
X-Google-Smtp-Source: ABdhPJysnVeB/FWl6Bri1AYGaxly/tSoNQHJmAzfUVRmxz9fgaCRdIXJbYh3udAauWw2dTrzgzHMBQ==
X-Received: by 2002:a65:6645:: with SMTP id z5mr25077651pgv.273.1617051823881;
        Mon, 29 Mar 2021 14:03:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce8f:: with SMTP id f15ls9566097plg.5.gmail; Mon, 29
 Mar 2021 14:03:43 -0700 (PDT)
X-Received: by 2002:a17:90a:20c:: with SMTP id c12mr945461pjc.224.1617051823340;
        Mon, 29 Mar 2021 14:03:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617051823; cv=none;
        d=google.com; s=arc-20160816;
        b=Gol4StuKtrMOn7W8le5Hmxqt7cEc7sfViKr2ap2roRk0nYltaysdbtNrwBEGcD2Sm/
         NuWA+EIoWD5yDZgLKgqHJsdsrLlIoC46PHD9M2n3x6HwLNNDnR5iHqMaSctHgQ0C3aUc
         abLLYK+NCe7Z7brKd3lKFDjf1y4OK2WusQD9ZisVLr1B8IDph7g2d5zg4Rzzz/B0rTRC
         Oc2Qjf9693t/ZR3TBOpF+6QAEWLC2kxLk/Kx3g8f/2cN0pgG6D0T6H50Pm3ZQ92OCplY
         w69weV8c7He7UlWY90GDBH10ablTueY/EHmB9GvqmPBWsk/7soVVYNgCyRofs8atA3zE
         Wbuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=BwfrYzDEehksizkTpjK73uBB+vQzg9/8Zhq70VLpg04=;
        b=Blw/Ojg7wMsfGlwO5rjj70oOC51nQQ7sCkfEQSslctAmKYQrvv3T77c6MqzcwIUAbz
         eaBfK/Adk27eS1TRtGAskuEMiCi2txqW6q7pg4IVHdjl7kgKH1u2uFMh6YhJ84nIh+A7
         6esA8qDv03xRQwh4UrKBo0VnbYIIVfBMfy5icfTqQxFRrvC3GuINzujKLDhC2yc4pd8N
         sKMaz7vFZJu3IqBhUDHFnRdSqrIAFQEamBVSsknpJAMZWll7/7EtvJpSxcUQXhml54Ru
         jhvKEAzODPaqxkzJJY1ytP4LBMM7CsI7qD6Pggg/IlOjA9BhoXmsH+dYLRnszARBxTCr
         lmqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id 145si996031pfb.0.2021.03.29.14.03.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 14:03:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
IronPort-SDR: glOR9aIlapUU2qbA7FvqzMR+z6Qee0EF8pEKbIZT5X/Ydd/dEyO3Cisv1zY7Btq68Y3YY4aweJ
 wqy8UbrQCe0A==
X-IronPort-AV: E=McAfee;i="6000,8403,9938"; a="191656724"
X-IronPort-AV: E=Sophos;i="5.81,288,1610438400"; 
   d="scan'208";a="191656724"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Mar 2021 14:03:42 -0700
IronPort-SDR: lzTsoGTpeGUNutDxGIcoQyA2JBxCXayDDEM4oMNIBef2LKg/nMeuOImLRswPvXJXSnTW2FnP1v
 JsYRselswgBg==
X-IronPort-AV: E=Sophos;i="5.81,288,1610438400"; 
   d="scan'208";a="411273851"
Received: from jmwolcot-mobl.amr.corp.intel.com (HELO [10.209.158.84]) ([10.209.158.84])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Mar 2021 14:03:41 -0700
Subject: Re: I915 CI-run with kfence enabled, issues found
To: Marco Elver <elver@google.com>
Cc: "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, the arch/x86 maintainers <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com>
 <66f453a79f2541d4b05bcd933204f1c9@intel.com>
 <YGIDBAboELGgMgXy@elver.google.com>
 <796ff05e-c137-cbd4-252b-7b114abaced9@intel.com>
 <CANpmjNP4Jjo2W2K_2nVv3UmOGB8c5k9Z0iOFRFD9bQpeWr+8mA@mail.gmail.com>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
 z5cecg==
Message-ID: <ef4956a3-c14b-f56a-3527-23fcecf7e1a3@intel.com>
Date: Mon, 29 Mar 2021 14:03:40 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNP4Jjo2W2K_2nVv3UmOGB8c5k9Z0iOFRFD9bQpeWr+8mA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as
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

On 3/29/21 10:45 AM, Marco Elver wrote:
> On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wrote:
> Doing it to all CPUs is too expensive, and we can tolerate this being
> approximate (nothing bad will happen, KFENCE might just miss a bug and
> that's ok).
...
>> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on KPTI
>> being enabled.  That's probably why you don't see this everywhere.  We
>> should probably have unconditional preempt checks in there.
> 
> In which case I'll add a preempt_disable/enable() pair to
> kfence_protect_page() in arch/x86/include/asm/kfence.h.

That sounds sane to me.  I'd just plead that the special situation (not
needing deterministic TLB flushes) is obvious.  We don't want any folks
copying this code.

BTW, I know you want to avoid the cost of IPIs, but have you considered
any other low-cost ways to get quicker TLB flushes?  For instance, you
could loop over all CPUs and set cpu_tlbstate.invalidate_other=1.  That
would induce a context switch at the next context switch without needing
an IPI.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ef4956a3-c14b-f56a-3527-23fcecf7e1a3%40intel.com.
