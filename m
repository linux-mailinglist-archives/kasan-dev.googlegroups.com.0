Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBG6QRKSQMGQEW73XS3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 55839745A9A
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jul 2023 12:51:09 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2b6b98ac356sf37095121fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jul 2023 03:51:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688381468; cv=pass;
        d=google.com; s=arc-20160816;
        b=OKcH+zlycd13BAyCEb+dNnJISD6qRQz3hPJCdEF8jSMpjmWtQEO6GuiBFk/Q1KrFfu
         hNOUG+MzzbAQfg344MB/v3wVMqELmJ/AqHcGpfMmBE2PD1pm8FPuoEv8WQufYXNLNTJB
         /xcC2kiZXGWNd39KxfYoWsGzXU6iOevnCAQ8I6j7kI/5OmxishU2s6PxQAegjNW6dbYO
         p87PpuHQ1qPkiW4fMhElBASfdEWfM2WR3NcZb/qpggbCaPPBf4780T3C21dEov8oG+OY
         nKsYMrT2zldGwR9a6zlAzFVUxvfntZbd2Rk+O3T8G+5f2ZfhGsKk6oa5cftXe4r3Vt00
         +sLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=36P87yDv8Mwc07wS47iFuQqCBBS2+q08wpqgMFyoq0A=;
        fh=fDZ9Cj7O6y85bLzVO4hs6ett/E23NhGmb6gKRLMB5XM=;
        b=fF/ykMs/eNbdJXM9iYoqEm4PFAmRPAGkPP6NSg8qaaYop/BZnU28yUSzImXAIA76fP
         Sxnj/mG/+bVQXpVSAmwcN1Sc2FPisafp3U8cLv2znKyaD34WW7qGZKvR/Kj/iY6n79WU
         AlIH4nET55LMVrM/da9y+jFf0VzUE3hMr8WymxdKxtQhsACAq7D0BttihUziYT+sjO3k
         aELSwRoiaMLkJAanknEYOfR15WGMHYGUNQxHnq4HKvNghN/t8pN1EvP3oTo9L1z+wx2Z
         BnyJYIodpb07kXB5xFShTBnaPzSX+XJO58v7lCkb7WyzkvOL3tYcHXGxylOsFFr2oMyV
         D6oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=htHZX9Cd;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688381468; x=1690973468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=36P87yDv8Mwc07wS47iFuQqCBBS2+q08wpqgMFyoq0A=;
        b=ORm0+bkIijzGy1cmTu2RUNH1uSLYPbK33TAeQ6/kfQo50qxBoqHv8X+7YqsoMV0zYo
         E9KLKRKQjEhOlPQIDzVsKi/Z20LWK5UiVJiekFuFMdE8S8O+QU+JcvHyuqA0QfgKzXaH
         Lyt2LAh3jW6NasL3q5ze4okk6SoZ8arFowSpq9o2RLxJBPK4q0cBH89LNgkek4iruqTa
         KbrZSwpsErV1v3K9XeYnwwYyqaEC2Vzk4wEXFSMXmc7EA0fViHIwnRKcaEGtc5fuykeX
         a+FwZjvcotWfokEMhNfw2reLVq2CmYqNZEm/370nO5/WFF9/Hyf5ksXPNh92i6c0E2VB
         Eqxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688381468; x=1690973468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=36P87yDv8Mwc07wS47iFuQqCBBS2+q08wpqgMFyoq0A=;
        b=Laus6hBJy6ub5pvaqrS4mVm3WcHYxPz+9IFtESiX5XKWyto6q0ATcuhMxzTmXQsLPJ
         hd6XTobSBnkfGQme18Fi46kH+fAdYRdNMAzva0KnZBklI6WQotzsR4NjpIz862P7EjTv
         F33kmdrHGR1NQ41aHAyYtghpE+wwVe7m001mxqXq/XbsfquQktjdQarIumbEMoccsl42
         7tt0OxcIhJ3D1dmnAWbdHQJS0LAkAam3XC1rxbEuiMRDENutX428WZhp3YPSh98m1+AT
         fs0thbDxLxec+5BKGuleorYUkZVHFxa9JeCf8SlmFepNYSh2qvOpNQ9y2OddjSAVzpmZ
         uQxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbl2j+l42ykOd5pcL/MK5VKtYCLfyFeMckDtNx+xXPdhmwEvUKI
	5B1n4ftADaqVj74qx+eKd/8=
X-Google-Smtp-Source: APBJJlE2me3Gne/3XMzGL3Wi7Z7rHByvFGHg5qeTVIEFASNCxTzUSWtpjX3warLvFyF4VlKQrYt4Zw==
X-Received: by 2002:a05:6512:15a8:b0:4fb:7933:dd4f with SMTP id bp40-20020a05651215a800b004fb7933dd4fmr8364561lfb.56.1688381468112;
        Mon, 03 Jul 2023 03:51:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:544:b0:4f8:560a:a8db with SMTP id
 h4-20020a056512054400b004f8560aa8dbls147448lfl.0.-pod-prod-04-eu; Mon, 03 Jul
 2023 03:51:06 -0700 (PDT)
X-Received: by 2002:a05:6512:3f20:b0:4fb:8a0a:31f2 with SMTP id y32-20020a0565123f2000b004fb8a0a31f2mr7266615lfa.69.1688381466635;
        Mon, 03 Jul 2023 03:51:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688381466; cv=none;
        d=google.com; s=arc-20160816;
        b=dUfT36Xcg51yIlISNpyNTI/5ELR9QF3kfg/nLkt8+sfi/VBlnna7BEGaXiD6bOkzgW
         D2MGmowJIJebU3GGcuHrwPjJBS7LUDz9Ob+B3EnrIlCbdTiN7Bmd5Ox6uQcR5VHZlNeX
         I1g3LYWX+YXrtdveymOtf6oErcl0aWs+IHMUlt5uJelEpr0344er0HcJm5Cd6vrN1lIF
         wUIcRcxmoN42J6zv/kDlt1AwsTgD5mcmzPBDF6QhGNhpjo8e+TYYqNqKz9Fh247pPhcw
         GFCDx2F+PxFWOL/Tzc1ewnFJ8CtvPdZDHG+kI/lp57iUeeAuV0fot/lPLrZaNSz0FGjg
         j33A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=dcEfFuaLU8WuZ734FC2zjBdbWqPM0/tL5GbnbkXmB5c=;
        fh=rSaFsQxblytBnf9QilyFR0ot9sTVdfTlDv8QfweZEEE=;
        b=bsJB7FclrLD4vIu0/1BkPczi28R/f9dKV6l7pxVVCEaRqCVuWVJZ3xhROEXVLIlFHi
         pYkW7vqOyx0Zno7lJ35ml/nmRK87KIqnqm/0839YAVk6Vw9TYx3EeMq123uTwfCsRDZK
         ZT/CVyCtt5Y8F/m1cU1VJ2K5h+jPiZm8nQRqbYNNu5F0VpqlVmHWZMjFlxBeyi8dhhje
         Doqs1GXECYnBPLlyZY8a9AXuvHPl6r0HDbIivtduu89zW36gvlDFB7wBVOL7LsriCnVq
         efb2KydttkZICm2DFZFMDVc8P+5J19hodWEJcP7zW/1nIpNleFpST1AQqNEeLkdY8G/7
         1xrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=htHZX9Cd;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id o8-20020ac24c48000000b004f8621b17fasi819880lfk.3.2023.07.03.03.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Jul 2023 03:51:06 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10759"; a="366335271"
X-IronPort-AV: E=Sophos;i="6.01,178,1684825200"; 
   d="scan'208";a="366335271"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Jul 2023 03:51:03 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10759"; a="808529347"
X-IronPort-AV: E=Sophos;i="6.01,178,1684825200"; 
   d="scan'208";a="808529347"
Received: from smile.fi.intel.com ([10.237.72.54])
  by FMSMGA003.fm.intel.com with ESMTP; 03 Jul 2023 03:51:00 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1qGH90-001qCc-2e;
	Mon, 03 Jul 2023 13:50:58 +0300
Date: Mon, 3 Jul 2023 13:50:58 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
Message-ID: <ZKKoEv9V6bTJQy7u@smile.fi.intel.com>
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=htHZX9Cd;       spf=none
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

On Wed, Jun 28, 2023 at 06:33:42PM +0300, Andy Shevchenko wrote:
> We don't need to traverse over the entire string and replace
> occurrences of a character with '\0'. The first match will
> suffice. Hence, replace strreplace() with strchrnul().

Not that it's a hot path, the bloat-o-meter shows +6 bytes on x86_64,
the change seems has no added value, self-rejected.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZKKoEv9V6bTJQy7u%40smile.fi.intel.com.
