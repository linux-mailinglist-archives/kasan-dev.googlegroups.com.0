Return-Path: <kasan-dev+bncBCV4DBW44YLRBOGB76WAMGQE2EFKETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BABC582AED1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 13:36:09 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3606e16e477sf133855ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 04:36:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704976568; cv=pass;
        d=google.com; s=arc-20160816;
        b=PvBHDe1WPrY4bsc6JxMkTwredDFCJ2TJ+7h8aVRRPM4q/TUGiA0cNl/BqHJ9fWQuAK
         EIVCtaFGL+aq1uzMA6JfgZSJA81WXleVsbmIBKq9dezsE8CqTT0TcjchnNwq97Xh5Lwl
         xq3XCedJ7PgC0hT8BBdREY8biGIrEx1+svbSVfCEioejykDcoZYoS39JN7SF88C9eOh/
         1ZbWuavWe0LXHV+PJk2BobHk8rT378itZr9u0oFRqEgKGL/F5HBpN8qPVhRP/HN5Xj2d
         6FOuoprQnDjBS7F+hF3HyysgyXqJX2ojT00/Ehf1eCzpbxQB/7flZtJcRCsmG2yp0CiX
         AifQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2ELeqn/8Cg24yWOOvY0cpGie2IGFLyjf+Qk9YBRklWE=;
        fh=mN/qU56MJ+i6MDCuuCU8el+kxbzHEA9O/nopluvZ1xI=;
        b=CNbikZSt3cJGYoRe4pJQKONjo4vxjyMQIUFtA4zYLPjYwqBK3uFYgiI/LwjhT3ZIbU
         14i0l4JEHX4yQjlb01dN8Gqpz9t+RIru+jmOJW39VkeMUaJP1xtTQP1NB+6HzQbMFKqy
         ks7udAzMVlgEUCxbgctwtHDt1VAix5Vjrab9275+esSGzf17vuy7DA7ymIaHAHrtdFTH
         I05RYDViCph1OStACBP6WRYiRQgJsrIT48zIdsZv5JnVWMLk5OolwX1g1tZLB/eag/AJ
         HXNqnQQoqkOlR02f+lJAu2ZOPTc8+MI32IlTWmhS0BnXgWE8a1tGq7JdF0GRX/w0C4Y0
         QtgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SLwERbM6;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704976568; x=1705581368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ELeqn/8Cg24yWOOvY0cpGie2IGFLyjf+Qk9YBRklWE=;
        b=lnBTsUqGf5F72H0GJqKqgjzl3XvWt3niTacLmO+EXNxbR+0gt0gbxq8fErPwm1Cd9X
         TUllnlAfQkQhIACj0Ul5pxmz/ipewfPucFn8XPpAOFy3xLxZU0wBhG+rIBSOsb+iuReP
         bgaOedDUTfqpFqum1hC6+4HpENWldNTgG5/66TTju6TiFdTjA16cNKbDojocvDUDe8OV
         haPtBVccxmqfhyoILYcP8sA7soOGDjkAOjiY0fAoz3IZDlkNoMfU4hdeIK/+Qbkn/z/2
         OCijunaYYYPvxHgWDF+cFGcs2cgAw93PekPC9La0IdZrn40LGbzgu5uC6RvwLzvBaiur
         3EYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704976568; x=1705581368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ELeqn/8Cg24yWOOvY0cpGie2IGFLyjf+Qk9YBRklWE=;
        b=hGDPCfq80gWunusJxfvPq29UkhFPHajLFPvJDh47Z5ofxXKZp7dWp8eX5dAGy9O757
         5oMbEToSVUPRMwnuRlLZiNrXD4CC1kiQhh78WnLYUA+elkXMmjo1VfZrn1k3RQG6x/Bh
         WTSURhH3wdPMbd/HCvCmY39FCBCoidJl2MhE2ofcBTrLvavMasqYhekt52SixX4Byw7d
         iXWn17BGsLx52E56A4sjf7XlPAgitcwPuDrpu0MSOSeugJdJrJRyrMoD0B4yYGWbNGF8
         odlH2KZYTR9nZYt8VcDEnzOzm4aPlssku1/aNJFJmuUcvlFly3pEZtz8FzH3M+2Bkqz4
         tv6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwEmXc8iYTVcKT+MWk2fVngf5rMhVDfmu8P9i7vKNdqI97id776
	Lf2a9gLbjALvDtmt81ohHm4=
X-Google-Smtp-Source: AGHT+IGsL/YeuRzf0QWjiYgZ/aIkgB4ARSmkRd1FJM22x2lXsKb7JvC3LWZw3jGaFCGJluxWi1TDKQ==
X-Received: by 2002:a05:6e02:3d03:b0:35f:dab8:1152 with SMTP id db3-20020a056e023d0300b0035fdab81152mr83964ilb.3.1704976568282;
        Thu, 11 Jan 2024 04:36:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b011:0:b0:35f:e96e:6e69 with SMTP id x17-20020a92b011000000b0035fe96e6e69ls171300ilh.0.-pod-prod-03-us;
 Thu, 11 Jan 2024 04:36:07 -0800 (PST)
X-Received: by 2002:a6b:e917:0:b0:7bc:4216:fb9a with SMTP id u23-20020a6be917000000b007bc4216fb9amr1236346iof.3.1704976567413;
        Thu, 11 Jan 2024 04:36:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704976567; cv=none;
        d=google.com; s=arc-20160816;
        b=WdAQ2VoaeenG3/p7ri2jndhWBrSyJHdIcauctKacO9f9UOmz367vDummuTKrCTz51N
         aGFcsmwLtVzVtCjva6A1EuOgToOOAMVVCsfEpt9NH/uKnEyAPX8XG0j3Yif2rV+vFxui
         b6O2cotlRXkyOJrd8BmzBPMsu4UOkytq5Gb8CWE4EdrhKPiGia+NDfpww2sm5q67E1De
         OhH5LVOUbX4PfQbEmnd6PaZhAvVrkQLSF2VmMntxr2a/GG3f++DWDErXnSkQ+AIessxs
         wQ7RjxonB0yYzJ6mmlPjlijK1h2v/d2c/CQVoQ3fGStOnpbn8AqoUwOIHwybw5Q2eZJX
         sH9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xRA8RaFNu4Cwx4kYpYDAzrlMhkoYHt6+xOaSNQBOWCc=;
        fh=mN/qU56MJ+i6MDCuuCU8el+kxbzHEA9O/nopluvZ1xI=;
        b=m8hYtRF6C3Q9VC0uuXQUDXPc5e+bVT76H+5+4Y7OlywDh9XwnoH3OmPnIgiu4XtHyc
         q8ynW4f4MDMWc1PCLcGy1OjUmgjBam94YG/DrWAWiEqYk9UNlc7CZT8HxjjAYstGG4gD
         UDQG/gnc6VPeduUT0uqw8C2hTFY5+9VNhkbA8SF5vRpDz0gZWyERVfGm9R+FBihIJYpa
         fbJGMASkdin42x09FhWD/Tv5RVXsf48oXDAMuJa1t1KxgsgR7hY3ZG6XrAD9Kg+fJ5jF
         wdAE7W5YxqRv+zes25KODzc+e77fKMIXZqv6ZQnlqduU9Plt6w+BDMIWVwidd5vi3Wvb
         amhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SLwERbM6;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id x67-20020a0294c9000000b0046e5105dd3esi110416jah.7.2024.01.11.04.36.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jan 2024 04:36:06 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.11;
X-IronPort-AV: E=McAfee;i="6600,9927,10949"; a="5561816"
X-IronPort-AV: E=Sophos;i="6.04,186,1695711600"; 
   d="scan'208";a="5561816"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jan 2024 04:36:04 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10949"; a="926000150"
X-IronPort-AV: E=Sophos;i="6.04,186,1695711600"; 
   d="scan'208";a="926000150"
Received: from tassilo.jf.intel.com (HELO tassilo) ([10.54.38.190])
  by fmsmga001-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jan 2024 04:36:04 -0800
Date: Thu, 11 Jan 2024 04:36:02 -0800
From: Andi Kleen <ak@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZZ_gssjTCyoWjjhP@tassilo>
References: <cover.1700502145.git.andreyknvl@google.com>
 <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain>
 <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SLwERbM6;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=ak@linux.intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

> stackdepot is severely limited in what kernel facilities it may use
> due to being used by such low level facilities as the allocator
> itself.

RCU can be done quite low level too (e.g. there is NMI safe RCU)

> 
> I've been suggesting percpu-rwsem here, but looking at it in more
> detail that doesn't work because percpu-rwsem wants to sleep, but
> stackdepot must work in non-sleepable contexts. :-/

Yes something per CPU would work too I suppose. We used to have
big reader spinlocks for this. 

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZ_gssjTCyoWjjhP%40tassilo.
