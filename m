Return-Path: <kasan-dev+bncBCAP7WGUVIKBB2556GXAMGQE6TLKQQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1661E866F33
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 10:50:37 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5a02a6e2886sf3055520eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 01:50:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708941036; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfP0j41769RSVOkMDY/EoAOxgjqSq7OGDBi3iLz+73SE6FWROzvSYAiBJIOZ9seYGq
         V2A3o6dQ9vaE1UuCsSgOQHwO8YAU2Qe9BUVAZzWuA4avUbTJE9UjvQ8B7XoeHcvd/uzO
         8A/8hF3NjPjY/fHVJnOn7qfUnXm6y13YfoJZZ78woz+283EXclK/dBYsJNMEVgy8WhXV
         oLrQpkmxJZ/MsWHAfPcnxPtFtB2ihu03UtLVwhJ3TStwysQ7Xu0Tib0b4S/IUoowMthz
         2PjBpGqepC/ViQJbHMUd1btZe4LevKmRMM8enpL57eNRm+ll5IXtBzPACYuB8+Bd1gql
         Rlvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=TTMT0E7EUekB3cxQy+7jatroZ5zphW5PiC8KLRsvqUI=;
        fh=UE7kjktxctg/bfnx8eZDaf40temHpwbtnkAtOvarVsI=;
        b=ajyk2KjNC3Gstoxnlg0C/D/buTnILuMsFwHDXojR90iUr+ewu2QUPdHquZ978mBPtW
         BskF42Cexpnh/P3nDTWm8RbgztdaLnhJRfyU70In6UpekszMzJrIfQxJPGVNBZAGnm2D
         jMkyoOJTUT1qGtMelcapDfmFoz91xjx5TNvqyPMpMKHgCjnH0907wARtFyYwsnvdpUdc
         kg+RfeiDFdDO/PtzwyR0AdS+ahGLhWNJwOnO3Qqp8Q9EFiiCif0+/668F2dEuITrmFK3
         WpQlrw515Aa4iXvaqaETeJUtgtcKcU4+HorByupsjdEEBiQPzW9s+8VkXezdhMqO4Ybg
         6DXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708941036; x=1709545836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TTMT0E7EUekB3cxQy+7jatroZ5zphW5PiC8KLRsvqUI=;
        b=XVoPRJtu6RX2nPE+r94orNEKhUC/aOj4E3dpLolDUbGq/zaAZisfllvRtKdJTHHyon
         cmiR0JxC/Ss0zpzfWh2XEAHiX64y+GLH+TYorOAn3YVvyqRb++LO7QMDI63nT4mmEOZJ
         KMd1XNOJWZjVKQN1u7ozHstm3MHsw/4f8urjVlGgRDqTTe6sShGl//jc+gGh+Xrb9ZK0
         jvrQLaRN/x7XNJYC6S1RNKRCbZ0SL4PWARu1MpR4a3YweiJecak/uIQwaQ2TnFUhi7rQ
         O616G03+JzrB92kJhAwCWv5wAx7J7JKV9vgXhdDQfY2RlqcfmMgjds7TaoW2w1h4zNzL
         7kgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708941036; x=1709545836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TTMT0E7EUekB3cxQy+7jatroZ5zphW5PiC8KLRsvqUI=;
        b=qxDxPguBDoyjCdbNKcf3xKCRLBT8Egk2HP47jphHxO2CGg+2cQH0GT7Zjyt29MtQyM
         XbhP9G4U9ioDz5GaWtXGP39LBAXaEDvi8fUV/WIM4aiuLnQbYfALf1OFhUC4S2NR4get
         dJUvzTBtEeX23CLJlgDmB3naDciItv4pkuFGzIaR3d0HV13RhC9C/LkxPTOBlzuWzFmr
         PGL3V9rj1CXu8je8npBDb4av7+dQrH19cxCZe4rwtmL8XBep1bImDC+hHpcTh//ew23F
         XunrmEWJVFhzKGyS3hBtcNu9l7KZ3+RCGycEWZsod1kP8FXqOt0toMkJCEfB15lPPzL8
         2e6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOiEUWiDEeKtuGUm0nhMJeGhbVqdFfqYcGH7fW61KUxaMBObs8XSZ74Uybw8jrBFsbsZlP36rUK4PCPgI4Ava/deRG/fArdg==
X-Gm-Message-State: AOJu0YzpNZE+kh9lCSwq/dU3ZJ4GtIuCtzvaHpJMJaqWRICsKRfZojlC
	2XROdfdZHTWPf/R0dwXbOYwGYhvT3XH/a2gKdFpQTu2W95wkIZQx
X-Google-Smtp-Source: AGHT+IFknLJv3DuWKWX7CQNc7l+e/mZBIwBCKuGOnUbXJWKEld7ud/Bqv2Hjm4GQGwRuqpTNwWcKYA==
X-Received: by 2002:a4a:6f52:0:b0:5a0:4598:cadf with SMTP id i18-20020a4a6f52000000b005a04598cadfmr5366696oof.3.1708941035834;
        Mon, 26 Feb 2024 01:50:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a9c8:0:b0:599:1da6:a4d8 with SMTP id h8-20020a4aa9c8000000b005991da6a4d8ls2861530oon.1.-pod-prod-03-us;
 Mon, 26 Feb 2024 01:50:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRX+9y6BmSVb+2l1Re0kmm1ad1bo7oEpp+UYhkrypK+FfYOQ3oDWLRwskPwvY9TUBXL8ve5kOehpDVwhm/fmQDj9V0IozM/VGl4g==
X-Received: by 2002:a4a:9b06:0:b0:5a0:2a63:af8f with SMTP id a6-20020a4a9b06000000b005a02a63af8fmr4708187ook.7.1708941034443;
        Mon, 26 Feb 2024 01:50:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708941034; cv=none;
        d=google.com; s=arc-20160816;
        b=qOuvCS3T1Dgy41Z9IGloLo2XzOv2znn+aKLikoli9UttNxdUPOQ6wPIVDDDqzTPyox
         nbhVZsxOOkOe87iPKDRLSmNP34QUBolapOFOipOnFqIZt/D1RvF+6RcP5d9FTvqH3vt+
         JeK39Zyf/FTHnoVwhYl8OsQspn018dXbOc/llTTUVCWY7UpP0lMEVj83mcTydH/z46Rq
         Ip+88juoTPsMzUXYcPazPcIuMtcTRc/Iv8XTmJkmw23dHD0plkEx4SGosDBZzwrCtyq8
         IC4eoX1j9CcqnvhMDzCISAqxHvwI5zjknt5By1p6888ZSCaKjU3d/37xSAsni5KFr3xt
         2Lig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=3VBjWNtNVbic9n33KMVqHXs7q7SDKzpQf2fsnVtUFo8=;
        fh=gSEydq/TyhkGaVN+iWsHLp+rZF81Biu6hKVuPH7LQ7o=;
        b=TmmrAc8shzsrrKYDkyqAx+Y+DrWtwbSWqVjzIsWSBDnsUwkXuIlxCtOYyd1lfCWxgB
         0Yxyo0uF6dVXhlxjlnawyhNF0yVHKhlLKF2zG/j6WU3/UhnYkgKZCi6vs3Ifo+g4LT/h
         UqJTi2S4N7sjIgSJd9s1vom5Mlsmlu1fskoAVnOAn553pF9bEUe1MKfoQe5owaxKr0hB
         /Wr62Mm+NzG4KgBwkS24V6pIaHxPWAghKpBhyksUGYhfQQr1z3ic9b18eRYYj11LK7GC
         HCkp7RJpAV4vnPt+sG/78BlYQXYnPCabdg7BZFMUMo+oNi0WsiualdPlYCm48bFp9yto
         Zd7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id e196-20020a4a55cd000000b005a0554c5d86si647167oob.1.2024.02.26.01.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Feb 2024 01:50:34 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav415.sakura.ne.jp (fsav415.sakura.ne.jp [133.242.250.114])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41Q9oJ9b098463;
	Mon, 26 Feb 2024 18:50:19 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav415.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp);
 Mon, 26 Feb 2024 18:50:19 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41Q9oJ0c098451
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 26 Feb 2024 18:50:19 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <17ec4ca0-db5c-47b7-ba8a-ec1d0798c977@I-love.SAKURA.ne.jp>
Date: Mon, 26 Feb 2024 18:50:17 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/2] stackdepot: make fast paths lock-less again
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        Andi Kleen <ak@linux.intel.com>,
        Andrew Morton <akpm@linux-foundation.org>
References: <20240118110216.2539519-1-elver@google.com>
 <20240118110216.2539519-2-elver@google.com>
 <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
 <CANpmjNMY8_Qbh+QS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg@mail.gmail.com>
 <ZdxYXQdZDuuhcqiv@elver.google.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <ZdxYXQdZDuuhcqiv@elver.google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/02/26 18:22, Marco Elver wrote:
> If we want this fixed in mainline, I propose that [1] + [2] are sent for
> 6.8-rc inclusion.

Doing

-		alloc_flags |= __GFP_NOWARN;
+		alloc_flags |= __GFP_NOWARN | __GFP_ZERO;

in stack_depot_save_flags() solves the problem. Maybe this is easier for 6.8 cycle?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17ec4ca0-db5c-47b7-ba8a-ec1d0798c977%40I-love.SAKURA.ne.jp.
