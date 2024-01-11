Return-Path: <kasan-dev+bncBCAP7WGUVIKBB64EQCWQMGQELIF4M5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id E43A382B13C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 16:00:12 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-429a30f4997sf36207711cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 07:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704985211; cv=pass;
        d=google.com; s=arc-20160816;
        b=hInGZJeDq4e/ndif0mBJtaddLuN35LR/87QShPxES6fSXnaQRDj0igQUxdDvhK2/YM
         z7xnTcFxDY4qhEb8Xtgg8CL3eFl4VD7bw6cdSjnHTqP/UpFKAcUhrCLJqBraBoqoCjef
         CSKWHc1XUvgRVL2Hn2hH1rfaNzj0CQNk4HT1CCSWIW1GSBKTgZhZxlMs1r6dhOC4qHvl
         qyS6o1AyBZMEi2Equu/3U3xEVGlzaYGi+wTamtcbCRQdGAAQzgL7ZpXJKZYZjJwndqWr
         WYH7yxgI6VavS4hVOIZlQ+sHv2rgFh8Cf+zV3aO5J2RHl2XHcfYLu40w4o2BEj7aUjXq
         YzGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2ALZV6K0b14DtTcWIKbmZBMmrCRkVNi2yLOJajMvOJI=;
        fh=J3cbg2eceuRKQ8aS2eZNv9qH6xs6tXvyiBSjCCQsD7k=;
        b=V5u+SLN7uaJdVh2x9G9tGp6nwmQpOh4f4e44God3aHBhBls2UMAszzBZ1w48bq5P6E
         OU6s7UX4xVRj5JkjfHds3g8jJRRyLHs1vwpyzwgJuTYt6zO/XiszdV2cIX9dSL38lFU+
         RsSWW8cSB3IITqNJGP2Ic4vWEfr61GA1fN7J8cFqc4yVTdDUdqrRl4OJU686h0cuNgwQ
         /KV4yZ7J0WGhzco5JNpw/Gx99hQ/XnVhrenuQhviVTP8R109xZC1pcHeMrcwtpZNT0WD
         G0gW2gyKsApYmw8cH9hjD8togrTp69FYihjYwQTyQ3RCh7AETCcBLBxaD1jPNRTeVzgk
         fMVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704985211; x=1705590011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2ALZV6K0b14DtTcWIKbmZBMmrCRkVNi2yLOJajMvOJI=;
        b=eGsyqlRY4WLmcvk3Mt71sHOHNrJ6bBRHaB/aKYvgZ/LcyYa9EZlNBKqHRS7irt3G4Z
         Fg/8ahZpM5pWA6ED93J2Inn4/YuSVnqVFIMyKKWVFtVM2FMj1LdrAU5UVt67X5L++sGq
         VyCq93lMnJR3X23Z5g8L9agB4ovvsCcCv+qMI8gPt6uG9iNZa63IPy0byjIHPHXocjee
         tho+YAge3Pgp1QC5dHxYDDJU4b3mB9491A0CBa0NG3QRC/7nSv9B9WKLolwl2liiR+8e
         +Ys+Uz2wy9uMOXbmebq1CD4zyxUEUGyEM5zQN/KJGbXxn7UiH+kRsc/0dAun6rw1aK49
         wdZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704985211; x=1705590011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2ALZV6K0b14DtTcWIKbmZBMmrCRkVNi2yLOJajMvOJI=;
        b=sSYHYNPaA8PQ9sRkZolk/m2i31tsEU8xbnUibTgl2hOXO7fEX6uURe44dcl+xJDC8B
         /kSKMfYZKoJdpXcIQV7PX72+OXnLkp/EIU5z8NACwMhLuOqIAqU42EhUiWL6+M0C6FeG
         NOkQc3/Zlup/SzY4MJy3DaI8wpSisnh4JXUHicke4Yp7bzwd9NQN7U2F99bmFn/FjPmd
         Sr6PJpg9Vcuaz6uVXwPJbK75j5hCXuA4uvv+bvj7sBqrduSPMPJYc0WvH72SCAeB9dzU
         2fHNP79K1K5JLuDBPGRS820Hut9WqTHefCxj4guwiYrt6XTt0X63kwaPhDSxLjvLYSQu
         h9NQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyANsfCYIp5nNnZknA1nxSketlhiHRHqCbQeK6IDxXqpu4VHQQ5
	T83FU08Apc4TPrWKQSf3EGs=
X-Google-Smtp-Source: AGHT+IFnwfT4kfLSjP+RZPYQhmEKDTUkUYV0CtOW8OTNg2JzmIbfGz4haurhX9QhRJWvnVc5FtUlew==
X-Received: by 2002:ac8:5a15:0:b0:429:992c:4d73 with SMTP id n21-20020ac85a15000000b00429992c4d73mr911972qta.124.1704985211290;
        Thu, 11 Jan 2024 07:00:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:764f:0:b0:429:7f20:1268 with SMTP id i15-20020ac8764f000000b004297f201268ls977122qtr.0.-pod-prod-06-us;
 Thu, 11 Jan 2024 07:00:10 -0800 (PST)
X-Received: by 2002:a05:622a:6:b0:429:c479:ec32 with SMTP id x6-20020a05622a000600b00429c479ec32mr793092qtw.93.1704985210257;
        Thu, 11 Jan 2024 07:00:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704985210; cv=none;
        d=google.com; s=arc-20160816;
        b=aix4Ja2Q0iaxuHh2CbV3iUpNIX3OHrG8ifNOPJMF5z7jpTjaIEBQyRsouT+hM1JX2/
         h6Er+2eEazCv+duKq92rz2wWKOXPXe2HiT9pmrpU34iXFa1zggrRm+uUJi+SIV5wy9jK
         Zd5sp/Cdi0gfSvGXaZgnccgG3/xMu68tfcI3ZRyH4gb1Bw3icQAjrWaJiTQpmmC41zJ6
         l8sfHyrOPUS/fphGYSAShv1JoOierXVnqcAhJCG4lTRkoLHdWcL1gK+EztbWpK7kDs3B
         BMzpBmmO8KHL9V2CQX89s2Z8pBzDb8FjP1v3Jr12DxLbDWBHk45YA4fggJWiylT5AZdL
         IJIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=4+3rv7hnWSdUPqDrA+K603o72Z9Dz7Stvpq81kICeiQ=;
        fh=J3cbg2eceuRKQ8aS2eZNv9qH6xs6tXvyiBSjCCQsD7k=;
        b=mmkMtShd4i9YuO13DFCcKi/GjdoZiJ3Lj1cUZMI70IgT6YqPw2m4PbL1Qv/0oCr0N2
         KqCdJM5tc4KO8no1FGm4Wvfj6lRW29nycIf6MwXpLXACC3nPIi3UQidxKGrc5hIKK+pB
         JHDAbcQqD97w0hmEzjrdpFA1FEaOhYv2OvLgRdz7ZfJGLB+OJHnK7c/8QjWo+OWa5sa4
         j8ikQ+gN7mk08uQdFhVumOp9YA4+TfKRNTikSc0d+nqC+B6GQoCfPs2+VDLSSRnbsWPi
         6Cpv3aKzd3WH37DyHDRNfhOzeyftSISSdF4mM+YdlyhJnR6EcdGNItRNCYkg2RTr7vXq
         rYcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id f13-20020ac8134d000000b00429c8a3abbasi46406qtj.1.2024.01.11.07.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jan 2024 07:00:09 -0800 (PST)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav112.sakura.ne.jp (fsav112.sakura.ne.jp [27.133.134.239])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 40BExr1v003615;
	Thu, 11 Jan 2024 23:59:53 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav112.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav112.sakura.ne.jp);
 Thu, 11 Jan 2024 23:59:53 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav112.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 40BExr5b003610
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Thu, 11 Jan 2024 23:59:53 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <b1adbb1c-62b7-459f-a1bb-63774895fbb3@I-love.SAKURA.ne.jp>
Date: Thu, 11 Jan 2024 23:59:53 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linus:master] [kasan] a414d4286f:
 INFO:trying_to_register_non-static_key
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>,
        Andrey Konovalov <andreyknvl@google.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, linux-kernel@vger.kernel.org,
        Andrew Morton <akpm@linux-foundation.org>,
        Marco Elver <elver@google.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com
References: <202401111558.1374ae6f-oliver.sang@intel.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <202401111558.1374ae6f-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

Commit a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
calls raw_spin_lock_init(&alloc_meta->aux_lock) after __memset() in
kasan_init_object_meta(), but does not call raw_spin_lock_init() after __memset()
in release_alloc_meta(), resulting in lock map information being zeroed out?

We should not zero out the whole sizeof(struct kasan_alloc_meta) bytes from
release_alloc_meta() in order not to undo raw_spin_lock_init() from
kasan_init_object_meta() ?

On 2024/01/11 16:29, kernel test robot wrote:
> [    1.582812][    T0] INFO: trying to register non-static key.
> [    1.583305][    T0] The code is fine but needs lockdep annotation, or maybe
> [    1.583887][    T0] you didn't initialize this object before use?
> [    1.584409][    T0] turning off the locking correctness validator.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b1adbb1c-62b7-459f-a1bb-63774895fbb3%40I-love.SAKURA.ne.jp.
