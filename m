Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUXMV2JQMGQECEDB4GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 79D64514616
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Apr 2022 11:56:35 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id i12-20020ac85e4c000000b002f3914cb0c7sf2221857qtx.15
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Apr 2022 02:56:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651226194; cv=pass;
        d=google.com; s=arc-20160816;
        b=EVxBYOVqfwZQOE8fihA0BTGxyRD7bLUntW49l2MaTDz2KcdCKvVb5fX36TmVacVkD9
         cCWMpM7QoVlQdW82gnhjn+Vri+y/wXs5HoP/UkiFdjKmWRfJtL3n7wJdFVghqcGY5cL2
         KWKHTAWpJSpOOpi+ye1SD9ysnL+pirOq8zOu7gsEUhyMcsEllmXNzP/d1SPYPz6zzJG9
         GW5LkyNMyQsQZoMqS4RkvW+oWI8+p2To4QDhb9pic+qXetdwIfzNhch8tifhbujJyUS0
         vN6AgjWK/wUfISpi0KQ7Cm6+pKukKzv9ROFtkVkloLC6T3EdyDETvKF7mXvOo5R+8piB
         Salw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=oYn9/0zFJDZNbTY5ZzpLlTEHD7wriNONuhSyX/XyUiY=;
        b=LYyXc079wFMZ8vy386iBmJ8Uz9hg+DVMuC6wYH+XAMRnfxjz4pALkA3dY7lhu5jGEj
         +FZYJ7MfFCHoNi1wmAZULBMUJrSRJZQZqatk+0VTjx+MMOxNlY8EEXK82RKHBLn5JqDl
         L1l7UDC4HUgPMSLYr5uu2dcsVLC5eDQ2xE3XeQ30umduoFAAxj+1pArfQ2+jzuAPGr7m
         UWjiQ7V5Cj778oWSFCsFlGKSgELRkxKd20bJYC3fT7eKY3F6TODXOpi8UXuHT/2kai85
         dhcxWTIhfok/DqYPxxfL0K+Rt9GApIT/VGEruZ8jhM2oPbtdnah51nDrCUlKyB9+aZ29
         Lu8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ljEEUfWi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UlkbKJTm;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oYn9/0zFJDZNbTY5ZzpLlTEHD7wriNONuhSyX/XyUiY=;
        b=kLHrxdM72SEvZMzE493wRRIDXtzha9AI/+/nwSNis/54cR27VHOdHcoe1kP8H6nYjI
         IxA/XMX0rXMNZ/2rbws9+tOD+jcgdfPB8jTzDP4aW1hTxN83LqoyZ83E7n7N+7veYAS8
         eDPtS+WuA1MXzdqLNlBk32E/4mYbIv3wu3eYI95gjkBxpF7bfF/ARVgXiJMJJNGTx36s
         mpaYzBQ8/w3bg5BqokwJlj/WcdTCN1bYu4Nu/x0uB0sXqZBLp+P1oy+kUvlEAypyO+br
         6KYXjvaaCu8LX9lqnXXg63ZBxkLORPwlaQ52kw+ZEMETr/4DpAcW811na4ypupYRWcjq
         EMoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oYn9/0zFJDZNbTY5ZzpLlTEHD7wriNONuhSyX/XyUiY=;
        b=RSZYo082GIrxeL1IKj734D3mmBdE0+AFqg10PW898i9vyH9JnZjlbDlotICW3JD9Yu
         YMQX7+X5rTwt7ka4GjYdU1TNqeyoHs8aZyQjDDQ3MxpfBmssB37p/bnxIxgT0x/tJ1Oq
         d1xd58jmHjkxjTmf92/Uv7BjwQM7RCqQGGBbx8pq2NbF8aLFfEAHA3soJgBzNYKHxsXB
         MtR7YmIFGjDNSHzGLz2O6enT7/yImJlWNuTqSrVAnDHmliQMhai0CUHl4r+y4AmJq02a
         jteJrakvAVpsk5SFrJuzaeRyoN+g1OY/LE02NOE1O94u2HSNusSDN5IbaZXmmNIpxQzL
         1PQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53072RcNwAhEVPhw5hIaQlpCtXnVetkJaPlV7lUegZa+mkWzJhcj
	TpyBF2005ezLwpTZ8g8Tg74=
X-Google-Smtp-Source: ABdhPJxMT+YIo0KDtxelKfAVfgfBzGFf3tJajYB/zmXiV7/xwv7MP6yX+ZZVCxRi88Ynk8p8IlNBOA==
X-Received: by 2002:a05:6214:500f:b0:458:51c0:ac8e with SMTP id jo15-20020a056214500f00b0045851c0ac8emr454954qvb.3.1651226194326;
        Fri, 29 Apr 2022 02:56:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2556:b0:699:fc29:e657 with SMTP id
 s22-20020a05620a255600b00699fc29e657ls1323874qko.6.gmail; Fri, 29 Apr 2022
 02:56:33 -0700 (PDT)
X-Received: by 2002:a37:a853:0:b0:69f:7f28:d90f with SMTP id r80-20020a37a853000000b0069f7f28d90fmr10291575qke.385.1651226193728;
        Fri, 29 Apr 2022 02:56:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651226193; cv=none;
        d=google.com; s=arc-20160816;
        b=KQATSMa35k98MzPf1QvRry3p7L4ORMOoEWSo7qbcgP/DwssBYNjswpY42fx4F+O5ru
         lIZlkbM4nED+4bpUK6fC5f2gsox2/D3x0Wq9pbFtkDYZ3qwph9MkZOnDDdpPZd3CWzU/
         tjqf5Gkbylzrs3a+8FvnieMhUGjrgPHULNAyJVe1xpcz0hkpuU9LnHJMulwGGGEewYq3
         esP5he6zwn0KO70ahavYP/nmOVH7RjnxImOyfd9rLYS1RoPaYS8ZcFd61lioB0nWW4mL
         KIhEC0ftrheF4XqWnL335RLRcBDoCZHzjIN1sDaLs9/9E/beTq2UtOVFD+wkNtNjBxWR
         6IoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=c50DF01aKj1CW75/eNJw3BumKm0+zPFfK1oMV+pk24I=;
        b=B6AnL5E584nEN37TE8Ohy8L4fwZX8dS7GYd6KuFMaFsok3IhCVd9hcENKH5+Yccm3I
         XkSZmDb6JCWuCHrHwjMQjs0h+FfPs80QAQtnrActpIt+oQuIQ19YlRrZY1JERnRxfXp9
         WtIm6nqJEyjt1lRlHiwkRvZ2YLQvx8kgj+wbXt83vr7NK1O6F4TRUI/YENGeGkZe+kgd
         G0JUGQqoIdl70EfRdGz8IB+GzW33seFto2Du1XwiGV0JoRXDBpGkVj5ygL4BG+Z7YdBp
         GEFG/628z+8YCMrWKiCOyGKUec2mTgBGEcsA7GtW/xOSvhjzeAzEyuDn7b5/Balh8t/E
         k11A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ljEEUfWi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UlkbKJTm;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id z12-20020ac8710c000000b002f36f4c45dfsi565985qto.3.2022.04.29.02.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Apr 2022 02:56:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5490D21877;
	Fri, 29 Apr 2022 09:56:32 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1953C13AE0;
	Fri, 29 Apr 2022 09:56:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UNF3BVC2a2IZEQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 29 Apr 2022 09:56:32 +0000
Message-ID: <2408e290-e016-250c-9e54-350fb923d162@suse.cz>
Date: Fri, 29 Apr 2022 11:56:31 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.1
Subject: Re: [PATCH v5 2/2] mm: make minimum slab alignment a runtime property
Content-Language: en-US
To: Peter Collingbourne <pcc@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo
 <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 penberg@kernel.org, roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com,
 rientjes@google.com, Herbert Xu <herbert@gondor.apana.org.au>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
References: <20220427195820.1716975-1-pcc@google.com>
 <20220427195820.1716975-2-pcc@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20220427195820.1716975-2-pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ljEEUfWi;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=UlkbKJTm;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 4/27/22 21:58, Peter Collingbourne wrote:
> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
> 
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
> 
> Before: 169020 kB
> After:  167304 kB
> 
> Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Acked-by: David Rientjes <rientjes@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Andrew's fixup LGTM too.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2408e290-e016-250c-9e54-350fb923d162%40suse.cz.
