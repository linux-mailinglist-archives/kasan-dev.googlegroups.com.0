Return-Path: <kasan-dev+bncBDO6RCO7UQBBB7GBXSDQMGQEUVNJOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B1AF3C89DE
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 19:38:06 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id s13-20020a056830148db029049b2f90601asf2402857otq.19
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 10:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626284284; cv=pass;
        d=google.com; s=arc-20160816;
        b=TNdE7ysD/33M97N9Pnus/l7RNcEka/RO4hIUeqM7VkBtiADBXuHKYnxhoSsfWGPW+3
         7divaJBAxN1YH3qHCEhrBa564jwSLoT7PaY0NpLhqb9E1BMeQHHF31mABhDELBBC3Fi+
         ePUjahr9ipAbQmq8uYIEHhLIk3MsPd/fL5w/kSxX5qchC47i+6Tf0LDVok50fUssPbT+
         bMrrzn+dbcNoTG1heE/GH3Dcuva1MK12pdPg7EoQfOefWA09X1jcswUQ8EOnrYo6fpbZ
         2zvcRWOQP+xrZGDEPSm7GvKqC2mnSjW8R4p3oPmHD71DNnOGi7xvRsI134XwnNQ+gQ4e
         kCQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=FKywaPwx8zx5M9J2VbIfX539yNpZsVDOXqGdJ33c5K4=;
        b=nBYmiYG6UHQ0LVjeI6+U2smfSR31brjxoPE5D5WhiRTSIJs0jMFfPp4O5klb9o+Ez6
         cMEfeKKZitGnsnO2tZhFjyEI4wj78bheuUHmaOMU0XZRdsqbwknSn8BiREIus1wPrcA6
         Usaexh5fYbhgb3oRwZpkNk2srwDDjrF9zmEVqB6M/VVf2yOU1IZf+JQj4kVoq6pvVuem
         8eLFcsLR4FVHur2BNNWqN7EbHMxbxm+0vkxEiKxi+rDDQt+tt6ZWBaT4fPRw82l6VsEn
         hZeRNLQScMNM3fgp3BM/HbGPigaZGM0bmSRQso0gidkN2KbWpbS55J2FvQOGKBYG3nGn
         906w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=eMg6FmyN;
       spf=pass (google.com: domain of yzhong@purestorage.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=yzhong@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FKywaPwx8zx5M9J2VbIfX539yNpZsVDOXqGdJ33c5K4=;
        b=do/8ONv1s+4HcbJ4yOtLsRqVljMpoWUSjKVbODMAlSkPYp7C/pllfa89mscROI/KfO
         mcQjkPHGv0hbLt/7OMVHUlL2NtbiL9WQ7rIvWnN7mqTrkThl2+bFdd46PWFiZjMWKGR7
         vwCbjIFMriD0+bdtYQObTg84OdWKwfLrKzNW0oUwREqERpMh3Kqn4mXeFu54HKRt86gm
         PJ3yWaaHcshamSW8dQneRvvLrZO1VjrdN4K4epLd9FzjDZM4vo+8SdtFGZID/2zIf3vL
         iwirU85CW+tCxheZfycEdUrs90+Nh6YaeKiTIcXHM2Zjf/0NhOy+6aDW/bzJRbS2P3LV
         biCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FKywaPwx8zx5M9J2VbIfX539yNpZsVDOXqGdJ33c5K4=;
        b=oiAGyheOOEHhYcEAwYi2jeUMsDQm38XqeUDlQ7QkU9JWrdUqbrY5c1PxeDaKnPgBsA
         IUK7YYTnqJZowfSbaiO83OIvB56xnqkA9KlpOGAYTnb2pEMQJIzCeysBv3iml8QdI4Vs
         0yePS/jwEIT2hYXBAp0q+sB6gw0MOBpcE7crETfbJL/F8qt2ZWV+gnNKCoE94qg/uNAb
         iVKhiLGt4C9gzD/yhxpTXcwRFb+q7tq5yruhKMZc4uqxvCBjMNGyTgVZcW1e/EixoG2c
         EBjxB0JWLLItUlRVQbYiIxhFOkN/POUI4YFS/unZi5beWV5Cc/EekHytkOVKGA1Uwkis
         sxXQ==
X-Gm-Message-State: AOAM532mhSxyWJZ9NXV5P2KHgN1yakonEs9jtYk2LkbM2ugf4WE+3Vix
	rLR30y7E5Ndw3eth2ZAQNIU=
X-Google-Smtp-Source: ABdhPJxW8KtzZd2wA42IPl+S12lwdFwYWx+B09C9sUmnZPdl/ssQRZExm4DyQjNb7wSlpNWkHpJ8Rg==
X-Received: by 2002:a05:6830:128a:: with SMTP id z10mr9116177otp.46.1626284284772;
        Wed, 14 Jul 2021 10:38:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9553:: with SMTP id n19ls325859ooi.3.gmail; Wed, 14 Jul
 2021 10:38:04 -0700 (PDT)
X-Received: by 2002:a4a:96c1:: with SMTP id t1mr8847850ooi.83.1626284284405;
        Wed, 14 Jul 2021 10:38:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626284284; cv=none;
        d=google.com; s=arc-20160816;
        b=A4jlMIlDAtJMmmlT/DYNnBgtaglF2BPIC+DDBJlRr//yEJoJSnd0EtG9VCvDS4F1RS
         sHk1duJ1gntOXxBaY6cYAQJ5DA7LRFw7EEkN7x7rfrqj++h8dgCk1ez9kJrsMfFcYWAH
         vuJ8aUwBzd5oud3Nk0XJ0ZK9Fem2qaWFvhNRxI0qBsMACS14/QgQVQpbHgDKuCW3C1ii
         ImKx1B6FtoCv9qLknTlvYySMdW8DG/D5nlrESY9+66sdbuorLhk+YnGKSXeoKZ7E4L/U
         NeiSsM4ChC7zRW4AfENMHGC3a539MRlhytCjYQ+K7EZm4EJsaLbjQgP7n6n3yuhILWxW
         3ukA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AkN/g8848yQUrVMq0VBpWbOyu8YJObYWSKkoyUzYfiU=;
        b=rfot4ZnqwIHFY8+MdQQ3YQgvTstc7iA0nZZd13er9yS0hC7bA3L3b+s2AgygE/pBco
         suKRKv6W/LZZ03DVZML1hT5UYSTDXjFGNfnfsZJxp4dvBLPJ8OduidAIb6gCrwMkf/Ht
         OCyxb8EzUJ1wZ0U7467Xcv4bkgkHYYEFlDafzD95uO66BcNGaR4mZUgRef6x1LN1LvTE
         tX5bPfGPDQHUz+kTGU371MxlYgsUV+UAiQnOoeElqP+zNYOeSxWCDGgBMZoJTdSS7LYH
         xyODbxFI/60XRFSDKsJ+jlI6dOymsnU3xo3NEsRKI1wbW0FfIvH7Rn5uyyJifa3jV5AM
         uPYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=eMg6FmyN;
       spf=pass (google.com: domain of yzhong@purestorage.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=yzhong@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id k24si319755otn.3.2021.07.14.10.38.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 10:38:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of yzhong@purestorage.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id g4-20020a17090ace84b029017554809f35so4240354pju.5
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 10:38:04 -0700 (PDT)
X-Received: by 2002:a17:90a:6a43:: with SMTP id d3mr4872708pjm.15.1626284283944;
        Wed, 14 Jul 2021 10:38:03 -0700 (PDT)
Received: from dev-yzhong.dev.purestorage.com ([192.30.188.252])
        by smtp.googlemail.com with ESMTPSA id d8sm3855074pgu.49.2021.07.14.10.38.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jul 2021 10:38:03 -0700 (PDT)
From: "'Yuanyuan Zhong' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	corbet@lwn.net,
	dvyukov@google.com,
	glider@google.com,
	joern@purestorage.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH mm v2] kfence: show cpu and timestamp in alloc/free info
Date: Wed, 14 Jul 2021 11:37:55 -0600
Message-Id: <20210714173755.1083-1-yzhong@purestorage.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20210714082145.2709233-1-elver@google.com>
References: <20210714082145.2709233-1-elver@google.com>
MIME-Version: 1.0
X-Original-Sender: yzhong@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=eMg6FmyN;       spf=pass
 (google.com: domain of yzhong@purestorage.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=yzhong@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: Yuanyuan Zhong <yzhong@purestorage.com>
Reply-To: Yuanyuan Zhong <yzhong@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
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

> +	/* Timestamp matches printk timestamp format. */
> +	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +		       show_alloc ? "allocated" : "freed", meta->alloc_track.pid,
> +		       meta->alloc_track.cpu, (unsigned long)ts_sec, rem_nsec / 1000);

s/meta->alloc_track\./track->/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210714173755.1083-1-yzhong%40purestorage.com.
