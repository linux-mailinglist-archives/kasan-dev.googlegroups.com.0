Return-Path: <kasan-dev+bncBCT4XGV33UIBBBMNT65AMGQEN5Y63YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 203E49DB0B7
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2024 02:25:27 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6d41a460386sf5788506d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2024 17:25:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732757126; cv=pass;
        d=google.com; s=arc-20240605;
        b=RTKfM4Gxd+JhyJret09vdbFK4vDLg8+kLMZd97GuBNnfcXY3vXgOb9vWrpCBim/eMC
         q+qBULIMfCEG2FZnOm84q+Wxbm6UT37yGEGIlWG5HO58rcImvz5N4hwh18vRxLEww6vx
         ISNMlnN+96BfwH3iE6Lo0pv395IFoFgsUQAdMF2szguU5jnoQwTSk/KL5h/PtXEJdjE2
         eK3E93OmMz+74E5fEmMnl4sXEg/ghURX3xeP5yLpUoQABaoRq9F99lEF3NHm1eyq7H4X
         4v67A5mXrxpM169QnK0GAHWqc642trB60D2u4gCEWkQJZuPV4OYQwBUm0LfZyUqmUooH
         8s3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=O0EnojJoGlttBJb6SHbpnHxYdDAo5o/kFKYtmlvbUJM=;
        fh=rafYlHx7RSg27SU/BMIOvtWBvF2DCy7ZxcYBROhcKlY=;
        b=Eb+A7xQ1/zE9maAW04eX//ozrJplafJmeC2TEBC0CzKKfZ5FYt2te8Mt5p1bsFn1Z5
         ALWWE2fUTCBCyfHzxTYyxqBU8i6tXVeBoLAwu3+UxtmujGnkYEAOkwvD+xzlJutVL51R
         IckOEpn04HtsCOLKFwvCqYyaWGqhbbpmIAxVLQMv0a957w9HwQ/t8O07wtAiF1KEkai4
         EW+DLc2BvNA7WS6ddCfop5jrLqfvBnQNaRWbziIJOuaHGVDuVyRB4O3Yqwhi8NEncZ2h
         XtHxig70imbDWw3eQ55CQ4VuuJiExxMHgaRuUed6AT/FM7GGadafvQ7mxpLEXNulcQ2s
         0CdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FKmA1PEC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732757126; x=1733361926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O0EnojJoGlttBJb6SHbpnHxYdDAo5o/kFKYtmlvbUJM=;
        b=FpsRmiRki5S/9aBc90TDA+6CBOsUc39etTTUWdCPFBEpWnk690vBuo1AhD/EC7bamW
         7lZTyB8IMXtuok37Zfbr6BiMgpGfm1isZPbh8VnYKB9X5PnAbA9ykmjXRCsg1NRC8wsV
         QWxv+3tOLQbul1NALxqPsrh0Mk1feuCUgfLgZVYqRUrTcmhZcDmpaizb7is/08EwsXPV
         NKpJ2iO4sMxa8iZJKXwVBui6Rn2nn8iKcg0UL0umBA2W7YyJ0Ikv468OP0gbTvgSFEkX
         YY3aNdR7MKDGJoKgXwC7bmKDmRwEp2jzgWCwB/L+RAOaj5M/rICpVz/z/rsPiU9cG95g
         omXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732757126; x=1733361926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O0EnojJoGlttBJb6SHbpnHxYdDAo5o/kFKYtmlvbUJM=;
        b=Fw4hWTpxuRhSRsVs1GwXYnwAaNrzPXyLdui5DqQJb+zSUv0Wp/7e9DzIGTbRdN0F9S
         G7MLAkDoVj5XmbBAuEZ5oyfW0RlQE5VkdXlG+vwuHaenx3r/26uA4LnhEM3d/2iFRAzB
         Tr2S1f82W5w+wCjJjXFt2+iSDbGnpPBrgZ7c+lPQdQLs5lP4TWHPlLEv/ooQpAnW994+
         hO07YsbERBcgZXXQuPAyErnoCPsKBFo6STBANz2NDPfV0k95Y8Z9cRaFYowe90+JYkHT
         uVYQ3PpR7wIhdYxpXfNt1kYBrkWzrH7k4pnJfyGasl2HBFX0c6UgRGh0JM6SrILKfqOB
         5Ncw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOMtnNEVf0C2jhYRQwbaGvgSnohcmgjA+ylPItnnrftCE7KXa/p2AHFKZ6rUNSqoafG8cxjQ==@lfdr.de
X-Gm-Message-State: AOJu0YyccM9Ns6rw4JMEswwiRH8tcOFnn6xyCC/5tCUznPB4YWleEU3s
	LP9idtZ7HCakc9svYGrj0EYYo4leY305jxHA5UKNas9uQNfwxNZv
X-Google-Smtp-Source: AGHT+IHE6fbUlQ9q3tFUEY1RqwoJVAzlIUKYVHZrFnO3HzYivU9uj2XWCdj4P2Q+p+sK2lN3hgtemQ==
X-Received: by 2002:ad4:4eec:0:b0:6d4:2685:938d with SMTP id 6a1803df08f44-6d864dca4f1mr72508766d6.49.1732757125663;
        Wed, 27 Nov 2024 17:25:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:29ed:b0:6d4:22f8:6cb8 with SMTP id
 6a1803df08f44-6d8726ece88ls5190076d6.0.-pod-prod-07-us; Wed, 27 Nov 2024
 17:25:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjDnPxqzfN4BXhrjvwLZcwp8c4DsDwlWuP+mfKYpwz8ZMwjzYzJbH/TRkSckC4gznvBeWV29ROmhc=@googlegroups.com
X-Received: by 2002:a05:6102:a54:b0:4af:4acb:a47f with SMTP id ada2fe7eead31-4af4acbadf1mr4574738137.18.1732757124770;
        Wed, 27 Nov 2024 17:25:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732757124; cv=none;
        d=google.com; s=arc-20240605;
        b=NGDVt9ddKhdy2mLgw63lqbGh1B8ndg7Z9owjhwYV53nldX756iduAW9S24BWGFr3yI
         jidrS3GCmeMg5E+wIyCZU7cqcEEGsjrfZeP9bKs5QkxFeDB8XPeSgtYvtCA/D6v47HC8
         HuFrVXybWpnT2VFhMILtlU0seELIBdFbmVPZbXkpgRxuS19pd25B2fiySFeuB1fd4O+5
         Q4r/g19cFBj+MBee/nT1zipor+B5O+UcYQ78+RiUuE6qOU4o15Rd+6Oh11Z3dRdnPd8b
         5iC4b+eN5HL5i/Cm+nLD6S1LtUA3p5C5jIobGPtljVFfYHYFPG3wq2JAw3APYut+lCBQ
         2PPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VMHYJD0RyO67S2qfb3e3KBi+TTrciPRuK/Snd5+iLfs=;
        fh=OQBxK4ZmmJC8u2Qu+Ck8ew9mxcsSJKEMxGGj8m7Ltfk=;
        b=dTFM/i0yDBOepWh2H1PqdObnfHBAsNLqGy78FnnCYSt6QYu3eSH15+lBOPFdosYX6U
         cSkYHtgw5QdCn0KyQSRdnCUwWfzHbJsjy2dQdgHQtvAx/2wr17lA1TsfuciqVr4kKEUz
         X55+I/whknry5xHVcf5vmsfG14RkBmD3YpHZK1OYb5WZdz5MZ6nLjfT6Rd2eDTL6JGcT
         mPUQWF+rne9fj+BpwKBCJC3OLzL1zjR4kflmYe846QOdeAnnig1YoJ+hVeItU5BcmofF
         HcXSOHUnLQBt71E9rnOMaCp8nr899NQDnlncL0SPOW6oWkotiCeN/2jXGCa7YzEUweIj
         vaKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FKmA1PEC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4af591daadcsi9183137.1.2024.11.27.17.25.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Nov 2024 17:25:24 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D6C3D5C568C;
	Thu, 28 Nov 2024 01:24:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8BCBAC4CECC;
	Thu, 28 Nov 2024 01:25:23 +0000 (UTC)
Date: Wed, 27 Nov 2024 17:25:23 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka
 <vbabka@suse.cz>, Oscar Salvador <osalvador@suse.de>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, Sebastian Andrzej Siewior
 <bigeasy@linutronix.de>
Subject: Re: [PATCH] stackdepot: fix stack_depot_save_flags() in NMI context
Message-Id: <20241127172523.b12b82d150aad5069e024645@linux-foundation.org>
In-Reply-To: <20241122154051.3914732-1-elver@google.com>
References: <20241122154051.3914732-1-elver@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=FKmA1PEC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 22 Nov 2024 16:39:47 +0100 Marco Elver <elver@google.com> wrote:

> Per documentation, stack_depot_save_flags() was meant to be usable from
> NMI context if STACK_DEPOT_FLAG_CAN_ALLOC is unset. However, it still
> would try to take the pool_lock in an attempt to save a stack trace in
> the current pool (if space is available).
> 
> This could result in deadlock if an NMI is handled while pool_lock is
> already held. To avoid deadlock, only try to take the lock in NMI
> context and give up if unsuccessful.

Is it possible to trigger this deadlock in current kernels, or is this
a might-happen-in-the-future thing?

> The documentation is fixed to clearly convey this.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241127172523.b12b82d150aad5069e024645%40linux-foundation.org.
