Return-Path: <kasan-dev+bncBCT4XGV33UIBBU7EXKXAMGQE7UXQ5UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 607F88572E5
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:54:44 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-68eecf368a4sf18680416d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 16:54:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708044883; cv=pass;
        d=google.com; s=arc-20160816;
        b=WE2ibced5tTmLE1G2+PBIzopdwJ6OhKPHwjx2ORba155gDlIkFhN1PoF64FmU+D5D2
         YB4pktPZ3fte3Ly/WT12YdagxiDNwSVnFf+5y4ksBOw0ptPBDEw8RmWjvKgsLNb8pZ9B
         0kozCrGDW8xRFpXYYAa8Ieny9dVf76vnyZAO0EXI2eBIphAmWK97eaYFbFPT8zzndtTS
         H6lAo0EULO1xZfzlcRduAxCY79ME2aYrw5aJ+JdceLp+N3nYwXNQ1bQisKUHU40LNPrE
         8zTgTBDHSQlcatnLgH0TMenzC88Y68KNHiIObKHov9OSy21n8NUjORM7USbFOgOyhj4T
         MJkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=52RtDIlnMllil1HWaCJhxTnSPLFUR4qDsAqETAVUI84=;
        fh=8dztVbFtCnpwaNnh8Y/iw6l6wqEfJ/Btq6rKK5c8Npc=;
        b=hQLg49G1zc1Gxo/rL/faVMBrqqElEHdBRGPPlWlf6KBB2ZhOknOYmo3+4IN0UoaMi/
         E4uzkWc3h/Y6qAGYJhvKyiyPoWeQ6GwxFB9L1uimDxDME4SFErWxHkczBOAjb3ZLvRVp
         /50wDS6PatRqApn9LCSYIVLYr8kz4RJkr/S4y8gpOhXTvvWSpAu2tKgt5YcQDBaWRNA5
         p5aCiQn5mTad5azcNTucG67BDNZj7+Vnu+muG9DLPsYbLxS5QuYISGg/TtUXrxhph+mw
         JS9xA3PJDxVusEdrXQSlYmsv++9rTkTVc6Hm2fJUm1RAoMwJY+iyZKBGbsg9/Y28hR+u
         F8Ow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KYXR1+er;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708044883; x=1708649683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=52RtDIlnMllil1HWaCJhxTnSPLFUR4qDsAqETAVUI84=;
        b=tK/81vMmlZbtAExM4IqdjQUG6QmUP9qbaoyeZ2JJduOSxKQ6gfqqQ/NVAY7dTcMSzH
         jB+2/sUK08Xy7VRr6aN68s7Fs029joObYZFtFeIF/DNWoaR6UH231Wj7fzs/k9+8jipU
         NAYGvAibSVASlWzsNgIiWArFWT1F5e41FS21T5OSH0onNAGjZwEXWcbwa+MZjUyqH8X8
         vi6j3szc9ZSk81zxxKPMS70LkS9vQIsMT/6K85Rm0Tj/JycJs2BYX2z3g58GoOBnDNDC
         nDJKXgGA52zyIHqcRsuSDeegg2x0K0iIIjLQzlQ59H0oRfZc0lrSrLHi3y2RNK6WxxZH
         9sAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708044883; x=1708649683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=52RtDIlnMllil1HWaCJhxTnSPLFUR4qDsAqETAVUI84=;
        b=wZqy/VhHaf+BGOMO7iJkzFlW8YKTcJlg8D4OxUklmw9p21opygml5nNuBU7rkUhjVM
         OSjl+aEmv3FV4QOroKxAePKZieRJ+XLahYl5L4e+Hjraue9sEFArX/PESwCHDI8WDW9D
         UBQusocFvzsMSHPnY8W3B4H0x9ifOAn8/QdSFLwjA6cMRyw4x76sDBAQUoJMHIa4PuGY
         combuKHr0j87o6PMDiz8wnTk+ptdaOL5LCqPIN6HU8AoA97o95Y26r1pFiMyHLyFHcUY
         LfqZHr+1/c/653E6F7lA4JCMAMqvUCkG0DnfKz4QrfRUTcTPX3GPIN7cfvJw75mCGWvu
         uwXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdCVFtOxcBDZPPW4qSHLpSruG1pq7wv+xOh4NpLNWReb92tX5+oLatmtauiyFY/sJn+nggeGpyHTuA+4P6zLxukrOtnRaU4w==
X-Gm-Message-State: AOJu0YxK9rAXqgLZrVdTyqA4MP3fJb8gOZSAxQKRNbZPXiJtxnmoE3AH
	YNrWRnbGAeYem4TxXzeYAAe4/h1B75jZiA+1Rvx1LlsojBfVFIG/
X-Google-Smtp-Source: AGHT+IEAMQFcVtVwV85Dg/yHcIjOJU+sgBzRAqCUCBuE8/ux/xb85GQgWso8+tMHt9A1yLKAdSW4Fw==
X-Received: by 2002:a0c:ca04:0:b0:68e:f8ed:e292 with SMTP id c4-20020a0cca04000000b0068ef8ede292mr3139563qvk.26.1708044883207;
        Thu, 15 Feb 2024 16:54:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5f89:0:b0:68e:eeaa:8248 with SMTP id jp9-20020ad45f89000000b0068eeeaa8248ls420441qvb.2.-pod-prod-06-us;
 Thu, 15 Feb 2024 16:54:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVnY+v8TKPxoZFZhLZXw5IgPPK70C3RMRicFiDl1fCeEITbFGXPuhAmJAkSyUVMvBnqUyajWDFMYQ38sQKcEn5cXbu4YiJ9IAtCsg==
X-Received: by 2002:a05:6102:1957:b0:46e:dcee:a378 with SMTP id jl23-20020a056102195700b0046edceea378mr3358665vsb.1.1708044882225;
        Thu, 15 Feb 2024 16:54:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708044882; cv=none;
        d=google.com; s=arc-20160816;
        b=dBb8iIlCebBw5mHkzMFuUt7ZbxF0VwxmiOgJj4iLyrin7J69PT0ePu3h0re+khlIZS
         PDXLEKejXTjtOPulEV3rcsNs1hHQqb4bIVnScEDCgUEmhoVG6sHnFSWWxHq2EbIeP8ik
         T8jSAvsRWYnRy0g2m2ncZ6XCoPawXXGYuUKSjxqz8yzq1Ren3HLltqRfu+rxfaiJPozf
         c7TTuGNbrWS/kCQIC5E06BXucngOaKqzcZSRz0iAK4wo89Z5XZNgbLRablxua0B6ARNw
         lXgaFvAR4DVIsHaWOVqZfpqHfoZRR10XeZOrTdDwOTWiNRwB19MalmC4J3sHYXl+jTr/
         DfCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bNHj95k9HjXwquwXTV4JxeGBU5zX1SyQoOc+W+JEAgY=;
        fh=Q+NjIMzzlfiDlrd5JfV9rUsaLbrty2zFT+Yb5/MnIAc=;
        b=yw7ZTDy6bicNziV48gocwJ8j/bp4+AP5QrJV+CfBS7dzdc6ynVeqeS2Hv+5QK1IrdK
         q62ZjoT7c7hBJhVXu1/d68gVRXR51acbWRgY6rGYhZ5NUicn9mKJH1Jd4Af7O/5hjMF/
         kii9ks4GZ9tWg+/YU2Dcp79H0MgCOmb2PsHBkEWPLE8sYPT3Mw0s8lQIo/IcYNYRlJXk
         42YHkIcwnyonSLhVe9FUmOhglhPzKx96RIO/7ZIXTISG86jLlzeNNt1nMkXbr4YGF6lN
         Ghxm6tTKi0oINbKuLxhT57O3qRPQtC6ARdKsRFuuPN6Y4nEGMParBnrJr8YnY18crpOG
         YJOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KYXR1+er;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ib25-20020a0561022b9900b0046d3986403esi462032vsb.0.2024.02.15.16.54.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 16:54:42 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7B59460FC9;
	Fri, 16 Feb 2024 00:54:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BAA5BC433F1;
	Fri, 16 Feb 2024 00:54:38 +0000 (UTC)
Date: Thu, 15 Feb 2024 16:54:38 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-Id: <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
In-Reply-To: <20240212213922.783301-14-surenb@google.com>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-14-surenb@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=KYXR1+er;
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

On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@google.com> wrote:

> +Example output.
> +
> +::
> +
> +    > cat /proc/allocinfo
> +
> +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc_order
> +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
> +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
> +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one

I don't really like the fancy MiB stuff.  Wouldn't it be better to just
present the amount of memory in plain old bytes, so people can use sort
-n on it?  And it's easier to tell big-from-small at a glance because
big has more digits.

Also, the first thing any sort of downstream processing of this data is
going to have to do is to convert the fancified output back into
plain-old-bytes.  So why not just emit plain-old-bytes?

If someone wants the fancy output (and nobody does) then that can be
done in userspace.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215165438.cd4f849b291c9689a19ba505%40linux-foundation.org.
