Return-Path: <kasan-dev+bncBCLL3W4IUEDRBF4HYSRAMGQEQJPZOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B39EB6F43F0
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 14:35:36 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2a8ae11c8dcsf16985381fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 05:35:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683030936; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4Ex3VHpi4T1bv9iD9V1NY9Yt0k6yyZ84Z3mn4giMVk40Ux6OkTSnmkbv6EdF1zqUd
         EVYb7KgR8CN+itR9SMuP42baTV4CVdOxpmLrMQmaYTMLu2WXifcToySs9KWl2DVXbVKZ
         zDHrsI6uJM6rnPGLvnAjvkBdHc28RwOO85GZfn+dbTFsIAVwa2Zl4P1E+8mDtC8egCmk
         rAWfvh8KBaqdh8viGJlxaPtTXFw/OK74boZoWXA/CBYkPEJXLTb3OmmM62pxH6BwtxLj
         q87M4mVm+xC5P2hjPh1AeFAXEInjwblOP5pqFsJVsefnRJNGapPXqecRg6jB9hhbsKxk
         jURQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=mcZmRYdpD9HL6oYZdUa3pKRceJ0W/XFnL20UsOAoPaY=;
        b=p96z1M2xzKfnq68FBzLXAEA10fySIq3gX7S6RW6bTQwYfBw5qiSPQRIfaYuz8y4P2V
         +8kL6XscG7cQ6K9Xp5i2cUv8ZNMEc4qKEYbhXkI1p4IwGxl4JkPG0gslc4VPywjFMxXK
         3eKILOTlFugrGfVMBc9IAFeNthHP4UtA/J598cWdkHa5YJAO9qBEQwe+358aQ3nHidHM
         c57LqnBrcveqC/pB3L9aUq4Lg1KA4qLcQk07trZzL3cTR/9kmsrrEv9I7zvOmRa7Jkvm
         yvDgAZnO+X0ojs/5hJYZ3wTOOrV50QmrXdLdK9iumIQWfYKLWpkYo3XF/fq0TvHS17CV
         zLLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=pvJgyuyS;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683030936; x=1685622936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mcZmRYdpD9HL6oYZdUa3pKRceJ0W/XFnL20UsOAoPaY=;
        b=CY2GoKGjQVavVI0EktxdGHesHFwVl0Q2GQINsgtOurMr/gabZo3p258MMqpzhBqv2f
         e7Y2AnSEXU1cXzLgC9UnpfC06o5Ro1FXgN4/FHo5yf62E40ky+Cj3YQOA31k4KQOIqMx
         wMz7HzZcNMofArIxRLgvZEDJ3seUX9feThz5tqsoa2EUfNM1VcU1ehnxGFFtKv/ell5M
         abeKxXsbv0prFOM1jK3weFmkK/t9u4BJ+ZZJYmGPDS9GwcAqO/3RLgdRsKC0HIK5upRM
         MK4ISKieP5wVPkWtZ7Q50RQVAqRR/pXZlt7QiUnEVowlGJQJ9Wo36lfpTdfrYcHSYxPm
         mZYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683030936; x=1685622936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mcZmRYdpD9HL6oYZdUa3pKRceJ0W/XFnL20UsOAoPaY=;
        b=I7s5v86D/tSp6tYyVYWRU0wJvFE6/qyZetWmPv0vbeT5dRRrbdpdUxR22Tc1UJIoel
         ORA79Nw0iz5yYa/TjH1Kz8VO5iAvBxq/dJQvVHwtguk6TvXyVPPniiWvwjZ1hu6wh6Dl
         6q95OXQivXMDxz3ulNDSg21YeyqVGVwepJPh8BSqaxCSiGyHMaVoqOPLEWWKAYsEKIWM
         3WSlAJJdigdfmXcP+yhzk2aWWKc03e/yNwYljQlrwmdhVbgMjDQRXHcgL8Z4U1Luxijj
         jopoY1uVZUiI34a/FDgk5eeub60LXRw51WWy1r45Vr50S+hUCRJSkV6pSsvtbzznpXiv
         wuVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxtmRT1t6BZWoUrHRCDfY1Cf10kWOB6FFnpYBwOBplanHBUh3BO
	x6yWvm5uCK69XDi6ugFs5Dg=
X-Google-Smtp-Source: ACHHUZ7Bz59Yq5LNChmsa3R43f3eY8qc2vSiHK5uQ5QDyesyXleTlk+Gn623/LttI8tyXufycoPMRw==
X-Received: by 2002:a05:651c:158:b0:2a8:d843:f9f8 with SMTP id c24-20020a05651c015800b002a8d843f9f8mr3997964ljd.7.1683030935846;
        Tue, 02 May 2023 05:35:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c2:b0:4ed:c108:7214 with SMTP id
 k2-20020a05651239c200b004edc1087214ls138371lfu.3.-pod-prod-gmail; Tue, 02 May
 2023 05:35:34 -0700 (PDT)
X-Received: by 2002:a05:6512:14a:b0:4f0:af5:5560 with SMTP id m10-20020a056512014a00b004f00af55560mr5224912lfo.19.1683030934494;
        Tue, 02 May 2023 05:35:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683030934; cv=none;
        d=google.com; s=arc-20160816;
        b=gxZQ7/WTyMS2ONZAEg/DlB411BfLQzBdVhVF4FQVj+3ejR0+D2DspL4LmlqtwrffH7
         MMk84OFcwtuZ2HB6TC4dPbShDX1pfJvr0wSM9wjvOrU3lmq87qR7sfrvGRHKi1Pjs/ij
         7xa9ftBN4S7ebUNmtgJkmhcFlpYAPhhv74N1+T/wIx5++1KqrrALvo4Dzjrw+Ojz+XMF
         rEQqpkrlBZLjIrGmh4WIoBikdWq7yQctozSYfH4iy3KpCoOnJH+PgUTOr46X0+zZZMvP
         TB58Wg8NlT9ZZsFDZjGaSgwJ1Ktjh4gbJDlCAjCbkcdQ2gzpVbAwH9rYRB3NBM0R6xzB
         le0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GBlnaFLww4aAN7ISgMyAakxTR0tEnfGc/VBHA7948aA=;
        b=UJqpWdP08xEEQKISX7+dXtPpaP0aCnExaFkokL/HRgjZu+a/oyjngoHo8ezarySnjV
         4KzqXRpIUaMrnF/jJGyu+8uGA4g9M+O4iiZOxK9XTDj1yDKOJ3/VGLaMtYAjDDPBJrZP
         5eGWOlhEZLpowbkcvvvx0i6KLulT2YgFb9xPz+Il5QZm8g8Zf2vqsMqFmiXeX0+0J2iF
         1pQ/9jmfdVgvdEHfMEqkm9bee8YF7OHM6oLH/SKEeb2JHDyQIgCFYh4mw+2gED3mYXKV
         lzqPgUK51TwWLNbDFDHPe0I2gMguTRSju9Kp3pb7IucP6OgCZba+clv026obNkTx/WzD
         r1mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=pvJgyuyS;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id be19-20020a056512251300b004edb55cd1e9si2213732lfb.1.2023.05.02.05.35.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 05:35:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 0369514C1AA;
	Tue,  2 May 2023 14:35:32 +0200 (CEST)
Date: Tue, 2 May 2023 14:35:30 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Alexander Viro
 <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH 03/40] fs: Convert alloc_inode_sb() to a macro
Message-ID: <20230502143530.1586e287@meshulam.tesarici.cz>
In-Reply-To: <20230501165450.15352-4-surenb@google.com>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-4-surenb@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=pvJgyuyS;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Mon,  1 May 2023 09:54:13 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> We're introducing alloc tagging, which tracks memory allocations by
> callsite. Converting alloc_inode_sb() to a macro means allocations will
> be tracked by its caller, which is a bit more useful.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> ---
>  include/linux/fs.h | 6 +-----
>  1 file changed, 1 insertion(+), 5 deletions(-)
> 
> diff --git a/include/linux/fs.h b/include/linux/fs.h
> index 21a981680856..4905ce14db0b 100644
> --- a/include/linux/fs.h
> +++ b/include/linux/fs.h
> @@ -2699,11 +2699,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
>   * This must be used for allocating filesystems specific inodes to set
>   * up the inode reclaim context correctly.
>   */
> -static inline void *
> -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
> -{
> -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> -}
> +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)

Honestly, I don't like this change. In general, pre-processor macros
are ugly and error-prone.

Besides, it works for you only because __kmem_cache_alloc_lru() is
declared __always_inline (unless CONFIG_SLUB_TINY is defined, but then
you probably don't want the tracking either). In any case, it's going
to be difficult for people to understand why and how this works.

If the actual caller of alloc_inode_sb() is needed, I'd rather add it
as a parameter and pass down _RET_IP_ explicitly here.

Just my two cents,
Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230502143530.1586e287%40meshulam.tesarici.cz.
