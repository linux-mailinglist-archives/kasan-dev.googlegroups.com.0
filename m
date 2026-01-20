Return-Path: <kasan-dev+bncBAABBC75XTFQMGQEFQVCKUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 546DDD3C233
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:36:28 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4779d8fd4ecsf25561365e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 00:36:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768898188; cv=pass;
        d=google.com; s=arc-20240605;
        b=GVUIanjKpoB7cslnoOZnaey8yhtSsBTqjibbICcXVcixjfavf0r8fQapXIrHv3w36z
         mQ7xuylFl2lYX3zjCEr6JI9vdh4O5N81l9qUJhk841h0qJGcaIwjGO+TNTLvSfGbOJNb
         V92SfxhoW4LAn5QMuBgckAcVcUYDYNULiFZC1jm5BtAZnWauScvTElkTnCEQOw3so93q
         lIukmK5Ta0Z3daKmCa6f6HOCuUxFNIIuDpOzsFPeNR8iMq8A1cESau2k66w1cGCS+CM0
         LV4WFAZDsHHLjtJVwlMGytTnf0nlqQiEpADuLqTCZswYTg6Vm569JYQ0uke+s3EQYkH8
         ko8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VlNFon1GiHU2qDYEh8V8IRlcTK85NVvNR/i+6p32150=;
        fh=QgnqWI6+SULUPoXsdHxig/I1N4Vb7FbpPVwMyc9VHKE=;
        b=hdikJWFKBpUqgGVwY/ezANCr2gEAl8wNZ40uks9/+y2KSNgoPMiqCXX4WW6xH7f3Le
         YCBcgj4CmZvpz8Nm0dkl/iCXNrt6EKVGKW6pD2V0SmQHXRbJuCzozdgLBxx8STK29L2a
         inf0tJlKmo91fY6c5xKhB7V7Xl+Wdrdw/k6VSbn6zrmwsUOayGeG88F2kd0X4KiRT5a7
         CBLmIAAQgNcUPvCceIxMu3zxbEknEoeorF2OfBQia33SRQBjsfq53mxbauZt8HVMPJpr
         1MjdRHZz2Ss5SifMNPJBPR3GGSNUgUVUnjz6g4BtLRsWrbCvO6BZaaRdq55f3zATm/am
         sIZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J9zB9Dhh;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ae as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768898188; x=1769502988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VlNFon1GiHU2qDYEh8V8IRlcTK85NVvNR/i+6p32150=;
        b=rAlANXeDiqua4mEsltyKzKbb7/uxL3jHYaXlwPFyqZYHUc9OOkgTynOKe87SDlzP+8
         Ec3qB7EB3e8uvOpwPIXp5kQxSzelJi4tHQqUeb5WyBvU6oUH0ZT+I5riuzj2lUhZBiaM
         uCf3AmPmnYRM5oTTMW60kGu6OC2B1zwx3jycye4oO9mTUWzm3MGQbloB4/38IfLg6R16
         DAIVxum5DAa82YALJC+BtBg63+fwWCSIEtaQs6MGezFalA66ldZadl0FijGw73jz5IJC
         1vT1WuIWSfQNPJWiTZ2f2jfhUxNqC4GHtvWvJJz97IO5vMTC+Suow/B4RPeLbxRjboQe
         hw5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768898188; x=1769502988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VlNFon1GiHU2qDYEh8V8IRlcTK85NVvNR/i+6p32150=;
        b=Wi3frCgwH3JKbG4BV8uSaBBTcp+MLShDZtpcw7ppl5ZhY1BF/KSTnrQZJ8AQbMbBGu
         ngM6wpk/rO5UbLiloN/8J/h9lEiId7aAMm0RvMzGHe2P6fQ+n6Wk7gapDhl+W8/BalHK
         Zktxhhs6i7e71CPnFBfY8zN44yrzIJNGjASsQKDJO4r6bDWPvv5hchF/X0h9P27iMud7
         V1oqHC9GBUjCHpgnPta5cGVthsatqj9+++Khw9Lqiom9K/XSp+fL6oJ+o53PVEzSABq1
         lMEtyijIwm2OtxrO1OD+k2+wtzR3ZEA56scEQTQqI9EDUW7XL5GeL0Qalu9xbSscB16B
         3Xow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWih5npkBhkL/0t0BF/Pt2HZ+g+daCyl4H3hGrY00Jo+lWJkT1BNAks/aLhqIU/oaVMIcSEvA==@lfdr.de
X-Gm-Message-State: AOJu0YwWYu601Yt7xmnD+N8gZb/jvn460H2rmt0hxTUKqAYPEhrWGV5l
	Xb5mVfO8DhRzBC20UNfQ27oLC6y4kaU/e8hw1Qq4IZz6j/FIrV+it36l
X-Received: by 2002:a05:600c:3e08:b0:480:1c1c:47d6 with SMTP id 5b1f17b1804b1-4801e53c069mr165829045e9.6.1768898187576;
        Tue, 20 Jan 2026 00:36:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FB3vRK7Wv/BM1EsFZEKSiWoK3KQzsRkZt+lIi3KIgXMg=="
Received: by 2002:a5d:6581:0:b0:432:d256:c485 with SMTP id ffacd0b85a97d-4342b986210ls1385029f8f.1.-pod-prod-00-eu-canary;
 Tue, 20 Jan 2026 00:36:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV6ZsluyN0OYNUx3rxGSL1cUM+nYH1IW5Z34oeC1OC6g4La82Q8vCMX9eUCTw8KznB2KfxVdt+i31g=@googlegroups.com
X-Received: by 2002:a05:6000:1acb:b0:42f:b555:5274 with SMTP id ffacd0b85a97d-434df0ed3d6mr21574275f8f.20.1768898185906;
        Tue, 20 Jan 2026 00:36:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768898185; cv=none;
        d=google.com; s=arc-20240605;
        b=c8M930g/RLDIIPK+ITkFAiBxhgceiYLvqkS74Un7wsP2CAlaQ17v7yRn6a2R/B977N
         /UMCd+RluTiJRhcwshGKF5wcdVHtE8Vl3EQNOKbib1x5laRvf7xjBjUS/UF3eT+NS59K
         tBnkX+1TAFZJQ4V2BAhStv6lKXmpai9BRIKH1R3Utg0UCAINWg7Nax+rloUnA4JuNr6O
         K74h/ZPhoIGfS61e5UdEumA1gj7em1njc4vbz6jixrrNjbfSONjdYu86sajubplSEvWJ
         E3gGkhEDeAMDVCXfshJoEigQA+E3AT3kwmiSLURwTs3LLa3MpRxfc8hr9nRMQwmfmwU7
         nwyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=1lkVn59AgzHG41rfxCcQcwV1gp3xTqlToekIxDgd/Iw=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=fKmDL5EFzeL3GyxNnrEudq99AdNxRYec/fkdTrt9NPu2EENTnBguCqnby2VZBhKEEg
         /LX+7adQufwr6NrkkP9MhI+M0oh4JkazpPKkvCTPfGRTCr3ZPwITFJKAOuYeqAYT77Bb
         QsIn0XvrVYGtxBUFkQdSA0XNVHv6K7t0qN22GPJ4Kk/NVkvDEljHW4MsqZ7WVNhWu9GS
         JSPnBV4PuKWIsIUgeh4VJ6vV1Yp7+iqqi8+Z5MpJYR3PXnMJj0sFo9gs4NCnZxaR95f6
         nSbalI2lzAWKqrMURBEr5sCDEHrwiGpx6WCdp5THqhzR/g9lz07XJutFe/tWSG6BKenP
         edEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J9zB9Dhh;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ae as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta0.migadu.com (out-174.mta0.migadu.com. [2001:41d0:1004:224b::ae])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435903fe0acsi19063f8f.8.2026.01.20.00.36.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 00:36:25 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ae as permitted sender) client-ip=2001:41d0:1004:224b::ae;
Date: Tue, 20 Jan 2026 16:36:15 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 10/21] slab: remove cpu (partial) slabs usage from
 allocation paths
Message-ID: <g73gai6ztmaxrigoqwvstyeatdsb6wjunli6gbbhvy7fxqomzv@la3452pj5na4>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-10-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-10-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=J9zB9Dhh;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ae as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Jan 16, 2026 at 03:40:30PM +0100, Vlastimil Babka wrote:
> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
> 
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab(). In the
> latter case we reuse alloc_from_new_slab() (when we don't use
> the debug/tiny alloc_single_from_new_slab() variant).
> 
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
> 
> The rest of the changes is removing functions that no longer have any
> callers.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 612 ++++++++------------------------------------------------------
>  1 file changed, 79 insertions(+), 533 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/g73gai6ztmaxrigoqwvstyeatdsb6wjunli6gbbhvy7fxqomzv%40la3452pj5na4.
