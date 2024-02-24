Return-Path: <kasan-dev+bncBDH7RNXZVMORB4FS5GXAMGQEAP3KFVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 74C988627A4
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 22:02:42 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-29ab1ccc257sf88008a91.2
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 13:02:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708808560; cv=pass;
        d=google.com; s=arc-20160816;
        b=vw5kdzLNnZx42DiftF+v/wMqQ/P/8KsDrYfQO1sGXxxwjk4kLvUrpkSTP2riJNlMig
         3ILyLhqn5b/fH31l2423bQDNgwkVgUCR5k6NhZOT1gnCTyW+a9lA/t4oQadwmMiR3vbU
         +Jgx81gOai/VpYj5PWZ1AHUj669yo0ZLvB6CSYlTvY/DJpOW31AYQHsdmLCovsOlrpMf
         ieM6MsXB9xnzFuiKu5/d+Bj3YyOPg2oaeBEBmTu4PyrsUAOsNP5ZuV3nQWUMbmgtFnNp
         GadHNk0Z3K1jiZNtTcX6vCDV2DnIf+HBVJtHrdca44lLlOQDbplprGPQCwub6T2d5jSo
         9kOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=3Pmlsmy/w7Izj/1NUrItolnaUviIh7IGaM6M3gDploo=;
        fh=W718wthyW87PW4b5YuVwSMPJin7fCwloSSRqhirTlZ4=;
        b=Vl1xMRnAOq1pO3XGEGH2CLcH5sNq7nX8DCpz+jao5yR70hoXycM+EjfBuDaDZ94NoN
         /e/Kg9eA6E6xoeYslGwGe7adF8kh8spJASLykzWGRT/qL4mDyMo/JM76kDFBmWkEsZUW
         obqbYy1BYgOdKcrzGSrAMzaHRbxxz16Rk5t+2RgsYRxRTrvprdWhKprC/baKmSOxO3+z
         68g1u0aUEwN5w2vF29Fq9o1lBvvTgbIhI+5eXO6klrrRjxodBd1fxb9CeNHxvH5e3k4K
         YX+38TSr5PUQrOl7Wq+yBXJ+dYgE7MeJhqh4/1qrObNbXsRcr70fCKhboxg9vGf5Ipfu
         e12Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vvnEwy1I;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708808560; x=1709413360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3Pmlsmy/w7Izj/1NUrItolnaUviIh7IGaM6M3gDploo=;
        b=RmU7Sl8CDtZcBZfd7Ihztnz8u3/+lgzVyYBZY/sij1mEtLMfATDzBhh5PAFbT19jxp
         iXBIV5Qhr18Z50ZU5KLaHjibuxXAnBDo1JzWLGeNHyzMcCv1liFUzH9vK4CVdCiU9dev
         jv22hk1kuxt4fw5oJ5BzJXmvZhPgq6nVYx7j3EHPjt91XzcVjawcklIGyNtR+VAN+jRF
         SlZOoVf+88IPpnIqCocx/TpEpJ/iCBgZmOEeceLN3kedwSDk64aUi7HoCAAf+UXGHgb4
         1zPJgWExDSoSLm1dzRVIyHz/GPCXUVI4zWSZ9BeyyWaoTveBpICFC8e+01hZmqf7Y4IY
         LROA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708808560; x=1709413360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3Pmlsmy/w7Izj/1NUrItolnaUviIh7IGaM6M3gDploo=;
        b=vbkIs3gEJXtVQjeSGgzUJkN7mZoWeznDIDp+Vz8XMIK+bBClB9QueZXqCGTTgp6ijj
         1OsFIJ6GZ+rV/3nJnoeFCmGdo4HV73lgaEVc04IPC1ADj7so7RtNFkPmTCnH1T1yAkRp
         5pNf5xoji8GdOik9D9++v4ddiWQobqMX3X1W7CgvY2bzTr9PEsA02H9DHTJjfU57llej
         5nai8e3mvAkcA02Lp6PY//VHDqfLjONA6xkuYQocPqUof9YVFQ7BzmUckt39vmqEMQ33
         xGfsUKcFeTOc5Erdzn2O/51M0mj8JYCKE3k3YdT9bKTl2jE9deBV6aDCLlX7J7rnffo7
         3ETg==
X-Forwarded-Encrypted: i=2; AJvYcCUvfTn8sTGy0/OKXRgl4ktumwTF9juMfxplWrJnucUjsJ6k1pQk0HBwNv9M7IO9f9xMIn4MWBZ9S6gqfdf6cJxtuxtmXAr7Mg==
X-Gm-Message-State: AOJu0YxmpXrZzjnr6uEAN3fVU4InHeZ28peAiW6qG89RbpuXLcbHUmOQ
	vgNws2kiLKkDQ4btqS4g9+WZGKy5BaqQpYVGmmrVua6w11gwTMgj
X-Google-Smtp-Source: AGHT+IF7ZGcfOEC9dBv3xCOTHsctOH2McmHlgbkBP9z0eLHzLKirdV6YP94MVVRHqXfSfRyeCoHqyw==
X-Received: by 2002:a17:902:7c92:b0:1db:c3cb:b088 with SMTP id y18-20020a1709027c9200b001dbc3cbb088mr3819579pll.35.1708808560723;
        Sat, 24 Feb 2024 13:02:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2642:b0:1dc:23dc:bf43 with SMTP id
 je2-20020a170903264200b001dc23dcbf43ls756679plb.0.-pod-prod-07-us; Sat, 24
 Feb 2024 13:02:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJ1PBynxSfCTgsbStbB0yRJmlwW7lAkgibdqEax5C2H83vUVoSzQIuk0raJ6Shll/YmxC+bDVyy/Y9T2ytCX79cR0gSo11jiVgNw==
X-Received: by 2002:a17:902:dac7:b0:1db:e227:381b with SMTP id q7-20020a170902dac700b001dbe227381bmr4115467plx.69.1708808559391;
        Sat, 24 Feb 2024 13:02:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708808559; cv=none;
        d=google.com; s=arc-20160816;
        b=x5oVKqqdl8HK+1LrEmZDqIdZI9T4JAINCoE2u92Sref/pDrrduXmoW4FIqoxEY+xrv
         OlOzIeMKHUeHsXFRNOr5rbxVsZiOSeERr/B+Otczg6+8iCnMXAXDptmRMMgEsTHCBbOk
         PWDjaY53z/4CUfs5ZIcme0BUc6SB/GnG83ZAzLeX0M/itZa+k4O6tdN/LpW/zblVnUoN
         SWcCTjBSubQFi3o026ShqvweUajNuQCIEF+qbDDMRRQ8M9yqEBHeQLcA+0XG/gIQVnKn
         xFM1aCmqb8tpg6O2nQBiUnNchri9GJprXiSF27L9YMXtFICv3u3CkOcaFyE2yCrdcuB9
         Lzjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=1bYqSsxfIR9raHGk2lM7F1xz8yf+qiSkrL7Pgn11QAY=;
        fh=378fkQPyg4ofUdUg80VlXDBs9LRR3461KLKwJ1ocTq8=;
        b=02lqQQmz+NR1TATQabmoASro8/fNO+r7NbLz7l7J1y82m5gVQJwZjLFqAhnUbDeql9
         2oAtHYLn5U8SKvf+dmYAoB2UHhg65JKuvfmvRX13A0kFwZm+tz+I3zakILIvAxrBMAHp
         xEE4e1tzXvcPeF+8xRC+rXyw2adNXZ5Sjhsr/4+ivpKK9DxZ1JLcN3K7Upu72cRyoqFt
         QuKdZ8kYJeSKyaSbeynzdmHYChq9NO7kYfIE2pl3NWshrCjjujNMfNa4vxeiCCUccXiP
         bQtv0v/Q3hRTKEm4/Bq57weSEUU0/xhtPUs6s/SraVgoz6W4tInfzD6fUcMVq4Gmrn9r
         rZCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vvnEwy1I;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id kx4-20020a170902f94400b001d8cea8344bsi119592plb.7.2024.02.24.13.02.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Feb 2024 13:02:39 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1dc744f54d0so127535ad.0
        for <kasan-dev@googlegroups.com>; Sat, 24 Feb 2024 13:02:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWz856aNOWKwV3Ci3snH+dbmGP5YQxtOBNBVgSmrg5oLofybjECmZ0aQQ+L0Qg0kidGeDLEurVyy3v1EBUCePAeit09OKwBnEaWJw==
X-Received: by 2002:a17:903:32cc:b0:1dc:7b9:196d with SMTP id i12-20020a17090332cc00b001dc07b9196dmr190478plr.18.1708808558515;
        Sat, 24 Feb 2024 13:02:38 -0800 (PST)
Received: from [2620:0:1008:15:ce41:1384:fbb2:c9bc] ([2620:0:1008:15:ce41:1384:fbb2:c9bc])
        by smtp.gmail.com with ESMTPSA id c10-20020aa781ca000000b006e4ce93dc28sm1468928pfn.104.2024.02.24.13.02.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Feb 2024 13:02:37 -0800 (PST)
Date: Sat, 24 Feb 2024 13:02:37 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, 
    Zheng Yejian <zhengyejian1@huawei.com>, 
    Xiongwei Song <xiongwei.song@windriver.com>, 
    Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
In-Reply-To: <20240223-slab-cleanup-flags-v2-3-02f1753e8303@suse.cz>
Message-ID: <78910de2-097d-9dea-4e00-acaf40af0299@google.com>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz> <20240223-slab-cleanup-flags-v2-3-02f1753e8303@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vvnEwy1I;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::632
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Fri, 23 Feb 2024, Vlastimil Babka wrote:

> The SLAB_KASAN flag prevents merging of caches in some configurations,
> which is handled in a rather complicated way via kasan_never_merge().
> Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
> for KASAN caches in addition to SLAB_KASAN in those configurations,
> and simplify the SLAB_NEVER_MERGE handling.
> 
> Tested-by: Xiongwei Song <xiongwei.song@windriver.com>
> Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Tested-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78910de2-097d-9dea-4e00-acaf40af0299%40google.com.
