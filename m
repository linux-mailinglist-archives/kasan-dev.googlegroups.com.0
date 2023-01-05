Return-Path: <kasan-dev+bncBD7LZ45K3ECBB4WV3KOQMGQEWLCQQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AA79E65E942
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 11:48:19 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id v19-20020ac25933000000b004b55ec28779sf12687405lfi.8
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 02:48:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672915699; cv=pass;
        d=google.com; s=arc-20160816;
        b=ziSY8Bay9ZG0t20BO2Zd3ojY1II4ogHz7yl1iFP1xxk7vWW2OYFppJJ8zjVPAxpzMY
         Dj5qn55eGjnSrXFnoOpGszaOVYgVR6RQY+XLMZJrCG2eMSUu6zRo3F6wmkvu3BO5FZmf
         gMK0BoqVveGDIIKUumMz3QD4zVuMArFkiieEZUc1+CKEHbcnC99+DeE7c0O8GgEAk44d
         OlLdASYJR1qMoRQiE0BePTb14/4fhZEQQ1RT07k6C7Rsr3eDW0Vvg2ox8IMzU9AVFZpM
         9euNtQWsy+bxyli2KPS72eAo756TMy9vFqAZsQkp/OHuLxomz59xsFZlR9soYirUPo4R
         mzeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jl3ouj1uoAYLl7kbH3HqYcYgcy8++JEgsg1nHy4rnDs=;
        b=szFFXpqSbx2z+FPShHApCdANNfK5f1Z13y5GKSdRGI4l+GpiDvcByieNpj1TOomSTl
         h7rc6Uw4txCxjmJbCdRWg3Va5sPGr8AkOUOkLZc+Pj709AUnnMw7LYQLU2X1zp37PYt8
         /cVdAeSdirX9BAt73kGqgwfQqQy4G+L15aIpEgkvb+fA/wyXyrem7OBVsSgV5HtGj2Bw
         UYAquiKKolUDBKcvDh9xuw4tfkaS3JHhjTnsH6RTMykr8sNCAu/zqowdykJZfNI0l09P
         uR/dCku8nYU5FgLrA/jr5uK6CZZbWgm5BVgdNJ4ZWZ6JSBTtJMRSHBrMOgwIejVYIxd0
         5FZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=E9K3NJxE;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jl3ouj1uoAYLl7kbH3HqYcYgcy8++JEgsg1nHy4rnDs=;
        b=b8pRmEEhJG7zRX4pTx0+ibpGLJ02I1njVUMpcwE4+AkDa6zGXpF5WN1LIxH/FK6JT8
         B21dM004LQYRv+DP2jroCK7vuKklkrlzHqBrmwfwIv255wCgW9Pwju9EYV/LcCxAxpjV
         v5cwJeiMDKzh7l1yEdfHcG+4fwWj61OPFu0pJgtOd2ypxz6BUm0UrzAWerF1xF0HpiVV
         db/QnC8JZmrVvGOjzMpU9q/kkwOFHZlXtrL+56JyYyT6LyePdeOsOiFWKqGqGHzbvLEA
         IS6qqcB1qjhsS54QIwcF4jIMQtw/VXomJlpja/ZZa5QMEJzEos8hSU1EoOLkhKxqMYhV
         kb3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jl3ouj1uoAYLl7kbH3HqYcYgcy8++JEgsg1nHy4rnDs=;
        b=s47+k13zmBmUcobQZkfUtBq/yAti4HUH38jONRgAIFm2zuH62WwPzCs5iYxm6+VFys
         565tv173/9QmG1v4Mu8cmWPzypjoX6gCkwDHHbFrHRJgxNzUsxXZt4z3xpjeVqoUBJXI
         aqtmWfYzgaaHn4ZK1NQhGESRj6RRCeEplZ9J1kg5WZg/CqE2AS9fpS82KbqHxgi0IEJJ
         oSiXUSiEHpFGN78DcEsCIAsf8RzuYs3fcGRQgquCk2vxsAbSd2BxUKNGaWDwO1fKcHH6
         onwkHuTBddU56ncUmg7ZDqTVi0hIm/eDQicegVAOOFR5aU4HTXI2Fe7W/i+DUfYg8VPk
         AIEA==
X-Gm-Message-State: AFqh2kpiYIyUdKOb8NFOR/2iryl2ZbhMhOXIqPy29BGPGXHlSwI0qC3v
	WdC0A+97Sv8wYKW0RCVJSBk=
X-Google-Smtp-Source: AMrXdXuVInPOuWo5Vs3YVxdqMHo8ISjnT9uEriNSLqkeuZNU1F4ooKUoAT3xuH5erXJKeAkzjhFnGw==
X-Received: by 2002:a05:6512:2311:b0:4b6:e525:6fcd with SMTP id o17-20020a056512231100b004b6e5256fcdmr3072344lfu.522.1672915698812;
        Thu, 05 Jan 2023 02:48:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls2057632lfr.2.-pod-prod-gmail; Thu, 05
 Jan 2023 02:48:17 -0800 (PST)
X-Received: by 2002:ac2:43b5:0:b0:4cb:40ba:4ae8 with SMTP id t21-20020ac243b5000000b004cb40ba4ae8mr1949221lfl.34.1672915697092;
        Thu, 05 Jan 2023 02:48:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672915697; cv=none;
        d=google.com; s=arc-20160816;
        b=mACdedt6NLg/f+6/LqaljrjyyboLRiyaNWkT70VTerWl0HWdXSsFo7GZQinJLA1fS9
         bhvxftYf1S/5pAgigvn1oT99MEmFwlalIAYtMtzQQy7uR8e0/8Eho8VOIrF1l8EOeP4t
         kSkDTCDSHbxqSgy2DP+Tb9RKBKz4OcMNwZrFE6Al7z4GnOShfnEt2dOv3fn/Ay+i2/9+
         ZTv/RYLLQH4TsO4DgoyFJFfahGcSp8hi/5FXxpKIfIN/yqJRR5hl3P5ISgbP6Wqw6V5o
         n7cDze+HVjzhzjtBLgSnE6yXDrfc3UnqBbP21d/QYgFGdnrvuBUs1SxnCwq4P4DkkBsX
         0YdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=6qLrWDP8UxJVLXXHnMyGiQx4P9YZKALZZuu63FSiH6E=;
        b=UIBaSuY85JkvP/3DAaw8rntBQMwYxpnT/DvD9X2Uv08oRoejcs7g9f2lr2yGi9W5fO
         6Q5nBn5n4/UHZN6SefJvFnJ/5pIhnmG6/cYmtf9+9o2YQUFKsNDzTRUXol4+6GeIrQAx
         MXO15Q6pBOuZie22qK+XUfKtl5D8bs7RFU+6kv8Bb8rsASdhJPUXh66I+EvyADpmlb3S
         bIeJw76JZBQIFMWCZpWzpwFa2slUon9m6EMq8osRw76rh/YJC878zKEaXyky9HgisFat
         C3bmOd48McRacHuFCUNbYVb+UEnhGScUMe9ygkS4Zhp17poHkwi0RyKybz4QdubcP3tY
         Glzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=E9K3NJxE;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id s15-20020a056512214f00b004b58f5274c1si1240297lfr.1.2023.01.05.02.48.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Jan 2023 02:48:17 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id g1so38086004edj.8
        for <kasan-dev@googlegroups.com>; Thu, 05 Jan 2023 02:48:17 -0800 (PST)
X-Received: by 2002:a05:6402:3784:b0:46d:cead:4eab with SMTP id et4-20020a056402378400b0046dcead4eabmr46314439edb.6.1672915696661;
        Thu, 05 Jan 2023 02:48:16 -0800 (PST)
Received: from gmail.com (1F2EF380.nat.pool.telekom.hu. [31.46.243.128])
        by smtp.gmail.com with ESMTPSA id x11-20020a170906b08b00b007806c1474e1sm16297503ejy.127.2023.01.05.02.48.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Jan 2023 02:48:15 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Thu, 5 Jan 2023 11:48:13 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Aaron Thompson <dev@aaront.org>
Cc: Mike Rapoport <rppt@kernel.org>, linux-mm@kvack.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v2 1/1] mm: Always release pages to the buddy allocator
 in memblock_free_late().
Message-ID: <Y7aq7fzKZ/EdLVp3@gmail.com>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
 <20230105041650.1485-1-dev@aaront.org>
 <010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@email.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@email.amazonses.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=E9K3NJxE;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Aaron Thompson <dev@aaront.org> wrote:

> For example, on an Amazon EC2 t3.micro VM (1 GB) booting via EFI:
> 
> v6.2-rc2:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  178867
> 
> v6.2-rc2 + patch:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  222816   # +43,949 pages

[ Note the annotation I added to the output - might be useful in the changelog too. ]

So this patch adds around +17% of RAM to this 1 GB virtual system? That 
looks rather significant ...

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7aq7fzKZ/EdLVp3%40gmail.com.
