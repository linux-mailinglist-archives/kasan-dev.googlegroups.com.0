Return-Path: <kasan-dev+bncBAABB55N4KMAMGQEQZLO7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F7C95B04A1
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 15:04:56 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d30-20020adfa41e000000b00228c0e80c49sf2801459wra.21
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 06:04:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662555896; cv=pass;
        d=google.com; s=arc-20160816;
        b=cCR/MpXfIrgkqdP1bLTQK/OJdpnkaGXdTCLlBNcWIoPr53JEBsUatPEEgaZGhpW56z
         Td8vsA5bXv7/m/mMRf0T5AVxF21o6vvdiPWa0tOUa7NwHYdxbE5HE21FMeX8NUGdDzWb
         Z1aRw0xeLWtHbbz1FP1dy8mGH/e8WbzLSACdvkgj/P9iCXIz1gcu3x/fs16gP5KMXlSG
         wcXg2KHxloKnb+hUlZVlYD70TCTJtkhy/xnlKCqM1r/q0qvKYuZsiJTOIFWt+twlpEV1
         FXbGoIhO4niV86pcF9y0ddUkJp2lGL/HgNptVf21KdAnbjgjLOAVf4WlKQwNI/ocxON9
         PkRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QihaEOCKZ9QZkrMf4fYfDaSPfmQcXskbYNiD5r2m2fY=;
        b=DCxjuO7r5EWBDqOkNsa01/pWkECjLazIjZlZGOo01ITGoSiw//kjafElnbC8tsH7EN
         84/4o0+c3Hb3VOfdosBdiqi52kCIpZAiKN62dJE9qfbDLVHDY+TlNt5ohhXITyX6g/RB
         1qAqe54ydqegAIc3WYmp0dKKm6j6N20KId5MxpfEOyoyPZVRFYXZUIztqUcVEsdVeXaG
         Wsnr17WM61hOPeTfCRbuHWir5fObFvrc4BYdM1KaPfw12loTV995Cay/h1luRqb5/1fl
         yzUVFCWRuomRvhqPkI7Xt8W198ivnNMxnjXAfrvJRBb/ZudU+jsT8svvyWhs3VvfjhT6
         w0dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=er2MzJbT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=QihaEOCKZ9QZkrMf4fYfDaSPfmQcXskbYNiD5r2m2fY=;
        b=MdQz1jhPXPdBXz5sAWhgJJ26RRJ5lQEcyYZipOeodTA0j4ATuhbmLatQrEEmWBaxga
         UZK+thjlgx0dq11nx0kbjdtPgp25BxoAjwDd9HZNDGG7Aign5InS8K0kZiTQ7QT+1E7j
         SCnj+psLhMf6EbOYefv2awKV0jqbRhsy1CpySYoz9sNipcA0C8UgXkeTh2jlqXIkyM6b
         t81SBGqW2alWUUIGN5Fn9mcOJgHCpem04oS38sTpIOUZpDfYMoGILgYnBGtIMoKvrH8y
         yo6aqQ2EVHfSg1IKRHBJRX734Z9BR+QwuEXIYWRhgG0DRMmOMcx5igXgo1Y3yxh7ntR8
         AbBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=QihaEOCKZ9QZkrMf4fYfDaSPfmQcXskbYNiD5r2m2fY=;
        b=LLsQWBPU6/dj/886UA0bb59F+1y+/S4ZDmxaH7hhu1y9VKfJyOCW6oarIkmCoqQoVt
         NBaukIq+wToccSqRVvpdOYnoOhL4HDDA2RcyT7JVuAmUnwnF/Q8Ixg295KAdUI4hXE5l
         e4iOUO/cYZ60Nmf+tEdpItpWcVcBEs8aVPSJazKxvDL59jbeD+s/4vkOz7qN1F8F7CRe
         43pzcPDWO/jS3Vlm0OzKvRTqYGf1o+sJtvbIHKPP/zlR/1KJf5HS5GLMGAqElv30QI2H
         tOPQxs6GpB9pjOx32G5U5Kk0aD2JpAF/brKd9hbroXQkdtQzZDWeGIx8yFxyANVCuaOM
         swvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2CWevWpX1btYBAjQgb51eg55Vh7Yv6BzbCGfkcrsY7fusq6+JH
	aUej5mxylTaCS/qnUBKU2Ws=
X-Google-Smtp-Source: AA6agR6OU3+AVcBINZCtAoAxQ5+8rokE4359zgkz5WgG8pwP+5ipuHMqH+5otmi9vmiST7aMh+EGbg==
X-Received: by 2002:a5d:64c4:0:b0:228:e143:ddb8 with SMTP id f4-20020a5d64c4000000b00228e143ddb8mr1902223wri.148.1662555896072;
        Wed, 07 Sep 2022 06:04:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:257:b0:228:a25b:134a with SMTP id
 m23-20020a056000025700b00228a25b134als2135043wrz.0.-pod-prod-gmail; Wed, 07
 Sep 2022 06:04:55 -0700 (PDT)
X-Received: by 2002:a5d:458e:0:b0:228:cd6e:dc56 with SMTP id p14-20020a5d458e000000b00228cd6edc56mr2156392wrq.614.1662555895110;
        Wed, 07 Sep 2022 06:04:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662555895; cv=none;
        d=google.com; s=arc-20160816;
        b=WXFNXQB8l0JtfS/9u1o+IGW1yKA7LjuypJrv4fJznbv96kYyRd7j5HVHmyjJxEYyNT
         E0QHhPapm+rbQAwI5RB45qzIE4w2HT5ym8qbQTni7oVH3u5faiqOW6M90K2GwiIX68xi
         4/RUkAOvlsBSqfyFA7IQrE9lxeTu3Gsz5j380Iaouq+VqNf4PQ7nx0Ag5tSGwlCY6mYH
         SUEMOF0Kf3OMid9Ve45j9wkLZ5kUgrZ5mZYfEcYgTWNUk/81MgjTPXuGqSvHZ481TNty
         fBqP5cFQtD4Hl2TL0ETLN2fjAWOukhIDapkm7/k5EizdkIoBERsmQTlmBNuTvUehrVPW
         z2zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=3UodEGmtAL0Z2fi75TPwE5UbXZRqdKXtyJj7vm5kpXk=;
        b=UiGs7CH5Vo5u5VM2xZYsKS9WEvnuD3VuVvLvvUrn5PF/IyIg38comthYnVMhxDiQCG
         4bkE6k1Zqv+XROD2qKhEI/n0S4I/jCPySIxFwz2qUGlsB2eUZFN7DuYKlDHd1EFeibYW
         LGp3Vj6CKusYrlAWhjQopDzkFR/6g7DIxboW5odaebWiOnjlyWvYuQyPJNz2jwKOefb1
         h2KfwTxQynJy419VHMWL2mzGG5u0L5Z0KVeDL1yuscmz/snzI4vW9AevZaUXee3ylYn4
         3+zx4h4rzwjhSx0J+y/vhWeLp542oey/sBR+jCONkLZw6IgGO01H9+OdCEZlXlavxAnC
         IHnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=er2MzJbT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id bp28-20020a5d5a9c000000b00226f006a4eesi895157wrb.7.2022.09.07.06.04.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 06:04:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
Date: Wed, 7 Sep 2022 09:04:28 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220907130323.rwycrntnckc6h43n@kmo-framework>
References: <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
 <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
 <20220906182058.iijmpzu4rtxowy37@kmo-framework>
 <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=er2MzJbT;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Sep 07, 2022 at 01:00:09PM +0200, Michal Hocko wrote:
> Hmm, it seems that further discussion doesn't really make much sense
> here. I know how to use my time better.

Just a thought, but I generally find it more productive to propose ideas than to
just be disparaging.

Cheers,
Kent

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907130323.rwycrntnckc6h43n%40kmo-framework.
