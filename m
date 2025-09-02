Return-Path: <kasan-dev+bncBCV4VKNQZYERBRXO3LCQMGQED5SAQQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE34B3FA20
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 11:22:15 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45b8dde54c1sf10829825e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 02:22:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756804935; cv=pass;
        d=google.com; s=arc-20240605;
        b=IgnZ0Ss7SwRQXIwXlN4EslvRrx58qdGJ/kOOSNNqi/8sNyGMXi1I5ccGzow3VKbPHo
         RrxCH2Ef0AFWzsOsewK4sYXrvIwFDxEI3HKiIIXywb2ryN10hUnRi93PtT2NBLr1W9ou
         1+08gf22PXRyYk7j+Vl1DlmxcykdzLDLPDcCIS+qM75PhqHhV58mtVgoXrKCKd9QWeAX
         X29sjUX/ojd1+kzS6iw9VayvkxmU7QIezNhnkRGq2SEVvDlAyCbNOsxSe6ieVGRpXQ30
         AhDq4kV1R2WsMSfZRPhjwGpwZBKaLMp4JRso4cDApL/DZeI/Gdx53B2o7Kl9y8SVQLMS
         NLpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=25j8El9ptVkH+nWKe2SwvRrOg5bY6HshXfFZ/r7nBc8=;
        fh=vDJTCteEDBHeDV4EMZPQKhg0iQ2w6CdnbX5arEYzSsg=;
        b=WQ1Az9jLRD/GkwKsRjtV8wkr0sTF7xb+OFq9a5ryDsPhvAIkenH968C62JpSAUlcxm
         mGITmP92OgqOuSsBtcGf38+6bQu/UXgapawruAk9+MXCc4GjHM1WjfzPkFYkj8M5zT/g
         ryyEKTc9RTo2CLLz55xwdOoWZOYj0NZNLeKya+nQjKmSke4YI2YwF1jFO0qzMyUxTQEd
         qCqO0GoPfywbQvma4jkK0B0jztsHchcjwFHngnfiq+9cJ4Ja7hPnlx/KuJdDSTJC7B4v
         6duquV/DG7zREmbboZYG8CKempRkCmcbiW7tCuQCN3Vtt5YmJMwrmtvsx4dR3QJWwIP8
         KKZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ursulin-net.20230601.gappssmtp.com header.s=20230601 header.b="oFwW443/";
       spf=none (google.com: tursulin@ursulin.net does not designate permitted sender hosts) smtp.mailfrom=tursulin@ursulin.net;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756804935; x=1757409735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=25j8El9ptVkH+nWKe2SwvRrOg5bY6HshXfFZ/r7nBc8=;
        b=VwO93y5Q5fXEgZ3wR2DWUphX9qRZUriLMYenOPQN3cqmYM3VGWEiZprA6CmT8JG597
         UrrSHSARkU06FC2LXRW8cjyIb3LgQbTCyhFdrl3Cv5GH57sPsgC2yNMGGuAKpGMR+goq
         YH9aVoSEPCAsSD23DLvMRDya41tWckt7JtfOQFIlp4bveMKSwkP6nUR8TbPzurOE5GFI
         2SVyAILS5WqRN01pNeJR5I+0aQ/C6XIIl0fka6QIvuIjHJ/OyxzFRCIMqmB1lO6u70Va
         JTDWPYXSTkhrWJRDPZbFdUi0Brea3Jb6bjaCOC7W+DknsdSHqPd2trMOhouzNAZUTI43
         pJuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756804935; x=1757409735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=25j8El9ptVkH+nWKe2SwvRrOg5bY6HshXfFZ/r7nBc8=;
        b=kk4ZOiCV4cEz8SYocjELoEYyGOrxjU3R8avnuCnwZ2/UhYacm4ljb21Jr4rGVLPUFZ
         MX1eleg0fSUMzSY03uopP+azmFfZtea972KzZ2WvlbKxvDt1KifpxSEocrjMiDxNM05T
         LZVbW0bo9cXjKDCNL54PKONOGZcJI+MB1Af/A/g5qsKNz38UTNK8s4Rt4MLMX6B3AK+t
         aVqW9GJMlVskF9jVWX2Cslz22W7ZQr3M74Dw3C4HZaSGixpEw4fA3h/Tp3s/r833Po4+
         VjsRLwxgIyaweMTOO2xLEJ63j/c0WLe3cmeuFqZ9VKYNJnWdT2TeSBuWwHZeNWX6I+8n
         KINQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSrRVEybgi1SwVbEoFKJXuTeSEYazxUQcX+oxF80nc+lKrTFgSKrZQU/vYOkeui/0H66O6PQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy2MJc/mRWGeVdoO3rsXarRywHNg6gUlX2Z0mQA3yXb782MpVmg
	BbSN0n+OlEBvG2jZw585mkcZm7sS7N7auzhYgfgX2SekbAIpZfOIE9k5
X-Google-Smtp-Source: AGHT+IFDTTwktZ3Kr8MB88HLfghfTcZCCF0phTDj/YG6ZvzRM69RVUhaOsdeLV03pChyRvX/e2be2A==
X-Received: by 2002:a05:600c:4447:b0:45b:8ac2:9756 with SMTP id 5b1f17b1804b1-45b8ac2a1e8mr66207095e9.1.1756804934822;
        Tue, 02 Sep 2025 02:22:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdZq9sLxKNZIksKfZg3uW/ERUafSIb46zpgwdSFWchBzQ==
Received: by 2002:a05:6000:230d:b0:3b3:9ca4:d6f3 with SMTP id
 ffacd0b85a97d-3d7b1c54dadls727540f8f.2.-pod-prod-09-eu; Tue, 02 Sep 2025
 02:22:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkMrSiqoMQ5esZy5+6leww87P4f4h2YTEWoFCLQFewc/XM2lvg6CTriBSs9TlARrz9swUd9z9eG2Q=@googlegroups.com
X-Received: by 2002:a5d:64cd:0:b0:3ce:16d3:7bd1 with SMTP id ffacd0b85a97d-3d1d9ac1cdamr7963538f8f.0.1756804932021;
        Tue, 02 Sep 2025 02:22:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756804931; cv=none;
        d=google.com; s=arc-20240605;
        b=Y0axj49zsP/xXVLcTJuYRC47xjrSwpdyndFDwIEVpbtE9YmMOi10cOkVQr4TAheI8v
         HuxttGbz0hbH9VnejwFfts7pbu0DxBPQe5jVIW9Kx6p/uiDljJS3T1C5qES0BIUFnDYS
         TZkaUP7Bi4TGd8m4qJiw0suzMqLd+qFyMGyiDXN008KcyWn9q+yMow3FXVNBzrr/JkJX
         bEK+Ztj4M0UYCary69DpyMFXdEbH5cEaEbEI1/Ad+iKSk5CAYnCfEp3Q3B8tgJxnS8YQ
         toXguh21ehufRrPRozQiNCYk2WUJUr6TKapQ8YLRDN23FwAkwiedghsdTdcAMTlsMKnj
         QmxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=0Be300C9M54HN2j6qqn3KzILYOn0Dm/rUn/s4aJntRQ=;
        fh=Qf+NoPbjua1FxmxE8v9nmNEPqqtrm0YXlLWTMDc2Cdc=;
        b=P/u76p5Pcx0xNv/jeag1SzpmsLqYm6QGzK037p4pr0w0fbDN2ZPB3uM4ekh8IBPkKN
         MlDpT01lYYVa85rVIP9qSDN0C+jICnt+b2KFA/p29DAvdO1EXaSfD32HxAP3CDuXEgCH
         v+/pACT0ngi7PMW7VsgFUjdZjfr1uB/FmZk85fNVyqG0AfbZGEcIYoRk4XoZshXFJSif
         Z0P0BzJveT8R0xfKA9hcY1gp7EmkBNGXD/z3FQGOhcNi9Lg8+Ddi/tdBy3qnfnnju4qI
         ZUCRaM9xqFhSLV2Gl90JKxuDDf2XL/mqQEXKE2Es/+yGZMg2YekCNHZoyRNZD6hTFFEi
         yGqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ursulin-net.20230601.gappssmtp.com header.s=20230601 header.b="oFwW443/";
       spf=none (google.com: tursulin@ursulin.net does not designate permitted sender hosts) smtp.mailfrom=tursulin@ursulin.net;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b8fa29a24si494675e9.1.2025.09.02.02.22.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 02:22:11 -0700 (PDT)
Received-SPF: none (google.com: tursulin@ursulin.net does not designate permitted sender hosts) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-45b873a2092so23014445e9.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 02:22:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWK9xFyyWDnZA+kS9NU9yt6va/lFZZjH3ZrGiIaO3/yi2b1aGuNnPyoLPq2FsokjZ9+eNwXJ5ORGz8=@googlegroups.com
X-Gm-Gg: ASbGncvsnX45tCePbbe0kyw3zzsEnb9B3uobkoHSlN1ahj5xWtfBsOSB0ugt0BV/2El
	OYynJRSFzECubgtq61+cJNNlYENA1GEEJvKFxWpx+XvZ1VuQYq1C/BFZ0UYMGLGiZh47HIoRtAs
	8B+4mW0x4kIvY/CxLHvVOidgKBnthimRkgAkk4Tv8Ac02QudaQnYdeL5SWguer/QY80T8Ujun/Q
	Q1SmHP3HQvBmszwXsTbHpuAKZYaeSImVZHQ3RSEXkIVQmDGABngIF5ZcY2bhIqwQPklRm4KKe4m
	YyJHIqC/+cBDwp76vWC9yMp2UD/x3pl5Y+O7z29bs6dIz/tPVnWovkcMmXKgvj1lAIpHhFnFHNh
	+EduK8uPZw1R+GYVf1ePNKQ/Oky6r5aEfpKg=
X-Received: by 2002:a05:600c:a04:b0:45b:7d24:beac with SMTP id 5b1f17b1804b1-45b8553335amr94619035e9.10.1756804930815;
        Tue, 02 Sep 2025 02:22:10 -0700 (PDT)
Received: from [192.168.0.101] ([84.66.36.92])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3d0b9402299sm17994846f8f.18.2025.09.02.02.22.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 02:22:10 -0700 (PDT)
Message-ID: <4bbf5590-7591-4dfc-a23e-0bda6cb31a80@ursulin.net>
Date: Tue, 2 Sep 2025 10:22:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 26/37] drm/i915/gem: drop nth_page() usage within SG
 entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Jani Nikula <jani.nikula@linux.intel.com>,
 Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
 Rodrigo Vivi <rodrigo.vivi@intel.com>, David Airlie <airlied@gmail.com>,
 Simona Vetter <simona@ffwll.ch>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-27-david@redhat.com>
Content-Language: en-GB
From: Tvrtko Ursulin <tursulin@ursulin.net>
In-Reply-To: <20250901150359.867252-27-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: tursulin@ursulin.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ursulin-net.20230601.gappssmtp.com header.s=20230601
 header.b="oFwW443/";       spf=none (google.com: tursulin@ursulin.net does
 not designate permitted sender hosts) smtp.mailfrom=tursulin@ursulin.net;
       dara=pass header.i=@googlegroups.com
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


On 01/09/2025 16:03, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Cc: Jani Nikula <jani.nikula@linux.intel.com>
> Cc: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
> Cc: Rodrigo Vivi <rodrigo.vivi@intel.com>
> Cc: Tvrtko Ursulin <tursulin@ursulin.net>
> Cc: David Airlie <airlied@gmail.com>
> Cc: Simona Vetter <simona@ffwll.ch>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>   drivers/gpu/drm/i915/gem/i915_gem_pages.c | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> index c16a57160b262..031d7acc16142 100644
> --- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> +++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> @@ -779,7 +779,7 @@ __i915_gem_object_get_page(struct drm_i915_gem_object *obj, pgoff_t n)
>   	GEM_BUG_ON(!i915_gem_object_has_struct_page(obj));
>   
>   	sg = i915_gem_object_get_sg(obj, n, &offset);
> -	return nth_page(sg_page(sg), offset);
> +	return sg_page(sg) + offset;
>   }
>   
>   /* Like i915_gem_object_get_page(), but mark the returned page dirty */

LGTM. If you want an ack to merge via a tree other than i915 you have 
it. I suspect it might be easier to coordinate like that.

Regards,

Tvrtko

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4bbf5590-7591-4dfc-a23e-0bda6cb31a80%40ursulin.net.
