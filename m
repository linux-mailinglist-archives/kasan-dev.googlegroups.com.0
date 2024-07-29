Return-Path: <kasan-dev+bncBCKPFB7SXUERBO5GTW2QMGQEWQDU7IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B215E93EFE8
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 10:30:52 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e05e3938a37sf3423747276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 01:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722241851; cv=pass;
        d=google.com; s=arc-20160816;
        b=bMz1aSLK72MImbKfUyuC/BRnBraq+dLaOzjb9vJOPAv7q+07scrBR4/CDznxnzrTXV
         EsDU0EFW4KQeyuRFFZpFBq9g3KpiHEhsmNqNIll9R2YxjSI8CMPjP1YJmsGpz0gZQHPA
         85jo/4d5HW6X2g/FJYi0RbF3cmdRDKEUywwDbjC2/E9m4FIi/De00+L0KUS9vfDJ6AZq
         08Uks0Ict1iT7KpRH7ZbEuweR753OsOa2Pb56qSH/3Rv8trgWhQezIIsE2Cjd6ZVZ7Uc
         VDh3B/utFii57P6pBVCZTJKHewgZ0cH26fgoiKPwaiViYTcAJtnSquuLOJnmxT0L5e/a
         Yu6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9JoJ7yb27/WDpeqE6SOBmkE8F2gVrnoBylFjPA8XcF0=;
        fh=QMawZoC5j/oJxE/7aEoweDosgVq5fjrwEB0eZ0SiSEI=;
        b=n6Mk5ygSLwkqTpi0Ozfi59a6UgL73sTg1xAHnEwbLe0AEQG/M0SPG384sj8m4K/n2G
         bJApxHFkay7CuqwmWzMSEBblOeUvYx3OyVlmwjbIZnkoAPgFpUP+Metlndt1PTTQ6vmN
         k8Of4Y3g2DrBpo3QPM2tGqHVaLfOzA5oP/0QFV09gDrEDKHU5fQnAE4Jk00nTEU3jUA/
         gK4dbc4F+8zddqRAQ3Xqi/oLzKQjQPKcYq7GCBICbpIu2icL6HTY0OGWvoTrM/+BTMsI
         Pm3KewVkntgv0+TolFLkELCZYmeD8vWZJEUdaARnj64x64D67ib2KAh5HKqPcjpJHDny
         whDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g9Jpp6Sq;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722241851; x=1722846651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9JoJ7yb27/WDpeqE6SOBmkE8F2gVrnoBylFjPA8XcF0=;
        b=o/tVeD5fBSILlXvxY6cRJ+9Jb2fRe/APo+rYauuq2iO8Rw/5UxDI+bPcGgqKa6kDEz
         bQnPjuoegtGOHDtzWR8H51uXoCPTsGLm+wD0cZYkl3ixBaiLcju2OOuj9gApdJLAbIza
         S+WvkodHUGg/Vb4DIpTepvHU3s+rVK31Yaf9DPkCmxrq7vWok+TIPdiwOp9z/YM6ChhA
         Tvu26AeyOP96U1t6HtqdFWpqY5Ii4N70hFIu0CfDz+u3KHf/Yh+IRImU/4ECNZl1Hzdx
         RTpbiY86ptVQMT0gsMaM2nh2cMpO55i7n7ObZ3xehDnRuIjHW9f+ymOARHplNjyrppqB
         BicA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722241851; x=1722846651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9JoJ7yb27/WDpeqE6SOBmkE8F2gVrnoBylFjPA8XcF0=;
        b=ZkMluoGYhPGuB/iNJIUP09oAnmXjow3bgX6iDF2q66uytdi5EWpxAci1bI5f+PNeLX
         +oH+RjMsFF4DOakYSyVyDmBiK11kVZ4th3Kp3jACcD5ExG933+rNdhqH+s8FjpycCcS+
         PMmmNmDEIC+tw5XR4xoG2ZBSoMkqgEwudXM9TifYejBgO4KE+ZBxM26B8rYaLziBjh9t
         23zl+jKdQbrrlVDHvWi/+Lf4RPqySZpnFh4CXt1wHWoT/15697uEOKEMqryopElSYfB0
         8jTaZPM8o5XqwUIS6epxstbLW6gsQc74LsHZFxzx4CKUUFjayX/mhBMNPZvOOi6rYw2L
         /qTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgygyKmh53OMTFBr//1vEk0PWfFJ2+QZYte4xMs++OHTGI+KknuAVYWEdgerN8EaweRsXfku8/Q8l9o7p8xdOoyvnbR5S3+g==
X-Gm-Message-State: AOJu0YyNAlPeJ/zOEZe7zR8NbePHW0LY4B0gdzogea+s9nf8qhRe3QMl
	l/L/MgSc6Nt62XGp6lntLklq56U2x+RGcNuAYbyW05I3QreehNuK
X-Google-Smtp-Source: AGHT+IHPp7XqND+GbGHxbfkraWXGxityTNzRf3SlIpZFxMJ1D4VO33ZVJ1M28F1vVa1UX4VvAwLneg==
X-Received: by 2002:a05:6902:2b11:b0:e0b:6ece:605 with SMTP id 3f1490d57ef6-e0b6ece070emr3988043276.41.1722241851386;
        Mon, 29 Jul 2024 01:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1028:b0:e0b:46d7:809c with SMTP id
 3f1490d57ef6-e0b46d78477ls4320737276.0.-pod-prod-09-us; Mon, 29 Jul 2024
 01:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWS/ybPzjwVvo8d4BB70RCHYGjLC9eE/CSuNG7zJdvpojmlQ8EItVlPpKZKpD+odPj97JlnALJJUAwvKLeRotJOzGcPLjh12AuRFw==
X-Received: by 2002:a81:69c6:0:b0:65f:645a:b3c4 with SMTP id 00721157ae682-67a095958acmr74106627b3.32.1722241850647;
        Mon, 29 Jul 2024 01:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722241850; cv=none;
        d=google.com; s=arc-20160816;
        b=pZOFsAishG1JKT71Hu5WdawL7eFSlQZgxkAsjzi03w4uV+QK+c5Ark/tL28FXAWm6+
         zl4XmjAx4lrp8HHB0lRvdzQ9BdUP1FVNRxyYc0O/DmV+H9q+P5Qiv6D9sS3oeKuPVd2u
         vwwzkrjeigXqbMYKymUTe6ncNqerGwiRefuacH+3pffoR+7tAWro0w4Yo0FG1wdIjQuq
         7vxv8UMAemZ2nhDxbvrRbO7TOz6ru5Q2oyemEMn+r+Aa093O5rh3KjJWv1Tfsd4WW4gY
         aNGP0daAtP+iKd8eAdqo/L4aYdVx4mAj217vifZODmxwejDD1VvtFzzYe6YS6qQbmEXH
         34jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BXyPUaLFEwtL9HdgLuVBIuBGMnXshUe7E68g55fuMDY=;
        fh=bv/YoPPe0+XyYElAYyFNIlctUfEjqIRP7w4oj2v7NlE=;
        b=QDzF4dJvRz+pf+43uEsb414XWU3oyphnyxCbnzRLTIOWkAMiWz2wm5aY91huMemZ6j
         G5i8UExEXzOMPcjqMprZpRfdF2kyke0OX2uSs7F+A2orh1IzCRAElSZjlxkyyOzzroFc
         ZINnusS+rca8w4Uv28K6EDuvVQQK9FWGzrD9prGe+6OfkEz1jn4D7BNGVm8woiB6Spla
         b3ajsQBymquF/BIfZx75lpgq4pLnGf0xe0Hcbwch/nEPGc87UYAoP3P0cTxPUdyYPtlH
         ritrZdj0lcs7etLw+Er3IB6GIgX7WJA+X77DLbrW3vbrhJqDeqtDxM8OZqwQFcgnex0l
         U6Ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g9Jpp6Sq;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6756302689fsi5313337b3.0.2024.07.29.01.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 01:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-652-wb0pl83oPHywSPCvyvl9Vg-1; Mon,
 29 Jul 2024 04:30:44 -0400
X-MC-Unique: wb0pl83oPHywSPCvyvl9Vg-1
Received: from mx-prod-int-02.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-02.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.15])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0AF4F19560A2;
	Mon, 29 Jul 2024 08:30:42 +0000 (UTC)
Received: from localhost (unknown [10.72.112.54])
	by mx-prod-int-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 38D701955D42;
	Mon, 29 Jul 2024 08:30:39 +0000 (UTC)
Date: Mon, 29 Jul 2024 16:30:35 +0800
From: Baoquan He <bhe@redhat.com>
To: Adrian Huang <adrianhuang0701@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Adrian Huang <ahuang12@lenovo.com>, Jiwei Sun <sunjw10@lenovo.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-ID: <ZqdTK+i9fH/hxB2A@MiWiFi-R3L-srv>
References: <20240726165246.31326-1-ahuang12@lenovo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240726165246.31326-1-ahuang12@lenovo.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.15
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=g9Jpp6Sq;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 07/27/24 at 12:52am, Adrian Huang wrote:
...... 
> If we combine all TLB flush operations of the KASAN shadow virtual
> address into one operation in the call path
> 'purge_vmap_node()->kasan_release_vmalloc()', the running time of
> drain_vmap_area_work() can be saved greatly. The idea is from the
> flush_tlb_kernel_range() call in __purge_vmap_area_lazy(). And, the
> soft lockup won't not be triggered.
              ~~~~~~~~~~~
               typo
> 
> Here is the test result based on 6.10:
> 
> [6.10 wo/ the patch]
>   1. ftrace latency profiling (record a trace if the latency > 20s).
>      echo 20000000 > /sys/kernel/debug/tracing/tracing_thresh
>      echo drain_vmap_area_work > /sys/kernel/debug/tracing/set_graph_function
>      echo function_graph > /sys/kernel/debug/tracing/current_tracer
>      echo 1 > /sys/kernel/debug/tracing/tracing_on
> 
...... 
>   The worst execution time of drain_vmap_area_work() is about 1 second.
> 
> Link: https://lore.kernel.org/lkml/ZqFlawuVnOMY2k3E@pc638.lan/
> Fixes: 282631cb2447 ("mm: vmalloc: remove global purge_vmap_area_root rb-tree")
> Signed-off-by: Adrian Huang <ahuang12@lenovo.com>
> Co-developed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Signed-off-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Tested-by: Jiwei Sun <sunjw10@lenovo.com>
> ---
>  include/linux/kasan.h | 12 +++++++++---
>  mm/kasan/shadow.c     | 14 ++++++++++----
>  mm/vmalloc.c          | 34 ++++++++++++++++++++++++++--------
>  3 files changed, 45 insertions(+), 15 deletions(-)

LGTM,

Reviewed-by: Baoquan He <bhe@redhat.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZqdTK%2Bi9fH/hxB2A%40MiWiFi-R3L-srv.
