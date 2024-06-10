Return-Path: <kasan-dev+bncBC32535MUICBBOP7TKZQMGQEMCDTVHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F16CF901D5F
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 10:56:26 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5bacf94fc7asf2911489eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 01:56:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718009785; cv=pass;
        d=google.com; s=arc-20160816;
        b=gOIMpxhwQoWNz2fVfcb6mXKgiGQqerWOyD1WQbdxxD34xbSzFezqrPRmmqdhFLbkYl
         4CG+Br6NLNiVyFbm70uRgxrpr/mEbCVNStyG+ud1UrpB7WUnK4Iq+FfLEvokLwTuvS92
         dMHRXSQcP6atA5J83WPXUnuluzZbnD7znUH3nukJFIPcihT5xY6hcGebpPp/uPvR7PYk
         Ib+piu7kp1jQhSpXe2Q94hADPyuutsGCbiW/X/WcrKQINv9gww3V7kJ4PLl92KL+wUPS
         xNu+dI+YnizGyFgPx387qr5PcA+Vr95+MAa6UKfd6k+CHKcSjQjWB8Y5LSzuolfRwVDB
         VMDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=VljFaihOxSSdspJWBfX67AW+RuYvPPEOIdurp5cHVBk=;
        fh=56TeOhXnNH4IXG9qJu91J77vcgzLHvjquqy0t3YY0TM=;
        b=LtMzeESgfETZSOQFOeFO3aDjVbQOpK3NhZhJqgGNXc3PTU5OX9otIJMunhQrC8hdIG
         JjeBTZcwu6kAtF8n72XY/hOhAXa/my/il5Qt+hW91c5gh07fG2vaLJ5syGQnQZD48zzQ
         Klv/HdUH90prPeY7CtdHwpMIrDjW9LYuot5rZ7jrb/KbnvoS2fJmKxTaswdsKrMm5hwl
         JPYspN3UukeXLLwA6xI7cyfHVFNwGNCx5rbtncpr01CVnnNkdikWyBIl65+3HzGZrVjW
         ptpakgdpBOkv9IqGNBfHO4Of9e8PmLPfdJljZdHODexLt1hDTmslOKPyZ5D14Wf1DkG4
         QkZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DaDQce6F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718009785; x=1718614585; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VljFaihOxSSdspJWBfX67AW+RuYvPPEOIdurp5cHVBk=;
        b=h77ny7wfnbkI664tFGI98DH38I49fLvEASku+yNw6AT+TRQ3/coQrVwWjyc78po33p
         ulMeEaQwir184mlM0OrOBkh/ZISOeSkPxxMCBTtgyTqDDyInHsvgF23lVPL3k0ZOLc/Y
         p1davL6+BHxjKPEjuKIfP8z9PV7N9Wg8eDj0Brg0wMB8979yLNz4x8q1HysCHXpnmAD4
         xzSmItcy1Cf7ycWNRT6Dbg2Vx3qO9aDsOnE1avJ4jQwMA3sngnLBuO34iniKnkqgWyvw
         fKc2+R/+abymWsW1Wu4imylFZIk4N7ysWiaSsiTRvOhwhuaBY5AhbkQCGVHHIRc3Ql/q
         DQog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718009785; x=1718614585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VljFaihOxSSdspJWBfX67AW+RuYvPPEOIdurp5cHVBk=;
        b=TfYN1awXvxhkTU+F/DgtuEyIrzNpKdIgpB15L+qFDivZbXoRw9CChsClD6S6+x34+9
         va+6CiNZeQ6AMTwCFCpAV/bjsNrigC5Wp5SgZ02SrXjdM+KfBR/BggF2NW9qYMVEh3Zc
         a0BbBWqyjiXzvYyLyARkaMUGm1QoTvFt5q+Kt4ftPy14ShKaIq4qhUl6+pVqI2cVgNcY
         7Vsr3uo+2yC15CGSm+gGv3A2qAkelK6Jd2GcW6K/3ScNu9Wyr/5ZARJLEqosfvo+Wiau
         JW09tX5fk7NYDNxyuSd51qhvST1QkXRhEs8Cg824sDwLllpvTqvbZCVCHLuc0Z4JwGUm
         mkyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCzF80YoOF/NVElFkZH3zpUKTLbnNEs/1N4M9wDVZZ/1y+idQdtpsn32k4KFb1LTVoQMY+RztTgB9Fb2E86tEu/mrVlk4K8A==
X-Gm-Message-State: AOJu0YzJmYYQ/bcAZHm+TAA3bJG2CqExaizu3hyR67FtF5xAQqG17D3a
	avIQhjFlqcN3shb1W57D0YA8171wu9uaKYvTK/aidaHGhPAu3yXP
X-Google-Smtp-Source: AGHT+IEFT8MVocyPhne3Ex2WdS54RdPpELamFUqd9TrK/3/OHw7Z8rKi5N/5Nb8LflvaUegMgzDdcg==
X-Received: by 2002:a05:6820:221e:b0:5ba:f004:cbc3 with SMTP id 006d021491bc7-5baf004ccd3mr2385067eaf.7.1718009785389;
        Mon, 10 Jun 2024 01:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d47:0:b0:5ba:68cc:8c40 with SMTP id 006d021491bc7-5baaa2d98ebls3479872eaf.2.-pod-prod-09-us;
 Mon, 10 Jun 2024 01:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+ANEEoQnKtu/vJjg5pgaoaJdgAgHYm7WrJnixLYMtXwlkTPv+TFncQuYfqdZpuuTggOQzwoTLDC8OrhH///vHwFod4viVtVGdPQ==
X-Received: by 2002:a05:6808:1456:b0:3d2:20e2:368e with SMTP id 5614622812f47-3d220e2379emr5538531b6e.40.1718009784317;
        Mon, 10 Jun 2024 01:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718009784; cv=none;
        d=google.com; s=arc-20160816;
        b=N8PfkcZDYxjH5yXhA/pxJ/xNSbKRnLb0nKXGuh1Qq+UeF4eO1xCQDOQc9+UK8ITRQM
         EPA35//D/KkNPvKo+StRc/d1BWyW0zSQV/++ZTiDNCUAE9xxnjn6frrgz0bvaqBpdPYb
         R2rUQnZOtNBaq9qHpartM5iZuWELMDXkbj6rH3qm356sPLJ33ZmSVekK4GkbSKi4dZRt
         FNfKS+FnUaf6SgaHcXH6LCQBm424MhFXuDmYMKC6D4S56k5AQ60z0FyQQ1zTrJbJKqez
         ALmbiWvNvt/JsKuFb3SpKletrS7ECrDD4iRfG0rZgVPOciBKQpOpzInmJTkIYiS+++LL
         aQYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=QUbORrAp1NZZYf9SPcpO+7DjP/I7StvG/pRCPWB4lqg=;
        fh=g1Z/CqZlkTS+BAQlqvrlgfrZs6iihGdGKmCKsmPuY4s=;
        b=EXPG2672YTro2+4+tOP3KwCK/X0kgNMYvTXbyIjLI7G3KIVzVpyPfK/Jf7IBSu54Lv
         CytLrmEk3pP2hN6fN/4U3GsdJvLZK4Zo9+BBKny34O3MUmZf8wYRFyKsPUQGrG8I/7ze
         6rK/sziOvXhI9tblhfqvpFzt5S7F6PMoA2MhZipP7oy1JruxGltahNUxyguOJx1IvOpi
         yv7HV/i79U94PhxuSC26UGPEtwGGRzDo7PCyfjZgJFa2d+rHqWgcjCFnJkcGC3rOd/v/
         47jQ+aaSox7CnvDdA7HReLirRlRCu5m2x2FSARCCG1WDnU8S9A1mJyXIVsiYnNgPaRUJ
         /ycA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DaDQce6F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70417015bdbsi324865b3a.0.2024.06.10.01.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Jun 2024 01:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-663-B6l6bwatONeOh3R2kAXdtQ-1; Mon, 10 Jun 2024 04:56:21 -0400
X-MC-Unique: B6l6bwatONeOh3R2kAXdtQ-1
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-4213441aa8cso27261865e9.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Jun 2024 01:56:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVPukEDNVPHK3d0VTeDzXhKi+6DX6YjsXxR6k8s8qoBbJkELFKk5zyYTbQRy3eU2yhdd2vbCmXdx7s7Rl1tNZssohlxw4v5VrZvvA==
X-Received: by 2002:a05:600c:4f84:b0:421:80d2:9db1 with SMTP id 5b1f17b1804b1-42180d2a37emr34136935e9.25.1718009780259;
        Mon, 10 Jun 2024 01:56:20 -0700 (PDT)
X-Received: by 2002:a05:600c:4f84:b0:421:80d2:9db1 with SMTP id 5b1f17b1804b1-42180d2a37emr34136735e9.25.1718009779932;
        Mon, 10 Jun 2024 01:56:19 -0700 (PDT)
Received: from ?IPV6:2a09:80c0:192:0:5dac:bf3d:c41:c3e7? ([2a09:80c0:192:0:5dac:bf3d:c41:c3e7])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4215c1aa2f7sm133235285e9.14.2024.06.10.01.56.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jun 2024 01:56:19 -0700 (PDT)
Message-ID: <aa370847-14a6-4806-8a04-d2da0a591014@redhat.com>
Date: Mon, 10 Jun 2024 10:56:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 3/3] mm/memory_hotplug: skip
 adjust_managed_page_count() for PageOffline() pages when offlining
To: Oscar Salvador <osalvador@suse.de>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-4-david@redhat.com>
 <ZmaBGSqchtEWnqM1@localhost.localdomain>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <ZmaBGSqchtEWnqM1@localhost.localdomain>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DaDQce6F;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 10.06.24 06:29, Oscar Salvador wrote:
> On Fri, Jun 07, 2024 at 11:09:38AM +0200, David Hildenbrand wrote:
>> We currently have a hack for virtio-mem in place to handle memory
>> offlining with PageOffline pages for which we already adjusted the
>> managed page count.
>>
>> Let's enlighten memory offlining code so we can get rid of that hack,
>> and document the situation.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> Acked-by: Oscar Salvador <osalvador@suse.de>
> 

Thanks for the review!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aa370847-14a6-4806-8a04-d2da0a591014%40redhat.com.
