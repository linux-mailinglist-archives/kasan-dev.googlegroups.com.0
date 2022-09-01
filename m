Return-Path: <kasan-dev+bncBC3YFL76U4CRBIGCYGMAMGQENMXFZ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 422925A9069
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:37:06 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id e4-20020a5d85c4000000b0068bb3c11e72sf5961262ios.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:37:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662017825; cv=pass;
        d=google.com; s=arc-20160816;
        b=tOnZaQFKquHyoeYgB2Y1StNG97DYFJw0EzDi5j4A7UrRMdMeJxdcHT4fD/+3HO58xf
         tGJhiKl5Wb6RT3JyIIPT8OsUdBAtp6xgp3VvKwyw6UYCaBf4slhIovbm/t5mbcPnCLLz
         SyQpn5rbMBnlP2HQKnHD+04cEnVRNlg0DS340om23F+WJlZJSULj6HS3lGoBNvhkheJh
         4XKJQZ6Gwd6tud1GL22sLCD0aVs5r9K0P6hou1QaVFgiO2U6BUblXqlWuRjbI3qR+qIX
         RKhIGu/w2UUrpKQYkvsto55aYRj8KVfiAOzUnT1257Qc4ZeT/kfBVLzOT+/K3HwEoYNA
         feCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=F3ezih+Bfr9FyYzY+iizdu86eXW5Csw4AQiDAIoXQlc=;
        b=UzpehT8/VlZTlh33hTb9UQ7omSu21VeuhA7dN6KX0MU/pG6SqG1Vee63L/NBYGc+84
         ws04QaJo7uWrWY5aGWCpiXvNl+tmDG2MvN7vJ1Fay+GhoRy0qizkzSALFMxCPx1Umosn
         UTqm4J5yVUY8IgbKmfyNzXdUDuEsaqKXskdZVLGjfZQTgmRja72GJECUwY6HlrQ4Msld
         ELbIlIjnvmNk4DRHNRKRNFU38bacYyTvC2MAAj1+p+I7D3mBeSBc0bWfX7HRPkzswcDu
         jaU+nfKqkP5LIMLIJ+cbyt6MSwp89iUgkzyGpYP5Rt1EdrYmd8+em3hbZuPvu0FkhgKV
         VVBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DgayC5dy;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=F3ezih+Bfr9FyYzY+iizdu86eXW5Csw4AQiDAIoXQlc=;
        b=PnrpCnKbCRAxHfVo1LYhE25UYk9pV+eQYz3gEDFB0cLbYpL8zRozFa9gVH3VAv1P23
         7g8nCj8WQ1lA5MMN/Xnm/ysNYRuCexwG8PLEnEPDdoEBgUiyXbGvpayE2fmHBdK5QeO4
         jSoyZEzdVNGszW/1tIs6GD5HUROmqh313ZIxeTPz1Ry+/YtfldKFqzJqfaqxbUMDfBpJ
         LezSUxlk9HObzLt3tC7iXhSCryv9IvZrTRRA76EuMDCZ12x+2cz6wchz18h+WrpZrMiJ
         oi4uSBl9S5qDbGKuewbjmQ6Uf7eSF5C1I5Su4vaPHZd8ctkwazFEaCw6rfh6HohwjUj0
         Um4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-gm-message-state:sender
         :from:to:cc;
        bh=F3ezih+Bfr9FyYzY+iizdu86eXW5Csw4AQiDAIoXQlc=;
        b=P1bZJw3pJHfZMsXqE0lEZEEbIsjH8buO4tqqqps0hyoc24iKh4hD8M11iWwot4h0vT
         03nPATX12C2YfEZztrmGjwyC31+xllfsWzjIjmvJGGhfls2nAR/6uIm9skl8D9eW7pLJ
         7OfxY2MMnq3GdKU35yV01UaOAEFpI8Jwz3ZyDVTwh8sIwOvL+Wv41B9R/5cX3b07RRcb
         jhrqQLQITeBJsUZ/5r/NJu9jQr5rssnnS4J9B7yhWjK3BCfNPaFhefrjHYOYOOABiXzD
         3veXBYg1BhA1349r7cGbHUO/Dwa+n2c3WdfVqYV/JkjkbCBp6BncHjS+d3p9AlPtzrku
         oIeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2zTVhmVBFfTejM1zuyR7LiBAIGUw4XmKWy55br9zlzutMbZFpM
	x6Xz4dLmEewER+LkhMC7RBg=
X-Google-Smtp-Source: AA6agR5xQMam93cM9NxfTLv5cwmVwvfME9JyGPL0Uh/eRty7h7ds6/6xdRzVqOOQa7Eb9rY8UQGMFA==
X-Received: by 2002:a05:6e02:1bae:b0:2e5:aa0f:154a with SMTP id n14-20020a056e021bae00b002e5aa0f154amr15616445ili.295.1662017824815;
        Thu, 01 Sep 2022 00:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:378f:b0:688:a413:576f with SMTP id
 be15-20020a056602378f00b00688a413576fls174940iob.0.-pod-prod-gmail; Thu, 01
 Sep 2022 00:37:04 -0700 (PDT)
X-Received: by 2002:a05:6602:1343:b0:67c:aa4c:2b79 with SMTP id i3-20020a056602134300b0067caa4c2b79mr13410493iov.172.1662017824198;
        Thu, 01 Sep 2022 00:37:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662017824; cv=none;
        d=google.com; s=arc-20160816;
        b=Ue+Qw9fbGyyzO2BXj2b4vxm3k+UOcpnRFNUjmjScw0ZeikS1kL/jW3JWCMW+eN3X6t
         6f9z0pTwtW8i8q5H82Hpqcxw/PUBh1ckY8ku7jzFTC02DUK2hxe3+0E6NF/fiEbZcJLw
         ufVIdlRj7JqXAHg250Y9uJ6UBulgqZ4zrO3a3jJeZcBhDNIk2DUjNcJ3TxhhtjClE/tI
         HNtHbWKdSaMh85vrY+Gz+t06IozCLTk8FVP0dEhhwzr2leTbV21pY5sHHogn91NVYvBQ
         wGruS7jDlo0J7Qeo3kHSTvto3s7znxAzpQhy8A676IwetozXGx4ribW9ktIzRK1gF9fb
         wzrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=w/uTT8lnpogUVhwkYNDxdhGZzOyBXG3eWWImkgPiyoM=;
        b=QLgsfQBw8koea6VdTeuSXojH6qzyhUQrTKkZzqaBdh/h3oOY+/tZbqxTOlhnfL62ZM
         8/Vkd5wShXfbE8wJiZy9vhyJEKR7iZDnGx7ZE5Be54mmt5mwXluV2Y4Od2ZVe3cXVpvZ
         zUEONKwX9fKp5t4l6DJww7RWu40SCGhwIgbtgfgaBdebhWvIt0caAm9jLsXMkdUTtQsk
         kSaU2ZmF8N7GO8K8vFDMs6iGrESZpzr/qPQrBjq/JVl3RyfkWNKK74VVshDkHnEhBzi8
         +y8+nq2KTENWkTb8TRMVdIgUvEruGSdROuvoFC6XeLN1JBFoHTIAxBy1QWKpBvTElR3g
         V/7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DgayC5dy;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id t9-20020a02ab89000000b0034a5b140fc4si307209jan.3.2022.09.01.00.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 00:37:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com
 [209.85.208.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-606-7fSr8ht6OkubnW9oonlPAw-1; Thu, 01 Sep 2022 03:37:02 -0400
X-MC-Unique: 7fSr8ht6OkubnW9oonlPAw-1
Received: by mail-ed1-f70.google.com with SMTP id y12-20020a056402358c00b00448898f1c33so6754448edc.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 00:37:02 -0700 (PDT)
X-Received: by 2002:aa7:d90e:0:b0:447:986d:b71e with SMTP id a14-20020aa7d90e000000b00447986db71emr27210723edr.235.1662017821495;
        Thu, 01 Sep 2022 00:37:01 -0700 (PDT)
X-Received: by 2002:aa7:d90e:0:b0:447:986d:b71e with SMTP id a14-20020aa7d90e000000b00447986db71emr27210669edr.235.1662017821253;
        Thu, 01 Sep 2022 00:37:01 -0700 (PDT)
Received: from [192.168.0.198] (host-87-8-60-205.retail.telecomitalia.it. [87.8.60.205])
        by smtp.gmail.com with ESMTPSA id u24-20020aa7d998000000b0043a61f6c389sm898086eds.4.2022.09.01.00.36.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 00:37:00 -0700 (PDT)
Message-ID: <37a66a8d-859d-5a8b-e298-d0c32e2028e7@redhat.com>
Date: Thu, 1 Sep 2022 09:36:58 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.0
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Peter Zijlstra <peterz@infradead.org>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Suren Baghdasaryan <surenb@google.com>,
 akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <20220831155941.q5umplytbx6offku@moria.home.lan>
 <YxBZv1pZ6N2vwcP3@hirez.programming.kicks-ass.net>
From: Daniel Bristot de Oliveira <bristot@redhat.com>
In-Reply-To: <YxBZv1pZ6N2vwcP3@hirez.programming.kicks-ass.net>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DgayC5dy;
       spf=pass (google.com: domain of bristot@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
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

On 9/1/22 09:05, Peter Zijlstra wrote:
>> Also, ftrace can drop events. Not really ideal if under system load your memory
>> accounting numbers start to drift.
> You could attach custom handlers to tracepoints. If you were to replace
> these unconditional code hooks of yours with tracepoints then you could
> conditionally (say at boot) register custom handlers that do the
> accounting you want.

That is strategy in RV (kernel/trace/rv/). It is in C, but I am also
adding support for monitors in bpf. The osnoise/timerlat tracers work this
way too, and they are enabled on Fedora/Red Hat/SUSE... production. They
will also be enabled in Ubuntu and Debian (the interwebs say).

The overhead of attaching code to tracepoints (or any "attachable thing") and
processing data in kernel is often lower than consuming it in user-space.
Obviously, when it is possible, e.g., when you respect locking rules, etc.

This paper (the basis for RV) shows a little comparison:
https://bristot.me/wp-content/uploads/2019/09/paper.pdf

By doing so, we also avoid problems of losing events... and you can also
generate other events from your attached code.

(It is also way easier to convince a maintainer to add a tracepoints or a trace
events than to add arbitrary code... ;-)

-- Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37a66a8d-859d-5a8b-e298-d0c32e2028e7%40redhat.com.
