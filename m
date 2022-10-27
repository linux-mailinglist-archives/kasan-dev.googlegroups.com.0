Return-Path: <kasan-dev+bncBDBK55H2UQKRBSNT5GNAMGQEWPAWIAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E50C60F4A6
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:13:30 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id gt15-20020a1709072d8f00b007aaac7973fbsf717231ejc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 03:13:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666865610; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0CyWSXlcpk/RMjtvW20qVX2kJNfB94F2rTqHlIWfbOW+JjQ7UDjvUy1HuR4NWw3+N
         lafSya/KcjYFQW8vbfDkq7l0DO/GmXgKEFFuSlSKMkAZgXLZFqroGUsUb2Mg8L5FqB68
         UNZHqOuia6E13uVTYi3Y3stZE2A5BNgivIS59Zm9jldLbUHLHuWU84/H1+eTzkNTqXQg
         ntvaywH6/yWNfhVWoncgDRIy/UyfLmccaIGr3WGANB0WMKYxriGlGjI0zYbQXVLRKTfn
         FV6jKCisTNnM5lDJ7d8lc+IKcF384kGQ1GU1c3h+XV5sH0ACQd9yhYg5At1a27c8sBaq
         /XvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C4reW7nQn3xSGo/wAJR1i2lo/f4n3yMFV97R8G1XFcw=;
        b=qYO0rCztE26lQNyKNp0gJHfr9evZGdDJDHyFGZVLCQEib3dyS6jSIoRoX2kCyJJ1Du
         5VJj3jkBQqKlVLO7BJ7yBoAAGmnwSdLANnLq0eUc5wvvepwmPhl2c67Ze15tkZ9kp79F
         +xdQy7SYfZtUaCLa/nW5y365aE8oqr/tZwUPObWeiLiDEwzDKWnsw5yVXiHvLLnG1xFe
         4KmMaYdHpITtCWQv6s9lV5/OJR3PYS/TXIZlXOsb8Vg3Csh/+34YnyuOQb4LvEFaMlyL
         LkHvFHqIdn+Ozcq8ZJwLjNQgD2aqnZqDsO+BGij42bsiPix4b4YvUz5NM07Tp0j9iC+l
         sMzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ejJYmTDq;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C4reW7nQn3xSGo/wAJR1i2lo/f4n3yMFV97R8G1XFcw=;
        b=fHAFoFulo88s+6YM7NjmndkM/yTw/CNuUZmPvKUwrDD5VNx5MizHHBKfX20VU5OivV
         0zz+0L/Oh0G0n7iaaOJxM0Mp9da8rin35fMebSFscDvURpYC8vUfiWljxgasd0EOOWE6
         +CvJRgBDu6orVn5gOF28gG+PRw/dpbtv+PcrWDPt8JyUAjrEg/92fgnODfjFaOJ8JdUU
         KOSucksncR58Ls9eHMywKiLZFCjEc5VM0jJJV17cW4c0cT29npXX6rHQcp1ShS76/o3p
         eRiXMH41XjxhsEMzc5CjaQFAX3R712sD/6HY1YFZ62MWaHkcTfgCGcApbjg3OTgnxKZT
         OuTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C4reW7nQn3xSGo/wAJR1i2lo/f4n3yMFV97R8G1XFcw=;
        b=LXXGrc6FtwbYw9/x8BiDRSz9v1PjHaRb9KjNOW3Dg2hZ6Id9pdRzOItqJdMKYaLyEL
         YrnQwAqmlWT6Q/v6VIg/ckc4v7JmdrhQD91kai0sXaaQKl/2c7e006OkCHaRJR1yELYW
         IQBzQwi8DLEXyhhZIuQ3mIHubJXli46iUHD7iRrX9fk2C+zfIyZ7N/XzogX7cR37ew3B
         tiUqRLsc7INQcOJUK7GM0EdFptkJmEkW/If5amshhCqzUU/zMYnL1/FXBmUscrBm4cmZ
         l7rLSsiWIT6QLMqbfYbkB0mK1k7zIYdnzgpFjIgArYUzz/KYFGTs0GN0/Q+Hn8032BaB
         Zvtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2VLxiN8GJuGJF//3ua1LJAJFkgk4PNDo6t2uX4EcYESCK05eiZ
	/wyMXkyT0T/KkzBQVbJtbss=
X-Google-Smtp-Source: AMsMyM7VFzwCs57rV9H8XHDrX8f2Kzl65Q11XcdNMb7Pun6xQ64aIF9wQZKNWBcaTlNig3ErwkaXjQ==
X-Received: by 2002:a17:907:3ea4:b0:78e:25e2:c33b with SMTP id hs36-20020a1709073ea400b0078e25e2c33bmr39695808ejc.603.1666865609868;
        Thu, 27 Oct 2022 03:13:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6a93:b0:791:9801:e4e4 with SMTP id
 p19-20020a1709066a9300b007919801e4e4ls9810307ejr.3.-pod-prod-gmail; Thu, 27
 Oct 2022 03:13:28 -0700 (PDT)
X-Received: by 2002:a17:906:ef8c:b0:78d:46b7:6847 with SMTP id ze12-20020a170906ef8c00b0078d46b76847mr40803090ejb.241.1666865608614;
        Thu, 27 Oct 2022 03:13:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666865608; cv=none;
        d=google.com; s=arc-20160816;
        b=y/73y+E/YgZoKaOeEWgI3er4805RFbuQkUwYra78uTNrKQfMc+Z/NKFjk2BfwqcMyu
         bWEPh6x8/t4oozZbxeiw/j+a8kKuR/vUsijfPBauzuqOmncFzBYlfU/kdGFzcKXXkPfa
         +scCjcLdx82X3V+d0XRNJ67/s7CUMSAvSX+xesdJXYyqTWORDdaRCYu1Rg4/rtE+U5k6
         jtzrOwKsu09szFtyBRCcUPUSyrVSGS/usNN51iYXjslrM4M5NVbzborKQOGpvwrVMA3C
         iIqrki3KGDnEdTg6y2IMBZH2AMr4/7RHlIluWPkBtRiYOkgFw3XmkZnYRhcyodP+Edm5
         bf4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ujmvw+TZR5k4uN3HoiTdwWd48LImUMTszRZtFiaHkwM=;
        b=ifMs7NAs/VWo6D91UPnwZHEcmMxVznHQ5Gojqz5EBWW3DWlrvqFwcxXMucjT0JMDu2
         oNbY4DrIO+Ecx1/hkcDe07+HofQQAP0Z65IGyZYw3dNwseDbLeQ0E7XfkZsNmv14LU5Q
         durFMchjsQhhC+ACkTPizjxiyCv1HjrZSOyNjkPZVvGKT+z3La2Yhej3VtC2EGS/dL01
         +2i4fxtn4JjQdQpDZrUBIU6qmNEvu2zQGC7XhYd4TF3m0tobTtS3gjp3KyLDBmuoLY2+
         /cFc6iuNy6IASCXoXZgRWoq+BBFuNbLAYYSZSyJkJD+617VUtrsHvOMWg7Xast2H1Pnh
         1C6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ejJYmTDq;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id y24-20020a50e618000000b004621a13c733si12623edm.1.2022.10.27.03.13.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Oct 2022 03:13:28 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1onztA-0007C6-D6; Thu, 27 Oct 2022 10:13:28 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 344BD30041D;
	Thu, 27 Oct 2022 12:13:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1D3F32C450484; Thu, 27 Oct 2022 12:13:23 +0200 (CEST)
Date: Thu, 27 Oct 2022 12:13:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Yujie Liu <yujie.liu@intel.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, oe-lkp@lists.linux.dev,
	lkp@intel.com, Dave Hansen <dave.hansen@linux.intel.com>,
	Seth Jenkins <sethjenkins@google.com>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "Yin, Fengwei" <fengwei.yin@intel.com>
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
Message-ID: <Y1pZwwuRfYmh8A4L@hirez.programming.kicks-ass.net>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
 <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
 <278cc353-6289-19e8-f7a9-0acd70bc8e11@gmail.com>
 <Y1pXJheAg+sMj7eG@yujie-X299>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y1pXJheAg+sMj7eG@yujie-X299>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ejJYmTDq;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Oct 27, 2022 at 06:02:14PM +0800, Yujie Liu wrote:
> Thanks for posting the fix. The issue is resolved after applying the fix.
> 
>   Tested-by: Yujie Liu <yujie.liu@intel.com>

Excellent; I'll talk to Dave if we want to ammend the original commit or
stuff this on top but we'll get it sorted.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1pZwwuRfYmh8A4L%40hirez.programming.kicks-ass.net.
