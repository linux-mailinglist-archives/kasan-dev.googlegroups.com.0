Return-Path: <kasan-dev+bncBDBK55H2UQKRBZGXT6RAMGQENPN523I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 29B426EE461
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 17:04:06 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2a83a0b7c32sf24128311fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 08:04:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682435045; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jv+7WtfQn/huFqviuasvza7xY2ahEht9S/aV96TP0lQx+y+xreoFYTZl7mhPvdfMfX
         lwqBgtMLQIiICJAYQSWtNp1KFQxt4ukuoeGrRGWzoGvtL+yLMh4MNEvxJpMdUVDkmW1X
         1coINsyri/2r6BAwIvVGCpiCqLGZh9NoAfKBhX6RHG6ex0sqIzc/Ahqj5H9H2u++FPz7
         5ZLCFbUl+L/U7+USMREi7S6eElj5EMl18Q1wiBrz9JTFzXL0bHNHxQn8xVgRsujS1HfH
         cwmyIrFVCNzeX/qS+ImYm6M79rcxKJGefh9F86r/w5H/GwtfvfHYGIODgM992psKocUY
         UIeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0GtGiLx2S5kv1xmxAP1kG0jauWtcUQGlrvGCSFb0LY4=;
        b=1F9ySmC0VQpQQenvyYZ1QYBaOCqv8EA0FFLDPEHY6hSuWUUBZnrEVzVK8BlyXnW7UR
         Gd+KArlSTFilzxwwCyOL8KNpgimmiFChxOgZh8ZOhPLqZ0qGQ9qUJp5AVXYgsb9Tlz+a
         mUUz71DGg0YTXoeHPZ1NIzBh/sbzvWB3O+wwBMtVafRnjYcZNvt3AkwEkAEWMddgkHCs
         prIGUKqidb0TcFXi/06qUN3S4cMYgp6FYSk+x/51ijgozNxK3rE/+rzngqNWTFhKIAdD
         zd4+wDvd4iDiY2X5+GATijQFkwiCVCpqe6bJpxKw0+Eb65IDnzjtWf5QQ2buBeYd1JZp
         ZJqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=qfDe1Xx2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682435045; x=1685027045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0GtGiLx2S5kv1xmxAP1kG0jauWtcUQGlrvGCSFb0LY4=;
        b=g6s7bdoBPV9a5bVq0vOhOpC75nAsHRu6yP3D/N5LlrhBwtspzG0mlMxYCPuBk2qI0J
         UaiNz1oqUkjxN9J2bJEzBajNNuhN7Y9FExHCFP6pKJtnhEpm/+5jIKR0YJd/nyg0G+cN
         GxY0pcauddxq5nTOgEv5avw8ODSxxFeQvBtus3xDcHxy/T/gP210+9EdAZP1So9y7T2U
         pBNkRW4emA08MVsrpGOH2vbvAGIKhVTqwogFvq7nQnONPLydoMER36CF8qaiwtzps+mn
         8FKDtKWwOed5jQ9TzdMQPvzHBSwPGa+UAOVtAK6Dy0cLQ9cRhwkpPA+vZNIKMTZhkaxA
         vhqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682435045; x=1685027045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0GtGiLx2S5kv1xmxAP1kG0jauWtcUQGlrvGCSFb0LY4=;
        b=ZHQTocYtTM97WcJHV+A11Mat3zqL6YF1epr85OwG3mUFkIfWzTKL/dDTBYdhAInL7k
         pN43Cn25Pn+631CUGKOPZPFlPMip+ydAzBJirKWJGqqPqrOAe9ncwc1VGcBOC7agZgFu
         8uIvGLwx2LcPB2EqIA/ImfL5jMRR2BAJiLiSMGIleRbIQOjAc9m4aG90321EPyaOQ9np
         lyiKaHKbUtEfr8kOzFrT+bF79QunBv+rmEKbXdqTBLrr+7ouGM6Unh4uZbxLEI1W6xJM
         eWzBayvilY07XLapi+QDeSlm5fHDADOHF5aMrfWtZYlM9ZniwY/9C3CSVTlj+WENh1cg
         4uog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eebiF1rfUtxDc2yhlNAOAZ7+fK2Fhu2NsZofgHmjzplFDHLEJs
	1J00RLdvM6/ZHOZp77SRatQ=
X-Google-Smtp-Source: AKy350bVDMZTLzF9AmTRdoIH+QaaXHTZAAdllOm2DR/gBhXrb7giU8fuCZl/pekJG99qOFsCchJ4rA==
X-Received: by 2002:ac2:5d23:0:b0:4ef:ec94:9667 with SMTP id i3-20020ac25d23000000b004efec949667mr2024317lfb.9.1682435045037;
        Tue, 25 Apr 2023 08:04:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c92:b0:4e8:c8b4:347a with SMTP id
 h18-20020a0565123c9200b004e8c8b4347als1587246lfv.1.-pod-prod-gmail; Tue, 25
 Apr 2023 08:04:01 -0700 (PDT)
X-Received: by 2002:ac2:4153:0:b0:4ec:89d3:a8a2 with SMTP id c19-20020ac24153000000b004ec89d3a8a2mr4396888lfi.43.1682435041788;
        Tue, 25 Apr 2023 08:04:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682435041; cv=none;
        d=google.com; s=arc-20160816;
        b=MHRWlZZgei/6NxwDrXd9KZi7tSvO9JeDLQZwxgrR4X3Z2Py+UjhpFFksbuz9kBo1E9
         ce8HBKk93LsuS/x56deL3awwksFLguE2kTlmt6CPBw3F6zaaIAilczzNleJkoqf41LBA
         xzpqXLdT/TDiIyUxaeljjkAyDTrw2vkwPepbh7BrQRXa4lqEeZ6h945WF6TQOkW4M2X2
         eHZgdWhAbxUFuQRayJkAdjYgb1pzEwFIYJz6WSei3+c/y8yr+OTObegeQRYU9GkWqNZz
         kOz+Q2xtkYIyXz7AlBuxB4sbSt6aJS9svDNKKBKO0AyDsOR7lY0ObxKNwIlG97Lc5K3P
         V9zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eZ6qtyBTxkPS/Vd6G2zvBKtjNEGs0l5IwnRWNQv4ceI=;
        b=iW1UHni9l1rcCiXk0MONods9oYaR8QsyCj3PkbWQcsoLojdgCQchcEF3SbliB7WXsG
         d+V9S1dxqRQvYzsEC7LJHoY8gNsuvAnm7x6Qu9okm5JNFu+564/dAEihaVsm2U2ZZwyM
         4oUP9pwxN1pRL+PlsxEJU0q4R9gkofcmvGZnZt8/bckfM82r04hqoiGBSn66+Zwu8Lk0
         LYZSQypOpP6PLXhoUfcxhBltO1Gd2OjeLMvqR/AeBqh14J4Y0ybLkvHsV4X5qGPU6sB7
         R7kzUPCOjcFra+QgQDo7AtBw7Z60mC6R47/ZTNP0uQDT7W7kiEEgSpie8jwE4j/Ml6sw
         9v/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=qfDe1Xx2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id g33-20020a0565123ba100b004efe97e3546si487244lfv.10.2023.04.25.08.04.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Apr 2023 08:04:01 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1prKCt-001Xn3-IN; Tue, 25 Apr 2023 15:03:51 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 215C73000D5;
	Tue, 25 Apr 2023 17:03:50 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 12C6531C76403; Tue, 25 Apr 2023 17:03:50 +0200 (CEST)
Date: Tue, 25 Apr 2023 17:03:49 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>, Zqiang <qiang1.zhang@intel.com>,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Qi Zheng <zhengqi.arch@bytedance.com>
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
Message-ID: <20230425150349.GG1335080@hirez.programming.kicks-ass.net>
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
 <CANpmjNOjPZm0hdxZmtp4HgqGpkevUvpj-9XGUe24rRTBRroiqg@mail.gmail.com>
 <be865fb8-b3f8-4c80-d076-3bbd15f3c0e8@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <be865fb8-b3f8-4c80-d076-3bbd15f3c0e8@suse.cz>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=qfDe1Xx2;
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

On Wed, Apr 19, 2023 at 09:50:23AM +0200, Vlastimil Babka wrote:
> Yes, the problem seems to be that if there's different paths tor RT and !RT
> kernels, PROVE_RAW_LOCK_NESTING doesn't know that and will trigger on the
> !RT path in the !RT kernel. There's was an annotation proposed for these
> cases in the thread linked below, but AFAIK it's not yet finished.
> 
> https://lore.kernel.org/all/20230412124735.GE628377@hirez.programming.kicks-ass.net/

Oh, thanks for the reminder, I'd completely forgotten about it. I just
replied with a new version... fingers crossed ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230425150349.GG1335080%40hirez.programming.kicks-ass.net.
