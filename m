Return-Path: <kasan-dev+bncBDBK55H2UQKRBL6732MAMGQE3L6ZIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 579CD5AF630
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 22:38:08 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id j12-20020adfff8c000000b002265dcdfad7sf2832719wrr.2
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 13:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662496688; cv=pass;
        d=google.com; s=arc-20160816;
        b=xmjMkB6pEGOE/ei9vobegSae0z/tM9/gj3FeQCqCs19OV+Y9vc+vUrYJYVkHFFvXMn
         lhMGokWSEN5z72VRIVQh5VTaD3BaiiOk3zECuVXdlxgk6Q+aOzgYXckS+y7QgZYXOQKr
         yyJkP0hw1/yAp/yPnUUb1JPBwPEiqSsC5dq+GiZfH6uFqvgjGTvYXdLD4IpLmdDKgVDY
         fzYpoLuBEMspza7JgMXfkc0OpYXsyVaXv586pKtDQeTYlCPpBKvva+jshnMFwELDJEmH
         TbVFe3XK4QbfwDSheT55ysYMHerQjTmni28uK7xYdAZOXrkjkBcFpQ2Ri/WWSaGjKjA7
         WUVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9fLEKxx3eXOI7M71zoICWtBuWb3SZI6deMvYOmgNWdc=;
        b=x7xZsfwR5KSyy2jxH2+86Hmw+fjaybTVmEzG1PYCkqXBmaNb7aHFpgiUxOkQ6Yepg0
         kbpmPMUAuJx1GRlDXNtHzSBW4hyy3NTslUmMU28mhOgBj2eURd5Fg59kvCfPR9WoRGxx
         dRjmUMBJQkO2FB9DHtqSsOENmleiH9T8P2X4PKeVdeJ30o9Jb2kq1ImccLPpna1LWsW0
         yLHFDKoRx9xrcUJ1GNjoX++TSu06fyQ8gbil+Ui4ZlDy8jSwM4bm2i9CJDcNWVHklk8V
         llyOz0bHUEZ3d06kWOOfq+GO2MomHqzDntuPKfOxRP6EqP1t7ZFqldS3lYuKGFLpMqAC
         z8TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=jPxkDIeu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=9fLEKxx3eXOI7M71zoICWtBuWb3SZI6deMvYOmgNWdc=;
        b=Hic1KvVh76t8KAsGWZYfuzu+nSHREUSqFQQ4J0ktJYfyt6fGWP0Wkh3m/+PQ8eoeuC
         /0fhupMTTrYWe7Nl1H/R48UNGhpnOQx4eLY2kIauuRi5+a3PV35O2M3bc43EogRw0jH1
         AMoaqUeUd3y50eqNbOo+S2NS4FEBWYq1FfHIu82qHWhknoVci3yYIpfQJi+aRr/Tv1QL
         oGxeZjTwU2+2AAZioWwkGKIag9mh+t5wcdYsDRwe3dfU5NqB+9p2/PzNW+8cpJ/yXTBJ
         cYaeKwqw+7qqlU5rqFwZanxmZqsplyJ+FjwynJRSM4QlSzhT8K8YIxF5IciPk6YpeHKi
         XSHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=9fLEKxx3eXOI7M71zoICWtBuWb3SZI6deMvYOmgNWdc=;
        b=AnNT7eoH2Ef2nazfW8FhC58DWixN/aFT36G2DJqieedgwVYIpSxiXzJHT9z+at4szR
         dm4IBdqxyjUGKo8ek8tcooWm8f3cqK+S6hY7114zH4P0rucOkgRyLKV/dWkcLZ9TncKE
         APB4txP6nNYbNApzVxWaxR5GjR3YKJ0Xt8WmPor24Xb6aBfsg9tX6u5kxwbbJ/BDnHbY
         h7MzknmfiBjnKa8qr5RH0DEFI6SRjE9UQiuPR/u1p6eU+PBLiBBOytOefMn97Mgrb740
         KyRNVgh8/insS3VBlZGPZcZqQcFQO8nqZ9lFZqPR3qMByOQGU1HbW8bCS/8lgpOpbs7d
         AKDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1D0laN0wnu2hHqQKQXWarX+o7aPQMXfhcBQCJwmvcjSy3jA+GZ
	QQwIhqucKJ3zQ/QL1F/L/8o=
X-Google-Smtp-Source: AA6agR4HxzkbRyQq2UNvynOBUM3UA0GCsPMIgtsU7k0K7jmhqul11wKJrCOf2d46rxRAbQ4/F7I65Q==
X-Received: by 2002:adf:d1c2:0:b0:226:fa44:bab7 with SMTP id b2-20020adfd1c2000000b00226fa44bab7mr124861wrd.195.1662496687800;
        Tue, 06 Sep 2022 13:38:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:721a:0:b0:3a5:4532:b3a6 with SMTP id n26-20020a1c721a000000b003a54532b3a6ls5090354wmc.3.-pod-control-gmail;
 Tue, 06 Sep 2022 13:38:06 -0700 (PDT)
X-Received: by 2002:a05:600c:29ca:b0:3a6:75fe:82af with SMTP id s10-20020a05600c29ca00b003a675fe82afmr121468wmd.3.1662496686547;
        Tue, 06 Sep 2022 13:38:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662496686; cv=none;
        d=google.com; s=arc-20160816;
        b=rrF9M2AQJTwEXRlusJfAFJaUo8KsvOgjYz7NORE0fjEnrQNFLFco759ObwswMc3/Vx
         fq0rHAozDU4NYsfUAGiCS9Wvebxf8wrk/HFQoHEf1KpqJY4hvWT4QawCYJO8YWBQ6LXI
         ZM+/wkFnwNtrqlc4BLtEkzMgikty2r0pV5pAQcawiGBi9Gpv3GcMtOlTbODcZJbM6lN9
         B+BgFLgTHmhbFQjKcL9Vz0b4U0Z5HH+VpY0J+Wh59xnVRqm1pi+iN7+tLk0fdVuMefIK
         lhcSZVsQjE7YoL8vaW8UvFhTyGqbn9U6IRO/iZLiI9LjtrnaStAKtZCxDoczlMPKAbIX
         iI9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DmGvl3uZQB8/M8fW3mjXEVral7dNpov0geEOt0uqNnA=;
        b=GTEtyNnGPnY++t+GGIxJHojlDLif7KdmmKvS96G/AWE9ZU1fZP3ZB7+nesGmAbdVUX
         vfcRzzZrbbViYZuZTCY90yjqSf2QSBg7cHZoe5YuRDhoZsgi1Hb/ZXojy4P7UcweAyO2
         aXxJfNsbnHR03NCSnIjyY7bhmg01htbuJtkGPYAZg85kVDEH1QlcPdoqiZOonWWSRj7t
         VT0gVqWONjZh28MCYjqrvzMoHco6t/2qJhx96j0IYvfdiumw+9y38htl7435iMMbKtIB
         7FsSbPmH14+8NoSaloTH0m4nD//weHbr3sgrgG37d2zcOcTE/QZT84KW1pAF3oOcgrhw
         kvIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=jPxkDIeu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si880490wms.0.2022.09.06.13.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Sep 2022 13:38:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oVfKd-00AkKB-AJ; Tue, 06 Sep 2022 20:38:03 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 61BB4300244;
	Tue,  6 Sep 2022 22:38:00 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3D7AB2B929A27; Tue,  6 Sep 2022 22:38:00 +0200 (CEST)
Date: Tue, 6 Sep 2022 22:38:00 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH] perf: Allow restricted kernel breakpoints on user
 addresses
Message-ID: <YxevqB2OpJ9BLE+s@hirez.programming.kicks-ass.net>
References: <20220902100057.404817-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220902100057.404817-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=jPxkDIeu;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Sep 02, 2022 at 12:00:57PM +0200, Marco Elver wrote:
> Allow the creation of restricted breakpoint perf events that also fire
> in the kernel (!exclude_kernel), if:
> 
>   1. No sample information is requested; samples may contain IPs,
>      registers, or other information that may disclose kernel addresses.
> 
>   2. The breakpoint (viz. data watchpoint) is on a user address.
> 
> The rules constrain the allowable perf events such that no sensitive
> kernel information can be disclosed.
> 
> Despite no explicit kernel information disclosure, the following
> questions may need answers:
> 
>  1. Is obtaining information that the kernel accessed a particular
>     user's known memory location revealing new information?
>     Given the kernel's user space ABI, there should be no "surprise
>     accesses" to user space memory in the first place.
> 
>  2. Does causing breakpoints on user memory accesses by the kernel
>     potentially impact timing in a sensitive way?
>     Since hardware breakpoints trigger regardless of the state of
>     perf_event_attr::exclude_kernel, but are filtered in the perf
>     subsystem, this possibility already exists independent of the
>     proposed change.
> 

Changelog forgot to tell us why you want this :-)

I don't see any immediate concerns, but it's late so who knows..

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxevqB2OpJ9BLE%2Bs%40hirez.programming.kicks-ass.net.
