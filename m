Return-Path: <kasan-dev+bncBDK7LR5URMGRBCH2TW2QMGQEC72ZSRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C9DB593F405
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 13:29:13 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-428207daff2sf2145565e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 04:29:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722252553; cv=pass;
        d=google.com; s=arc-20160816;
        b=pzx0uHWObmu/2P3GHkzg+cTAeMxrYVzpTM8XASiwXW0zjy3Q/Q++3QfHTyRiS/ettP
         H1U6p8JSSbGJe+gHn2GIDiuMJ0yaxsVk9VGJzX5P/EpyCQalnrlmY5n+nbV904ZLjK7W
         VnkrAzJzsWxINywNNyzVwsnVZuNjAahHmzsz/kcZYuZtrZ6A48Kc5vYNHnbNrw66x4bl
         UZC6psu0dxvJ0D1OKhb2h5aPGYWH0HVg6eOGC9Ev9Naw7whkz5E3/7Qd+9Xw1vGJSbff
         XG/Li6uA5zdxtXgHPL/J65068cuRzZgNzOx3OkOnpeQxVcaHk8+iENGF+/yEvNJ4FypB
         DAPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=L+Hls/a5oa0wH3/HuVIgCxZ7eH0b1OKVQapbCkW/sy0=;
        fh=MHBvfgNrTDag3bSPvxQrtE47dFKsOlA/Cib5LhRMgZ8=;
        b=xFcIrkM8O35C5Crb/eBt4rUUfsArkAlQTcY0LtKUY+VgYqSNY7W9vYQ6mb1Shia2ZZ
         zSpGo24b8B2DJSX/5YJrFMr6ttZfXsBXVNRItdPFOgTzwwbgBhXMCZABHh3OA0WNZx95
         WYqkRGsoRf4FyxxIKA7caZvQfAiJn9lpTzCuhN0E6FYGt7XqkuLader5kPN1kKYnVcE5
         h5d3/ii0JAlCpf7NL3w0WecZGo2m3bSrp9HmFQSmHr2KwqCCcKqFuN/YqvLCDFWOic/V
         9Iey5r8NXQtQfMa1oKn7X9pB2/cucZamW5M0gzxemK7/+H00L10Ia8daQxDxcWVlrScS
         6nZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=avC2XxzS;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722252553; x=1722857353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L+Hls/a5oa0wH3/HuVIgCxZ7eH0b1OKVQapbCkW/sy0=;
        b=mOpMwQg5SOgSHc2cdaKozx+jodPIo4q0vJ5qvXSK7jPydjKLY34/jC6M8F5HtNouVp
         zkpPGyNCN5Pd7OCWVOnGJHn6PtRrDcEhdZ35krCbXxjmwWriMTceV+u09NKoJD6kRZTf
         1bHqcstHcbauhevXeNCRuKviRfIyI+gcfdjAlt0q12h0ZfWL4d1fd94qsbebQybHJApq
         UPvT4XlUMSEJD8lRkIT3sxWQ6VqC9cltfifczj5m5Ai2yDN8EJjK/Yjd/e+ToQ+Yo34z
         L3na9tpIaCj0qB3Hwk/8arTLDEg/Lzgya+azZsFdNIIczv9UdR4Wet8JPf7wSd/ICSkM
         GhSA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722252553; x=1722857353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=L+Hls/a5oa0wH3/HuVIgCxZ7eH0b1OKVQapbCkW/sy0=;
        b=MYSscDJjCTCqWLwXtG0i7NB0YaOBOpJJ9jUBT3RNfpEoysc/ZphUEWb1wMov7uS305
         D7mhmEB5WsfEBS2bIx7aAuzb5rXTAjKf6DEQQ7dH/6JoxqMgs3cO3wVE88VzxUylUquR
         z4JzKybZX1iP1PCXUhBUciaENMhUeVC6PuR7XHgVkZGLsxZSGnF6AwoQ9qUcK6Xvfyhx
         /F+5qVUb8BBcwpsII3AcXs7Kny1FtD4m4xKJfo9/P1QatHAB+q9DQfEZfGuMIDzvGPtC
         UpDm7rG2LxZQJhzEMf1uigRlwlvZQTzLttIzMKXa10OWGqYVC4jZa/7ldN4GOXzd4pBw
         yB9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722252553; x=1722857353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L+Hls/a5oa0wH3/HuVIgCxZ7eH0b1OKVQapbCkW/sy0=;
        b=sQg8s2e5Fkl6IIz1c4iQz8brARDMSEdV/pHGBMUVePpVIqkijB97raGdC69/dAyTbC
         4b9wznRxYQbZybX/a1zDL2kzjRXsntNSOJcHvj+BofCyAK8jnPuunxGQShmJG4YWVlD3
         TXJP8WgkJAbynFqjvAExOGZI8QSethll9/wXb0p9w45BXpB4rywVXhaXngiTEeon9dN/
         fyNJIl7fAT4iUlCrfSt8uePCWg8RXDdBXlOANGv5mFNMnGGFqOypDdIIbl0cqy6yZIqd
         H3x74INmGf89mvGColMUpmVHzgSfCnElo0lra+aaji33mJdRZnTz1JHOi9lIb1D6iAVG
         XImw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9JVmlqVRjySQFri93EMPE3RcOTXTo52awdYker2FksXRhMO2l3g1o9kbpT1zk1HlXUHl9mZiqKpv5/moxbhvOAKLTzA7/9g==
X-Gm-Message-State: AOJu0Yzs5qLAen+MObu4S9loWrfMnAWLbUamgXipO61k7rRpdlPHvMy7
	VdCDyiV9MyizkYyFeVcZNcpb/wCloklkkRW1ZMZYxZsgfkHxeTxM
X-Google-Smtp-Source: AGHT+IFTwJsAOjIfZLtRsOAXYYCzbX+lZvS2F+CeS2QzdFNOkUjiM8Gt/LkqWZJbcjuJ+3S3Q4SDUA==
X-Received: by 2002:a05:600c:4fcf:b0:426:62c6:4341 with SMTP id 5b1f17b1804b1-42811d9cb8emr47449905e9.20.1722252552861;
        Mon, 29 Jul 2024 04:29:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:426:6c3e:18fc with SMTP id
 5b1f17b1804b1-42803b79e84ls20869125e9.2.-pod-prod-04-eu; Mon, 29 Jul 2024
 04:29:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVPdkNI4vpBDLmAUjzoB33WPf/Eu6IBpTBTrvk43+tL7YDZ+a3P7sbtoe5YXvPvf/ar4KpKuoA31chtUMghUGH5X5WlSJVAH+bPkg==
X-Received: by 2002:a05:600c:1c0a:b0:427:9dad:17df with SMTP id 5b1f17b1804b1-42811d89a06mr42500825e9.12.1722252551258;
        Mon, 29 Jul 2024 04:29:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722252551; cv=none;
        d=google.com; s=arc-20160816;
        b=eZbwiViX7Ot+tIK2H2qyPtXW+S3uzZUFmpPnPnt6J73iIBNd+odaZrd0cxMaL+dlWT
         wRdj/wj7n9PoqyYmwP7i07snfWVxVPf29Os6gSrk81SH4VWp0q3uwoSTIRJCLgEazT/a
         zkKO3ScvEFWC1Xy3KmGRn0n8OcZN5yvaHOluLSHsG6cx33th3BVDv8s6bj5zfQ2j4/R6
         8qKQ+7y7vlTLUawF97R8xqImTLW50tVmO+rSGne+xibvSl9SIMZKv08ziXBXCfWpBNYS
         5Ll2VnBS5AH/QDlap344rwHgtnDMV+2QTrDKJtdrozAbzsL8hZPRADxTP86IMKHODkmk
         rfRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=Ylub7aafKxlZMuv2JYZ4S/MrGVU3Si7xKcH11JwBeGE=;
        fh=MeilTSs1gga2esRh/2yI/0F4TBilldto6dArMQu5YZo=;
        b=x2GM6BzeOcnIB6UdFtK0lbBkQRJ0QQB7oSmkxxEEdDm1O1a3LM0M+jvM9/njcCkF8I
         0oC6MJEPqira3T4CvjFc4YY6027B6rKf6drWjgS90vO/mcldEQh1TOMllYaS7UKchKvQ
         29u99qyoH2SgUBjYjcVrO82O+s5S6ZORR++1MhaP4vLLoFNMjpJbRK93K9afqtY3Qnnj
         3egf5/BKkOCYMrVwIgVgXwCtfVE2xbE4l9hVzN2kRkH1AfauozVYJrK+M2pd9viS4PS/
         nxkFrpiGimSrkWZYbukXN3lOkFb2JR6lBn6+dyeRsDgEnDAqLp0Isqo/s8KTtibHz+Op
         sesA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=avC2XxzS;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42806c76337si2555945e9.0.2024.07.29.04.29.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 04:29:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-52f025bc147so4659032e87.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 04:29:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuYgaD14s1YLuxgwVeVDTPqcMnNfcnYV+lYXFjdoSmAs0Nza5JvUltSTkZJtUf9z20uwvHQM6lEU+/vk3gUzubB7bFgSANOuKTxg==
X-Received: by 2002:a19:8c58:0:b0:52c:f12a:d0e0 with SMTP id 2adb3069b0e04-5309b27a656mr4548211e87.28.1722252550544;
        Mon, 29 Jul 2024 04:29:10 -0700 (PDT)
Received: from pc636 (host-90-235-1-92.mobileonline.telia.com. [90.235.1.92])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52fd5bd11f0sm1452561e87.80.2024.07.29.04.29.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 04:29:09 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 29 Jul 2024 13:29:06 +0200
To: Andrew Morton <akpm@linux-foundation.org>,
	Adrian Huang <adrianhuang0701@gmail.com>
Cc: Adrian Huang <adrianhuang0701@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Baoquan He <bhe@redhat.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Adrian Huang <ahuang12@lenovo.com>,
	Jiwei Sun <sunjw10@lenovo.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-ID: <Zqd9AsI5tWH7AukU@pc636>
References: <20240726165246.31326-1-ahuang12@lenovo.com>
 <20240728141851.aece5581f6e13fb6d6280bc4@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240728141851.aece5581f6e13fb6d6280bc4@linux-foundation.org>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=avC2XxzS;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Jul 28, 2024 at 02:18:51PM -0700, Andrew Morton wrote:
> On Sat, 27 Jul 2024 00:52:46 +0800 Adrian Huang <adrianhuang0701@gmail.com> wrote:
> 
> > From: Adrian Huang <ahuang12@lenovo.com>
> > 
> > When compiling kernel source 'make -j $(nproc)' with the up-and-running
> > KASAN-enabled kernel on a 256-core machine, the following soft lockup
> > is shown:
> > 
> > ...
> >
> >         # CPU  DURATION                  FUNCTION CALLS
> >         # |     |   |                     |   |   |   |
> >           76) $ 50412985 us |    } /* __purge_vmap_area_lazy */
> >
> > ...
> >
> >      # CPU  DURATION                  FUNCTION CALLS
> >      # |     |   |                     |   |   |   |
> >        23) $ 1074942 us  |    } /* __purge_vmap_area_lazy */
> >        23) $ 1074950 us  |  } /* drain_vmap_area_work */
> > 
> >   The worst execution time of drain_vmap_area_work() is about 1 second.
> 
> Cool, thanks.
> 
> But that's still pretty dreadful and I bet there are other workloads
> which will trigger the lockup detector in this path?
> 
> (And "avoiding lockup detector warnings" isn't the objective here - the
> detector is merely a tool for identifying issues)
> 
As for 1 sec execution and worst case. I did some analysis with enabling
CONFIG_LOCK_STAT to see some waiting statistics across different locks:

See it here: https://lore.kernel.org/linux-mm/ZogS_04dP5LlRlXN@pc636/T/#m5d57f11d9f69aef5313f4efbe25415b3bae4c818

It would be really good if Adrian could run the "compiling workload" on
his big system and post the statistics here.

For example:
  a) v6.11-rc1 + KASAN.
  b) v6.11-rc1 + KASAN + patch. 

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zqd9AsI5tWH7AukU%40pc636.
