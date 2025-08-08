Return-Path: <kasan-dev+bncBDK7LR5URMGRBYXT23CAMGQEUHNRJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 105FDB1E4A4
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 10:48:36 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55b92839bd3sf589223e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 01:48:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754642915; cv=pass;
        d=google.com; s=arc-20240605;
        b=kQ7/w9jvJT4AxQjsPpLCIW7UnoDZWy+DO96FOeyqcmwsfWDxazv+77eADYjH+f7m6b
         4Jqpo8Mhj1cEINiYTdlord8tfrEACeO3Rnn/Euvr2+bOgcBPDoxmVDF7TCo0/GOMfQmA
         X8gpCg4n2aXsF2Bp2ky/qKiranFeGBjwYQJITNmSegHdpT3Pv5PYTTmgD8jZcFzne5uM
         diD4p9LqEVFm4iq+Py3o00K3gHNjmKIqsO1Md+l4xCz/j5d81cL5/eWIbog5XyJ+fuvz
         2APpp6TuZfUsaqh6sb0tCVZa0idYHv8nI+lm274iZFIO13G7W/NzZYYdE+qXy8g10a+4
         giSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=8JwlT1XkcvWc4yeZCKmVNj8xJnr1T5gdkb04fbNzu8M=;
        fh=mYRudwwQZjAPPZawQhd5i8VApEF39n3bE7+JrnfBZws=;
        b=iCRXV6VI/V9MduIwSY+fNUm+GAjH99J2HafeGm9y/UohQt3z68f19ijM8AhYDggxc+
         TNulXFmaeiJ5UmZwIKtouTMZ1YvJKpS7iuvAGodamEUkdZxJN/oXfUDU1i16wsggkS0Y
         FY14c5ZKXQ+lM7nwKVJCGZW5tXD4+oaA5vgGw3nwGDIWiTjcqEzFTd3tzARpD7vv4jJZ
         6jZ37s5uj2x4lryLKAWkJbm+h5WvpHoW7Crrph+gmrjpSoY9SJ4eSNanp1kkairJWpiJ
         /NagU+A9Fzq1VLP3rIHOKtuiw36+vUf8lq8h64lfw3jLyrZ+mYaBkZfhygRpH6Dn6Mat
         cM4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Yct88vHy;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754642915; x=1755247715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8JwlT1XkcvWc4yeZCKmVNj8xJnr1T5gdkb04fbNzu8M=;
        b=tXWnQSupJjt6Ak7Bjj5xVS3cJO+rsp8WKbzVEhep0z4wFb0t97TlJP8EUDpE66aRxs
         ESC6qojNV0iHQI037GbjbHvDDJp1tLMpqJVqWSqVt2zZim3RFg/dDWO+XEN6Kut81eaY
         1B2QoM4XL84d+rYGpAdrzchYQpzge7XEldQfkwN6GhSUCv0XWmZJq9VzEBxTLCVhsOwE
         XDFbDp77ZqB6ExYJ2x81Q+UYt7esMh5+gPkbUSt6PRraRBH1pwGUWcvKBvtpc7WqAnF8
         FxxV62NsdgO96d+rN5WT9yeqXPTxGrsM9VHcam5Lw6ZfgEAafAr1V+1hdVptPNAGKybn
         9Rsg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754642915; x=1755247715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8JwlT1XkcvWc4yeZCKmVNj8xJnr1T5gdkb04fbNzu8M=;
        b=fJuwIc7wprJ6isILZAo/MokpWMS4ovDd4zxiubF6iP1x7hwFsxTaUzjxLo9B33uqLk
         hy8+45hTojfBHcR+ZPnEOyPtsFlLjCKt7umJBOJgJDXHIiQi11kHTdmJr0KxzMu29WPI
         v3d62Whmo1nF4EjZdZcyF83LfsdOqTORv0GmVFKLzgNjuBOzw8YuHsTHiTflMf8c0eY7
         0o8p/fOC4kOm9uDBX+ALWBAlVVH2nC3ORwzB3Q4ZvDvpBIXD1AP8C6t5S8d8PqqoBdiU
         jb0TN6xNlonaNWWuuOVX0EW6AIdQPOOQICn3a4Pq3tq0vu4IwTjkWG08ZF+z0E6r09dD
         wwhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754642915; x=1755247715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8JwlT1XkcvWc4yeZCKmVNj8xJnr1T5gdkb04fbNzu8M=;
        b=siD37nZkGTTPXIY4Ht23T9XlHrwe0zfVlUP+tlpfA/LpBb8uRxdkHovsXE4rswcXlP
         bP1FAA1qge36l2F+GsfJ3OoWtBy/PJp74AQ7udXUmxMwgNPXVJwMAkSI4tB7S+NVYgjo
         xG/EoW5GF8bq5qbiN2zzog32+gipy87fYwdOph+wVozRVsDH22fSeb/+LD/8EuF6AWkR
         gQUe2kx1qLh9mpxFVpYEgNemdcsJy9pEwz2E7OL3X5cz53gOx/WRlSkIhXoSeXZzO1AP
         vXZm6IQ4qYdxjPZJWbLMML+2C19HeXULSPkqrV42JASvYcG/zD1o+mriHE5Os2GOgfm5
         bOTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUAFB1BjYRWw1tpzRNvk3ZPK20HdMzRmALWK9GG6aM2/CJhTxs5mNDsqOuFeD+A+IiwfdSWA==@lfdr.de
X-Gm-Message-State: AOJu0YyXuhaQsdMQdzZ9kA1iCu6E9PLlVshi7jliwwU/hkW6QuK5erDv
	MNO8cgQ1IVwIIJXi2wwlrBufWls/5xIUALMak6AsAdGg8HglTD+FUX3b
X-Google-Smtp-Source: AGHT+IH7kmccGHF3w/d8Q7s6DSfbRspCwmMGb+oKljCOpOKr8mj+GkB/rCCs0MlEBnAZCQIoqMtWqg==
X-Received: by 2002:a05:6512:e91:b0:553:29cc:c49c with SMTP id 2adb3069b0e04-55cc00340c9mr551199e87.7.1754642914656;
        Fri, 08 Aug 2025 01:48:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeuzMWDGzc9qFgkJnRasyUVwHT+LQIIbor6tfcE15RDsg==
Received: by 2002:a05:6512:1418:b0:55a:4f5c:f12e with SMTP id
 2adb3069b0e04-55cb5ea90ccls485577e87.0.-pod-prod-00-eu; Fri, 08 Aug 2025
 01:48:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXd2QMKas+jyNP1ewYiONQFNrUHg5Nk+vySE+Z1/cVGBDWI55O57g6liqnNa19GpbVDMamRlXyNpmM=@googlegroups.com
X-Received: by 2002:a05:6512:3b07:b0:55a:31ee:ee14 with SMTP id 2adb3069b0e04-55cc00e3acfmr662099e87.23.1754642911764;
        Fri, 08 Aug 2025 01:48:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754642911; cv=none;
        d=google.com; s=arc-20240605;
        b=anKqIYZ2LGFS8/ZEt++bav7ingSCQD/LyDiRF2mHxHBHzcxNQF1i68IatCJ/MGZdq3
         6UWaU8iDGhg+WjZENXeDApwdP01s9sfTpz1wpg7DKBh1HqKSl0080WmVsU5QDVNA2i3Y
         HY9GOXi4HrusD6eGwhbi/1TCYxhjZtrtJKPCFFB1y+ucDT3LSYE/D634jTSJKIiQQ4I1
         Njov+xHOy6mwGqKCoTxoSOJoP74h6WVitvWCF6dnU9l0QPxbV+Wqp0bXrI6VO8ktxIe3
         G1f0jRL64WZ8ZMPa6ei0rB0QN9/6ABxEYntLinSilIZXOlbOviBlJvkoRsTyTzrTZOrb
         GZdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=v9nfb25BPwvJZ+khUKkOpGadyQIkm1x1hsyBk6u4F3w=;
        fh=gGqYXtu5oN5rKrgMilZh+0xA8zTNHh5FukrD0EeqnCY=;
        b=SHWQIs43uDRNH7srm6qerXoJ/26sJIpalJ42wm99O/DX34+P+kM0L/QUSqgPalLgnv
         ZB83TjTcjNHwHPFJureOD7FRkb+GbsvLMJeQT2JhS95gOQJPZmrfPEpqsvc6/hMMlt7G
         rsPBRnYXTxafXPFEiTyYMz+rbvsj8h5LZe9RSwfkrpIWOAeAaV9kNe+3iybr5Pwnob5/
         /qKsgRZw7jCZHR/l9kFLsic8Npt8xCgAub8g4yO+AbZ7Il/g6pZx5sbISXv6Ak9GOmu6
         AjYLfAFdpxigXEwmnEsrGrSVYT28gJISJyf4sVICbBN0sXpzkFUg2pwYlC8AQ4Xi1S/4
         maLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Yct88vHy;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9f778a88si358840e87.1.2025.08.08.01.48.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Aug 2025 01:48:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-3338149d8a3so22673611fa.0
        for <kasan-dev@googlegroups.com>; Fri, 08 Aug 2025 01:48:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC0M1cga4pJpBIHLPy+40n2T5PQ0r1ePrsFHKAkV2OTsXQeGZeSFZCwm6ZyUVHN+rr28z/H+E8Wgk=@googlegroups.com
X-Gm-Gg: ASbGncuYPhITEqq/5JJ8yiSP/tRPi8A5p7k/H5qKpY3lMfpTWvqyHPzXuTAwJ56BdxV
	uWi1fO7S7ce1HNkwq0sxAouzZF628C/mgzoKZj+MtkGdJ1ezKTE4zLSNUSc2P+OU/VectUI7FCp
	iU+o12kQDdwqm424tCdWOpectPEQ54T5iNJXv5o2Tf8yndNBA8p8tqFYSJvse3vZ6a/0P9SdcX+
	AloqTHr285I54Y1MHTnWUfJhCACI+y0EWWMnNN3m94afXvLhFzK1a32MzS5CJtIjUhcNebmoHxv
	/xNDuvgZ8PklAkE91ELBdZE+HoUG0SPPmeFLQo0UInozPfq/ifGweGs72G/7aDpDtms6pLnAWKp
	5eRQm7y22alQY0IbaUv06rYtSMS4GzVOQ2B7IDjwOu/8vmQT/GMxN9O28qIVv
X-Received: by 2002:a05:651c:50c:b0:32b:7ddd:2758 with SMTP id 38308e7fff4ca-333a236da8emr4056051fa.0.1754642910978;
        Fri, 08 Aug 2025 01:48:30 -0700 (PDT)
Received: from pc636 (host-90-233-217-11.mobileonline.telia.com. [90.233.217.11])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-3323a85d7c1sm28777831fa.68.2025.08.08.01.48.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 01:48:30 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 8 Aug 2025 10:48:27 +0200
To: Marco Elver <elver@google.com>
Cc: "Uladzislau Rezki (Sony)" <urezki@gmail.com>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Michal Hocko <mhocko@kernel.org>,
	Baoquan He <bhe@redhat.com>, LKML <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/8] __vmalloc() and no-block support
Message-ID: <aJW520nQ78NrhXWX@pc636>
References: <20250807075810.358714-1-urezki@gmail.com>
 <aJSHbFviIiB2oN5G@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJSHbFviIiB2oN5G@elver.google.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Yct88vHy;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22a as
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

On Thu, Aug 07, 2025 at 01:01:00PM +0200, Marco Elver wrote:
> On Thu, Aug 07, 2025 at 09:58AM +0200, Uladzislau Rezki (Sony) wrote:
> > Hello.
> > 
> > This is a second series of making __vmalloc() to support GFP_ATOMIC and
> > GFP_NOWAIT flags. It tends to improve the non-blocking behaviour.
> > 
> > The first one can be found here:
> > 
> > https://lore.kernel.org/all/20250704152537.55724-1-urezki@gmail.com/
> > 
> > that was an RFC. Using this series for testing i have not found more
> > places which can trigger: scheduling during atomic. Though there is
> > one which requires attention. I will explain in [1].
> > 
> > Please note, non-blocking gets improved in the __vmalloc() call only,
> > i.e. vmalloc_huge() still contains in its paths many cond_resched()
> > points and can not be used as non-blocking as of now.
> > 
> > [1] The vmap_pages_range_noflush() contains the kmsan_vmap_pages_range_noflush()
> > external implementation for KCSAN specifically which is hard coded to GFP_KERNEL.
> > The kernel should be built with CONFIG_KCSAN option. To me it looks like not
> > straight forward to run such kernel on my box, therefore i need more time to
> > investigate what is wrong with CONFIG_KCSAN and my env.
> 
> KMSAN or KCSAN?
> 
> [+Cc KMSAN maintainers]
>
Sorry for type, yes, that was about CONFIG_KMSAN.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJW520nQ78NrhXWX%40pc636.
