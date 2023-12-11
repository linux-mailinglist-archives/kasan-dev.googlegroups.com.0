Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5V63OVQMGQEZ62457Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 98C6E80C5C0
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:07:52 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6ce337ff87fsf2617262b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:07:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702289271; cv=pass;
        d=google.com; s=arc-20160816;
        b=HQ9d7/2kToI1UQ1rsTZHqqQ5NWdKWOPVC/UomC4DZuFaJX9rsKSRi8HSuvYo+BxkwV
         +/oHWA9/BEZ7wSy8asOjTW6S9nseZuO+ExocD9T7HFrMcZ2wHDl57Te1e9PlpsrZglpg
         eNUj0GAUuYb7aVHXxsMBGnCr9DvveTIYCRHc8eKNd4I8KbE+HInW51a72YoZtg57nX6P
         blBMV5r3kR7/Y4d2ki+LTNaxh2RZuqdAJrsY7CIcocTJhYOz9otyMhD7J0mzKbCntj2X
         RWiYR8q2TNW1aAmqUVPpz8tYufcjmQe21+Cf1n/nFPVz/AWDxPqK4u3ZaFufpDYOVws/
         zc/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=unesLSsKfNOgDJd6YqJPtg9DrLkLT/qp2+0q1KcHguc=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=K4PvgsfaKcWytamPzUannF2ljr09/BEWpFm53jnk+N/DRF2y5GuGyt6atllJzIp7Hn
         2ljAeW4TCXr2tro37HR0na3gmgCNOgPST6nydH2Mlce80Ab0J9+jMBje25l/hf9Mou9q
         kDBiwdSLX9+q8WnjJ1TM4xbIbqG4OWXmRyYEUnZRYrzIMxe3YksvWeT4eyEXR0lRNqOL
         GXriqBNq5IMYQUZzxRafLtSLS21KoKzYXMx6OfNHyOWDLmCf2QijAvPQdEK3CaafSlFy
         hCqrt3V3ucnJxNwUFpbo0cKNIVrT7/jvGiQxG6adC8aeCc6mp6AFl5fZbCCsIHLAnyC9
         hTWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4sB3oxKa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702289271; x=1702894071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=unesLSsKfNOgDJd6YqJPtg9DrLkLT/qp2+0q1KcHguc=;
        b=lc+i2LqddRpprT1s6reAu1dOWlBqNp1pNE0DJQDfIHeMtFInfKs5uhdynKl4S+Go0G
         PLQcaCAVx+ZXUerWd4cRPUECI2xcw9fg5mDO00I5EjGYh/b15KgP/nqITQdxv85cyK0a
         7cRj0gVyL97w0Hk6VMQ5bKCQk6OKwXR1havSZVG9i9HMQ9ieCsm9tB4b6BCTT4wTY7IC
         3w+KDVSB5Y4mbA8ggmZLA2exB7rJL9JdjziEIzPv7LfM/OJrff1qfZ/I9ZRTRBEgHm6d
         NItZlDWDl8FV3dIrLBicqTQoX34fr2bbCXf+Ywv5yPu6iL2jRaOzMbmJBDVDr92WfWZX
         gsoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702289271; x=1702894071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=unesLSsKfNOgDJd6YqJPtg9DrLkLT/qp2+0q1KcHguc=;
        b=Rzie1um18vkHs54dq0HZxq7AJj+NgHM9pAqMTRDCFAVgfa95Rg3AA3pdkZP8LtVVxz
         7BIXik6vX8FR7jiSBvt8z03ggACuc0vSVaUdvHKU8+4vlumX0d3dsJ1PkJNYuHF9NmwT
         VljQ5ECpZSzjz403e39aZcjolvvM7tDIkgRro5sz142V42fB6vZGDD7t3/8YYfbuAaK4
         HuqEswApJHMgJ4+iv38ygQ0svcYX5EzyRA45hnAu689o7LcKju6+H9UJ4PYf1R4rZyDN
         Id3tOQhB/20nNn94K6eeGWG6q0uqjY8XaY/h0wAU4qNqBrzhiFj1KXyDkvSaNHsInRwf
         MNsQ==
X-Gm-Message-State: AOJu0YzJZrVY/dkmCQe3/pyQbQy33rOkDzFxvwg5DnutGQ5KfNNlOfBT
	oPSNiVkplko4UsVq4I63xBY=
X-Google-Smtp-Source: AGHT+IEgeIW6FipY0QFu3EzKYjHcjeto0iZiqBC03VEElq9lcSL0WhfymqiniWG4jTBcQU12AolzOQ==
X-Received: by 2002:a05:6a20:54a4:b0:17a:4871:63fd with SMTP id i36-20020a056a2054a400b0017a487163fdmr6074446pzk.0.1702289270982;
        Mon, 11 Dec 2023 02:07:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4593:b0:6ce:4441:9abf with SMTP id
 it19-20020a056a00459300b006ce44419abfls2579498pfb.0.-pod-prod-00-us; Mon, 11
 Dec 2023 02:07:50 -0800 (PST)
X-Received: by 2002:a05:6a00:1142:b0:6ce:2731:47bd with SMTP id b2-20020a056a00114200b006ce273147bdmr4770889pfm.29.1702289270061;
        Mon, 11 Dec 2023 02:07:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702289270; cv=none;
        d=google.com; s=arc-20160816;
        b=jq7jbH/uzn0hR/dEsdktNXUi345xBE7BVnizlN5K2hm9csvBUkrFMoOSuFCC9St0nU
         3CPtu7EvSiOQvIXsj9iAWQXLo0WimhtQRBwgJm7QT2MMkCUthy+7IC1fhAvdxjBATDYU
         n7f1MOSLBoF4avntqE2cNKWsYhDwHrWtXGHI2FBleOnq4qm7N3yPPhk0/QoDUprg+AAY
         NjVlNpPM98pRvjzrxoKHkX4tU1WI1T4Jdf5Ilg79KYTz4Pr7CfHxpjumSjD1P56cWGi4
         RBf8z5poPJWC/5S9XW/5OVBC0JZnmgQp+8iU7uOW3BmxNXdmoexknT3kQJkLdyWgBxcZ
         6lfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iQbib7KuYZwXSs7TOXR8fysQbrU5Bbc58V4j1zKqFv0=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=DIyUUrp4FteKv2wSM06rXDl1RUu7dfiE/f7K8a1ZmVketBm/cHmHl6+OxQT9ADg6o9
         M/0SxEWu1DLaNRWpQTwMWWurMC7oOBucLsRmk3alebBdic39xcd/Bs4Qrk324UFewMEp
         6NTVM8/yofOSLcFhzyp657JrYrGdxNsjWPLbk//T2vDiKFraHns7cgWu3rO0Tb+5/2HF
         PXlytwXNJZEgPTbMXB9jYHKbWOhXHNFMuMFoRn8exnw9oXCz9QQ0TXyBw+vcw3m+KL6+
         p3jkJFP5fXhQB3Ec5zyIBal8+72/qadGOrm63rs/OszqDyPh6sdiF1MwoY+aVb/QvBd0
         EVfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4sB3oxKa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id ay18-20020a056a00301200b006cea411de2fsi523311pfb.0.2023.12.11.02.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:07:50 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-67a8a745c43so34364016d6.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:07:50 -0800 (PST)
X-Received: by 2002:a0c:cdce:0:b0:67a:9440:2b26 with SMTP id
 a14-20020a0ccdce000000b0067a94402b26mr7123627qvn.20.1702289269049; Mon, 11
 Dec 2023 02:07:49 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-11-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-11-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:07:13 +0100
Message-ID: <CAG_fn=WVfh_E+5uFs1GXfQCVMj3EBvNGFTrJ6_DxVb4t3WnVPA@mail.gmail.com>
Subject: Re: [PATCH v2 10/33] kmsan: Expose kmsan_get_metadata()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4sB3oxKa;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> +static inline void *kmsan_get_metadata(void *addr, bool is_origin)
> +{
> +       return NULL;
> +}
> +
>  #endif

We shouldn't need this part, as kmsan_get_metadata() should never be
called in non-KMSAN builds.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWVfh_E%2B5uFs1GXfQCVMj3EBvNGFTrJ6_DxVb4t3WnVPA%40mail.gmail.com.
