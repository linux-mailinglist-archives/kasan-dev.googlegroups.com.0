Return-Path: <kasan-dev+bncBDK7LR5URMGRBTVCYPBQMGQEEPEYRPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46F92B016E6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 10:54:40 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-32b4b645bb4sf6830801fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 01:54:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752224079; cv=pass;
        d=google.com; s=arc-20240605;
        b=joccjV59lrIqmEEg/MtGKnv1QH5jamOJ2fFlvJk+nlfWb1yNKOVcTh4OtxRrcEU63S
         l8Dasg+jn7nzfWOxVHTVlEqb7Hh+jsUh3uLT1Zap/pE2PGFMr82B7RU+EJKWejpBcT69
         9BEZGY4/krCVSi+wJfQaH+BpDvK8fLM6tIG8R5KAinXr0HfVSwb1Zd15fT0GaiSd4ggb
         3PPyQFc98Q34y8WLIKMPykhBJzPQxn95RElgqOIDAfbgg3gOUJKqSRvxIkCoWe9enOcx
         sEmId78XTsmmS+45LSGghtylv12yuxrG8+3l5tpF6ZaYITa+7nJrIKzRNnspkga4Em+m
         3zYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=I2eSKntJoDu7PSaifjCNtjwnVw+DXqkMp+7B0fZShOc=;
        fh=jZhFO2vxnoeq0j+8bMKdXrAlX/UfmE1no0utPqorWX0=;
        b=WnsqsbwUonfI9v9tVPYYY9jofvSyFY2SAGuXOzGhbDClxVStpB7bWXelm11qm3VZd1
         H7FbKTkvqge3ek6UgKYkY6p1rZyE1K9FeNCT7/tvlS4mZzCdP1TYjuCgTcKmeD+2kdHl
         t28dX4QkdnN6+JgMapfqcbMfbsnvDKciVLy1Uu6X4Kc971oyPDNxRUuUS6HQlyMFrE9k
         //TZNS4dQ3NocZvIsq5J2B6sqycuFreCzKSKAhWdKdAIoXG3ekUB8xc/WJvIKpYoApdx
         oceLrCp72iu3nkFqpA25TK5n3rXpGXiJM3lkWploVSgoZ7SDNqJGZ9gw/KFsl03V0Gj4
         HAUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FD64poPs;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752224079; x=1752828879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I2eSKntJoDu7PSaifjCNtjwnVw+DXqkMp+7B0fZShOc=;
        b=X9AeRLWBXAcDskFdiwoLBy2sEJskNY5p027QqRU0zJkXauPaZHJ/WCqDjQz02HjAj1
         AFoBgd6ql1PUOgz1WtG3KHT7k5IznAexV47bKZP0JEx6/fZIs024nTbtBjklJgxnYd/7
         sDdA+xgxdfZGpojY6MuSalrlxuwIYsZYZkr1kE0Qg6LXIpRTJUKEJQ9KxyuxjJrcT+ZT
         ncfyOuq+0O9k0p8633ybyr57jsJMNkDVc6jXU+/E3ImTUDHApsNGinj05Q31g95qtiDN
         kPyf7iYj6ZNNGVuFcfd9KlXnKsfeKkOJ3H/nt4XMh8uIz6Y1mJN6GQf3THyfyWylEQKp
         lfbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752224079; x=1752828879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=I2eSKntJoDu7PSaifjCNtjwnVw+DXqkMp+7B0fZShOc=;
        b=BdnhJdCOTQunj02qxQyRDng9Y4yGC9HIDBatdXgE25L805w6Mi+Lu95aY1Pg/DrUc9
         wI6mK13TrG9JDwJ+Pyude64jYdDEGqIrd+2W/GZMVITuYDXhBljDv161DrOHC29sjy6z
         PToWA1SZss5ORq6Xas2Nofm3kndrHhOkSbaoaz0ty+ELxTZd+CeAOexJ9oxHpNYDS643
         VRnFGo7DKQP7yXrJCR1icZoIANDdjcJ3m7T2RWiqszIGOe+ClpVcrcAlVy4z6Q3PCitc
         qd2zfV5FIkUE2Kl7AfAi4qvzrSwlrQypLK0SfIr2aYhIO6Ue9bfZp4VptpeYYGQfJ38Q
         kF4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752224079; x=1752828879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I2eSKntJoDu7PSaifjCNtjwnVw+DXqkMp+7B0fZShOc=;
        b=eK6QX8DMGlZti7spZg7uHvOjAJYbZtWo/UpeYHGUeNrk+ZyyvRa+qkPrHOfjOEFQi3
         u5rbKLeoGj6ZqE0d/1vQ/J4j7y06L0OPUJPSlHLsjizOiIJXR0OcY/MCwJP2S+fcXJ8u
         hrjiNjDQYCxKAqm0TSs8QTejQnqpfrZxtQ/jqqUBzZ9IWVxQTtDbh3nhoeRydXlavcSZ
         5ki7ycJwS4Hu7fHU2cHxupzKfWAOLyBE/Ut4c5DQJWPpWF6E+xBVODTpzasbLH9QM08Y
         7ANokxJOUDtnJFNQtHo/0WaN7TU/yrVwWcSZXnRjoVWwSWWZFpnWy55F6g/Da7Tu74QR
         xXQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWrWQprwHyoAh9Zl76gM9QMUVV0Qmk78mlrWfMKLT88XM1nptNtIlUMJyyJzNl6psZG3njUw==@lfdr.de
X-Gm-Message-State: AOJu0YzzuPsUX//hSdY3qflYT/oC1b6Y3mVdPTESw2uTc6Yh/p1SiE1Z
	St0g9Sv9JxSLDbQfILfiz2DOVtxzvC6OKUA8KPcHG7SxZbGvukT6lAz7
X-Google-Smtp-Source: AGHT+IF2efqKuzwYh9PW8Wlj0rMOl1SpYT4nPqjaCe4s+KMvFFyimgUcSv8CGXKsYy5X//vLTR6x6Q==
X-Received: by 2002:a05:651c:19ab:b0:32a:8030:6ff8 with SMTP id 38308e7fff4ca-330532cb89amr6857581fa.10.1752224079319;
        Fri, 11 Jul 2025 01:54:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeLbG7egvP00UFBiiJg4E+Do8IG7KkX66WGUKhdnyDCxA==
Received: by 2002:a05:651c:4215:b0:32b:800e:a2ed with SMTP id
 38308e7fff4ca-32f4fd4e8dfls2976141fa.1.-pod-prod-09-eu; Fri, 11 Jul 2025
 01:54:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUo1ef4LUtCpvzsymuNSEWaH9VI2oTXjTKQjjIqnWu6jCT0cmikLYtaYURNaYLXS7ojbGMbUzWwadk=@googlegroups.com
X-Received: by 2002:a2e:8a8e:0:b0:32b:7356:94cb with SMTP id 38308e7fff4ca-3305343f60emr4128761fa.19.1752224076213;
        Fri, 11 Jul 2025 01:54:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752224076; cv=none;
        d=google.com; s=arc-20240605;
        b=kS90SPuGwHTdtlKPxaOrSSs6+jrO9eQefWh3/IRlsHzeCcnr1y8NT/PFWhnGYTQUJd
         mzqkv/wANtlv+SLi6iMn6GoVfjrN4RneqLauPJTpmXtAz5J/BOhGiRIAZKUuctEkN0XF
         HzMD2tyeMYOznN3y2wAEQOuN8X5qksRGP/l+ywfE40yktu622v2V+BLcnfvEsnw0zL7o
         s/lLFfWgeMF6KjlMpkjqgn8TmAp9PgLcS9etBCAu+7RCXkGnLZnBlhNOsG/ibeCpAf+3
         6Enzi+RQ28D78cLhc/k+CIJnOfu0SnKC8UMjyqDysAjn+dRxAxrv+Fe48gifYkhXhF5Y
         U4Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=ziEQtJ6TzJ+Y/Zcb94FyvvcznpnXNVBhWXC9sDmSYV4=;
        fh=Hcz9f/FH/jGbj8dHjHJEVlOV1ygHXw6m2RS5SIwlVMY=;
        b=KH7cU8R3hWP1PGKCWZBWm2iFNDik3EMUlepsxXUFth5nmMSeOPUbLOOAKqomGtKdH8
         /c0IDqI4RLyxBwsZ7/tvl3gTU2eiCuFOTxz6psMZ4bSicadedGOJZKd73Pfz5s0vM9Qx
         YzmVzPXwdqA9OKXQU7c7symnHg+XYwtHYuoMdzg3bX++sFIL9eW1iTUnVIngZHnRMxG2
         scT6aRmNF93Ok94wGndgLxS+qcXF3SrY9+qOlIhz0QaGzHL+MM+SSY34XbqIX2IlNMnW
         XxQm4yYVJk+keE4oi1d1bxAsPUd5338YJVIlC5xIAnLw60NIyd7GcWmaP00dXxNvapb9
         OAww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FD64poPs;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32f99f4ee07si697201fa.0.2025.07.11.01.54.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 01:54:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-553b3316160so1920411e87.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 01:54:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJfmLyf5ArrDQTwJilrSmC5ckwWLl9vz46zeP9OcBTSexZAVqNdDJyi8y1RYMdp75nkOFUaRgsz/0=@googlegroups.com
X-Gm-Gg: ASbGncsVs7/Fu/Yo81dwbyH1X1DjBTOCCF9JsT1ye8j0b1rIIrKbXaRRwaeKnxJPo6k
	pRcBbhKktA5n/0um0KwwHUmrK8VCkslaFQ4qk1QmIu9x5Eg2iB49mr4+68nRIfN9kyVPkdc6j+o
	Tj0rKsyGu+f00CQOzgoy8TH9QS2snd8ylPxykRJXwNEnzFqdOuC8v56nSo/fLgTnM6vMDcXxCij
	Dj1tdRFVLewdqRtve88LFB8EbJOUBzd3AjipnwZhx/D+VJmFwc5ekHkP4kKmtz3y9n38ArcBggi
	qLsl1EeoB/zOf7nxZIZCndkBaqPlL887Dvo/Sat2JV5IJB49m21slZ3i7solk4Pp5VEE8BNC3p0
	Eu/uu/laANHrvZGWpJcu4UMNthxJq6yPtPmY/qfjSqfWBHJeKsA==
X-Received: by 2002:a05:6512:e9e:b0:553:543d:d996 with SMTP id 2adb3069b0e04-55a04609b15mr657418e87.33.1752224075346;
        Fri, 11 Jul 2025 01:54:35 -0700 (PDT)
Received: from pc636 (host-90-233-194-86.mobileonline.telia.com. [90.233.194.86])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55943b7a6f2sm820437e87.235.2025.07.11.01.54.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 01:54:34 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 11 Jul 2025 10:54:31 +0200
To: Byungchul Park <byungchul@sk.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Yeoreum Yun <yeoreum.yun@arm.com>, akpm@linux-foundation.org,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	bigeasy@linutronix.de, clrkwllms@kernel.org, rostedt@goodmis.org,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	kernel_team@skhynix.com
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <aHDRR6WBISSljdcd@pc636>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com>
 <20250711021100.GA4320@system.software.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250711021100.GA4320@system.software.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FD64poPs;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as
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

On Fri, Jul 11, 2025 at 11:11:00AM +0900, Byungchul Park wrote:
> On Fri, Jul 11, 2025 at 11:08:58AM +0900, Byungchul Park wrote:
> > On Thu, Jul 10, 2025 at 02:43:15PM +0200, Andrey Konovalov wrote:
> > > On Thu, Jul 3, 2025 at 8:10=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.c=
om> wrote:
> > > >
> > > > find_vm_area() couldn't be called in atomic_context.
> > > > If find_vm_area() is called to reports vm area information,
> > > > kasan can trigger deadlock like:
> > > >
> > > > CPU0                                CPU1
> > > > vmalloc();
> > > >  alloc_vmap_area();
> > > >   spin_lock(&vn->busy.lock)
> > > >                                     spin_lock_bh(&some_lock);
> > > >    <interrupt occurs>
> > > >    <in softirq>
> > > >    spin_lock(&some_lock);
> > > >                                     <access invalid address>
> > > >                                     kasan_report();
> > > >                                      print_report();
> > > >                                       print_address_description();
> > > >                                        kasan_find_vm_area();
> > > >                                         find_vm_area();
> > > >                                          spin_lock(&vn->busy.lock) =
// deadlock!
> > > >
> > > > To prevent possible deadlock while kasan reports, remove kasan_find=
_vm_area().
> > > >
> > > > Fixes: c056a364e954 ("kasan: print virtual mapping info in reports"=
)
> > > > Reported-by: Yunseong Kim <ysk@kzalloc.com>
> > > > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > >=20
> > > As a fix:
> > >=20
> > > Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
> > >=20
> > > But it would be great to figure out a way to eventually restore this
> > > functionality; I'll file a bug for this once this patch lands. The
> > > virtual mapping info helps with real issues: e.g. just recently it
> > > helped me to quickly see the issue that caused a false-positive repor=
t
> >=20
> > I checked the critical section by &vn->busy.lock in find_vm_area().  Th=
e
> > time complextity looks O(log N).  I don't think an irq disabled section
> > of O(log N) is harmful.  I still think using
> > spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> > of significant irq delay.  Am I missing something?
>=20
> I prefer this one tho.
>=20
> 	Byungchul
> >=20
> > If it's unacceptable for some reasons, why don't we introduce kind of
> > try_find_vm_area() using trylock so as to go ahead only if there's no
> > lock contention?
> >=20
>
I wish we get rid of using the find_vm_area() from already existing
users including KASAN outside of vmalloc. In some sense it is not
safe to access a VA because of "use after free" issues.

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
HDRR6WBISSljdcd%40pc636.
