Return-Path: <kasan-dev+bncBCF5XGNWYQBRBW66V6XAMGQEQDZM5JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E01CE853EDB
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:38:20 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1d45d23910asf59055805ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:38:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707863899; cv=pass;
        d=google.com; s=arc-20160816;
        b=y4JFIOypzMsPbIma1FYgJeUwxYlgUisgmeuR6ZB6ULZ4Av85dEJYR82MCUZb4FYTtV
         w7vQXPOau1lwtW3+Lln0iK1kuXx8nbrCwp2du6T/hGuZLYdjJDxYpkdjqyOkK9A+oDQA
         4ZRw8IW92ykdb4lb9hahsErGP2UMq57MT5osXOVL2gOZ6tZydDxDQwDu3SO0P3E5iHqM
         12OGvk8N6uxae4t3sqqfAqv0gMCn4MBYXq5yt6AlYqYE8N/cKAjDTTYMxm5iuWfNZSjL
         UjzHw0xzKE9GCh9unv1oT7eSEx71k3htobAP7+i1tdVbjoDMYeIwT8Qnk4LBZmJYoyFb
         vyig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=+NFIIi2q6Y5jz/Us900Lldn50S9NbV1pYUmNnCASJ7E=;
        fh=gdUjR7mKZ5LCpBiTWPGKN4CCA+0oUqYoqa9H4uBnoOo=;
        b=fUZXoYoN5n4ncLSKmn2iWVwnBc5H7zRAz67sXaPsDJcSRHs+G8QcUCP5iIhw2D4mdf
         mXOHAViTivPa2Nm7BtiCG+xznKFGObwfrta5se8x7DpuWGy+R6RA+ib+dBPC0Ogyc6l8
         6hrzKWfZAfqNkukyw2S+3po+92ltkA1jvfpg5NflbZKMTlGcpDBC8pXOIpLxZe3Isu37
         eMrA+8PvuAXLzTikGzGx700pj+wO96dkx/SKzb7Yfr/jqv0N0I3JeezNpXGBxC1dHa5g
         nccfR/AwtbvO1ow7nuRPCXQZvZW/mvGTjttx6wfaYXgbYDnG0V+Wlq7d9+1xwDuofye0
         S+Lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qq9f2Rzw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707863899; x=1708468699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+NFIIi2q6Y5jz/Us900Lldn50S9NbV1pYUmNnCASJ7E=;
        b=VzKeViYxEJUw5p/0x3M5ZXAy1tPpQxKXaghsdbdklKg9mZSk+y9NtMU4J+ErIc5vzn
         4KKbTCThR0K+I2bG8G2Mch0vk/M/apCmq/aJLLR0oRGl7rcjjBO6bp1VWWeMCQt23EHi
         Kxzp2KWO8ucVdloxA1myppLL2GbJrhk7mJM+KNRtA0HfixnarJ4ySFkBMcIO5IGvvwbw
         j2Bx99u0GVU2y7pCeGIOUgf6GFyPAwZBWqW2GDOaLxMT+QnW5ZRTj+Cxm9Fl+ZF+O81/
         Ppzabhwy1FqIWdO0q5wQ5mo8vYXVj8gRhGFZPjqYm4UjIbxfjATvMTFvgwicB6/uJ/bC
         bxbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707863899; x=1708468699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+NFIIi2q6Y5jz/Us900Lldn50S9NbV1pYUmNnCASJ7E=;
        b=BiqlK57n18FW3QFsuf2WLx+bWSTUjqa9I36QZ7JWhgUqwr/ee8Jr66gY4b9A58MZIU
         BdORCKVbpUPEifhhfclK1yW5yThZ24SHEoxed4bRFyC7w2rHorYpUDQ+J/uv1NoG3cwT
         QCQFi30xWqtF11Qv6sAtjzE4zF9i3IUKiF9LZS+HE0QfHYeXRV/UXuuU4llpPIRFj1q3
         5C6oq75urS01nQ/qkymYKqeFmeDr0MqCSfR/7C49Akj00Mm33jfm33rtBOTpk0VQFhmR
         ZDeSjPUtm+0FAdpg0D1Jano9FMbzApGh8MMmreEJgKM039RYOlXn/qx8RP48fQTenArG
         ibww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0Gm5l1DEEzYMoypVQv3exl5jfZi5DweTVQYda6sneEVU2hcMdbyrorQMJfgs3eeZJO2SfpiDx7CPZPLTMh+O+sHiIduXNVQ==
X-Gm-Message-State: AOJu0YwG62QP4pqZ7dKDKlSDyogLPOsiZqDtCRK9ZyTp/oGrS4M32r7i
	DI5lw5vYjedLCZK9Z5CRUV7FN+QMLInm8SdXPUGPSHnuvJ+Js1yB
X-Google-Smtp-Source: AGHT+IH0+ch3aIsGSldztXuvohOekLBGA9y839AjeP7D8TrfMsta2iv9KnB4D3a2rAbLGDCFzr37Nw==
X-Received: by 2002:a17:902:654d:b0:1db:2b8b:49e4 with SMTP id d13-20020a170902654d00b001db2b8b49e4mr941194pln.59.1707863899290;
        Tue, 13 Feb 2024 14:38:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecc1:b0:1d5:dad7:c276 with SMTP id
 a1-20020a170902ecc100b001d5dad7c276ls3544513plh.2.-pod-prod-01-us; Tue, 13
 Feb 2024 14:38:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXW83feTI5v4FfWBeZNJkdY/tuRzQsjwcsPgYa8EkCboWlfaVHb/jPPd4w8Js4+4CWoxFgRqaCXv174OD1o0gXmuZFfSlnVRE2W4Q==
X-Received: by 2002:a17:902:708c:b0:1d8:f071:5067 with SMTP id z12-20020a170902708c00b001d8f0715067mr919287plk.35.1707863898293;
        Tue, 13 Feb 2024 14:38:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707863898; cv=none;
        d=google.com; s=arc-20160816;
        b=ekqDphBC/dTgPRYw1OMsU9YyHbrziM8l5W8yQs2CQYjtLTnuglnEjJ1zQ2aNabFzk9
         RSsL9bE19F8502ANqeL7q8i7hR7gNjoiIhoEWaW2s4RDi1QDBRPdwDSvHRHB/C1Fk5Zn
         pHkWYZpFD/ZCTubQ4vKFYDKSSlX4Sv5CppAqj/koCzcA7K+onBAAPiX5V93e2gR52fp4
         KHebDsOAsMjBpzHEjcKRJUO/gdhvu9QK8vnLbVxIIxYH7QPzuBoZv2Rm6l8qbs/pOOO9
         Sm2WfbXvIVSljXH91UUFTrcKf8DfkY4BvibsCNYEiQ52SSgEfK/377QqYjyRC650f0rk
         6YNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2hiMS9Vllp3coocjvge8ABDhc28Vq8F9ZVWNu08lRdE=;
        fh=KFW8Y1DJZJu4YCX3M2LZlOaUJ/KOgmBarbVnu3qn7/Y=;
        b=NU6eXY9+ZYjMK99WPrXAusB5FRuYTXlvSxt3gH132WC3j4x8I7LJMir9pz8sUxAEbx
         jkPcy71+nWmfxP0R2/B9vPfIaDhm/LkMu2ZuJjjwheXO0cHBOsc1Le5bPnbmU8YHXDO7
         JSvMMenoumHhIXou+QM1jQJ08ABfIgSvXPBHOsDrIt5ZpQ7a6ZyFi/AnEEo6Au9g19pG
         aHbz2L0c4/ahOpMNUEsFvjlWV00x/LKXTS5G0jjF5pDr7afByhjrua85h1IbSGmUMn1h
         gCXBwhdKZ37dpVwR2NXcYJQW9jMxUPHCp8S/cjSB1NNQJAimvWy4mmbnALENEHxpVPfe
         Id3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Qq9f2Rzw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWmEcQYIApnyqmrRkqWpxxHFQjgp9zQYGWd0Wej4RIHtaL6iwgZBSbOwf04z+yu1FJjTJx0sn1uwF686Jsz1SKKGI3F2yyqqJcspw==
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id kk13-20020a170903070d00b001d8d1a697bdsi285014plb.9.2024.02.13.14.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:38:18 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-6e0cd3bed29so1572604b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:38:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVqzoFDgP4zBrnl9A37HYms2n2EAvahibDj0GV4XEHsjx3HNmPd9tLDLMaJ97yMQ7YnffEt1FNEKJ4lvVUtMC1VVX62xqQJ58EVYg==
X-Received: by 2002:aa7:9990:0:b0:6e0:41fa:7a15 with SMTP id k16-20020aa79990000000b006e041fa7a15mr653579pfh.22.1707863897877;
        Tue, 13 Feb 2024 14:38:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW/mn7Onajn1J9Z/lzc5p1K3GH0bHTJ8UQh7vHO5BQAFHnDtHbjjGikPt8hRIxFLijyXXfhs6BUN9IGUx/qqnllCDiNQW35HgkzGgIiJms/lS7cKaMxaTrICe0InwvzpgoTdPMlJXH8ZsyKhtMa1YtjeN2hhA1HGJ7RbTZSnMgNW5Nn7kqMq1jXl00ngm3yAPwt4B+ltS1m3X80zQ0tx2+0vuqofg1OJkcdOXWaSDMKQzjAgI2V9j/sN+NU12nSCSPRpWWje79JH5v2z5778ubXaBbRHfCmHUPR5jpZdFMxFDDRaMDf/I3IQksTGF+Dvz9thjaYtmnnla/Xf8d8s57uBU1wxG97yEGGnSk8Abi1qhLYAlgDk6rwO1+57C0IxWUsveToMKKfRTvzSXFBtvOXMrbqaEXeZYD6+KnSV4xXsdCITu8MvuzOgO5UCjop+8j2Os6P6oscGHq1+KkNrzNeQAdGKeIoq4frxWn4WjnyXY9l8erqIvfl2xanToYVpK3iWBYmuR5sVECyuowQkQJDlxWOW6eWs53JgYs5Rc7YlppdjxP/NspE/ksEkkc+SyDYflDndEmCqBETHM1isOIYb/QKCYfob55PByWAGxEynzShVBWDUAxrgUL3vt7Tuv1hdrqPEf3NuV6WudZ6HOymLHhktUYR0CNdTjRTNqR6yprREa7ffm0HRb1UFAmrPP8Zpghvk8PrJGNPkMRC8C9IsAb4mR826io/AvAdWw6/8HxQxjRifwiXL3ax19SiYvcaWZJORgRvrc6BKqDE+9YhtzdtY7mxwZaA5FPY2Z93Dzjhu6tBp5O4iBOTmH3pYGWF48N/ixRoGO9ZF2XT7PCRzy2HnrSHklqXYj8OiVtT5Z2Grztp9A54UxToDUwNm/rqVjreNyZUFIeybKxRtLmAxSXtWg9ZhjixxrmFdj9QJwTPj8xrHT0QrD2KPYnQzWzNvg
 sL7QoWy6KDuO0oyAl0vITPBG/cs14G886TXwdmDk7A8EOyY3m6dR6vNdga3RYMpePu/vzNqbOm4ygJkJFc8tHJAVzQNK46PAMrgR6eYNGymWaqkIvVBuFR/hnImOxZyoQlaKs3QmlXMBH/5S/PPuQAIfo5Hgcs/GjlnwbbHUqz6lS9HF74Kf3g9ohORS3UD8a7CYM0IVXW2vpqo8QuscdGqJE/CmetUsk81U36AV+rn8AB/jd9qAZBPpkscPzoE+ms0rADXE4zzMS3SI9r205hfu+7aoVS9+pgt7DHPqz0UF/QuSoA+4QGdmamg4PBvu6oszFezeZKHXxUV0cvvkw5PyAta9VaSDdeZPlCeIA/A3b31HF2iqZ2IZtHbyb7nKZHCY3QLOA+BGYeGUXZp58WpatZ3FmcHRTzDDpP+pP1JiTuJMUG0VvYNmBy
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id x23-20020aa79197000000b006e05c801748sm7926811pfa.199.2024.02.13.14.38.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:38:17 -0800 (PST)
Date: Tue, 13 Feb 2024 14:38:16 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: "Darrick J. Wong" <djwong@kernel.org>, akpm@linux-foundation.org,
	kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <202402131436.2CA91AE@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
 <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
 <20240213222859.GE6184@frogsfrogsfrogs>
 <CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Qq9f2Rzw;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Feb 13, 2024 at 02:35:29PM -0800, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 2:29=E2=80=AFPM Darrick J. Wong <djwong@kernel.or=
g> wrote:
> >
> > On Mon, Feb 12, 2024 at 05:01:19PM -0800, Suren Baghdasaryan wrote:
> > > On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromium.=
org> wrote:
> > > >
> > > > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > > > > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions t=
o easily
> > > > > instrument memory allocators. It registers an "alloc_tags" codeta=
g type
> > > > > with /proc/allocinfo interface to output allocation tag informati=
on when
> > > >
> > > > Please don't add anything new to the top-level /proc directory. Thi=
s
> > > > should likely live in /sys.
> > >
> > > Ack. I'll find a more appropriate place for it then.
> > > It just seemed like such generic information which would belong next
> > > to meminfo/zoneinfo and such...
> >
> > Save yourself a cycle of "rework the whole fs interface only to have
> > someone else tell you no" and put it in debugfs, not sysfs.  Wrangling
> > with debugfs is easier than all the macro-happy sysfs stuff; you don't
> > have to integrate with the "device" model; and there is no 'one value
> > per file' rule.
>=20
> Thanks for the input. This file used to be in debugfs but reviewers
> felt it belonged in /proc if it's to be used in production
> environments. Some distros (like Android) disable debugfs in
> production.

FWIW, I agree debugfs is not right. If others feel it's right in /proc,
I certainly won't NAK -- it's just been that we've traditionally been
trying to avoid continuing to pollute the top-level /proc and instead
associate new things with something in /sys.

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202402131436.2CA91AE%40keescook.
