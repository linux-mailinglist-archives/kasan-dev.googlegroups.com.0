Return-Path: <kasan-dev+bncBC7OD3FKWUERBXUDY6YAMGQEZXQRDOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7390689AD1B
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 23:42:56 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-7d5d7d6b971sf38838339f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 14:42:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712439775; cv=pass;
        d=google.com; s=arc-20160816;
        b=fQIFlbHB66jr5LzJe0R/T6U8lEDwn0QAee7HjrVjuDfTkWfY9bgJEZKY5wSDh/FRU+
         GV9L4TYpPqVOAEM5e7ZFmGzStz7m1NutvnJDBE3QrLeAG4hgZn83HoDMAncbIvztODIu
         z7w4NXSSF+FM6nduyHvgUWM+0qEE+phYKCPcyHyla8QI+WlEugErte5X9OkPFAibgIgo
         BtLNn0UsXxtA3U826iPC8LEgcjsMCEM1ceG6qlREg6NQ9BOk6O91Jq1hdJnKIawvw7/v
         yEjWM91UyKfJ1263F2nHcO3qval2ekm31N4iMJ781FlxX5HxhMjzsZNaC5Q8dufqRhay
         nrBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4+Yk3/um/aqtIUys6118Eg7Y/Iidd0EADgSrz/NE/8s=;
        fh=RDS6C+XKhWzigRkYh9RsNlpQxl31K0SMezOz9CKsyms=;
        b=qkMrGud+/lfYE/yEKGUDm6h43oaIpS+imu0u6kujg85t3Z42ZJSp8J29NQbz4lH02X
         O4cbKIfSF9Kdgtr0VXi/tnbYdBqIl3avqYo24iuRHyEeRT27qbHTlP7zHdjOtLoRdC3X
         8fV8k9/BV7yiEUKhnMfFcOUTesTCZZmq4DViusvULC6sMJiDuk7IIf6R/2R5dTo2aWwo
         gH3oY9OiLapO8d1GCCm2nWBL1O46odLGmVJFNHFKrXADz/vV3qztmmA2ApMcJZIVN/7F
         xtfX6vMVl/OX3kI7r+i8B9924Fd5d8I06jH5caMa3138po6OqchpF89vWVMQang8jq1T
         CvGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wy0niJEN;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712439775; x=1713044575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4+Yk3/um/aqtIUys6118Eg7Y/Iidd0EADgSrz/NE/8s=;
        b=TarB6igpYAYlBjZ4uRA/DTHmLB4E/fAqMQKH2FX/oC94gr/2V6/51Xz5Q05/W1o4Jv
         3lgv8bauvpU0Wbsva3wIQZ0pICI8DRK0mx1iZClslSm2GD4Asz/5mtH25si3QC0p3sr8
         SKyEMfJhX3anw4EzsPtUn2vjsDZjDxibiuY4Grzz1csHfZiItagwdxNb/n8LsMuVmz+N
         3eayLuULRcNUPpdiuAwRqEQQFr7FRNjRfOoLLaAp53G099b4LyjVwuvvi5cyJqPbcLJO
         /l4UuaAfp/53CQV5CFz03lyR7DFA1MbDLG6OVxJk5sB3w4SlvYkiYokXpfpr5DoSHsf1
         CiZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712439775; x=1713044575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4+Yk3/um/aqtIUys6118Eg7Y/Iidd0EADgSrz/NE/8s=;
        b=mFckn1UaPlPxa0q6QSkB2+qlYsijWTwyW/xM4AtUqSUOH+ZndavCDABh2i8yfxlEV9
         EtdHlKUKBMQNWvM7TghC9fbkNPv3hFEdj1F/R1SKqhv1JHvuybTTgJCK5lSuPRXzt9D2
         9LfwT4Bj65tJtdW+pLlg48w12k0h/9Ozshc6tiPA7OvtQMalfxmaThn+zN1Snw0Gc5gE
         9KTLjHJHkMSGCux7c3Hd2zYkdXuu9dh8mgEOV/aM9Mhq1TKkZCv72hR1aJ9xxIhkI1Rr
         Gi6XFgDvqirNLKdOOE2Q0rF/DHaFXqJ7IciMK+pLXykTcsb/kH6ze+U0+76Ct1k4eik6
         4EGw==
X-Forwarded-Encrypted: i=2; AJvYcCVkwK+9OFUKxezERliGp+6tVbyWEBuFRyN++lSTPaCZJTaLM56nS/tMW49GPam54k4IWZO/KbJm21DpshjCeMMnLfsGETIcpA==
X-Gm-Message-State: AOJu0YxDHnyXMguY3oSW9CgXn78oYAT2loXvALoSEk2Ju3/boAWZWODT
	adrLPJjpr2vHkRFcEBGIR9T0gbOhCo8b+yOBXruItBB+qzEWw3Fe
X-Google-Smtp-Source: AGHT+IHSCP1ygtgc9GV1OVJ6asLSGogb9o75Di7HQJ3tQK1yXrHma5qLlIuJIDKVaTGR8ghQxSFRKQ==
X-Received: by 2002:a05:6e02:2197:b0:36a:1e55:535b with SMTP id j23-20020a056e02219700b0036a1e55535bmr827842ila.16.1712439774779;
        Sat, 06 Apr 2024 14:42:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2206:b0:368:8295:6251 with SMTP id
 j6-20020a056e02220600b0036882956251ls2363300ilf.0.-pod-prod-04-us; Sat, 06
 Apr 2024 14:42:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsc5A1/2qOQyLw6IcnjJxJjUtyH9kooR9o81oYu0fp16YAx4qZQWzrz08iv5mpDXlll1Uht5r4xTfL+M2Oo78JOnBRr8eAvYAcVg==
X-Received: by 2002:a92:cdae:0:b0:369:9adc:8ae with SMTP id g14-20020a92cdae000000b003699adc08aemr6439875ild.10.1712439773839;
        Sat, 06 Apr 2024 14:42:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712439773; cv=none;
        d=google.com; s=arc-20160816;
        b=gqvwBTauvnDjwaMu4d8obM7pjkl3bA/kDWDNLPXZ2QriHyhG7LNV1TgbDCOWnYckC3
         Nfw/enelQKkNwmPihMgdEDHlHagxNDxUrHr7SVNQ9MllB+suO9EryJWQ3fNv/kP+UVT3
         O/KCEKHeel2Ts+AwUGIZX/vlUzgs6bu69wlINEdmd0L1YIgt0mUlPS0g+mTgdPFgrL1G
         qT4Qn5we+p+KYx1GtNx9lKgfEGpmrAdC/kv3+0zbEFQy25oSLJWSQuVZt0JlXP5K7CQj
         6WnUHa7RJtGmg4A763b4lmlElOR4j+0Xep0quvBimUGSTlUUoPmPNL1o3U0IOk/23lbc
         Eq3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m1G9gUrNc9dGzPe7AYM33DPZfjgc9cVYEl/DEKm89Aw=;
        fh=GeOgK6TvINXP5aDczkdEDr1oHgeRmI+VFpoy903h4/8=;
        b=0jjSQhIxsnxJhrJlb/kM8xiW9uds3x+H2Zb62BjJbmDAdJoo4K6NmImmZiKWl2Hz1A
         rClEvnhZU41Q6zEoKobnv3VGKnHsRPLYJ9GMo6h7eFX3n2aY52Mu011APrc2vzQ3xiet
         86eSwU8bVKc8yBtGU1GT59yMqxPE8CyI3+a81o4kTxqL8Tvt/W5ZAYD4h3IGOfj3zWCB
         CxpzxXnvbZHAMZkUNKgK+F7fbOEOxX5LOQLD57PnaWhc5b8c4K1NcVyDs3T3mjCXUvPq
         8f2nU1jQ3sQvBkzk1fZ2YWV+1YFOasaV0R/zJD49YadMsRPt7s63Yny3lo4nOXDLw8WF
         bxIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wy0niJEN;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id p9-20020a056e0206c900b00365e9e3139fsi288153ils.2.2024.04.06.14.42.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Apr 2024 14:42:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id 5614622812f47-3c5d5de746cso1125132b6e.0
        for <kasan-dev@googlegroups.com>; Sat, 06 Apr 2024 14:42:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXVtEcgFVvI9xE/p8LQWd1EPHf29FH8rWNcUyZVfF1KY4IsazrEopPgjzImgQTe7aNVxKPSKlbTF1GgrZQIBsoOypqY7Qknb/5csw==
X-Received: by 2002:a05:6808:3084:b0:3c3:dcfc:f694 with SMTP id
 bl4-20020a056808308400b003c3dcfcf694mr5989197oib.47.1712439773006; Sat, 06
 Apr 2024 14:42:53 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
 <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com>
 <41328d5a-3e41-4936-bcb7-c0a85e6ce332@gmail.com> <CAJuCfpERj52X8DB64b=6+9WLcnuEBkpjnfgYBgvPs0Rq7kxOkw@mail.gmail.com>
 <3d496797-4173-43de-b597-af3668fd0eca@gmail.com>
In-Reply-To: <3d496797-4173-43de-b597-af3668fd0eca@gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 6 Apr 2024 14:42:40 -0700
Message-ID: <CAJuCfpHXr=183+4AJPC_TwrLsNOn0BZ1jSXipoP0LE+hd7Ehfw@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Klara Modin <klarasmodin@gmail.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wy0niJEN;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::22a as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Fri, Apr 5, 2024 at 8:38=E2=80=AFAM Klara Modin <klarasmodin@gmail.com> =
wrote:
>
>
>
> On 2024-04-05 17:20, Suren Baghdasaryan wrote:
> > On Fri, Apr 5, 2024 at 7:30=E2=80=AFAM Klara Modin <klarasmodin@gmail.c=
om> wrote:
> >>
> >> On 2024-04-05 16:14, Suren Baghdasaryan wrote:
> >>> On Fri, Apr 5, 2024 at 6:37=E2=80=AFAM Klara Modin <klarasmodin@gmail=
.com> wrote:
> >>>> If I enable this, I consistently get percpu allocation failures. I c=
an
> >>>> occasionally reproduce it in qemu. I've attached the logs and my con=
fig,
> >>>> please let me know if there's anything else that could be relevant.
> >>>
> >>> Thanks for the report!
> >>> In debug_alloc_profiling.log I see:
> >>>
> >>> [    7.445127] percpu: limit reached, disable warning
> >>>
> >>> That's probably the reason. I'll take a closer look at the cause of
> >>> that and how we can fix it.
> >>
> >> Thanks!
> >
> > In the build that produced debug_alloc_profiling.log I think we are
> > consuming all the per-cpu memory reserved for the modules. Could you
> > please try this change and see if that fixes the issue:
> >
> >   include/linux/percpu.h | 2 +-
> >   1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/include/linux/percpu.h b/include/linux/percpu.h
> > index a790afba9386..03053de557cf 100644
> > --- a/include/linux/percpu.h
> > +++ b/include/linux/percpu.h
> > @@ -17,7 +17,7 @@
> >   /* enough to cover all DEFINE_PER_CPUs in modules */
> >   #ifdef CONFIG_MODULES
> >   #ifdef CONFIG_MEM_ALLOC_PROFILING
> > -#define PERCPU_MODULE_RESERVE (8 << 12)
> > +#define PERCPU_MODULE_RESERVE (8 << 13)
> >   #else
> >   #define PERCPU_MODULE_RESERVE (8 << 10)
> >   #endif
> >
>
> Yeah, that patch fixes the issue for me.
>
> Thanks,
> Tested-by: Klara Modin

Official fix is posted at
https://lore.kernel.org/all/20240406214044.1114406-1-surenb@google.com/
Thanks,
Suren.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHXr%3D183%2B4AJPC_TwrLsNOn0BZ1jSXipoP0LE%2Bhd7Ehfw%40mail.=
gmail.com.
