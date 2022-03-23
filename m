Return-Path: <kasan-dev+bncBDGIV3UHVAGBB3NU5SIQMGQE6I5NAXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A5B4E52B5
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:02:37 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 76-20020a2e054f000000b00249606fea4fsf545501ljf.19
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 06:02:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648040557; cv=pass;
        d=google.com; s=arc-20160816;
        b=BOx6uTHQVj8qSo6gnr1eqQUtE4xICMbVXmdf3PwE2CJvQRc31y1a03URrqETgqCB77
         Gm7LA9A5QCT6FtL3e3IRTSZWk9qxYbWRhyNVYMh0RQQO2tOMtjeDU4Ax667xrZa2rqGd
         hqQJLnEJC0kcEIw4AKfpMbpxwvrR9CWhdRgAeafpU61P3Vmg0NljkLUgqQS7c2PvdZ04
         TtFOyCRVrebMC31dK77/9m4+WSlD6z470a6YoH5pV52UqIwpCYwyXY4CEbzELwp7syp9
         PWAyNp9ON+aIx3GODQCVBDCTGzSWmrww7NYByus71HkNXzlCzKIXhFeXnwYRuMrXj47W
         gWjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=w91gLygJAucp5bGAnNyTn/22eXGCjke2xlC+kkmoaYc=;
        b=sgcAkGPPo8R95PbI5lX4tkSKRsWvwfhTYGv56JpQgLTGlNWYB1/11vgOsT5N/mZCOK
         hxLuNYlu88CQf+jA0+QoNIcZMjssLnzJ1ewdsj33UGebRUO/4sDWBpNZYLMMVwH3XAti
         kQuc7wSShQ9M1uEZjId+jgPW7KmsJyuFDjhfpGqMsJeJANnQGyK8ivVk7QxUZo/CaosG
         /hEaqDpFK3eK6HuqZVj6K0AWS2hARmfjRqukDF3bvDZAscOzWQyIN6wd50igXnMLl2du
         90Wr6ZaMOxcgiHjRNSTiaShj/a182CEbFKzKRx+AwOJeEFe0apffzULej5cQNVEw7TYH
         vhTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=lTyix5ma;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w91gLygJAucp5bGAnNyTn/22eXGCjke2xlC+kkmoaYc=;
        b=dl1xGjnXCn9n2c569ePyH8paooupZXwZVlPWJ2e8MA/KosEmbtQjrn8JsmbSDw0szd
         2H6CF53V8x3c5raJD5xMcaZCJ9ehxlW2ZTT7OBj8TGidJs3Xntec1s2m23zb9dKm20I6
         zkeOZqGjYsb1UXavWvZgxxhtDXhnsT5RDxwklCnFW/Kvv3dXpF191MpfN20QevQB4HmU
         JySfLv8K+Y7N3HRAdvoRWpp/K7csyh3yHasYQanw0Q01WsQABl47/9nxpjuqyfrjjKhP
         djf6DDDpo+tA8DIK7JC7wcSvAAWJTl1558PXPtgRIAXMABnDov9EiWgDRTNTYtKN6vd1
         Ov9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w91gLygJAucp5bGAnNyTn/22eXGCjke2xlC+kkmoaYc=;
        b=naKpVu8pnOVDPCXghRghsLgv9R4rHzFJ70vKuLA6gRbQC9LAikJ1pgmOUbicbhilIr
         NpiYF7St/YnVu1BnzXpesOCoUj1LRSPmJCMK+9jZnsHlOVC6HKWzUCUTtlzdYHN7ZyaY
         /ZbNy0NJP+qW8B1lSpdheseaWHKSdyJxoF2qhlor1eg6q3/VwApzFGMTCtQjER0uzDLQ
         BCyxm22VUkUZnUGBadiSlGSIkWA5oJM+Y1L3Pxnz9EXyGD74N4BgYCJNIVi8zWHpVtcs
         6QX878F2GrhJ10ElUIUEIKfeag5d76ipBdvIbHo/IAbmqYVQ03kPhUtmTd6krupZma6z
         2sfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tjJpC3XOHn4AU0Ha4pKWJb/1eMIkfiKHQahk5vf1IBU7U6Gzs
	a/0jNMP1nvsScTIo5UiFcu8=
X-Google-Smtp-Source: ABdhPJzp6JTRjipisR+NsgBxkg/CYn5II7Zbe39Qx48fZVRYBrsKeVECmgKmKfU1E9hEiyBskvf9WA==
X-Received: by 2002:a05:6512:3056:b0:44a:5117:2b2b with SMTP id b22-20020a056512305600b0044a51172b2bmr1968158lfb.275.1648040557285;
        Wed, 23 Mar 2022 06:02:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1427838lfa.2.gmail; Wed, 23 Mar 2022
 06:02:36 -0700 (PDT)
X-Received: by 2002:a05:6512:3985:b0:44a:3764:f5ed with SMTP id j5-20020a056512398500b0044a3764f5edmr7204047lfu.0.1648040556243;
        Wed, 23 Mar 2022 06:02:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648040556; cv=none;
        d=google.com; s=arc-20160816;
        b=QnLuH/Qp5ynFSreBQCddi9OwGCJAIlOwWWPpFWcqbT/ILKpPdwmwUuu0C2V4W4OaHf
         IZAAfNu4xr/rBccU+sZtwE56rb6YWj66NR5kfBiLl1UibeuWTOnveDJJMqInxCHi/nhK
         pZ1Myovt8WIyof6RFYgECF7+YKKysSTFkZ3C2kH9RlRBGEzXwuOUcIWbJxeZVCU67MBP
         gRIShq744sdL4PyYienKQ91WXsj2g64twTIJFiaMFZcivBunTUgAZGB5Jhp2pE7YnWqk
         6cCShlP65GLhQliHRBOYSzGeN5kWLTAm10IJJJYgDqkJ0pqv/pEd13lDVq0pY0oQqLbn
         mqkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=fbCwVVRphwKFhHFjdgqzv4b5jAPDrPw5EXg1eflzqcM=;
        b=Uv7zJ4eR163lTKzSGOuYS1kjyIp8YPVOIDeJBHFqhh4+r7WrdZKnCLLgR0LVHQYKvx
         esaCgU74h3F1WyR/dgsTAX0n6z81643bU+Q5MfjSg3m5EeJs26tD90OGonoQH4I4jE44
         1Zhplxd8ugSzIOAT5aKB4631UdwYqDJhTK3jSt/dn775TrUz7+XI0ruJupnrat0CYQd8
         6G5eQgeTShMEx2U48+ZwDARfDVnlH+zYbJOr43O2IPn9dtnEvCFFNqYCgBB/0HL5Y4/h
         uBmMYC7gpTJXag8KcIkFwnV9PxvSh2tGEZKaJQURxoPKOfnP15JNHOwupqYd8q8Znxed
         loyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=lTyix5ma;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id z18-20020a0565120c1200b0044a2a2536b5si545448lfu.1.2022.03.23.06.02.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Mar 2022 06:02:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Wed, 23 Mar 2022 14:02:33 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
Message-ID: <YjsaaQo5pqmGdBaY@linutronix.de>
References: <cover.1643047180.git.andreyknvl@google.com>
 <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
 <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=lTyix5ma;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2022-03-23 12:48:29 [+0100], Vlastimil Babka wrote:
> > +#ifdef CONFIG_KASAN_HW_TAGS
> >  #define ___GFP_SKIP_KASAN_POISON	0x1000000u
> > +#else
> > +#define ___GFP_SKIP_KASAN_POISON	0
> > +#endif
> >  #ifdef CONFIG_LOCKDEP
> >  #define ___GFP_NOLOCKDEP	0x2000000u
> >  #else
> > @@ -251,7 +255,9 @@ struct vm_area_struct;
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >  
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT (24 +					\
> > +			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
> > +			  IS_ENABLED(CONFIG_LOCKDEP))
> 
> This breaks __GFP_NOLOCKDEP, see:
> https://lore.kernel.org/all/YjoJ4CzB3yfWSV1F@linutronix.de/

This could work because ___GFP_NOLOCKDEP is still 0x2000000u. In
	("kasan, page_alloc: allow skipping memory init for HW_TAGS")
	https://lore.kernel.org/all/0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl@google.com/

This is replaced with 0x8000000u which breaks lockdep.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YjsaaQo5pqmGdBaY%40linutronix.de.
