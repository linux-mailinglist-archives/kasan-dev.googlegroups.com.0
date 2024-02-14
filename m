Return-Path: <kasan-dev+bncBDNOHB7NUMKRB4N7WSXAMGQEOUZ223Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 112B68553D3
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 21:17:55 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59d77bac3besf109881eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 12:17:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707941874; cv=pass;
        d=google.com; s=arc-20160816;
        b=bVZjrRbhQSZB9Hh2mAbAFFihWp+lxJ4z8YFdBAUTJPBW+h8s7yTY/QQFo1KMPzjKfD
         oPG/aBMVIv/C3lZZB1Nb7i/dmy075l910mzz0YchFhKVAAsMJACQQDelN0mC7ayx0ie1
         ZhOSV/hI0DLJBCpAz1yna8XKusyU1tZtivdiPQIrQApEsvwiKH9G9GUWNHbsIWDBl9N/
         0JcjcdDIvJr96iBZFE7DsXONV66n6q06nvrSZntv9fsA8AoofJIFKukKo5Gaq1iiZrEn
         Xj64jdfDlrfskIlDXUCjJ2VfoZeYlYd0lJ3xKutB45zYNC7DUwgU54vjlNm474CaTjra
         p6mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VRm2yAXqwxiZXB7S7jeLSPmJajJS6AepMSoJccpGVNY=;
        fh=vEC/cwo55EQmekSTfa5x4sgjh9cuWQfRt1bOdTQJu1A=;
        b=q18HUqBmz1C9ULpLKsswKEZ9g4kIGItQaVJBeBfXetBYqvTiGJzGJuriT8j44ccEdD
         tT4W+rSe2cc84PpNEhjrqdpF+cFSOEGERXBpuiMNyQ91ee6mkn7wTnLAoNTV4dOu8inZ
         oItFWviLIO0lRDaqorhM/ZRiC9A91Rb9u4feeNbI+s4hhONo3n1zn5UH5xvhvmArUJXf
         vhyWEWOlr0jlZBerobfVvsZJCzuyMIqh2V72LlIcPMHMU7Ge9MALDx8gPVVSMaUAHSzk
         78+YY98za3Tg0ZkGmabzvCOCS2LNA6LfNdvRpa22p78OZhjhbfHyHRihfb6gZKZ3D48z
         SlTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mAuIno4c;
       spf=pass (google.com: domain of 38b_nzqokczkrhlkr3af769hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--yosryahmed.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38B_NZQoKCZkRHLKR3AF769HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--yosryahmed.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707941874; x=1708546674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VRm2yAXqwxiZXB7S7jeLSPmJajJS6AepMSoJccpGVNY=;
        b=v6o8f66d7cxIHvtyRCbeZoD4Xc+M6SkuXn76qukXYOZ4rf96QOpDhZZ/OVTL+tAFnv
         VUwWki0CAMmcLzouL13PoG+bo5FyMuD9wHMk2CTqXd5TU9Xm8000xXN8LV2jnilnilV7
         7ENIc66GzD3O6B+g+rEWezAazwNLyvobKA0BIOHcsxYUplMEOHhQE9pmtWIRm25eQKFl
         Xe2/YSNdYu4+ph4cD3YLh20Xc0h91cX2zFFxlUehSbnnS0u+38Yi2qrOlos4vpceGpQO
         04eAeL5wDgnk4Qvn8Mk8quZzrJSXbA4AIVgqoNB1c9okc7b4zD3jvVY99L/kaThdHes2
         nJ4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707941874; x=1708546674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VRm2yAXqwxiZXB7S7jeLSPmJajJS6AepMSoJccpGVNY=;
        b=dMXxKgqJ0hxF/DPssKCiuFpnzCPLVCOth41FJt0vDbfJc8mnCXsx+oQ1hL/cNwmyaP
         L4mLxivq/2M+hbgs5kF9/rSI9OkSw5a+qgaYcilyiCFry+zZCniKAbiZgizEzlvuvwRN
         SZ3imqPVghah0P7T5R9ei/JISPPAKB2QVDqR4lj8wVcnay+rpyQS8s2Ai4p2+zhNQ9uK
         LYRHKzUr1CbSszO1L9n5v/q9YBnhfkfXCP5vEByUBr9vT1nuCAqNGs+EWlcc44WpWT3y
         UKE9jaxNj6iZPcaj9exOitSfIz13qSWmmpZEo3BDTM4mCMWbS/mhUoZjuQnkKAhV9AYl
         B6EA==
X-Forwarded-Encrypted: i=2; AJvYcCVni64VGqEMuzzCIJQpwXGfQDWf/QZoxQtmEH1lsISB+5b870yc5pxjTlTZePX0VGjnael9BYVk/yCF077vDUTdZ4boAYU5tw==
X-Gm-Message-State: AOJu0YxEa6ZTpnd2ayFFRh300mY8zn94VlBnriT09Taoo+1Cj07KkSaI
	oXwc9iHnkTP0i5MW9PStHtl4bQDMIHLZvjK0Xqe8V0mAXjsmtv/c
X-Google-Smtp-Source: AGHT+IHb6qXfpUua6Kx9fULZ1sm30IpmrSEF9tz3f7qpD9aHqHOI+WfVsPoyOhhaidWfDu+sjnvneg==
X-Received: by 2002:a05:6820:1b8e:b0:59d:d34f:7eda with SMTP id cb14-20020a0568201b8e00b0059dd34f7edamr4910021oob.0.1707941873985;
        Wed, 14 Feb 2024 12:17:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:584c:0:b0:598:c95b:c3bc with SMTP id f73-20020a4a584c000000b00598c95bc3bcls482746oob.0.-pod-prod-05-us;
 Wed, 14 Feb 2024 12:17:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVpGAhZxvY5Gy4ainIIxfMArnZG0vSnQr25HsZB8GGxcCy1GnQyGpYO5NA4t6mXxLcUx0SSbroSXjxWYSaDz6w0wV8UkP6MboUHAQ==
X-Received: by 2002:a05:6808:1796:b0:3c0:465a:2b58 with SMTP id bg22-20020a056808179600b003c0465a2b58mr4422225oib.6.1707941873140;
        Wed, 14 Feb 2024 12:17:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707941873; cv=none;
        d=google.com; s=arc-20160816;
        b=DKWTZEa5B6y0ufdi9iOj5oIWsca4JLuMS/IpMokRZjwkzvkMR4l5gvJEAJkQUwPXO8
         SkyAYntZxGHDbEUw0HO+G1yKK9/TtMLoSIjrkLEbvof+Reho3fWXbh/E5t18WtdrPE20
         xsuz0vRxFuPa/OOrZP5yYpqC5+os2Luq/Yh6NqPeX9bN8Fj1Rm/iu+GnsgM35TVEegIc
         z1jCZphLveAf9sGQ5iUO5kucnG9DuY1nmS1ou1LLpltCWP/1mnBJRSYNPGdRb4vxwZtf
         1ND90YuP9NbX7RyPfgNok+UT7uC/BCO43NA+sxJHNpMW1a9r1aPfN81zB4jYrjuQ9GY/
         BVww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DFRgEJKqx8IUK/onZJk4TNjtYloWEJQ2VMeYiwjP0ZI=;
        fh=XffKXwnjz8u8G4NTb3y9ETFs3cI+/+gs+EfoNw840V4=;
        b=pbj0ot1toXcGf/K9JGx5vYn8dP4uVa3nwrPLBtlOcdZDyzelnDvidyuEaBz9Xqj97y
         huH/uiJk3NXLfO4xNrFMUIhtlvt+J/OIkf52VbPGQ21SSaZ0M5k4cNfX76bmZ5RmyL+L
         n7TzFJmGm9B79Q0Le2QdaI7C7ARXzS4nt8V0K2gWcbVdGMF1XM9YX1pZlktsqBNEclLv
         MMBRIM5kO/VIwxePHAXjVgVLc9/aCNQyk+/d3CmcJQXlWTy9fZJFQRWtYU0t+2h57lAl
         3mu7VKAvjq9+ioxPd/vuGn1f3xuPV6h66b9BqvI/rgZD2i8EVJe5g9R79cR1F+PYj/cK
         FFxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mAuIno4c;
       spf=pass (google.com: domain of 38b_nzqokczkrhlkr3af769hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--yosryahmed.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38B_NZQoKCZkRHLKR3AF769HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--yosryahmed.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUlsGEbtjibMr0DeHfVLJ1Ff7GRkxsesMj73cE81et/clBWRJZeDEHBLMk96JmYU1vuVkWzLlicOky78hLNEoWRu7OD2pzFPE3O/w==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id dj13-20020a056808418d00b003be04bcac59si525212oib.3.2024.02.14.12.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 12:17:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 38b_nzqokczkrhlkr3af769hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--yosryahmed.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-607ca296b64so1332437b3.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 12:17:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW/HeG6YceAujkTRkCNO8GvfLwYrOg0x1UxyNcErcwW+HQ9IngUoBUG0+/TqiooSET73oex6PwPJ0318KSt98Cc72Nyb4mnWE3pmQ==
X-Received: from yosry.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:29b4])
 (user=yosryahmed job=sendgmr) by 2002:a0d:eac3:0:b0:5ff:b07b:fb83 with SMTP
 id t186-20020a0deac3000000b005ffb07bfb83mr555354ywe.4.1707941872610; Wed, 14
 Feb 2024 12:17:52 -0800 (PST)
Date: Wed, 14 Feb 2024 20:17:50 +0000
In-Reply-To: <CAJuCfpGnnsMFu-2i6-d=n1N89Z3cByN4N1txpTv+vcWSBrC2eg@mail.gmail.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
 <CAJuCfpGnnsMFu-2i6-d=n1N89Z3cByN4N1txpTv+vcWSBrC2eg@mail.gmail.com>
Message-ID: <Zc0f7u5yCq-Iwh3A@google.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
From: "'Yosry Ahmed' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Tim Chen <tim.c.chen@linux.intel.com>, akpm@linux-foundation.org, 
	kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yosryahmed@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mAuIno4c;       spf=pass
 (google.com: domain of 38b_nzqokczkrhlkr3af769hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--yosryahmed.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38B_NZQoKCZkRHLKR3AF769HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--yosryahmed.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yosry Ahmed <yosryahmed@google.com>
Reply-To: Yosry Ahmed <yosryahmed@google.com>
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

> > > Performance overhead:
> > > To evaluate performance we implemented an in-kernel test executing
> > > multiple get_free_page/free_page and kmalloc/kfree calls with allocation
> > > sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> > > affinity set to a specific CPU to minimize the noise. Below are results
> > > from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
> > > 56 core Intel Xeon:
> > >
> > >                         kmalloc                 pgalloc
> > > (1 baseline)            6.764s                  16.902s
> > > (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> > > (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> > > (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> > > (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
> 
> (6 default disabled+memcg)    13.332s (+97.10%)         48.105s (+184.61%)
> (7 default enabled+memcg)     13.446s (+98.78%)       54.963s (+225.18%)

I think these numbers are very interesting for folks that already use
memcg. Specifically, the difference between 6 & 7, which seems to be
~0.85% and ~14.25%. IIUC, this means that the extra overhead is
relatively much lower if someone is already using memcgs.

> 
> (6) shows a bit better performance than (5) but it's probably noise. I
> would expect them to be roughly the same. Hope this helps.
> 
> > >
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zc0f7u5yCq-Iwh3A%40google.com.
