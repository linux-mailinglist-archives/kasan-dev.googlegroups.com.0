Return-Path: <kasan-dev+bncBC7OD3FKWUERBCGGWSXAMGQECC4O7YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id CC7EB8553FE
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 21:31:05 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7baa6cc3af2sf9295039f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 12:31:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707942664; cv=pass;
        d=google.com; s=arc-20160816;
        b=Swen2SU/X+dgp5MzJsbavQKMvzw24xrIfLTx38fqNNJiKPdrjCb1phvSVHFJrDwaT7
         bwObBO4kMkrD9tVN+1vK4QongbiS2LOMVrtrEc8C85NreGZGtVLlsrie6yQbzPdzUBQs
         qN7KbJYitXyXAOh/ObXaj24KctF4NnnBzBIJaG7MdzQYqhPCWufaQgXWA31NXh5h7Bm5
         thPoUImZzezfa5IcERMqw2fl171iFQXBLRMGSRSmbL6z0HachqcPIF1ZLV2ZQOUOxP5W
         1z17w+3FiUsF+vvMeFzQ8sQeJE2qL7PIXkfwnZEf79a8ZCMHOIWjHRim334e2AxWHKCh
         ovmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sAtr5/ltl9rc0DiVnA1fk6BPRqdgMhz2Hl0FLqNg2ZQ=;
        fh=VCWNYXRV9vhdixZJnahM5IFDuMWx7key/9qFFMvvmz0=;
        b=wYLg0nQvUuAcZPqB4Lg95LqiYfL7z1fAAYAZ/PGob7tAjNz4UbSevo3AUO9CTICi1I
         Tu0b2I6utx5FatPMSqlPmxnKGTBoBe5PsHXbfmN/IB8YMe2GflQaiS4OKiwyeKhfKDZ3
         jby1KaxqOcYpjou+tvBMcxJVH9Ea8EzYmZ8cH4gZ4h895y/P3WKzYYSU0veTZsKJWSRO
         hxUovDZJZX7ivfVdGyPHtz6FenvLhcR/zfzqUXz9ooiYjGZ2jOysKGrekGZlZuf5d83M
         n/40v4ERVQH9GAunddxlFae4l4vsLQAx9Cws1a3LRjFlYdmyZIb4OYReXK+3Gh2VSnFx
         HXYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FkrkvnUn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707942664; x=1708547464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sAtr5/ltl9rc0DiVnA1fk6BPRqdgMhz2Hl0FLqNg2ZQ=;
        b=TSxfrFL/RCazWZf8xyS+LtJIc3FSvgPCXN/ZkzMH79eNhFlNX8RZRDDQONYuJ9nibZ
         +dMLyqm7mMwzjmfYYU7j1OHZDQqLSbMog9crAsTUd7VfkvHRCdPyfT+xjTwENu0hRJgn
         ym8PoUG9yUPjT0fzHD6D7pwIAIY+ksU9WT9gO3rklgYo8bmIMO9JapcsmN76HcU7wuP5
         ieBwGF7iyXgqUM/rkm/jC8UtOm4NscT2p26X97USh5i/zu4JvZYpfNDRDP3E6k9Xq9/f
         Wlq4bfnzhIqASdPx/BhdSEO4A0/8ScGnRmIdZlikkC1TrLl2NWFVbDkxRd8jcIg7NubH
         /71Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707942664; x=1708547464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sAtr5/ltl9rc0DiVnA1fk6BPRqdgMhz2Hl0FLqNg2ZQ=;
        b=Xs8bAPMK39KqRSZfq0me3fNn5W/Od0NzCw9xS5ZjgkILGQHGtaBTRYakh4HGF5inQG
         lvb/awHMlzKcR4T6j35F/z2haEqljOReuaQ3OPFAcZyuLDiaK915vG87wHzU8W0wZFih
         voD0nPWeB+oWC6WXw66st0YqTPMqfElOpiKFIEoppE4qK8tsRx0Yjvj+6ZY7dr6/VKfc
         7wn5QzDeBfB8SQJ0ozzXQyxaCo1DN2H0KjpeV2yWznG4DxxEcZPxJm78DHAi7FQqCiSS
         rSf0/DVb82cBJhyTX9w5jRC3cf73+6LYRVYbwDcywToUMFSRQlpovV3deEAD/n3L5Hv5
         JwPg==
X-Forwarded-Encrypted: i=2; AJvYcCX6nCi6nkxgfU0pdT5mZ3HPP8G/USDae92XLvM2pRiit70ppyxsjrUJhsbJWR95l0g2RR17grfN0j7NLR2s2AbmS+j4bHUVew==
X-Gm-Message-State: AOJu0YxovKHZLg9CkGWsUpFJsMCMRgIj7OhUB2/4c/y/i66bOMCVos88
	rtdo5d9viYuSWZuswFp2e904ci0FfWKbK5zkVGqKTQHsfMmykMwC
X-Google-Smtp-Source: AGHT+IHky/twHKy2+OmEHu+kOUAYZO40HNQtZxjg94BXOGKOwWuXiGimthMkx9w4Kv+qXpX96meVbw==
X-Received: by 2002:a05:6e02:2190:b0:362:9250:df39 with SMTP id j16-20020a056e02219000b003629250df39mr5185199ila.21.1707942664221;
        Wed, 14 Feb 2024 12:31:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3702:b0:363:d634:8954 with SMTP id
 ck2-20020a056e02370200b00363d6348954ls467659ilb.2.-pod-prod-06-us; Wed, 14
 Feb 2024 12:31:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLfleZMo6CHPUkPuDp8YDqrQeSaJlOuH7NjcCOL5Ef9leHxFJMHU3GoNLd5bZWpOZpA+AF+2sYaHbo7FEIKIY6Vj449EW4XePvfw==
X-Received: by 2002:a92:d312:0:b0:363:7a98:c33a with SMTP id x18-20020a92d312000000b003637a98c33amr4071031ila.30.1707942663214;
        Wed, 14 Feb 2024 12:31:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707942663; cv=none;
        d=google.com; s=arc-20160816;
        b=aBQ9Vkar210NfVEJq8To9E9r0a5WW4DeQUpHXEk8T5x0H4eE80RFq+BTJYISWseXaJ
         9SeWy4FWSF41Z/v96exi4JJn0zoIw/Ea5lhcm9odeC4I10phRm2HIicbflN8sy3Kt0hY
         BorGg8As693U1tJ3rQa6aj1UVmaN4Q3F5SwTbd9uyZmCQ5g916G5qbfLMn+HnJC0JJ79
         j7W0q3R5xECTLVfch9RsjQyPzY7fJtrihKYn5101CAN5/A3C5tLRJIEu3Uu3MUzK7wOk
         lWiLqIsd2TOykkrNre/8AKr2UUMthBxZM3GXK3ymzxN9xzhqOEkB7n+Lvr4qWrblPclF
         mL1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NcEj/SyVb+AY5aiDL6vEY+YAlLL1EeaxcCrjK4Q+5oY=;
        fh=72rYKN0NhpFjs8gvE/JZS/d17p9HTcwwERENBhfq4Xg=;
        b=bZo4NbXgYrE40E9KE0DaTvCZxysU+7Ax3B1xAjK9P1k7AKL5QELDP5QiEGlZDreQQ/
         Q560QyEtfczlkRQM4Q/JFU+R4GGio1M/+8JJta8aafQ7e8easR6dU7E6n6ubJhXdFTqf
         n1w95pQ7cpkMTqzPapaLu5OsgSKxSHvpoAxJ2+6jbvSAmJHtGWE7/N2IDMa1p+EKi+oO
         mVhQJahhtxGJMHDj9Mqb5MYXyydlry6o6tUQ1/a3vmknsrqObqiBYvQ4NCEekPHTywnT
         BlrA53hLFmoljHtj5whlByvAYb83Xm64nVNAN7QWIPYfqhUcpPIReAMJlO3J7v4v6Urk
         RIPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FkrkvnUn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXuHYAV/IHXatK3as7zLYRw7E+/X/TnSyBfh+RUeTfvwLxKNVuqu35MbfPeubuvV8+/UkuYkBE93MhRPO0ESEpXA+mua1ILo6NeCQ==
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id r8-20020a92c5a8000000b0036427ee7bbcsi196812ilt.2.2024.02.14.12.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 12:31:03 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dcd94fb9e4dso76560276.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 12:31:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW1YTqd2JJm3yomhNruD9GNyAnOUCLX/ve6NP0Jo8nBFJXPqpo9WlU4gEKkVcY7r2Y2TCJkWVWkY4TeXiUfkuep9Pl/MljqWeI74w==
X-Received: by 2002:a25:4115:0:b0:dc6:bbeb:d889 with SMTP id
 o21-20020a254115000000b00dc6bbebd889mr3283052yba.52.1707942662262; Wed, 14
 Feb 2024 12:31:02 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
 <CAJuCfpGnnsMFu-2i6-d=n1N89Z3cByN4N1txpTv+vcWSBrC2eg@mail.gmail.com> <Zc0f7u5yCq-Iwh3A@google.com>
In-Reply-To: <Zc0f7u5yCq-Iwh3A@google.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 12:30:49 -0800
Message-ID: <CAJuCfpEbdC4k=4aeEO=YfX2tZhkdOVaehAv9Ts7S42B_bmm=Ow@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Yosry Ahmed <yosryahmed@google.com>
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FkrkvnUn;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
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

On Wed, Feb 14, 2024 at 12:17=E2=80=AFPM Yosry Ahmed <yosryahmed@google.com=
> wrote:
>
> > > > Performance overhead:
> > > > To evaluate performance we implemented an in-kernel test executing
> > > > multiple get_free_page/free_page and kmalloc/kfree calls with alloc=
ation
> > > > sizes growing from 8 to 240 bytes with CPU frequency set to max and=
 CPU
> > > > affinity set to a specific CPU to minimize the noise. Below are res=
ults
> > > > from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel o=
n
> > > > 56 core Intel Xeon:
> > > >
> > > >                         kmalloc                 pgalloc
> > > > (1 baseline)            6.764s                  16.902s
> > > > (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> > > > (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> > > > (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> > > > (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
> >
> > (6 default disabled+memcg)    13.332s (+97.10%)         48.105s (+184.6=
1%)
> > (7 default enabled+memcg)     13.446s (+98.78%)       54.963s (+225.18%=
)
>
> I think these numbers are very interesting for folks that already use
> memcg. Specifically, the difference between 6 & 7, which seems to be
> ~0.85% and ~14.25%. IIUC, this means that the extra overhead is
> relatively much lower if someone is already using memcgs.

Well, yes, percentage-wise it's much lower. If you look at the
absolute difference between 6 & 7 vs 2 & 3, it's quite close.

>
> >
> > (6) shows a bit better performance than (5) but it's probably noise. I
> > would expect them to be roughly the same. Hope this helps.
> >
> > > >
> > >
> > >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEbdC4k%3D4aeEO%3DYfX2tZhkdOVaehAv9Ts7S42B_bmm%3DOw%40mail.=
gmail.com.
