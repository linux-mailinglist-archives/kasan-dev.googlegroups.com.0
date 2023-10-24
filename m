Return-Path: <kasan-dev+bncBCX55RF23MIRBD424CUQMGQE2KSL2FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B9A757D5A78
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 20:29:36 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4085a414d5esf26515e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 11:29:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698172176; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqdLXIfL+62DZqE1fCW7JdtmSNrHj6U49Om09ov8EfMF/xehgEBI/iiAIf9FR3rJ9T
         DtWjiaCH8OG1Flq6n0CNEif9Gt4Y9Eef1QZSsOp2Sf05oiCMGRA33vV5TGY3n8DP8KBh
         5hct6NnL2utWwChKNz+vYZgznJg65mrrkMt/ZUFHDu0R7MLle9zDuVJXyBtOmmTBCyJ5
         ceYYxn6KwZ3mTNJCCJr597m5zcKShYoZhiKbZWU4FDUQmyNVM3QKAS39Saaf9tB5k5hI
         sEtxx55Q56J1NrS7cYcCGRonr3xFRocJBVJKuDy9Z2knHFhszP9efhKent+e9WHVGNaa
         WKRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VoqJiKtjk6vCratudff+JxDbhmQR3aqA7hmccQeFfb4=;
        fh=XZXHwb2VVltm/y/4Bh+qiSc/o+zObAQhj9mP43i6I2c=;
        b=ZmJ8LJ8YF57cDr6ndXwH5Qkc+BkRvjGrG9g2KNeTiALxZPybViLlQUpdwE7NWwId0y
         RQaX2VLAHddCPgyLtq2yL6hLSlovYz3iYMzCp3AkTy7gcOwFtNUnE7d9NIPw2BUhQEYc
         m34p4Vs3CfWJulOIOWmZwb2TOTgx+TkUbbdyF4XmBXw1cpj1d994A5H8b+REAGhd96zm
         L4lqo7utfnZABntmfZxb3vjt4hpevBiqosPsWNNg6pOq2HoC+lOZUX5avbLEfw5XgYtZ
         OqDW7rX3z/wV3xC+YtnE8MQRbDXVM1uMqIrEsHKG1DSCiktLEckyGPwMX97N36V9jn0e
         k1hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qxmyiqZd;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.194 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698172176; x=1698776976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VoqJiKtjk6vCratudff+JxDbhmQR3aqA7hmccQeFfb4=;
        b=Otw0GQSUtsR/I2DoukHJsdSr7m/ULG5FyHpmQypSEblW6bJMSgiK8MSNGQJkWX4z+Y
         uJVOWtf119gvvfIx/5hk2dpY3K8B7Z6ASFhT2Iz+G8JjRya2615Nzjcz8FKsnCdV1Yut
         hyyF7bmDfPJg9GoAyDKgEeIy64dtzF/nlfXu3vAUvbH6PHMnS+dftlEpGy5PWUUn4WAK
         3ev9bWadVuhycGJIgqF498IRCY75guvWlfLtNalvSaTakOfydOrym/V7mnjYqdkLcggB
         8yFTRZNCGr48w1joMkRYEyQcGWUxnBPH7dyuMDLUIfoSAX68A+RLTGLJDIT6ln0dMcdT
         i9bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698172176; x=1698776976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VoqJiKtjk6vCratudff+JxDbhmQR3aqA7hmccQeFfb4=;
        b=sES90v3/lD4WTZxF456KmKxgQXcVmu716IkfFjLymnpdNW78NL6I0x/1bDFu21Lv66
         A5j10CmI2kt95baLw9QnHNrNe301rKDeJr1MqokdcpTy69K2P5awcl2UAjgjDtTptixB
         4rD5kvmexe1tlNsZgYaKayElTR2VLmKKPZHzkWvMTCIqeVmo+ewz12w35d23CMvr/NSo
         DCdsrlDHh/MGTi13UEnf/CwNDMXSx1SXlBxy7Mo7XzUx4F47d6JzA42w8ylM8us2KqlY
         ILR8qd/t65Ja1Xw7I8iDHY6EgCBl56cip8U64kmOYl0jkBVdPnDVc81XEdYPWL8XW8vo
         8TaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwTPH9IgfVMpdqM1sycVhgZCdzCD1+hDlXneMbANX+UNd8ki+qs
	0E33toHtgj4F8ZkOkIP8V+8=
X-Google-Smtp-Source: AGHT+IF8seTpjKNLKrrlMbJ6MqU0nKCHJfckGrTJo0jyS4IIwx2VnfX/44q9QQ0W7NQ0Zk3C2JHqRw==
X-Received: by 2002:a05:600c:1d97:b0:408:2b:5956 with SMTP id p23-20020a05600c1d9700b00408002b5956mr153646wms.6.1698172175387;
        Tue, 24 Oct 2023 11:29:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c8b:b0:408:3ea0:3038 with SMTP id
 k11-20020a05600c1c8b00b004083ea03038ls1950621wms.0.-pod-prod-03-eu; Tue, 24
 Oct 2023 11:29:33 -0700 (PDT)
X-Received: by 2002:a5d:68c1:0:b0:32d:bf26:e7a8 with SMTP id p1-20020a5d68c1000000b0032dbf26e7a8mr9058202wrw.36.1698172173362;
        Tue, 24 Oct 2023 11:29:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698172173; cv=none;
        d=google.com; s=arc-20160816;
        b=OhvlrTl8bSdPaB2cxgcJLRk/912+snR6T6IXdPA8rmFEFgj4ptEXnaJz51kKIonC00
         89DEC2FGQTKL+7gtscsI0+wpgJkjl7i7hLW3Tx1C0VPVVWcSwbgVdXIpcCufVkLBFJZr
         GMoZA2FyKmlreiZlYkHF7EwR+/dU5J33xuwl1tAu4ZtFy7sOoGSNbYFweuybKNlZZTMB
         +6BGUvtUV5xJrB2wrHJEyG8K+dsm26pWxp8xh3BQh+B3Fov08o+HEsy/UCjH+2YAs2Yj
         5r7TuyzQYrfuQVxjW592AbYuJJ6ox5cfb9NTZnQVVagCXyfsABOdAgLWPhf4v9/Kbw44
         jF0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=cJvtH1RU485LotJpakrbV9U/UfyKsr5ptSPtEPeho50=;
        fh=XZXHwb2VVltm/y/4Bh+qiSc/o+zObAQhj9mP43i6I2c=;
        b=XGn4zRngBmd5xBlUdAyfTC54/e9jrLf3Ngbykf/Hu1qdARdb+ft1gCTQbhQ8SUe8UH
         FyZp2moCoia62kvYpPnyIzBazXK3j/sL1kV7yWWlMOF7lTYeUB6ra1h8EpdBzdFM5DaM
         RSQ3kONSA6HoyjC2fwNvAsfT7ADlgK+CGbHTFjwIyY/kyaNNON3jgSV4SyuNmzjOsVfn
         /AQ9auRhjTH7MDlhgAv7uttgPP3yeUtigIhWqtW7Su7Pl2fBKHO+4l+mSqoxR+KjkU4K
         nWSupBJBWkqiAAXLVSHg+gROA0hvJZezGshGSZRckPcMaaqGQSVP4721bYoqO3G3DIBR
         EuWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qxmyiqZd;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.194 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-194.mta0.migadu.com (out-194.mta0.migadu.com. [91.218.175.194])
        by gmr-mx.google.com with ESMTPS id cw11-20020a056000090b00b0031aef8a5defsi381666wrb.1.2023.10.24.11.29.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 11:29:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.194 as permitted sender) client-ip=91.218.175.194;
Date: Tue, 24 Oct 2023 11:29:03 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v2 00/39] Memory allocation profiling
Message-ID: <ZTgM74EapT9mea2l@P9FQF9L96D.corp.robot.car>
References: <20231024134637.3120277-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qxmyiqZd;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.194 as
 permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Oct 24, 2023 at 06:45:57AM -0700, Suren Baghdasaryan wrote:
> Updates since the last version [1]
> - Simplified allocation tagging macros;
> - Runtime enable/disable sysctl switch (/proc/sys/vm/mem_profiling)
> instead of kernel command-line option;
> - CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT to select default enable state;
> - Changed the user-facing API from debugfs to procfs (/proc/allocinfo);
> - Removed context capture support to make patch incremental;
> - Renamed uninstrumented allocation functions to use _noprof suffix;
> - Added __GFP_LAST_BIT to make the code cleaner;
> - Removed lazy per-cpu counters; it turned out the memory savings was
> minimal and not worth the performance impact;

Hello Suren,

> Performance overhead:
> To evaluate performance we implemented an in-kernel test executing
> multiple get_free_page/free_page and kmalloc/kfree calls with allocation
> sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> affinity set to a specific CPU to minimize the noise. Below is performance
> comparison between the baseline kernel, profiling when enabled, profiling
> when disabled and (for comparison purposes) baseline with
> CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:
> 
>                         kmalloc                 pgalloc
> (1 baseline)            12.041s                 49.190s
> (2 default disabled)    14.970s (+24.33%)       49.684s (+1.00%)
> (3 default enabled)     16.859s (+40.01%)       56.287s (+14.43%)
> (4 runtime enabled)     16.983s (+41.04%)       55.760s (+13.36%)
> (5 memcg)               33.831s (+180.96%)      51.433s (+4.56%)

some recent changes [1] to the kmem accounting should have made it quite a bit
faster. Would be great if you can provide new numbers for the comparison.
Maybe with the next revision?

And btw thank you (and Kent): your numbers inspired me to do this kmemcg
performance work. I expect it still to be ~twice more expensive than your
stuff because on the memcg side we handle separately charge and statistics,
but hopefully the difference will be lower.

Thank you!

[1]:
  patches from next tree, so no stable hashes:
    mm: kmem: reimplement get_obj_cgroup_from_current()
    percpu: scoped objcg protection
    mm: kmem: scoped objcg protection
    mm: kmem: make memcg keep a reference to the original objcg
    mm: kmem: add direct objcg pointer to task_struct
    mm: kmem: optimize get_obj_cgroup_from_current()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZTgM74EapT9mea2l%40P9FQF9L96D.corp.robot.car.
