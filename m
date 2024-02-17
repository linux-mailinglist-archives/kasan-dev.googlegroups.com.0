Return-Path: <kasan-dev+bncBCS2NBWRUIFBBT5FYSXAMGQEUF53QNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F09985924D
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 21:10:57 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2d23143f4a1sf2187591fa.1
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 12:10:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708200656; cv=pass;
        d=google.com; s=arc-20160816;
        b=efzIWGFjdQrz69EFWJD7HPSL4ucMcrOMihKubogUYeHXP72ltknSLMGXqP6dNpert6
         m+K4zLyRmJ6m5vrdM/NuomBlrmDgxVu2n0p8KB/h/MYLVVsQkMmsCEpMC34HrmQNByN+
         hvNrnvTt4cN+UHUaqR838OYAUfyeM26s1qEW+tIxFEy1Jc4UhdSgiLb4+gsDmEIM0kHb
         PzbrhOuN6lyDC5Bov4FGgu61f+sHJcjv2qfGMSPrHXZK9eNhI0r5W4PBosIcqZrPcoyr
         o0Mdt7q7H3UJ2q40dIl4jmeb6Mz7ti4/ZdxeinkbkGN1WVWX0qqYEIgdaUsxI5ywf0OY
         Hktw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S8uc+qzxkM/zHWvyZi/w3TxtwVLLU8YiTy2PPef2h2w=;
        fh=6LK5wB+kCl5vevMVjyBFM8WeEDGBdPWCtuwh6hNuR4w=;
        b=wjzTw9hmfK7D5HcczEZCA6DfIcScrDYmwPJT7+CjA6nf4rDqfz8MA4OIzv+ncoqDa+
         x7rRmhyQYSTBXAb0+Jt1HqFhEPr36t5NeCb2j56bez+OB0TiQd5IlYf9al7RWEbHxMs9
         SgBoliK06qLLHDk1VCbgB2GcTQcBv2VAPWskMziCtAxmcL+eezAr58k6rjCM/7jMwFfy
         D4e1TJwUwAwq+zdAoP0tjdcSE77aUOYoe6jO8fxuY7f8CNq/osSSH9eNy5op/F5qHsEA
         WEEpMUC+2lV0sr9VePf7in3PfaQWybZ9QzozZj8ji5SLCiNJvDwMmVv7BBfejcvo5x2a
         8uJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gGO7GNDq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708200656; x=1708805456; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S8uc+qzxkM/zHWvyZi/w3TxtwVLLU8YiTy2PPef2h2w=;
        b=vLkK4Jw5P+bqge+jdOAn9BORBSBQUPmTb4Cjb/BZbIJuVxmtqlJ1HohxMd7F7U/5w2
         6jq36gIVP/H9LbW+zM/aEXOsLLc5CUPBogBZLrn7ujkfnhMYbXou3AslgGahV6tDXbWl
         mv3uQXIhfdINzSzswF4SFiPnPnN+W4F5P64Yd/we7lnodf3r3744sGPxtw0jv9TtzSmV
         UikWeCxa3hlE3HRmLou2Ea2w3eSs6mkmCEiCAadrgytkUpBYfo/1CJm1yHTZ6ELfg1oL
         K5eyFQ1eyhM1ryDAscNtYK5KufpZZbe4uMFpinXdw6A2F0veXVbWfGBzFHNuGs7rpsKT
         s+SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708200656; x=1708805456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S8uc+qzxkM/zHWvyZi/w3TxtwVLLU8YiTy2PPef2h2w=;
        b=fl4rFaZdmwds6W2yK9OOBEvemPk7v5tV/NYFw7Zz7j+blnupyKMBcxLf0VKzhBwdMZ
         yuGg8LY0NOfVSWdc8H8I7UmXkdtCF+8GHNIstlg/vvon44JfKw4v3iDq/zW0uBcWoWeG
         Cr0C2sbwh1VE+eDMX+lumOJjq79lGwJyTFNx0Z1BZgbGsqISzJifkLLCGWgXhv/Z78Cu
         ECXnOR8XKZY+QpnJ/oRil+ry3PhZc/Xe2fkyLXqvFjJT+D+n6xuwdKqiBVgMeaM0U4qC
         9GK+ebicxzNTb7vVFgtRsWQsDiuI8Z4dhTWIvX0MXihcQ9XyNQ0xSpcloupdzA8ZpK5h
         Vwcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXi0M2vad2JUJgg6D8MW/CrYQownRKXmPj1l2MbSdimCrgKC0vCparFP5VEyn3NAC6tCTZ0MQq5i35G3MWb6QBksg4cKjjrmw==
X-Gm-Message-State: AOJu0YxI3WFKnzo8U31Tm4lCRY0HEHnfoLyGrifVhQFf3QMCdlTn/zkM
	jSfUQIz3JS/bezQWVGlBhq4oONMIXU9zbTfmjkM9835rbHEqpLB5
X-Google-Smtp-Source: AGHT+IENExbhsN3B+NYuj7bU6n7JfymAYq7TaqAeeO7HkCrJsGts/kHbmajA1mwycge10pdTqbQhew==
X-Received: by 2002:a2e:b748:0:b0:2d0:c3f8:d3b7 with SMTP id k8-20020a2eb748000000b002d0c3f8d3b7mr4726735ljo.8.1708200656119;
        Sat, 17 Feb 2024 12:10:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a495:0:b0:2d0:a7cd:36ff with SMTP id h21-20020a2ea495000000b002d0a7cd36ffls741450lji.2.-pod-prod-06-eu;
 Sat, 17 Feb 2024 12:10:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWpjoLlAt00WOafbqBPuV+b+U79ddujq1Rzj+oFkhzRYUVmtFpT6oNeWSZ1R+iBnduEpy1IBLjO2sxzji9YkCg28WnRW5Eqdg33kQ==
X-Received: by 2002:a2e:9806:0:b0:2d2:2ff0:9b8a with SMTP id a6-20020a2e9806000000b002d22ff09b8amr838000ljj.15.1708200654161;
        Sat, 17 Feb 2024 12:10:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708200654; cv=none;
        d=google.com; s=arc-20160816;
        b=lbjTj2619azQA9akUOrmSs4zGIZieLuEArd37+igb+PWzVWaSKxz2i3j088aU5h2c0
         6XQHY6spupMU88EBaXCOzntrEnNGGCPc1L2TbHSFNYCNUY4MKUferoI0Vo/TsTdpmFBF
         PWygmjL0o4vjsCRvxLrKuYUAGOU2BAiY8BU+TMzg8vTYQjAJ2hGYDSFuKz1ZBnQiQm6r
         /w+OjD8G5xAmdCeRaO4ED4xuLm4/VBizkXtmsBCeyuuqI3moi8mBjpmWQrpAPbOUo47v
         7+Y8aRcsbDkwIVmJMjbol8ZzjoS2xj4eyAEoENAzX5XOID5UQ1f6U1+nBgvFj6xQxLF/
         PP0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=widJLyBLNbG/fhM0WxQtdV2j/zClvMMmMBAQpE7WaPU=;
        fh=FR3RXmyA9ofBvidLh9oUCOIYkJ4Sq2+r/JW45qKHLng=;
        b=rYkskouxWZNKaFUAmevhiq6LQEC/uFGjnryjIOCUlXzOLkOcKdo5+mALPK3UG3WiLV
         4Fqg61nAr+3CH6ZgIm6NUampF4vhJj+qLzNVGbXTpn1e1/3B89V2dbSmSOYHIwjxrA6b
         iAfKvCAEkgECN+WHmfrgLqXdht/2wdK9p0YHEdQNnMaRP0gbKOUNluEN8OukXFh1N8kW
         XxEToC2T1VmIE+4KNrLmB6L7Hi7Nc7RJHJU/O5L8AEQ0xj9GKc+2PNSYdEe4+hxEdyeq
         R6UN7W4vXNjJq2RbwMtWaS9sVnKaQrdkTfJfBJ7BbpfU3Wfn/aSLDLye+9NApeb+YNvl
         52/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gGO7GNDq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta1.migadu.com (out-180.mta1.migadu.com. [2001:41d0:203:375::b4])
        by gmr-mx.google.com with ESMTPS id g8-20020a2eb0c8000000b002d0f87fb1c4si90700ljl.1.2024.02.17.12.10.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 17 Feb 2024 12:10:53 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) client-ip=2001:41d0:203:375::b4;
Date: Sat, 17 Feb 2024 15:10:42 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <fejelroz2s7fnjakqp4fuqhukqf7uwjofu36hdyz33nhg2gnjr@hji5t6wlgznh>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
 <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
 <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
 <iqynyf7tiei5xgpxiifzsnj4z6gpazujrisdsrjagt2c6agdfd@th3rlagul4nn>
 <CAJuCfpHxaCQ_sy0u88EcdkgsV-GX3AbhCaiaRW-DWYFvZK1=Ew@mail.gmail.com>
 <CA+CK2bCsW34RQtKhrp=1=3opMcfB=NSsLTnpwSejkULvo7CbTw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+CK2bCsW34RQtKhrp=1=3opMcfB=NSsLTnpwSejkULvo7CbTw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gGO7GNDq;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Feb 16, 2024 at 12:18:09PM -0500, Pasha Tatashin wrote:
> > > Personally, I hate trying to count long strings digits by eyeball...
> >
> > Maybe something like this work for everyone then?:
> >
> > 160432128 (153MiB)     mm/slub.c:1826 module:slub func:alloc_slab_page
> 
> That would be even harder to parse.
> 
> This one liner should converts bytes to human readable size:
> sort -rn /proc/allocinfo | numfmt --to=iec

I like this, it doesn't print out that godawful kibibytes crap

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fejelroz2s7fnjakqp4fuqhukqf7uwjofu36hdyz33nhg2gnjr%40hji5t6wlgznh.
