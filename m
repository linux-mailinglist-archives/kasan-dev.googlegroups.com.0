Return-Path: <kasan-dev+bncBD22BAF5REGBBIN3XKXAMGQEPI6UIMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 618FB857191
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:26:27 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1d4212b6871sf1210925ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:26:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708039586; cv=pass;
        d=google.com; s=arc-20160816;
        b=WR39kxBjg10Z5wYmTN2lOz1YrjpvSmCH64Mb/q3rGzposMST07zZ85ETcOFFm2UrEF
         Sd1J+nfxso7P4h7h8MUoVFWhXm/Pynf9QEgHBhCrnU3hnqin3Bw1YzG9BJxNvEw2asFT
         rf+cuFUhWG75ZCzMo2SfW29t0ieFcnP7crk1r404r2d9K3hRrG1ChwSu6hS4znej+/cH
         J7QQS0S6kTRI4LTPfWk/esFjcroNFtTajAy5IlB8aHnRXU34HhOuv9cWAPLPtN6iU5JD
         C+POFdScbdZNruPdv0V/y/bi2Y4sY25kJIfp/phROpa59dMgGgwhol18OVM0MMCooojF
         wKag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=xC8/o3C2AJesErLxLnkVOybL8x+lScJkeTCUHUdIj1g=;
        fh=8/Vt9TJElYNZpFJCkIUY/p+scES0+AQM2zTk1k6VpwU=;
        b=iabDfwa/TIjiCknYEGsAiHYIDJyRXb2pDaWRhHNytYQvWZTEbo19a+P0Nadiyg67CQ
         v4i+GAF1vQCTSpjaN9Y66RV/6dqpztZbezza8+Ox0w0cEXQSLJn23tE+Wpfr/tAnaVR9
         v+KOGfgpduHCqSTiS0FDVQ0iLqewTsqiSmJdv6epIE1Erq4Rvw5vQVBTPpADoFwwow4N
         elFEl4RWfpzXgCvfsLh31UQBdx4JS4pDjrw/uillYWX9Un5F+AbeuIQRmXLz772BHOqc
         NBayu2G3Vs6Uk9I0mLOOBtlQCPuDi39+i05rldO/tDQHrytDpWbqNIUBCTKHdrbpzW3v
         ngxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XLT1Dm21;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708039586; x=1708644386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xC8/o3C2AJesErLxLnkVOybL8x+lScJkeTCUHUdIj1g=;
        b=kqpWpnrjvFL8oJ1MwYaklxBF7m+KnOkxP0ze4Xi+yFed8tj0VcJ/5INhwWf6khyaBR
         +ntb2BXIqWfc2ga/UxwS3/11u1guEoQOchnMqZ0M1sOQWKmtANXvtXpXcz321JpV1vYZ
         VuyFYezvIDp59ofnhjrWWuhH0xWfZBIcNonsbW8ZMX45xM+uHVKgUzFRp7QsuU5AB9cJ
         WtOq1fz3bV4Qul3sX3WsYCBw4XrH0Fc+zjxGy6mF7dqkpjxkEx8fl5y5u7eJ3oFo0xvl
         nvdek6DqVul+N6vqgGvmgc9CLFweQoPMZqWcq2O6O7meueq9J9Jk2Yeec7tpklFt1S4s
         v7lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708039586; x=1708644386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xC8/o3C2AJesErLxLnkVOybL8x+lScJkeTCUHUdIj1g=;
        b=m5A6nFby3SmOqDEiIRTxgqg/4UPBdXpifgnSARYXRr8wBAyLsZdqxU2HC3jsGatMDS
         jBJpb8zu7CsCC/TAlSTxER5NxKCxbBrWecJpQEgiFgMNZxMpf7Gu68Jtb0bMIlSZl/O3
         v2CuLOjDhBiAUF1LlrPVGGgMqK7WHBiQHRy+IiPO12iOHGv6MlYRf2PhB9s+DBfkwJxg
         OExeSjzz2zrx2Vor7YEMNi3xOgY99j/WyZ4QxZN/YhJ8YXNVyCchh1D6uftQ4qZCc3yO
         NxPtoqagzNRNlEuAk+O+swF5cEhD80x31gSUHC4z0g6h3kx5T1X6mhhsi/auKzbpEDsP
         CxaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIVWoOw4ATl2u93U3c45ycgSmuf9dvrmjn4PYb8eUTBeCz+p+8ZRFLQ8yMRMQRc3ZKKakhkZYbqHXNk1L3JniIJszfsp0DtA==
X-Gm-Message-State: AOJu0YwgYA0jupbeqrKf8wyS8Z/18i8KdfoOXscx+gyRk9Dd1fiQYNOu
	CBmugJDObG6RKypC9GqS2JSECNA1TWBYTJi90Z2EicFTwYU9pgbi
X-Google-Smtp-Source: AGHT+IGrVy7qvbApW+sFSSwQ4A54OwaZoJr8C1woL0kvECTXkf5SK78iu3CwxWeeOY7/Zf4+9lLp/w==
X-Received: by 2002:a17:90b:80e:b0:299:d9c:1ea1 with SMTP id bk14-20020a17090b080e00b002990d9c1ea1mr3143042pjb.0.1708039585853;
        Thu, 15 Feb 2024 15:26:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d12:b0:298:d44d:198f with SMTP id
 pt18-20020a17090b3d1200b00298d44d198fls223451pjb.0.-pod-prod-03-us; Thu, 15
 Feb 2024 15:26:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVkoW0NfJ+fa4HU/hSIQEL8RBHYw2JHcQ8jKQURq7H3g8oDbk1Yg0RIuIlhhB362bTIdLE+Al/SURTfwytbplPAsHI2e1h5m+ze8A==
X-Received: by 2002:a17:90a:e296:b0:298:c3bb:7743 with SMTP id d22-20020a17090ae29600b00298c3bb7743mr3180620pjz.37.1708039584337;
        Thu, 15 Feb 2024 15:26:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708039584; cv=none;
        d=google.com; s=arc-20160816;
        b=uUuLfm7F/Gat8Mk/LBLEfa/KcoOmttqNAHiMefHSl0DyN2b5BH0TNe970LAxNtONCK
         lBj3eSIkwtj0l+rvegI7HlLOTV4czOKn4LPezQuWfrpMlzy6Iu5ilahkdyReFqWzJzAq
         h9FuyVqZ9eMvyTdR6jDJUJmsOn2sls8DPIqfrCM3q3p9ssuKLbh9XzKCu4GEpTivRhHA
         Ckg0Pz6BmWdzrxDzMpPUhusdw7zJpLRlQ2GTbjylnRxMamQ1TlbHDifaYMudGB+EOump
         yZRkl4u7YpLn9BqxUkYoI9p2UNSpBkzcSVTFSJ41HnEo3NSkywJMZ9LCNHZThmXfMwia
         U5RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=besEAXBQIdD5PzM18byzU0r45Vk4lStMjadbe1Ig10k=;
        fh=nAipLXvvbeRNu6mE1Pvn0HwnSqPwUYcbNN7JRHG2Kos=;
        b=hp4RwGylyCOL39CUQ7mopewHakS3RL+3qkhb2Nvr32DLr8w9Hx7yuytD19vuzgpmKB
         2+0l30DttAOlykULS4UACM702i24zRsXt8ZlzcvnOU3fpvtgtTCxX+HPQi529Yg0Vr36
         CgnU9mmkmSc//V0b+CTSeHOAftg/nc5IRa/kYhpoR3cK7VGmGxDBPXhrXIW4MMOZB4tV
         eyIQ/IkMVJXr0xm0iV3qPatrM41bko26seeiJpjsn4fifSDC2j5JE/EumQsCNrkQ9eKg
         y0aU6o9XuDSLStFxm3F3rBDEmJnDVgxayOmSLBUyJsHCM3df3bGmAgiY9P51TIXAoP4D
         j4vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XLT1Dm21;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id a23-20020a17090a8c1700b0029908fe424asi135928pjo.2.2024.02.15.15.26.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Feb 2024 15:26:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-IronPort-AV: E=McAfee;i="6600,9927,10985"; a="5127846"
X-IronPort-AV: E=Sophos;i="6.06,162,1705392000"; 
   d="scan'208";a="5127846"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Feb 2024 15:19:35 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,162,1705392000"; 
   d="scan'208";a="4077327"
Received: from jmjohns4-mobl1.amr.corp.intel.com (HELO [10.209.57.138]) ([10.209.57.138])
  by orviesa008-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Feb 2024 15:19:33 -0800
Message-ID: <38e34171-e116-46ee-8e2b-de7cc96d265e@intel.com>
Date: Thu, 15 Feb 2024 15:19:33 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Content-Language: en-US
To: Steven Rostedt <rostedt@goodmis.org>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>,
 Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
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
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com> <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20240215180742.34470209@gandalf.local.home>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=XLT1Dm21;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 2/15/24 15:07, Steven Rostedt wrote:
> Just adding the patches increases the size by 5k. But the rest shows an
> increase of 259k, and you are worried about 4k (and possibly less?)???

Doesn't the new page_ext thingy add a pointer per 'struct page', or
~0.2% of RAM, or ~32MB on a 16GB laptop?  I, too, am confused why 4k is
even remotely an issue.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38e34171-e116-46ee-8e2b-de7cc96d265e%40intel.com.
