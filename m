Return-Path: <kasan-dev+bncBCKPFB7SXUERB4WWSTDAMGQEJMZ4IXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8958BB55F8A
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 10:29:40 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b5f6eeb20esf100924301cf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 01:29:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757752179; cv=pass;
        d=google.com; s=arc-20240605;
        b=az2Z8EmQba/bVfa5dCM67kKrjTvaeCJ6URq1VUOsgEZM4Zj9eecGyfhSwxD3JoXVcX
         hOZkzzk7yE3BcbIgFXGyd2I9FnSKXrRIEEV67ozVy0Di7s47QZzf2pLVu/YN/1HAU0uf
         MAtnS8vrkZ9ilrbMlkIIzf/ZBS8wsa0g2lHfwydn4qgU69CGtjgVCMgNcebFkoOZTEhY
         HJIwI1kZbnueF7UzCNb0c64tWkHNEbMzKxlBZXy3Jtj0KBkuC7fbbBos0rVLflhwaw5B
         8cquVmqwNGEidkl3uiJMPQqRwZXtH5SU38rzar5yFasB8/ybc/Lg83CwhnIUc2vQUFZJ
         cJlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=oow2AzHTV4PQOnJK1Y4w/W75Yl4khaxa90EnEnL/JJs=;
        fh=T8q9gl9T8M2k11qSWTJxmiVv1pl2g5hPew5NOjEuDJE=;
        b=ClHAEFKaGmMAoWpc+VszUO/0X8NPkt75qC1O66mvuViN2QlP8arLoWp321cNB2tV4S
         BPr/YHdQw6bUhMRPeXlTxtEHIZAEyDYp1VI4Oso3Idw/gqmC5HU6Nn3TSBJpB+3N6dSo
         0ItlqvVBlHmKbaDpz5jliSrKwWSXq5fxIo0TSh/WK/pGSc5ffamJgEgzKZQZpT8RewZr
         oQphmyZ9qPgii7RWxQYzCfLUoHpo6xsnbT6Jtdnu8cSETR69bfaKEVkacv90OlEWh65/
         +C9aZVw2EunVeOT0shLUqpLk7z2N6TDSfClNa2LL6PAvK3O9fNweuKqmqQ9Z4J1BxiqT
         Kq0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NIhFoz3V;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757752179; x=1758356979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oow2AzHTV4PQOnJK1Y4w/W75Yl4khaxa90EnEnL/JJs=;
        b=v99Nm0NcJii1QaJaMiWKeTi7cFxoSJuI2VQlm+VQkR42PLq9E0K2W4Yghr6MXKTWV1
         M6QosZShfQmkOM+PVcBZEobV8Rro9R68tmt4Pe5EuaiSYgTLqgPU/C0UGx1Kj9hwlnmF
         DiRPtPfHNwRHqHRxo274Ph2z4QNDDz3bOSm8DL30L9K4prPt9DJk+3fkdEs8WC7UggtB
         YmbjpQNHOvTiYYxcbD0QfqBNjeYWy0FsQ2Zd9c0XOYHy+MOa7ilb5wFRxziXEXAMPLO1
         pSfiP1JKoztMxenIUjsUP8hCr9NhnGZJn2atjWcTnp2wFxfrGWNBrpBQp6WJymcCPq+h
         wcEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757752179; x=1758356979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oow2AzHTV4PQOnJK1Y4w/W75Yl4khaxa90EnEnL/JJs=;
        b=XvdIQ+oIEmA4N72KIADGFd3mLDY1gqm8wKInyJcAQ4krVZiv3hoHm6hYgudkdQ27lO
         QgVAyoxVJhBoI9s4qE6yPlCjdscA6PkgZbyaLwlWAnYnkM9t/EabbzysqgVmQfY1V/rA
         qUP0q9IPi1JO9smaEW+FfRK1yKQgrEq8BUUw5deBJW7UY1xpmJUExcHL2BdT+u080kUj
         RA/AJRQ+cETf5TD3L/WSM3qGaGr9GVCGvPDL3jYMmB+z03MZxPQI46jvxngkiEOEvpd7
         hx15mmq2X/wtbEO7dUSUAtY93hJO9xUEpISPsFbFYCug75O9U/J5BGDkzWIPZVBPlhys
         fwYA==
X-Forwarded-Encrypted: i=2; AJvYcCW07k+Q1HPTP0/5D2ypDhKyEIxduwKMjuBcuQz8N3lpHTW+5Jn9ftmff1UBnc2JdyFqyXTlPA==@lfdr.de
X-Gm-Message-State: AOJu0Yz6Jw8eLdFgviRGarFXlq87Tj16JFI9D+u16i6GQpO3yKNeZFob
	Ck41osJWHMIm+PJYVZr4o2pTtVPOo1OQIQIUg88UzEMnMo7P8+y7g83k
X-Google-Smtp-Source: AGHT+IFyhWTDascRNIzhPB8p0gXnMc+tWRhDKwwV3dJURdO88foNVdD7Y5TChXy/oxtOGN21NfLwVw==
X-Received: by 2002:a05:622a:14ce:b0:4b6:2377:1403 with SMTP id d75a77b69052e-4b77d03edb5mr72840651cf.41.1757752179187;
        Sat, 13 Sep 2025 01:29:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeq7yZlNF6JcvUVtBs2iADoz2MoumBk4DI+VZ5luFO+pg==
Received: by 2002:ac8:5949:0:b0:4af:19fb:76cc with SMTP id d75a77b69052e-4b636cad4f4ls52833541cf.1.-pod-prod-04-us;
 Sat, 13 Sep 2025 01:29:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVA4cE0ip1lq8nUtavB6y0Hv9ph7FYcxeWIaptNnAYR92ZeiDddRIJpIRNj9a1715rwew8r+o0yoJg=@googlegroups.com
X-Received: by 2002:a05:620a:2994:b0:826:f242:e515 with SMTP id af79cd13be357-826f242fb94mr147981085a.9.1757752178136;
        Sat, 13 Sep 2025 01:29:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757752178; cv=none;
        d=google.com; s=arc-20240605;
        b=BG6Gu6rb/doghLuVr4cyEW/JdNNnjPrdCip1nSP3RXgMwGTi0cupE9h1n5aurlxUpd
         GhwY5lTa4gTn5BkqvgPSVWO4IpoEg8ngU2toP6SVlZhn4ZYobYYs28qrxFLin6rPoxJD
         lAEpVJ0f6nmGkCZ6w0C89tBP3b+fGH9le7OyFseQgqYKvpVED88jP0AkYo7HwYh+3Uxo
         HScTFIfQKn6j74s5UdlEYP+04fjyEMvGHekRSuJG71Jr3H7GtCekhMdq3kr9ngy6UTFl
         5v8+tsvVT+zP4grEnbGVFykb1ijHOHrdqAv1ke2qB1TIXt6RQc3YYg+5egOiKcbCNLul
         n2BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PIeQDW6Tdi47ZNT16hYEbfLPFjdOb5UbtK5p18GEOMw=;
        fh=n05jP89k9isIfe4PcjpqcVIOyCdM7MhN2egDEws8aIY=;
        b=bqfUKNuguak2O815Oph0ghg9054qc3c1//q2WDugGrucEr2jkq8RHcW4U1Zf+A19o3
         ouURfmMfDaqeEGGjQ/LDlzjNlXWYyUYuDFcUr1DuUvfeQzYStq33njFtCZdosvjXMabE
         aTfq5ldbzldOSvvXDOK7I42Y+Ohn35CIqkCUa8+d86j4K61bj3JavE9kjmKcANSn/4AJ
         tgLI8vd6rQbXh5zhW9bm41AhNbIR5owk4tvSL+c7O1Uk0OBfRtZd07ZsAHBIIOw39EEv
         LnnVnEECsQ83drfwg3U+CXRAua01ycDmVvrnRf7QoHhP8Ew0u7oa3AKiVbZQrbCFQEkw
         I/Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NIhFoz3V;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820cd32a499si22177185a.5.2025.09.13.01.29.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 13 Sep 2025 01:29:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-212-Ke3lSLs4P8SczzOZFgRwfw-1; Sat,
 13 Sep 2025 04:29:34 -0400
X-MC-Unique: Ke3lSLs4P8SczzOZFgRwfw-1
X-Mimecast-MFC-AGG-ID: Ke3lSLs4P8SczzOZFgRwfw_1757752165
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 965251953943;
	Sat, 13 Sep 2025 08:29:24 +0000 (UTC)
Received: from localhost (unknown [10.72.112.45])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E99FA1954126;
	Sat, 13 Sep 2025 08:29:19 +0000 (UTC)
Date: Sat, 13 Sep 2025 16:29:15 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	andreyknvl@gmail.com
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	catalin.marinas@arm.com, alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com, dave.hansen@linux.intel.com,
	corbet@lwn.net, xin@zytor.com, dvyukov@google.com,
	tglx@linutronix.de, scott@os.amperecomputing.com,
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
	mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com,
	leitao@debian.org, peterz@infradead.org, wangkefeng.wang@huawei.com,
	surenb@google.com, ziy@nvidia.com, smostafa@google.com,
	ryabinin.a.a@gmail.com, ubizjak@gmail.com, jbohac@suse.cz,
	broonie@kernel.org, akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com, rppt@kernel.org, pcc@google.com,
	jan.kiszka@siemens.com, nicolas.schier@linux.dev, will@kernel.org,
	andreyknvl@gmail.com, jhubbard@nvidia.com, bp@alien8.de,
	x86@kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 17/19] mm: Unpoison pcpu chunks with base address tag
Message-ID: <aMUrW1Znp1GEj7St@MiWiFi-R3L-srv>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <bcf18f220ef3b40e02f489fdb90fc7a5a153a383.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
In-Reply-To: <bcf18f220ef3b40e02f489fdb90fc7a5a153a383.1756151769.git.maciej.wieczor-retman@intel.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Wk0uP_qNZ87uZxr2Bd1hq3OFn9bu207PFp764K6LaLg_1757752165
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NIhFoz3V;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Hi ,

On 08/25/25 at 10:24pm, Maciej Wieczor-Retman wrote:
> The problem presented here is related to NUMA systems and tag-based
> KASAN mode. It can be explained in the following points:
> 
> 	1. There can be more than one virtual memory chunk.
> 	2. Chunk's base address has a tag.
> 	3. The base address points at the first chunk and thus inherits
> 	   the tag of the first chunk.
> 	4. The subsequent chunks will be accessed with the tag from the
> 	   first chunk.
> 	5. Thus, the subsequent chunks need to have their tag set to
> 	   match that of the first chunk.
> 
> Refactor code by moving it into a helper in preparation for the actual
> fix.

I got a boot breakage on a hpe-apollo arm64 system with sw_tags mode, and
the boot breakage can be met stably. The detailed situation is reported
in below link:

System is broken in KASAN sw_tags mode during bootup
https://lore.kernel.org/all/aKMLgHdTOEf9B92E@MiWiFi-R3L-srv/T/#u

After applying this patch 17 and patch 18 in this series, I can confirm
the breakage is gone. Thanks for the great fix, and please feel free to
add:

Tested-by: Baoquan He <bhe@redhat.com>

========================
CONFIG_KASAN=y
CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=y
# CONFIG_KASAN_GENERIC is not set
CONFIG_KASAN_SW_TAGS=y
# CONFIG_KASAN_HW_TAGS is not set
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y
CONFIG_KASAN_KUNIT_TEST=m
================================

[  100.907469] ==================================================================
[  100.907485] BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8
[  100.907509] Write of size 160 at addr 10fffd7fbdc00000 by task systemd/1
[  100.907524] Pointer tag: [10], memory tag: [5b]
[  100.907532]
[  100.907544] CPU: 229 UID: 0 PID: 1 Comm: systemd Not tainted 6.16.0+ #2 PREEMPT(voluntary)
[  100.907562] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[  100.907571] Call trace:
[  100.907578]  show_stack+0x30/0x98 (C)
[  100.907597]  dump_stack_lvl+0x7c/0xa0
[  100.907614]  print_address_description.isra.0+0x90/0x2b8
[  100.907635]  print_report+0x120/0x208
[  100.907651]  kasan_report+0xc8/0x110
[  100.907669]  kasan_check_range+0x80/0xa0
[  100.907685]  __asan_memset+0x30/0x68
[  100.907700]  pcpu_alloc_noprof+0x42c/0x9a8
[  100.907716]  css_rstat_init+0x1bc/0x220
[  100.907734]  cgroup_create+0x188/0x540
[  100.907749]  cgroup_mkdir+0xb4/0x330
[  100.907765]  kernfs_iop_mkdir+0xb0/0x120
[  100.907783]  vfs_mkdir+0x250/0x380
[  100.907800]  do_mkdirat+0x254/0x298
[  100.907815]  __arm64_sys_mkdirat+0x80/0xc0
[  100.907831]  invoke_syscall.constprop.0+0x88/0x148
[  100.907848]  el0_svc_common.constprop.0+0x78/0x148
[  100.907863]  do_el0_svc+0x38/0x50
[  100.907877]  el0_svc+0x3c/0x160
[  100.907895]  el0t_64_sync_handler+0x10c/0x138
[  100.907911]  el0t_64_sync+0x1b0/0x1b8
[  100.907925]
[  100.907931] The buggy address belongs to a 0-page vmalloc region starting at 0x5bfffd7fbdc00000 allocated at pcpu_get_vm_areas+0x0/0x1da8
[  100.907963] The buggy address belongs to the physical page:
[  100.907970] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x8811a35
[  100.907984] flags: 0xa6a00000000000(node=1|zone=2|kasantag=0x6a)
[  100.908006] raw: 00a6a00000000000 0000000000000000 dead000000000122 0000000000000000
[  100.908019] raw: 0000000000000000 b4ff00878bce6400 00000001ffffffff 0000000000000000
[  100.908029] raw: 00000000000fffff 0000000000000000
[  100.908037] page dumped because: kasan: bad access detected
[  100.908044]
[  100.908048] Memory state around the buggy address:
[  100.908059] Unable to handle kernel paging request at virtual address ffff7fd7fbdbffe0
[  100.908068] KASAN: probably wild-memory-access in range [0xfffffd7fbdbffe00-0xfffffd7fbdbffe0f]
[  100.908078] Mem abort info:
[  100.908083]   ESR = 0x0000000096000007
[  100.908089]   EC = 0x25: DABT (current EL), IL = 32 bits
[  100.908098]   SET = 0, FnV = 0
[  100.908105]   EA = 0, S1PTW = 0
[  100.908111]   FSC = 0x07: level 3 translation fault
[  100.908118] Data abort info:
[  100.908123]   ISV = 0, ISS = 0x00000007, ISS2 = 0x00000000
[  100.908130]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
[  100.908138]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[  100.908147] swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000008ff8b76000
[  100.908156] [ffff7fd7fbdbffe0] pgd=1000008ff0299403, p4d=1000008ff0299403, pud=1000008ff0298403, pmd=1000008811a17403, pte=0000000000000000
[  100.908192] Internal error: Oops: 0000000096000007 [#1]  SMP
[  101.185060] Modules linked in: i2c_dev
[  101.188820] CPU: 229 UID: 0 PID: 1 Comm: systemd Not tainted 6.16.0+ #2 PREEMPT(voluntary)
[  101.197175] Hardware name: HPE Apollo 70             /C01_APACHE_MB         , BIOS L50_5.13_1.16 07/29/2020
[  101.206912] pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[  101.213877] pc : __pi_memcpy_generic+0x24/0x230
[  101.218418] lr : kasan_metadata_fetch_row+0x20/0x30
[  101.223299] sp : ffff8000859b7700
[  101.226610] x29: ffff8000859b7700 x28: 0000000000000100 x27: ffff008ec6291800
[  101.233758] x26: 00000000000000a0 x25: 0000000000000000 x24: fffffd7fbdbfff00
[  101.240904] x23: ffff8000826b1e58 x22: fffffd7fbdc00000 x21: 00000000fffffffe
[  101.248051] x20: ffff800082669d18 x19: fffffd7fbdbffe00 x18: 0000000000000000
[  101.255196] x17: 3030303030303030 x16: 2066666666666666 x15: 6631303030303030
[  101.262342] x14: 0000000000000001 x13: 0000000000000001 x12: 0000000000000001
[  101.269487] x11: 687420646e756f72 x10: 0000000000000020 x9 : 0000000000000000
[  101.276633] x8 : ffff78000859b76a x7 : 0000000000000000 x6 : 000000000000003a
[  101.283778] x5 : ffff8000859b7768 x4 : ffff7fd7fbdbfff0 x3 : efff800000000000
[  101.290924] x2 : 0000000000000010 x1 : ffff7fd7fbdbffe0 x0 : ffff8000859b7758
[  101.298070] Call trace:
[  101.300512]  __pi_memcpy_generic+0x24/0x230 (P)
[  101.305051]  print_report+0x180/0x208
[  101.308719]  kasan_report+0xc8/0x110
[  101.312299]  kasan_check_range+0x80/0xa0
[  101.316227]  __asan_memset+0x30/0x68
[  101.319807]  pcpu_alloc_noprof+0x42c/0x9a8
[  101.323908]  css_rstat_init+0x1bc/0x220
[  101.327749]  cgroup_create+0x188/0x540
[  101.331502]  cgroup_mkdir+0xb4/0x330
[  101.335082]  kernfs_iop_mkdir+0xb0/0x120
[  101.339011]  vfs_mkdir+0x250/0x380
[  101.342416]  do_mkdirat+0x254/0x298
[  101.345908]  __arm64_sys_mkdirat+0x80/0xc0
[  101.350008]  invoke_syscall.constprop.0+0x88/0x148
[  101.354803]  el0_svc_common.constprop.0+0x78/0x148
[  101.359598]  do_el0_svc+0x38/0x50
[  101.362916]  el0_svc+0x3c/0x160
[  101.366061]  el0t_64_sync_handler+0x10c/0x138
[  101.370423]  el0t_64_sync+0x1b0/0x1b8
[  101.374095] Code: f100805f 540003c8 f100405f 540000c3 (a9401c26)
[  101.380187] ---[ end trace 0000000000000000 ]---
[  101.384802] note: systemd[1] ex
** replaying previous printk message **


> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Redo the patch message numbered list.
> - Do the refactoring in this patch and move additions to the next new
>   one.
> 
> Changelog v3:
> - Remove last version of this patch that just resets the tag on
>   base_addr and add this patch that unpoisons all areas with the same
>   tag instead.
> 
>  include/linux/kasan.h | 10 ++++++++++
>  mm/kasan/hw_tags.c    | 11 +++++++++++
>  mm/kasan/shadow.c     | 10 ++++++++++
>  mm/vmalloc.c          |  4 +---
>  4 files changed, 32 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 7a2527794549..3ec432d7df9a 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -613,6 +613,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
>  		__kasan_poison_vmalloc(start, size);
>  }
>  
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
> +static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +	if (kasan_enabled())
> +		__kasan_unpoison_vmap_areas(vms, nr_vms);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>  
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -637,6 +644,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
>  static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
>  { }
>  
> +static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{ }
> +
>  #endif /* CONFIG_KASAN_VMALLOC */
>  
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..1f569df313c3 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -382,6 +382,17 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>  	 */
>  }
>  
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +	int area;
> +
> +	for (area = 0 ; area < nr_vms ; area++) {
> +		vms[area]->addr = __kasan_unpoison_vmalloc(
> +			vms[area]->addr, vms[area]->size,
> +			KASAN_VMALLOC_PROT_NORMAL);
> +	}
> +}
> +
>  #endif
>  
>  void kasan_enable_hw_tags(void)
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d2c70cd2afb1..b41f74d68916 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -646,6 +646,16 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>  	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>  
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +	int area;
> +
> +	for (area = 0 ; area < nr_vms ; area++) {
> +		kasan_poison(vms[area]->addr, vms[area]->size,
> +			     arch_kasan_get_tag(vms[area]->addr), false);
> +	}
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>  
>  int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index c93893fb8dd4..00be0abcaf60 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4847,9 +4847,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	 * With hardware tag-based KASAN, marking is skipped for
>  	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>  	 */
> -	for (area = 0; area < nr_vms; area++)
> -		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
> -				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
> +	kasan_unpoison_vmap_areas(vms, nr_vms);
>  
>  	kfree(vas);
>  	return vms;
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMUrW1Znp1GEj7St%40MiWiFi-R3L-srv.
