Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBNHXT2GQMGQERB3RWQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 983E04654EB
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:15:17 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f15-20020a056512228f00b004037c0ab223sf9935787lfu.16
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:15:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638382517; cv=pass;
        d=google.com; s=arc-20160816;
        b=qK4st6KDkRnaxJETwIa6+AQ3geZ5GC8gLphfqpkXX3CyFQVkeg184cEFuy0n4Z7tUI
         I9N9nRmDeuzM6XNFcPvLIV7oB7Wh4ZACDyxwZhHSgSJcD3m1pcQ1yVs/8kK88LdzxJNs
         frdRESGzeVk2b8asp9Ox0C82ylMYBJnZPDPVcuxwCCPkTS0SDYX18PkS7UVM1XKPh+me
         7lX32+iM9aw5lrF04aFr36PePC3KIoFr44+Jps1N+kIaJcQ+/fJX7rDt2DsgEWdYjbEk
         L2Qyv11FzqCkTn7lJb5+EufqSQfo+Mr28bE69Y0kVSTNaLPpCKG/Nu29YkYvvpW8ZWw7
         yFSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Hu5IHrcVpWpUSAH2ps/ervF2DNRkeVLQpI9Wutwa+Wg=;
        b=vXMX9obdlowE4A95NygMnxBJGqXthN8oC5VS/1Vcuc060yaJTBj51Dmntdf9jjyJqk
         EMLVudvd5v+4N5id+TpUwk+K+tlsvtACZGU/mLWQ2rE8Nc/No9ZhfIu/UxwiaRQ7Y3Mt
         eurXeZ7XO/Ib8A191BRkAzJukc90hevXDk8KxFJYQ2qx9Ck44k8nnAeTNkFq8Vo2pjiv
         ehmm1i834PNRkg/TEDD/kWUyuvKK/njF+WWhh0JSRRM4q6qvLXrsGLbzgv/ujQXUL9Jy
         dnenH54WMOEWhAQ/ymQNpfP7MueC98ksxUlpxLmA3KCKkrlhCpN35H9HYue2SozlQEcI
         VywQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="UaIAD/rh";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hu5IHrcVpWpUSAH2ps/ervF2DNRkeVLQpI9Wutwa+Wg=;
        b=SEw/0k9Bx0rdn2NuhJg8kdV4yKlLYXJwjfceYcdEw/GHPTc0H4Cqctr5SJsgTOViwz
         nvd4uSr63WEmULp2679qQciu0ySO2oFujwcb6rw6ch1KgYQyXBz/WuYt5FctfX1nfrRW
         pRn+T6Hx2QFkyZP76Fc1jPGIv/IA8Y26NaNYfPxITr4ogaqsk/0LppffNbSITMJUkNqw
         THq2ulYc1q3tb+fxtNxkh4jAw/5EXdN7wEdllawjKCdcojR0woz7Cg0DQv5Lu1i2tM4c
         LQwNgESNWyVKm0tgWHzi+C5l1SK1td6YxkAfPMBejhcxQ7qIuZJBq6a3aoeEtTBRm+hi
         VReg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hu5IHrcVpWpUSAH2ps/ervF2DNRkeVLQpI9Wutwa+Wg=;
        b=ibNznCnG+j97DEkB8nO6yisjdmCJ9b+85tmu+lx+/vGazbw3ljdxgwoTXp7bGWMJRQ
         U4lLOhkYO0e0luKRaUG/13sHoEPZz3R5PQA7nWY6sfYxLVAZ+pD/vlZbbLSwzjQvLyQZ
         bWW7WzbF4Ib8hYycOcDtMND1EpXuAptaOa4XFth56PYzqxhZKRCKQKaSYH9ltwvITHUR
         das0MLjKJlrcYBRPx60qODAUepqoAIxZsoBG5gPioEpbYkIv0txcGnUmGo8om3LVJlWf
         GncY3lgo1D8PaHP9sn4gyIT6GeWzkJt8Kegdm4d+kSaCFw8t/w1QpE/aT076Hml7xeVm
         kU7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iz6iSEWLyWIUeOnJTh//RlD3MsBDQ9E44gHB/67nfcMSnQW1w
	JKGYPYG4pS6t/4cU1xjUxUk=
X-Google-Smtp-Source: ABdhPJwd+O8DDgu4X1G+R1zgDB3tyoXjWcwwcEah3NEPbwTkkMxUIF+I4VaT+cckUsmXTZHRIyUT2g==
X-Received: by 2002:a2e:22c3:: with SMTP id i186mr7173500lji.417.1638382517179;
        Wed, 01 Dec 2021 10:15:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls552082lji.1.gmail; Wed, 01 Dec
 2021 10:15:16 -0800 (PST)
X-Received: by 2002:a2e:9d48:: with SMTP id y8mr7054591ljj.19.1638382516074;
        Wed, 01 Dec 2021 10:15:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638382516; cv=none;
        d=google.com; s=arc-20160816;
        b=Kqe2fuDIihmqK1CUVQNx2iIcezNVrWiqlYcUjuB+Ot+7llWt1CfnEcXt6vF2Ueixcf
         9EXo5iVmqnjJrkNoefx0zdCN/GQOKCFzK8hrNxxHpSwiR7Tz9KL7ABROhRvdLV3P0Nrt
         YYdOGuVrMGQHoEWEMOeN3Iuwk/iZU6fXuCmREB9xWgfCs8vof+vHdA826eXM1vzT5ReD
         cx6lYikwcwS8cleoyIjyKKNTEXK/sQAGBsnPsJ6qoH6NAnqwsFJBSAOoh/MJ0gu1hP/Q
         9oa+2OyTij6MdppKgm6xxyC1yWF7N20+17Yd1Yy2RMelWo991F6mW5a+/4FRwyBqT7we
         rCDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=JudYALEd+vfrSbydk9WzA1a8Jbja5L0uMhSJtIDczwA=;
        b=cgI1d5+W661ffvjOrIX5zspThkA/fLmlGomxE2VMsTMZfHhyyk4Q2gilz/R69lwyfk
         M7s92DUgu0PQLwl2U2vqTxM5QFtJp2GHQxtoc7kOKL50XEyTt/rfWOOd4y4/x1VA9ZWR
         gYFXk1B46HdiJNvFUjLvMSNaWUeNJ4Hqeu8l6D+ube7ujvvxZDI6rYrZuvZ+EvAfRUcW
         jB7vyEZFfvmUqChNwi5rhfNuS7e9BAMVmI6RBAZ33teCsE/jBiHRsM3X2XTCDhXbAvj9
         m29M+kr7m5XeUNKCZo3jKfh+UnFi7JpWEerHi8+X1DfOqz3LnbhsF9CAccZmITCMX50j
         VCQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="UaIAD/rh";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c15si52109lfv.8.2021.12.01.10.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 10:15:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3F12A212B5;
	Wed,  1 Dec 2021 18:15:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A01A513D9D;
	Wed,  1 Dec 2021 18:15:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 1FhbJrK7p2HPSAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 01 Dec 2021 18:15:14 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org,
	Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>,
	kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>,
	Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>,
	Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>,
	x86@kernel.org
Subject: [PATCH v2 00/33] Separate struct slab from struct page
Date: Wed,  1 Dec 2021 19:14:37 +0100
Message-Id: <20211201181510.18784-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6884; h=from:subject; bh=C9Y/49TsxB/E0akYUQmXh/Rw3x/uvjRHIGWgJWjz1iY=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhp7tbz3TdAfpYMhghWpBPjpyNQELQnNXbCWvxjXXW V+khgIGJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYae7WwAKCRDgIcpz8YmpEL55B/ 0YVOB9lFU4Yo+9QGDna3BPOOTGFYoU+NhN1HU+HWaN4/METjmHzL6QTkZey7Vf/iUopoghro1cTifZ VJ0movi8ZzLs2CGqHCSXxycHOUjYhJga97oHj5g228ilwmOxRvwbltPZf/4Dq1GsHNPvA519rK17Mb FAtSBH05pG6994CDDcdJ87Ml2jM1WOYqIznymTYUQcDxcdqenLbyIZ6iYkLNZlWM6eHSMaZTuIZhJ4 5EobcLpyHXjVaQh30br8NhlSFQwc2JsF/S1x4wdWfs7uLnGix90NeTfKlxxOoK5pScmDEnNMYULCHG qssJrZ/85aCJE+jQj+N/wBkMCp87Jl
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="UaIAD/rh";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

Folks from non-slab subsystems are Cc'd only to patches affecting them, and
this cover letter.

Series also available in git, based on 5.16-rc3:
https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2

The plan: as my SLUB PREEMPT_RT series in 5.15, I would prefer to go again with
the git pull request way of eventually merging this, as it's also not a small
series. I will thus reply to this mail with asking to include my branch in
linux-next.

As stated in the v1/RFC cover letter, I wouldn't mind to then continue with
maintaining a git tree for all slab patches in general. It was apparently
already done that way before, by Pekka:
https://lore.kernel.org/linux-mm/alpine.DEB.2.00.1107221108190.2996@tiger/

Changes from v1/RFC:
https://lore.kernel.org/all/20211116001628.24216-1-vbabka@suse.cz/
- Added virt_to_folio() and folio_address() in the new Patch 1.
- Addressed feedback from Andrey Konovalov and Matthew Wilcox (Thanks!)
- Added Tested-by: Marco Elver for the KFENCE parts (Thanks!)

Previous version from Matthew Wilcox:
https://lore.kernel.org/all/20211004134650.4031813-1-willy@infradead.org/

LWN coverage of the above:
https://lwn.net/Articles/871982/

This is originally an offshoot of the folio work by Matthew. One of the more
complex parts of the struct page definition are the parts used by the slab
allocators. It would be good for the MM in general if struct slab were its own
data type, and it also helps to prevent tail pages from slipping in anywhere.
As Matthew requested in his proof of concept series, I have taken over the
development of this series, so it's a mix of patches from him (often modified
by me) and my own.

One big difference is the use of coccinelle to perform the relatively trivial
parts of the conversions automatically and at once, instead of a larger number
of smaller incremental reviewable steps. Thanks to Julia Lawall and Luis
Chamberlain for all their help!

Another notable difference is (based also on review feedback) I don't represent
with a struct slab the large kmalloc allocations which are not really a slab,
but use page allocator directly. When going from an object address to a struct
slab, the code tests first folio slab flag, and only if it's set it converts to
struct slab. This makes the struct slab type stronger.

Finally, although Matthew's version didn't use any of the folio work, the
initial support has been merged meanwhile so my version builds on top of it
where appropriate. This eliminates some of the redundant compound_head()
being performed e.g. when testing the slab flag.

To sum up, after this series, struct page fields used by slab allocators are
moved from struct page to a new struct slab, that uses the same physical
storage. The availability of the fields is further distinguished by the
selected slab allocator implementation. The advantages include:

- Similar to folios, if the slab is of order > 0, struct slab always is
  guaranteed to be the head page. Additionally it's guaranteed to be an actual
  slab page, not a large kmalloc. This removes uncertainty and potential for
  bugs.
- It's not possible to accidentally use fields of the slab implementation that's
  not configured.
- Other subsystems cannot use slab's fields in struct page anymore (some
  existing non-slab usages had to be adjusted in this series), so slab
  implementations have more freedom in rearranging them in the struct slab.

Matthew Wilcox (Oracle) (16):
  mm: Split slab into its own type
  mm: Add account_slab() and unaccount_slab()
  mm: Convert virt_to_cache() to use struct slab
  mm: Convert __ksize() to struct slab
  mm: Use struct slab in kmem_obj_info()
  mm: Convert check_heap_object() to use struct slab
  mm/slub: Convert detached_freelist to use a struct slab
  mm/slub: Convert kfree() to use a struct slab
  mm/slub: Convert print_page_info() to print_slab_info()
  mm/slub: Convert pfmemalloc_match() to take a struct slab
  mm/slob: Convert SLOB to use struct slab
  mm/kasan: Convert to struct folio and struct slab
  zsmalloc: Stop using slab fields in struct page
  bootmem: Use page->index instead of page->freelist
  iommu: Use put_pages_list
  mm: Remove slab from struct page

Vlastimil Babka (17):
  mm: add virt_to_folio() and folio_address()
  mm/slab: Dissolve slab_map_pages() in its caller
  mm/slub: Make object_err() static
  mm/slub: Convert __slab_lock() and __slab_unlock() to struct slab
  mm/slub: Convert alloc_slab_page() to return a struct slab
  mm/slub: Convert __free_slab() to use struct slab
  mm/slub: Convert most struct page to struct slab by spatch
  mm/slub: Finish struct page to struct slab conversion
  mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
  mm/slab: Convert most struct page to struct slab by spatch
  mm/slab: Finish struct page to struct slab conversion
  mm: Convert struct page to struct slab in functions used by other
    subsystems
  mm/memcg: Convert slab objcgs from struct page to struct slab
  mm/kfence: Convert kfence_guarded_alloc() to struct slab
  mm/sl*b: Differentiate struct slab fields by sl*b implementations
  mm/slub: Simplify struct slab slabs field definition
  mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only
    when enabled

 arch/x86/mm/init_64.c          |    2 +-
 drivers/iommu/amd/io_pgtable.c |   59 +-
 drivers/iommu/dma-iommu.c      |   11 +-
 drivers/iommu/intel/iommu.c    |   89 +--
 include/linux/bootmem_info.h   |    2 +-
 include/linux/iommu.h          |    3 +-
 include/linux/kasan.h          |    9 +-
 include/linux/memcontrol.h     |   48 --
 include/linux/mm.h             |   12 +
 include/linux/mm_types.h       |   38 +-
 include/linux/page-flags.h     |   37 -
 include/linux/slab.h           |    8 -
 include/linux/slab_def.h       |   16 +-
 include/linux/slub_def.h       |   29 +-
 mm/bootmem_info.c              |    7 +-
 mm/kasan/common.c              |   27 +-
 mm/kasan/generic.c             |    8 +-
 mm/kasan/kasan.h               |    1 +
 mm/kasan/quarantine.c          |    2 +-
 mm/kasan/report.c              |   13 +-
 mm/kasan/report_tags.c         |   10 +-
 mm/kfence/core.c               |   17 +-
 mm/kfence/kfence_test.c        |    6 +-
 mm/memcontrol.c                |   43 +-
 mm/slab.c                      |  455 ++++++-------
 mm/slab.h                      |  322 ++++++++-
 mm/slab_common.c               |    8 +-
 mm/slob.c                      |   46 +-
 mm/slub.c                      | 1164 ++++++++++++++++----------------
 mm/sparse.c                    |    2 +-
 mm/usercopy.c                  |   13 +-
 mm/zsmalloc.c                  |   18 +-
 32 files changed, 1317 insertions(+), 1208 deletions(-)

-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211201181510.18784-1-vbabka%40suse.cz.
