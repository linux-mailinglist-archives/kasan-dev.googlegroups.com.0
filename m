Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZXQZOGAMGQE2LF7UAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C65CD451C84
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:38 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcsf346884wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:16:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637021798; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZU1uILD6uDIdS0odPabN6jLMLlmvNqAWRKQ+IuCVJhAQjccfSIqbxF2K5twu/fvYCB
         iN9+TBnfUaNFnarGSiF3BDQGs62/4yvlZjf/1OJ/kJ2q0EWjuh6lCY55zcETbCf7gCLh
         WgkTYYkVX+qpO7AFR3ZoOgU2T2ahn9FIE8unnBsUULlD5HGUs6ERHOGNIzJ5HJ7UKhB2
         zz2ihF7MhZ+vKtnmXgdnXZU8jEd47ujYBsfRzUAdgFIgn5CTevpqLpVb0uxl6HvLDinV
         ytS+pZevkc6uSDMfmqYR3Krd0Fvoi7m96wBQRpzk7dk8ldTsNXGq2cHzUDlfzJCgHf2a
         MKBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rYQPtfc7a6CSzB86TIeyBOvZpUfYT4kS2Nrvlt7LvOA=;
        b=FIqQx5cACUCK+wFBCOnrmlP+GQPPwsr4L8CHdamMk7bCo6RtU3RM91x/KBEGBWW/Uk
         zAkm7xTPwpsyBIuWlfiglssXS8v6aCVA+TROJ64ospoeFO8HpkIFbwW6l2gXxxUQ0K8z
         Zd0BEAbO+Ei/pjNYhckt40BJ9wQmbxYSqetbuSwnwk7HCTpqHC5Dv1hUVr0Wz0KheNg8
         upMuxSoUG63wVNVRlINJ41AU8bBjfHU4JqvUhQ2jNuTTWbhXgaVFNDncnQhwM9MwSir6
         oyMIKu1dtct81ae442o5ncVyhp0B/j9SsH9KFpCjVdtJh+fCSCGZhV5dPcxnr61ArXdZ
         czUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ulrfLKfX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rYQPtfc7a6CSzB86TIeyBOvZpUfYT4kS2Nrvlt7LvOA=;
        b=E4p0N+EHOrDC4uip8nZVe6jNMvFMvKYhXK0m8Ty2tLeAusSWGuID+xjL546DzrHfzn
         aXXcAmA9GGtWLu1cSuapcoarbkEAjjSX2X1ZzrmETCYw75YeryPqH81DG7Xb94MVlwbc
         Q3Qp2FuVtFc5XxouOTAnojBWcvHYciLeN/Qr8uscsMnDmkgCFMuq6fGRpIyGAahnbg8S
         fbP9xJNdgDrvEYawAtJN0NiO5+9DELQR2msz7lN/W5I7Q+j7i7S7jOXgytfCHPZefhgL
         ZVTzMnrVJTXNRinJnx5qK6ME3U3VkUgoIh3KO6QKD+QyLp5qPdWPwCIPW2/gGrH6auQV
         w+Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rYQPtfc7a6CSzB86TIeyBOvZpUfYT4kS2Nrvlt7LvOA=;
        b=lVULgIhbawdSqY388Sd6tFt6WvBwK++Qnz35T7zLsi5ZI/skwHJNufEwWaTxUDz+qR
         eBk6SBFGIJKyN6CeV8O+E0R29foE5GpZdSAuvbe6lLPbmNJ0AInM5vE2d2QLEEWJZdb9
         xHqbbjtSs/axWP4hV/00B4MpDrExzoFMzaZf+DPT2W1b6jlj0Wz4qhz1qF+v3EHWVLOa
         NfqQPDtjm45lskwFlg3w1pkbh2zL0utsN06ia1h01j9mH/YZuN7jWbQMwThdkfvCvGMK
         6Q0vSFuf6Q6ZG5/NRWirxpF7dZlLwaGZ0OctByuYgaG+tmQYsAJrtFyeSt9eK47BOQhP
         B6OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oJ2mCYTFZkPJw/hmAp6WwRjP3QcRnVStRdctaHqTgR0jOlcPg
	PtvPixQKdQUU+ivejqONNr8=
X-Google-Smtp-Source: ABdhPJx2xo9TfaIM06Slrtl6oCxjsX+NyzRf1VXY1z6r2lpBI6UA3HABZitsxlAD0bbzScUNti99wQ==
X-Received: by 2002:a7b:c409:: with SMTP id k9mr2812969wmi.173.1637021798545;
        Mon, 15 Nov 2021 16:16:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls403759wmb.3.canary-gmail; Mon,
 15 Nov 2021 16:16:37 -0800 (PST)
X-Received: by 2002:a1c:f219:: with SMTP id s25mr64281039wmc.31.1637021797591;
        Mon, 15 Nov 2021 16:16:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637021797; cv=none;
        d=google.com; s=arc-20160816;
        b=pP/jWgP30hG7p49OY6Hoi9B4ThHdkyCJ9/1qghvsk2wxU/yh3w318o45palk5LZNNr
         nEplnNAvZZ954Z6qmoBTjKw+cODO2tOMzpk56XhJApTEAH5AQ18O6OjFcqtLT7PU6Bqx
         0b1aRphBXnWJ3bRvAbYRzU9cO1sBc60C8asdaF1HQdEW9YMAWVUEuILQA/Mp4vgGEAl7
         T2tqnfUPq/pGYczsZPr9Fq+q4iNh+XvJFTo06/SD/ExB0+AVNWxvpQyFU07jilGvVDMf
         aVMPhyxz2rGw48cMsg41M7ue3tCTaVjNFcRC1QHYn2XhJ9skTDLIYNdgiSYPySgQKmqF
         17aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=qMPAWzuBja3HPc266bh9/SxdkyevbbiS70h3IGw63Mk=;
        b=PNjZ5kr+iFno4J/UpMVKCbn7yTejWtT1aHig3QPTa12vNIXTHQztH66jcXcl31JIAX
         4MI25bXqYO9LT0iEP5A1+rLVjDJES75j9cIMsvxifzTVFHXMRpTkx8U9i6PrfVQlcnUl
         quDwMYXsR3W5nKi3S3odevg95trNBmvwMBnuersktlVufPFVbLh1klo/Oit2gKSMiwEw
         tZcDF8Mh8KJJmXYrUzinHtUFgMsbDb4i16j67/7YqXA/b6UdSn1r7Zp8Ktnzwa9qK3se
         ghQI5mcos6G6Cs9yoKAuXayFbQf/eIA8/j0Le95iAgrL7bDA3Vqzx4XjjJH9sUjkWFYh
         zyAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ulrfLKfX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id z3si82440wmi.2.2021.11.15.16.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:16:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0EE092170C;
	Tue, 16 Nov 2021 00:16:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 880A3139DB;
	Tue, 16 Nov 2021 00:16:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id OON5IGT4kmFjXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 00:16:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	linux-mm@kvack.org,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
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
Subject: [RFC PATCH 00/32] Separate struct slab from struct page
Date: Tue, 16 Nov 2021 01:15:56 +0100
Message-Id: <20211116001628.24216-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6354; h=from:subject; bh=Yv4yTdINqcoqD7G0pRh1MdRj/fEwyrMlw3UnFAcYj7Y=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhkvgftiZeNrWVhI+DKUHzPdvji/FLFq5wjFQzaaPr g56dz96JATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYZL4HwAKCRDgIcpz8YmpEDd2CA C5VF2fCCrFh+cwzoazBKYOudAHl4b/Ln5DcnL9t00V5H6CRcgWEe+uq7ju+KYaShk/4aDVU6/k4iI/ i8XUUIcXQBM1hQfAzvivKsbo37IEwmw/yYTJu7P8HI5stLfZ9pYSuNZiMa3tjh7xDXE2lXoboaSisR pJ5PEvAxmgTPOKQ0Kn3axIp5C8xS+5lQIoDk10I7DiVwjiPjWgyOnYKXGwxQ10xu6Rs0VTv79x9Fo1 beM5ueTcBD4P12IyMYNLnjPDHveynUlOqdrB/oS6gcSstu847TOW64xYyb9KBgkhnJG6epdIvJTRMr tcE5Bo6jnyrVzSwZc6pgdQjX45G7Ju
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ulrfLKfX;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Series also available in git, based on 5.16-rc1:
https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v1r13

Side note: as my SLUB PREEMPT_RT series in 5.15, I would prefer to repeat the
git pull request way of eventually merging this, as it's also not a small
series. Also I wouldn't mind to then continue with a git tree for all slab
patches in general. It was apparently even done that way before:
https://lore.kernel.org/linux-mm/alpine.DEB.2.00.1107221108190.2996@tiger/
What do other slab maintainers think?

Previous version from Matthew Wilcox:
https://lore.kernel.org/all/20211004134650.4031813-1-willy@infradead.org/

LWN coverage of the above:
https://lwn.net/Articles/871982/

This is originally an offshoot of the folio work by Matthew. One of the more
complex parts of the struct page definition is the parts used by the slab
allocators. It would be good for the MM in general if struct slab were its own
data type, and it also helps to prevent tail pages from slipping in anywhere.
As Matthew requested in his proof of concept series, I have taken over the
development of this series, so it's a mix of patches from him (often modified
by me) and my own.

One big difference is the use of coccinelle to perform the less interesting
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
where appropriate. This eliminates some of the redundant compound_head() e.g.
when testing the slab flag.

To sum up, after this series, struct page fields used by slab allocators are
moved from struct page to a new struct slab, that uses the same physical
storage. The availability of the fields is further distinguished by the
selected slab allocator implementation. The advantages include:

- Similar to plain folio, if the slab is of order > 0, struct slab always is
guaranteed to be the head page. Additionally it's guaranteed to be an actual
slab page, not a large kmalloc. This removes uncertainty and potential for
bugs.
- It's not possible to accidentally use fields of slab implementation that's
not actually selected.
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
  mm/kasan: Convert to struct slab
  zsmalloc: Stop using slab fields in struct page
  bootmem: Use page->index instead of page->freelist
  iommu: Use put_pages_list
  mm: Remove slab from struct page

Vlastimil Babka (16):
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
 include/linux/mm_types.h       |   38 +-
 include/linux/page-flags.h     |   37 -
 include/linux/slab.h           |    8 -
 include/linux/slab_def.h       |   16 +-
 include/linux/slub_def.h       |   29 +-
 mm/bootmem_info.c              |    7 +-
 mm/kasan/common.c              |   25 +-
 mm/kasan/generic.c             |    8 +-
 mm/kasan/kasan.h               |    1 +
 mm/kasan/quarantine.c          |    2 +-
 mm/kasan/report.c              |   12 +-
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
 31 files changed, 1302 insertions(+), 1208 deletions(-)

-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116001628.24216-1-vbabka%40suse.cz.
