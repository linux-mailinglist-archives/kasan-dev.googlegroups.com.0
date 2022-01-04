Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBDVBZ2HAMGQEKP3MRNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7248F483962
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 01:10:55 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id g18-20020a05651222d200b0042612bda352sf7124795lfu.11
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 16:10:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641255055; cv=pass;
        d=google.com; s=arc-20160816;
        b=UoonP8fCr1HpyH7XfOqlI8ISfV18icuuhVw7OKXipxAKpECG+NNNe5TgzNvTwJR8Qx
         LhfyDatvBM/jXOVdXR2t5neJSuraemTL8zxkAlz81lppPbVqdxmMc27S5xRvrTcbmi9h
         hpkt61wgv0eHe5om/eu3SfmPl6m863Klrp0rHQFPHNVQtBQXcM8Qc8sXlFq5B1pde29q
         8DbJcWKYUkNbdIoVzA53a0ZDB5m3czU6nW2A7KXWoGqM7hqIY/a1xZM2R4mXX4/oNc9e
         IPw2+vwfUY762ADoK1iHzNOSbu+Y80GdcSUsElcV7uprcwYeJ3yKWwPZGzPDkAYP1zz7
         BDjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kZGrjGvc+cDpczQg5K5SkrXLcM/mT9I7SSsgS3Nsj8w=;
        b=C5JkXKtxUd4wHJpz0Iek/f8sLT+/JUMNX1HcLSg5Y2gLyA2Mzsbh2zLcKF+ez6IzNr
         vmXLisRu/1qcx/REXfK9FSPI7xlZe5BuTlrUXV2gHBM+AZO5RGIE0R9qhCSoPkPpkAlc
         wBwef48Vax/+cqTNj3JvMzRY0dpUraayAbGZl4Mf5E2q0wj8xNFl6AqiaiFCp8TvDl88
         xVcCjyEdaX7dtbYxk2uPP27lAo9Xg31acsawSGAKmtMpTwb0GQl+jKDYl/Pt57Y5i7h+
         Xgo8K1sGcUmTcS5Z3JlaBXlO285orgxxosVhOZONPoHFO3w7jScIdCF+p0ixM89xtlfI
         Kj7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="n8krX/Pr";
       dkim=neutral (no key) header.i=@suse.cz header.b=qOgAdn94;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kZGrjGvc+cDpczQg5K5SkrXLcM/mT9I7SSsgS3Nsj8w=;
        b=CNAkvwV+GKym/AGGkW4M7p0rd07gMQ5bUDV7TEAIo2mx0npdKha65q3QZr5/80q9PB
         tUCoYVDlk5nngzOG9NzztQR6sFZuJmFljjmC/QxgC04eZQzt99m3iUzDMEPG53UoACaE
         n82AJuB/S6SOoKcSRWGb6xx38xI8aMfH8b4bGIqb//kgJvO/kQqPLZgJ8ybtsl30T9jP
         wR1v3/k2iLUcuI3CLJn5cWhvcp/qt9pfzxkiqdoHDA+213Fo9ELFmjOFQhc2RfZTS/31
         IwE7ogxm/9OGbNP9K2AMHy0EUWh2C5DJSRCudObcgJoaE/oTBV0tw1fU7W66focafN6s
         BJdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kZGrjGvc+cDpczQg5K5SkrXLcM/mT9I7SSsgS3Nsj8w=;
        b=0ysiL7ZCSA07lAGnmyf89qXL+RG4rgwOWUOVAEzAimAvcQCNz8kdwImfdTAca3eXw1
         pC+hcjVPpqjU3ExJfbjxe9vlSCMSbrFK/uO+YdfUcMkThDEOGAQgWcxtcjH2hbOsp/tC
         yiEnKclrF7dKR1ZHgLlmuxkBiywZ/SgvAXeB0EVwEXmUbfbvW40YI2la1ZZGWwGCuXk6
         b77oKlUsVC74OgLX60QjKZiw9WhOQPlfxZg8wGLVUF+Y5KwBzHCl+YppEdjDrLabI9fU
         Af7r56vcSt34mRsPfV1GIWH6qA3ZfpGqbEG63H8ODUQBMvAebQddEscX1oK+BOln5AgD
         5vpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rbE8ntVD9U1vQmxS6LHQ+uRjet6wcQp/UEVsJciFgm4DYx2UB
	HCbhNyFOXS9/5nYiPEWTGMg=
X-Google-Smtp-Source: ABdhPJzTdCX1dclS0S696ktH1BJYUpJj+bEWg/NT7+5Ohe2DtOrXxIJ2Lu+0CMWh2y1HhgOZLviT1Q==
X-Received: by 2002:a2e:7c01:: with SMTP id x1mr38175774ljc.145.1641255054751;
        Mon, 03 Jan 2022 16:10:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls3754434lfh.3.gmail; Mon, 03 Jan
 2022 16:10:53 -0800 (PST)
X-Received: by 2002:a05:6512:ac7:: with SMTP id n7mr43596164lfu.280.1641255053682;
        Mon, 03 Jan 2022 16:10:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641255053; cv=none;
        d=google.com; s=arc-20160816;
        b=jFxY1Vd9i5MegvK/DvxepVHsxtYS0BNucif1+ty6rPXbj7H4mj9D4W1VnEsXHhPRdY
         11n+ayvqvqKV9dnoP1fTD8Bre4FJ6YdId7i8rrvyhu5fP2pghDiFevLSmS9rhYp+xHpM
         lTSwxxz7oD09xdrJaB4O1vqJxZWMaL2F08hIGSNIUiCClMTe5JT7f/vbyEdCqRy8bRag
         QhLP6LQD1qeNE3AauIRYPD5nH4I1pJKnZ9d1CgwrK3XmVTmSPxYJN0lc7KB40+LuZNU7
         CT1SBwfLjfp5qG/wMpRm5n/W5HYUP7bBI6d6TypDNlp4a6yv0q/7vBE9Cgt/ZF7PnO8f
         OqFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=UXaf9uC0yYgj8UoQwGZWBVf6JmBt0lJxsQgnWsQtcO0=;
        b=tWpV2rV+W3TF9fPUN9Jw3cQlf5/dl5wigcIfDeNoGRItYIVNBPgy42RLaxwTpWaQ7p
         1NFFLVDKAx+lIoPv/ORGC12nIM4mQq7alwGJlGVhy7ggIKlaDmzuoYWFjGfDtA+dMV+J
         x1KXWJiQE88YHXgAYJVkR41Z4vd+vnkFgq4M/EIBw5sMPrefpmnS0dXHExtSNVytFlQy
         sK/+cPTad34+M8DedPeSEv45fiIF2Ks/tjmNOJ85InmIW7mmDb9FeVU3EOQZqFYJAr9T
         pKbtI9XVCHtOkN4JhjrdjXv6yLLt0rxMSh4vqNkT0OELHPgabb/x0w7URpu5ZV03zY/N
         FPTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="n8krX/Pr";
       dkim=neutral (no key) header.i=@suse.cz header.b=qOgAdn94;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id z24si1897322lfu.0.2022.01.03.16.10.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 16:10:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B64601F396;
	Tue,  4 Jan 2022 00:10:52 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 43AEC139D1;
	Tue,  4 Jan 2022 00:10:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id wY9ZD4yQ02FEQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 04 Jan 2022 00:10:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <guro@fb.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ingo Molnar <mingo@redhat.com>,
	Julia Lawall <julia.lawall@inria.fr>,
	kasan-dev@googlegroups.com,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>,
	Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>,
	Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	x86@kernel.org
Subject: [PATCH v4 00/32] Separate struct slab from struct page
Date: Tue,  4 Jan 2022 01:10:14 +0100
Message-Id: <20220104001046.12263-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6877; h=from:subject; bh=eOU73DU2R3hiX6ZTz0IVJqWoxCtxeG917wETQZKQato=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBh05Bpj4k8YTH2hlMn7F5iXTAu0XxQ385rOPwcQkTF VOpOIdaJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYdOQaQAKCRDgIcpz8YmpEK41B/ 91il7ZCibzyFB9paEVEvC5Hoh3WWOJx5XAPHsslQF7ojSGH2mztLJnOahhjZpSC+AzQbu0BrhbbGK9 sv3Y/MSnYu13NrbzAlUEDB6Unya8GQ3H5u4zGdTVtcOmjMpQ5djzk/YCPIRMm4UeMNM4kR6LVIx6RY Cdh4UCrVVVlqMnMKaPVCb9Wx07ghgYwhJezqttD5RYhS68vnoeAaPkmT1/pFOQHvbyz62Z3COZS8/K NxSbN1iLkyVrx4i6zmlbwE//4MVVFxF4PXTidKHDhuZzrEQGsQIjkHJn9ZhnpndCVdAN5voaK04IpF HdSm1x5ApsAOXQg9lB4o6ipOG9FNT8
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="n8krX/Pr";
       dkim=neutral (no key) header.i=@suse.cz header.b=qOgAdn94;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Series also available in git, based on 5.16-rc6:
https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v4r2

The plan is to submit as pull request, the previous versions have been
in linux-next since v2 early December. This v4 was in linux-next since
Dec 22:
https://lore.kernel.org/all/f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz/
I planned to post it on mailing list for any final review in January, so
this is it. Added only reviewed/tested tags from Hyeonggon Yoo
meahwhile.

Changes from v3:
https://lore.kernel.org/all/4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz/
- rebase to 5.16-rc6 to avoid a conflict with mainline
- collect acks/reviews/tested-by from Johannes, Roman, Hyeonggon Yoo -
thanks!
- in patch "mm/slub: Convert detached_freelist to use a struct slab"
renamed free_nonslab_page() to free_large_kmalloc() and use folio there,
as suggested by Roman
- in "mm/memcg: Convert slab objcgs from struct page to struct slab"
change one caller of slab_objcgs_check() to slab_objcgs() as suggested
by Johannes, realize the other caller should be also changed, and remove
slab_objcgs_check() completely.

Initial version from Matthew Wilcox:
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

Hyeonggon Yoo (1):
  mm/slob: Remove unnecessary page_mapcount_reset() function call

Matthew Wilcox (Oracle) (14):
  mm: Split slab into its own type
  mm: Convert [un]account_slab_page() to struct slab
  mm: Convert virt_to_cache() to use struct slab
  mm: Convert __ksize() to struct slab
  mm: Use struct slab in kmem_obj_info()
  mm: Convert check_heap_object() to use struct slab
  mm/slub: Convert detached_freelist to use a struct slab
  mm/slub: Convert kfree() to use a struct slab
  mm/slub: Convert print_page_info() to print_slab_info()
  mm/slub: Convert pfmemalloc_match() to take a struct slab
  mm/slob: Convert SLOB to use struct slab and struct folio
  mm/kasan: Convert to struct folio and struct slab
  zsmalloc: Stop using slab fields in struct page
  bootmem: Use page->index instead of page->freelist

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

 arch/x86/mm/init_64.c        |    2 +-
 include/linux/bootmem_info.h |    2 +-
 include/linux/kasan.h        |    9 +-
 include/linux/memcontrol.h   |   48 --
 include/linux/mm.h           |   12 +
 include/linux/mm_types.h     |   10 +-
 include/linux/slab.h         |    8 -
 include/linux/slab_def.h     |   16 +-
 include/linux/slub_def.h     |   29 +-
 mm/bootmem_info.c            |    7 +-
 mm/kasan/common.c            |   27 +-
 mm/kasan/generic.c           |    8 +-
 mm/kasan/kasan.h             |    1 +
 mm/kasan/quarantine.c        |    2 +-
 mm/kasan/report.c            |   13 +-
 mm/kasan/report_tags.c       |   10 +-
 mm/kfence/core.c             |   17 +-
 mm/kfence/kfence_test.c      |    6 +-
 mm/memcontrol.c              |   47 +-
 mm/slab.c                    |  456 +++++++------
 mm/slab.h                    |  305 +++++++--
 mm/slab_common.c             |   14 +-
 mm/slob.c                    |   62 +-
 mm/slub.c                    | 1177 +++++++++++++++++-----------------
 mm/sparse.c                  |    2 +-
 mm/usercopy.c                |   13 +-
 mm/zsmalloc.c                |   18 +-
 27 files changed, 1263 insertions(+), 1058 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220104001046.12263-1-vbabka%40suse.cz.
