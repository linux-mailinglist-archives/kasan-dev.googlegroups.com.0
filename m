Return-Path: <kasan-dev+bncBDN7L7O25EIBBX5BZCNAMGQEYEFC74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 87A6C606E45
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 05:24:16 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf472426lfb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 20:24:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666322656; cv=pass;
        d=google.com; s=arc-20160816;
        b=XXFffeLGG+A2lx+ploNKqZ4t8vfZ75vrODjGjeHi5vniq0t6HSaDHKYEtTodWx6ODu
         J+uVg7KCoFeHrpX8vAccQYariRMaDEzIJCuu9062fL5EDAWqVyk3IPqluLNmsOPnY0rn
         KVn1oyqQKyruiCbGfKkY3ZsoT/UUywxYw+gmNWan5VqbXQFEk+hg43nLHOzEOkV1pvqD
         bds1lFX4FiGD1lQEQ2xPmZvoVngLCrirPXrIr5CFc8yuyZGt7Vnsb0MPWIOi0eaADR0C
         B4gQpwYcOuKhvomTIPfx9WgyCd6EDVnVAtEGsAxehvVeoNgVvZ4jBHRrhXR+6CQyfGLQ
         2phQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7ei6RpI2//gxhTrJNh5Op3deYUtu8UZ0TqdCQ0bjSlk=;
        b=0w2nQKRp4UU85FiDt7SyzBlwAORQjS9T6qYyG2r5WdjBzqSkhBl0BCqvp87aB51T1g
         llgminIQWWemHyd6mSoisHCUm4HXZD38HiVvcJgj3MRuMWPNxzw3860nC6lZ6pjzwGC6
         ULnoxnHNCXEnY34fg1MFuODoab6tGcf6e6bWzCqyFTjLpJUvxa7jxqnjS6wWbdjIX3et
         2FwX9cT1hWmvySgpTHZoUFGH9Fe/loy70m6ntdTfpXV6NKWc0DHltuGBPzRLngWcrXLD
         Y3yOsYgmifkOI4Zbnky3COLRyxkNkxRTlKkm9P5q/O7PibdagqB6dBClWMvtrhtUMcId
         uTNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NhumLSCZ;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7ei6RpI2//gxhTrJNh5Op3deYUtu8UZ0TqdCQ0bjSlk=;
        b=hDhA+SIyPok3RcqFJQyqXJR6YR+FgZP264JnESnIIWaxIc6OC3jcGab7paTKVNyZDm
         BBWx0QfnUCO0oeFy1yJUCYX3vs4JtMyOR5mrtkQJiEdGRjs7BncnczTQji9hEpxdwLTq
         tYmrKAxtxE3DM0OvMmQkcTFXiA2I2tdvYG2u25zDjhu4bSmY8VO6q8GLFjk2HbG/rps1
         dccdfA3wqyx/5JLZGIIaX5mWpfCSKmYpMkb7RXA3yFd98/xg8cfrxMTOed0K/XIrN4LZ
         eGhnatUEaTrJWmOQXKRYMx+vl2e17d2KW6O6dGi7Cs7okl8hQJCWuhBLHJv3UIKqEPf4
         h5ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7ei6RpI2//gxhTrJNh5Op3deYUtu8UZ0TqdCQ0bjSlk=;
        b=0riGCvzsuWe/X6+O4LJ1eeCg/h0VGqpIwLDHGLVQJrpfIOkFpUEw5pCCcnbI/EYSw0
         WwD90s38kDogRzu1rjbaaOHXzSTb7AYzvataTjrmiM5PheUqdsNjN7V1SXRt+bU8LVgm
         Dkhm+KWBJesZHYf7agtxAnanLcfeKdXrRzMPPfyQyStpRKL8Vfi07jZ6E0E0K4QkX1Fu
         nCH5zYyB7moL9byq0oexvryFXHZk+d5bymI4W0m16+oOIiSg0mocxu7rC0ZV0CcxTNM4
         v/fjeoD1ZMHoZRO2B2R0WhTrMIc6UzkNI06wqFJ9yBvdfimNyOZNdeYfo7u0EvxhEZeJ
         Zutg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2FvqKZdET6F4U2VixHnu+HvtCjLbbrsv2VKOeIZvhi3gVyx77y
	3j4nQpZCZ/b/CiXXUmEas9Y=
X-Google-Smtp-Source: AMsMyM5pffc2I4ddTXRt+aogDPjXCoqqRg8maX05+iTMEP38upWHgeDC2N7P1VQ05uCfIQrRYm0BwQ==
X-Received: by 2002:a05:651c:1950:b0:26f:e54b:8c54 with SMTP id bs16-20020a05651c195000b0026fe54b8c54mr5700632ljb.108.1666322655595;
        Thu, 20 Oct 2022 20:24:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1186:b0:4a2:3951:eac8 with SMTP id
 g6-20020a056512118600b004a23951eac8ls11829lfr.0.-pod-prod-gmail; Thu, 20 Oct
 2022 20:24:14 -0700 (PDT)
X-Received: by 2002:ac2:531c:0:b0:4a2:7c6b:4703 with SMTP id c28-20020ac2531c000000b004a27c6b4703mr5524565lfh.61.1666322654355;
        Thu, 20 Oct 2022 20:24:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666322654; cv=none;
        d=google.com; s=arc-20160816;
        b=lCmFSm0m95is02TPqzp6NNA5yijXGzPFY9+vjPAqTviMjKTnExc0KR5cXMgRlRJom+
         TYVBlq166hFdRixmO+w1U/K6WiGynJwDymfzscVimmwJKBPpplRI6qN9hCvnTdM6EHKF
         92WtIL9TS2//l9s4fgomswGCbCM3bms9F3kitfcrPmZBBAXhMF3R1aDg94R0GXSGGvSv
         FU6aOWmtjqX/ov5/d+/JeFpIMrVBpVF9BLB15xFjO2cuMIz/DB6sF+LDdJ4jumKmaveZ
         dDMgjlzaaHw7hf2u9UEYp8jb9ozq2FkPfd7Py9JD73u+LTaHC2dZs2MwgL8U5wEIhgWZ
         Qzug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dC2A/rL7A2O3RZ+6eRWTY11NX70whx7Aj8RzyV9j+tc=;
        b=OGh92rhe67i4zRj87KHbH6JMigT6pKIi8GRE5ZF5NDpTKmiTWVMYltZjHYx7G1TPfc
         w466vn0nYk9IjPS86Zu6AjbdSAoZ5GhI/LVL6dIoNzk+bGC9oij9f9ktsWUlDEYTmDFO
         CdQeL8Z43wqNM0Icutgip/zF/s4xXipPLkrsP3ZmpDpigdZE4Ts5AlnbmbXtlVaXX0ts
         9pwUAWNT4vzQYcYQhzPUt7ytt1koStesBWIj7Hd/M768kDQyB7tygO10UbrPxOFUtrUC
         38EdAVV2WMku93MqgJyEdzDFgIRlt5wi90by2PCxYtztOHhvk5inlO8zQFG2fx7cZr32
         5qrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NhumLSCZ;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id k20-20020a2eb754000000b0026fb09d81bbsi595748ljo.1.2022.10.20.20.24.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Oct 2022 20:24:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="371114038"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="371114038"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Oct 2022 20:24:11 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="719459530"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="719459530"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by FMSMGA003.fm.intel.com with ESMTP; 20 Oct 2022 20:24:07 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v7 0/3] mm/slub: extend redzone check for kmalloc objects
Date: Fri, 21 Oct 2022 11:24:02 +0800
Message-Id: <20221021032405.1825078-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NhumLSCZ;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

kmalloc's API family is critical for mm, and one of its nature is that
it will round up the request size to a fixed one (mostly power of 2).
When user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
could be allocated, so there is an extra space than what is originally
requested.

This patchset tries to extend the redzone sanity check to the extra
kmalloced buffer than requested, to better detect un-legitimate access
to it. (dependson SLAB_STORE_USER & SLAB_RED_ZONE)

The redzone part has been tested with code below:

	for (shift = 3; shift <= 12; shift++) {
		size = 1 << shift;
		buf = kmalloc(size + 4, GFP_KERNEL);
		/* We have 96, 196 kmalloc size, which is not power of 2 */
		if (size == 64 || size == 128)
			oob_size = 16;
		else
			oob_size = size - 4;
		memset(buf + size + 4, 0xee, oob_size);
		kfree(buf);
	}

(This is against slab tree's 'for-6.2/slub-sysfs' branch, with
HEAD 54736f702526)

Please help to review, thanks!

- Feng
---
Changelogs:

  since v6:
    * 1/4 patch of kmalloc memory wastage debug patch was merged
      to 6.1-rc1, so drop it
    * refine the kasan patch by extending existing APIs and hiding
      kasan internal data structure info (Andrey Konovalov)
    * only reduce zeroing size when slub debug is enabled to
      avoid security risk (Kees Cook/Andrey Konovalov)
    * collect Acked-by tag from Hyeonggon Yoo

  since v5:
    * Refine code/comments and add more perf info in commit log for
      kzalloc change (Hyeonggoon Yoo)
    * change the kasan param name and refine comments about
      kasan+redzone handling (Andrey Konovalov)
    * put free pointer in meta data to make redzone check cover all
      kmalloc objects (Hyeonggoon Yoo)

  since v4:
    * fix a race issue in v3, by moving kmalloc debug init into
      alloc_debug_processing (Hyeonggon Yoo)
    * add 'partial_conext' for better parameter passing in get_partial()
      call chain (Vlastimil Babka)
    * update 'slub.rst' for 'alloc_traces' part (Hyeonggon Yoo)
    * update code comments for 'orig_size'

  since v3:
    * rebase against latest post 6.0-rc1 slab tree's 'for-next' branch
    * fix a bug reported by 0Day, that kmalloc-redzoned data and kasan's
      free meta data overlaps in the same kmalloc object data area

  since v2:
    * rebase against slab tree's 'for-next' branch
    * fix pointer handling (Kefeng Wang)
    * move kzalloc zeroing handling change to a separate patch (Vlastimil Babka)
    * make 'orig_size' only depend on KMALLOC & STORE_USER flag
      bits (Vlastimil Babka)

  since v1:
    * limit the 'orig_size' to kmalloc objects only, and save
      it after track in metadata (Vlastimil Babka)
    * fix a offset calculation problem in print_trailer

  since RFC:
    * fix problems in kmem_cache_alloc_bulk() and records sorting,
      improve the print format (Hyeonggon Yoo)
    * fix a compiling issue found by 0Day bot
    * update the commit log based info from iova developers


Feng Tang (3):
  mm/slub: only zero requested size of buffer for kzalloc when debug
    enabled
  mm: kasan: Extend kasan_metadata_size() to also cover in-object size
  mm/slub: extend redzone check to extra allocated kmalloc space than
    requested

 include/linux/kasan.h |  5 ++--
 mm/kasan/generic.c    | 19 +++++++++----
 mm/slab.c             |  7 +++--
 mm/slab.h             | 22 +++++++++++++--
 mm/slab_common.c      |  4 +++
 mm/slub.c             | 65 +++++++++++++++++++++++++++++++++++++------
 6 files changed, 100 insertions(+), 22 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221021032405.1825078-1-feng.tang%40intel.com.
