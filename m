Return-Path: <kasan-dev+bncBDN7L7O25EIBBOOSQCMQMGQEUYZRRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AE105B682E
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 08:54:50 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id f14-20020a1c6a0e000000b003b46dafde71sf2810753wmc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 23:54:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663052090; cv=pass;
        d=google.com; s=arc-20160816;
        b=JM+0CfTT+t+9q+Ah4Zxc8eDBVTdzgYcFD0Qb3MIJwY0C8IIP/N0wuP8aLZeXHiRMp6
         k4HhJKlIeullyO9WKD62tgQxkeoFNNY830cc/NrLiGkSc+xnmrnAJwr88yRMcjnxSO43
         CP65pQN4ZSN2ZtC35cXQkrImwVmtF18bHqu4oVlwQoN3Y8/PsOVkeoFOSeSQr28g3oBK
         tAq9s2rdsMhw1PcILCobCIQwqziI7mfs/3mPZaAnkZ6Bz46YxTbK/2BZKZB6GuiCBQAF
         SSNltKcd/yZj18C9XGNxWKhsKKlPhaTkBPXTyHOgS8s0JiDHL103Wc45Eu7BQ4Dayo8l
         Yz+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Jvq+cybeLraTdNHdwmxoPeT8vNzaVqvL51ipccSG63c=;
        b=0SLXplTs2We3yqaV9kuMy1IWEKCehWv/adW5ik4K3dLV06jvVkXJ2Xhg7/4ozL1m/F
         y3VT0sWfDgxkoEDmfi6C4ycUdAOpyGOgIdYJ9UID/aMQrF5dcPLkpX4rR4xwJBexRTE5
         Podyt2kwMUKaJqsKoRcLCq5GTf6c/Sb7IkOrEv/NOL1GUUNeLCSb2BWHeFD7fy2NCS5P
         9Q2lYg34znPXYYhQC3r4g8qz3/oZmm5X0VSJ2eN27V2+AHiHN5F1BZkx8AgyItFO9iFY
         /tMeNauQ0p+Lfj6AfEiTCJlLh3aN9VyXHShBfsDu4PbA+rjRuKPIOm2UsYchodQG+Wdq
         9UoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JtHsBail;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=Jvq+cybeLraTdNHdwmxoPeT8vNzaVqvL51ipccSG63c=;
        b=OgRsF7TNUhaHPVLsvRdawwTKpQlhhwZ/hdK6rENgvQIiWiZFTHBSy8ieZf9zmPXMB2
         MNI/ySzMSGms0u29XfQ1DzPnjVN/4NIWLPQZSHUbSQjplPuIINOpmJbs39F4GCVs7bKe
         jS84/hAKvxD+0zj4l9jjzJWYU4acOTFe1/iyZ2+GThNHjilIIQoBS5N9GTyH/rLermwz
         Y2KAiUWu3sxX5wBFKFZqtSHYRymMXlTsIh8sHwZzS+gFv9Puxde0mMnzkbJNqN4izGh+
         T1Wsa+Ab9nqEE+hVESqK1sMPFdSudFNP/o/dZfkrNPf1sF29k68BqaG50eFECKwQTw/8
         eozg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=Jvq+cybeLraTdNHdwmxoPeT8vNzaVqvL51ipccSG63c=;
        b=fFMGTStAeEhmAGJE1Ru6dvKQ7SU/E1Hia5LHf1n5SbkZE/wAOoykeDUdeUvvDZ+KcL
         QkjuVXQDqCn9LA9PHKZ4M+2JV2kVf6MaACtr8PpzJRYbkxR2LRU0vCprpjOGsxuBfpUz
         lz9BOxoCu/Lo2PdyzsRl+ctyNi5IW6uUECYOMAZImjveXV6Qylcns8ozKAsPFk8e+8Ex
         rWIGuhywLd5O/WlCTEuEVzCUyUpwZjA6Z+B5cTH9cseBc9KIsXE8fc/ebHTzIOphvc/b
         XVxDjMbCRCEdL73hNnRp/iVz407fQOi129v44wUHhWFDcu1VyW5JzhPYFb9fHRX6tl/R
         jnMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo26ptAHLZ7I/5bZSVqG6TOvn1uwth9ZWCAvNLIlECzTzf7wUaqq
	ZcnzyjxA2lp4eYX5YXQ/4Ug=
X-Google-Smtp-Source: AA6agR7fotoeVV4AUuwRdNEEU3bIpna75pL8qhhgF1ziCyJMfAdNu0gPhSjW/AdFLrur0mW4om1MWw==
X-Received: by 2002:a05:6000:81c:b0:22a:38f5:1a49 with SMTP id bt28-20020a056000081c00b0022a38f51a49mr12455160wrb.454.1663052090139;
        Mon, 12 Sep 2022 23:54:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f418:0:b0:3a5:24fe:28ff with SMTP id z24-20020a1cf418000000b003a524fe28ffls4676565wma.0.-pod-control-gmail;
 Mon, 12 Sep 2022 23:54:49 -0700 (PDT)
X-Received: by 2002:a05:600c:3512:b0:3a5:e9d3:d418 with SMTP id h18-20020a05600c351200b003a5e9d3d418mr1242176wmq.0.1663052089143;
        Mon, 12 Sep 2022 23:54:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663052089; cv=none;
        d=google.com; s=arc-20160816;
        b=OMe8i1a45zWZGRK1KvhEaEs2xL34jxarQMbF9QaBkmYFc5CEGU9d7nyndgW1WT7jRb
         mgVskSZAZEwfekxTRlM9ikh+wATKIump2d5UXYFAfogPc7L/NgBVVm7pRtHo8SXti8h0
         JcZsmtY+CRdoCSU63td8Y6knobB/0D6WP/Ur/ZB+pw/Pk+O6n0TIlknNORDP2vRfmDhX
         T8folrzs1ocTeN6RRM+xLz6CM1JvrDVeGcjgO1GxGgM2bYuDUwDuUn92Eth0N2giZ/U+
         hoWKLb4CsPsY0fM8Z8KtU6oQicXvna+JVngOrgcWM4tCPFR5qWo88QZHxC0SltQewY8e
         3sBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=FdYDyT2B17X665XR0+NBBp8BvSTa8XkSkT+0HlzuKu0=;
        b=eoqEovKIV7udY4DalDS+Z0Hrl2AVg2Gu5IBuXa7OgQ7xBvpTW5vCjTLvijKEswYtOz
         mZMOM5VAcsIvyyZ5+FxZmJramVUvm6vLqZvWdiKFaixCJPI/lUJTgcjNbvDI+RfWZ4sB
         HZdMK3ZGVeUYoXs1MQ7KrSnFRWSDn1dRbTzRVQScvKNI+BWdXxiDTcDun2YT93oGkJk4
         WPxAddAGtTrS9OFqSJYoiVO9NJgrNuTh62eBlXGNi+ZX1bTJ89Fh6WJ59BkT+t0l1El2
         O0EXYKZNPHRmd2BIo+/QVQiFB+0sO8AvLhdcPZqPgUVORnpy1nEdtxts0+v/J5f6ESV7
         Yj7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JtHsBail;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si13124wma.1.2022.09.12.23.54.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Sep 2022 23:54:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10468"; a="285079351"
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="285079351"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Sep 2022 23:54:46 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="861440697"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 12 Sep 2022 23:54:42 -0700
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
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v6 0/4] mm/slub: some debug enhancements for kmalloc
Date: Tue, 13 Sep 2022 14:54:19 +0800
Message-Id: <20220913065423.520159-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JtHsBail;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
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
could be allocated, so in worst case, there is around 50% memory space
waste.

The wastage is not a big issue for requests that get allocated/freed
quickly, but may cause problems with objects that have longer life time,
and there were some OOM cases in some extrem cases.

This patchset(4/4) tries to :
* Add a debug method to track each kmalloced object's wastage info,
  and show the call stack of original allocation (depends on
  SLAB_STORE_USER flag) (Patch 1)

* Extend the redzone sanity check to the extra kmalloced buffer than
  requested, to better detect un-legitimate access to it. (depends
  on SLAB_STORE_USER & SLAB_RED_ZONE) (Patch 2/3/4, while 2/3 are
  preparation patches)

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

Please help to review, thanks!

- Feng

---
Changelogs:

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

Feng Tang (4):
  mm/slub: enable debugging memory wasting of kmalloc
  mm/slub: only zero the requested size of buffer for kzalloc
  mm: kasan: Add free_meta size info in struct kasan_cache
  mm/slub: extend redzone check to extra allocated kmalloc space than
    requested

 Documentation/mm/slub.rst |  33 +++---
 include/linux/kasan.h     |   2 +
 include/linux/slab.h      |   2 +
 mm/kasan/common.c         |   2 +
 mm/slab.c                 |   7 +-
 mm/slab.h                 |   9 +-
 mm/slab_common.c          |   4 +
 mm/slub.c                 | 217 ++++++++++++++++++++++++++++++--------
 8 files changed, 214 insertions(+), 62 deletions(-)

--
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220913065423.520159-1-feng.tang%40intel.com.
