Return-Path: <kasan-dev+bncBDN7L7O25EIBB7EH4GMAMGQEXSZL4XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 15EFE5AFD1F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:10:58 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id t11-20020adfba4b000000b00226eb5f7564sf3272233wrg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:10:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662534652; cv=pass;
        d=google.com; s=arc-20160816;
        b=bI7n3faXV5/JHZ3BbNdh4332g4CULVkDyEWbLGGFiJg1xH/FweqG47/KvLB65DiO5x
         khfQDFK/XhVZ6AxElWoVM+baGYKU7rDnH6r5R5xpc0e6nTIjM5bpYqWs7tWme42YFWQo
         eJXekEYtlXZTzZMbGV6MnXAfE0hWKY8g3NC417jwiMuHgNia1T4ec4pasP7DWQqy2iuY
         hj3LokO7t37AE6iX9jvttkI3stSDStJeymlIMzGlOh6h88BfyM+04lV2yk7YFi7k5h3/
         t5cGnlF9g33klyjGTtJBU9jAoZ3i6FDahMGkpvIqvvgA5uLvtpRsNrCVLy7rviGS5sFT
         9VVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PyfgSu4Fooqg7Nm8ncH3drRclxF0IUdtC9DcNkJgq3U=;
        b=qJWiFiX5Pe1dRBv0nVAvT/AInf5ks85GmVdyJMWQ9kNhD/wGv7/mf9iDOSBunlC5Ni
         SD5s0uKAH2sJ+4KOxeOGZt+RSLM4bLEm3UJ49o3/OvVBj6qqQlX9f1a0cD9A2XVKvI57
         DRnstMbaVj7QCmlKzhKF6lE4LNt1Cr9qmdPtD/UcJv5xrsTJIl4MJRxPhyatAD7ZJKfj
         ovR7aw7BT2r5B283Ja8JAlg3SB4vMY7Wbu0Zmtm7TAUspGq53gZtDxB6JbWFseJHaA+8
         7IJTarMBh0rz21MyV7F+iwlyT9TD1j+KypHBgqtBgMZTwiTo+H4LGGhqcBc0GaM91jPj
         dHrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ej4nw5fq;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=PyfgSu4Fooqg7Nm8ncH3drRclxF0IUdtC9DcNkJgq3U=;
        b=bBgpu5l4qWvVZ3rvAqNr1nwt1GuYxof47oVwd4vBgbkLfkZqvbEYkyf3wk4pn0CP/E
         0J+20CiWoAFEo+QIv6YX+ui8QQeo5fNyPckVUbcNslc0HthSuKEbIV7NF554zVl41BN/
         /YgrKPW2Sq5Iw/pWqhVuJzlFDaV5GaQV71oi/eFaKADcgSobfVCcQo4MSNmkj2xe93gH
         xNQGPpg2orErQpUM9+zAQtTLQejzkJ1D6jba7pfCzDFSDAvD94HipzjX23RPwrNWCmV3
         Y0kz5+8BIgArRjLQ3N6c/xBy3KU1hE7Tni7ive1AV6kzYPsQOuQqyEqzKRbSP10iRGe0
         QLhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=PyfgSu4Fooqg7Nm8ncH3drRclxF0IUdtC9DcNkJgq3U=;
        b=aoOW59q25HC2LM/MJHjPUVOoN12KsbsORSA9LEslpaptMW+fpv1tZ0WAiylc3fgZcN
         eEleNa5almN1QlgiIh5e6YvRedpdkfdAU92yPtR5X8VgjpnMCqhCRynp18sDQugcFfhQ
         jTvAY32axAvHufLZ3/5ND/T7ZOrqVMHyno0GmNhYI7u5anxgPiLpZJJZZ7PrXEaKA8No
         jRRc2HfUNZILzDZltcGrkkDeul8Nc2mXL5Ps+nk7cev2bsJILtV5lvB+nT8iWPKh16AN
         u8Y/KwW+xaIq0gL612Z3EBby9/sfwNh97CTy6UrQ0u/rEKfQ9K3XZDd1wjhCUphJNcxf
         w6EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Wpm+zIcxnEUQrdxlanwH3Bel4NjcANz92tN+xbBVmlxWx4f+s
	c4xIYKCmFVbpi28HyBgGrh4=
X-Google-Smtp-Source: AA6agR5RiorFdBjDagCJLh6J9LoP0WS/L3C6m8P1HmAKSZ4/xPvljJwpw0Zasejh6gcR4AWnZFDedQ==
X-Received: by 2002:adf:e9c2:0:b0:228:62a5:a59b with SMTP id l2-20020adfe9c2000000b0022862a5a59bmr1089554wrn.47.1662534652530;
        Wed, 07 Sep 2022 00:10:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls547635wrt.1.-pod-prod-gmail;
 Wed, 07 Sep 2022 00:10:51 -0700 (PDT)
X-Received: by 2002:a5d:6d46:0:b0:21f:8b7:4c1d with SMTP id k6-20020a5d6d46000000b0021f08b74c1dmr1091423wri.455.1662534651372;
        Wed, 07 Sep 2022 00:10:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662534651; cv=none;
        d=google.com; s=arc-20160816;
        b=jzlyN39OmQ8JxCQ6/tQXhO5jEbRjlg85DLyt3GFuB3xsbCCMvixmqYmHvPJEQGxhqu
         srd7sAyPdQC7GNFT0Hs7sIexjFJxrWMu8ilaMwNhjZD4Yv9E25NvslCl4gUIsTb3uZbF
         ChyW2NKHUw+Ip7Io/iuY5JkjOL0TZMxsv6h0rrwECFo/ttFG1Td/gG5sz0kqzxCCh8l+
         6CHGCjOGvFX/0mzKLZii1YTGNmcDsUnjQDwBBt8ZbEkNcwdf4GQmkOrYo/K6FVpJxnfu
         gZf01Qt8gc31KN2Bdtw4ZfVOaK3kkSEjvcXuYM7NCjQkCMHNIiUh07J9lo/m3eATkRY7
         r4PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7vGaJ+8rR4sKenXyQevhftma18DmMyFcMlRG/iZVWcM=;
        b=IsFRgggB6QBpA2OJlrgn2eJ8hOXjVg8+kzdhXGV2rvj66khvDu6zqHT48jH+RFg04j
         oBcn5byY7UJmMRvCUX4+XvJ4IZ0DoAhqw0SPDVg3OMQ45xG8qgHPoAeKGsINnDk0Dihi
         eO1XDcSBkkonqrDxR8mQBv875dOwla1gFTILSK20uraw8JD6mPHg//STn0RDIdxo/O6h
         PL4X5dq7KtKLpE7iFA6eWVGpZnA9BOm47BCsGs+YoXrFwNDpmxn6FIcz422+INPhEvNO
         1njsovmDLhpHaKb7Ik6kpgTLCCiHyZco143hRyGEM1SGWA4ptBAH98Qeu9HtT5AHr7tR
         kQPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ej4nw5fq;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id y18-20020a05600c365200b003a5ce2af2c7si724421wmq.1.2022.09.07.00.10.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:10:51 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10462"; a="298115253"
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="298115253"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Sep 2022 00:10:49 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="676053353"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 07 Sep 2022 00:10:45 -0700
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
	Jonathan Corbet <corbet@lwn.net>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v5 0/4] mm/slub: some debug enhancements for kmalloc
Date: Wed,  7 Sep 2022 15:10:19 +0800
Message-Id: <20220907071023.3838692-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ej4nw5fq;       spf=softfail
 (google.com: domain of transitioning feng.tang@intel.com does not designate
 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

This patchset tries to :
* Add a debug method to track each kmalloced object's wastage info,
  and show the call stack of original allocation (depends on
  SLAB_STORE_USER flag)
* Extend the redzone sanity check to the extra kmalloced buffer than
  requested, to better detect un-legitimate access to it. (depends
  on SLAB_STORE_USER & SLAB_RED_ZONE)

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
 mm/slab.c                 |   6 +-
 mm/slab.h                 |  13 ++-
 mm/slab_common.c          |   4 +
 mm/slub.c                 | 219 ++++++++++++++++++++++++++++++--------
 8 files changed, 220 insertions(+), 61 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-1-feng.tang%40intel.com.
