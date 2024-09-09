Return-Path: <kasan-dev+bncBDN7L7O25EIBBJE77G3AMGQE57TB6PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id CEF21970B34
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:13 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-45828d941f1sf13815401cf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845413; cv=pass;
        d=google.com; s=arc-20240605;
        b=RQ/DbnV42hCWV8sDa+OLbe8mcslcuL7hv6lLgk7ARQFBWBlPSFZDqh6paPdbBk77si
         TfXbL6U6HoyERbhttrKPtqrogf+SwItxEAsbo6uGJC/Uvp1Iaq7PIaYXED/3Q4ffrLQT
         R5GSj/c3tMSuSWUGJqaZedQRpAJf/1rAQIob5wfLp2iNx+YYSGoxmmdqTbwe1V3tuCq5
         /l5HKJjarGZVOvt3SbeflQMEvb5kPNz3J2QE+zHWyYvCdDxLglxvnWXfk3TzUSN4sw7d
         KvemO+vQazV2j6oTwPrX9ogkEFNFmsAvZp9d1ErwkvFncew/yVUtHdE44PxTXBr9IAkb
         CfHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OPxWDbuVJ4plbVOMzLshYWpCVuSIJROkjpC9xk/9qy8=;
        fh=LBXN8/nUy4Cxs/wI8vA8isD/H3JmxrwOxw4QU4UW4zQ=;
        b=hbysqFqtJzYP8Dn+f1AbZasuZhnneP/wHMQ/SQn8D2gD6DtsQ22fCjldyP1cFgIK9M
         sp8grIWc5TYtR6DystjWoAA9vPXJuyn5JNT7TH4SZ8MRzHnXVA4OSph0sG6ZH3dFM7BN
         6b26xMRQxtMN44lSl+4VbBJfZefpLapfJ1jGsyiJ8mzCTTR2aLbtudFk04wqtSb7Wneo
         O7fQu3cWKzt5A/Xroy5SCaxI38vOYdXodHhBeX2d+7InGg2wLEFStHdjdqXQ1DOwKVm9
         gO2TrKNc+766U/3XUpV4Y4PAMa97xkZvMZhm2QBiQNBxPEXF6qHbXYDsu3gLE9RfrPOW
         QNJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jDz1jhGK;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845413; x=1726450213; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OPxWDbuVJ4plbVOMzLshYWpCVuSIJROkjpC9xk/9qy8=;
        b=mKU+uBCLsqCB80MEdQjC3Op5ouP2fQt+sYWl1568Stgom1mCIvHn07WarEOCvVXYU4
         fKh/5d5eqc0ThFdrpuuxsbYfj9laZenM/WbvN7+/m25jNwTevQn8HyONcLva7dvdjAWU
         Zl8jCBdiFeXmjx11+sSYOPzB9/n7whQI6wL83Qpa9XBYC6Vql2bcSx6FNmWcxt0Mpk/d
         iESMr8vdU+Fw4PFcI6a3zKfajD7tlWspAsD6cpEjwckmTUkt32cBrUHIgL2iS9+giEL/
         KDDDdlEo8a/dTR5WesEf6q47kGRbvzCdQ9z6qADQyjggmCT89t/sgVWrR5YRRQUOTNDQ
         1PnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845413; x=1726450213;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OPxWDbuVJ4plbVOMzLshYWpCVuSIJROkjpC9xk/9qy8=;
        b=J9SUOPV6nJKCkvrrDYB+VUu61kOEfz+mKE1kEhKM/Rp1rx5EQaKHouinZzJMOOY0TD
         CeJ5qo6jSiTu4jxhLdbjpOtaBGpLQHD0Z/+6ZgT2THPKkCdOX7QWNjFu0SMHeW2EknBd
         8jP5uuwJ1kmTQPf4GF3SsG5HGg/W3hsxwMgRBdeBPFRLo0f2I4JM6o17IiDJq/JLPW+E
         bUXJv+OpzwGUcIH0aypjoYd+msWEa7s+ykXpmdQaVeM86+8sfAsDpf9uf9mulsxWBdWm
         sDF5vJf4+S5407rAbWF9CF7+W4feubC1iwBWzgZQFtCWCXIMcewjOwe9h5iEA92YGIzU
         goPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuwvhpZTxGwXjB/cYNXKWlLqJxiGCX+73b9YgtNF+dA5CNDz25LmnmgBTdLwhdGem9Dpi+cw==@lfdr.de
X-Gm-Message-State: AOJu0YxhyjKl2qcHNK6wGwC3oFtFVdgmkFgEaVGpSh9S8NHHtcd9y/qU
	D985yOaKCUjxDOl1nZQq9/Mcl5BmkMcGWmt7pRIS2s7It+ndoiUO
X-Google-Smtp-Source: AGHT+IE3z3F5gLdiCG2lHLNlaO/n9FbuHQkGZCe3DlUq+EHWhHiENolm0BNcK7tX6CljjiAOWP4l3g==
X-Received: by 2002:a05:622a:550:b0:458:368a:dd4e with SMTP id d75a77b69052e-458368ae666mr2119521cf.22.1725845412581;
        Sun, 08 Sep 2024 18:30:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:464a:0:b0:458:1588:173d with SMTP id d75a77b69052e-4581588193els21664411cf.1.-pod-prod-05-us;
 Sun, 08 Sep 2024 18:30:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXR/ntUSfuMkALor1m5IUYVTaSNSrI6eo2Uv59VEkpamueR9u0y0MiAiTY0SjkBqq83IzPkiks4xbY=@googlegroups.com
X-Received: by 2002:a05:620a:246:b0:7a9:9fd5:2e20 with SMTP id af79cd13be357-7a99fd52ef8mr682909785a.23.1725845411991;
        Sun, 08 Sep 2024 18:30:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845411; cv=none;
        d=google.com; s=arc-20240605;
        b=cGVklXzprF2UciibxWCwYxLw/fZ9MFpc5wHRURQINV0ivMgqRwX2ebQZ30xzH8PuHo
         OLzb33KXKAxYQNxVx00NbM2CuPUjttiqVNdRJ+O/GcpJxvU/HXBhYuyz3OEca8x4x+1k
         6qq1tchGKb7jYI+Fg6Acfmj7/HCaVb8fPnSNUsS6wL6ZbnN7iAEFf8Z2faQN1Ab70eOn
         p6hI/ti95d+KKlHcETtEApuFFluW5YF0Ij09wpsOVLa0FMh4tebXVNieKiPPsrmbOdV+
         W02pxmej7eX9ASRhoZMtXL7HhUl6VW4AwMfLl3IZFi2GzucrTHqIQciIuGwMF4x3FzfZ
         d6hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2rD/2vlH1Beqh3HFAyv0sq8bJP93CMB8SMvlgU7yd5k=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=WiD2q2EqWcJBiJPLUD44kEGq09nTeTxgNydiKEsgri+jLBKH/wEsi1WlrLK2mzEQp1
         EsQU75WvP6beaRorFxeANHnQj0PFClo922wsIt5aCrJ004Zi05uFXYlGNsE98G2j9zGY
         SAdrfWh/RWEJlqlMDUerIHkmGp/LTPeZ0UiEY7gvUvZi0d/vxtQpxwJSolLEm6dc8wC6
         jbQFR3P2TjgbRfZ7EFxkjTerRWbwvJHCmAzMCOo3nFsg+xEp2psHnt+EWwF/0qHAaqnu
         Cl05NGfscX3Ir/PQw/qOX/wPVW3CGcZZqWU4j7tsViNmzYmavsNdcnr8OZLVRVNEKDAL
         56aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jDz1jhGK;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: Uz4/+d/6QUC8mEblgG2Igw==
X-CSE-MsgGUID: jFtRHxcQThKihaS3gsiaQg==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258113"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258113"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:11 -0700
X-CSE-ConnectionGUID: DjU4Ii44RO+mC+79SYUM9Q==
X-CSE-MsgGUID: wZvquO98SZKlH1AaBHu3rw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486450"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:30:07 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH 2/5] mm/slub: Consider kfence case for get_orig_size()
Date: Mon,  9 Sep 2024 09:29:55 +0800
Message-Id: <20240909012958.913438-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jDz1jhGK;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as
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

When 'orig_size' of kmalloc object is enabled by debug option, it
should either contains the actual requested size or the cache's
'object_size'.

But it's not true if that object is a kfence-allocated one, and its
'orig_size' in metadata could be zero or other values. This is not
a big issue for current 'orig_size' usage, as init_object() and
check_object() during alloc/free process will be skipped for kfence
addresses.

As 'orig_size' will be used by some function block like krealloc(),
handle it by returning the 'object_size' in get_orig_size() for
kfence addresses.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 996a72fa6f62..4cb3822dba08 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -768,7 +768,7 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
 {
 	void *p = kasan_reset_tag(object);
 
-	if (!slub_debug_orig_size(s))
+	if (!slub_debug_orig_size(s) || is_kfence_address(object))
 		return s->object_size;
 
 	p += get_info_end(s);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-3-feng.tang%40intel.com.
