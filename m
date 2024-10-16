Return-Path: <kasan-dev+bncBDN7L7O25EIBBSV5X64AMGQEKMIRVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CD839A0EB4
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:42:04 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6cbe3ff272bsf128288216d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:42:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729093323; cv=pass;
        d=google.com; s=arc-20240605;
        b=CrcGe3cM3hkOhRw9E8tfkvPler/ItBWjc2bWnEwWBKIewOliFXvl8MsATWletC2Fa4
         CefCXh6yrlpYhrffwHK4VEZgKgXxJmqzEFL9MQdp7zNF+0rq9G7S5Wgfzy4ZuZ4Mf9sZ
         PolrPNRIjMwhP5+qnHQHcqxdjwjxIBXQ4tYwxPJEzpLHLGT8rBvVQokplKHmCITaoro6
         Apqt6iATBVrp0uLgyHiDuSr6tAiOYIlKXfLmOhJ0vtrDX8Km6SlqVh/RGPK9/RxVPZQ4
         i1xlsP+9WeX90lQQf1dO8+sVQ0MO8+1IH8cJWenzfaQzQEHKbC3soAuAd+nEgqW3EPwj
         JJPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mNFb48ApcVTg7cPoDX38YFsbtmy0OG/py/WScsoSTsQ=;
        fh=0U2AlE1B6jKNEmTKFCf1Y3/Tus5LLkrMRzOPWFchgVQ=;
        b=bqJKu+a7f+LgK/ZHQojcPyc6xCUfKVSlC+aBjWybb4g+xmJudSC7qknClpE5aHIu2s
         wFTAQEUfTHk8g5KIhdcCCpoVjPFtvYkzOCYUTfWIZBnB3LyqXU7a5L0ZUZK8femNHcgy
         vQm+eF9L/vtNyIu3/K9nbU4K0l9Z42CPqwGz8sdWZTLu1I+nIu8rlYLghCw48H5il9WS
         gboB7lAY9YfEEOEI7Ml/eGLv4odXEU6PLn5+LMq4MwU7LxclmCXDkbH7GnWpfH2RwjU/
         JmnReaxez9UqdV1WxY/O34fqBpgBj9XjP99aHFJQ1mUFx/qDdjRnaz2yACbK56NZK2fk
         uQGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ub8EXjkf;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729093323; x=1729698123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mNFb48ApcVTg7cPoDX38YFsbtmy0OG/py/WScsoSTsQ=;
        b=MnhSxBbTyyH6nhl+oFv/LkjmXlxilQpXKM0njhFLRxZBMH6l9K5uWdAGsKVwbm0+t/
         igA+vDDPpf/0/VSkAxhGzZodeMf+oTy8Ue8txZf6E9+Y0V6vg2u7r0w7Bq2jCe1LXAdb
         QPB7YGZv377lx5j4mdJBdj2ANYWQlhwTROu/VRQIOuXc+qBmerpeZBwaB5ROUOq+RFpN
         mNxJe0Z4lJbXoUvX8Ioj4Ii1voTr7vr/WJwTK/YO6eQcCxeQEzCn5RDCjDt1XANvkYXM
         TySLEeK2x6YkK+Vn65F+lILFG2LHuZW5Q+PS2v8wIvtqGNyIGEOuapY1hs8bIwJFnfds
         9m5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729093323; x=1729698123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mNFb48ApcVTg7cPoDX38YFsbtmy0OG/py/WScsoSTsQ=;
        b=ZGpmPV1Eku6KaED5tfXkOelbgV8XxDVS9Ko3aNKZxbKGit7I08OV0x5MmWBIUdFlL6
         3U5qrl7GnaL+EzwjkQ9WkwI1GeH1OwlLN8yStj2thX2sLcloHjvUZzH+gTgW501/mxJN
         PUie/Gjbwj8d5Z73sZrm6iheiwQpd7XbS0cVQ9LQAFffnM5kqEuUJ57Yx+IBQDArHC3K
         /kXl4bgAzCjeoSsMNbjQMla9sIPQALmRNSXguOqWgTPa4P0s+8WERMXtjJoDeTGchSop
         7hPG8nB/8tbqcua3RuD3bSVojTJof88Tr6yFxvVcvL3Dli7lOut8jfAv2nsiq9M6P8ga
         +spA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbpxTlaaG671wtz6Jq7AOSWpTtvbPyXd2e5dTbZ0AKqFpvhdIYogbaHLk1bnHO1ZwfrpFIIA==@lfdr.de
X-Gm-Message-State: AOJu0Yzpj/ff2WLolXEdPXF0P/NvQflNb8DjfQAph4QbkTMn/D01pfhN
	pEYS8GAxsfwMM7ZbTBOt3IoTW2MEUD7D8c6pFz2GAWwbdB2iQtBj
X-Google-Smtp-Source: AGHT+IEbp4CNFU25C57zx4xjvwTfKY6CRVhiC9xmSS0xNNhWrptvLgXls5ttvHQpL+6w7Zox9S1WvQ==
X-Received: by 2002:a05:6214:3b84:b0:6cb:c54c:b782 with SMTP id 6a1803df08f44-6cc2b91a5d2mr53205866d6.32.1729093322184;
        Wed, 16 Oct 2024 08:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:629:b0:6b5:da50:ac19 with SMTP id
 6a1803df08f44-6cc375c2fe3ls496126d6.2.-pod-prod-07-us; Wed, 16 Oct 2024
 08:42:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWiV15aALHjW9M8Ot3IFWQ9ZV2TcdnOxvv/527DrVa3v8SsDpuYKC1j8HTJEjbj3/U0cNGD/Bvn698=@googlegroups.com
X-Received: by 2002:a05:6102:ccd:b0:4a4:8a29:a902 with SMTP id ada2fe7eead31-4a5b59394aemr4075968137.3.1729093321545;
        Wed, 16 Oct 2024 08:42:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729093321; cv=none;
        d=google.com; s=arc-20240605;
        b=Emy7EnFSbTP+7vD0BtpJzfpEoQL5vy/n2uYvLeKDz9GXSBECziyvxYjYGFpfydNWrg
         jUkm5bOHVmTnQQfISlfM/l8yDv7bT3EGbwOIG056cG4RKhu1Dbb2x0z88mHeZtvcCH+X
         d+ztVX/cDnJSRUo/jzbGktsRCSE/0tT6i6hraf+ezX6X0A0Of6rMdDxPHjMRHO0tBsu0
         Z3qoRAwsZBop6mR6viaV4GJiFQPO8HAdFDO9prCh7PvlEK6UrlOSpwsZQzXC1HaU9IQF
         cH2oGEGw9i750FrQ0qHSembIYcUNRoX2GBV15s24nqUG5hUUlx+1qfPHmBl4jCHaXwVg
         +CAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g4wtmCSOL20OH1846ssdNZijDKNqe+VpFdtBicgceqw=;
        fh=7lbPjXPBrR8dSgG7ysvKWnMIE29dr8yWrocKYwe0ENg=;
        b=lROCA041M1kCINq+7O1ZJIk2Ft69DrZltbumJY6e/fikAeTw+Sm6vDpzkjIQloER/T
         M/N2m96q7YadUrAVSJfh09UvIccUAOsfxjx1p9kxWOwGxin/6Loa6WduZ/ng8nY6bpdP
         YeyI1WNN9xbatKc0ZxBKkc8Ua97PFwFnqOfy6hrCjI00ElahDxMCGhgktNQJXkCfiXD8
         xGZ1WZfhdK8OOp/lCI+sb4UfbPmgYkGPjK074xapdMWb/pyuB1VCT0p9bl4GsA9Cq+jR
         8RZ+j7ZMuJ/oEqERuCy0GuLmVWcvyP+7NxZBkJBvdppZ384fl9OdwSbJKrPQfiwtZ+Gr
         9bTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ub8EXjkf;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a5acc321fbsi175313137.2.2024.10.16.08.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Oct 2024 08:42:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: gQ8D1OpWQPegHFLi4aAj9g==
X-CSE-MsgGUID: sdrjfmR9ROyo7KSxtb7ksw==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="46021341"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="46021341"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Oct 2024 08:42:01 -0700
X-CSE-ConnectionGUID: +cn8A2teRjqp+D+KyviP2Q==
X-CSE-MsgGUID: 8UoO9yu/TrqGqxq22dttoQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,208,1725346800"; 
   d="scan'208";a="109018906"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by fmviesa001.fm.intel.com with ESMTP; 16 Oct 2024 08:41:57 -0700
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
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Narasimhan.V@amd.com
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v3 1/3] mm/slub: Consider kfence case for get_orig_size()
Date: Wed, 16 Oct 2024 23:41:50 +0800
Message-Id: <20241016154152.1376492-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241016154152.1376492-1-feng.tang@intel.com>
References: <20241016154152.1376492-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ub8EXjkf;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as
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

But it's not true if that object is a kfence-allocated one, and the
data at 'orig_size' offset of metadata could be zero or other values.
This is not a big issue for current 'orig_size' usage, as init_object()
and check_object() during alloc/free process will be skipped for kfence
addresses. But it could cause trouble for other usage in future.

Use the existing kfence helper kfence_ksize() which can return the
real original request size.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slub.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index af9a80071fe0..1d348899f7a3 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -768,6 +768,9 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
 {
 	void *p = kasan_reset_tag(object);
 
+	if (is_kfence_address(object))
+		return kfence_ksize(object);
+
 	if (!slub_debug_orig_size(s))
 		return s->object_size;
 
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016154152.1376492-2-feng.tang%40intel.com.
