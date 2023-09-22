Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBZH3WSUAMGQEETLIMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 69E437AA9C5
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:10:30 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ba1949656bsf22776151fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:10:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695366630; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jx2XT+m6HOPHmgj5jq38+dg8kYGHz1wGFMHMpSYowijwzvP6rNQF2GJ1dTGzSZYOBE
         WtnLEbNR0cHKUbD8+2WkPwhtBvz3BT9++a6bSTxVYMsVwEkZIz9ott6KFzGiOlZCv1jl
         3I+a0qg772NIsYaP/HAAouYC6s0u/714JqqaVxop0EzPAdNEjtHKrxoyO+vJOoKPg6Eb
         0rascpRXHz8Boz/we/+Zro13zb9VYQ2JvmbPZ2b/zao+XbcEvZFhHducEvBfRn0OCjw7
         kE1+tZb9DOloszjPkTMgyVUhrzX8dOwKUm+9uoL6Oizufu48abva5RBK9RTWz4OY0WoR
         VMKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Aqz8OTa8YZ15KF6kJrJYDlllG01uC9H52WpK1N+1xrQ=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=MU1D9C97BqFoEucm+0kxI2kyBUM7ncNei3q7pc7IPXHz9roEd/P3ZtBlXRvstfp4DH
         HQnGXEkagdylmUUv6fW5h3ba3MZYJ62FNjEE8eXnGJGlrEl3TttugSseSRwc+WQ+Q51a
         aSs2DVFVmL2oRmYZxCS8dZWoETURnvJEP3VndD6MHPUf171xsjOaahH2gVVH0nsRbMBL
         r8BzXcZO/qZZpP7krgY2YtecdE7SOwLJsHexCOJ7w+3F3Fv+Ct8HDVnlJYNUDevDbfvg
         t8IZKpGzZI3uW/H5b5aniAncC01AsjVh0wF3cUFhZO/UzzY1kx2mzm56wbGiU+CHfz5S
         q5Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fPPxKFrT;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.217 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695366630; x=1695971430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Aqz8OTa8YZ15KF6kJrJYDlllG01uC9H52WpK1N+1xrQ=;
        b=NhpDj747hytRcIgMiI0zoHxLZ2p/Ar6BR/01ydEJW7punuu9zI6M4Jl0RbFpUZ0IKv
         SHpdKcyZ/MP+NkboSd1NqfFpwRH0xeMgxR45+4kFgD3nF7HKGMgy8lObqH1dkdQoCz+i
         hQyeWWAxawsLJKA9TRhhAkEhkipKj8aibw8Mj1bAedwlNkG9sXJ3O7eKTavYlpHoRzfb
         qjKO7i+tVpnZBHTAtBc6Bk9BQGtrZN3VXIWuh5u/ObIG/9rIBKnx+XfYWDdKtWzIFbDi
         NXYIOH/HHxNVfIyp0alXKyDcwK3tjryQD9Qf5KlV/fF8mZApzwn6FOoX6DeYQdDb1ZnB
         arBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695366630; x=1695971430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Aqz8OTa8YZ15KF6kJrJYDlllG01uC9H52WpK1N+1xrQ=;
        b=s17VdW7k2RkA5gM9vkdIWKwNRLbrTa0I2UaXS6p0tzMlc5ZYolVc3N9STBFmBB7QF+
         J8HYMnCKBBsz0NlHgGzTLufFmwf0it0F9ZbLCFtZ7E6VuVoUaCKgWYyRbV4rV5+JqvYM
         yVj32/unOPgJWN+xE4Hza+j4TWRyeOKHglOSoKRsWzjsop8IgkUgaem9jx17BD6E5nG1
         /f5frws9U+AGYgN4P9L9kmJqJoT6LXbW6kqu8Hd8UlI7zSDA241LQcnm5OMHRwIP/PZe
         E9I7ugFJYnpetUGQMYNsVTdlIuj6pcIq2VLX2xu6xuanWPA6znmq8Ne1R24Dx/Ra3Pzo
         0oZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxikJ2s6ObJPyGIlFVI8zZHC/gghjoplkN0OtMOX88JjvE1CiW/
	UCyiqfpEBf928JlFRtEQ2qk=
X-Google-Smtp-Source: AGHT+IHIj/TTLGGiJrJk9QWMZ1qkhv9Z6epQJ29SWN9ovXLfQq3x25rbH30KX9peXIsrha9zGEc8gg==
X-Received: by 2002:a2e:870a:0:b0:2bf:a961:2374 with SMTP id m10-20020a2e870a000000b002bfa9612374mr6409875lji.47.1695366628395;
        Fri, 22 Sep 2023 00:10:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:205b:b0:2bc:da88:b686 with SMTP id
 t27-20020a05651c205b00b002bcda88b686ls116524ljo.0.-pod-prod-01-eu; Fri, 22
 Sep 2023 00:10:26 -0700 (PDT)
X-Received: by 2002:ac2:4642:0:b0:503:36cb:5433 with SMTP id s2-20020ac24642000000b0050336cb5433mr6695842lfo.6.1695366626414;
        Fri, 22 Sep 2023 00:10:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695366626; cv=none;
        d=google.com; s=arc-20160816;
        b=A9FyAQcXyrQNonsKfK4sYd1JmrIH1exQukYQsDUqcqTz5ga9UsjKn/NjODhPZ9iEI0
         PcyAxsMBePjPPiKgFIDxwmYK9qHJ/S94OH5pKAmh2hTtXZ9GG0Yscu0WvdFMCjbdrVff
         VTUWzk9nGNR7rjuV2zVkrmKI2cbb8IIFEE3jm9GYxqgedhrd/8Hqzgqu1fttcy1AzUcu
         Rhb8FqLj7Foiyt0W6VQcjHFSCLBvI+DAntrEKNWYkeLmt+eRWZ0EUMnLGlUGfeijQUV1
         fu4npyYbU5rwMe8YUheNZ3v1bvgn4BaQ9msh+1DDVrhUwIuvf5PqTY0DTaKMF5QokSlb
         koJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0NMcmRX/w2n3M3EQea1/2ZhpgRQyZV6LdD1tfFyUHrY=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=vkC9YjNZAVrMH/+K8xbgDy+XAd66tWe7f5W+UBoL42adEzEgQ0vp7DNShaj4FNKCDw
         31ymnoLebzjfhF0l8RjgYFgHLnvO7md9Ldm3bCk5cSL7bPkIPHEGpG8dv1xU5acBXUmo
         xaV5sUevNf3dQAL7z38jJ98PNoB04vOgDNiFT8Dq6GpiKz0xr1ivLNUUr83ozf765lld
         Krj3+6j94CnYTSz2SLeDpLfAI7rnkR/4W1ABNWB4y+i4lOzo2P+b/w11qQNhpI61gBr0
         in4Yqq/jSdX+F7zriKesIFKJryoOPqKaH3YzEyr1FW9Yzk4CGefScRayNxDZm1orDHtm
         Z0KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fPPxKFrT;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.217 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-217.mta0.migadu.com (out-217.mta0.migadu.com. [91.218.175.217])
        by gmr-mx.google.com with ESMTPS id g19-20020a056402321300b0051fe05f750asi286403eda.2.2023.09.22.00.10.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:10:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 91.218.175.217 as permitted sender) client-ip=91.218.175.217;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
To: akpm@linux-foundation.org,
	mike.kravetz@oracle.com,
	muchun.song@linux.dev,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	rppt@kernel.org,
	david@redhat.com,
	osalvador@suse.de
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yajun Deng <yajun.deng@linux.dev>
Subject: [PATCH 4/4] mm: don't set page count in deferred_init_pages
Date: Fri, 22 Sep 2023 15:09:23 +0800
Message-Id: <20230922070923.355656-5-yajun.deng@linux.dev>
In-Reply-To: <20230922070923.355656-1-yajun.deng@linux.dev>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fPPxKFrT;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 91.218.175.217 as
 permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

The operations of page count in deferred_init_pages and deferred_free_range
is the opposite operation. It's unnecessary and time-consuming.

Don't set page count in deferred_init_pages, as it'll be reset later.

The following data was tested on an x86 machine with 190GB of RAM.

before:
node 0 deferred pages initialised in 78ms

after:
node 0 deferred pages initialised in 72ms

Signed-off-by: Yajun Deng <yajun.deng@linux.dev>
---
 mm/mm_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/mm_init.c b/mm/mm_init.c
index 1cc310f706a9..fe78f6916c66 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1984,7 +1984,7 @@ static void __init deferred_free_range(unsigned long pfn,
 	if (nr_pages == MAX_ORDER_NR_PAGES && IS_MAX_ORDER_ALIGNED(pfn)) {
 		for (i = 0; i < nr_pages; i += pageblock_nr_pages)
 			set_pageblock_migratetype(page + i, MIGRATE_MOVABLE);
-		__free_pages_core(page, MAX_ORDER, MEMINIT_LATE);
+		__free_pages_core(page, MAX_ORDER, MEMINIT_EARLY);
 		return;
 	}
 
@@ -1994,7 +1994,7 @@ static void __init deferred_free_range(unsigned long pfn,
 	for (i = 0; i < nr_pages; i++, page++, pfn++) {
 		if (pageblock_aligned(pfn))
 			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
-		__free_pages_core(page, 0, MEMINIT_LATE);
+		__free_pages_core(page, 0, MEMINIT_EARLY);
 	}
 }
 
@@ -2068,7 +2068,7 @@ static unsigned long  __init deferred_init_pages(struct zone *zone,
 		} else {
 			page++;
 		}
-		__init_single_page(page, pfn, zid, nid, true, false);
+		__init_single_page(page, pfn, zid, nid, false, false);
 		nr_pages++;
 	}
 	return (nr_pages);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922070923.355656-5-yajun.deng%40linux.dev.
