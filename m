Return-Path: <kasan-dev+bncBC7OD3FKWUERBPGE6GXQMGQEPEINVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F2CC885D9A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:18 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5a10683780dsf978551eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039037; cv=pass;
        d=google.com; s=arc-20160816;
        b=RePlSXC70PERHB/QW3ScVsLHulTtZP7Pn0LeIBPG1bjzXT7oFdLKoD/cKBE+XNp/up
         nJ50V9cOnbo+bVX9WPpghqbndNpxCDjK4okHAL5E2mY63kyoY+7fOy0PnOaFh1ogY5mH
         Iog82vbmmH6drefVMUSVPK1ysTzqE3JMBA1TW9xPkW8JmFvERA33x9akfmv3xHJMvu/n
         KpcoPFLnJl/bHFs0c/fABE4M8vF7AKZfjEN25qUZDfffOnu9RXPxm5kfr2+lH24owknI
         EqZKmQzem00rh8GKrOUkFElvaAgECqscxxJIvmAuca3zYXEuGDNLt2RuLO3SRNrTA4FS
         MDzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=BTTm6oDKbWOnidvvjwNUSHseXWoJlEtk5JSSOXgJRUk=;
        fh=uag72cDJtHejtjgfnuzIxhozkjshBn5cuQFUoJf7d98=;
        b=phcfvSCxRIMqSlxVKdMDptk4rTnkwTxwBkRKc54ld+bXXs/WkgKMCbhyvO3lYg7B00
         No6FRF9LYrs2zF6OylbrrMQ7W8CBznsNH8MtSk0Nhc99nhzgEXs9CaJC3RlrAdTZwdmb
         jiJme/Vr5457oZD0bfR5rMB8lsFQHCMF8DkHruvO7O3hlu+EqYNBiqqVbw03kJdYkmvT
         C9PcDh+GukuD02rfvUZKY9BJO9b/wQUjnIjOgk0/zPI/wmBqlzRqeZmRM04NcNYIMMS+
         Yb1UtKQ9PE+Wrk7TS08xRVlCkN5tYOXRz6ev4mR09AMABzdjyqtGFfGE6yRTeA6XpijW
         k+rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JA8oQDDK;
       spf=pass (google.com: domain of 3oml8zqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OmL8ZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039037; x=1711643837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BTTm6oDKbWOnidvvjwNUSHseXWoJlEtk5JSSOXgJRUk=;
        b=p4EJDHcaA1u5Eg9AFnkBPtC4AnFqUpmnyd4t5FR3iwu3R/KC5ZLBh3FBzyxMDkqB2V
         OLZ+PwYHOYEE6bUWwdVYENVNvYga6ubvmrtlAUAkv8UBCaNJi6IUP8xl0G4AModckvHK
         BmM72vz7pOCQhdG+PytJj0nGLzaiO9ZSyaaOGiksCMaoH/PnZMZrhKfLi6FNa5CItMxh
         zZ8RbDSJVDmnb62mXztm/9dFI4gxA+42kUvEFiQ989IVr2A5p2v+zGfDVOxtEsWDJbwV
         +utCyFojgD7N+7A2yuhLFsyYLgxfcMtTF1t3QlerxK/0OXE1/UM0x81x1Kdzxa19C8V0
         PFgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039037; x=1711643837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BTTm6oDKbWOnidvvjwNUSHseXWoJlEtk5JSSOXgJRUk=;
        b=pqXUpsbnKexagL3BIaMZf1gixWMeVXbOKFyK1tU1nlpJwhYX0MWw6zhh7N6+u2LxJv
         Qi2LfRdPApz+nId1gatCJvhwxhGdt9ZEHhJcZHnzA/zmFxtgYIY+vy2uB/7YwZ9JMvBS
         dtsttLiZBxsJICx908Ns57FZDUbHx3DdUuYWHhOvObo+i4xA5CSVg8De23ShcqxpfW2y
         dRbal/eXS7Wn/4w7Htf3ShMvhX7FraA7fyg3oKVrZQ892/iGTSrkHj7kTESG27HrEXf4
         F7gfaivWr0Zn7HcjknXsgJVwN5miev5a0QTimzjisXWqrRQL6SoDEsjgI7EBlTU1Qbzf
         V78w==
X-Forwarded-Encrypted: i=2; AJvYcCXpzrOwKlUiGy5KM1TqdSpfbeh/KjK8yEHtya9LtfUQ9eX0A+WTGMDHDNW2CVY6XatPRB1UkMfnyXegRMeR/U3ogGyPmK5wdQ==
X-Gm-Message-State: AOJu0YxhlGwDK2XsoV5+uk2j8NWwjCCHc9n+oq6lPB8wLVHdrKgkhlu0
	l+xpvrJzKqILfy2My3F7hcZNJM0OTZNnDOHlEvqwoEI3ui5uosYD
X-Google-Smtp-Source: AGHT+IG9cPVdHg3JMImKzYqE3AEBGQCzR4cZB3duaCEEugXNHHI7GcG7GT6BOiJf7GFsOWR9XsxxCQ==
X-Received: by 2002:a05:6820:1f06:b0:5a1:23a6:e4b9 with SMTP id dl6-20020a0568201f0600b005a123a6e4b9mr23078oob.3.1711039036989;
        Thu, 21 Mar 2024 09:37:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e1c7:0:b0:5a4:f1d4:44cd with SMTP id n7-20020a4ae1c7000000b005a4f1d444cdls955515oot.2.-pod-prod-04-us;
 Thu, 21 Mar 2024 09:37:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdoUXa4kFB5h/hxz77rq73eedKmQmY/h1MhQp6xQOzqOSytb4MLOmH3fxw6/7DzOSFoI4DCB3EZQLZcUAvQ2ApdMNnP6IudMx4OA==
X-Received: by 2002:a05:6830:1d9c:b0:6e6:b560:60f2 with SMTP id y28-20020a0568301d9c00b006e6b56060f2mr1466397oti.30.1711039035361;
        Thu, 21 Mar 2024 09:37:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039035; cv=none;
        d=google.com; s=arc-20160816;
        b=jceCRp+VOPCMtg5oSUnz9+VTqKpxh6mofG1vtx7p/Yz3I1s20DTC3/VPnaabXUR8E2
         psBhMFF5xSzYlMPAaCTXvT54Ep5LKPO/Gp5QtoC2uDypS8Yoym0f9vai2u819Tq30YWK
         TtboIZcryZAjhfV/wE3gf2ODDArKd8t54ZGln3HoeD2Vc9CgSRPFkmfffft9oT86YOzO
         p4o1W/6Gt7DH1z2CYqg4w+dzKMpE0J0aUizAKdqlNb6dcTM7AMGmwpLUU6AN/MWPNx+i
         mjXolw6NjxDaPWi1UP4qeA2nYc+De07o7iHCuPRmwtv2oIFCJlkTIUaKkuS5YTz/kpVj
         WxeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WfR76FD4Au5CxbM75qQNdquNFQiSYxURTySBYiFO3v0=;
        fh=dPk9MWz18s9faxsSz/h8sihbRqaWyom0YvEY5x6J5ic=;
        b=Q7hAO+/MnEN1DaDrUcKlHpueCYn2mvqeQDL0NwGz32YpClWsghdulVv9PONJg9GT3b
         t6zBjJZ01i5aW4vxBSvwK3rnutiZERa7GIb8gGY6c8NpVwiPxreMAO8LHI9gwK6JidQU
         7tRu2qyqDRYSRyzqWqsZ9nHTefQFsyoL+n5CDF3RRHON4N4t02++lWpx026Q1lVRFjfH
         hg1cQuG83BaXF5dYi8IOlFn+Dj5hw9oYTXI0Rk3Xq3Pas5xE5lmFbBCU8aUUPo9c6vTg
         pibwCN/0TfnWseY8Thrsi390nm+I1cfEfa6cUbt/54KL4yKUeqA6yaysXRzAvStm0wpa
         qxgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JA8oQDDK;
       spf=pass (google.com: domain of 3oml8zqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OmL8ZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id eg5-20020a0568306f8500b006e67e931ae8si29053otb.2.2024.03.21.09.37.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oml8zqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc743cc50a6so1520457276.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfGc/JkrsMmN5v0rXyb2W1/NJz2uIe4JHHMuZmbwTx2Q5G8VmyeVbFBzh8Z3d7UxxLVWNWZjLAJLFqXXTjXEROUnn0+4gHm1IKkQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:102a:b0:dc7:4af0:8c6c with SMTP id
 x10-20020a056902102a00b00dc74af08c6cmr1219995ybt.6.1711039034585; Thu, 21 Mar
 2024 09:37:14 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:24 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-3-surenb@google.com>
Subject: [PATCH v6 02/37] asm-generic/io.h: Kill vmalloc.h dependency
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JA8oQDDK;       spf=pass
 (google.com: domain of 3oml8zqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OmL8ZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Needed to avoid a new circular dependency with the memory allocation
profiling series.

Naturally, a whole bunch of files needed to include vmalloc.h that were
previously getting it implicitly.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
---
 include/asm-generic/io.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/asm-generic/io.h b/include/asm-generic/io.h
index bac63e874c7b..c27313414a82 100644
--- a/include/asm-generic/io.h
+++ b/include/asm-generic/io.h
@@ -991,7 +991,6 @@ static inline void iowrite64_rep(volatile void __iomem *addr,
 
 #ifdef __KERNEL__
 
-#include <linux/vmalloc.h>
 #define __io_virt(x) ((void __force *)(x))
 
 /*
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-3-surenb%40google.com.
