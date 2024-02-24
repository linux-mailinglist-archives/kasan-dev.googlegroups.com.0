Return-Path: <kasan-dev+bncBCAP7WGUVIKBBTVK46XAMGQEFSLU2QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 890D086248E
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 12:38:56 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3651fbce799sf254745ab.1
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 03:38:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708774735; cv=pass;
        d=google.com; s=arc-20160816;
        b=v62LY2lF5MrwLqm3fxH1nJodJcWF2pFk36/ae+RNwXTtCfZ/MKET4p/KgUZlouGJwl
         7mhmdly5BeUO8mBlkyHAGMn2IPk3KrGs93OzFw8jn/5/Cqewb1aAqpxvAESuUahNy86s
         Ei7xeqgsaXAG5QbP1F494w2b14qGt5aPqPaLDyAOTStAtwnON7gkvb3cq1gRXSvGq+7Q
         Rk+hU/6W3iKSBc8j/NOROu3I31YrxctSAKsn7IJ8P2ghYD/xZ21CiSmHf/RkFhXTQXwQ
         FTiTshw0F/YWLK/3r/qMgBHomN038bT7m1lVfgRS8DyfTy8JeNJngLB82IkqYEtUCh2m
         AE0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=dnTeu0+laqPeBPatrvUo3yGboxRNoqgYzz+QcItMGJQ=;
        fh=qEoyHjm/nJ1ME/zcCZLKcjVV7NUwBZlBqnoDQ42cy+g=;
        b=e9NzNdEcEgpPLOzznrIyhh7r0jyHHqdRr5Xr//lrJ7Ou/uYvHlrn9OgqNv14MWQOcL
         Yvv2C/9SkVOcP8tHZXE51u1Mn6UFGNCfSSbSkaC0+zXJhLnrx5k8YPRzG9bFJN+O+jN5
         Cuw65UUDchtTEQGzRdd0rQKJnu+qA0ofiUmLNDSpgLIsKkrKf+YJHkg/Pv+hfiNdftIK
         UeoOzMKzau/JRpAtFeGQIZIUwZoPkKIcgRNFqAbNwEOI1og/tg8GQNJ8lbMHF9NfE8wc
         +0e4dmPNcCILi09HSfRDSCSTXe14nFKIwARwV05FvS5YDvmWWQgog103sroBUZwRlsus
         jWlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708774735; x=1709379535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dnTeu0+laqPeBPatrvUo3yGboxRNoqgYzz+QcItMGJQ=;
        b=VTLHA/X4DdfWh3ErHApCQkQw3EUG4sH4tgZ8mz1f4gZjp//EQgC4FGgQbWqiUUvVIO
         PSvdEstD8QQ8MjuJqW5LXw0K3HQfNSkfrJ9IcXMFViCIOv0ypUA6hcal7QnZTfmiJTVu
         gWHHB4pLGWEjD7FG2jBrZEoTi2HGbE0agBwmwTLorO626uRPaiRY+OnLxsVimKjWk7Ez
         iJ9N4jBm0vGW/ATofSoyr/0Vb9I5sZepfFwVfDkrHML0HaVbUqFNX7HzIjGvf66qXTxF
         KCOQKLwtXgT9NfwZOaxAJ9VTLISIRsTuOZePGCKvCNTI6g2ySPVNhqoI7PJWrROBCthr
         91Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708774735; x=1709379535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dnTeu0+laqPeBPatrvUo3yGboxRNoqgYzz+QcItMGJQ=;
        b=Mge20C20JvIeMcuyLF9cyoiXt1k2+MQOQnyNtLj68VWsEtf+lvgHCyHXHBR45kLRKh
         Jm8s8OQN2C8AIDRXJkUKg5otpIzKS08d6vzAJcuZ8KaqnxpPTZvTVbzqYILs6EBzZga9
         h8LNQPKSFKNkV//Ty60FC/mfR9T4jctw8BmgPLxAO4vAi+iTFb8QYwDQkbe9Lu4unidU
         tntnHneqh0IX9dxkDklS8LY45GdbUuDYgLrY8QVzYCJJ0LzTc5ksuOc9YtJ8oPHObYep
         APkLn3vW629jTvcDI+NEjtFaIvyf40KkfDA9Z1EFHR/ZTgrm5OlYOO/2g6jmEwiA5VJW
         ThsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSe23n2rYg6iBI1imPCRLhTDg8QU03dgz839mlawNLk2FmOvjn2EOflCTGwqCLIA+YZqYCs8XKui3ksEjGT4xHdHH/4l8pCA==
X-Gm-Message-State: AOJu0YxV/GWutDli/54hLf0FZceHGaZqHT/14+JiqjThiaXaIypatev/
	bSoYvQg91AngW+j/2itAMMFMBXp0UW2I9Pq6Jkb7yvFQol+w8LLs
X-Google-Smtp-Source: AGHT+IGegvMdrxqfAjrbfI5zdW8isAUXSTMhhsoy36J5HTh8fosvMF+db3iFwXSU+wIH+FIfnx/wfA==
X-Received: by 2002:a05:6e02:748:b0:365:1684:8466 with SMTP id x8-20020a056e02074800b0036516848466mr191077ils.13.1708774735012;
        Sat, 24 Feb 2024 03:38:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c88f:b0:29a:9584:8933 with SMTP id
 u15-20020a17090ac88f00b0029a95848933ls445146pjt.0.-pod-prod-07-us; Sat, 24
 Feb 2024 03:38:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0xaSBjW7qbFX9flYOfw/3ebiud95T3L3GEtKSkTsTUZTpXRTYEkLS74bOCCUC1LCahsGAQ64e9AtxOvm0Ln7i5We41WiW/sE81A==
X-Received: by 2002:a17:90a:9b02:b0:299:7b37:9221 with SMTP id f2-20020a17090a9b0200b002997b379221mr1714514pjp.12.1708774733314;
        Sat, 24 Feb 2024 03:38:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708774733; cv=none;
        d=google.com; s=arc-20160816;
        b=rS1IZhCpBzKItmpYeCHO0aulpOUmhmp7K3AIYnAL65ZYF/LVjtBhTJCF7rpdaAr+i6
         zNSsKWIqtxFhHxu0X3G9Io2em0cnnk+o6fwPP3edVi5jjEVjqgvP9RDLSe36k2AnH6MB
         jYvH4shJDTFFj6l6VeLbZVcZoCR3+hyorx0Bhg3PcxRXWf0x5FaJH9NvzdInv6emwNNp
         L3CK2hDsqNuUAi85rkedwojVlzsrXICWO+jebuBHZIsbsc/VahSWzDA46nKK6gCFl21L
         n2AC67C82EBo/STXtKGFJ6O5LZiVhYJ9h6dxU2/wSF1qjs6sG0O3/onPJUxn8VyZO856
         i1HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Yy98UP6s8Jpm2h5SgCfsqqr1/gOjzT7uZuHyOPKTafA=;
        fh=gSEydq/TyhkGaVN+iWsHLp+rZF81Biu6hKVuPH7LQ7o=;
        b=kodujsCZs6y9W6L76UvgIdHutCfCbrSs0KKWibSQs25ZE1uqBE3TtvvChVf95M838C
         ghROupNJ7N7GqINW3pwKPlXb2rv8DYUAJpkPT7RiWNqmunrCKIQ1F3IGuYFPv2xZR1dv
         Mxn7lRTlPcgZ73IgCgFzSmYs0cAPH4VwMk1joEseyOGVOQefo0ZlGKSFR8J6tVpLya/w
         FU93cAtXKG7vUIKRGF9t/VqWVs+zzB6MTM4vA7u8H6idCMKazhBry8OZyylICpwrVRem
         TTKuIVQSIxCqjXX52FIRG/OEgMNsFTZSmHfqH+Qy6/YcteYAFDwgMp2HWm7uiP8YXiRU
         v9fQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id x23-20020a17090a789700b0029a4cae3e4bsi271003pjk.0.2024.02.24.03.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 24 Feb 2024 03:38:53 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav311.sakura.ne.jp (fsav311.sakura.ne.jp [153.120.85.142])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41OBcdWr066959;
	Sat, 24 Feb 2024 20:38:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav311.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav311.sakura.ne.jp);
 Sat, 24 Feb 2024 20:38:39 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav311.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41OBcdAu066956
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 24 Feb 2024 20:38:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
Date: Sat, 24 Feb 2024 20:38:37 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/2] stackdepot: make fast paths lock-less again
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        Andi Kleen <ak@linux.intel.com>,
        Andrew Morton <akpm@linux-foundation.org>
References: <20240118110216.2539519-1-elver@google.com>
 <20240118110216.2539519-2-elver@google.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <20240118110216.2539519-2-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

Hello, stackdepot developers.

I suspect that commit 4434a56ec209 ("stackdepot: make fast paths
lock-less again") is not safe, for
https://syzkaller.appspot.com/x/error.txt?x=1409f29a180000 is reporting
UAF at list_del() below from stack_depot_save_flags().

----------
+       /*
+        * We maintain the invariant that the elements in front are least
+        * recently used, and are therefore more likely to be associated with an
+        * RCU grace period in the past. Consequently it is sufficient to only
+        * check the first entry.
+        */
+       stack = list_first_entry(&free_stacks, struct stack_record, free_list);
+       if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
+               return NULL;
+
+       list_del(&stack->free_list);
+       counters[DEPOT_COUNTER_FREELIST_SIZE]--;
----------

Commit 4434a56ec209 says that race is handled by refcount_inc_not_zero(), but
refcount_inc_not_zero() is called only if STACK_DEPOT_FLAG_GET is specified.

----------
+       list_for_each_entry_rcu(stack, bucket, hash_list) {
+               if (stack->hash != hash || stack->size != size)
+                       continue;

-       lockdep_assert_held(&pool_rwlock);
+               /*
+                * This may race with depot_free_stack() accessing the freelist
+                * management state unioned with @entries. The refcount is zero
+                * in that case and the below refcount_inc_not_zero() will fail.
+                */
+               if (data_race(stackdepot_memcmp(entries, stack->entries, size)))
+                       continue;

-       list_for_each(pos, bucket) {
-               found = list_entry(pos, struct stack_record, list);
-               if (found->hash == hash &&
-                   found->size == size &&
-                   !stackdepot_memcmp(entries, found->entries, size))
-                       return found;
+               /*
+                * Try to increment refcount. If this succeeds, the stack record
+                * is valid and has not yet been freed.
+                *
+                * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior
+                * to then call stack_depot_put() later, and we can assume that
+                * a stack record is never placed back on the freelist.
+                */
+               if ((flags & STACK_DEPOT_FLAG_GET) && !refcount_inc_not_zero(&stack->count))
+                       continue;
+
+               ret = stack;
+               break;
        }
----------

I worried that if we race when STACK_DEPOT_FLAG_GET is not specified,
depot_alloc_stack() by error overwrites stack->free_list via memcpy(stack->entries, ...),
and invalid memory access happens when stack->free_list.next is read.
Therefore, I tried https://syzkaller.appspot.com/text?tag=Patch&x=17a12a30180000
but did not help ( https://syzkaller.appspot.com/x/error.txt?x=1423a4ac180000 ).

Therefore, I started to suspect how stack_depot_save() (which does not set
STACK_DEPOT_FLAG_GET) can be safe. Don't all callers need to set STACK_DEPOT_FLAG_GET
when calling stack_depot_save_flags() and need to call stack_depot_put() ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1f0ebe6-5199-4c6c-97cb-938327856efe%40I-love.SAKURA.ne.jp.
