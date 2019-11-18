Return-Path: <kasan-dev+bncBDQ27FVWWUFRBJ5AZDXAKGQEBSHULPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EA108FFD57
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 04:29:44 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id k127sf7770547vka.10
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Nov 2019 19:29:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574047784; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAS1GLJVyWwScoQiUqgpsF+HBTSoyC9wjDo9o5scWuUezKohIA/q231jq1pmAya89H
         1BbTb26YyYgo/cltnx2ftF5aFRNbVrm5dajDo0XiCmcii7YGo0ILn+/H37snATcriNra
         nN4ImJZhHG38CxxUzy/XRSo41PhGWYvD5+ZivsBuiqP82SMTDVvdk6eVnZrZJiX2vs6i
         uUQXj/bjL9dweg5LIBuX6Qz32FiTVy0LJQWCn64yQ3YRUln0M14Wx2v1Os2zinhQuQjl
         xm2pPr663ghht5be9T43+I/idbOYWx1/pDYGDfXf60XJfsx89XKecXXvaAzDUEVGAKC9
         UDtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=jCBjurTcoMmFBpI7avAA7AwNn8sGIZNwEcScsDKJSMI=;
        b=W6BoYNH9grvIP4wz+GX5ZZsJjPBfRyrzXr6tmCr1gSa5ZkzS9iADSmCM7q6b2KxilY
         O/E3TpTTWSR0hZYCwwlvQeXQz+OO9L5k3fPe7u3nXDvDhPW2SGcb9AlDQbZMF7furRWI
         SkTTgfPSRnaFLEaobK88AA1zXrfH303qMQPixQG/j7LCwVp57USKMtEDU3NQw+mbYmNX
         RISYDzPnLOKJoHFLu+t7RaFOJCPTZ93eK0MX7vyTVwRB4CzwY7jrpL+pShrBWNjREGKR
         nHV7cmDK5S9lzpw9zPOgOHvk0qhiOIvuhLeUPmCss33OioH9tD35/UpyXmMHkwNBUUUN
         0DjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="eNgIem4/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jCBjurTcoMmFBpI7avAA7AwNn8sGIZNwEcScsDKJSMI=;
        b=TdmlGPGCaXZF82mf6eznikO9E1IccmFXacEyJlAG42txj+0YnB+0kuaZitrZqS5UpQ
         llRkcLRp3dwqDgSaHy043nINQ89MZAkurouqpf14nT4hNK8gCgtK9oE06sudXq7MiYF/
         hGFRfDXJb5FQEG++t72DeJnciC4E4O2gxkcQtp0UIQ2V9UcZhshoUuF5UkXRO8OAimU4
         HUNobLaEZ/i6UzIo5Hf+7OQMHiaR48XWlM7uHR+niYrpMOxKv4SmpnyUzzp5I03bLt12
         lfJcwo4ZEYX+suYwXAQOxL4WNwASxfLPE52a8ZjveHSxkttuAH/vbAdwHDLpm0HlQjhV
         mR0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jCBjurTcoMmFBpI7avAA7AwNn8sGIZNwEcScsDKJSMI=;
        b=Xvqo+npR6riXpur6dzO9a8v973lqQPjcBiwS/pXSI62t5f2ygdvA4UqBB6n13P7T2y
         3MKfaWTJa0dT2rriLKrlAm0EP8t+PAYn7bNQgworXSCbnlND0bAOCG6NIncvxjSYCQet
         gXWgeL5qHUGljrHX6y0k50Io7Ob7fjJa5qRinlSn/JFl26OGU5HOu6KEqZDLmR0HYiN6
         8m90en6LTSQvq6fMkZxM8Ps5GTJr4PSFgotZv3v+uU/6/JgWVMqVdbVEarNxSMxMRm9W
         YsoZZyVS/K11qow84ZEkiHferkETbOXjL6pl3/P26A6bAoON1ZCd8v59ZI4dQ+Yo+8xS
         c5WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVM2tV6ASKUkVLt9T45fUS0FHRdiRRMXUWLFAK3uWnxnR86r0Yf
	J65wvtklU0gmBwWl9hHchp4=
X-Google-Smtp-Source: APXvYqxbvrUaCAZTpSaLs9ztt7jV4zaRdeWyXbCS5lPTa0W9ebp4FLcZHsdat+vm96YvsXribi1lew==
X-Received: by 2002:ab0:2ea5:: with SMTP id y5mr15899207uay.97.1574047783922;
        Sun, 17 Nov 2019 19:29:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4813:: with SMTP id b19ls902469uad.15.gmail; Sun, 17 Nov
 2019 19:29:43 -0800 (PST)
X-Received: by 2002:ab0:393:: with SMTP id 19mr6732477uau.58.1574047783536;
        Sun, 17 Nov 2019 19:29:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574047783; cv=none;
        d=google.com; s=arc-20160816;
        b=oA6fV3c+0ckfeGg8T6OF6isSXHfFTKBuDDw6vUI60DK4fBKzujChAuBFk7HMiAJHEQ
         yRmEKASPERXKlL376KzkkXe2hJBtdHQxRnlFiPQXDvk7ZmWKdmwDqzVIoFmOpZh1iIwP
         v6HBxRJEmxscG6I8LTrRJ5O5c6NyKisT648HBFwIdQwM+2z9VodzHWywIbkP6qYZdGwc
         FAOiKKF8DFESviOC0DHfv/k6QIWhqSlJNE/BPSaUwJNZ19GEwjkmyD0LifF730z5xuSa
         4BXUlwUeCyyJT//jsoDodEqe4t+7bcGqTjZ4ZYT8+BFttLuVMt0C+zp+3vihZzVcTdFb
         7kNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=slCYCjmvNMTbkkbIU6vyjGQZT2Z+twrEjOEJUYrjB/c=;
        b=V540XeEhG6CfBerk9PU7tcKJsUVaWPVjXnkgi2MBCxjI26oNMmulROeWVGp6F2V+oR
         ZbDJGXqW8hWHXQT8X3/teqBsepdVHGdGPxa14BLCFpV2GOMUkZ/4l/lb8nA++lw4tUg7
         iSWQWSi0EedwrIX4N+zscNlybnxmNqezZjRoqmd4YLWiu3il+i0Cvi5TlkzP4HqKcy1D
         rI3EQUqci4aPfYoa2RXhh6uB+HtVMvLXR6lFyxmeZvujnw1iabEiLmy4gUK1+2GJyOAP
         DDaOosQmNqe9OdJ21lHH21GgPE2GugYZ+6mwBjDfyqgAHCypqBjTm1egMN+9+9UM94XQ
         LXtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="eNgIem4/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id p78si987807vkf.0.2019.11.17.19.29.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 17 Nov 2019 19:29:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id h27so8944382pgn.0
        for <kasan-dev@googlegroups.com>; Sun, 17 Nov 2019 19:29:43 -0800 (PST)
X-Received: by 2002:a63:b502:: with SMTP id y2mr7469398pge.317.1574047782524;
        Sun, 17 Nov 2019 19:29:42 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1d8-c2a6-5354-14d8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1d8:c2a6:5354:14d8])
        by smtp.gmail.com with ESMTPSA id j17sm18141516pfr.2.2019.11.17.19.29.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 17 Nov 2019 19:29:41 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Qian Cai <cai@lca.pw>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <1573835765.5937.130.camel@lca.pw>
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw>
Date: Mon, 18 Nov 2019 14:29:38 +1100
Message-ID: <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="eNgIem4/";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Qian Cai <cai@lca.pw> writes:

> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
>>  	/*
>>  	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>>  	 * flag. It means that vm_struct is not fully initialized.
>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>>  
>>  		setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>>  				 pcpu_get_vm_areas);
>> +
>> +		/* assume success here */
>> +		kasan_populate_vmalloc(sizes[area], vms[area]);
>>  	}
>>  	spin_unlock(&vmap_area_lock);
>
> Here it is all wrong. GFP_KERNEL with in_atomic().

I think this fix will work, I will do a v12 with it included.

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a4b950a02d0b..bf030516258c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 
                setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
                                 pcpu_get_vm_areas);
+       }
+       spin_unlock(&vmap_area_lock);
 
+       /* populate the shadow space outside of the lock */
+       for (area = 0; area < nr_vms; area++) {
                /* assume success here */
                kasan_populate_vmalloc(sizes[area], vms[area]);
        }
-       spin_unlock(&vmap_area_lock);
 
        kfree(vas);
        return vms;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871ru5hnfh.fsf%40dja-thinkpad.axtens.net.
