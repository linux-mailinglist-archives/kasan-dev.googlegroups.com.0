Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUUPRSHAMGQEIWANHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id BA6FA47D084
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 12:11:16 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id t29-20020aa7947d000000b004bb4bd3dd77sf1034158pfq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 03:11:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640171475; cv=pass;
        d=google.com; s=arc-20160816;
        b=yABLyH02mIJPHrYcK8dJcKSA9w+TLoM9FjgvvTH6PiaPsfrKtmUsOLD+WDOmU1/t4P
         yP7UuAGTeUyUV1Zyt6SvWdH4IQW17cSsdbb9YhGY+UA93Nhrl3ODnLt8WIkybLo8EDV1
         r9rlvby+2ccZQ+6v/zCr7Bv4zeYo6Q4Pyc6aHPWnRO2JywpReQN/K4gBPPIMAsqqQoh5
         ViljQOOMuodXXfEo8RXiRjO4CYtU4OITza0uHNLxn3XItTYUUsa3/ZO35bPCZqQIgTb3
         HYEcWgTM8uyr9Zeptl2E9upKVB61SxMH3su8aV4yjSJZTM77sxgt1qR8BafjfKMKeBpu
         dZBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ei4S3Qm5gZUfT9DbRAjkajQ6TAY0FcnQmoYPgryy0tI=;
        b=qJRmuR9TeGY26xrbc1cpb2fXrUiBa550InA3Z1ytLcOLraZri8eVbO/Z5Dosb3CcmF
         NOaIZR0BgIG3cprywflwndMG1H/YdB4nX0FRmaCrk0oaXiWckec0wDhu8nz5nV0qI5M1
         7vlN6qHn6g1HUgS7Kcw6CryZCAcQW9hlyVKUvpLbbxTIfDEbUWKXq1d4/MPenoWHBnrZ
         oQbhP3bMZjz4oTjepA2J/Br4Oop38C3lBtLN6KRbfLrFMzMVgp4hTpjU1LMFsX5Fcz8C
         gZlizm/5tQjmfSXJ24l5jNIaXZ90pumrc4QHquUA9F6Jnd+ti5WD0GwCRLh3loT8c5Z/
         n2ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ei4S3Qm5gZUfT9DbRAjkajQ6TAY0FcnQmoYPgryy0tI=;
        b=Ep/DKlEBZVW/rqaJobkQ4/hjUxMXSsVt18soHVcAEyJb9S5z7eEYtFQceFD1NB+mrv
         OLbnUpW/nJBQ1m4T1IbXxxxRBGn91+g6M8VXqZQQ6rV8uDBynLtDFXEBouDLoav96Y82
         MlX3Uvx9eI35zMN0AmfRuDdnidGp+/ASI/Uh14IYglVvx2eXrBAva0GMyGHeaO0CyTLK
         V8WwEQ7mC5tHpRmKdxuzNMxg4dOYe/bNGrvxjyaoJrmdmMfL5MMprO6HB2DQTbIlUvyD
         jZgnWR80Tow8WSaoP9Xb5xwCT8vuo+GO/6s/Y7yqMcf3WGfnUqSpkW2xzmvHCvtZAZow
         VuHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ei4S3Qm5gZUfT9DbRAjkajQ6TAY0FcnQmoYPgryy0tI=;
        b=Lr7dlG6WMhKt+syh0YPuqY6hWGyX4GM0CLEuJsKjqAMFH/MVwp85l9o9CSy2EKdZAX
         4d3r329inG/fw/UKdBwDs0B9HGNbZeBnL/ABhMpg79wZb760DXQOr8peq/NInDsOmlPf
         x7xxjAkiGXwKcV+qEKYmtvG5UAfwIZCrsC4ApjU07juRb5VIHyQJn/1MkIukHzIdWXrL
         l/O56ZDMf6fzU/uKsjDlEekIMQgzUj6PbVN63XPRM49tG45mr50gv6KjronBcY8rLvRu
         7WwNj8PvLTOsMuVRhApPkauRhqcQYN8POr2Oms2mlnBeZisOWIFPG/I05Ngom8k61Tx2
         KVYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AYxg9yT1E+tj7FZCf1O6JjRhvT/jEdnw0M1IZa3n51XCWI20P
	J+uDRtEwtSfAeO5uhPiHhvk=
X-Google-Smtp-Source: ABdhPJxFFIIneWyByPhFW2VVKdotVma1dQdFaQyGSmFSRwTI4d/cQ13LXW554xQnq85tju3ecpiggg==
X-Received: by 2002:a63:191d:: with SMTP id z29mr2375016pgl.358.1640171474899;
        Wed, 22 Dec 2021 03:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4d85:: with SMTP id oj5ls2106543pjb.0.canary-gmail;
 Wed, 22 Dec 2021 03:11:14 -0800 (PST)
X-Received: by 2002:a17:90a:b012:: with SMTP id x18mr757369pjq.140.1640171474269;
        Wed, 22 Dec 2021 03:11:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640171474; cv=none;
        d=google.com; s=arc-20160816;
        b=evy9ozdTIxzZA5Eb1YopBkYSJni8dwsQtVnCbyQP+610H9K3d/y/5nEszhQjqpHiFX
         KVU+d4RmirwnKhW15V8x15tcKz1bp+10hT1a91MbKE5RIyA/+JvMMHd2pAnbsNRVnvCP
         eBBFy1aamJA8hSc9oD9qE5Nj1imiQ8lk43gon/Lr8dDW+C2GDYZTMCKfB5FPUGwyUL/c
         He9FdSjhonwa87ikW2NTXNAVLhoR+fKuwmwkkivLx3Kp3ViwY9k4hmOMB8BzPcW5Hkew
         ev1xcmGTp+R3qLs0Q27InL7gf6lys80qJkqkHx6/mKse2n01vABYQpsJ7tMWQmf6GaXu
         oz/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=zDevqOGHrnaSXWOBZdeoMoYsQ5hDM4uZFouXt0cqDrg=;
        b=Vlr4BAuR/eB2KmsgvvmQanvnxpAfa24NreagSlwbfu6XxalxEx0yfdXz6ZRWbRI/Dw
         x7dJ2nDZl7fcC/Em5CoxPo0AzIO5ctKSvrXIVCwom2x90ehiCKxIDvAwQ5piuI9lkxk4
         1bcmACvkd7a79w/7K50ScjYoJLw7U4M64DS8NXVv6MiTtUuI7OjYRuJjCq70aHtSfZFQ
         dPETyc7VL/chYpB98bK6ymIHbxXYoy/rZpXPSXHnXco8qjp6g/OgkMVeQ6FY9QeKSa/y
         ZV//C3VWIeGw7dUAOIR8Lrfq7pPMXw/3ktnwWy5AGufxDwyy7CwHi1tzY/t7aW5DB7La
         bZIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fa11si280513pjb.0.2021.12.22.03.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Dec 2021 03:11:14 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A55E061947;
	Wed, 22 Dec 2021 11:11:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30E0CC36AE5;
	Wed, 22 Dec 2021 11:11:10 +0000 (UTC)
Date: Wed, 22 Dec 2021 11:11:07 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v4 32/39] kasan, arm64: don't tag executable vmalloc
 allocations
Message-ID: <YcMHyxOIN0LD7Lrt@arm.com>
References: <cover.1640036051.git.andreyknvl@google.com>
 <85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 20, 2021 at 11:02:04PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Besides asking vmalloc memory to be executable via the prot argument
> of __vmalloc_node_range() (see the previous patch), the kernel can skip
> that bit and instead mark memory as executable via set_memory_x().
> 
> Once tag-based KASAN modes start tagging vmalloc allocations, executing
> code from such allocations will lead to the PC register getting a tag,
> which is not tolerated by the kernel.
> 
> Generic kernel code typically allocates memory via module_alloc() if
> it intends to mark memory as executable. (On arm64 module_alloc()
> uses __vmalloc_node_range() without setting the executable bit).
> 
> Thus, reset pointer tags of pointers returned from module_alloc().
> 
> However, on arm64 there's an exception: the eBPF subsystem. Instead of
> using module_alloc(), it uses vmalloc() (via bpf_jit_alloc_exec())
> to allocate its JIT region.
> 
> Thus, reset pointer tags of pointers returned from bpf_jit_alloc_exec().
> 
> Resetting tags for these pointers results in untagged pointers being
> passed to set_memory_x(). This causes conflicts in arithmetic checks
> in change_memory_common(), as vm_struct->addr pointer returned by
> find_vm_area() is tagged.
> 
> Reset pointer tag of find_vm_area(addr)->addr in change_memory_common().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcMHyxOIN0LD7Lrt%40arm.com.
