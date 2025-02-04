Return-Path: <kasan-dev+bncBAABBLGKRG6QMGQEMDODFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 425CAA27AD5
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 20:06:22 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2f9c78739f5sf162858a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 11:06:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738695981; cv=pass;
        d=google.com; s=arc-20240605;
        b=GMw1EqHguCfFeLX0+MwiysQ8ngb0d7EgV6tEr685UcTeLLD+wgPps8n5RuuuSLjZDu
         GOaiqcRqhk18V+pJIKTWf+jsvhMW2GF3MOUib7oKW7HIpTMY5B/t8GL69t/GkKdbG0Vv
         4CirV6RYQ9s2W7LMEJuyFOAyCu+s80jKOdye8PQZqh7hlG6kx8181Vm69eA/rMgUOUhf
         o80qNqCMnkkO5aAks/kg784avJvRnaVlR6k+KN0B5pYF7Mk1AUbBQfQlrxxz6I51gc9z
         Wlu/WXhtekaE9+0+NaiMLFd/KhrglMB8vnIp01xBSG7KJFInjU4Zs3EhfxfAeUQxayjc
         8DBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=vhGwnS7i0Y8nnI4zbUZS76gAvG29DnRJbCWMjqBYE6M=;
        fh=9YoJRKNGToVkffzCJpaVquhIWM5EnqWFjYLxayekx2o=;
        b=Ku5UNleMMBaJjDDlILGYsDdo6IsLYDBTUbasLRL2hrZqCVuzZnDruF5ZkvFTbodo+n
         IYjFHwkJGKGWFkfWScA8eRCK0nwMgagvRAuLTi5cVEknYUuNN9gmK3+50nw1F34W66yO
         O59aho0kAGnk8wlt0OoX3JyRKCvzDVlTHsW6tDBTXDRH+l3Rgv09BQ7ittuZOPRnXg2O
         jm4GhjD9AmdDhKZpWGknckUKM7NPy1rdKO+xELzQhOEmkYPeYp0P1OHyrzKS2nOyvXmc
         938kp7VEKjKYQsRPMgFoQZtt5WMlc99YWp1ZYBGH/+d6UKn/zLi+nX1ezhu85cOTIYgF
         iNxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b="jyGtOg/i";
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738695981; x=1739300781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vhGwnS7i0Y8nnI4zbUZS76gAvG29DnRJbCWMjqBYE6M=;
        b=RH9lds4GObnTyQrzMnWE9V5m8MQm0G8PQlx1KMOS8ILhrDSp6bkvkKWwRt8f+zeud1
         6UeTbGHhC2tB/OlDqJqcUBgtRKM202jikqkyuKvk9iQ4vedAEOSBHvK3sx/8SX/nCu50
         6pmluUgJXtl6VNz1ldBf79x3rs+EIM3ZXsFhyNI1/K6ekvsnM3xkTW/kp1en/o7oHRN7
         9RmM16AaBTO4G3AIkS1h90ciS86Sq4nuQmG/bWUmM7AUmO6e4RkGxcwd5zcWItfVZiMI
         lwgR0NrAOOVVWYd93Hl0M5aoQP1qDWWUIpVtRCbKMZNpPtfM1GLHYvxi+jfx2VH+zMSL
         SPmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738695981; x=1739300781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vhGwnS7i0Y8nnI4zbUZS76gAvG29DnRJbCWMjqBYE6M=;
        b=rYq7Ap3lz8zyaQHa4h6G3ACg9335vY5yuz54gnLi4TZpX1p14IzZyPNEHlwpDPUUqH
         ArTrXQoyBX2NYhx4KW92KtoAAe84soy9wp6m/rqSk0KOB8Vot9fAJuOC7aEjz25DV/sI
         GKtPh3SV4lL+W+B1FSNZC+uxIdZCbd8fFpTD+8iWD3eSvxEnXkJfYU33mmEoNj6nniWO
         A9vJLtGo1QXn6cvp0aEneKzaODWs3RkH7y4Yi8pU1uixu7oRvDYTOcUd78btfi/xXW0K
         c5c3z4Y0tUXOpsQcJbqMseFVXwJYHuLrQx0jxQyhFKg1xF/M80/A7o0vpDWJNZVLBJrI
         9D1w==
X-Forwarded-Encrypted: i=2; AJvYcCWzzPz6tqMiYjUOmwgKYIf28kOu9glfubJRS5np/LdNK/4fZOdiF/691tfv21cN05N2ETr5VQ==@lfdr.de
X-Gm-Message-State: AOJu0YwvREGs8imfjDNhkkNnMBaXlZiIrA+OBhtq03bH0+IqEEUJKX+w
	VwAa2z5SmL1aNUh0q2ZjMTQxMjEty5Crlm32cyOmU6w7t/yDgj9e
X-Google-Smtp-Source: AGHT+IGTZZva8anZyhkQ3Fy+eiN8Y/KaaH5XiahlZ3wPHfTxTSd5MIsw6+IALrBOSfnZ7+SUju6QWw==
X-Received: by 2002:a17:90b:5387:b0:2ee:d9d4:64a8 with SMTP id 98e67ed59e1d1-2f9b9ec1ef7mr7391525a91.0.1738695980701;
        Tue, 04 Feb 2025 11:06:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4ac8:b0:2f1:2e10:8152 with SMTP id
 98e67ed59e1d1-2f9ddab8f39ls67679a91.2.-pod-prod-00-us; Tue, 04 Feb 2025
 11:06:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUKod8zdTiSZ7aaAC7kXt/tpO71j0e6i+vE+NCM6OcdBFxmHi/CaqUEPQatn8qy+usDB4TgIn9Tzog=@googlegroups.com
X-Received: by 2002:a17:90a:dfc6:b0:2ee:8253:9a9f with SMTP id 98e67ed59e1d1-2f9ba6f8084mr6944307a91.11.1738695979568;
        Tue, 04 Feb 2025 11:06:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738695979; cv=none;
        d=google.com; s=arc-20240605;
        b=fGDk0VmFWr1OiNTyqLCTtsI3SKo1ZJXoPYLY3nM+UMeTALy0B+nyNNLmuTWAC18mec
         7XVYIrF/ghBpJzIs01zW7pX7po0KeRDGcFnG9DWeNWd8egzGQYlwHU8j+WH4QpLt3kQg
         C72VdXS4tejP8eSePjxslhTkI6L4ryOZPMWRUaUDt8YuQZ/+ZPIwg9ujqk29d2vZxh1y
         1TBx+yUzbX+PHPemH1crL5RajmBf15f7UbItd4rzGepyHGdFZygonR0uZT16/sC8HHuI
         /8sae6Dzz2YBd6JkpFah4Ltq0CQY7ftVZUVQFD7F26rG0vTgqQBYJU2NzpAqcmRkKLob
         eVWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=L7hZ7sYPCCjt4cWuKdRqkFzNU2NINe/kZtlYF3GX+To=;
        fh=IgoRSNN/XY4wKrIwEORIUlA7IAp/NLdzGEb/wmSAuQk=;
        b=Z9R1xfWKujmVJt1TrT9vBPnqPrP/wj6mcs1A8xCg7K6sQPNTimma/Skuq7fbMNMLqG
         /gbSjBsFnFIn3z71chhna30KKhGoP7irCNHz0GsvoPWCxaTUmHuxgPbaAccVz95wQBmb
         Xk2aRu8UbdgngVFQiVox4ymX50tO/WRooG1EJy+4Gx2L1tDswKvxgU/HHjYmnJfHsWC2
         etq4hRPUL2COKqK51TBIPs4V5a001z+ofLfEwgtd4yQtNQdg95mJBZNaHUTjM3sWVG+B
         HDQQulXnvmN07LUxVVkS1IPXSu1IaV+bhjkT8vlHJKkwZ6WVuss/YOm8Jzc4v7Tnpf7c
         L0Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b="jyGtOg/i";
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f9d1992406si58976a91.0.2025.02.04.11.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Feb 2025 11:06:19 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id EC29D401EB; Tue,  4 Feb 2025 10:58:23 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id E915A401E9;
	Tue,  4 Feb 2025 10:58:23 -0800 (PST)
Date: Tue, 4 Feb 2025 10:58:23 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
    palmer@dabbelt.com, tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, 
    ardb@kernel.org, dave.hansen@linux.intel.com, jgross@suse.com, 
    will@kernel.org, akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, 
    dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com, 
    tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
    paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
    jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, 
    jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com, 
    rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com, 
    catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org, 
    ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de, 
    kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com, 
    julian.stecklina@cyberus-technology.de, peterz@infradead.org, 
    kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org, 
    linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
    linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
    linux-doc@vger.kernel.org
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
Message-ID: <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b="jyGtOg/i";       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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

ARM64 supports MTE which is hardware support for tagging 16 byte granules
and verification of tags in pointers all in hardware and on some platforms
with *no* performance penalty since the tag is stored in the ECC areas of
DRAM and verified at the same time as the ECC.

Could we get support for that? This would allow us to enable tag checking
in production systems without performance penalty and no memory overhead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8bd9c793-aac6-a330-ea8f-3bde0230a20b%40gentwo.org.
