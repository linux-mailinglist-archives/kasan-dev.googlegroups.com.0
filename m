Return-Path: <kasan-dev+bncBCB33Y62S4NBB652YKXQMGQERPA6UHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-f55.google.com (mail-oo1-f55.google.com [209.85.161.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 934E1879B3F
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 19:22:52 +0100 (CET)
Received: by mail-oo1-f55.google.com with SMTP id 006d021491bc7-5a20d31ea8fsf2024603eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 11:22:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710267771; cv=pass;
        d=google.com; s=arc-20160816;
        b=aeEtc1aUp/jKH/ksj2YbtFTZFkj9eR1sVhEsMzEkoi1YbqIZUpc5szsXQiOYPe0spM
         +RUYzG8jGieKVpJCKgliGHUSey+JmWyR/qTXc1gR7S0ikXq7EgDhkgCxrBJq9DAPvy87
         rPCvCbtldBtYLEAptTFMsqzHXiMrf07owWlbjf9KPo/AaSQfa7lKU3+8+FKbdLOCFyWh
         wT5oX1JrN3fkZTrJY2ppz8O5qC+aLVP4oWbwsZKgkpjGHpp0PvjD7JXK3u/gF+un8Go1
         9UzbzC8ao2ZOatVjxILfGDGJ/36UBXrucnI8bFJP7bz09mK2PE/0QqiYyBn+OVDBkhtB
         6/xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=nfRnj1Ge+akQY0ixXIza0OANJPOBnSVUB9RK7u6z25o=;
        fh=tYBx+LlldWQEdeF6PSdnzGrYynKxS8ZcatAPwkuTfhU=;
        b=mqVmc4V8awdVFRITNML/khbFf+NnvfYssCgipaUwYKCLXItIqzXE4iQN2Bq6qXDdMJ
         JXDnbsY5Aim1zCGZWJbisZtvYUdEgWOJrEKQklm+RLzksBE0N1s6aj6EFgVOSfjOIW6A
         hrczm3EeyO1fgvqxkOJrc9xJFGKHkWNHohwTC9kB5UD2WBT6PUvnF2HGzy71OlFqhI0i
         zUqJKgUXDUYj3EV0yFW2e8WLlzdJcSHhZodbaxB4SA52Dw7NRp0aZKcD12GaG+xTeAsY
         2r3yHLfOQhrXWvWXvZOAtMaTUxkL9bd+dEY7Zb/beMZ8FYSXSVsqKSvzeJmr+/w16LFq
         hHWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=QqGwtO3T;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710267771; x=1710872571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nfRnj1Ge+akQY0ixXIza0OANJPOBnSVUB9RK7u6z25o=;
        b=rIi+OC4BiGUJK0JyQUJT7WaFsRZYRgps7C9Fxm15a/k1MuEGfWKBB+WtpD/Obpn979
         pKtNzcaYNPMv6Rnd7De1cXp1CQxE51pTxmeHQMGL9Yq2bHnhcvXvKXIBe5yy0ZD4RBr0
         +/jecqC2WsipHZBskQXU+o2HAsDXaiAzkF2X3yWKGsTpHNf9aGyt6E+JZ7sqarlQRaig
         oKi+V/weeheaAdfK62lAla667c1mdDZmm9w9ohMwMj9pBL3KSpjeAhRXHrVXvfDPanuh
         jSE28LLzoSiZFVVMpJ3n0OuLzSf1utAJElNxeKnHtHmI32ZIqAemDAmSZwIlOhLW45PU
         a3cA==
X-Forwarded-Encrypted: i=2; AJvYcCXdelGSc5JkiC+Dq/9FCwjGMGAw6usIWtSb9QtWNWwqCih7Q3p7spokUukONOYtuagFItAalIgZIMXEKT1FvXlZmz56/kLBkA==
X-Gm-Message-State: AOJu0Yxm3D+f7wsfNvci9Jc43Tt7Nh80CIpnEk7StKzXZD+Z0VOy0yKC
	6g1AJJVkzj/rafsZNBUEFbpA0L4glOIyDj6J46973jE57hcSq/sJ
X-Google-Smtp-Source: AGHT+IHnuGj9ZgVO5J4DIFYAeUAiot4y5eLX/NenXftp5TF/B3jI8ly8vV0Gyi2rrbDBxanxr1DCwA==
X-Received: by 2002:a4a:384e:0:b0:5a0:daf5:a5d0 with SMTP id o14-20020a4a384e000000b005a0daf5a5d0mr8354999oof.9.1710267771154;
        Tue, 12 Mar 2024 11:22:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:7554:0:b0:59a:347a:de04 with SMTP id g20-20020a4a7554000000b0059a347ade04ls3809568oof.2.-pod-prod-07-us;
 Tue, 12 Mar 2024 11:22:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+W6M2EnvN8E5cEupjpyK+My/lTUE3Rez1Z8KLzVmAxt6NCbToFhVCwR9VXFcrAdTjnFz96fuFxNnlhBVgUmwrXZhQZxeLv8r93Q==
X-Received: by 2002:a05:6808:200e:b0:3c2:50c6:f14b with SMTP id q14-20020a056808200e00b003c250c6f14bmr5641369oiw.43.1710267770445;
        Tue, 12 Mar 2024 11:22:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710267770; cv=none;
        d=google.com; s=arc-20160816;
        b=wuD3L9ss6FeDtvR4yEm1NUMspe+ixbAlWWGv8sOcanTpkHY5a820plt6TVYDWc4WhS
         Pqe87ZNgnKM5TNJ9zG+NWTFqLr3uT0IkfgyNyUeEvsOhBRGt2SqR3gLUE4kBMtSnM+rf
         TJFxAzkXw7yE+I4C1wM7Io5SmCwjGf3oUzCrgZvUV1MAUVzwH2+UHI7RZgE9TuoHYP/r
         trUf3/24+ftgkz5Trs6bt7CKZ3twVZzaJhyU6QK6XB4xOb1Pqccy0FN7Wc6g15pBmu7U
         GnGW4ZKvSv81H8F+HscyRfB7g5BKewlKT/KZAX+YeTLHUM8MKhdCsCKZjzI5WGGW2aay
         OYGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dyIsdsMhrpRwB/lg1STothrgvq3zjNGfcwfAiy3Vmak=;
        fh=fs11CUmKubfaAVVjf9q6kBKZCa4mH0cqS9GeVxX7GCc=;
        b=g2NaeRxoE5MVCcaPblVMQZWX1e+/H771iRqCcZDZMK7kXQbbHExcT33SU5ixxUdrL8
         FEMfws9rtOJsk2enjctnb/G1Y+Cwb3Tc8sY1QbwGsHiL5WSyZGOpjKeJateNe7N8XEfk
         BEnNaEX3h747wtKv9Q89k3CalUJ/C1VneS8illRa+ZjAEobd4gczgxEW4N9u1HCL7LBR
         UbLJ2+RYgjmtUSR9E6ZR8v5XlJyupfKVcWpiBZ+gu+x3Xv8cAsHKly7h0w4hg82r8gJh
         +KE0EXEU8g0XK0D33fpIr4T/CfOTgWVzuyAkAODyDfEg3HjqkYUBPFIqeUmzF/kjnyla
         pvxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=QqGwtO3T;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id bg32-20020a05680817a000b003c1b010a07esi1492324oib.2.2024.03.12.11.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Mar 2024 11:22:50 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from mcgrof by bombadil.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rk6lQ-00000007648-3mVp;
	Tue, 12 Mar 2024 18:22:12 +0000
Date: Tue, 12 Mar 2024 11:22:12 -0700
From: Luis Chamberlain <mcgrof@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v5 12/37] lib: prevent module unloading if memory is not
 freed
Message-ID: <ZfCdVI464EqeI9YP@bombadil.infradead.org>
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-13-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240306182440.2003814-13-surenb@google.com>
Sender: Luis Chamberlain <mcgrof@infradead.org>
X-Original-Sender: mcgrof@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=QqGwtO3T;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=mcgrof@infradead.org;       dmarc=fail (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Mar 06, 2024 at 10:24:10AM -0800, Suren Baghdasaryan wrote:
> Skip freeing module's data section if there are non-zero allocation tags
> because otherwise, once these allocations are freed, the access to their
> code tag would cause UAF.

So you just let them linger?

> Signed-off-by: Suren Baghdasaryan <surenb@google.com>


>  /* Free a module, remove from lists, etc. */
>  static void free_module(struct module *mod)
>  {
> +	bool unload_codetags;
> +
>  	trace_module_free(mod);
>  
> -	codetag_unload_module(mod);
> +	unload_codetags = codetag_unload_module(mod);
> +	if (!unload_codetags)
> +		pr_warn("%s: memory allocation(s) from the module still alive, cannot unload cleanly\n",
> +			mod->name);
> +

Because this is not unwinding anything. Should'd we check if we can
free all tags first, if we can't then we can't free the module. If we
can then ensure we don't enter a state where we can't later?

  Luis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfCdVI464EqeI9YP%40bombadil.infradead.org.
