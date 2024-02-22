Return-Path: <kasan-dev+bncBCC2HSMW4ECBB7FB3KXAMGQEEVVELYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F20A85EDA8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:10:37 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36540e65a9asf30459985ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:10:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708560636; cv=pass;
        d=google.com; s=arc-20160816;
        b=fwvOra9OH4imNwp9RegodaGbBHce3EMprG1UeJ69raCrfletYIf7zUuscb1CidKPd1
         1LlMz0PdNiblNU9RfWMbO6j8cK8OUU6W98ArzmqHLClCwI1BUxiarj6Cx/qwqqedGdTw
         R/u+/UD8KVIh8/tTaSQbZRh02+R//xB1QWjJk67lJ9tzyFijdZc3dRfPnL7doGga8Ji/
         q6dssyeDXmV8SfQISzRz9AlNuTSY+C9z3t89ls1QEAMAHXhGCT/Qk0A7EHbSW7IMCK/j
         TGUj1PYaFPGnZGAskBV/vQZJe8m5oZ1P31P24pNK6FsyAJ3ezZCjm3yH2h3+IJhUtoM9
         5Zvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=QMC82voDRNSz1ZCzyfG/0W4msprPAF5PlJwX6NkJ41c=;
        fh=ab9mz86y4WDVzWO0CObLK4Lst4oNtGzStp1YKi1xAq0=;
        b=FBAfN5QzYcSnZQBJZeXClFisi0cCuh43eBrLL5TgxE5HRR6nZSvHhdzAYEYzL2Tqn4
         oTZdLj1ZQPiskJ28einQ50LIwf2PN0uPvFMycMo4klDwowAHDaX+eTpuQJDFnDmiRttm
         lnTt4owJwxqmojzWECE5AtwH+YKPa10yUxAoBb7MjqeDs74fIvohLklm3nigcSb4veQF
         jhq/La4RQjCrdyPe4tv+VDCjWfSSsABHorw7KtotxOLlvhsbQCBaRa9skAdG/26N2lK1
         7Ok9Hk7KuMIo5cH48ftc8XVSDxpjeYy9Ueaj2jBoYoTPHQTy9e5Ed5i8Yc0KgOji1AX9
         fvrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=0KFUw4O6;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708560636; x=1709165436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QMC82voDRNSz1ZCzyfG/0W4msprPAF5PlJwX6NkJ41c=;
        b=n22wJA2I47u3BTius4VzA98/8wntMFrGZNHOhgzT3CuzpS2WHN3YG7CanHa0JpKeCz
         dST5bjxWw2/119b9kA++VahL7Y7krmdbg0WKcgAu/apmYtCDGF3rxHVklkVQx+UIQfgX
         g3iHlTAO4K52knCD/4gpYD39YnLGVixrbQOK5+7wGONB01LudSRuu0nO2TtxoHCkYIPw
         LJmxdBvgGYOfkyy2LbHXmcW81OZ7l5eTRiDxAqeC17YHJFCcM+TmlX/iJyJHBjWW9QqU
         eGuDF2KNPnE4jCqgmSq58WVSkGX5SEIxkaIVjWhh/hUVGMmRxISCgUx6rq1wkAAs5U+r
         yqOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708560636; x=1709165436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QMC82voDRNSz1ZCzyfG/0W4msprPAF5PlJwX6NkJ41c=;
        b=IS/Gp62lN1TUBOuHCrvayxF08ZfPLK+ZrcQtWNU9y0T7Q1eNE9pfBilUK9vyyJFGk2
         6qYC9S7ZtPpYFQsuBcIDTEG+WFyNhPMmix4pGdpgOa/R3NKwGX4PGX4HAqOlOAY+i+kz
         Yv3Z/+MHXAmseRn43HLtgw1kGUlpdIr1v8nk3h6M8atrcfGM5J5sTBW05toeL88JRnU2
         mnpip/LsHyK0RPEtV6Z1ypbAmy8+65ZyMQyPk7QQ4+T5Om+XHYLJnL1DcPWdb968SI+X
         SKbbHmgREdEKnOWnXVjQQChTIivPtynRJ9SViXHbSPwBLKoY/JlFLwG7QusT94xzIr8K
         xm7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdgOk16XbFsdIc3eniGGoYcWseEZrIkXoz4UWAeoMgz6mZU+RzajlnwepKZwfxmesCYnjRbYhZ2q+3xavq9ZNFBW6wrqF1CA==
X-Gm-Message-State: AOJu0YyiCnfVeqPMxmjEFPqVSxpb46O7/qilKY0tYNI1GSQ5++f0fkzm
	Gnpqn+RdFnC8mrrWOrEOrN1DXZwNcleh25mLMLCy29EDXAsbAA0G
X-Google-Smtp-Source: AGHT+IETuw17B8uowBC/XL+4a+FjPOAbtR3fxzK5UXC5HS9Ge9J9WasJsUtI+dCiGkcmG4szRmTPsQ==
X-Received: by 2002:a92:dc8d:0:b0:365:c8e:bd2d with SMTP id c13-20020a92dc8d000000b003650c8ebd2dmr17448542iln.28.1708560636232;
        Wed, 21 Feb 2024 16:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:805:b0:363:7ae1:ab51 with SMTP id
 u5-20020a056e02080500b003637ae1ab51ls3474206ilm.1.-pod-prod-04-us; Wed, 21
 Feb 2024 16:10:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBibUmRBfgrxc8T+RlpcpkfEvcTFYwxcIcwUn62pUH5TZ20ociXDTTAK5F3zvMsTluV+iqfvlDBAfDmIKagOL7OP1qqt+iYTDV5A==
X-Received: by 2002:a6b:6503:0:b0:7c4:9579:347f with SMTP id z3-20020a6b6503000000b007c49579347fmr21578767iob.12.1708560635452;
        Wed, 21 Feb 2024 16:10:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708560635; cv=none;
        d=google.com; s=arc-20160816;
        b=ehGcXI/t2QPX250V47ZF5BHExQBRPNRe7k81sNJVpptSPARcJKFXaU0xrtBGvsp5jm
         VZfgsLfBEWxcosWL/CUj41YLdHjn+DdxNRz9GMN2DPtNsI/sXfaEmEnvNs5HhU1AJalr
         stP56BSZF8flbsjUngUdYLzQw2fzPyjBBjPsuPwLSzl1DgkrH7kQGSLC4NUyUmBtEMdg
         2cpL/lTuxMp8JozXOh0lgBnTlGBCwK5z/TdbbvxOqJGfgmdCF4q9n7kq6S6ddWhaR+f8
         8/TsAjoBnF0dClBGBnqH4IUdmPTaYfQ55HIkXVP1jgm4iLz4U/m0CWA8kuU1tmEai8Uk
         P+aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1D0pVaWMlr8hskhdGaW7hZtXBWle1reW17x7OUuU9Uk=;
        fh=UayIAESwBGnQgiYTxXVSZaOE6Zvh/cTt8H5ltXh8+iY=;
        b=m+iKJDi5tvQFK4O/AvXHqN7E5+aJSGU6wiTaqkDbMqw9h4ON4JIGkBfax0Gy3MVUd9
         2/0tyOkMT/8DKtAtI6peKoOhCsq7len3U2zCvhGkMEZaU9/0fdsqRhu/qjUIgWhYpgLC
         NvL5brTUbPe4MEYYyiVbYgXRy4eLNLhr/U4nZ5bbmTgoWvcZAJDbp5SMdS1gsk72ompJ
         RhF84xY/lwQL4NNARgkN5VEckZcnvzf//W7EPmKspkj0+PVkI1Q8yjKpuIzsE/Hg6JLa
         TGPd9YbjUaVYKIKjPIXPw274axggpj3YX2bmSsJAwLlMKDoPMn5eG0T7eu0d7njsXukw
         yOTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=0KFUw4O6;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id o5-20020a02c6a5000000b004742d0fb3aasi406874jan.0.2024.02.21.16.10.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 16:10:35 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id a1e0cc1a2514c-7d643a40a91so3085924241.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 16:10:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXNbrKcz3M2aAD4gD4kVj0s2BP0s5hI8x1iXaEebLVRaH3bMqWvyZtWofxU3fcOR0XnqrfhnWj26NsDIzTBRXuK6uWfCNwKONJR6A==
X-Received: by 2002:a67:f54a:0:b0:470:3ade:af52 with SMTP id
 z10-20020a67f54a000000b004703adeaf52mr11439980vsn.6.1708560634875; Wed, 21
 Feb 2024 16:10:34 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-10-surenb@google.com>
In-Reply-To: <20240221194052.927623-10-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 19:09:58 -0500
Message-ID: <CA+CK2bDWkrNapWD7pv47XQo8PD4qJ3O=U99pL3o72KCnrzpsXQ@mail.gmail.com>
Subject: Re: [PATCH v4 09/36] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=0KFUw4O6;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> Slab extension objects can't be allocated before slab infrastructure is
> initialized. Some caches, like kmem_cache and kmem_cache_node, are create=
d
> before slab infrastructure is initialized. Objects from these caches can'=
t
> have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
> caches and avoid creating extensions for objects allocated from these
> slabs.
>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bDWkrNapWD7pv47XQo8PD4qJ3O%3DU99pL3o72KCnrzpsXQ%40mail.gm=
ail.com.
