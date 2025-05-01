Return-Path: <kasan-dev+bncBDA5JVXUX4ERBCEGZ3AAMGQETMKPIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E431AA5FC1
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 16:19:54 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-54b0e3136ddsf931245e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 07:19:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746109193; cv=pass;
        d=google.com; s=arc-20240605;
        b=PJvVrJsRmFTRsUwOXjBuxO4J5oyaOa/Qx78z9JGXt7WSMyhKkthZ730clYXgFLq6zf
         RiUcOWtI0vvm0BydOP0fB2KUCQJnDjV3nWOJGwTxajvDZeacs3FKuIfw6RpYlIJ1KuLY
         ksiOBUoDF/DSrOzaxRKayX6PeH2rsBMDwzQ/cNZ3OW/eo5jxTjpfunC7uPvlRaq3ozmY
         c3BtWFneORIu0YEgzFjMNcwrNdxzj+fyWeQypSM4Rx+l1T3jW80Lw3cnpPra3lM+HPig
         KMYaV26ZkyWcXklRHhFScYJmEt52TqY3aZJ0EfWXpb16at8eYsHqOio3lZgQkhP5wtaw
         ynaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RMb3YsIr+fv6qTzVJuBQAf9QVNttuowtdRIdb6hjMdQ=;
        fh=6jbJu7BQjI0tzkY0fQdu4AaKzWQK5SJwlOQHVabrRaM=;
        b=K6dCPT+qCaALUQgLtTlL24jjLUuXWj8dHQGajqKQnEzf4WmGaI5kQq+V0pKAtKTUyy
         PiQy6qBEDplD5KRl34ZK0YjkXoX8qek5+RZRUd1IRY4YJYICNZ5BPtP4fs3ipy0JEve3
         KHHVJHhp2voQlnIeHbiix24E9GrvP6LtVxUcMOwWMsVYyiLpBqU666Htpfv4S93ANXTN
         bSHf26FAKTFQk3nTIr2s9id+FMuiDCNKqL2UzglqnOcnEG5yqryqWtAcvLZdtl2ZjASl
         Y9tZF/BSAN2YhUHm16ETeKGU1kxk8kZjLJ3wKmI8XswaNT4pibWzqk3HyjK5SPS6quau
         P5Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J+O8HDjr;
       spf=pass (google.com: domain of 3bymtaagkcaajackmanbgoogle.comkasan-devgooglegroups.com@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BYMTaAgKCaAJACKMANBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746109193; x=1746713993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RMb3YsIr+fv6qTzVJuBQAf9QVNttuowtdRIdb6hjMdQ=;
        b=Rr2OicNv/Tp4Ldu0gRCt61pVJu+u9UDyeY2biTUs/LkpUzzixYMBN2S+EKEfaJU4pK
         Ts5AUvIRKvNZ7k+oYlRwQbwUVmOnxwTL6m3Ao7/CY0Yp4dS2b0jBLgE/7uyOVCo/A7BK
         rXcbbSevSKMIyQWNFLoPhSDC6owZTrd0eZ1snriczq7zwzfDCVKDP5FTKOaAvtZ+AjfG
         3e/ujpH2VX15djMXe+7R8QtaQGEynq22x2Do7ldgXF09UKoIg5gpy2OQkueLy3vWTMZ1
         xVSKkieY+DYIcPFzl0AFndfMbj8peKOFEfPiELNG02YFPQ/kh3Ou+Da18x8Vqm/K2Ijs
         CnJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746109193; x=1746713993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RMb3YsIr+fv6qTzVJuBQAf9QVNttuowtdRIdb6hjMdQ=;
        b=iBbXEgrq1wkR9hYbT+0IGQIhm/Jz+YYON/5tVR+XtXdWMUwUV33XZzmt1NUiLgFd+U
         5zPdLGnhcwSc9kqwWRDf2mQICDwVtdbT2VaUf/+IjiV7wT3hXZJqBULT2a5IkecuKpo9
         F7LGRDqmoe3wkL+9vbFj/5sojVqYmCP4hgv/51VJW4REv36T0I4gtbbQOZlJ1xb8gDIB
         sV+KO8PE7zUCTtQ4eCVnCv1w+Qr630s3Q6fvqzPp7DNrbIa4sNrs+SBIbeUrepu1iBoU
         gPI5OQxTsOXjCn493NvFoFAvUHUL2+v1c08Ny9TtCGjMKxqFal//ovlAEj94AOmFlMZc
         Gf0w==
X-Forwarded-Encrypted: i=2; AJvYcCV3dIXOKqEcVi2l37hlsQ+u+N0xgvaZ+e0IiVBlav/OmYFHwZcN6ccoO69vohNp1YMrdQ95Gg==@lfdr.de
X-Gm-Message-State: AOJu0Yxv67M/9z6QDOq5HALXXHz2H1NYThhykz08+xNSb5dXE8OOfVGs
	O1LWEJGlXbEv2pH11FWyYygto6NYZmjzjuKsjQqxjkeJacDyVZKH
X-Google-Smtp-Source: AGHT+IExQ4l1X6fV0Z/ZHTrrhqFRxMTG67w8qa9fsgrq/k6doHYwCzXUHGNFRKSQHDM2giihw9QZPg==
X-Received: by 2002:a05:6512:1314:b0:548:878b:ccb3 with SMTP id 2adb3069b0e04-54ea7b25b52mr889611e87.25.1746109192848;
        Thu, 01 May 2025 07:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEBcTCJpFBRA12v7WvB5FEbvb5hAqZxjHfNhVRSnRd4mg==
Received: by 2002:a19:640d:0:b0:549:950d:3478 with SMTP id 2adb3069b0e04-54ea675fb89ls164754e87.2.-pod-prod-00-eu;
 Thu, 01 May 2025 07:19:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcKlMc1ceCN1V8+Ker1fpenMEOLaO1cc+lA4LoZmilopcgiQ4AbSrH3hb/n1MgxPKhPqt7y9uqshs=@googlegroups.com
X-Received: by 2002:a05:6512:1385:b0:54e:784e:541 with SMTP id 2adb3069b0e04-54ea7a5178dmr854176e87.14.1746109190115;
        Thu, 01 May 2025 07:19:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746109190; cv=none;
        d=google.com; s=arc-20240605;
        b=YcbT7M62WSbSbAaQ/fWxbkdAMKG6E1lOdK5u+b/Z1ra+P52QmTsd3821nC/z3DtxmM
         zjAEElxYQ8gN8Ek7n+4eVJjafvpnM8Dab0v0pPY+sSmw6670Ep79vb917oQYbUc9qWVu
         iFmqee7lmDNef4PvjguSzzdxXpvYdX699UZMbVbZGV1dgMH2+xtkSyRkDiCeuhUUWSKL
         icSkeIQAhtAx9f+tDCzf+GehRN5RHq9wuFutS60yARIvWUeVo66zkNdGJeIAmBs+HC9X
         k7Lgu5Bfhh8/cW+Awhba/bbh4YZE+2Ql1IRq4NNHxcmGz/ZWRwi87uLhAlUbRD2I0xJR
         zfiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TmEF1yP8U0niebBh9hfc5iyUEhI2jhPWqahRuFkaIQM=;
        fh=dxEhv8BeTy/hua5/+ck1AAiYd7PdvpuHja+fcyTksQY=;
        b=MatAzkw/f6CG6W4tD/E4RYusY/xZZVn4/tZgJME4ykBphXUG5QQD0PmwEiVChmNfHV
         QUlldP3XFxh/95v+oERfNhTDFFtLydM9bN/6osJNbba/uV2rGDHjHtmW5odZVTB+DoPA
         EEzRGa25/s2G4jmtn+Z63PXMyGT828+9gAEWwa5ADhOneh6ltlLEzX7/jjfBCVA1Amph
         NHeDF1196wghq32bgRGuJH87hZiQ3lcXnXeoQjKbLTYYP22ZJ7mr4cAYX+yMiMt4MUvu
         aSu1ltixJdYJ7eZvDM7Y6/ZiifzN1pLfkYWN5WPQ3o+F22HTHq0MgO2mZQ0DS9fFXNFb
         D7Eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J+O8HDjr;
       spf=pass (google.com: domain of 3bymtaagkcaajackmanbgoogle.comkasan-devgooglegroups.com@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BYMTaAgKCaAJACKMANBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ea94f0a60si26188e87.8.2025.05.01.07.19.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 May 2025 07:19:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bymtaagkcaajackmanbgoogle.comkasan-devgooglegroups.com@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-43941ad86d4so3766985e9.2
        for <kasan-dev@googlegroups.com>; Thu, 01 May 2025 07:19:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6EDr3leFdKpcyVakz5SycpNOkDGqbkzLAr7kC3p0rwGcqlBkjOWCi0EuNiBkAJamkw7sCv9YMKKE=@googlegroups.com
X-Received: from wmbhe15.prod.google.com ([2002:a05:600c:540f:b0:441:b79a:76cf])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:35d6:b0:43c:f8fc:f686 with SMTP id 5b1f17b1804b1-441b64ed9d8mr27510245e9.3.1746109189194;
 Thu, 01 May 2025 07:19:49 -0700 (PDT)
Date: Thu, 01 May 2025 14:19:47 +0000
In-Reply-To: <20250429123504.GA13093@lst.de>
Mime-Version: 1.0
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com> <20250429123504.GA13093@lst.de>
X-Mailer: aerc 0.20.0
Message-ID: <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce CONFIG_NO_AUTO_INLINE
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>, <chenlinxuan@uniontech.com>
Cc: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
	Sagi Grimberg <sagi@grimberg.me>, Andrew Morton <akpm@linux-foundation.org>, 
	Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, Kevin Tian <kevin.tian@intel.com>, 
	Alex Williamson <alex.williamson@redhat.com>, Peter Huewe <peterhuewe@gmx.de>, 
	Jarkko Sakkinen <jarkko@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Peter Zijlstra <peterz@infradead.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Juergen Gross <jgross@suse.com>, Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, <linux-nvme@lists.infradead.org>, 
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>, <kvm@vger.kernel.org>, 
	<virtualization@lists.linux.dev>, <linux-integrity@vger.kernel.org>, 
	<linux-kbuild@vger.kernel.org>, <llvm@lists.linux.dev>, 
	Winston Wen <wentao@uniontech.com>, <kasan-dev@googlegroups.com>, 
	<xen-devel@lists.xenproject.org>, Changbin Du <changbin.du@intel.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=J+O8HDjr;       spf=pass
 (google.com: domain of 3bymtaagkcaajackmanbgoogle.comkasan-devgooglegroups.com@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BYMTaAgKCaAJACKMANBGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

On Tue Apr 29, 2025 at 12:35 PM UTC, Christoph Hellwig wrote:
> On Tue, Apr 29, 2025 at 12:06:04PM +0800, Chen Linxuan via B4 Relay wrote:
>> This series introduces a new kernel configuration option NO_AUTO_INLINE,
>> which can be used to disable the automatic inlining of functions.
>> 
>> This will allow the function tracer to trace more functions
>> because it only traces functions that the compiler has not inlined.
>
> This still feels like a bad idea because it is extremely fragile.

Can you elaborate on that - does it introduce new fragility?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D9KW1QQR88EY.2TOSTVYZZH5KN%40google.com.
