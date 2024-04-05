Return-Path: <kasan-dev+bncBC7OD3FKWUERBXFNYCYAMGQEZS7V6YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C934F89A0E9
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Apr 2024 17:21:02 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6993c176044sf17988236d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Apr 2024 08:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712330461; cv=pass;
        d=google.com; s=arc-20160816;
        b=NDKGbX2PF3orlQxOgf5f7dhfyUxehLUC6Ql4hUMWcM2eNhkyMAbMrI4+W67wlSYjXx
         SFTeP5RwB82RooXGr52/sPV/TrQhdU+rmcGseXkKiiWzI7qZEenbjyvfBRUbaNL9K/gm
         VdTY5d6S0DSeE5V8ZNHoPKxVbJ0mi0yAWOlSP8uqX+aboMJrGoTAZlXQQK9we8ik/T0Z
         5uqfXXQ026kT5o6aQMKk+MXDyG/LGvksJ6eslgIfSX+mOeJ7dHhGbjC1a9fVxa8gQb96
         Txhecqb92CKSmh3Xdc05BmnJ7b5XW3AuNuM8VVDPfa8rrpFDLA/5WA4viN7eqoXtodkH
         Vk6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5aefSyzGovKkKhmlFHIaRtzzzAVIk+GcZdaXwDpk53s=;
        fh=O//wG1WiTt3m6xrXOCmeghy47F8uNatCQSmL6nxdz38=;
        b=nITvtDTB+vVKa31Iho2/V88Va8wfUx/66O8sMIlo0jHgCxXjp/rBAIVENy1OJDcuxd
         ibeFs1veujuK3r1mtNjRaQ5Gv8lEYT2KcgUHvJmliw9/M4+kHDZTIF6/yMF3vA9dq0LL
         xUUc2TCPtWqhW3xyb82TSWukp97KorPYG2+OCNyT7Y5quWWJyZO7e/GcBlr9sz54iMMW
         cSQ6fEITVL9eGhodrUwt5mYWC1Oi+G5BE3BZO/rPvRVRRW9+rzN39U3eCPvCtkqW87kA
         8iPKYxbTzkUU2jtqQPbqJa66zQXmI4XEtErZHSVg/iaZuweXi6w0fF9pY7Gfi9gnUTZg
         tfwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OZYII97c;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712330461; x=1712935261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5aefSyzGovKkKhmlFHIaRtzzzAVIk+GcZdaXwDpk53s=;
        b=f2Fv7LFRdsjT8UYScOcVmeZcSwOasLA2D4GPvemiNJsc1eYHqOOz7mNxzmLPkzIHtQ
         DfYWLsYcxfou5wVh9cUJ/cs1WBgt7BisBHTay9epADOstqp3Jcs0UavIf9qtJwxMNFR4
         nyICBqbra8abFpiUQo9QSBC+VCX5hAi+PPsPf8N/wmhAmUbeDdajZIHTrl1DUn/AZK8m
         vvodPiExM2Hp2dqAEn3OoHohGjQfBQFFX2k3YKsr0avUkH+ck735etiYHlSwsdO/zuRR
         0GC+1ecU8RmxEr1rNqdFMgneMGtcwkD5b23bgKCPoefygUkH71D3ttPXYGzvFA6JjgyQ
         ZroA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712330461; x=1712935261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5aefSyzGovKkKhmlFHIaRtzzzAVIk+GcZdaXwDpk53s=;
        b=qHCBfjjAwCJolZHPTikKjD654YUnWlwC6RKooD/pxe816HIJ0pPmwUSQisPMwGbQXn
         B1EE4nmOLesby+mHcUwB1Wan0D0C1GIWPBwcG/rii2GtmnvNMx8QGLjvPfsJIfBMIGmj
         /8xyhuGCGwCPHEJz/2svOlb9Zm3lWnxnUSFv3vNQeZhXuZzBF8swAQX3cxmx58Ruz2/e
         1JI23c4CHK3tYbghMTgeiPJAJ4ovswXJXdE+s8ORu8YL6um/3G2R+SVPErgW8/RibVvr
         IAbPnJqC93B6RihnIgN0E9Th8Q/qMq/wdlHYuhogcTagbwTN5sJM+anHzabjMymprquH
         fP+w==
X-Forwarded-Encrypted: i=2; AJvYcCXFCtrGAL/fk7BnvIKpir/ujSZYBnPMwVuHRzQ/sWGPrg3GMkMe/pRxtcpOYs59LGRJlozvIlQ528tyHdv5lEXzYau+BRr4qw==
X-Gm-Message-State: AOJu0YwYe0J2prEmvwYJg4k8n2bbH85fTOTZXZdUFDA9RnX0RbBQJuk9
	INTGDXPK8J2WF18KMIIud7gTjGYL85ictfIxhVd/A4gC/PwLYDVO
X-Google-Smtp-Source: AGHT+IFgLE7KCTI5XkukeK2UXwc72mjU2GA0+uK9tp15VPRMKXWf66kphyOzl4MVYFDqEej9XgoJHQ==
X-Received: by 2002:a05:6214:f6a:b0:691:85a2:4434 with SMTP id iy10-20020a0562140f6a00b0069185a24434mr2684237qvb.26.1712330460931;
        Fri, 05 Apr 2024 08:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:484:b0:699:1044:f17a with SMTP id
 pt4-20020a056214048400b006991044f17als3620491qvb.1.-pod-prod-00-us; Fri, 05
 Apr 2024 08:20:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4150SZaIsru/RhBIIpodXqpUWh6eTU3Fl6dLWXqDa9c4CtzTsrwecHHR1+ZDjr9e+hqRO3851ATcunkqC/0m8CLTP/6cxl2jpgA==
X-Received: by 2002:a05:6122:4f0d:b0:4da:bae9:4449 with SMTP id gh13-20020a0561224f0d00b004dabae94449mr1615042vkb.4.1712330459334;
        Fri, 05 Apr 2024 08:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712330459; cv=none;
        d=google.com; s=arc-20160816;
        b=UgjsQThGOxwIgl4C4BVd1bQT4OdSmGvO9ShT94ZX0OKAcKSXwSTUgxfPJvCUL60vJ1
         YuA91Lp3WroNWAqCCE80aIIS5hZxS5pFII/khJ4HflE1BVmPiNpnAk+mGhYtF/4LIrxF
         zuE74A7dvWP4BbO2E9VsuECt0I3InJYfBu//k3LSnFV/X9tMigzLVuHA5rGx4L1YyFEW
         xPmnqcO89Thhhld7V9F/wIt7LEcbuLjlKmbAn865XkQFv5SBxq0k3hvGdEE5UDOZ1vBe
         ceNm0ZQDLxTXHlLTkAihsei2G5M8Nvwe5Vr7ltwuwFdrqV2uvm7jX+6G5rZtw5O4UTpd
         QgIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xfDVWiPNFB4hCGgsx7SCawcdvp63A70UKMWvRcHoJQg=;
        fh=eNntGycHVkUtnd6hv7DX6VsKHmfWt5nvTYKUopMe93o=;
        b=be3NoXJxJGY+r1hzIFR4tYxrNzw0t9NrwEuXluCOX1Uzo7Fe0hIpNSjCclBGeqXN7y
         fhs+oWEXI7ep40eAvvVHrPDqJC3WwcZPkT5EOV6QtLCJoHQorJFsepImK3+3bTzbda6t
         Kv7VasoAw9Y97pNRbjyowQe0Jzz3bqJKM/KRo5WAuspjziqWPsyhTByVzPkpx44l6HXd
         EFoPJXEzwVSZ0LjJ9QBiblPenqYuBdFE8ElDfJ7gdGkVDVVkp7Z3DbDy25Yswm2G/Tuw
         K9xH/9T6IxL1p5ZycjMG66z2U1YeXCvvKT6GRO1zstcOX+/A4ZEggPkTA5mEmigqyunY
         VLJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OZYII97c;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id ec40-20020a05612236a800b004d32e96f356si72070vkb.4.2024.04.05.08.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 08:20:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dcc6fc978ddso1923820276.0
        for <kasan-dev@googlegroups.com>; Fri, 05 Apr 2024 08:20:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsXaItTvSzAgt/V6ReGLTR4dxD5ydkGN5/PrOAFZAmXOpVu3df9Il6w4RHRsywi3UbJoLBoq0tW2KB1521htc2aXWkfPVH2neB4w==
X-Received: by 2002:a25:6ec3:0:b0:dc6:d258:c694 with SMTP id
 j186-20020a256ec3000000b00dc6d258c694mr2014282ybc.19.1712330458412; Fri, 05
 Apr 2024 08:20:58 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
 <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com> <41328d5a-3e41-4936-bcb7-c0a85e6ce332@gmail.com>
In-Reply-To: <41328d5a-3e41-4936-bcb7-c0a85e6ce332@gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Apr 2024 08:20:44 -0700
Message-ID: <CAJuCfpERj52X8DB64b=6+9WLcnuEBkpjnfgYBgvPs0Rq7kxOkw@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Klara Modin <klarasmodin@gmail.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OZYII97c;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Apr 5, 2024 at 7:30=E2=80=AFAM Klara Modin <klarasmodin@gmail.com> =
wrote:
>
> On 2024-04-05 16:14, Suren Baghdasaryan wrote:
> > On Fri, Apr 5, 2024 at 6:37=E2=80=AFAM Klara Modin <klarasmodin@gmail.c=
om> wrote:
> >> If I enable this, I consistently get percpu allocation failures. I can
> >> occasionally reproduce it in qemu. I've attached the logs and my confi=
g,
> >> please let me know if there's anything else that could be relevant.
> >
> > Thanks for the report!
> > In debug_alloc_profiling.log I see:
> >
> > [    7.445127] percpu: limit reached, disable warning
> >
> > That's probably the reason. I'll take a closer look at the cause of
> > that and how we can fix it.
>
> Thanks!

In the build that produced debug_alloc_profiling.log I think we are
consuming all the per-cpu memory reserved for the modules. Could you
please try this change and see if that fixes the issue:

 include/linux/percpu.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index a790afba9386..03053de557cf 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -17,7 +17,7 @@
 /* enough to cover all DEFINE_PER_CPUs in modules */
 #ifdef CONFIG_MODULES
 #ifdef CONFIG_MEM_ALLOC_PROFILING
-#define PERCPU_MODULE_RESERVE (8 << 12)
+#define PERCPU_MODULE_RESERVE (8 << 13)
 #else
 #define PERCPU_MODULE_RESERVE (8 << 10)
 #endif

>
> >
> >   In qemu-alloc3.log I see couple of warnings:
> >
> > [    1.111620] alloc_tag was not set
> > [    1.111880] WARNING: CPU: 0 PID: 164 at
> > include/linux/alloc_tag.h:118 kfree (./include/linux/alloc_tag.h:118
> > (discriminator 1) ./include/linux/alloc_tag.h:161 (discriminator 1)
> > mm/slub.c:2043 ...
> >
> > [    1.161710] alloc_tag was not cleared (got tag for fs/squashfs/cache=
.c:413)
> > [    1.162289] WARNING: CPU: 0 PID: 195 at
> > include/linux/alloc_tag.h:109 kmalloc_trace_noprof
> > (./include/linux/alloc_tag.h:109 (discriminator 1)
> > ./include/linux/alloc_tag.h:149 (discriminator 1) ...
> >
> > Which means we missed to instrument some allocation. Can you please
> > check if disabling CONFIG_MEM_ALLOC_PROFILING_DEBUG fixes QEMU case?
> > In the meantime I'll try to reproduce and fix this.
> > Thanks,
> > Suren.
>
> That does seem to be the case from what I can tell. I didn't get the
> warning in qemu consistently, but it hasn't reappeared for a number of
> times at least with the debugging option off.
>
> Regards,
> Klara Modin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpERj52X8DB64b%3D6%2B9WLcnuEBkpjnfgYBgvPs0Rq7kxOkw%40mail.gm=
ail.com.
