Return-Path: <kasan-dev+bncBCC6PY4IDUIKV6VDTIDBUBH4VZ6TU@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E53595FE8B3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 08:09:46 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id i9-20020ac25229000000b004a24f6e0f78sf1244167lfl.23
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 23:09:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665727786; cv=pass;
        d=google.com; s=arc-20160816;
        b=CIKUh66g7GzBwDDkirEetL5eJVOjoL2VnIwIVx5D7YbKbbOYYLCR7dPFWkRftKxI9l
         a0BviboBflqWwuN0AFhxseBTnpNNPnQ7u9+I3Qj9aWtUrUC3/GaBh73yuDOCFrrjES+9
         uaDGsXr9C6aBRpiPevdG9yj5S66e7u8rYKVDQ7x91plej1Lx+lE9EH1ib1yYNxUof9fu
         B9v63o9lzbVSrcuDMu5bqCSMTm8pjKNupWwRjo6JQICl2ZdasDocojVPdreS1s1AQbl8
         jfCu1scO2tDg0fKkYUxNNEdARsGXLHkPqRxp3itHLEG1tj+Wnl75kMU/W+7VRjcnER2m
         r1Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZILBF10Iy1NhW33DXCTJqVR/wI9V6fEV9i+gLACDmaU=;
        b=U8kpo5t8+9V8HSz5MgCgOGlncrDyiL3pQMyhu+g4mteG//arxsRKf8a+rgh3gwtZAQ
         R8iFTSj6KmtPaso/9UY9s+TGrH8VKaxa7ACLhNwwmr+TLhS+HPAWpxTw5KhOSgvgtBtP
         IEX1kAjGmq3awkxQnPZXErooLdeORFrZinZLJrx5+kYVVZB3agpwOlJnzN9qSPYMbkU3
         lFaa4pXv5BrDBroT+lesbCPWsVBVAS3nNGkzLKbngwjzYR1VWd2zsDcdvhRFOA2Hg9Ri
         oup4e53hUYo74NdyU6jQqgCth2+rrLSDzjtOP5YPjomVeyvWOqOQJOJ9Lyx7xykYI+SN
         UiBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Nxo/ikEp";
       dkim=neutral (no key) header.i=@suse.cz header.b=JNOjO25P;
       spf=pass (google.com: domain of mbenes@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=mbenes@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:message-id
         :in-reply-to:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZILBF10Iy1NhW33DXCTJqVR/wI9V6fEV9i+gLACDmaU=;
        b=Jhbue/7j/2Ksux6zHOhuKThA5D2MXK8oAWsSlMTXvYg1fdM6uS+LSlhatvWKLDCWfG
         YA/0U0xKtNIOQ3rfyPL2KRWwwlCN7OsNAMc/DVkkqcHJ7hYPK+KCqlJSFL4uIwBSu24b
         COVNEvJdICqZGaH/y5j+qU91JyI+spBt6z9uXgf15uWYXkpRlkfpzTDy/GnpnHdByETK
         uHOSRF1mNbyvAEid1rurfGrAC994yLPmUqLn2fCeesxkfkzxJEGzY1iEP8prS9wW1dcP
         L33tbonlVn1pgy2sRX/qWqshAhtpJjavAPTBo7JTbXCfu6OQeSTtT7a27udvIo7Cjm+O
         bm/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:message-id:in-reply-to:subject:cc:to:from
         :date:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZILBF10Iy1NhW33DXCTJqVR/wI9V6fEV9i+gLACDmaU=;
        b=fQAM4pwMOz5Ao+M95Al/Rusc8YR1t/iJIW8e+9ZEDt3qxuJM99PFim1Wtv6bi1Did7
         5jI+c+2uBwLPS2LsWrKLGgXZthxsbs8wx8Qsyh9LRyfBxZd4sPP3Yhzh3XyCEl/ZgPAp
         O1Q3tWppjBmZPhPN/rkXwhJnud7B52RtTua+eWuxHpkmHG7LA85Knn9Tu+b4PoxuJ5Au
         CciXTr2qny75sMBiPCavZIHA+G+EMuSDFHhV1XKlIarzlwFNSQCIJKqTauPlYzxnVIlu
         pQqQDnxfE88qHTFAtv7gJpo0W7V0TxyKPFef/20WRsPg0hlXT1ppjnzhBB8IIChaESNc
         ZNwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0jKokr24VH+biOlrKu9TkH0+b7eJb4ajrhcquvkgn4DUX8RN5R
	Fvvy6av2CrMEdETd0PYei0E=
X-Google-Smtp-Source: AMsMyM7AN5tmj6GH0o1JvKW5re5Qm3nQIV9Wuz5lDcr8sratGOE2IZSpKnmgX7zNC+h0Ui7aLF8Drw==
X-Received: by 2002:a2e:95d2:0:b0:26f:b14a:d639 with SMTP id y18-20020a2e95d2000000b0026fb14ad639mr1238016ljh.57.1665727786304;
        Thu, 13 Oct 2022 23:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9357:0:b0:26b:db66:8dd4 with SMTP id m23-20020a2e9357000000b0026bdb668dd4ls818825ljh.8.-pod-prod-gmail;
 Thu, 13 Oct 2022 23:09:45 -0700 (PDT)
X-Received: by 2002:a2e:a98b:0:b0:26f:c755:ae8e with SMTP id x11-20020a2ea98b000000b0026fc755ae8emr1189648ljq.27.1665727785106;
        Thu, 13 Oct 2022 23:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665727785; cv=none;
        d=google.com; s=arc-20160816;
        b=LpPDrELjGa/mKQ3j7LbWdGEr7ZPnrzYY430kML+iFRdsvFVfmW7XbMEGr92blT7sBH
         rB6gJArw0XSR/lDnpP/W0T9z57diIbjKSTkmA4WNkhdvi+Nq6v4NyjtsVGX+ZBZkvKi/
         MWrDf2wgzS1/Pt3u68z+azvhvyx5MpUA6BGh0wQib2+zVLe/6iRJCNi/VRYlN96DzLP2
         YQapesoRIoLWEsD1Ry+EX1Og5LM2GG54efe8QB4bkvi2s6K+hbjOYJA7SgIR7KtWHVOu
         EV04avtKUXtfIop2jAz8hGWJot80ihgzb9gEnqWsIOhmTGi8U8QPzDwdoPOhTyMRXo1B
         741A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature:dkim-signature;
        bh=AxWuERTisS42uO91Wt9T0iy8s6OTDiXNii5dAiOnBhk=;
        b=q7NgNP57SxI4IoTGSJOaphKlClGT/84RU29GRqYxouD9FnD1oxVL+Idi/EG3k/t5+D
         K7wO6mg98O5XYuAB3jq/iadVpoUNs+0pYDIYh+jSofZ3xhKYnkNuNewg58OLLe38V3RZ
         h3HF8QkCsrtOPcCPbvr8upRJe/4y2mSdWhoMjmiB+lM1fnDJzCb/omQSrM793f7ceXQ3
         k0H2NKnQK8kJDOa2ms4bhPh3a4oogLjAdtqSJwJonKmT/qfnlY6ehXSeYcTN7+PEZFWM
         i1Y37iuiMDdtBEW3aKPEefo+axglzdD4rsYpMaNM6/3SXJKHEn8vT9mfVV+IFyytpsSl
         hc5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Nxo/ikEp";
       dkim=neutral (no key) header.i=@suse.cz header.b=JNOjO25P;
       spf=pass (google.com: domain of mbenes@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=mbenes@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bd21-20020a05651c169500b0026fb9b63793si69914ljb.0.2022.10.13.23.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Oct 2022 23:09:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of mbenes@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 223391F461;
	Fri, 14 Oct 2022 06:09:44 +0000 (UTC)
Received: from pobox.suse.cz (pobox.suse.cz [10.100.2.14])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id A8A812C141;
	Fri, 14 Oct 2022 06:09:43 +0000 (UTC)
Date: Fri, 14 Oct 2022 08:09:43 +0200 (CEST)
From: Miroslav Benes <mbenes@suse.cz>
To: David Hildenbrand <david@redhat.com>
cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
    linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
    Lin Liu <linl@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
    Luis Chamberlain <mcgrof@kernel.org>, Uladzislau Rezki <urezki@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, petr.pavlu@suse.com
Subject: Re: [PATCH v1] kernel/module: allocate module vmap space after making
 sure the module is unique
In-Reply-To: <20221013180518.217405-1-david@redhat.com>
Message-ID: <alpine.LSU.2.21.2210140806130.17614@pobox.suse.cz>
References: <20221013180518.217405-1-david@redhat.com>
User-Agent: Alpine 2.21 (LSU 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mbenes@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Nxo/ikEp";
       dkim=neutral (no key) header.i=@suse.cz header.b=JNOjO25P;
       spf=pass (google.com: domain of mbenes@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=mbenes@suse.cz
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

Hi,

On Thu, 13 Oct 2022, David Hildenbrand wrote:

> We already make sure to allocate percpu data only after we verified that
> the module we're loading hasn't already been loaded and isn't
> concurrently getting loaded -- that it's unique.
> 
> On big systems (> 400 CPUs and many devices) with KASAN enabled, we're now
> phasing a similar issue with the module vmap space.
> 
> When KASAN_INLINE is enabled (resulting in large module size), plenty
> of devices that udev wants to probe and plenty (> 400) of CPUs that can
> carry out that probing concurrently, we can actually run out of module
> vmap space and trigger vmap allocation errors:
> 
> [  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.836622] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> [  165.837461] vmap allocation for size 315392 failed: use vmalloc=<size> to increase size
> [  165.840573] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841059] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841428] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.841819] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.842123] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.843359] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.844894] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> [  165.847028] CPU: 253 PID: 4995 Comm: systemd-udevd Not tainted 5.19.0 #2
> [  165.935689] Hardware name: Lenovo ThinkSystem SR950 -[7X12ABC1WW]-/-[7X12ABC1WW]-, BIOS -[PSE130O-1.81]- 05/20/2020
> [  165.947343] Call Trace:
> [  165.950075]  <TASK>
> [  165.952425]  dump_stack_lvl+0x57/0x81
> [  165.956532]  warn_alloc.cold+0x95/0x18a
> [  165.960836]  ? zone_watermark_ok_safe+0x240/0x240
> [  165.966100]  ? slab_free_freelist_hook+0x11d/0x1d0
> [  165.971461]  ? __get_vm_area_node+0x2af/0x360
> [  165.976341]  ? __get_vm_area_node+0x2af/0x360
> [  165.981219]  __vmalloc_node_range+0x291/0x560
> [  165.986087]  ? __mutex_unlock_slowpath+0x161/0x5e0
> [  165.991447]  ? move_module+0x4c/0x630
> [  165.995547]  ? vfree_atomic+0xa0/0xa0
> [  165.999647]  ? move_module+0x4c/0x630
> [  166.003741]  module_alloc+0xe7/0x170
> [  166.007747]  ? move_module+0x4c/0x630
> [  166.011840]  move_module+0x4c/0x630
> [  166.015751]  layout_and_allocate+0x32c/0x560
> [  166.020519]  load_module+0x8e0/0x25c0
> [  166.024623]  ? layout_and_allocate+0x560/0x560
> [  166.029586]  ? kernel_read_file+0x286/0x6b0
> [  166.034269]  ? __x64_sys_fspick+0x290/0x290
> [  166.038946]  ? userfaultfd_unmap_prep+0x430/0x430
> [  166.044203]  ? lock_downgrade+0x130/0x130
> [  166.048698]  ? __do_sys_finit_module+0x11a/0x1c0
> [  166.053854]  __do_sys_finit_module+0x11a/0x1c0
> [  166.058818]  ? __ia32_sys_init_module+0xa0/0xa0
> [  166.063882]  ? __seccomp_filter+0x92/0x930
> [  166.068494]  do_syscall_64+0x59/0x90
> [  166.072492]  ? do_syscall_64+0x69/0x90
> [  166.076679]  ? do_syscall_64+0x69/0x90
> [  166.080864]  ? do_syscall_64+0x69/0x90
> [  166.085047]  ? asm_sysvec_apic_timer_interrupt+0x16/0x20
> [  166.090984]  ? lockdep_hardirqs_on+0x79/0x100
> [  166.095855]  entry_SYSCALL_64_after_hwframe+0x63/0xcd[  165.818200] vmap allocation for size 2498560 failed: use vmalloc=<size> to increase size
> 
> Interestingly, when reducing the number of CPUs (nosmt), it works as
> expected.
> 
> The underlying issue is that we first allocate memory (including module
> vmap space) in layout_and_allocate(), and then verify whether the module
> is unique in add_unformed_module(). So we end up allocating module vmap
> space even though we might not need it -- which is a problem when modules
> are big and we can have a lot of concurrent probing of the same set of
> modules as on the big system at hand.
> 
> Unfortunately, we cannot simply add the module earlier, because
> move_module() -- that allocates the module vmap space -- essentially
> brings the module to life from a temporary one. Adding the temporary one
> and replacing it is also sub-optimal (because replacing it would require
> to synchronize against RCU) and feels kind of dangerous judging that we
> end up copying it.
> 
> So instead, add a second list (pending_load_infos) that tracks the modules
> (via their load_info) that are unique and are still getting loaded
> ("pending"), but haven't made it to the actual module list yet. This
> shouldn't have a notable runtime overhead when concurrently loading
> modules: the new list is expected to usually either be empty or contain
> very few entries for a short time.
> 
> Thanks to Uladzislau for his help to verify that it's not actually a
> vmap code issue.

this seems to be related to what 
https://lore.kernel.org/all/20220919123233.8538-1-petr.pavlu@suse.com/ 
tries to solve. Just your symptoms are different. Does the patch set fix 
your issue too?

Regards
Miroslav

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LSU.2.21.2210140806130.17614%40pobox.suse.cz.
