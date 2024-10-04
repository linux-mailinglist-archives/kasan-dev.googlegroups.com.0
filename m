Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD46723QMGQEXYTVW3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id BCD5C98FD78
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 08:45:36 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cb461aed30sf26477316d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2024 23:45:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728024335; cv=pass;
        d=google.com; s=arc-20240605;
        b=RgzKM88t5a8GylG2lrSbZDSykPxFN48Tz+7As57U2WmJXcJLi36H59dsZahV6kHE31
         aqyAH3un3QRJWsnGziRKA59cESvB/POfOiaVPEL7WeFpYDRD1LNsm+hd57PNVzvrYfjY
         syZjwSwblQseFVLPuFxE9sxI0Txg314p5gpggfALT4g/9cKc9ZAgGiIPYfzWby0z+HOU
         2Vji9afhB3PexQNVFIOnjb49ezI6Ix7ozccl7M3ZDSP9T+bmltqRaNWCk4/h2Vn0bxKr
         VJAk4XZ+AhFdapfO1QqoDwGm2ypKx00yo3t/PRT6vNv1LjuQb0AF/XRz0bgFZsGjxCtJ
         SFMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1RQL4f+NgmECNiyRdqgD/khitFvYZgNZ5PMh0Of1C88=;
        fh=nNCEu120Wfp6GJFQfN2k3fx/r3CKu8EjlONm469c8Mw=;
        b=No1OY1PiADm9/LptrpKAEBulqmMAKRoZXqbCjpsvOlVsoZLHV8Q9Kkl+UknvOBfcdR
         L22FUpaBZr3GtiyGHgDoVZgyTZbDTUHptsXFEBEKwjYaTGYrafrjuPvonhV1BqvxSbQF
         /44livCWbjVlvKEOgas3ODjg7s9kMTXCoFVPTKpY4XXEZbRfprJzMWRbGeKvNlbhGGkl
         MqyKcycnjmL4O2WVMMaTy1Zlo8JsApP2AuPd9BtuhI5NBz19MImxHqJpILzjVprYI7I3
         E5dpIqiqzsAanATA1TktuyfPkgXF2HFCOYWBLC591yMIm4MdoYLhvFgub4+ncVoGGECO
         vibQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GJXLhzaS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728024335; x=1728629135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1RQL4f+NgmECNiyRdqgD/khitFvYZgNZ5PMh0Of1C88=;
        b=DvAgUCfteitkdCXjXl39bc5jelkHK/5BcYA8g7/FKRgsAxSEaOevIdiGTVKP9taeEv
         ftQy3xJ5MQ+Cu6ml1MSTGlXSFv18gskrWVvugbJ71Op9P/gdZZUuwvPhKxAQMIzfRtj4
         1fuYY7Y/ydtEqPPUFO+Ct0hjahjMWcd5PCn80FxurkDDO+1lKYQmswMFDWh9XNd/LNlk
         cqqJIXcwdfV85j7onXSTBq/w4wdVyJY3YPDaA32th4pBoBKnq8G6SWAgXztOm7lNK1yD
         zK11eseqV45EwqhhDqB7H7uJOTjdFbWAz7EiWpqaTetnfN5LpKPMu//GRugAZPupxSc8
         OeHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728024335; x=1728629135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1RQL4f+NgmECNiyRdqgD/khitFvYZgNZ5PMh0Of1C88=;
        b=Ug1tOc5SC5M+qnnmJAg0cxL45soPoO7TblqrR77YoCBgsZkKtEN8Ki1iCdVLdaGJnR
         smQY39Gff9tIKy7AiGH2dGixemqYIPOHs2m50du3nnRatCQNxne3Co0BUgFmE8I3yvQF
         JK+xJrbb/NbU57wzRFJWXvNgPHDVqd1QgKFe6hTysTiJ7ZdEKMalcqq9Ae0uOjnLhPSJ
         dgWxvqV5axD5y+4jwO+HCnkzcItlWFRYfGdAnwBJi5iuw6IAugp3D9iISUWe8lgKoPwn
         haCEJIKAI7z38xmyt+w6lb41TL3YVXIOSLiHvNRbOudI/7fOOZO3E8jDLy0WweZhDUcm
         CsqQ==
X-Forwarded-Encrypted: i=2; AJvYcCUKWsTcD7MTO4eF7zbLzyqYLxLdtP9MiG2Dk1Ikc7CcLCXOCh98LFBS6vKCf/51fn04ObV+wA==@lfdr.de
X-Gm-Message-State: AOJu0YzDEvXECCHmkUidSmUMP3PBq7N8rAdK0K9TGYL/6RPzhOUl0WBu
	EiRXbx1je2TaIm8b38rm7tfC/ZkrFTivJKuZ3DAped5EQ6LsjHR4
X-Google-Smtp-Source: AGHT+IF5ZPCqjuqHyEIuxNWAMdnVs5XqxGmcTZtjVpMZVDIUGKTG2FyWQuH/keT2QvOsUrujIHrZxA==
X-Received: by 2002:a05:6214:4287:b0:6c7:c650:962b with SMTP id 6a1803df08f44-6cb9a4bd0ccmr22546246d6.51.1728024335248;
        Thu, 03 Oct 2024 23:45:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aa1:0:b0:6bd:735f:a702 with SMTP id 6a1803df08f44-6cb8fdbc78bls31031796d6.0.-pod-prod-03-us;
 Thu, 03 Oct 2024 23:45:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZj6kOX3RLhM0WLeYsaRa2Xsb+q9I+NzihYqRuTTtMo7jmDeVBEDgXQgLb/it/jQnxotAxqucem78=@googlegroups.com
X-Received: by 2002:a05:6102:3595:b0:4a3:b777:3613 with SMTP id ada2fe7eead31-4a405905334mr1234195137.27.1728024334133;
        Thu, 03 Oct 2024 23:45:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728024334; cv=none;
        d=google.com; s=arc-20240605;
        b=e2/Munh4dB/sHNZzl05AEAqdLoz8kJsRuKdKWt992LByjZkw2G3G1PngFSnRZa4Z7W
         XyzLH4vvfy44tTE+NXXsBdQTB0W8suqRdOZoVnGTMZjKcgAk/0+1n2LK94drmismaDF9
         5zhmGk51+rCJXYi/6f6kk8aUs8zDnCDuqjSrpaxdK7MQsfcS2BENGbuTfJSwiJtgNxsM
         QX7pJqby6FeHBgZl9AVNRT1WJWAeMfEq1wi2rciuPlQ5T7jvVtmy47AYZ22mi9JHHcS/
         0s/zLDtvNyDG6s8r3CU15Af1nhpsFM3mC4tB7Dr9ZcceKOe8AOB27UET7Vji00+ScyFJ
         9wpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mL2W2tJrDMQeo1z+yDtY45KIaV/M8fHOjbAIS4+Vjz4=;
        fh=p3jaZZVGiZvn7A2H+aSW6l2rq6PsVCQohpdaGcHW13g=;
        b=S1vKXj5N2+4/tnCOHM+LU1fuAPj/RVLQOwm4/4TIhvQebWpidgfT3gTTuFrER87ydM
         vSUdqFqsio2kB6aG6k8Vwbu6Whmpa9SkMlGlwWrswLM/oa8CzIZxF+Ztkp7CxnIaI7b0
         UKLMvdFcnTIh7TgjQLJZfKq+XmxVI4bqQnsRgegnHpRVG/CvIlI4eL/hQr5gkVIdXJ9Y
         pk37kOApIKvkCfdB8GQy4ZVY37mnk3UNSHVE/Hpt7iu6JJ80s4SLxxpCvv1+nimH8VOZ
         pM2Hw5BHAc8/cW4uhpoPSGio3e8yVVFgssgmti6HZXLlcx+PYeoojwYmq74hn+sy4rXQ
         DOrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GJXLhzaS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ae6a124d36si11210785a.1.2024.10.03.23.45.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2024 23:45:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 006d021491bc7-5e1b6e8720dso920933eaf.0
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2024 23:45:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwW1D3CcuY2Y2j0h6XIRDOV70eP37lVsu1y8vn9YJ8vaJ2f6SiQ6IG+WvQkZMV0tsFbxKJGzFxGXI=@googlegroups.com
X-Received: by 2002:a05:6870:364e:b0:278:14b6:a8f7 with SMTP id
 586e51a60fabf-287c20219d4mr1335084fac.42.1728024333180; Thu, 03 Oct 2024
 23:45:33 -0700 (PDT)
MIME-Version: 1.0
References: <20240911064535.557650-1-feng.tang@intel.com> <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
In-Reply-To: <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2024 08:44:54 +0200
Message-ID: <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, 
	Danilo Krummrich <dakr@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GJXLhzaS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 2 Oct 2024 at 12:42, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 9/11/24 08:45, Feng Tang wrote:
> > Danilo Krummrich's patch [1] raised one problem about krealloc() that
> > its caller doesn't pass the old request size, say the object is 64
> > bytes kmalloc one, but caller originally only requested 48 bytes. Then
> > when krealloc() shrinks or grows in the same object, or allocate a new
> > bigger object, it lacks this 'original size' information to do accurate
> > data preserving or zeroing (when __GFP_ZERO is set).
> >
> > Thus with slub debug redzone and object tracking enabled, parts of the
> > object after krealloc() might contain redzone data instead of zeroes,
> > which is violating the __GFP_ZERO guarantees. Good thing is in this
> > case, kmalloc caches do have this 'orig_size' feature, which could be
> > used to improve the situation here.
> >
> > To make the 'orig_size' accurate, we adjust some kasan/slub meta data
> > handling. Also add a slub kunit test case for krealloc().
> >
> > This patchset has dependency over patches in both -mm tree and -slab
> > trees, so it is written based on linux-next tree '20240910' version.
> >
> > [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
>
> Thanks, added to slab/for-next

This series just hit -next, and we're seeing several "KFENCE: memory
corruption ...". Here's one:
https://lore.kernel.org/all/66ff8bf6.050a0220.49194.0453.GAE@google.com/

One more (no link):

> ==================================================================
> BUG: KFENCE: memory corruption in xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
>
> Corrupted memory at 0xffff88823bf5a0d0 [ 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ] (in kfence-#172):
> xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
> xfs_iext_destroy+0x66/0x100 fs/xfs/libxfs/xfs_iext_tree.c:1062
> xfs_inode_free_callback+0x91/0x1d0 fs/xfs/xfs_icache.c:145
> rcu_do_batch kernel/rcu/tree.c:2567 [inline]
[...]
>
> kfence-#172: 0xffff88823bf5a000-0xffff88823bf5a0cf, size=208, cache=kmalloc-256
>
> allocated by task 5494 on cpu 0 at 101.266046s (0.409225s ago):
> __do_krealloc mm/slub.c:4784 [inline]
> krealloc_noprof+0xd6/0x2e0 mm/slub.c:4838
> xfs_iext_realloc_root fs/xfs/libxfs/xfs_iext_tree.c:613 [inline]
[...]
>
> freed by task 16 on cpu 0 at 101.573936s (0.186416s ago):
> xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
> xfs_iext_destroy+0x66/0x100 fs/xfs/libxfs/xfs_iext_tree.c:1062
> xfs_inode_free_callback+0x91/0x1d0 fs/xfs/xfs_icache.c:145
[...]
>
> CPU: 0 UID: 0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.12.0-rc1-next-20241003-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
> ==================================================================

Unfortunately there's no reproducer yet it seems. Unless it's
immediately obvious to say what's wrong, is it possible to take this
series out of -next to confirm this series is causing the memory
corruptions? Syzbot should then stop finding these crashes.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM5XjwwSc8WrDE9%3DFGmSScftYrbsvC%2Bdb%2B82GaMPiQqvQ%40mail.gmail.com.
