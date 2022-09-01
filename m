Return-Path: <kasan-dev+bncBDYYJOE2SAIRB2EHYWMAMGQEPXWSJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4995AA3DE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:44:42 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 36-20020a9d0627000000b0063927bfccb5sf265275otn.18
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:44:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662075881; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPhP8vDv/f0rX5u67na1AF0nk4YWF1n7BlTgtq6ZuFSo4PvJzDQuChvQyusrMuVg/w
         pQpHodciGCS2CF1h2X81PYlXN0V+yWo8Ga1q7hb5gdaRsCPjKJjcoh/kGJdV630u0mrd
         FvxfEplf4u3DMvpEk4nB/TrQnBL2x2PAdr3BkbxtuYMB/vbW3Rg2lIdHjGEkU1gufA+R
         Odojn9hktIsCcbhZ/CBXboAAYC0SCocaR2Wi/einik5AjMHTqY6t56Q05BjCmV3qy5EQ
         JPr8You1hUKiTrUCu1KFZAso6i1EL+Ta8HjOvMstkJtSgK0rhL1ILAhwj+3Ft2LxTp0l
         FrHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GKWSYYZkkKMa3SzKn2ZYdxXDNe82EeEqOr0/TlAhB0I=;
        b=I5Tu1AZQM8KCL+vxzTUv7faIWjC1gWQ8I4jzxswXaCE4JcpAh2BS7K2NfxCtUqTAA9
         Hve0c/v/1Clu7vMZCGJvg4vmu5gumMR2S7k1me1yxqJUxxMD/e9Qv/Zq6NrSq8nCPbsu
         FWkXVdWyn0bdAxqRdDSNa0pns6h/kV7E9gPMHgXHoftZGM7DIpY0JqEoQwYGI6xWq2SF
         wCdtzBgBDqlLUI3EN/Pvm9CNcP5oyf0TOHOpNyE+SYBI0Wx2KjvXD5XUs41/Yv7eMEni
         1e5cCm/VCfEyffzAWl+a0dPncJlp06YYP4IZbXPYAUaJaF41aAh499AvdziHOrr68qP1
         kRsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d64iMYOS;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=GKWSYYZkkKMa3SzKn2ZYdxXDNe82EeEqOr0/TlAhB0I=;
        b=RVQyVjXFi+Fv/kQgcHfoym+BEZ1Eoy4yYEINYN8BY9/fSh8TzvWz4BKApiP25mR+tu
         DBwWy/YKAblOJ31t2dkQtSebDmQVqHJzqB2qxRgWEO1FpRw7ewyh4d1z303cCaow3L7b
         BL95efR90DU2rcbTWXRkjeJLHdx3Xq8J1PviRZnRAnmoKI1qE6klHd9AZ3Qh2kD+t3+S
         n/TNSIi4tGFmYJjtsIWwLoSl32rrYtE7kA1ONAssuaoZUPcMN/23tnAOJYNOw/fBmQTi
         9GFEZkyoK2xSEutM+CvDyp+s68cnFyDQuglnHfh3HwGLB5qlHmB2/rdA8hGfrqHFHXY6
         4AJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=GKWSYYZkkKMa3SzKn2ZYdxXDNe82EeEqOr0/TlAhB0I=;
        b=zVk+kE3GOgAK2viVST4ymhT7nbwIYpX+Sx2pjIpHpqa3052MXzjHa5IJMfpaJzGwj8
         4U2z0EQ00DWquWpmLDjq7mc5R5Ac2G4+58j2tMZ+Q4browJf63XVcyLz853q38uQskqZ
         /0TWrJ5sZ7fFNas51i2ENicEC03Vg4/ZkmbOG01Lv57I0CSSbXQAObFvxjUW0OIx5Ccq
         ja7iNkLDhh+F76YApWeJxJQ633qu8p2UBCWA3WDfDADmj6cldJzi8HN0vsAsCVGWlGhL
         b4pQzxyOdHJJYI+nqe4SydYhpJiTPygNlF7SJ37+UeF2nvwOgBB5Acz1fpHQ7sSHGEnU
         0HzA==
X-Gm-Message-State: ACgBeo0JeNlCwppiU8jTcFn9huPdsAs3Rt/LDcaH8QnOi85fcuHE0BIz
	0TEYexkM0twRlDXwapo9nlQ=
X-Google-Smtp-Source: AA6agR4XJK1yhR4Z9T6utL88JXztzJuxUVcESz24Zs0RRvDmTds92DLma0t7AEh1I3pv8N0WDGj3rg==
X-Received: by 2002:a05:6870:5599:b0:10d:cd9a:3d46 with SMTP id n25-20020a056870559900b0010dcd9a3d46mr879491oao.18.1662075880998;
        Thu, 01 Sep 2022 16:44:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3816:b0:116:c21d:f9c3 with SMTP id
 y22-20020a056870381600b00116c21df9c3ls1384701oal.10.-pod-prod-gmail; Thu, 01
 Sep 2022 16:44:40 -0700 (PDT)
X-Received: by 2002:a05:6870:41c3:b0:11c:3697:6632 with SMTP id z3-20020a05687041c300b0011c36976632mr96027oac.1.1662075880470;
        Thu, 01 Sep 2022 16:44:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662075880; cv=none;
        d=google.com; s=arc-20160816;
        b=CBzvANClGvADw+2gp9CFa8I4Vmz0IoW7oc5SUNVpJDdLwXfAoPwUNkWkj/cIRdvWIR
         u3stD4Nda0DJyaDA1EAa3fX8TXLb25hKSLomDm/7wMLhFrDtD1G74MY5HHkLAdwtq0Fg
         ye+1QDo9TQ8Mg2IDqkJjUgWKeMxjCo85Tz7hhXE0JNtC2CdtKwBaW70xDNAwmjGwWkbh
         XFshe4l3tX48NbtEp/V+GVve++9ewnfLst82HgNUVQdZ0C4n2tKeguQmDn94R81gV9Hb
         ETG447Bz3Jca6KNXikbi/IIJtNnek7CMuCPgcd5Uk23D8T5G6eR3sPLw4MlqgGMC+nTI
         nPSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E/w20BQSdzic7HV/DXA4w/RdjxH6IBYdbHhBUiDju7A=;
        b=xRHNpk+YJkamG2ywKdwtp2z0KWyz1TEXWI+9MHE0v4SeYHyuxEC+SjBEIkGA3rGoTp
         u1w9AM99ElJN3wNSk8a1GPuHi484GDlz7mnpMYAjFvxrpYyoo1hvmUT2GHPVZCOolghv
         33uKe7fYtQyRXy1F79hvHNnA0s0fjZqMCbtKOx9hN4ce0HPKnZYtIMiOXwIUdvPjqw9T
         TP/KOZ+5Cu75+fzHqbT6ADLxFS35nc21Qo4C86TT1rFMCRBnWX9AVBpm6X3hKyeCKDui
         yGZFZpcLF1HVBLwtrxqAUUUYOZCQHzUK9c6xL4xAEpjr78QzzpJJPjp/0e6KqNPBn/Cd
         yu+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d64iMYOS;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b0011c14eefa66si99848oao.5.2022.09.01.16.44.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 16:44:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id c2so259089vkm.9
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 16:44:40 -0700 (PDT)
X-Received: by 2002:a1f:2c8c:0:b0:394:76ba:b08c with SMTP id
 s134-20020a1f2c8c000000b0039476bab08cmr6966094vks.32.1662075879803; Thu, 01
 Sep 2022 16:44:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220826150807.723137-1-glider@google.com> <20220826150807.723137-5-glider@google.com>
 <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
 <CAG_fn=Xpva_yx8oG-xi7jqJyM2YLcjNda+8ZyQPGBMV411XgMQ@mail.gmail.com>
 <20220829122452.cce41f2754c4e063f3ae8b75@linux-foundation.org>
 <CAG_fn=X6eZ6Cdrv5pivcROHi3D8uymdgh+EbnFasBap2a=0LQQ@mail.gmail.com> <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
In-Reply-To: <20220830150549.afa67340c2f5eb33ff9615f4@linux-foundation.org>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 17:44:03 -0600
Message-ID: <CAOUHufY91Eju-g1+xbUsGkGZ-cwBm78v+S_Air7Cp8mAnYJVYA@mail.gmail.com>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
To: Andrew Morton <akpm@linux-foundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yuzhao@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=d64iMYOS;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a30 as
 permitted sender) smtp.mailfrom=yuzhao@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yu Zhao <yuzhao@google.com>
Reply-To: Yu Zhao <yuzhao@google.com>
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

On Tue, Aug 30, 2022 at 4:05 PM Andrew Morton <akpm@linux-foundation.org> wrote:
...
> Yu, that inclusion is regrettable.  I don't think mm_types.h is an
> appropriate site for implementing lru_gen_use_mm() anyway.  Adding a
> new header is always the right fix for these things.  I'd suggest
> adding a new mglru.h (or whatever) and putting most/all of the mglru
> material in there.
>
> Also, the addition to kernel/sched/core.c wasn't clearly changelogged,
> is uncommented and I doubt if the sched developers know about it, let
> alone reviewed it.  Please give them a heads-up.

Adding Ingo, Peter, Juri and Vincent.

I added lru_gen_use_mm() (one store operation) to context_switch() in
kernel/sched/core.c, and I would appreciate it if you could take a
look and let me know if you have any concerns:
https://lore.kernel.org/r/20220815071332.627393-9-yuzhao@google.com/

I'll resend the series in a week or so, and cc you when that happens.

> The addition looks fairly benign, but core context_switch() is the
> sort of thing which people get rather defensive about and putting
> mm-specific stuff in there might be challenged.  Some quantitative
> justification of this optimization would be appropriate.

The commit message (from the above link) touches on the theory only:

    This patch uses the following optimizations when walking page tables:
    1. It tracks the usage of mm_struct's between context switches so that
       page table walkers can skip processes that have been sleeping since
       the last iteration.

Let me expand on this.

TLDR: lru_gen_use_mm() introduces an extra store operation whenever
switching to a new mm_struct, which sets a flag for page reclaim to
clear.

For systems that are NOT under memory pressure:
1. This is a new overhead.
2. I don't think it's measurable, hence can't be the last straw.
3. Assume it can be measured, the belief is that underutilized systems
should be sacrificed (to some degree) for the greater good.

For systems that are under memory pressure:
1. When this flag is set on a mm_struct, page reclaim knows that this
mm_struct has been used since the last time it cleared this flag. So
it's worth checking out this mm_struct (to clear the accessed bit).
2. The similar idea has been used on Android and ChromeOS: when an app
or a tab goes to the background, these systems (conditionally) call
MADV_COLD. The majority of GUI applications don't implement this idea.
MGLRU opts to do it for the benefit of them. How it benefits server
applications is unknown (uninteresting).
3. This optimization benefits arm64 v8.2+ more than x86, since x86
supports the accessed bit in non-leaf entries and therefore the search
space can be reduced based on that. On a 4GB ARM system with 40 Chrome
tabs opened and 5 tabs in active use, this optimization improves page
table walk performance by about 5%. The overall benefit is small but
measurable under heavy memory pressure.
4. The idea can be reused by other MM components, e.g., khugepaged.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOUHufY91Eju-g1%2BxbUsGkGZ-cwBm78v%2BS_Air7Cp8mAnYJVYA%40mail.gmail.com.
