Return-Path: <kasan-dev+bncBC7OD3FKWUERBVE2YWMAMGQE47AX7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE5B5AA450
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 02:24:54 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id x8-20020a17090a1f8800b001faa9857ef2sf334653pja.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 17:24:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662078293; cv=pass;
        d=google.com; s=arc-20160816;
        b=QrdJPtV6jpIIaaFwKfXC9sej8wfmUMxtgcpNa9yD80M4JyDUIPEwxypv5NKu5Rv1j4
         tEQpdXNkoMCuSeXvQUgLYNZdV3qMy/ERxDxxcEe0Nm9vtjmwegx8Fo1Xb+I6ZMQBn/aw
         p5hFc9cOBoHPe4rhvjR8lL32qGPGu+yAOHAjjUiElR78s5B+VxzR9ECVqsQruwpiylGU
         TnoiC7L9NtEg6idERgl1BM+jypHM3lDWL/nr0XcHu7yoMLCHJ1m5wXW7GmGlibIJB7ai
         eKnE9JkV3MwPWVGOccjLyvY3TFreAdhqaZXoD/OfOWi+2iVuJJk76jEmu74Fvt92nPJa
         cvRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vPwm108P7nWLZcIbIf9FHfrM/6aaZ78NN2R+FaQ3Ijo=;
        b=YUPSA6dxzmVigHJuwQsLWN0X5ZnJXyxcesEH/09aQdSnF2/oMl5ZupTQPcX+ITDmlu
         IfobhWtUEs+I35F7XQPsmKYZv9q3olMkwFZ7X2LYvJs+KSw4J5lXFyisgPnY46FkK+yl
         ttH7egC9pxLGpbz6Nx3BwJMxaVJdVXw/ljuPrxIDPcR4ZOca9L2EkOW3IBgoWpLpRN6W
         0hER3Be5E4jtPjUzfc3UvGaGQahvi0Wh2Z48QLaYK9bHeZiF5bPPkTEftYrcYgmAfv/E
         +owBQlS2ED5WA0+ad27FOd3Rd7TIa0fVakZrk04dtdite8/Asb5iRZparq21X9tFDPco
         t2MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JFydOg9Q;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=vPwm108P7nWLZcIbIf9FHfrM/6aaZ78NN2R+FaQ3Ijo=;
        b=bRC4r7+WOfMFCdXQPazFpDEcmdPqLCF+qk7O7B1yBKj+EyUIXpwmuB3Gvsa2h0q/x0
         ihONyenVjTrwXqIaGMrIevjCJBiNE9obaprFX9US34TEhVvisEbDrTwH03rH56zwEWd7
         Tz4L1B1uJwne1dn2Sd8xkRg2e4TRsz16q4TAgDyMGXrXrux7xKr9BcB3cDgKCO1vK9Sx
         KEWTn4XSijHeQ0tgyVRdKESy6UUviDCCexlaEZjfoZPym1T3EXauLoWoSJc7BUhK9ONo
         pXqHaZtXERa5ENC5+K6TwiadSRPCi3GYHW+vWVAHPbMFdopF/CsSX9VBlF0j6Akm4DO9
         9mlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=vPwm108P7nWLZcIbIf9FHfrM/6aaZ78NN2R+FaQ3Ijo=;
        b=eR21b3nQmBczZ9QEomGnuN+4XJNoh3Bn7GgqyoB5LDTK20efegTg+wv4R8IRHGs2+W
         hOTx64O/3R6HD/n1xFXeOlqdCUsMpSafTBUUBC6gtb0yb3HNG3Sa3vRaicBlNTWLNDcv
         HrngX68kcT7UMa0nqhzLdyioK07SC6HGLyEF3AMrlIQ3AlqHURA4GNsSI82M1a1sJLwm
         Lt0lY3BUCEJZUBHVh5QplXVG+otcLxntRfDem45lFwMJIffg9dAajxqvYQKavC9bJt47
         8zt21gFN7IR3TMBxzT5NKC2G/QVMLTYBrBHQxQB83asiMLsBo1MMB14iuhO7E0xH1Q4s
         ZNxg==
X-Gm-Message-State: ACgBeo309e22ME3k9L4DWe43e8ktw0D5ydZHkMk0hWpGAZ/YRX0R5QSQ
	aubl/iDsi65SOvzqyIMbSUI=
X-Google-Smtp-Source: AA6agR4MY1Nd/smAr+R94O7opfCd5lA/V8Nf/7oB5FPOziuHvH2UXEsOVoYMoUOOOIjSBtKZmkbRtw==
X-Received: by 2002:a17:902:6a8a:b0:173:14f5:1d89 with SMTP id n10-20020a1709026a8a00b0017314f51d89mr33336397plk.89.1662078293151;
        Thu, 01 Sep 2022 17:24:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1b64:b0:1fe:2dcc:657a with SMTP id
 q91-20020a17090a1b6400b001fe2dcc657als4293809pjq.3.-pod-canary-gmail; Thu, 01
 Sep 2022 17:24:52 -0700 (PDT)
X-Received: by 2002:a17:902:f68d:b0:172:a34c:ff96 with SMTP id l13-20020a170902f68d00b00172a34cff96mr33156278plg.26.1662078292346;
        Thu, 01 Sep 2022 17:24:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662078292; cv=none;
        d=google.com; s=arc-20160816;
        b=QQ19x1AoSPxp2mLBQnSXjmRzIi8bJCHqq4HuL8mvwO9uD2+dzO2K7kvmkRTI41P4KO
         ch7ApzBZOJ+VOaSudf51MZEqZPHqV7S59/DZai2Pu4syi/CXOK7d6F6/hs7IJaPSOpF8
         rnvDGNva8hzN4JQZ6fZatFJHYLI8c1H453ETTQvjwIb2xsrD/4EmJaERwGGjNjXeCGe5
         K0jCY6aOwZx7aJaw9MZXt0XV7vpOdYxofxI8NlRXHsckOOx8sgZg5ylpBedZ+8MVL0UD
         jtMEnrjdrykG9d9ymyPf9RUHE6z2hU25bfNCxdaXVozALrxL9CAOtKIYQAZvO/gqFUGN
         sOrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/pPOPbPw8AnpH29BUzSqTrm5ZvDmaEgEyFxuBQlNiEg=;
        b=B1bITwomDKZtduN0Yzm9/Ox+EhUp3sjIZx7W7iahhCNGZSeUAmriMgyg2PfmbaQT6r
         DG2kZu1NGREu7S14QWMiWKv+Qg7klvOH1B8u6+6WDh8znIidfRveV+2oL28QUsrVwlLE
         dxXw52upJPmo6bGK6xfFqHv53K2SxodAvtyEErs5M70XQHkefTix4bSHOqZ8VEdov1IG
         ojVAfDQqNJx+NH9SYhlmbvp/fjqih/DGIrtIUuD/mOsAzvzF+1GLF+KqNrTANfevq990
         g+mkHdK0MEm7LmqaHXU7mnw0AqPcg1ZBxe/wd6aahwH7pqboimLohZa383aMSatf2wm9
         MG5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JFydOg9Q;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id h10-20020a170902f54a00b0016bf5c9dfb5si16265plf.12.2022.09.01.17.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 17:24:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id t184so1074472yba.4
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 17:24:52 -0700 (PDT)
X-Received: by 2002:a05:6902:705:b0:695:b3b9:41bc with SMTP id
 k5-20020a056902070500b00695b3b941bcmr21283555ybt.426.1662078291363; Thu, 01
 Sep 2022 17:24:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-15-surenb@google.com>
 <YxFC9NSQ7OADTEwp@P9FQF9L96D.corp.robot.car>
In-Reply-To: <YxFC9NSQ7OADTEwp@P9FQF9L96D.corp.robot.car>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 17:24:40 -0700
Message-ID: <CAJuCfpGRL72qghDf9bNsp_K0kabvLBs5ags2hHXn-5_Ar8RX5A@mail.gmail.com>
Subject: Re: [RFC PATCH 14/30] mm: prevent slabobj_ext allocations for
 slabobj_ext and kmem_cache objects
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Mel Gorman <mgorman@suse.de>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JFydOg9Q;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as
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

On Thu, Sep 1, 2022 at 4:41 PM Roman Gushchin <roman.gushchin@linux.dev> wrote:
>
> On Tue, Aug 30, 2022 at 02:49:03PM -0700, Suren Baghdasaryan wrote:
> > Use __GFP_NO_OBJ_EXT to prevent recursions when allocating slabobj_ext
> > objects. Also prevent slabobj_ext allocations for kmem_cache objects.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> Patches 12-14 look good to me.
> It's probably to early to ack anything, but otherwise I'd ack them.

Thank you for reviewing!

>
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGRL72qghDf9bNsp_K0kabvLBs5ags2hHXn-5_Ar8RX5A%40mail.gmail.com.
