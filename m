Return-Path: <kasan-dev+bncBDKPDS4R5ECRBW5CQSJAMGQEYY3MOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id ABC1B4E8BA9
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 03:37:33 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id o13-20020a17090ab88d00b001c96a912b04sf3260754pjr.5
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 18:37:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648431452; cv=pass;
        d=google.com; s=arc-20160816;
        b=lfIfvepWhGj8Fl/7ntHfuANbhhb557jnckxX4f4104fmCakj3eY/DTuoq+xms6dIZo
         lCmK383hAtYRVl2mQ4Y5nm7O3aKSek3LxNaxI/EUf4o/GVVJuNoEprvLvLR5ZNR+y9AO
         IHM6i4l4YKMoR+AqtdHXSjREt74zr+qC+No6W0hDOgCDRoCV+g0+HDtroxya28ggMe4D
         EPh6S/B40m0FRzu3geV1c5zRTI+CZZd7DBXRtGraqANWV41pTynv/AuLFLt8DAzZraGR
         tJpA3nm5XjskJlExxLdmfgm4D69HrZ32MHAm7V9ya76ulqOsgmsNrzpcMo8gGh8A0XA/
         CHNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=oFM7K2EMU6L+5oGt2uW92x/B97ZgmsY7FBZJVibTyno=;
        b=nRoGBSYgWwL6o2nhVLk6y8yvMOB/zFNvRCljjal1ffQsK215nlRbfU6cexuKihmq2o
         8QDyyTDgPq2KHQVJnLpvqusmpA8cw4vhhynrTS2LCFYkvTjhj0l6WL6MhZtxwReLSBJ5
         Vu4lvlvZpooDy1qDJEj2+ZhVKchjq61ji1GxRZ33Ay1QFsIWPUEO+KEN7OmtQSG4FZcm
         0v5FaqlYFrFnOvMB6RfieoCeNZVKpAuNOB0jFDLGQ8hUZJN3pzQOJV331P61riER9Pmq
         9bKHXiioWm5x8FM38qD09sZe2uYDAtXz79Vc3iK7lbGVWyPGsLi6E1v+eTe/exdI1DsL
         y8QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=Rfi7hxBh;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oFM7K2EMU6L+5oGt2uW92x/B97ZgmsY7FBZJVibTyno=;
        b=rHqDvKviN7ABMZl0evEj1XQs1P5toVgBumBXhyeTM+DJ02VPaTEg6ts7rmP8ZN+iv6
         Iq7fgGhQSnNl+FHRXF+LGlxCvd4m63Xe7G39n6F2DsI99zJbBRulbRNJjya2/6CJ6Dle
         A6KnoSwnrSvIOgqwj5bOIzDZFBjTFNQ1Hf1GXcv9dfVuUt3ibukMQyMrhtPTxIW/zRmx
         7Lgqku/Cdvz8PZk5dC91goNFloVJ1TZDlkJKwmHix/pVG1Lqtrm+dLxGxyZBJ+O96R5x
         PSX7LWv4ad2GEiPCzYZCCG2l6JVHLrfCevOSvXJOGeBOThTOReziaCZvA8WunOsY+0Ei
         z9Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oFM7K2EMU6L+5oGt2uW92x/B97ZgmsY7FBZJVibTyno=;
        b=IVDGm5eXAElFydiT16TrtNTMQmUnOv2W82hwC8O9c6J9huckJOdBvWon4oeeetIvP7
         ekVM54MWinEkhUxv3cww0ZUhoec4f2w0h7N04sc+3Y8cFYwtPd1+/V9Cu7DjpDFGyTxr
         V5Ijc5YghjKGNPRw+ZFqoTwBBQZxfmJ26kl29GYCril4YsIM+5BDPD2A7GIVJeCjpEcF
         riwADj2oFKoBd/V9qh9/J2ALCH143qDT/Ew4mYM4IpiArD6Z0si6XUEn/S301Ozkpqt7
         vQCdRsPdmVH0yHKikGSB1nzKnUMkBHyOWDf6dDyNxKB+7blUYhHqd/FY+4f3v5pkFhCU
         euCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ejf++dIggPgtbph35LTi38ZdfsAkUXu5H78jKJozQrni2Bg/f
	bqMl8jvCPrj9eOCWIhv/uMo=
X-Google-Smtp-Source: ABdhPJys9uuqnQPPfH9sIDP1fj1vxD2BbDhOe0FMgPKRrZi4fJRPj+HHGt9wM5Vscmmfmmdt7Aw04g==
X-Received: by 2002:a05:6a00:2402:b0:4e1:3df2:5373 with SMTP id z2-20020a056a00240200b004e13df25373mr21290638pfh.40.1648431452004;
        Sun, 27 Mar 2022 18:37:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8c:b0:14d:d65a:dbdb with SMTP id
 m12-20020a170902bb8c00b0014dd65adbdbls8746530pls.6.gmail; Sun, 27 Mar 2022
 18:37:31 -0700 (PDT)
X-Received: by 2002:a17:903:20d:b0:154:8227:a389 with SMTP id r13-20020a170903020d00b001548227a389mr24005893plh.142.1648431451425;
        Sun, 27 Mar 2022 18:37:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648431451; cv=none;
        d=google.com; s=arc-20160816;
        b=Sjy2rYgl4vF+HA1sjvoP+1IeXzd5KCr1mjvZQtA0WPOERFQ/rvVoJB+HExkTFtfM5x
         PDIkIr3Q8PFY8Ln+ruaSnY9HZuis78FGauw1j+6mynl3Zyryt5pWQRZF3gHBkE7cLZPx
         MREzLKg2w3leSE4hzf7/qMOCgtb7PD43sCF0DeCFB6cQsnP3my47reZdXKawiEsUtS5K
         iIjGPMVxRebZ+eqUfKZOvLzVHndHi9Iu5CtTk4Q2SmG8lLh9/ZULmwv7VIKU4se5rt1U
         OoTTi7yu2JmJA3jMKj28J2q+EeGm2Kz4AfVKd8cHEUPXeYSMlLtU55M+HlhGdEUdz9RC
         6QLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vdyfkkOtVcY9wMmcQ9hL8yLIG6KQpQUvBHwAp6nqkPs=;
        b=Yz0aNyMX1ZRBoTfsyUpZdw2FAENrLu0agA7Yr+++5JOMLOlmcwgHGNK06XUkcq5aoD
         s6npbz/hJ7Su73+/0YAUi62288B7oI3PaFkBxdyHVkFi71c9xgB0oMABUmqohXq71Zej
         kKc2t3vycdNCXJL6yURefJoXTCr14mCF/GBPzXC4XkM/Uop0aQpijbGu3bK9r1us5L03
         MdV+/oUcw1OoawMxOzL1PAqVGAdBQDVJfahZpcy72wCp3oQ3zQoOF0J9ndEHBSlQjKy6
         bF1P4/jnNbEqN1lGoVeP/gVgH3t0IauPIwd9A76VIeddmrKh/6O4W4kEEPKttXsfPJqz
         dlPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=Rfi7hxBh;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id t19-20020a656093000000b00363bc052cd4si683898pgu.5.2022.03.27.18.37.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Mar 2022 18:37:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-2db2add4516so133595137b3.1
        for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 18:37:31 -0700 (PDT)
X-Received: by 2002:a0d:f685:0:b0:2e2:22e6:52d7 with SMTP id
 g127-20020a0df685000000b002e222e652d7mr22805715ywf.418.1648431450769; Sun, 27
 Mar 2022 18:37:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com> <CAHk-=wh-mVrp3auBiK2GSMpuqS10Bbq_7fRa6+=zt-0LiF7O2A@mail.gmail.com>
In-Reply-To: <CAHk-=wh-mVrp3auBiK2GSMpuqS10Bbq_7fRa6+=zt-0LiF7O2A@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Mon, 28 Mar 2022 09:36:52 +0800
Message-ID: <CAMZfGtWV4cOvD1DxOXxaX2-FB+_sfquBFS+7s5DBp59k8cL-RQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm: kfence: fix missing objcg housekeeping for SLAB
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	syzbot <syzbot+f8c45ccc7d5d45fc5965@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=Rfi7hxBh;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Mon, Mar 28, 2022 at 5:08 AM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Sat, Mar 26, 2022 at 10:19 PM Muchun Song <songmuchun@bytedance.com> wrote:
> >
> > The objcg is not cleared and put for kfence object when it is freed, which
> > could lead to memory leak for struct obj_cgroup and wrong statistics of
> > NR_SLAB_RECLAIMABLE_B or NR_SLAB_UNRECLAIMABLE_B.  Since the last freed
> > object's objcg is not cleared, mem_cgroup_from_obj() could return the wrong
> > memcg when this kfence object, which is not charged to any objcgs, is
> > reallocated to other users.  A real word issue [1] is caused by this bug.
>
> Good that this looks sorted out.
>
> Patch 2/2 seems to still be up in the air. The patch not only causes
> build errors, but it looks really very odd to me.
>
> In particular, you do that loop with
>
>                 __SetPageSlab(&pages[i]);
>
> in kfence_init_pool(), but that is *not* where you set the
> MEMCG_DATA_OBJCGS, and instead do that virt_to_slab(addr) dance later.
>
> That looks very odd to me. I think the two should go hand-in-hand,
> since that __SetPageSlab() really is what makes it a slab thing, and I
> think it should go together with setting the slab state correctly.

Right. It is a little odd. I'll improve it in the next version.

>
> Finally, is there a syzbot report for that second problem?

No. The second bug does not trigger any oops, so it is hard to be seen.
It is just my code review.

>
> Anyway, should I apply this PATCH 1/2 now directly as the solution for
> the dentry issue, or should I wait for that second patch? They seem to
> be related only indirectly, in that the problems were both introduced
> by the same commit.
>

I think you could apply PATCH 1/2 now.  PATCH 2/2 is another issue not
related to dentry issue.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtWV4cOvD1DxOXxaX2-FB%2B_sfquBFS%2B7s5DBp59k8cL-RQ%40mail.gmail.com.
