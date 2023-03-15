Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXGZCQAMGQEOHDPGZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C81B6BBE79
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 22:05:20 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id l11-20020a4aa78b000000b005254a9621e1sf5510366oom.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 14:05:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678914319; cv=pass;
        d=google.com; s=arc-20160816;
        b=keFTdLDjdRwvsPqd/CDdmnrPXr5utCkZuxrZ9SiHkHxK1zi711b3z2sk9UmE7o9oO2
         Qrz3tvL05eHo7dZves4bms7DxRTnw0iwAlE+ZB9enI0Pvem90lcuzCWlRQYzyUImGGan
         0vdDB6fZe9J1OuDfB8pOYIcmfaXKFal5lI5H8Obdz3y8z7nbeKGxWzDf/Dj5cJfQ9KLq
         0ka4zFt4wblQmb4KuRoBhBe+ib/5ekZk68FsydhSmjbrpHyfd6lTzkgYrBzZnqwXKn0g
         bBRaqXa6+aFjLRWMrkBzwL2PUwofCLxu+lmmypf/3i0gSEi0cxxPwLm3fgAuJ6A8lwh4
         dFfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D6HxL6FSJakmshQQeTtHtiwA9y0SHsIeyGLfTk5nBmc=;
        b=HqPsmqc5sVUIRHTPMMvhTWmzzi3ZrmYKQe4QlFihmuQ3XN4cK218w+Ss/iYfrsnUbr
         HrrehgIMGOnxvOREwB1D/LDLDXgDMN21kE2PUbq370wg9lAcl5M356S1Q3K2iCADY/5R
         ordfNEDEVbejjrEose2nPFGOKCo0M56y2JCVhbMQ58QAS6mf6o9alsLpaToz7xx47Fw9
         JOxL28wTMyBwjR14gGq6NVIoHergH0G1FlW0bksjSsB5g/kyNhb/sfBNZbh+fiId0osF
         8Mx3tm54wFvY50iEfszc3TgW7WrMMxTX7rGAiL2cA5FyVIozdyTrA+e+Mb8/dnzZW5E+
         OmvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzSWvQUx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678914319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D6HxL6FSJakmshQQeTtHtiwA9y0SHsIeyGLfTk5nBmc=;
        b=TMskstNhkgrqWwezrlZpYW2bAaekTvnA3jG3wOqo1ncPSTlRr1tUxaZHeTZcf8aFea
         rn47jREAAdaoPlv0Rr1aGc90FdrkbZ0BsU1zuaJHOLQVOFjHwpH163diu1MV51a59OdY
         xxuWor0zkgatHdJIOWfqa5uheWw47Et+Y+jSYB59uqZbpYgjTWkO3M9RiWDEAqOOiD45
         Y4AE8MeSzwvvqDqgz6CjQf7pyPnGuMOG5ZIU5x7bgyDFM5sdxbqqBCREH8We4pPBwUSg
         js9rxWFuPhtR6Hz03QkwfZ+lqYvZZdYHmeoRtFI33EJOppKc1Ry+yJbj/dHAjTN9IZfE
         kQFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678914319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=D6HxL6FSJakmshQQeTtHtiwA9y0SHsIeyGLfTk5nBmc=;
        b=qloFHbOk0OeL7OxloTO1cNFcui1enlJ8svIboeYGW/H0DAP5icAfJcNdafb6nyl1D0
         rW+A7N1cpHlh6bJpEIzqN86NQtPGGXxDfmb38Yly2nhVQKDhZsgBrOlPUuOjDX6agWyZ
         2e+r6oeu9ssjsZWZTup46XqLKiHJAqCPqlimc3flyYWx+xC+0W6vWwT3iaosHBIHyxl6
         D/NANYgTnHRVDPk5QSuN1IbItI30yy3uxDrx5Fi3olYyWZdNVLkpaThqF+8p49ByT85F
         TLaCr2PCzcto7ilTnoL/kyTzLm/dSk4HGGQ91UDgP3pJ8OgKaNz8mEwwAn72biTCzsR+
         dsJQ==
X-Gm-Message-State: AO0yUKUVsdMXBK5jClEIQvZk1++TLJt2GaTp84x/ADf3MBrY2XdfL+ji
	AFl0Tg7VdFimJ+HS18ivFyvUrQ==
X-Google-Smtp-Source: AK7set+z3r6TRj8U7JHXOWfSxjmTcFHT73p5ylc+B/jBChFwcUUo7KEtKx/cW1A6NqRgWaFp906khA==
X-Received: by 2002:a05:6830:3347:b0:690:ee75:741b with SMTP id l7-20020a056830334700b00690ee75741bmr14427218ott.6.1678914318862;
        Wed, 15 Mar 2023 14:05:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:60aa:b0:172:899d:3569 with SMTP id
 t42-20020a05687060aa00b00172899d3569ls9465434oae.6.-pod-prod-gmail; Wed, 15
 Mar 2023 14:05:18 -0700 (PDT)
X-Received: by 2002:a05:6870:c350:b0:178:ff14:5dff with SMTP id e16-20020a056870c35000b00178ff145dffmr6651920oak.47.1678914318372;
        Wed, 15 Mar 2023 14:05:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678914318; cv=none;
        d=google.com; s=arc-20160816;
        b=r0h/s1Oz/3jTninrbP0DZMvtrLuB8DzMKbAjHa9JT1SIVqfUxrguOXvyTBA7eJsJgL
         //1f+5S/e4gcmPeixCOal/vezoxtHfZ/kxy4g0z0vDX6ejM3MzfZKnmgrDciL572rAWm
         fVOYQ7hpy2O78CJ6bEweitZb0kcbMwcOK+r8rTlS8DYg7cILyEXYhwMXaW1Ev34l+MhQ
         3Ro/9ZodLSy75QDsDl1bNqKyrOx7LLccNNJH9xO7AxGZObqBe3vaEiUXrJ9g6KgOFJAs
         W3hoC0m8CZeDXKaUkN2Ip4OVPxl/LfB84UVD3Sr0B97kBGe7hFN0YEtGqjdeMU8sqtfK
         iirw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IwGhmwR58ADGQ+ITIo7v6jnjt7oIvun400KU/kpOQR4=;
        b=p11eoFBKE009zEuYgEXQhfowfBzI3mG7iOUuCo/Kd8qVCYnEzU3B+7MNkFECDTBRTv
         sZTB33Te43omz+D6FxJ0wkSv7Fu87IwcD9ELI9tvN3ogi+QDgJCEw7DwOMGgG6lay8wE
         4So1b8k4oxfAJIPrypw9DcS6G4eFrW+1i5DaIxuWHhjiWj34oPIzG7+7qLc0W8kdjVab
         uQC/hBYXficnLuO230+G9kanwbo013hCTmOX5dg661gOsDw6s4dmBrmPUuDfvj2OVgpi
         mXpg7dVMV8PgzKCFQbFvicpcSrCX/OGuKoRwBENhyomw/s5FO0o2nx0EKedS5tOnFtDb
         3YzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzSWvQUx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id hl22-20020a0568701b1600b001763813b106si1117259oab.5.2023.03.15.14.05.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Mar 2023 14:05:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id s4so1272027ioj.11
        for <kasan-dev@googlegroups.com>; Wed, 15 Mar 2023 14:05:18 -0700 (PDT)
X-Received: by 2002:a6b:ed02:0:b0:74c:8243:9291 with SMTP id
 n2-20020a6bed02000000b0074c82439291mr19019902iog.1.1678914317895; Wed, 15 Mar
 2023 14:05:17 -0700 (PDT)
MIME-Version: 1.0
References: <20230315034441.44321-1-songmuchun@bytedance.com>
 <CANpmjNMxDT+AHBZra9ryhm6aw+WqBsdJ_SKdcdZr6CBsh97LyQ@mail.gmail.com> <20230315125425.70a22d32cf46b23d249775ec@linux-foundation.org>
In-Reply-To: <20230315125425.70a22d32cf46b23d249775ec@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Mar 2023 22:04:33 +0100
Message-ID: <CANpmjNO=_Oi++xgywqcnj2W0dyX96zmUd+37BSbmwMd0=c_=Mg@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: fix using kfence_metadata without
 initialization in show_object()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Muchun Song <songmuchun@bytedance.com>, glider@google.com, dvyukov@google.com, 
	jannh@google.com, sjpark@amazon.de, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YzSWvQUx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 15 Mar 2023 at 20:54, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Wed, 15 Mar 2023 09:07:40 +0100 Marco Elver <elver@google.com> wrote:
>
> > On Wed, 15 Mar 2023 at 04:45, Muchun Song <songmuchun@bytedance.com> wrote:
> > >
> > > The variable kfence_metadata is initialized in kfence_init_pool(), then, it is
> > > not initialized if kfence is disabled after booting. In this case, kfence_metadata
> > > will be used (e.g. ->lock and ->state fields) without initialization when reading
> > > /sys/kernel/debug/kfence/objects. There will be a warning if you enable
> > > CONFIG_DEBUG_SPINLOCK. Fix it by creating debugfs files when necessary.
> > >
> > > Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> > > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> >
> > Tested-by: Marco Elver <elver@google.com>
> > Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks, I'll add cc:stable to this.
>
> I assume the warning is the only known adverse effect of this bug?

For architectures where the initial spinlock state is 0, the warning
is the only issue. For architectures where that's not the case, it
might result in lockup of the task querying the 'objects' file --
which isn't the case for any arch that supports KFENCE by the looks of
it (last I checked 'sh' and 'parisc' don't support KFENCE).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3D_Oi%2B%2Bxgywqcnj2W0dyX96zmUd%2B37BSbmwMd0%3Dc_%3DMg%40mail.gmail.com.
