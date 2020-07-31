Return-Path: <kasan-dev+bncBDDL3KWR4EBRB26RSD4QKGQE4VN6TLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D39FA2347A3
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 16:21:33 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id ck13sf10650588pjb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 07:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596205292; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEI0TA6AzbZBj+EaDqgikN2cJyy3I7QEMLnOOnLJI9I/ucSky+6vr5cJ7ZF9pPKG8N
         Z18Aev0y/klLeFHoYKz4Wz7grIjvGZyPUe5460BvSofEISuEmTKp95FWqv3xzHtCPosl
         AAXbWhAgZpI5CEEHN6oIK31XjVXw99Cg37V4JgrCVSnNscb1EUP3CNBEFbzxTlugNDmG
         hLHDyMHbCQVTloRQGLwtCrWG5Wb/j5hz9csNOggWmNrgJ3HXv9fMdRF+Z5EzC/eaSK56
         OPAiOoRH00E3iCP/FqWiAHgM/1RxuYDl5LifV8F2dOPFCVndg4KD8L9N04kizijk/KfV
         VnKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6BujTbenabEGSiJ7WZjylT4qdqwfT5E1S/lmjhOYuwI=;
        b=YShdYWhs3AI8EWQPDDK50IX67tooOZAHdYRCGigZbFWomUMUwKVzlZW9tvTB6EhgMb
         u1vS2oJhVdwuwwyOFTojxJL3Lr/7rOKIjoPUscFRwHX/n8WRYvmt9ClfnSk5j/I0fsJU
         0GX+plCELQcmVgnSc3MIavHyPuBOVX6Y8sfALlXfMeEsmOnE+yy9vbGEAKIhMnXrPIRu
         sBttT+s9d21vmkguEvm1P90jHpY+zFBrrv/CB1JOieEcw1VFWdP1LFqJxrqt61oSsu+Y
         SAX+htsfEdn+fd/kMRigaqNJYdSy3NLqCQrPxlobJU+k2hRPxEMPbKzqry8YRA6oD9yS
         /uQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6BujTbenabEGSiJ7WZjylT4qdqwfT5E1S/lmjhOYuwI=;
        b=hYDiPiZMuQroBQVUhh4byCgWr3grIoxZVIxuBT51n0Mh4tH1F3yPYhiecbI/7ES4+l
         eNiIceN89tDg4oqUC83/VQdtV3asVkBMX+MbJ7PdyfHBptn/QMhv1KlFIjBNWBtptSAn
         RWCX6b52lq7akolecNjfiy1a4qHJJBOLPru02eVy1ClND/AkM+piDvEjIA5gnJiQsGQK
         TFKmzEV0af+QVed95gk+lC4VVKQeyEqcoIlr8gRKzmvRWJr7bu/7zWOgvNoKS1Pcvac2
         +za6K1r/uEMxliemyrJDV9nDKn2cCeWzhdkhBH+EwVIRMbNHv91pr0AItOds2xe6PCDg
         pSbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6BujTbenabEGSiJ7WZjylT4qdqwfT5E1S/lmjhOYuwI=;
        b=GXL0t63i29Z+9SP0WSD5Ai1LpksXMQ9eLXjPGFJv8xBGMXf9g02VEROE6a5kqJzZvx
         xgp2mI4F6xaQkJ+TzVXReBTZj8JGQ4mUAbqxkQtpwKDZmGi0799OnIGJa3+amFFipVPd
         WiGd2qlMqU9RUwN3I9b87UyHGbZIYt7xeim6be9MqQxU0uSWkZ7G9OsAYeKQX1dQCGkv
         IMQ3VRIUnH7p+JzE0zzOG9j1/Xiw0NmKcFtQ0d/dmk8x2VRThTSdZ4OqWSCAdAz/TV/J
         Lx2ryPAq2bf2W3o8m5VVwB7THwVuj/GJFdbl/k+m+JQ4ZUaTHUdAMmy/cb/m1GfhsZrJ
         TCbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FBSkOcjy8TYvfLspdYJMOraJjsT1v9PyURX4i03AcZLo0rXgq
	h5dz0N8ErSTMMpRQj2aN8wY=
X-Google-Smtp-Source: ABdhPJzmJ09GeqohxJ00qIlSb6BgeJGAXTf19SD3FVHnqjlvH4JeVHHqyVoNXAM8J084Qwt0Ao/NuA==
X-Received: by 2002:a17:902:7585:: with SMTP id j5mr4060051pll.168.1596205292168;
        Fri, 31 Jul 2020 07:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7616:: with SMTP id k22ls3867394pll.1.gmail; Fri, 31
 Jul 2020 07:21:31 -0700 (PDT)
X-Received: by 2002:a17:90a:fd82:: with SMTP id cx2mr4519051pjb.67.1596205291566;
        Fri, 31 Jul 2020 07:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596205291; cv=none;
        d=google.com; s=arc-20160816;
        b=qEXavTIK1RbTYYgrHhKoV+2SoSnTy1uE5+2jPliG9T8OHrL8pZJPeaV/0lHUKFRqzw
         99F7Hj7g3dfEZKT9vG3+N4hpV2fHK872UHnBegGwRUn/zErL/NpOEZ3ZwmYX2KSMhN4u
         s0gJHBEyRGmj3BIW61ww26ayVycMiAz5vUaje/hurhiDSYb/GtLm8uDV9OssBUQ3sEh+
         tVlRLmBEsi+3T0LXjYlRVTAVjH5183sBBQ0IUHWIL+MXYbXBEymBJgOooeQCULyFNwZ2
         EuT8j278N7P22AcNiguOUc2+YuBZkq12XueOzUtyJOFWZTMV9ZC7hCLB2n5qyR5v2d8t
         jhVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ZFGDu7BI4OmDGFNpIatGujZz15MJasvxe4LxLd80w50=;
        b=smRoIZ1odklf6mBAtKY5ZIMraVJUynqYSdaTouANSo+w/MSQj3sAM/KBvuL3Sybmcg
         OQ1lPtzDBmfUQQQND4ujoguYHQ6JI4ck/vxTrbp7JyDykvVMqM2yc0utw9mgh4Ebipdr
         k6x2G5QGbE2BkJxbU1p+78gvvdpBdCc6u+ccqJs3//4gt+AFsCrVHWIdzZsFHs2bImGT
         L5mnaY8Nar4O2YHVQnywma2uYoiKk2x2fnAt/Xr6KPwl+Z76TJGXZlprXapcqxytVGZb
         Cf/fre3W5U1a15yvKmUfMy6DWDzyeZXlaBUWi3Wr2gerz6FMRBWX7qf/9WhaM47ab/0x
         zyyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j4si614621pjd.0.2020.07.31.07.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 Jul 2020 07:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.146.230.158])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 66956208E4;
	Fri, 31 Jul 2020 14:21:29 +0000 (UTC)
Date: Fri, 31 Jul 2020 15:21:27 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Walter Wu <walter-zh.wu@mediatek.com>,
	Elena Petrova <lenaptr@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH 2/4] kasan, arm64: don't instrument functions that enable
 kasan
Message-ID: <20200731142126.GE29569@gaia>
References: <cover.1596199677.git.andreyknvl@google.com>
 <55d432671a92e931ab8234b03dc36b14d4c21bfb.1596199677.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <55d432671a92e931ab8234b03dc36b14d4c21bfb.1596199677.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Jul 31, 2020 at 03:20:39PM +0200, Andrey Konovalov wrote:
> This patch prepares Software Tag-Based KASAN for stack tagging support.
> 
> With stack tagging enabled, KASAN tags stack variable in each function
> in its prologue. In start_kernel() stack variables get tagged before KASAN
> is enabled via setup_arch()->kasan_init(). As the result the tags for
> start_kernel()'s stack variables end up in the temporary shadow memory.
> Later when KASAN gets enabled, switched to normal shadow, and starts
> checking tags, this leads to false-positive reports, as proper tags are
> missing in normal shadow.
> 
> Disable KASAN instrumentation for start_kernel(). Also disable it for
> arm64's setup_arch() as a precaution (it doesn't have any stack variables
> right now).
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

For arm64:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731142126.GE29569%40gaia.
